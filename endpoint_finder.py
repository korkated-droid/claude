#!/usr/bin/env python3
"""
endpoint_finder.py — Web endpoint discovery tool for authorized security testing.

Usage:
    python endpoint_finder.py <url> [options]

Only use against targets you own or have explicit written permission to test.
"""

import argparse
import asyncio
import json
import re
import sys
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urljoin, urlparse

try:
    import aiohttp
except ImportError:
    print("Missing dependency: pip install aiohttp beautifulsoup4 lxml")
    sys.exit(1)

try:
    from bs4 import BeautifulSoup
except ImportError:
    print("Missing dependency: pip install beautifulsoup4")
    sys.exit(1)


# ── Patterns for extracting endpoints from JS ──────────────────────────────

JS_ENDPOINT_PATTERNS = [
    # fetch / axios / XHR calls
    r"""(?:fetch|axios\.(?:get|post|put|delete|patch))\s*\(\s*['"`]([^'"`\s]+)['"`]""",
    # route definitions (Express-style)
    r"""(?:app|router)\.(?:get|post|put|delete|patch|use|all)\s*\(\s*['"`]([^'"`\s]+)['"`]""",
    # string paths that look like API routes
    r"""['"`](/api/[^'"`\s<>{}]+)['"`]""",
    r"""['"`](/v\d+/[^'"`\s<>{}]+)['"`]""",
    # href / action attributes in templates
    r"""(?:href|action|url|endpoint)\s*[=:]\s*['"`]([^'"`\s]+)['"`]""",
]

HTML_ATTRS = ["href", "src", "action", "data-url", "data-href", "data-endpoint"]


@dataclass
class Finding:
    url: str
    status: Optional[int] = None
    content_type: Optional[str] = None
    source: str = "unknown"   # crawl | wordlist | js
    size: Optional[int] = None


@dataclass
class ScanResult:
    target: str
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    elapsed: float = 0.0


# ── Helpers ────────────────────────────────────────────────────────────────

def same_origin(base: str, url: str) -> bool:
    b, u = urlparse(base), urlparse(url)
    return b.scheme == u.scheme and b.netloc == u.netloc


def normalize(base: str, url: str) -> Optional[str]:
    if not url or url.startswith(("mailto:", "javascript:", "data:", "#")):
        return None
    joined = urljoin(base, url).split("#")[0].rstrip("/") or "/"
    p = urlparse(joined)
    if p.scheme not in ("http", "https"):
        return None
    return joined


def extract_from_html(html: str, page_url: str) -> list[str]:
    soup = BeautifulSoup(html, "lxml")
    found = set()
    for tag in soup.find_all(True):
        for attr in HTML_ATTRS:
            val = tag.get(attr)
            if val:
                n = normalize(page_url, val)
                if n:
                    found.add(n)
    return list(found)


def extract_from_js(js: str, base_url: str) -> list[str]:
    found = set()
    for pat in JS_ENDPOINT_PATTERNS:
        for m in re.finditer(pat, js, re.IGNORECASE):
            path = m.group(1)
            n = normalize(base_url, path)
            if n:
                found.add(n)
    return list(found)


# ── Core scanner ──────────────────────────────────────────────────────────

class EndpointScanner:
    def __init__(
        self,
        target: str,
        wordlist: Optional[str],
        max_crawl: int,
        concurrency: int,
        delay: float,
        timeout: int,
        same_origin_only: bool,
        include_js: bool,
        user_agent: str,
        status_filter: list[int],
    ):
        self.target = target.rstrip("/")
        self.wordlist = wordlist
        self.max_crawl = max_crawl
        self.concurrency = concurrency
        self.delay = delay
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.same_origin_only = same_origin_only
        self.include_js = include_js
        self.headers = {"User-Agent": user_agent}
        self.status_filter = status_filter

        self._visited: set[str] = set()
        self._queue: asyncio.Queue = asyncio.Queue()
        self._findings: list[Finding] = []
        self._errors: list[str] = []
        self._sem: asyncio.Semaphore = asyncio.Semaphore(concurrency)

    async def _probe(self, session: aiohttp.ClientSession, url: str, source: str) -> Optional[Finding]:
        if url in self._visited:
            return None
        self._visited.add(url)

        async with self._sem:
            try:
                async with session.get(url, headers=self.headers, allow_redirects=True, ssl=False) as resp:
                    ct = resp.headers.get("Content-Type", "")
                    body = await resp.text(errors="replace")
                    size = len(body.encode())

                    if self.delay:
                        await asyncio.sleep(self.delay)

                    finding = Finding(
                        url=str(resp.url),
                        status=resp.status,
                        content_type=ct.split(";")[0].strip(),
                        source=source,
                        size=size,
                    )

                    # Crawl HTML pages for more links
                    if source == "crawl" and "html" in ct and len(self._visited) < self.max_crawl:
                        for link in extract_from_html(body, str(resp.url)):
                            if self.same_origin_only and not same_origin(self.target, link):
                                continue
                            if link not in self._visited:
                                await self._queue.put(("crawl", link))

                    # Extract endpoints from JS files
                    if self.include_js and "javascript" in ct:
                        for ep in extract_from_js(body, self.target):
                            if ep not in self._visited:
                                await self._queue.put(("js", ep))

                    return finding

            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                self._errors.append(f"{url}: {e}")
                return None

    def _passes_filter(self, f: Finding) -> bool:
        if not self.status_filter:
            return True
        return f.status in self.status_filter

    async def run(self) -> ScanResult:
        start = time.monotonic()

        # Seed the queue
        await self._queue.put(("crawl", self.target))

        # Wordlist paths
        if self.wordlist:
            try:
                with open(self.wordlist) as fh:
                    for line in fh:
                        path = line.strip()
                        if path and not path.startswith("#"):
                            url = f"{self.target}/{path.lstrip('/')}"
                            await self._queue.put(("wordlist", url))
            except FileNotFoundError:
                self._errors.append(f"Wordlist not found: {self.wordlist}")

        async with aiohttp.ClientSession(timeout=self.timeout) as session:
            workers: list[asyncio.Task] = []

            async def worker():
                while True:
                    try:
                        source, url = self._queue.get_nowait()
                    except asyncio.QueueEmpty:
                        break
                    finding = await self._probe(session, url, source)
                    if finding and self._passes_filter(finding):
                        self._findings.append(finding)
                    self._queue.task_done()

            # Drain queue with concurrency
            while not self._queue.empty():
                batch = min(self.concurrency, self._queue.qsize())
                tasks = [asyncio.create_task(worker()) for _ in range(batch)]
                await asyncio.gather(*tasks)
                if self._queue.empty():
                    break

        return ScanResult(
            target=self.target,
            findings=self._findings,
            errors=self._errors,
            elapsed=time.monotonic() - start,
        )


# ── Output formatting ─────────────────────────────────────────────────────

STATUS_COLORS = {
    2: "\033[32m",   # green  2xx
    3: "\033[33m",   # yellow 3xx
    4: "\033[31m",   # red    4xx
    5: "\033[35m",   # magenta 5xx
}
RESET = "\033[0m"


def color_status(status: Optional[int]) -> str:
    if status is None:
        return "???"
    c = STATUS_COLORS.get(status // 100, "")
    return f"{c}{status}{RESET}"


def print_results(result: ScanResult, no_color: bool = False):
    if no_color:
        global STATUS_COLORS, RESET
        STATUS_COLORS = defaultdict(str)
        RESET = ""

    print(f"\n{'='*60}")
    print(f"  Target : {result.target}")
    print(f"  Found  : {len(result.findings)} endpoint(s)")
    print(f"  Elapsed: {result.elapsed:.1f}s")
    print(f"{'='*60}\n")

    by_source = defaultdict(list)
    for f in result.findings:
        by_source[f.source].append(f)

    for source in ("crawl", "wordlist", "js"):
        items = by_source.get(source, [])
        if not items:
            continue
        label = {"crawl": "Crawled", "wordlist": "Wordlist hits", "js": "JS-extracted"}[source]
        print(f"  [{label}]")
        for f in sorted(items, key=lambda x: x.url):
            size_str = f"  {f.size}B" if f.size is not None else ""
            print(f"    {color_status(f.status)}  {f.url}  ({f.content_type}){size_str}")
        print()

    if result.errors:
        print(f"  [Errors — {len(result.errors)}]")
        for e in result.errors[:10]:
            print(f"    {e}")
        if len(result.errors) > 10:
            print(f"    ... and {len(result.errors)-10} more")
        print()


def save_json(result: ScanResult, path: str):
    data = {
        "target": result.target,
        "elapsed": round(result.elapsed, 2),
        "findings": [
            {
                "url": f.url,
                "status": f.status,
                "content_type": f.content_type,
                "source": f.source,
                "size": f.size,
            }
            for f in result.findings
        ],
        "errors": result.errors,
    }
    with open(path, "w") as fh:
        json.dump(data, fh, indent=2)
    print(f"  Results saved → {path}")


# ── CLI ───────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="endpoint_finder",
        description="Web endpoint discovery for authorized security testing.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic crawl
  python endpoint_finder.py https://example.com

  # Crawl + wordlist + JS extraction
  python endpoint_finder.py https://example.com -w wordlists/common.txt --js

  # Only show 200s, save JSON report
  python endpoint_finder.py https://example.com -w wordlists/common.txt --status 200 -o report.json

  # Fast scan, high concurrency, no color
  python endpoint_finder.py https://example.com -c 20 --no-color
        """,
    )
    p.add_argument("url", help="Target base URL (must have explicit authorization)")
    p.add_argument("-w", "--wordlist", metavar="FILE", help="Path to wordlist file")
    p.add_argument("--js", action="store_true", help="Extract endpoints from JS files")
    p.add_argument("-c", "--concurrency", type=int, default=10, metavar="N", help="Concurrent requests (default 10)")
    p.add_argument("--max-crawl", type=int, default=100, metavar="N", help="Max pages to crawl (default 100)")
    p.add_argument("--delay", type=float, default=0.0, metavar="S", help="Delay between requests in seconds")
    p.add_argument("--timeout", type=int, default=10, metavar="S", help="Request timeout seconds (default 10)")
    p.add_argument("--status", type=int, nargs="+", metavar="CODE",
                   help="Only report these HTTP status codes, e.g. --status 200 301 403")
    p.add_argument("--allow-external", action="store_true",
                   help="Follow links to external domains (default: same-origin only)")
    p.add_argument("-o", "--output", metavar="FILE", help="Save results to JSON file")
    p.add_argument("--no-color", action="store_true", help="Disable ANSI color output")
    p.add_argument("--user-agent", default="EndpointFinder/1.0 (security-audit)",
                   help="Custom User-Agent string")
    return p


def main():
    parser = build_parser()
    args = parser.parse_args()

    # Sanity-check the URL
    parsed = urlparse(args.url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        print(f"Error: invalid URL '{args.url}'. Include scheme, e.g. https://example.com")
        sys.exit(1)

    print(
        "\n⚠  Only use this tool against targets you own or have explicit written"
        "\n   authorization to test. Unauthorized scanning may be illegal.\n"
    )

    scanner = EndpointScanner(
        target=args.url,
        wordlist=args.wordlist,
        max_crawl=args.max_crawl,
        concurrency=args.concurrency,
        delay=args.delay,
        timeout=args.timeout,
        same_origin_only=not args.allow_external,
        include_js=args.js,
        user_agent=args.user_agent,
        status_filter=args.status or [],
    )

    result = asyncio.run(scanner.run())
    print_results(result, no_color=args.no_color)

    if args.output:
        save_json(result, args.output)


if __name__ == "__main__":
    main()
