#!/usr/bin/env python3
"""
tools.py — External Tool Orchestrator
Wraps and chains best-in-class bug bounty tools.
Authorized testing only — bug bounty / owned targets.

Tools integrated:
  subfinder    — Passive subdomain enumeration (ProjectDiscovery)
  amass        — In-depth subdomain OSINT + active recon
  httpx        — HTTP probing, title/tech fingerprint, status
  gau / waybackurls — Get All URLs from Wayback/CommonCrawl/AlienVault
  katana       — Fast JS-aware web crawler
  nuclei       — Template-based CVE/misconfiguration scanner (ProjectDiscovery)
  ffuf         — Fast web fuzzer — directory/param discovery
  feroxbuster  — Recursive content discovery (Rust, fast)
  gobuster     — Directory / DNS / vhost brute
  arjun        — HTTP parameter discovery
  sqlmap       — Automatic SQL injection detection + exploitation PoC
  dalfox       — DOM/Reflected/Stored XSS scanner
  trufflehog   — Secret scanning in HTML/JS responses + git history
  gitleaks     — Secrets in git repos
  nikto        — Web server misconfiguration scanner
  whatweb      — Technology fingerprinting
  nmap         — Port/service scanning (OS detection, script scan)
  masscan      — Ultra-fast port scanning
  semgrep      — SAST patterns on downloaded JS/source

INSTALL
───────
  # Ubuntu/Debian:
  apt install nmap masscan nikto whatweb
  pip install semgrep trufflehog

  # Go tools (fastest method):
  go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
  go install github.com/projectdiscovery/httpx/cmd/httpx@latest
  go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
  go install github.com/projectdiscovery/katana/cmd/katana@latest
  go install github.com/lc/gau/v2/cmd/gau@latest
  go install github.com/ffuf/ffuf/v2@latest
  go install github.com/epi052/feroxbuster@latest   # or cargo install
  go install github.com/OJ/gobuster/v3@latest
  go install github.com/s0md3v/dalfox/v2@latest
  go install github.com/sqlmapproject/sqlmap@latest  # Python, use pip

  # Automated install:
  python3 tools.py --install

USAGE
─────
  # Run all available tools against target:
  python3 tools.py https://target.example.com -o results/

  # Specific tools only:
  python3 tools.py https://target.example.com --only nuclei,ffuf,sqlmap

  # With auth + proxy:
  python3 tools.py https://target.example.com -t "Bearer eyJ..." --proxy http://127.0.0.1:8080

  # Aggressive (more coverage, more noise):
  python3 tools.py https://target.example.com --aggressive

  # Passive only (no active requests to target):
  python3 tools.py https://target.example.com --passive-only
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

R="\033[91m"; Y="\033[93m"; G="\033[92m"; B="\033[94m"
M="\033[95m"; C="\033[96m"; W="\033[97m"; DIM="\033[2m"; RST="\033[0m"; BOLD="\033[1m"


@dataclass
class ToolResult:
    tool: str
    success: bool
    output_file: str
    findings_count: int = 0
    raw_output: str = ""
    error: str = ""
    elapsed: float = 0.0


def check_tool(name: str) -> bool:
    return shutil.which(name) is not None


def run_cmd(cmd: List[str], timeout: int = 300, env: Optional[Dict] = None) -> Tuple[int, str, str]:
    try:
        r = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            env={**os.environ, **(env or {})},
        )
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "TIMEOUT"
    except FileNotFoundError:
        return -2, "", f"NOT FOUND: {cmd[0]}"
    except Exception as e:
        return -3, "", str(e)


def status(tool: str, msg: str, ok: bool = True):
    icon = G + "✓" + RST if ok else Y + "!" + RST
    print(f"  [{icon}] {BOLD}{tool:15}{RST} {msg}")


# ══════════════════════════════════════════════════════════════════════════════
# TOOL RUNNERS
# ══════════════════════════════════════════════════════════════════════════════

def run_subfinder(domain: str, outdir: str, passive: bool = True, verbose: bool = False) -> ToolResult:
    """Passive subdomain enumeration via 50+ OSINT sources."""
    if not check_tool("subfinder"):
        return ToolResult("subfinder", False, "", error="not installed")

    out_file = os.path.join(outdir, "subfinder_subdomains.txt")
    cmd = [
        "subfinder", "-d", domain,
        "-o", out_file,
        "-all",           # use all sources
        "-silent",
        "-timeout", "30",
    ]
    if not passive:
        cmd += ["-active"]  # DNS resolve each subdomain
    if verbose:
        cmd.remove("-silent")

    t0 = time.time()
    rc, out, err = run_cmd(cmd, timeout=120)
    elapsed = time.time() - t0

    count = 0
    if os.path.exists(out_file):
        with open(out_file) as f:
            count = sum(1 for l in f if l.strip())

    status("subfinder", f"{count} subdomains in {elapsed:.1f}s → {out_file}", ok=count > 0 or rc == 0)
    return ToolResult("subfinder", rc == 0, out_file, count, out[:2000], err[:500], elapsed)


def run_amass(domain: str, outdir: str, passive: bool = True, verbose: bool = False) -> ToolResult:
    """Deep subdomain OSINT — ASN, BGP, certificate transparency, WHOIS."""
    if not check_tool("amass"):
        return ToolResult("amass", False, "", error="not installed — optional")

    out_file = os.path.join(outdir, "amass_subdomains.txt")
    cmd = [
        "amass", "enum",
        "-d", domain,
        "-o", out_file,
        "-timeout", "10",  # minutes
    ]
    if passive:
        cmd.append("-passive")

    t0 = time.time()
    rc, out, err = run_cmd(cmd, timeout=700)
    elapsed = time.time() - t0

    count = 0
    if os.path.exists(out_file):
        with open(out_file) as f:
            count = sum(1 for l in f if l.strip())

    status("amass", f"{count} subdomains in {elapsed:.1f}s", ok=count > 0)
    return ToolResult("amass", rc in (0, 1), out_file, count, out[:2000], elapsed=elapsed)


def run_httpx(hosts_file: str, outdir: str, verbose: bool = False) -> ToolResult:
    """HTTP probe: status, title, tech, CDN, WAF detection."""
    if not check_tool("httpx"):
        return ToolResult("httpx", False, "", error="not installed")

    out_file = os.path.join(outdir, "httpx_live.json")
    cmd = [
        "httpx",
        "-l", hosts_file,
        "-o", out_file,
        "-json",
        "-status-code",
        "-title",
        "-tech-detect",
        "-content-length",
        "-web-server",
        "-cdn",
        "-tls-probe",
        "-follow-redirects",
        "-threads", "50",
        "-timeout", "10",
        "-silent",
        "-retries", "1",
    ]

    t0 = time.time()
    rc, out, err = run_cmd(cmd, timeout=300)
    elapsed = time.time() - t0

    count = 0
    if os.path.exists(out_file):
        with open(out_file) as f:
            count = sum(1 for l in f if l.strip())

    status("httpx", f"{count} live hosts in {elapsed:.1f}s → {out_file}", ok=count > 0)
    return ToolResult("httpx", rc == 0, out_file, count, out[:2000], elapsed=elapsed)


def run_gau(domain: str, outdir: str, verbose: bool = False) -> ToolResult:
    """Get All URLs — Wayback Machine + CommonCrawl + OTX + URLScan."""
    if not check_tool("gau"):
        # Try waybackurls as fallback
        if check_tool("waybackurls"):
            return run_waybackurls(domain, outdir, verbose)
        return ToolResult("gau", False, "", error="not installed")

    out_file = os.path.join(outdir, "gau_urls.txt")
    cmd = [
        "gau",
        "--subs",        # include subdomains
        "--blacklist", "png,jpg,gif,jpeg,css,woff,woff2,ttf,eot,svg,ico,mp4,mp3",
        "--threads", "5",
        "--timeout", "15",
        "--providers", "wayback,commoncrawl,otx,urlscan",
        "--o", out_file,
        domain,
    ]

    t0 = time.time()
    rc, out, err = run_cmd(cmd, timeout=180)
    elapsed = time.time() - t0

    count = 0
    if os.path.exists(out_file):
        with open(out_file) as f:
            count = sum(1 for l in f if l.strip())

    status("gau", f"{count} URLs in {elapsed:.1f}s → {out_file}", ok=count > 0)
    return ToolResult("gau", rc == 0, out_file, count, elapsed=elapsed)


def run_waybackurls(domain: str, outdir: str, verbose: bool = False) -> ToolResult:
    out_file = os.path.join(outdir, "waybackurls.txt")
    t0 = time.time()
    rc, out, err = run_cmd(["waybackurls", domain], timeout=120)
    elapsed = time.time() - t0
    if rc == 0 and out:
        with open(out_file, "w") as f:
            f.write(out)
        count = len(out.splitlines())
        status("waybackurls", f"{count} URLs in {elapsed:.1f}s", ok=True)
        return ToolResult("waybackurls", True, out_file, count, out[:1000], elapsed=elapsed)
    return ToolResult("waybackurls", False, "", error=err[:200])


def run_katana(base_url: str, outdir: str, proxy: Optional[str] = None, verbose: bool = False) -> ToolResult:
    """Fast JS-aware crawler with automatic form submission."""
    if not check_tool("katana"):
        return ToolResult("katana", False, "", error="not installed")

    out_file = os.path.join(outdir, "katana_crawl.txt")
    cmd = [
        "katana",
        "-u", base_url,
        "-o", out_file,
        "-js-crawl",          # crawl JS files
        "-form-extraction",   # extract form details
        "-passive",           # include passive sources
        "-depth", "3",
        "-concurrency", "20",
        "-timeout", "10",
        "-silent",
        "-no-color",
    ]
    if proxy:
        cmd += ["-proxy", proxy]

    t0 = time.time()
    rc, out, err = run_cmd(cmd, timeout=300)
    elapsed = time.time() - t0

    count = 0
    if os.path.exists(out_file):
        with open(out_file) as f:
            count = sum(1 for l in f if l.strip())

    status("katana", f"{count} URLs crawled in {elapsed:.1f}s", ok=count > 0)
    return ToolResult("katana", rc == 0, out_file, count, elapsed=elapsed)


def run_nuclei(base_url: str, outdir: str, proxy: Optional[str] = None,
               severity: str = "critical,high,medium", verbose: bool = False) -> ToolResult:
    """
    Nuclei template-based scanner — 9000+ CVE/misconfiguration templates.
    Auto-updates templates on first run.
    """
    if not check_tool("nuclei"):
        return ToolResult("nuclei", False, "", error="not installed — HIGHLY recommended: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")

    out_file = os.path.join(outdir, "nuclei_findings.json")
    cmd = [
        "nuclei",
        "-target", base_url,
        "-o", out_file,
        "-json-export", out_file,
        "-severity", severity,
        "-no-interactsh",     # disable OOB (add -ni flag) for speed; remove for full coverage
        "-rate-limit", "50",
        "-timeout", "15",
        "-retries", "1",
        "-silent",
        "-stats",
        # Key template categories
        "-tags", "cve,misconfig,exposure,default-login,takeover,token",
        # Exclude noisy / destructive
        "-exclude-tags", "dos,fuzzing",
    ]
    if proxy:
        cmd += ["-proxy", proxy]
    if verbose:
        cmd.remove("-silent")

    # Update templates first
    print(f"  {DIM}» nuclei: updating templates (first run may take 30s){RST}")
    run_cmd(["nuclei", "-update-templates", "-silent"], timeout=60)

    t0 = time.time()
    rc, out, err = run_cmd(cmd, timeout=600)
    elapsed = time.time() - t0

    count = 0
    if os.path.exists(out_file):
        with open(out_file) as f:
            count = sum(1 for l in f if l.strip())

    status("nuclei", f"{count} findings in {elapsed:.1f}s → {out_file}", ok=True)
    return ToolResult("nuclei", rc == 0, out_file, count, out[:3000], elapsed=elapsed)


def run_ffuf(base_url: str, outdir: str, wordlist: Optional[str] = None,
             mode: str = "dirs", proxy: Optional[str] = None,
             cookies: Optional[str] = None, verbose: bool = False) -> ToolResult:
    """
    Fast web fuzzer for directory/file/parameter discovery.
    mode: dirs | params | vhost | backup
    """
    if not check_tool("ffuf"):
        return ToolResult("ffuf", False, "", error="not installed — go install github.com/ffuf/ffuf/v2@latest")

    # Default wordlists (use seclists if available)
    seclists_base = "/usr/share/seclists"
    if not os.path.exists(seclists_base):
        seclists_base = os.path.expanduser("~/SecLists")

    default_wordlists = {
        "dirs": os.path.join(seclists_base, "Discovery/Web-Content/raft-large-directories.txt"),
        "files": os.path.join(seclists_base, "Discovery/Web-Content/raft-large-files.txt"),
        "params": os.path.join(seclists_base, "Discovery/Web-Content/burp-parameter-names.txt"),
        "backup": os.path.join(seclists_base, "Discovery/Web-Content/Common-DB-Backups.txt"),
        "api": os.path.join(seclists_base, "Discovery/Web-Content/api/objects.txt"),
        "vhost": os.path.join(seclists_base, "Discovery/DNS/subdomains-top1million-20000.txt"),
    }

    wl = wordlist or default_wordlists.get(mode, default_wordlists["dirs"])
    if not os.path.exists(wl):
        # Fallback to built-in minimal wordlist
        wl = _write_minimal_wordlist(outdir)

    out_file = os.path.join(outdir, f"ffuf_{mode}.json")

    if mode == "dirs":
        url_fuzz = base_url.rstrip("/") + "/FUZZ"
    elif mode == "params":
        url_fuzz = base_url.rstrip("/") + "/?FUZZ=test"
    elif mode == "vhost":
        host = urllib.parse.urlparse(base_url).hostname
        url_fuzz = base_url
    elif mode == "backup":
        url_fuzz = base_url.rstrip("/") + "/FUZZ"
    else:
        url_fuzz = base_url.rstrip("/") + "/FUZZ"

    cmd = [
        "ffuf",
        "-u", url_fuzz,
        "-w", wl,
        "-o", out_file,
        "-of", "json",
        "-t", "50",          # threads
        "-timeout", "10",
        "-mc", "200,201,204,301,302,307,401,403,405",
        "-ic",               # ignore comments in wordlist
        "-c",                # colorize
        "-s",                # silent mode (no progress bar)
        "-rate", "100",      # max 100 req/s
        "-recursion",        # recursive discovery
        "-recursion-depth", "2",
    ]
    if proxy:
        cmd += ["-x", proxy]
    if cookies:
        cmd += ["-b", cookies]
    if mode == "vhost":
        cmd += ["-H", f"Host: FUZZ.{urllib.parse.urlparse(base_url).hostname}"]

    t0 = time.time()
    rc, out, err = run_cmd(cmd, timeout=300)
    elapsed = time.time() - t0

    count = 0
    if os.path.exists(out_file):
        try:
            data = json.load(open(out_file))
            count = len(data.get("results", []))
        except Exception:
            pass

    status("ffuf", f"mode={mode}: {count} paths in {elapsed:.1f}s → {out_file}", ok=count > 0)
    return ToolResult("ffuf", rc == 0, out_file, count, elapsed=elapsed)


def run_feroxbuster(base_url: str, outdir: str, wordlist: Optional[str] = None,
                    proxy: Optional[str] = None, cookies: Optional[str] = None,
                    verbose: bool = False) -> ToolResult:
    """
    Recursive content discovery — handles redirects, threads, auto-recurse.
    Better than gobuster for APIs with depth.
    """
    if not check_tool("feroxbuster"):
        return ToolResult("feroxbuster", False, "", error="not installed — cargo install feroxbuster")

    seclists_base = "/usr/share/seclists"
    default_wl = os.path.join(seclists_base, "Discovery/Web-Content/raft-medium-words.txt")
    wl = wordlist or (default_wl if os.path.exists(default_wl) else _write_minimal_wordlist(outdir))

    out_file = os.path.join(outdir, "feroxbuster.json")
    cmd = [
        "feroxbuster",
        "--url", base_url,
        "--wordlist", wl,
        "--output", out_file,
        "--json",
        "--threads", "50",
        "--depth", "3",
        "--timeout", "10",
        "--rate-limit", "100",
        "--status-codes", "200,201,204,301,302,307,401,403,405",
        "--no-state",
        "--quiet",
        # Scan API paths automatically
        "--extensions", "php,asp,aspx,jsp,json,xml,txt,bak,old,zip,tar.gz",
    ]
    if proxy:
        cmd += ["--proxy", proxy]
    if cookies:
        cmd += ["--cookies", cookies]

    t0 = time.time()
    rc, out, err = run_cmd(cmd, timeout=300)
    elapsed = time.time() - t0

    count = 0
    if os.path.exists(out_file):
        with open(out_file) as f:
            count = sum(1 for l in f if l.strip())

    status("feroxbuster", f"{count} entries in {elapsed:.1f}s → {out_file}", ok=count > 0)
    return ToolResult("feroxbuster", rc == 0, out_file, count, elapsed=elapsed)


def run_arjun(base_url: str, outdir: str, proxy: Optional[str] = None,
              cookies: Optional[str] = None, verbose: bool = False) -> ToolResult:
    """
    HTTP parameter discovery — finds hidden GET/POST/JSON parameters.
    Essential for finding undocumented API params.
    """
    if not check_tool("arjun"):
        # Try python module
        rc, _, _ = run_cmd([sys.executable, "-m", "arjun", "--help"])
        if rc != 0:
            return ToolResult("arjun", False, "", error="not installed — pip install arjun")
        arjun_cmd = [sys.executable, "-m", "arjun"]
    else:
        arjun_cmd = ["arjun"]

    out_file = os.path.join(outdir, "arjun_params.json")
    cmd = arjun_cmd + [
        "-u", base_url,
        "-oJ", out_file,
        "-t", "10",      # threads
        "--stable",      # stable mode (fewer false positives)
        "-q",            # quiet
    ]
    if proxy:
        cmd += ["--proxy", proxy]

    t0 = time.time()
    rc, out, err = run_cmd(cmd, timeout=180)
    elapsed = time.time() - t0

    count = 0
    if os.path.exists(out_file):
        try:
            data = json.load(open(out_file))
            count = sum(len(v) for v in data.values() if isinstance(v, list))
        except Exception:
            pass

    status("arjun", f"{count} parameters discovered in {elapsed:.1f}s", ok=count > 0)
    return ToolResult("arjun", rc == 0, out_file, count, elapsed=elapsed)


def run_sqlmap(url: str, outdir: str, proxy: Optional[str] = None,
               cookies: Optional[str] = None, level: int = 3,
               verbose: bool = False) -> ToolResult:
    """
    SQLMap — automatic SQL injection detection and exploitation PoC.
    level 3 = thorough parameter testing.
    """
    if not check_tool("sqlmap"):
        rc, _, _ = run_cmd([sys.executable, "-m", "sqlmap", "--version"])
        if rc != 0:
            return ToolResult("sqlmap", False, "", error="not installed — pip install sqlmap")
        sqlmap_cmd = [sys.executable, "-m", "sqlmap"]
    else:
        sqlmap_cmd = ["sqlmap"]

    out_dir_sqlmap = os.path.join(outdir, "sqlmap")
    os.makedirs(out_dir_sqlmap, exist_ok=True)

    cmd = sqlmap_cmd + [
        "-u", url,
        "--batch",            # never ask for user input
        "--level", str(level),
        "--risk", "2",        # avoid destructive tests
        "--threads", "5",
        "--timeout", "15",
        "--output-dir", out_dir_sqlmap,
        "--forms",            # automatically test forms
        "--crawl", "2",       # crawl 2 levels
        "--random-agent",
        # Test all common injection types
        "--technique", "BEUSTQ",  # Boolean, Error, Union, Stack, Time, Inline
        # Useful for API targets
        "--data", '{"id":"1"}',
        "--content-type", "application/json",
        "-p", "id,user_id,userId,item_id,itemId,product_id",
    ]
    if proxy:
        cmd += ["--proxy", proxy]
    if cookies:
        cmd += ["--cookie", cookies]
    if verbose:
        cmd += ["-v", "2"]

    t0 = time.time()
    rc, out, err = run_cmd(cmd, timeout=300)
    elapsed = time.time() - t0

    # Count injections found
    injections = len([l for l in out.splitlines() if "injectable" in l.lower() or "sqlmap identified" in l.lower()])

    status("sqlmap", f"{injections} injection point(s) in {elapsed:.1f}s → {out_dir_sqlmap}", ok=True)
    return ToolResult("sqlmap", rc == 0, out_dir_sqlmap, injections, out[:3000], elapsed=elapsed)


def run_dalfox(url: str, outdir: str, proxy: Optional[str] = None,
               cookies: Optional[str] = None, verbose: bool = False) -> ToolResult:
    """
    DalFox — DOM/Reflected/Stored XSS scanner with parameter brute force.
    Fast, accurate, supports pipe mode.
    """
    if not check_tool("dalfox"):
        return ToolResult("dalfox", False, "", error="not installed — go install github.com/s0md3v/dalfox/v2@latest")

    out_file = os.path.join(outdir, "dalfox_xss.json")
    cmd = [
        "dalfox", "url", url,
        "--output", out_file,
        "--format", "json",
        "--no-color",
        "--timeout", "10",
        "--worker", "20",
        "--skip-mining-dom",   # faster scan without DOM mining
        "--only-discovery",    # discovery mode first
    ]
    if proxy:
        cmd += ["--proxy", proxy]
    if cookies:
        cmd += ["--cookie", cookies]

    t0 = time.time()
    rc, out, err = run_cmd(cmd, timeout=180)
    elapsed = time.time() - t0

    count = 0
    if os.path.exists(out_file):
        try:
            data = json.load(open(out_file))
            count = len(data) if isinstance(data, list) else 0
        except Exception:
            count = out.count("[POC]")

    status("dalfox", f"{count} XSS findings in {elapsed:.1f}s", ok=count > 0 or rc == 0)
    return ToolResult("dalfox", rc == 0, out_file, count, out[:2000], elapsed=elapsed)


def run_nuclei_pipes(urls_file: str, outdir: str, proxy: Optional[str] = None,
                     verbose: bool = False) -> ToolResult:
    """
    Pipe discovered URLs into nuclei for per-URL CVE/template scanning.
    Much more thorough than single-URL nuclei.
    """
    if not check_tool("nuclei"):
        return ToolResult("nuclei_pipe", False, "", error="nuclei not installed")

    out_file = os.path.join(outdir, "nuclei_urls_scan.json")
    cmd = [
        "nuclei",
        "-l", urls_file,
        "-o", out_file,
        "-json-export", out_file,
        "-severity", "critical,high,medium",
        "-tags", "cve,exposure,misconfig,default-login,takeover,panel",
        "-exclude-tags", "dos",
        "-rate-limit", "30",
        "-timeout", "10",
        "-retries", "1",
        "-silent",
        "-bulk-size", "25",
        "-concurrency", "25",
    ]
    if proxy:
        cmd += ["-proxy", proxy]

    t0 = time.time()
    rc, out, err = run_cmd(cmd, timeout=600)
    elapsed = time.time() - t0

    count = 0
    if os.path.exists(out_file):
        with open(out_file) as f:
            count = sum(1 for l in f if l.strip())

    status("nuclei(urls)", f"{count} findings from URL list in {elapsed:.1f}s", ok=True)
    return ToolResult("nuclei_pipe", rc == 0, out_file, count, out[:2000], elapsed=elapsed)


def run_trufflehog(target: str, outdir: str, verbose: bool = False) -> ToolResult:
    """TruffleHog — secret scanning in live HTTP responses + git repos."""
    if not check_tool("trufflehog"):
        return ToolResult("trufflehog", False, "", error="not installed — pip install trufflehog OR brew install trufflehog")

    out_file = os.path.join(outdir, "trufflehog_secrets.json")

    # TruffleHog v3 can scan URLs directly
    if target.startswith("http"):
        cmd = ["trufflehog", "filesystem", "--directory", outdir,
               "--json", "--only-verified"]
    else:
        cmd = ["trufflehog", "git", "--repo", target, "--json", "--only-verified"]

    t0 = time.time()
    rc, out, err = run_cmd(cmd, timeout=180)
    elapsed = time.time() - t0

    count = out.count('"SourceMetadata"') if out else 0
    if count > 0:
        with open(out_file, "w") as f:
            f.write(out)

    status("trufflehog", f"{count} verified secrets in {elapsed:.1f}s", ok=count > 0 or rc == 0)
    return ToolResult("trufflehog", rc == 0, out_file if count > 0 else "", count, out[:2000], elapsed=elapsed)


def run_nikto(base_url: str, outdir: str, proxy: Optional[str] = None,
              verbose: bool = False) -> ToolResult:
    """Nikto — classic web server misconfiguration scanner (6700+ checks)."""
    if not check_tool("nikto"):
        return ToolResult("nikto", False, "", error="not installed — apt install nikto")

    out_file = os.path.join(outdir, "nikto_scan.xml")
    parsed = urllib.parse.urlparse(base_url)
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    cmd = ["nikto", "-h", host, "-port", str(port), "-output", out_file,
           "-Format", "xml", "-nointeractive", "-Tuning", "0123456789abc",
           "-maxtime", "5m"]
    if parsed.scheme == "https":
        cmd += ["-ssl"]
    if proxy:
        proxy_parts = urllib.parse.urlparse(proxy)
        cmd += ["-useproxy", f"{proxy_parts.hostname}:{proxy_parts.port}"]

    t0 = time.time()
    rc, out, err = run_cmd(cmd, timeout=360)
    elapsed = time.time() - t0

    count = out.count("+ ") if out else 0
    status("nikto", f"{count} findings in {elapsed:.1f}s → {out_file}", ok=True)
    return ToolResult("nikto", rc == 0, out_file, count, out[:3000], elapsed=elapsed)


def run_whatweb(base_url: str, outdir: str, verbose: bool = False) -> ToolResult:
    """WhatWeb — technology fingerprinting (1000+ plugins)."""
    if not check_tool("whatweb"):
        return ToolResult("whatweb", False, "", error="not installed — apt install whatweb")

    out_file = os.path.join(outdir, "whatweb.json")
    cmd = ["whatweb", "--log-json", out_file, "-a", "3", "--colour=never", base_url]

    t0 = time.time()
    rc, out, err = run_cmd(cmd, timeout=60)
    elapsed = time.time() - t0

    tech = []
    if os.path.exists(out_file):
        try:
            data = json.load(open(out_file))
            if isinstance(data, list) and data:
                tech = [k for k in data[0].get("plugins", {}).keys()]
        except Exception:
            pass

    status("whatweb", f"Detected: {tech[:10]} in {elapsed:.1f}s", ok=bool(tech))
    return ToolResult("whatweb", rc == 0, out_file, len(tech), elapsed=elapsed)


def run_nmap(host: str, outdir: str, aggressive: bool = False, verbose: bool = False) -> ToolResult:
    """Nmap port scan with service detection and vuln scripts."""
    if not check_tool("nmap"):
        return ToolResult("nmap", False, "", error="not installed — apt install nmap")

    out_file = os.path.join(outdir, "nmap_scan.xml")
    cmd = [
        "nmap",
        "-sV",              # service version detection
        "-O",               # OS detection
        "-p", "80,443,8080,8443,8000,8888,9000,9090,9443,3000,4000,5000,6443,7777",
        "--script", "http-headers,http-auth-finder,http-methods,ssl-cert,http-title",
        "-oX", out_file,
        "--open",           # only show open ports
        "--host-timeout", "120s",
    ]
    if aggressive:
        cmd += ["-A"]  # aggressive: OS + version + scripts + traceroute
    cmd.append(host)

    t0 = time.time()
    rc, out, err = run_cmd(cmd, timeout=180)
    elapsed = time.time() - t0

    open_ports = len([l for l in out.splitlines() if "/tcp" in l and "open" in l])
    status("nmap", f"{open_ports} open ports in {elapsed:.1f}s → {out_file}", ok=True)
    return ToolResult("nmap", rc == 0, out_file, open_ports, out[:3000], elapsed=elapsed)


def run_masscan(host: str, outdir: str, verbose: bool = False) -> ToolResult:
    """Masscan — ultra-fast port scanner for full port range discovery."""
    if not check_tool("masscan"):
        return ToolResult("masscan", False, "", error="not installed — apt install masscan")

    out_file = os.path.join(outdir, "masscan_ports.txt")
    cmd = [
        "masscan",
        host,
        "-p", "1-65535",        # full port range
        "--rate", "10000",       # 10k pps (reduce if causing issues)
        "--wait", "3",
        "-oG", out_file,
    ]

    t0 = time.time()
    rc, out, err = run_cmd(cmd, timeout=300)
    elapsed = time.time() - t0

    count = 0
    if os.path.exists(out_file):
        with open(out_file) as f:
            count = sum(1 for l in f if "Ports:" in l)

    status("masscan", f"{count} open ports in {elapsed:.1f}s", ok=count > 0 or rc == 0)
    return ToolResult("masscan", rc == 0, out_file, count, elapsed=elapsed)


def run_semgrep_js(js_dir: str, outdir: str, verbose: bool = False) -> ToolResult:
    """Semgrep SAST on downloaded JS files — finds secrets, unsafe patterns."""
    if not check_tool("semgrep"):
        return ToolResult("semgrep", False, "", error="not installed — pip install semgrep")

    out_file = os.path.join(outdir, "semgrep_findings.json")
    cmd = [
        "semgrep",
        "--config=auto",        # auto-detect best rules
        "--json",
        "--output", out_file,
        "--no-rewrite-rule-ids",
        "--quiet",
        js_dir,
    ]

    t0 = time.time()
    rc, out, err = run_cmd(cmd, timeout=120)
    elapsed = time.time() - t0

    count = 0
    if os.path.exists(out_file):
        try:
            data = json.load(open(out_file))
            count = len(data.get("results", []))
        except Exception:
            pass

    status("semgrep", f"{count} SAST findings in {elapsed:.1f}s", ok=count > 0 or rc == 0)
    return ToolResult("semgrep", rc == 0, out_file, count, elapsed=elapsed)


# ══════════════════════════════════════════════════════════════════════════════
# HELPER
# ══════════════════════════════════════════════════════════════════════════════

MINIMAL_WORDLIST = """admin
api
login
register
dashboard
config
backup
test
debug
internal
v1
v2
graphql
swagger
redoc
metrics
health
status
actuator
.env
.git
robots.txt
sitemap.xml
crossdomain.xml
phpinfo.php
server-status
server-info
""".strip().splitlines()

def _write_minimal_wordlist(outdir: str) -> str:
    path = os.path.join(outdir, "_minimal_wordlist.txt")
    with open(path, "w") as f:
        f.write("\n".join(MINIMAL_WORDLIST))
    return path


def install_tools():
    """Print installation commands for all tools."""
    print(f"\n{BOLD}Tool Installation Guide{RST}\n")
    print(f"{Y}Go tools (requires Go 1.21+):{RST}")
    go_tools = [
        ("subfinder",   "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"),
        ("httpx",       "github.com/projectdiscovery/httpx/cmd/httpx@latest"),
        ("nuclei",      "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"),
        ("katana",      "github.com/projectdiscovery/katana/cmd/katana@latest"),
        ("gau",         "github.com/lc/gau/v2/cmd/gau@latest"),
        ("ffuf",        "github.com/ffuf/ffuf/v2@latest"),
        ("gobuster",    "github.com/OJ/gobuster/v3@latest"),
        ("dalfox",      "github.com/s0md3v/dalfox/v2@latest"),
        ("amass",       "github.com/owasp-amass/amass/v4/...@master"),
        ("waybackurls", "github.com/tomnomnom/waybackurls@latest"),
    ]
    for name, pkg in go_tools:
        installed = G + "✓" + RST if check_tool(name) else R + "✗" + RST
        print(f"  [{installed}] go install {pkg}")

    print(f"\n{Y}Python tools (pip):{RST}")
    py_tools = [
        ("arjun",    "arjun"),
        ("sqlmap",   "sqlmap"),
        ("semgrep",  "semgrep"),
    ]
    for name, pkg in py_tools:
        installed = G + "✓" + RST if check_tool(name) else R + "✗" + RST
        print(f"  [{installed}] pip install {pkg}")

    print(f"\n{Y}System packages:{RST}")
    sys_tools = ["nmap", "masscan", "nikto", "whatweb"]
    for t in sys_tools:
        installed = G + "✓" + RST if check_tool(t) else R + "✗" + RST
        print(f"  [{installed}] apt install {t}")

    print(f"\n{Y}Optional (recommended):{RST}")
    print("  feroxbuster: cargo install feroxbuster")
    print("  trufflehog:  brew install trufflehog  OR  go install github.com/trufflesecurity/trufflehog/v3@latest")
    print("  SecLists:    git clone https://github.com/danielmiessler/SecLists ~/SecLists")
    print()


# ══════════════════════════════════════════════════════════════════════════════
# ORCHESTRATOR
# ══════════════════════════════════════════════════════════════════════════════

def run_all_tools(
    base_url: str,
    outdir: str,
    token: Optional[str] = None,
    proxy: Optional[str] = None,
    cookies: Optional[str] = None,
    passive_only: bool = False,
    aggressive: bool = False,
    only: Optional[List[str]] = None,
    verbose: bool = False,
) -> List[ToolResult]:
    print(f"\n{B}{BOLD}[External Tools Phase]{RST}")

    os.makedirs(outdir, exist_ok=True)
    results = []
    parsed = urllib.parse.urlparse(base_url)
    domain = parsed.hostname or base_url
    host = parsed.hostname

    def should_run(name: str) -> bool:
        if only:
            return name in only
        return True

    # ── Passive / OSINT ─────────────────────────────────────────────────────
    if should_run("subfinder"):
        r = run_subfinder(domain, outdir, verbose=verbose)
        results.append(r)

    if should_run("amass"):
        r = run_amass(domain, outdir, passive=True, verbose=verbose)
        results.append(r)

    if should_run("gau"):
        r = run_gau(domain, outdir, verbose=verbose)
        results.append(r)

    if passive_only:
        return results

    # ── Active Recon ─────────────────────────────────────────────────────────
    if should_run("nmap") and host:
        r = run_nmap(host, outdir, aggressive=aggressive, verbose=verbose)
        results.append(r)

    if should_run("whatweb"):
        r = run_whatweb(base_url, outdir, verbose=verbose)
        results.append(r)

    if should_run("katana"):
        r = run_katana(base_url, outdir, proxy=proxy, verbose=verbose)
        results.append(r)

    # ── Fuzzing ──────────────────────────────────────────────────────────────
    if should_run("ffuf"):
        for mode in ["dirs", "files", "api"]:
            r = run_ffuf(base_url, outdir, mode=mode, proxy=proxy, cookies=cookies, verbose=verbose)
            results.append(r)

    if should_run("feroxbuster"):
        r = run_feroxbuster(base_url, outdir, proxy=proxy, cookies=cookies, verbose=verbose)
        results.append(r)

    # ── Parameter Discovery ───────────────────────────────────────────────────
    if should_run("arjun"):
        r = run_arjun(base_url, outdir, proxy=proxy, cookies=cookies, verbose=verbose)
        results.append(r)

    # ── Vulnerability Scanning ────────────────────────────────────────────────
    if should_run("nuclei"):
        r = run_nuclei(base_url, outdir, proxy=proxy, verbose=verbose)
        results.append(r)

        # Also pipe crawled URLs to nuclei
        katana_out = os.path.join(outdir, "katana_crawl.txt")
        if os.path.exists(katana_out):
            r2 = run_nuclei_pipes(katana_out, outdir, proxy=proxy, verbose=verbose)
            results.append(r2)

    if should_run("nikto"):
        r = run_nikto(base_url, outdir, proxy=proxy, verbose=verbose)
        results.append(r)

    # ── Injection Testing ─────────────────────────────────────────────────────
    if should_run("sqlmap"):
        # Try common injectable params
        test_urls = [
            f"{base_url}/api/v1/users?id=1",
            f"{base_url}/api/search?q=test",
            f"{base_url}/api/v1/products?category=1",
        ]
        for u in test_urls[:1]:
            r = run_sqlmap(u, outdir, proxy=proxy, cookies=cookies, verbose=verbose)
            results.append(r)

    if should_run("dalfox"):
        r = run_dalfox(base_url, outdir, proxy=proxy, cookies=cookies, verbose=verbose)
        results.append(r)

    # ── Secret Scanning ───────────────────────────────────────────────────────
    if should_run("trufflehog"):
        r = run_trufflehog(outdir, outdir, verbose=verbose)
        results.append(r)

    # ── SAST on downloaded JS ─────────────────────────────────────────────────
    js_dir = os.path.join(outdir, "js_files")
    if should_run("semgrep") and os.path.exists(js_dir):
        r = run_semgrep_js(js_dir, outdir, verbose=verbose)
        results.append(r)

    # Summary
    total_findings = sum(r.findings_count for r in results)
    installed_ran = sum(1 for r in results if r.success or not r.error)
    not_installed = [r.tool for r in results if r.error and "not installed" in r.error]

    print(f"\n{G}[+]{RST} Tool run complete:")
    print(f"    {BOLD}{installed_ran}{RST} tools ran, {BOLD}{total_findings}{RST} total findings")
    if not_installed:
        print(f"    {Y}[missing]{RST} {', '.join(not_installed)}")
        print(f"    Run {BOLD}python3 tools.py --install{RST} for install commands")

    return results


# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="External Tool Orchestrator")
    parser.add_argument("target", nargs="?", help="Target URL (e.g. https://app.example.com)")
    parser.add_argument("-t", "--token",   help="Auth token")
    parser.add_argument("-o", "--output",  help="Output directory")
    parser.add_argument("--proxy",         help="HTTP proxy")
    parser.add_argument("--cookies",       help="Cookie string")
    parser.add_argument("--passive-only",  action="store_true")
    parser.add_argument("--aggressive",    action="store_true", help="Run nmap -A, deep scans")
    parser.add_argument("--only",          help="Comma-separated tools: nuclei,ffuf,sqlmap,...")
    parser.add_argument("--install",       action="store_true", help="Show tool installation commands")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    if args.install:
        install_tools()
        sys.exit(0)

    if not args.target:
        parser.print_help()
        sys.exit(1)

    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    host = urllib.parse.urlparse(args.target).hostname or "target"
    outdir = args.output or f"results_{host}_{ts}"
    os.makedirs(outdir, exist_ok=True)

    only_list = [x.strip() for x in args.only.split(",")] if args.only else None

    results = run_all_tools(
        base_url=args.target,
        outdir=outdir,
        token=args.token,
        proxy=args.proxy,
        cookies=args.cookies,
        passive_only=args.passive_only,
        aggressive=args.aggressive,
        only=only_list,
        verbose=args.verbose,
    )

    # Write results summary
    summary = [{
        "tool": r.tool, "success": r.success,
        "findings": r.findings_count, "output": r.output_file,
        "elapsed": round(r.elapsed, 2),
    } for r in results]
    with open(os.path.join(outdir, "tools_summary.json"), "w") as f:
        json.dump(summary, f, indent=2)

    print(f"\n{G}Results:{RST} {outdir}/")
    for r in results:
        icon = G + "✓" + RST if r.success else (Y + "!" + RST if not r.error else R + "✗" + RST)
        print(f"  [{icon}] {r.tool}: {r.findings_count} findings")
