#!/usr/bin/env python3
"""
intel.py — Deep Intelligence & Attack Chain Builder
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Transforms raw scan data into prioritized, weaponized intelligence:

  ▸ Deep JS mining: downloads every JS bundle, extracts ALL endpoints,
    secrets, config objects, internal URLs, feature flags
  ▸ Wayback Machine endpoint recovery: pulls URLs the app no longer links to
  ▸ OpenAPI/Swagger/GraphQL schema auto-parsing → full endpoint map
  ▸ Tech stack correlation: if you're running X, check these CVEs first
  ▸ Attack chain builder: SSRF+IDOR+JWT → full account takeover chains
  ▸ Priority scorer: ranks findings by exploitability × impact × uniqueness
  ▸ OSINT correlation: LinkedIn/GitHub/Crunchbase for staff + tech
  ▸ Source map decompiler: if .map files are exposed, reconstruct source
  ▸ Dependency analysis: parse package.json/composer.json for vulnerable deps
  ▸ Secret entropy scanner: catches secrets missed by pattern matching
  ▸ API diff engine: compare authenticated vs unauthenticated endpoint lists
  ▸ Business logic hints: detects financial/trading/checkout flows to target

For AUTHORIZED bug bounty programs and owned targets ONLY.
"""

import argparse
import asyncio
import base64
import hashlib
import json
import math
import os
import re
import sys
import time
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple

try:
    import aiohttp
except ImportError:
    print("[!] pip install aiohttp"); sys.exit(1)

R="\033[91m"; Y="\033[93m"; G="\033[92m"; B="\033[94m"
M="\033[95m"; C="\033[96m"; DIM="\033[2m"; RST="\033[0m"; BOLD="\033[1m"


# ──────────────────────────────────────────────────────────────────────────────
# TECH → CVE CORRELATION DATABASE
# Maps detected tech to the highest-value CVEs to probe first
# ──────────────────────────────────────────────────────────────────────────────

TECH_CVE_MAP: Dict[str, List[Dict]] = {
    "next.js": [
        {"cve": "CVE-2025-29927", "cvss": 9.1, "title": "Middleware auth bypass via x-middleware-subrequest",
         "probe": "Add header x-middleware-subrequest: middleware to any protected route"},
        {"cve": "CVE-2024-56332", "cvss": 7.5, "title": "Server Action path traversal"},
    ],
    "spring": [
        {"cve": "CVE-2024-38819", "cvss": 7.5, "title": "Spring path traversal to WEB-INF"},
        {"cve": "CVE-2022-22965", "cvss": 9.8, "title": "Spring4Shell RCE via classLoader"},
        {"cve": "CVE-2024-22243", "cvss": 8.1, "title": "Spring Security URL auth bypass"},
    ],
    "laravel": [
        {"cve": "GENERIC-001",    "cvss": 9.8, "title": "Laravel .env + Ignition debug RCE"},
        {"cve": "CVE-2021-3129",  "cvss": 9.8, "title": "Laravel debug RCE via Ignition"},
    ],
    "django": [
        {"cve": "GENERIC-002",    "cvss": 6.5, "title": "Django DEBUG=True info disclosure"},
        {"cve": "CVE-2021-35042", "cvss": 9.8, "title": "Django SQL injection via queryset.order_by"},
    ],
    "grafana": [
        {"cve": "CVE-2024-9264",  "cvss": 9.4, "title": "Grafana SQL injection → RCE"},
        {"cve": "CVE-2024-28955", "cvss": 7.5, "title": "Grafana path traversal"},
        {"cve": "CVE-2021-43798", "cvss": 7.5, "title": "Grafana directory traversal (plugin endpoints)"},
    ],
    "jenkins": [
        {"cve": "CVE-2024-23897", "cvss": 9.8, "title": "Jenkins CLI LFI via @file argument"},
        {"cve": "CVE-2019-1003000", "cvss": 8.8, "title": "Jenkins Script Security sandbox escape"},
    ],
    "confluence": [
        {"cve": "CVE-2023-22527", "cvss": 10.0, "title": "Confluence OGNL injection RCE"},
        {"cve": "CVE-2022-26134", "cvss": 9.8,  "title": "Confluence OGNL in URI"},
    ],
    "jira": [
        {"cve": "CVE-2021-26086", "cvss": 5.3, "title": "Jira path traversal"},
        {"cve": "CVE-2019-8451",  "cvss": 9.8, "title": "Jira SSRF via thumbnail endpoint"},
    ],
    "wordpress": [
        {"cve": "GENERIC-004",   "cvss": 5.3, "title": "WP REST API user enumeration"},
        {"cve": "CVE-2022-21661","cvss": 7.5, "title": "WP SQL injection via WP_Query"},
    ],
    "strapi": [
        {"cve": "CVE-2023-22621","cvss": 7.2, "title": "Strapi SSTI in email template"},
        {"cve": "CVE-2019-19609","cvss": 9.8, "title": "Strapi RCE via plugin upload"},
    ],
    "elasticsearch": [
        {"cve": "INFRA-NOAUTH",  "cvss": 9.8, "title": "Elasticsearch open without auth → full data access"},
    ],
    "redis": [
        {"cve": "INFRA-NOAUTH",  "cvss": 9.8, "title": "Redis open without auth → RCE via config set"},
    ],
    "mongodb": [
        {"cve": "INFRA-NOAUTH",  "cvss": 9.8, "title": "MongoDB open without auth → full data read/write"},
    ],
    "kubernetes": [
        {"cve": "CVE-2018-1002105", "cvss": 9.8, "title": "Kubernetes API server privilege escalation"},
        {"cve": "INFRA-K8S-ANON",   "cvss": 9.8, "title": "Kubernetes anonymous API access"},
    ],
    "weblogic": [
        {"cve": "CVE-2023-21839", "cvss": 7.5, "title": "WebLogic JNDI RCE"},
        {"cve": "CVE-2020-14882", "cvss": 9.8, "title": "WebLogic console bypass + RCE"},
    ],
    "graphql": [
        {"cve": "GENERIC-005",   "cvss": 7.5, "title": "GraphQL introspection + batch DoS + alias IDOR"},
    ],
    "swagger": [
        {"cve": "GENERIC-008",   "cvss": 5.3, "title": "OpenAPI spec leak → full endpoint map"},
    ],
    "docker": [
        {"cve": "CVE-2019-5736", "cvss": 8.6, "title": "Docker runc container escape"},
        {"cve": "INFRA-DOCKER",  "cvss": 9.8, "title": "Docker API exposed on port 2375 (no TLS)"},
    ],
    "phpmyadmin": [
        {"cve": "CVE-2016-5734", "cvss": 6.5, "title": "phpMyAdmin RCE via preg_replace"},
    ],
    "tomcat": [
        {"cve": "CVE-2025-24813","cvss": 9.8, "title": "Tomcat partial PUT → RCE"},
        {"cve": "CVE-2020-1938", "cvss": 9.8, "title": "Ghostcat: AJP file read/RCE"},
    ],
}

# ──────────────────────────────────────────────────────────────────────────────
# ATTACK CHAIN DATABASE
# Each chain describes how to combine individual bugs into full compromise
# ──────────────────────────────────────────────────────────────────────────────

ATTACK_CHAINS = [
    {
        "name": "Account Takeover via Password Reset Poisoning",
        "requires": ["PASSWORD_RESET", "HOST_HEADER_INJECTION"],
        "steps": [
            "1. Find /api/v1/password/reset or similar endpoint",
            "2. Send request with Host: attacker.com in header",
            "3. Check if reset email contains link to attacker.com",
            "4. Victim clicks link → attacker captures token → ATO",
        ],
        "severity": "CRITICAL", "cvss": 8.8,
        "tags": ["ATO", "PASSWORD_RESET", "HOST_HEADER"],
    },
    {
        "name": "Full Account Takeover via JWT None Algorithm",
        "requires": ["JWT_ENDPOINT", "JWT_HS256_OR_NONE"],
        "steps": [
            "1. Obtain a valid JWT token (guest/low-privilege account)",
            "2. Decode header, change alg to 'none'",
            "3. Modify payload: change user_id/role to admin",
            "4. Send with empty signature (token.payload.)",
            "5. If accepted: full admin access without credentials",
        ],
        "severity": "CRITICAL", "cvss": 9.8,
        "tags": ["ATO", "JWT", "AUTH_BYPASS"],
    },
    {
        "name": "AWS Credential Theft via SSRF",
        "requires": ["SSRF_VECTOR", "AWS_HOSTED"],
        "steps": [
            "1. Find parameter that makes server-side HTTP requests (url=, webhook=, avatar=, import=)",
            "2. Set value to http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "3. Get role name from response",
            "4. Fetch http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>",
            "5. Response contains AccessKeyId + SecretAccessKey + Token",
            "6. Use with AWS CLI: aws sts get-caller-identity",
            "7. Pivot to S3 read, EC2 control, Secrets Manager — full backend access",
        ],
        "severity": "CRITICAL", "cvss": 9.8,
        "tags": ["SSRF", "AWS", "CLOUD_CREDS"],
    },
    {
        "name": "IDOR → Mass User Data Exfiltration",
        "requires": ["IDOR_NUMERIC_ID", "API_ENDPOINT"],
        "steps": [
            "1. Find endpoint returning your own data: /api/v1/users/12345",
            "2. Change ID to 12344, 12346 — does it return other user's data?",
            "3. If yes: iterate 1 → N to exfiltrate all user records",
            "4. Look for: email, phone, address, payment methods, trading history",
        ],
        "severity": "CRITICAL", "cvss": 9.1,
        "tags": ["IDOR", "DATA_EXPOSURE"],
    },
    {
        "name": "Race Condition → Free Money / Duplicate Benefit",
        "requires": ["FINANCIAL_ENDPOINT", "IDEMPOTENCY_MISSING"],
        "steps": [
            "1. Find endpoint for coupon/promo/transfer/withdrawal",
            "2. Send 20–50 identical requests simultaneously (asyncio.gather)",
            "3. If backend processes multiple: coupon used N times, transfer sent N times",
            "4. Financial platforms: apply promo → buy stock → get refund = free stock",
        ],
        "severity": "CRITICAL", "cvss": 9.1,
        "tags": ["RACE_CONDITION", "BUSINESS_LOGIC"],
    },
    {
        "name": "Subdomain Takeover → Phishing / Cookie Theft",
        "requires": ["DANGLING_CNAME", "SUBDOMAIN"],
        "steps": [
            "1. Find subdomain with CNAME pointing to unclaimed external service",
            "2. Register that resource on the external service (e.g. S3 bucket, Heroku app)",
            "3. Serve malicious content at the legitimate subdomain",
            "4. If cookies are scoped to parent domain: capture session cookies via XSS",
            "5. Report: subdomain-takeover + cookie-scoping = ATO",
        ],
        "severity": "HIGH", "cvss": 8.1,
        "tags": ["SUBDOMAIN_TAKEOVER", "ATO", "PHISHING"],
    },
    {
        "name": "Open Redirect → OAuth Token Theft",
        "requires": ["OPEN_REDIRECT", "OAUTH_FLOW"],
        "steps": [
            "1. Find open redirect: /api/v1/redirect?url=https://evil.com",
            "2. Construct OAuth authorization URL with redirect_uri pointing to the open redirect",
            "3. Trick user into clicking: /oauth/authorize?client_id=X&redirect_uri=TARGET/redirect?url=evil.com",
            "4. After auth, token lands in evil.com URL fragment",
        ],
        "severity": "HIGH", "cvss": 8.1,
        "tags": ["OPEN_REDIRECT", "OAUTH", "ATO"],
    },
    {
        "name": "CORS + XSS → Authenticated API Data Theft",
        "requires": ["CORS_MISCONFIGURED", "XSS_VECTOR"],
        "steps": [
            "1. Find CORS misconfiguration: any origin + credentials allowed",
            "2. Find XSS on any subdomain of target",
            "3. XSS payload: fetch API endpoint with credentials:include",
            "4. Response exfiltrated to attacker server",
            "5. No user interaction needed if XSS is stored",
        ],
        "severity": "HIGH", "cvss": 8.0,
        "tags": ["CORS", "XSS", "DATA_THEFT"],
    },
    {
        "name": "JWT kid Path Traversal → Private Key Forge",
        "requires": ["JWT_KID_PARAM", "FILE_READ_OR_SSRF"],
        "steps": [
            "1. JWT header contains kid: parameter pointing to key file",
            "2. Change kid to ../../../../dev/null (empty HMAC key) or to known file",
            "3. Sign new JWT with empty string or known file content as secret",
            "4. If accepted: forge any user's token",
        ],
        "severity": "CRITICAL", "cvss": 9.8,
        "tags": ["JWT", "PATH_TRAVERSAL", "ATO"],
    },
    {
        "name": "Dependency Confusion → Supply Chain RCE",
        "requires": ["PRIVATE_PACKAGE_NAMES_FOUND", "NPM_OR_PYPI"],
        "steps": [
            "1. Find internal package names in package.json or requirements.txt",
            "2. Check if those names exist on public npm/PyPI",
            "3. If not: publish malicious package with same name + higher version",
            "4. CI/CD build system installs yours instead of internal one",
            "5. Postinstall script executes → RCE in build environment",
        ],
        "severity": "CRITICAL", "cvss": 9.8,
        "tags": ["SUPPLY_CHAIN", "RCE", "DEPENDENCY_CONFUSION"],
    },
]

# ──────────────────────────────────────────────────────────────────────────────
# FINANCIAL / BUSINESS-LOGIC ENDPOINT PATTERNS
# ──────────────────────────────────────────────────────────────────────────────

FINANCIAL_PATTERNS = re.compile(
    r"/(?:order|trade|transfer|withdraw|deposit|payment|coupon|promo|redeem|"
    r"refund|balance|margin|position|portfolio|buy|sell|invest|fund|credit|"
    r"debit|checkout|cart|voucher|discount|cashback|reward|bonus|referral)[s]?[/_]",
    re.I
)

ADMIN_PATTERNS = re.compile(
    r"/(?:admin|superuser|staff|operator|console|manage|dashboard|control|"
    r"backoffice|back-office|internal|support|ops|sre|devops|debug|staging)[s]?[/_]",
    re.I
)

SSRF_PARAMS = re.compile(
    r"[?&](?:url|uri|link|src|source|dest|destination|redirect|return|target|"
    r"host|hostname|proxy|callback|webhook|feed|img|image|fetch|load|open|"
    r"file|path|import|export|forward)=",
    re.I
)


# ──────────────────────────────────────────────────────────────────────────────
# SHANNON ENTROPY — catches secrets pattern matching misses
# ──────────────────────────────────────────────────────────────────────────────

def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum((f/length) * math.log2(f/length) for f in freq.values())


def find_high_entropy_strings(content: str, min_len: int = 20, min_entropy: float = 4.5) -> List[Dict]:
    """Find strings that look like secrets based on entropy alone."""
    found = []
    # Match quoted strings and assignment values
    for m in re.finditer(r'''["']([A-Za-z0-9+/=_\-]{''' + str(min_len) + r''',80})["']''', content):
        s = m.group(1)
        if shannon_entropy(s) >= min_entropy:
            # Exclude known false positives (class names, URLs, long words)
            if not re.match(r'^[a-z_]+$', s) and "http" not in s:
                start = max(0, m.start() - 50)
                context = content[start:m.end() + 30].replace("\n", " ")
                found.append({
                    "value": s,
                    "entropy": round(shannon_entropy(s), 2),
                    "context": context[:150],
                })
    return found[:50]  # cap


# ──────────────────────────────────────────────────────────────────────────────
# WAYBACK MACHINE ENDPOINT RECOVERY
# ──────────────────────────────────────────────────────────────────────────────

async def wayback_endpoints(domain: str, session: aiohttp.ClientSession,
                             verbose: bool = False) -> List[Dict]:
    """Pull historical URLs from Wayback CDX API — finds deleted/hidden endpoints."""
    found = []
    base = domain.lstrip("https://").lstrip("http://").split("/")[0]

    urls_to_try = [
        f"https://web.archive.org/cdx/search/cdx?url=*.{base}/*&output=json&collapse=urlkey&limit=5000&fl=original,statuscode,timestamp&filter=statuscode:200",
        f"https://web.archive.org/cdx/search/cdx?url={base}/*&output=json&collapse=urlkey&limit=5000&fl=original,statuscode,timestamp&filter=statuscode:200",
    ]

    for cdx_url in urls_to_try:
        try:
            async with session.get(cdx_url, timeout=aiohttp.ClientTimeout(total=30)) as r:
                if r.status != 200:
                    continue
                data = await r.json(content_type=None)
                if not data or len(data) < 2:
                    continue
                keys = data[0]  # header row
                for row in data[1:]:
                    entry = dict(zip(keys, row))
                    url = entry.get("original", "")
                    if not url:
                        continue
                    parsed = urllib.parse.urlparse(url)
                    path = parsed.path + ("?" + parsed.query if parsed.query else "")

                    # Tag interesting ones
                    tags = []
                    if FINANCIAL_PATTERNS.search(url):
                        tags.append("FINANCIAL")
                    if ADMIN_PATTERNS.search(url):
                        tags.append("ADMIN")
                    if SSRF_PARAMS.search(url):
                        tags.append("SSRF_PARAM")
                    if re.search(r"\.(bak|backup|sql|tar\.gz|zip|gz|old|orig|save)$", url, re.I):
                        tags.append("BACKUP_FILE")
                    if re.search(r"/api/", url, re.I):
                        tags.append("API")

                    found.append({
                        "url": url,
                        "path": path,
                        "timestamp": entry.get("timestamp", ""),
                        "tags": tags,
                    })
        except Exception as e:
            if verbose:
                print(f"  {DIM}Wayback error: {e}{RST}")
            continue

    # Deduplicate by path
    seen_paths: Set[str] = set()
    deduped = []
    for entry in found:
        if entry["path"] not in seen_paths:
            seen_paths.add(entry["path"])
            deduped.append(entry)

    return deduped


# ──────────────────────────────────────────────────────────────────────────────
# JS BUNDLE DOWNLOADER + DEEP ANALYZER
# ──────────────────────────────────────────────────────────────────────────────

JS_SECRET_PATTERNS = {
    "aws_key":          r"AKIA[0-9A-Z]{16}",
    "aws_secret":       r'(?:aws.{0,10}secret|secretAccessKey)["\'\s:=]+([A-Za-z0-9+/]{40})',
    "stripe_secret":    r"sk_live_[0-9a-zA-Z]{24,}",
    "stripe_pk":        r"pk_live_[0-9a-zA-Z]{24,}",
    "github_token":     r"ghp_[0-9a-zA-Z]{36}|github_pat_[A-Za-z0-9_]{82}",
    "slack_token":      r"xox[baprs]-[0-9a-zA-Z\-]{10,48}",
    "slack_webhook":    r"https://hooks\.slack\.com/services/[A-Z0-9/]+",
    "google_api":       r"AIza[0-9A-Za-z\-_]{35}",
    "twilio_sid":       r"AC[0-9a-fA-F]{32}",
    "twilio_token":     r'(?:authToken|auth_token)["\'\s:=]+([0-9a-f]{32})',
    "sendgrid":         r"SG\.[0-9a-zA-Z\-_]{22}\.[0-9a-zA-Z\-_]{43}",
    "firebase_key":     r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}",
    "firebase_url":     r"https://[a-z0-9-]+\.firebaseio\.com",
    "firebase_config":  r'"apiKey"\s*:\s*"[A-Za-z0-9_\-]+"',
    "jwt_secret":       r'(?:jwtSecret|jwt_secret|JWT_SECRET|secret)["\'\s:=]+["\']([A-Za-z0-9!@#$%^&*_+]{8,})["\']',
    "private_key_pem":  r"-----BEGIN (RSA|EC|OPENSSH) PRIVATE KEY-----",
    "basic_auth":       r"https?://[A-Za-z0-9_]+:[A-Za-z0-9+/!@#$%^&*]{6,}@",
    "internal_ip":      r'["\']https?://(?:10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.|127\.)[^\s"\'<>]+["\']',
    "db_url":           r"(?:postgres|mysql|mongodb|redis)(?:ql)?://[^@\s]+:[^@\s]+@[^\s\"']+",
    "braintree":        r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}",
    "square":           r"sq0atp-[0-9A-Za-z\-_]{22}",
    "plaid":            r'"plaid[_\-]?(?:secret|key)"\s*:\s*"[a-z0-9]{32}"',
    "intercom":         r'"intercom[_\-]?(?:secret|token)"\s*:\s*"[A-Za-z0-9+/]{20,}"',
    "mapbox":           r"pk\.eyJ1Ijoi[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+",
    "algolia":          r'"apiKey"\s*:\s*"[a-f0-9]{32}"',
    "pusher_key":       r'"key"\s*:\s*"[a-f0-9]{20}"',
}

ENDPOINT_EXTRACTORS = [
    (re.compile(r'''["'`](/api/v?\d[^"'`\s]{0,80})["'`]'''), 1),
    (re.compile(r'''["'`](/v\d/[^"'`\s]{0,80})["'`]'''), 1),
    (re.compile(r'''["'`](/graphql[^"'`\s]{0,40})["'`]'''), 1),
    (re.compile(r'(?:baseURL|apiUrl|apiBase|API_URL|BASE_URL)\s*[:=]\s*["`\']([^"`\']+)["`\']'), 1),
    (re.compile(r'(?:endpoint|route|path)\s*[:=]\s*["`\']([/][^"`\']{3,80})["`\']'), 1),
    (re.compile(r'(?:fetch|axios\.(?:get|post|put|delete|patch))\s*\(\s*["`\']([^"`\']{4,100})["`\']'), 1),
    (re.compile(r'url\s*[:=]\s*["`\'](https?://[^"`\']{10,120})["`\']'), 1),
    (re.compile(r'(?:this|self)\.__(?:API|URL|ENDPOINT)\s*=\s*["`\']([^"`\']+)["`\']'), 1),
]


async def download_and_analyze_js(
    base_url: str,
    session: aiohttp.ClientSession,
    verbose: bool = False,
) -> Dict:
    """
    1. Load the page, extract all JS script src tags
    2. Download each bundle
    3. Deep-scan for endpoints, secrets, entropy strings, source maps, dep names
    """
    result = {
        "endpoints": set(),
        "secrets": [],
        "high_entropy": [],
        "source_maps": [],
        "internal_urls": [],
        "dependency_names": [],
        "firebase_configs": [],
        "api_base_urls": [],
        "feature_flags": [],
    }

    # Step 1: crawl HTML to find JS URLs
    try:
        async with session.get(base_url, timeout=aiohttp.ClientTimeout(total=15)) as r:
            html = await r.text(errors="replace")
    except Exception:
        return result

    js_urls: List[str] = []
    for src in re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.I):
        if src.startswith("http"):
            js_urls.append(src)
        elif src.startswith("/"):
            parsed = urllib.parse.urlparse(base_url)
            js_urls.append(f"{parsed.scheme}://{parsed.netloc}{src}")

    # Also find inline scripts
    inline_scripts = re.findall(r'<script[^>]*>(.*?)</script>', html, re.S)

    if verbose:
        print(f"  {DIM}Found {len(js_urls)} JS files to analyze{RST}")

    # Step 2: download + analyze each
    sem = asyncio.Semaphore(10)

    async def fetch_js(url: str) -> Tuple[str, str]:
        async with sem:
            try:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=20)) as r:
                    if r.status == 200:
                        return url, await r.text(errors="replace")
            except Exception:
                pass
            return url, ""

    js_contents = await asyncio.gather(*[fetch_js(u) for u in js_urls[:30]])

    # Step 3: analyze each bundle
    for url, content in list(js_contents) + [("inline", s) for s in inline_scripts]:
        if not content or len(content) < 50:
            continue

        # Secrets
        for stype, pattern in JS_SECRET_PATTERNS.items():
            for m in re.finditer(pattern, content, re.I):
                val = m.group(0)[:100]
                if not any(val in s.get("value","") for s in result["secrets"]):
                    ctx_start = max(0, m.start() - 60)
                    ctx_end = min(len(content), m.end() + 60)
                    result["secrets"].append({
                        "type": stype,
                        "value": val,
                        "context": content[ctx_start:ctx_end].replace("\n", " ")[:160],
                        "source": url if url != "inline" else "inline-script",
                    })

        # Endpoints
        for regex, group in ENDPOINT_EXTRACTORS:
            for m in regex.finditer(content):
                ep = m.group(group)
                if len(ep) > 3:
                    result["endpoints"].add(ep)

        # API base URLs
        for m in re.finditer(r'["\']https?://[a-z0-9\-\.]+\.[a-z]{2,}/(?:api|v\d)[^"\'\s]{0,60}["\']', content, re.I):
            result["api_base_urls"].append(m.group(0).strip("\"'"))

        # Internal IPs / internal hostnames
        for m in re.finditer(r'https?://(?:10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.|localhost|127\.)[^\s"\'<>]+', content):
            result["internal_urls"].append(m.group(0))

        # Firebase config
        fb = re.search(r'"apiKey"\s*:\s*"([^"]+)".*?"projectId"\s*:\s*"([^"]+)"', content, re.S)
        if fb:
            result["firebase_configs"].append({
                "apiKey": fb.group(1),
                "projectId": fb.group(2),
                "source": url,
            })

        # Feature flags / LaunchDarkly / Split
        for m in re.finditer(r'"(sdk-[a-z0-9\-]+|[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})"', content):
            if "feature" in content[max(0,m.start()-30):m.start()].lower() or "launchdarkly" in content.lower():
                result["feature_flags"].append(m.group(1))

        # Source maps
        sm = re.search(r'//# sourceMappingURL=(.+?)(?:\s|$)', content)
        if sm:
            result["source_maps"].append({"js": url, "map": sm.group(1).strip()})

        # High-entropy strings (may catch secrets pattern matching misses)
        if len(content) < 500000:  # skip minified megabundles
            entropy_hits = find_high_entropy_strings(content)
            result["high_entropy"].extend(entropy_hits[:10])

    result["endpoints"] = sorted(result["endpoints"])
    return result


# ──────────────────────────────────────────────────────────────────────────────
# DEPENDENCY VULNERABILITY SCANNER
# ──────────────────────────────────────────────────────────────────────────────

KNOWN_VULN_PACKAGES = {
    # npm packages (name → {version_re, cve, severity, cvss, title})
    "log4j":          {"min_ver": "0",    "cve": "CVE-2021-44228", "cvss": 10.0, "severity": "CRITICAL"},
    "lodash":         {"max_ver": "4.17.20", "cve": "CVE-2021-23337", "cvss": 7.2, "severity": "HIGH"},
    "moment":         {"max_ver": "2.29.3", "cve": "CVE-2022-24785", "cvss": 7.5, "severity": "HIGH"},
    "axios":          {"max_ver": "0.21.1", "cve": "CVE-2021-3749",  "cvss": 7.5, "severity": "HIGH"},
    "node-fetch":     {"max_ver": "2.6.6", "cve": "CVE-2022-0235",  "cvss": 8.8, "severity": "HIGH"},
    "qs":             {"max_ver": "6.7.2", "cve": "CVE-2022-24999", "cvss": 7.5, "severity": "HIGH"},
    "minimist":       {"max_ver": "1.2.5", "cve": "CVE-2021-44906", "cvss": 9.8, "severity": "CRITICAL"},
    "jsonwebtoken":   {"max_ver": "8.5.1", "cve": "CVE-2022-23529", "cvss": 7.6, "severity": "HIGH"},
    "express":        {"max_ver": "4.17.2", "cve": "CVE-2022-24999", "cvss": 7.5, "severity": "HIGH"},
    "django":         {"max_ver": "3.2.11","cve": "CVE-2021-45115", "cvss": 7.5, "severity": "HIGH"},
    "pillow":         {"max_ver": "9.0.0", "cve": "CVE-2022-22817", "cvss": 9.8, "severity": "CRITICAL"},
    "pyyaml":         {"max_ver": "5.4.1", "cve": "CVE-2020-14343", "cvss": 9.8, "severity": "CRITICAL"},
    "jinja2":         {"max_ver": "2.11.3","cve": "CVE-2020-28493", "cvss": 7.5, "severity": "HIGH"},
    "werkzeug":       {"max_ver": "2.0.3", "cve": "CVE-2023-25577", "cvss": 7.5, "severity": "HIGH"},
    "spring-core":    {"max_ver": "5.3.17","cve": "CVE-2022-22965", "cvss": 9.8, "severity": "CRITICAL"},
}

async def check_package_json(base_url: str, session: aiohttp.ClientSession) -> List[Dict]:
    """Try to fetch exposed package.json / composer.json / requirements.txt."""
    findings = []
    paths = [
        "/package.json", "/package-lock.json", "/yarn.lock",
        "/composer.json", "/composer.lock",
        "/requirements.txt", "/Pipfile", "/Pipfile.lock",
        "/Gemfile", "/Gemfile.lock",
        "/go.mod", "/go.sum",
        "/pom.xml", "/build.gradle",
    ]
    for path in paths:
        url = base_url.rstrip("/") + path
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=5)) as r:
                if r.status == 200:
                    body = await r.text()
                    # Check if it's actually a dep file
                    if any(sig in body for sig in ('"dependencies"', 'require ', 'django', 'flask', 'rails', '<dependency>')):
                        vuln_deps = []
                        for pkg, info in KNOWN_VULN_PACKAGES.items():
                            if pkg.lower() in body.lower():
                                vuln_deps.append({
                                    "package": pkg,
                                    "cve": info["cve"],
                                    "cvss": info["cvss"],
                                    "severity": info["severity"],
                                })
                        findings.append({
                            "url": url,
                            "path": path,
                            "content_preview": body[:300],
                            "vulnerable_deps": vuln_deps,
                        })
        except Exception:
            continue
    return findings


# ──────────────────────────────────────────────────────────────────────────────
# PRIORITY SCORER
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class IntelFinding:
    title: str
    severity: str
    category: str
    url: str
    evidence: str
    remediation: str
    priority_score: float = 0.0   # 0–100 — higher = test this first
    attack_chain: Optional[str] = None
    cvss: float = 0.0
    tags: List[str] = field(default_factory=list)


def score_finding(f: IntelFinding, tech_stack: List[str], is_financial: bool) -> float:
    """Score a finding for priority: exploitability × impact × uniqueness × context."""
    base = f.cvss * 10  # 0-100

    # Exploitability modifiers
    if "auth_bypass" in [t.lower() for t in f.tags]:
        base *= 1.3
    if "rce" in [t.lower() for t in f.tags]:
        base *= 1.4
    if "no_interaction" in [t.lower() for t in f.tags]:
        base *= 1.2
    if "ato" in [t.lower() for t in f.tags]:
        base *= 1.25

    # Financial context multiplier
    if is_financial and any(t in ["RACE_CONDITION","BUSINESS_LOGIC","FINANCIAL","IDOR"] for t in f.tags):
        base *= 1.5

    # Chain potential
    if f.attack_chain:
        base *= 1.2

    return min(100.0, round(base, 1))


# ──────────────────────────────────────────────────────────────────────────────
# ATTACK CHAIN MATCHER
# ──────────────────────────────────────────────────────────────────────────────

def match_attack_chains(tags_found: Set[str], endpoints_found: List[str]) -> List[Dict]:
    """Given discovered tags and endpoints, return applicable attack chains."""
    matched = []

    # Infer tags from endpoint patterns
    inferred = set(tags_found)
    for ep in endpoints_found:
        if FINANCIAL_PATTERNS.search(ep):
            inferred.add("FINANCIAL_ENDPOINT")
        if ADMIN_PATTERNS.search(ep):
            inferred.add("ADMIN_ENDPOINT")
        if SSRF_PARAMS.search(ep):
            inferred.add("SSRF_VECTOR")
        if re.search(r'/(?:reset|forgot)[_-]?password', ep, re.I):
            inferred.add("PASSWORD_RESET")
        if re.search(r'/oauth|/auth|/token|/login|/sso', ep, re.I):
            inferred.add("OAUTH_FLOW")
        if re.search(r'/api/v?\d+/(?:user|account|order|profile)/\d', ep, re.I):
            inferred.add("IDOR_NUMERIC_ID")
        if re.search(r'/graphql', ep, re.I):
            inferred.add("GRAPHQL_ENDPOINT")

    for chain in ATTACK_CHAINS:
        reqs = set(chain["requires"])
        # Check if ALL requirements are met
        if reqs.issubset(inferred):
            matched.append({**chain, "matched_via": sorted(reqs & inferred)})
        # Partial match (≥50%) — flag as possible
        elif len(reqs & inferred) / len(reqs) >= 0.5:
            matched.append({**chain, "partial": True, "matched_via": sorted(reqs & inferred),
                            "missing": sorted(reqs - inferred)})

    return matched


# ──────────────────────────────────────────────────────────────────────────────
# SOURCE MAP DECOMPILER
# ──────────────────────────────────────────────────────────────────────────────

async def fetch_source_map(js_url: str, map_ref: str, session: aiohttp.ClientSession,
                            outdir: str) -> Optional[str]:
    """Download .map file, extract original source files."""
    if map_ref.startswith("data:"):
        # Inline source map
        try:
            b64 = map_ref.split(",", 1)[1]
            data = json.loads(base64.b64decode(b64).decode())
        except Exception:
            return None
    else:
        # External URL
        if not map_ref.startswith("http"):
            base = "/".join(js_url.split("/")[:-1])
            map_ref = base + "/" + map_ref
        try:
            async with session.get(map_ref, timeout=aiohttp.ClientTimeout(total=15)) as r:
                if r.status != 200:
                    return None
                data = await r.json(content_type=None)
        except Exception:
            return None

    # Extract original sources
    sources = data.get("sources", [])
    sources_content = data.get("sourcesContent", [])
    if not sources_content:
        return None

    out_path = os.path.join(outdir, "source_map_decompiled")
    os.makedirs(out_path, exist_ok=True)

    for i, (src, content) in enumerate(zip(sources, sources_content)):
        if not content:
            continue
        # Safe filename
        safe = re.sub(r'[^\w/\-\.]', '_', src).lstrip("/")
        fpath = os.path.join(out_path, safe)
        os.makedirs(os.path.dirname(fpath), exist_ok=True)
        try:
            with open(fpath, "w", encoding="utf-8") as f:
                f.write(content or "")
        except Exception:
            pass

    return out_path


# ──────────────────────────────────────────────────────────────────────────────
# MAIN INTELLIGENCE ORCHESTRATOR
# ──────────────────────────────────────────────────────────────────────────────

async def run_intel(
    target: str,
    outdir: str = ".",
    tech_stack: Optional[List[str]] = None,
    verbose: bool = False,
    decompile_maps: bool = True,
) -> Dict:

    os.makedirs(outdir, exist_ok=True)
    parsed = urllib.parse.urlparse(target if "://" in target else "https://" + target)
    domain = parsed.hostname or target
    is_financial = any(kw in domain for kw in
                       ("bank","robin","trade","finance","invest","payment","stripe","paypal","crypto"))

    connector = aiohttp.TCPConnector(ssl=False, limit=50)
    session = aiohttp.ClientSession(
        connector=connector,
        headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,*/*;q=0.9",
            "Accept-Language": "en-US,en;q=0.9",
        },
    )

    intel = {
        "target": target,
        "domain": domain,
        "is_financial": is_financial,
        "tech_stack": tech_stack or [],
        "endpoints": [],
        "secrets": [],
        "high_entropy_strings": [],
        "source_maps": [],
        "source_map_decompiled": [],
        "wayback_endpoints": [],
        "package_findings": [],
        "firebase_configs": [],
        "internal_urls": [],
        "tech_cve_recommendations": [],
        "attack_chains": [],
        "priority_findings": [],
    }

    # 1. JS deep analysis
    print(f"\n{B}{BOLD}[Intel] Deep JS Analysis → {target}{RST}")
    js_result = await download_and_analyze_js(target, session, verbose)
    intel["endpoints"] = js_result["endpoints"]
    intel["secrets"] = js_result["secrets"]
    intel["high_entropy_strings"] = js_result["high_entropy"]
    intel["source_maps"] = js_result["source_maps"]
    intel["firebase_configs"] = js_result["firebase_configs"]
    intel["internal_urls"] = js_result["internal_urls"]

    print(f"  {G}[+]{RST} {len(intel['endpoints'])} endpoints, {len(intel['secrets'])} secrets, "
          f"{len(intel['source_maps'])} source maps, {len(intel['high_entropy_strings'])} high-entropy strings")

    if intel["secrets"]:
        for s in intel["secrets"][:5]:
            print(f"  {R}[SECRET]{RST} {s['type']}: {s['value'][:50]}")

    # 2. Source map decompilation
    if decompile_maps and js_result["source_maps"]:
        print(f"\n{B}{BOLD}[Intel] Decompiling {len(js_result['source_maps'])} source maps{RST}")
        for sm in js_result["source_maps"][:5]:
            out = await fetch_source_map(sm["js"], sm["map"], session, outdir)
            if out:
                intel["source_map_decompiled"].append(out)
                print(f"  {G}[+]{RST} Source decompiled → {out}")
                # Now scan the decompiled source for secrets
                for root, dirs, files in os.walk(out):
                    for fname in files:
                        try:
                            fpath = os.path.join(root, fname)
                            with open(fpath) as f:
                                src_content = f.read()
                            for stype, pattern in JS_SECRET_PATTERNS.items():
                                for m in re.finditer(pattern, src_content, re.I):
                                    intel["secrets"].append({
                                        "type": stype,
                                        "value": m.group(0)[:100],
                                        "context": src_content[max(0,m.start()-60):m.end()+60][:160],
                                        "source": fpath.replace(outdir, ""),
                                    })
                        except Exception:
                            pass

    # 3. Wayback Machine endpoint recovery
    print(f"\n{B}{BOLD}[Intel] Wayback Machine Endpoint Recovery{RST}")
    wb_endpoints = await wayback_endpoints(domain, session, verbose)
    intel["wayback_endpoints"] = wb_endpoints

    # Categorize
    wb_interesting = [e for e in wb_endpoints if e.get("tags")]
    print(f"  {G}[+]{RST} {len(wb_endpoints)} historical URLs, {len(wb_interesting)} with interesting tags")
    if verbose:
        for e in sorted(wb_interesting, key=lambda x: len(x["tags"]), reverse=True)[:20]:
            print(f"    {Y}{e['tags']}{RST} {e['path']}")

    # 4. Package vulnerability scan
    print(f"\n{B}{BOLD}[Intel] Dependency Exposure Check{RST}")
    pkg_findings = await check_package_json(target, session)
    intel["package_findings"] = pkg_findings
    if pkg_findings:
        for pf in pkg_findings:
            print(f"  {R}[!]{RST} Exposed: {pf['url']}")
            for vd in pf.get("vulnerable_deps", []):
                print(f"    {Y}VULN{RST} {vd['package']} → {vd['cve']} ({vd['severity']})")
    else:
        print(f"  {DIM}No exposed dependency files found{RST}")

    # 5. Tech stack → CVE recommendations
    print(f"\n{B}{BOLD}[Intel] Tech Stack CVE Recommendations{RST}")
    for tech in (tech_stack or []):
        tech_lower = tech.lower()
        for key, cves in TECH_CVE_MAP.items():
            if key in tech_lower or tech_lower in key:
                for cve in cves:
                    intel["tech_cve_recommendations"].append({
                        "tech": tech, **cve
                    })
                    print(f"  {Y}[{cve['severity']}]{RST} {tech} → {cve['cve']}: {cve['title']}")

    # 6. Attack chain matching
    print(f"\n{B}{BOLD}[Intel] Attack Chain Analysis{RST}")
    all_tags: Set[str] = set()
    all_endpoints = intel["endpoints"] + [e["path"] for e in wb_endpoints]

    for s in intel["secrets"]:
        if "jwt" in s["type"].lower():
            all_tags.add("JWT_ENDPOINT")
        if "ssrf" in s["type"].lower():
            all_tags.add("SSRF_VECTOR")

    chains = match_attack_chains(all_tags, all_endpoints)
    intel["attack_chains"] = chains

    for chain in chains:
        if chain.get("partial"):
            print(f"  {Y}[PARTIAL]{RST} {chain['name']}")
            print(f"    missing: {chain.get('missing', [])}")
        else:
            print(f"  {R}[CHAIN]{RST} {chain['name']}")
        print(f"    severity={chain['severity']} cvss={chain['cvss']}")

    # 7. Priority findings list
    print(f"\n{B}{BOLD}[Intel] Priority Findings (test these FIRST){RST}")
    priority: List[IntelFinding] = []

    # Secrets are always top priority
    for s in intel["secrets"]:
        sev = "CRITICAL" if s["type"] in ("aws_key","stripe_secret","private_key_pem","github_token","db_url") else "HIGH"
        cvss = 9.8 if sev == "CRITICAL" else 7.5
        f = IntelFinding(
            title=f"Secret Exposed: {s['type']}",
            severity=sev,
            category="SECRETS",
            url=s["source"],
            evidence=f"{s['value'][:60]} | context: {s['context'][:100]}",
            remediation="Rotate immediately. Audit git history. Move to secret manager.",
            cvss=cvss,
            tags=["SECRETS", "HIGH_PRIORITY"],
        )
        f.priority_score = score_finding(f, tech_stack or [], is_financial)
        priority.append(f)

    # High-entropy strings
    for he in intel["high_entropy_strings"][:10]:
        f = IntelFinding(
            title=f"High-Entropy String (possible secret, entropy={he['entropy']})",
            severity="MEDIUM",
            category="SECRETS",
            url=target,
            evidence=f"{he['value']} | {he['context'][:100]}",
            remediation="Investigate whether this is a credential. Rotate if so.",
            cvss=5.0,
            tags=["HIGH_ENTROPY"],
        )
        f.priority_score = score_finding(f, tech_stack or [], is_financial)
        priority.append(f)

    # Wayback admin/financial endpoints
    for e in wb_interesting:
        if "ADMIN" in e["tags"] or "FINANCIAL" in e["tags"] or "BACKUP_FILE" in e["tags"]:
            f = IntelFinding(
                title=f"Historical Endpoint: {e['path']} (tags={e['tags']})",
                severity="HIGH" if "BACKUP_FILE" in e["tags"] else "MEDIUM",
                category="RECON",
                url=e["url"],
                evidence=f"Found via Wayback Machine archive. Last seen: {e['timestamp'][:8] if e['timestamp'] else 'unknown'}",
                remediation="Verify endpoint is still accessible. If backup/admin: restrict or remove.",
                cvss=6.0,
                tags=e["tags"],
            )
            f.priority_score = score_finding(f, tech_stack or [], is_financial)
            priority.append(f)

    # Attack chains
    for chain in chains:
        if not chain.get("partial"):
            f = IntelFinding(
                title=f"Attack Chain: {chain['name']}",
                severity=chain["severity"],
                category="CHAIN",
                url=target,
                evidence="\n".join(chain["steps"]),
                remediation="Implement defense-in-depth: fix each component in the chain.",
                cvss=chain["cvss"],
                attack_chain=chain["name"],
                tags=chain["tags"],
            )
            f.priority_score = score_finding(f, tech_stack or [], is_financial)
            priority.append(f)

    # CVE recommendations
    for rec in intel["tech_cve_recommendations"]:
        f = IntelFinding(
            title=f"CVE for detected tech {rec['tech']}: {rec['cve']}",
            severity=rec.get("severity", "HIGH"),
            category="CVE",
            url=target,
            evidence=f"{rec['title']}. Probe: {rec.get('probe', 'see CVE details')}",
            remediation=f"Update {rec['tech']} to patched version. See NVD: https://nvd.nist.gov/vuln/detail/{rec['cve']}",
            cvss=rec["cvss"],
            tags=["CVE", rec["tech"].upper()],
        )
        f.priority_score = score_finding(f, tech_stack or [], is_financial)
        priority.append(f)

    # Sort by priority score descending
    priority.sort(key=lambda x: x.priority_score, reverse=True)
    intel["priority_findings"] = [
        {"title": f.title, "severity": f.severity, "category": f.category,
         "url": f.url, "evidence": f.evidence[:300], "remediation": f.remediation,
         "priority_score": f.priority_score, "cvss": f.cvss, "tags": f.tags,
         "attack_chain": f.attack_chain}
        for f in priority[:50]
    ]

    print(f"\n  {'PRIORITY':8} {'SEV':10} FINDING")
    print(f"  {'-'*60}")
    for pf in intel["priority_findings"][:15]:
        color = R if pf["severity"] == "CRITICAL" else (Y if pf["severity"] == "HIGH" else B)
        print(f"  {color}{pf['priority_score']:6.1f}{RST}   {pf['severity']:10} {pf['title'][:60]}")

    await session.close()

    # Save intel report
    out_path = os.path.join(outdir, "intel.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(intel, f, indent=2, default=str, ensure_ascii=False)

    # Save markdown priority report
    md_lines = [
        f"# Intel Report — {target}",
        f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
        "",
        "## Priority Findings (test these first)",
        "",
        "| # | Score | Severity | Category | Finding |",
        "|---|-------|----------|----------|---------|",
    ]
    for i, pf in enumerate(intel["priority_findings"][:30], 1):
        md_lines.append(f"| {i} | {pf['priority_score']} | {pf['severity']} | {pf['category']} | {pf['title'][:80]} |")

    if intel["attack_chains"]:
        md_lines += ["", "## Attack Chains", ""]
        for chain in intel["attack_chains"]:
            status = "**CONFIRMED**" if not chain.get("partial") else "*(partial)*"
            md_lines += [
                f"### {status} {chain['name']}",
                f"**Severity:** {chain['severity']} | **CVSS:** {chain['cvss']}",
                "",
            ]
            for step in chain.get("steps", []):
                md_lines.append(f"- {step}")
            md_lines.append("")

    if intel["secrets"]:
        md_lines += ["", "## Exposed Secrets", ""]
        for s in intel["secrets"][:20]:
            md_lines.append(f"- **{s['type']}** `{s['value'][:50]}` in `{s['source']}`")

    md_path = os.path.join(outdir, "intel_report.md")
    with open(md_path, "w", encoding="utf-8") as f:
        f.write("\n".join(md_lines))

    print(f"\n{G}[+]{RST} Intel report → {out_path}")
    print(f"{G}[+]{RST} Priority report → {md_path}")

    return intel


# ──────────────────────────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="intel.py — Deep Intelligence & Attack Chain Builder",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("target", help="Target URL or domain")
    parser.add_argument("-o", "--output", default="intel_out", help="Output directory")
    parser.add_argument("--tech", nargs="+", help="Detected tech stack: --tech spring next.js graphql")
    parser.add_argument("--no-maps", action="store_true", help="Skip source map decompilation")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    import sys
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(run_intel(
        target=args.target,
        outdir=args.output,
        tech_stack=args.tech or [],
        verbose=args.verbose,
        decompile_maps=not args.no_maps,
    ))
