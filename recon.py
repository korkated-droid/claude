#!/usr/bin/env python3
"""
recon.py — Unauthenticated endpoint discovery & exploit-relevance triage.
Bug-bounty / authorised pentest use only.

Phases
  0. Passive   — robots.txt, sitemap, security.txt, .well-known
  1. Crawl     — spider HTML + extract from inline/external JS
  2. Wordlist  — categorised smart brute-force
  3. Spec      — Swagger/OpenAPI parse, GraphQL introspection
  4. Triage    — tag each endpoint with attack classes
  5. Enum      — account enumeration probes (timing + response diff)
  6. AuthMap   — which endpoints respond without a token
  7. Verbs     — OPTIONS / method fuzz on high-value paths
"""

import asyncio
import json
import re
import sys
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urljoin, urlparse, urlencode

try:
    import aiohttp
    from bs4 import BeautifulSoup
except ImportError:
    print("pip install aiohttp beautifulsoup4")
    sys.exit(1)

# ── colour ────────────────────────────────────────────────────────────────────────────
R  = "\033[0m";  BD = "\033[1m"
GN = "\033[1;32m"; RD = "\033[1;31m"; YL = "\033[1;33m"
CY = "\033[0;36m"; MG = "\033[1;35m"; BL = "\033[0;34m"

def hdr(t):   print(f"\n{YL}{'━'*70}\n  {t}\n{'━'*70}{R}")
def ok(t):    print(f"  {GN}[+]{R} {t}")
def info(t):  print(f"  {CY}[i]{R} {t}")
def step(t):  print(f"  {MG}[→]{R} {t}")
def warn(t):  print(f"  {YL}[!]{R} {t}")
def found(t): print(f"  {GN}{BD}[FOUND]{R} {t}")
def high(t):  print(f"  {RD}{BD}[HIGH]{R}  {t}")
def crit(t):  print(f"  {RD}{BD}[CRIT]{R}  {t}")


# ── Attack-class tags ────────────────────────────────────────────────────────────────
#  Each tag maps to a reason + suggested follow-up

TAGS = {
    "ACCOUNT_ENUM":   "Username/email existence oracle — timing or error diff",
    "IDOR":           "Object ID in path/param — try other users' IDs",
    "AUTH_BYPASS":    "Admin/privileged endpoint accessible without token",
    "INFO_DISC":      "Sensitive data / debug info exposed publicly",
    "INJECTION":      "Parameter accepted — test SQLi/NoSQLi/SSTI/XSS",
    "FILE_OPS":       "Upload/download/path — path traversal / SSRF",
    "BUSINESS_LOGIC": "Financial / coupon / quantity — negative values, races",
    "JWT":            "Token issue/refresh — alg:none, weak secret, confusion",
    "OAUTH":          "OAuth/OIDC flow — open redirect, CSRF, grant abuse",
    "ADMIN":          "Administrative surface — BFLA, mass assignment",
    "GRAPHQL":        "GraphQL — introspection, IDOR via resolver, mutations",
    "SSRF":           "URL/target param — server-side request forgery",
    "OPEN_REDIRECT":  "redirect/next/return_to param — open redirect chain",
    "MASS_ASSIGN":    "PUT/PATCH with JSON body — role/balance override",
    "RATE_LIMIT":     "Auth endpoint — check for brute-force protection",
    "CORS":           "CORS headers — credentialed cross-origin read",
}

# Pattern → tags mapping (path + param signals)
TAG_RULES: list[tuple[re.Pattern, list[str]]] = [
    (re.compile(r"(login|signin|sign-in|authenticate|auth/token)",      re.I),
     ["ACCOUNT_ENUM", "RATE_LIMIT", "JWT"]),
    (re.compile(r"(register|signup|sign-up|create.?account|join)",      re.I),
     ["ACCOUNT_ENUM", "RATE_LIMIT"]),
    (re.compile(r"(forgot.?pass|reset.?pass|password.?reset|recover)",  re.I),
     ["ACCOUNT_ENUM"]),
    (re.compile(r"(verify|confirm|activate|otp|2fa|mfa|totp)",          re.I),
     ["ACCOUNT_ENUM", "RATE_LIMIT"]),
    (re.compile(r"(oauth|oidc|sso|saml|connect/auth|authorize)",        re.I),
     ["OAUTH", "OPEN_REDIRECT"]),
    (re.compile(r"(token|refresh|jwt|access.?token)",                   re.I),
     ["JWT"]),
    (re.compile(r"/users?/\d",                                          re.I),
     ["IDOR"]),
    (re.compile(r"/users?/[0-9a-f-]{8,}",                               re.I),
     ["IDOR"]),
    (re.compile(r"/(users|accounts|members|profiles)$",                 re.I),
     ["IDOR", "ADMIN"]),
    (re.compile(r"/(admin|administrator|manage|management|backoffice|"
                r"dashboard|panel|console|cms|cp|staff|ops|internal)",  re.I),
     ["ADMIN", "AUTH_BYPASS", "INFO_DISC"]),
    (re.compile(r"/(debug|env|config|settings|info|status|health|ping|"
                r"version|phpinfo|server.?info|actuator)",              re.I),
     ["INFO_DISC"]),
    (re.compile(r"/(\.env|web\.config|appsettings\.json|config\.json|"
                r"database\.yml|secrets\.yml|credentials)",             re.I),
     ["INFO_DISC"]),
    (re.compile(r"/(swagger|openapi|api.?docs|redoc|graphiql)",         re.I),
     ["INFO_DISC"]),
    (re.compile(r"/graphql",                                             re.I),
     ["GRAPHQL", "INJECTION"]),
    (re.compile(r"/(upload|import|file|attachment|media|document|"
                r"image|avatar|export|download|backup)",                re.I),
     ["FILE_OPS", "SSRF"]),
    (re.compile(r"/(fetch|proxy|redirect|forward|request|curl|url)",   re.I),
     ["SSRF", "OPEN_REDIRECT"]),
    (re.compile(r"(redirect|return_to|next|callback|continue|"
                r"redirect_uri|return_url|RelayState)",                 re.I),
     ["OPEN_REDIRECT", "OAUTH"]),
    (re.compile(r"/(order|checkout|payment|invoice|cart|coupon|"
                r"discount|promo|voucher|billing|subscription|refund)", re.I),
     ["BUSINESS_LOGIC"]),
    (re.compile(r"/(search|query|filter|find|lookup|autocomplete)",     re.I),
     ["INJECTION"]),
    (re.compile(r"/(comment|review|feedback|message|post|note|"
                r"template|render|preview|report)",                     re.I),
     ["INJECTION"]),
    (re.compile(r"\.(php|asp|aspx|cfm|jsp|do|action)$",                re.I),
     ["INJECTION"]),
]

# Response-body signals → tags
BODY_TAG_RULES: list[tuple[re.Pattern, list[str]]] = [
    (re.compile(r"(jwt|bearer|access_token|refresh_token)",  re.I), ["JWT"]),
    (re.compile(r"(role|permission|privilege|admin|scope)",  re.I), ["ADMIN"]),
    (re.compile(r"(ssn|social.?security|credit.?card|cvv)",  re.I), ["INFO_DISC"]),
    (re.compile(r"(password|passwd|secret|api.?key|token)",  re.I), ["INFO_DISC"]),
    (re.compile(r"(error|exception|traceback|stack.?trace)", re.I), ["INFO_DISC"]),
    (re.compile(r"(db_host|db_pass|database|mongo|redis|"
                r"postgres|mysql|mssql)",                    re.I), ["INFO_DISC"]),
]

# Interesting response headers
HEADER_TAG_RULES: list[tuple[str, list[str]]] = [
    ("access-control-allow-origin",       ["CORS"]),
    ("access-control-allow-credentials",  ["CORS"]),
    ("x-powered-by",                      ["INFO_DISC"]),
    ("server",                            ["INFO_DISC"]),
    ("x-debug",                           ["INFO_DISC"]),
    ("x-aspnet-version",                  ["INFO_DISC"]),
]


# ── Categorised wordlist ────────────────────────────────────────────────────────────────────────────

WORDLIST: dict[str, list[str]] = {
    "auth": [
        "login", "signin", "sign-in", "logout", "sign-out",
        "register", "signup", "sign-up", "create-account",
        "forgot-password", "forgot_password", "reset-password", "reset_password",
        "password/reset", "password/forgot", "account/password",
        "verify", "verify-email", "confirm", "activate",
        "2fa", "mfa", "otp", "totp",
        "oauth/authorize", "oauth/token", "oauth/callback",
        "auth", "auth/login", "auth/register", "auth/token", "auth/refresh",
        "auth/logout", "auth/verify", "auth/callback",
        "sso", "saml/login", "saml/acs", "saml/metadata",
        "token", "token/refresh", "token/verify", "token/revoke",
        "session", "session/create", "session/destroy",
        "connect/authorize", "connect/token", "connect/userinfo",
        ".well-known/openid-configuration", ".well-known/oauth-authorization-server",
        ".well-known/jwks.json", "jwks.json", "certs", "keys",
    ],
    "users": [
        "users", "user", "me", "profile", "account", "accounts",
        "settings", "preferences", "notifications",
        "users/1", "users/2", "users/3",
        "api/v1/users", "api/v1/me", "api/v1/profile", "api/v1/account",
        "api/v2/users", "api/v2/me",
        "members", "member", "customer", "customers",
        "whoami", "current-user", "self",
        "api/v1/users/1", "api/v1/users/2", "api/v1/users/me",
    ],
    "admin": [
        "admin", "administrator", "admin/login", "admin/dashboard",
        "admin/users", "admin/settings", "admin/config",
        "admin/logs", "admin/reports", "admin/metrics",
        "manage", "management", "management/users",
        "dashboard", "panel", "control-panel", "cp",
        "backoffice", "back-office", "cms", "staff",
        "superadmin", "super-admin", "sysadmin",
        "internal", "internal/admin", "internal/users",
        "ops", "operations",
        "api/v1/admin", "api/v1/admin/users", "api/v1/admin/config",
        "api/v1/admin/delete_user", "api/v1/internal",
    ],
    "api_versioning": [
        "api", "api/v1", "api/v2", "api/v3", "api/v4",
        "v1", "v2", "v3",
        "api/v1/", "api/v2/",
        "rest", "rest/v1", "rest/v2",
        "service", "services", "api/latest", "api/beta",
    ],
    "info_disclosure": [
        ".env", ".env.local", ".env.production", ".env.backup",
        "config.json", "config.yml", "config.yaml", "config.php",
        "appsettings.json", "appsettings.Development.json",
        "web.config", "database.yml", "secrets.yml",
        "debug", "info", "status", "health", "ping", "version",
        "phpinfo.php", "phpinfo", "server-info", "server-status",
        "test.php", "test.asp", "info.php",
        ".git/config", ".git/HEAD", ".svn/entries",
        "Dockerfile", "docker-compose.yml", ".docker",
        "package.json", "composer.json", "Gemfile", "requirements.txt",
        ".htaccess", "nginx.conf", "apache.conf",
        "robots.txt", "sitemap.xml", "crossdomain.xml", "clientaccesspolicy.xml",
        "security.txt", ".well-known/security.txt",
        "humans.txt", "CHANGELOG.md", "CHANGELOG.txt", "README.md",
        "swagger.json", "swagger.yaml", "openapi.json", "openapi.yaml",
        "swagger-ui.html", "swagger-ui", "api-docs", "api-docs.json",
        "redoc", "redoc.html", "docs", "documentation",
        "graphql", "graphiql", "playground",
        "metrics", "prometheus", "grafana", "kibana",
    ],
    "spring_actuator": [
        "actuator", "actuator/health", "actuator/info", "actuator/env",
        "actuator/metrics", "actuator/mappings", "actuator/beans",
        "actuator/configprops", "actuator/loggers", "actuator/dump",
        "actuator/trace", "actuator/httptrace", "actuator/shutdown",
        "actuator/refresh", "actuator/restart",
        "manage/health", "manage/info",
    ],
    "files_media": [
        "upload", "uploads", "file", "files",
        "media", "images", "attachments", "documents",
        "export", "exports", "import", "imports",
        "download", "downloads", "backup", "backups",
        "report", "reports", "invoice", "invoices",
        "api/v1/upload", "api/v1/files", "api/v1/export",
        "avatar", "photo", "picture", "thumbnail",
        "static", "assets", "public", "resources",
    ],
    "business": [
        "orders", "order", "checkout", "cart",
        "payment", "payments", "pay", "billing",
        "invoice", "invoices", "subscription", "subscriptions",
        "coupon", "coupons", "discount", "promo", "voucher",
        "refund", "refunds", "transfer", "transfers",
        "withdraw", "deposit", "balance", "wallet",
        "products", "product", "catalog", "catalogue",
        "pricing", "plans", "tiers",
        "api/v1/orders", "api/v1/checkout", "api/v1/payment",
    ],
    "ssrf_sinks": [
        "fetch", "proxy", "redirect", "forward",
        "request", "url", "curl", "webhook", "webhooks",
        "callback", "notify", "notification",
        "ping", "check", "preview",
        "api/v1/fetch", "api/v1/proxy", "api/v1/webhook",
    ],
    "search": [
        "search", "find", "query", "lookup", "filter",
        "autocomplete", "suggest", "typeahead",
        "api/v1/search", "api/v2/search",
    ],
    "posts_content": [
        "posts", "post", "articles", "article",
        "blog", "blogs", "news", "content",
        "comments", "comment", "reviews", "review",
        "messages", "message", "chat", "notifications",
        "feed", "timeline", "activity",
        "api/v1/posts", "api/v1/articles", "api/v1/feed",
    ],
    "misc": [
        "logout", "signout",
        "error", "404", "500",
        "changelog", "release",
        "socket.io", "ws", "websocket",
        "graphql/schema",
    ],
}

# Flatten + deduplicate all paths
ALL_WORDLIST_PATHS = []
_seen: set[str] = set()
for cat_paths in WORDLIST.values():
    for p in cat_paths:
        p = p.strip("/")
        if p not in _seen:
            _seen.add(p)
            ALL_WORDLIST_PATHS.append(p)


# ── Data model ────────────────────────────────────────────────────────────────────────────

@dataclass
class Endpoint:
    url: str
    path: str
    status: int
    methods: list[str] = field(default_factory=list)
    tags: set[str] = field(default_factory=set)
    notes: list[str] = field(default_factory=list)
    requires_auth: Optional[bool] = None
    content_type: str = ""
    body_sample: str = ""
    source: str = ""          # crawl / wordlist / spec / passive
    redirect_to: str = ""


# ── HTTP client ────────────────────────────────────────────────────────────────────────────

class HTTP:
    def __init__(self, base: str, session: aiohttp.ClientSession):
        self.base = base.rstrip("/")
        self.session = session

    def abs(self, path: str) -> str:
        if path.startswith(("http://", "https://")):
            return path
        return urljoin(self.base + "/", path.lstrip("/"))

    async def get(self, path: str, *, headers: dict | None = None,
                  allow_redirects: bool = True, timeout: int = 10):
        hdrs = {"User-Agent": "Mozilla/5.0 (compatible; SecurityAudit/1.0)"}
        if headers:
            hdrs.update(headers)
        try:
            async with self.session.get(
                self.abs(path), headers=hdrs, ssl=False,
                allow_redirects=allow_redirects,
                timeout=aiohttp.ClientTimeout(total=timeout),
            ) as r:
                body = await r.text(errors="replace")
                return r.status, dict(r.headers), body, str(r.url)
        except Exception:
            return 0, {}, "", ""

    async def post(self, path: str, body: dict | None = None,
                   raw: bytes | None = None, ct: str | None = None,
                   headers: dict | None = None, timeout: int = 10):
        hdrs = {"User-Agent": "Mozilla/5.0 (compatible; SecurityAudit/1.0)"}
        if ct:
            hdrs["Content-Type"] = ct
        if headers:
            hdrs.update(headers)
        try:
            kw: dict = dict(headers=hdrs, ssl=False,
                            timeout=aiohttp.ClientTimeout(total=timeout))
            if raw is not None:
                kw["data"] = raw
            elif body is not None:
                kw["json"] = body
            async with self.session.post(self.abs(path), **kw) as r:
                b = await r.text(errors="replace")
                return r.status, dict(r.headers), b
        except Exception:
            return 0, {}, ""

    async def options(self, path: str) -> tuple[int, str]:
        try:
            async with self.session.options(
                self.abs(path), ssl=False,
                timeout=aiohttp.ClientTimeout(total=8),
                headers={"User-Agent": "Mozilla/5.0"},
            ) as r:
                allow = r.headers.get("Allow", r.headers.get("Access-Control-Allow-Methods", ""))
                return r.status, allow
        except Exception:
            return 0, ""


# ── Tag helpers ────────────────────────────────────────────────────────────────────────────

def tag_from_path(path: str) -> set[str]:
    tags: set[str] = set()
    for pat, t in TAG_RULES:
        if pat.search(path):
            tags.update(t)
    return tags


def tag_from_response(status: int, headers: dict, body: str) -> set[str]:
    tags: set[str] = set()
    for pat, t in BODY_TAG_RULES:
        if pat.search(body):
            tags.update(t)
    lhdrs = {k.lower(): v for k, v in headers.items()}
    for hname, t in HEADER_TAG_RULES:
        if hname in lhdrs:
            tags.update(t)
    acac = lhdrs.get("access-control-allow-credentials", "")
    acao = lhdrs.get("access-control-allow-origin", "")
    if acac.lower() == "true" and acao not in ("", "null"):
        tags.add("CORS")
    return tags


def interesting(status: int, body: str) -> bool:
    if status in (200, 201, 204):
        return True
    if status in (301, 302, 307, 308):
        return True
    if status == 403:
        return True
    if status == 405:
        return True
    return False


# ── Phase 0: Passive ────────────────────────────────────────────────────────────────────────

PASSIVE_PATHS = [
    "robots.txt", "sitemap.xml", "sitemap_index.xml",
    ".well-known/security.txt", "security.txt",
    "humans.txt", ".well-known/",
    "crossdomain.xml", "clientaccesspolicy.xml",
]

JS_ROUTE_PATTERN = re.compile(
    r"""['"` ](/(?:api|v\d+|graphql|auth|admin|login|user|account|oauth|token|"
    r"register|upload|search|checkout|order|payment)[^'"` \s<>{}]{0,80})['"` ]""",
    re.IGNORECASE,
)
SITEMAP_URL_PAT = re.compile(r"<loc>([^<]+)</loc>", re.IGNORECASE)


async def phase_passive(http: HTTP) -> list[str]:
    hdr("PHASE 0 — PASSIVE RECON (robots / sitemap / security.txt)")
    paths: list[str] = []

    for p in PASSIVE_PATHS:
        s, hdrs, body, _ = await http.get(p)
        if s == 200 and body:
            ok(f"/{p}  ({len(body)}b)")

            if "robots" in p:
                for line in body.splitlines():
                    line = line.strip()
                    if line.lower().startswith(("disallow:", "allow:")):
                        ep = line.split(":", 1)[1].strip()
                        if ep and ep != "/":
                            paths.append(ep.lstrip("/"))
                            info(f"  robots.txt path: {ep}")

            if "sitemap" in p:
                for u in SITEMAP_URL_PAT.findall(body):
                    parsed = urlparse(u)
                    if parsed.path and parsed.path != "/":
                        paths.append(parsed.path.lstrip("/"))

            if "security" in p:
                for line in body.splitlines():
                    if line.strip().startswith("Contact:"):
                        info(f"  security.txt: {line.strip()}")

    return list(dict.fromkeys(paths))


# ── Phase 1: Crawl ────────────────────────────────────────────────────────────────────────────

async def phase_crawl(http: HTTP, max_depth: int = 2,
                      max_pages: int = 80) -> list[str]:
    hdr("PHASE 1 — CRAWL (HTML + JS endpoint extraction)")
    base_host = urlparse(http.base).netloc
    visited: set[str] = set()
    queue: list[tuple[str, int]] = [("", 0)]
    found_paths: set[str] = set()

    while queue and len(visited) < max_pages:
        path, depth = queue.pop(0)
        abs_url = http.abs(path)
        if abs_url in visited:
            continue
        visited.add(abs_url)

        s, rhdrs, body, final_url = await http.get(path)
        if s == 0 or not body:
            continue

        ct = rhdrs.get("Content-Type", "")
        is_html = "html" in ct.lower()
        is_js   = "javascript" in ct.lower() or path.endswith(".js")

        if is_html and body:
            soup = BeautifulSoup(body, "html.parser")

            for tag in soup.find_all(True):
                for attr in ("href", "src", "action", "data-url", "data-href"):
                    val = tag.get(attr, "")
                    if not val or val.startswith(("#", "mailto:", "tel:", "javascript:")):
                        continue
                    p_url = urlparse(val)
                    if p_url.netloc and p_url.netloc != base_host:
                        continue
                    ep = p_url.path.strip("/")
                    if ep:
                        found_paths.add(ep)
                        if depth < max_depth and abs_url not in visited:
                            queue.append((ep, depth + 1))

            for tag in soup.find_all("script"):
                src = tag.get("src", "")
                if src and not urlparse(src).netloc:
                    ep = src.lstrip("/")
                    found_paths.add(ep)
                    if depth < max_depth:
                        queue.append((ep, depth + 1))

                inline = tag.string or ""
                for m in JS_ROUTE_PATTERN.finditer(inline):
                    found_paths.add(m.group(1).lstrip("/"))

        if is_js:
            for m in JS_ROUTE_PATTERN.finditer(body):
                ep = m.group(1).lstrip("/")
                found_paths.add(ep)
                info(f"  JS endpoint: /{ep}")

    ok(f"Crawl complete: {len(found_paths)} unique paths found")
    return list(found_paths)


# ── Phase 2: Wordlist brute-force ─────────────────────────────────────────────────────────────

SKIP_STATUSES = {404, 410, 400}

async def probe_path(http: HTTP, path: str, sem: asyncio.Semaphore,
                     results: list[Endpoint]):
    async with sem:
        s, hdrs, body, final_url = await http.get(path, allow_redirects=False)
        if s == 0 or s in SKIP_STATUSES:
            return
        if not interesting(s, body):
            return

        redirect = hdrs.get("Location", "")
        ep = Endpoint(
            url=http.abs(path),
            path=path,
            status=s,
            tags=tag_from_path(path) | tag_from_response(s, hdrs, body),
            content_type=hdrs.get("Content-Type", ""),
            body_sample=body[:400],
            source="wordlist",
            redirect_to=redirect,
        )
        results.append(ep)


async def phase_wordlist(http: HTTP,
                         extra_paths: list[str] | None = None,
                         concurrency: int = 40) -> list[Endpoint]:
    hdr("PHASE 2 — WORDLIST BRUTE-FORCE")
    all_paths = ALL_WORDLIST_PATHS.copy()
    if extra_paths:
        for p in extra_paths:
            p = p.strip("/")
            if p not in _seen:
                all_paths.append(p)

    sem = asyncio.Semaphore(concurrency)
    results: list[Endpoint] = []
    tasks = [probe_path(http, p, sem, results) for p in all_paths]

    step(f"Probing {len(tasks)} paths (concurrency={concurrency})")
    await asyncio.gather(*tasks)
    ok(f"Wordlist: {len(results)} endpoints returned interesting responses")
    return results


# ── Phase 3: Spec discovery ────────────────────────────────────────────────────────────────────────

SWAGGER_PATHS = [
    "swagger.json", "swagger.yaml", "openapi.json", "openapi.yaml",
    "api-docs", "api-docs.json", "api/docs", "api/swagger.json",
    "api/v1/swagger.json", "api/v2/swagger.json",
    "v1/swagger.json", "v2/swagger.json",
    "v1/api-docs", "v2/api-docs",
    "api/openapi.json", "api/v1/openapi.json",
    ".well-known/api-catalog",
]

GRAPHQL_PATHS = ["graphql", "graphiql", "api/graphql", "v1/graphql",
                 "api/v1/graphql", "api/v2/graphql", "query"]

GRAPHQL_INTROSPECT = """{"query":"{ __schema { types { name fields { name } } } }"}"""


async def phase_spec(http: HTTP) -> list[Endpoint]:
    hdr("PHASE 3 — SPEC DISCOVERY (Swagger / OpenAPI / GraphQL)")
    found: list[Endpoint] = []

    for path in SWAGGER_PATHS:
        s, hdrs, body, _ = await http.get(path)
        if s != 200 or not body:
            continue
        try:
            spec = json.loads(body)
        except Exception:
            continue
        if not isinstance(spec, dict):
            continue
        if not any(k in spec for k in ("paths", "openapi", "swagger")):
            continue

        ok(f"OpenAPI spec found: /{path}")
        spec_paths = spec.get("paths", {})
        for sp, methods in spec_paths.items():
            for method in methods.keys():
                method = method.upper()
                if method in ("GET","POST","PUT","PATCH","DELETE","HEAD","OPTIONS"):
                    ep_path = sp.lstrip("/")
                    ep = Endpoint(
                        url=http.abs(ep_path),
                        path=ep_path,
                        status=0,
                        methods=[method],
                        tags=tag_from_path(ep_path),
                        source="spec",
                    )
                    params = methods.get(method.lower(), {}).get("parameters", [])
                    for param in params:
                        pname = param.get("name", "")
                        pin   = param.get("in", "")
                        if pin == "path" and re.search(r"id|uuid|key", pname, re.I):
                            ep.tags.add("IDOR")
                        if pin == "query" and re.search(r"url|uri|redirect|target", pname, re.I):
                            ep.tags.add("SSRF")
                            ep.tags.add("OPEN_REDIRECT")
                    found.append(ep)

        if spec_paths:
            ok(f"  Extracted {len(spec_paths)} paths from spec")
            spec_ep = Endpoint(url=http.abs(path), path=path, status=200,
                               tags={"INFO_DISC"}, source="spec",
                               body_sample=body[:200])
            found.append(spec_ep)
        break

    for path in GRAPHQL_PATHS:
        s, hdrs, body = await http.post(path, raw=GRAPHQL_INTROSPECT.encode(),
                                         ct="application/json")
        if s not in (200, 400):
            continue
        try:
            resp = json.loads(body)
        except Exception:
            continue

        if "data" in resp and "__schema" in str(resp):
            ok(f"GraphQL introspection enabled: /{path}")
            ep = Endpoint(url=http.abs(path), path=path, status=s,
                          tags={"GRAPHQL", "INFO_DISC"},
                          source="spec",
                          body_sample=body[:400])
            ep.notes.append("Introspection enabled — full schema exposed")

            types = []
            try:
                types = resp["data"]["__schema"]["types"]
            except (KeyError, TypeError):
                pass
            for t in types:
                if t.get("name","").startswith("_"):
                    continue
                fields = t.get("fields") or []
                for f in fields:
                    fname = f.get("name","")
                    if re.search(r"(password|secret|token|ssn|key|flag|admin)", fname, re.I):
                        ep.notes.append(f"Sensitive field: {t['name']}.{fname}")
                        ep.tags.add("INFO_DISC")
                    if re.search(r"(delete|remove|update|create|set|add|modify)", fname, re.I):
                        ep.tags.add("ADMIN")
            found.append(ep)
            break

    return found


# ── Phase 4: Triage (deduplicate + score) ───────────────────────────────────────────────────────

def triage(endpoints: list[Endpoint]) -> list[Endpoint]:
    seen: dict[str, Endpoint] = {}
    for ep in endpoints:
        key = ep.path.rstrip("/").lower()
        if key not in seen:
            seen[key] = ep
        else:
            seen[key].tags |= ep.tags
            seen[key].methods = list(set(seen[key].methods + ep.methods))
            if not seen[key].status and ep.status:
                seen[key].status = ep.status
            if not seen[key].body_sample and ep.body_sample:
                seen[key].body_sample = ep.body_sample

    result = list(seen.values())

    GOLD = {"AUTH_BYPASS", "ACCOUNT_ENUM", "IDOR", "INFO_DISC", "ADMIN", "GRAPHQL"}
    def score(ep: Endpoint) -> int:
        s = len(ep.tags)
        s += sum(3 for t in ep.tags if t in GOLD)
        if ep.status in (200, 201): s += 2
        if ep.status == 403:        s += 1
        return s

    result.sort(key=score, reverse=True)
    return result


# ── Phase 5: Account enumeration probes ─────────────────────────────────────────────────────────

TEST_USERS = [
    ("admin",    "x"), ("test",     "x"), ("user",     "x"),
    ("root",     "x"), ("info",     "x"), ("support",  "x"),
    ("noreply",  "x"),
]
NONEXISTENT = ("_no_such_user_zzz_", "x")


async def phase_account_enum(http: HTTP, endpoints: list[Endpoint]):
    hdr("PHASE 5 — ACCOUNT ENUMERATION PROBES")

    auth_eps = [ep for ep in endpoints
                if any(t in ep.tags for t in ("ACCOUNT_ENUM", "RATE_LIMIT", "JWT"))
                and ep.path not in ("token", "refresh")]

    if not auth_eps:
        info("No login/register endpoints found to probe")
        return

    for ep in auth_eps[:5]:
        path = ep.path
        step(f"Probing account enumeration on /{path}")

        t0 = time.monotonic()
        s_nx, _, body_nx = await http.post(path,
                                            body={"username": NONEXISTENT[0],
                                                  "password": NONEXISTENT[1],
                                                  "email": f"{NONEXISTENT[0]}@example.com"})
        t_nx = time.monotonic() - t0

        results = []
        for username, password in TEST_USERS:
            t0 = time.monotonic()
            s, _, body = await http.post(path,
                                          body={"username": username,
                                                "password": password,
                                                "email": f"{username}@example.com"})
            elapsed = time.monotonic() - t0
            results.append({"user": username, "status": s, "time": elapsed,
                             "body_len": len(body), "body_sample": body[:120]})

        nx_status = s_nx
        nx_body   = body_nx[:120] if body_nx else ""

        status_diffs = {r["user"] for r in results if r["status"] != nx_status}
        body_diffs   = {r["user"] for r in results
                        if abs(r["body_len"] - len(nx_body)) > 20}
        timing_diffs = {r["user"] for r in results
                        if r["time"] > t_nx * 1.5 and r["time"] - t_nx > 0.3}

        if status_diffs:
            crit(f"/{path} — STATUS CODE difference for users: {status_diffs}")
            ep.tags.add("ACCOUNT_ENUM")
            ep.notes.append(f"Status code oracle: {status_diffs} differ from nonexistent user")
            for r in results:
                if r["user"] in status_diffs:
                    info(f"  {r['user']}: HTTP {r['status']}  (nonexist={nx_status})")

        if body_diffs:
            high(f"/{path} — RESPONSE BODY differs for users: {body_diffs}")
            ep.tags.add("ACCOUNT_ENUM")
            ep.notes.append(f"Body oracle: {body_diffs} return different body length")

        if timing_diffs:
            high(f"/{path} — TIMING difference for users: {timing_diffs}")
            ep.tags.add("ACCOUNT_ENUM")
            ep.notes.append(f"Timing oracle: {timing_diffs} respond slower (bcrypt hit?)")

        for r in results:
            for phrase in ("user not found", "no account", "invalid username",
                           "email not registered", "account does not exist",
                           "unknown user"):
                if phrase in r["body_sample"].lower():
                    crit(f"/{path} — VERBOSE ERROR for '{r['user']}': {phrase!r}")
                    ep.tags.add("ACCOUNT_ENUM")
                    ep.notes.append(f"Verbose error message: '{phrase}'")

        step(f"Rate limit check on /{path} (10 rapid requests)")
        tasks = [http.post(path, body={"username": "admin", "password": f"x{i}"})
                 for i in range(10)]
        rr = await asyncio.gather(*tasks)
        statuses = [s for s, _, _ in rr]
        if 429 in statuses:
            ok(f"  Rate limiting active (429 detected)")
        elif 200 in statuses[5:]:
            warn(f"  No rate limiting — brute force possible")
            ep.notes.append("No rate limit on login — brute force may be viable")
        else:
            info(f"  Statuses: {statuses[:5]}... (may have rate limiting)")


# ── Phase 6: Auth boundary map ────────────────────────────────────────────────────────────────────

async def phase_auth_map(http: HTTP, endpoints: list[Endpoint]):
    hdr("PHASE 6 — AUTH BOUNDARY MAPPING")

    candidate_tags = {"ADMIN", "IDOR", "MASS_ASSIGN", "BUSINESS_LOGIC", "FILE_OPS"}
    candidates = [ep for ep in endpoints
                  if ep.tags & candidate_tags and ep.status in (0, 200, 403)]

    step(f"Testing {min(len(candidates), 30)} high-value endpoints without a token")

    for ep in candidates[:30]:
        s, hdrs, body, _ = await http.get(ep.path)
        ep.status = s

        if s in (200, 201):
            ep.requires_auth = False
            ep.tags.add("AUTH_BYPASS")
            crit(f"NO AUTH REQUIRED: /{ep.path}  [{', '.join(ep.tags)}]")
        elif s == 401:
            ep.requires_auth = True
        elif s == 403:
            ep.requires_auth = True
            ep.notes.append("Returns 403 — try: different HTTP method, X-Original-URL header")
        else:
            ep.requires_auth = False


# ── Phase 7: Verb enumeration ─────────────────────────────────────────────────────────────────────

async def phase_verbs(http: HTTP, endpoints: list[Endpoint]):
    hdr("PHASE 7 — HTTP VERB ENUMERATION")

    gold_tags = {"ADMIN", "AUTH_BYPASS", "IDOR", "MASS_ASSIGN", "GRAPHQL"}
    targets = [ep for ep in endpoints if ep.tags & gold_tags][:20]

    for ep in targets:
        s, allow_header = await http.options(ep.path)
        if allow_header:
            methods = [m.strip() for m in allow_header.split(",") if m.strip()]
            ep.methods = methods
            dangerous = [m for m in methods if m in ("PUT", "DELETE", "PATCH", "TRACE")]
            if dangerous:
                high(f"/{ep.path} — dangerous methods: {dangerous}  (Allow: {allow_header})")
                ep.notes.append(f"Dangerous methods allowed: {dangerous}")
                if "PUT" in dangerous or "PATCH" in dangerous:
                    ep.tags.add("MASS_ASSIGN")
                if "TRACE" in dangerous:
                    ep.tags.add("INFO_DISC")
                    ep.notes.append("TRACE enabled — XST (Cross-Site Tracing)")
            else:
                info(f"  /{ep.path}  Allow: {allow_header}")


# ── Final report ────────────────────────────────────────────────────────────────────────────

ATTACK_NEXT_STEPS: dict[str, list[str]] = {
    "ACCOUNT_ENUM": [
        "Enumerate valid usernames via status/body/timing oracle",
        "Combine with password spray — use found usernames",
        "Test forgot-password: 'email not found' vs silence",
    ],
    "IDOR": [
        "Replace your ID with 1,2,3 or other users' IDs",
        "UUID v1: predict timestamps (see advanced_techniques.py #7)",
        "Try IDOR on POST/PUT: change owner_id or user_id in body",
    ],
    "AUTH_BYPASS": [
        "Access endpoint directly — no token needed",
        "Try HTTP verb tampering: GET protected, POST/PUT not",
        "X-Original-URL / X-Rewrite-URL header path override",
        "Add ?admin=true, &role=admin query params",
    ],
    "INFO_DISC": [
        "Read exposed config / secrets / credentials",
        "Check for DB creds, API keys, JWT secrets",
        "Swagger/OpenAPI: extract all undocumented endpoints",
    ],
    "ADMIN": [
        "BFLA: call admin endpoints with non-admin token",
        "Mass assignment: PUT/PATCH with {role:'admin', balance:9999}",
        "List/modify other users via admin API",
    ],
    "GRAPHQL": [
        "Full introspection: dump all types/fields/mutations",
        "Test unauthenticated queries for sensitive fields",
        "IDOR via resolver: query {user(id:1)} → change id",
        "Mutation abuse: createUser, deleteUser without auth check",
    ],
    "INJECTION": [
        "SQLi: ' OR 1=1--, UNION SELECT, time-based blind",
        "NoSQL: {\$gt:''}, {\$ne:'x'} in JSON body",
        "SSTI: {{7*7}}, ${7*7} in string params",
        "XSS: <script>alert(1)</script> in reflected params",
    ],
    "SSRF": [
        "http://169.254.169.254/latest/meta-data/ (AWS IMDSv1)",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://localhost:6379/ (Redis), http://localhost:27017/ (Mongo)",
        "XXE-based SSRF: see advanced_techniques.py module 4",
    ],
    "JWT": [
        "Decode token: base64 decode header+payload",
        "alg:none — strip signature, change alg header to 'none'",
        "Brute weak secret: hashcat -a 0 -m 16500 token.txt rockyou.txt",
        "RS256→HS256 confusion if JWKS exposed (advanced_techniques.py #6)",
    ],
    "OAUTH": [
        "Open redirect: redirect_uri=https://attacker.com",
        "Missing state param: CSRF on OAuth flow",
        "Password grant: grant_type=password bypasses MFA",
        "See advanced_techniques.py module 10 for full OAuth suite",
    ],
    "CORS": [
        "ACAC:true + reflected ACAO = credentialed cross-origin read",
        "PoC: fetch from attacker.com with credentials:include",
        "Can read authenticated API responses cross-origin",
    ],
    "MASS_ASSIGN": [
        "PUT/PATCH body: add role, admin, is_admin, balance, credits",
        'Try: {"role":"admin"} or {"is_admin":true}',
    ],
    "BUSINESS_LOGIC": [
        "Negative quantities: {amount: -999} to credit balance",
        "Race condition: parallel requests on one-time coupon/transfer",
        "Integer overflow: amount=2147483648",
    ],
    "FILE_OPS": [
        "Path traversal: ../../../etc/passwd",
        "Upload: .php/.jsp webshell disguised as image/pdf",
        "SSRF via URL field in upload endpoint",
    ],
    "OPEN_REDIRECT": [
        "redirect=https://evil.com after login → phishing",
        "Chain with OAuth: poison redirect_uri",
        "XSS via javascript:alert(1) in redirect param",
    ],
    "RATE_LIMIT": [
        "Try X-Forwarded-For rotation to bypass IP rate limiting",
        "Cluster bomb: valid usernames × password list",
        "Try null byte / encoding tricks in password field",
    ],
}


def print_report(endpoints: list[Endpoint], base: str,
                 out_file: str | None = None):
    hdr("FINAL REPORT — ENDPOINTS BY ATTACK RELEVANCE")

    by_tag: dict[str, list[Endpoint]] = defaultdict(list)
    for ep in endpoints:
        for tag in ep.tags:
            by_tag[tag].append(ep)

    priority_order = [
        "AUTH_BYPASS", "ACCOUNT_ENUM", "IDOR", "INFO_DISC",
        "ADMIN", "GRAPHQL", "INJECTION", "SSRF", "JWT",
        "OAUTH", "CORS", "MASS_ASSIGN", "BUSINESS_LOGIC",
        "FILE_OPS", "OPEN_REDIRECT", "RATE_LIMIT",
    ]

    total_exploitable = 0
    report: dict = {"base": base, "endpoints": [], "by_attack_class": {}}

    for tag in priority_order:
        eps = by_tag.get(tag, [])
        if not eps:
            continue

        c = RD if tag in ("AUTH_BYPASS","ACCOUNT_ENUM","IDOR","INFO_DISC","ADMIN") else YL
        print(f"\n{c}{BD}━━ {tag} — {TAGS[tag]} ({len(eps)} endpoints) ━━{R}")

        for ep in sorted(eps, key=lambda e: e.status in (200,201), reverse=True)[:15]:
            s_col = GN if ep.status in (200,201) else (YL if ep.status in (403,405) else CY)
            auth_str = f"  {RD}{BD}[NO AUTH]{R}" if ep.requires_auth is False else ""
            methods_str = f"  [{','.join(ep.methods)}]" if ep.methods else ""
            print(f"  {s_col}{ep.status or '???'}{R}  /{ep.path}{methods_str}{auth_str}")
            for note in ep.notes[:2]:
                print(f"         {CY}↳ {note}{R}")
            total_exploitable += 1

        print(f"\n  {MG}Next steps:{R}")
        for s in ATTACK_NEXT_STEPS.get(tag, []):
            print(f"    → {s}")

        report["by_attack_class"][tag] = [
            {"path": ep.path, "status": ep.status, "methods": ep.methods,
             "notes": ep.notes, "requires_auth": ep.requires_auth}
            for ep in eps
        ]

    print(f"\n{YL}{BD}━━ ALL ENDPOINTS ({len(endpoints)} total) ━━{R}")
    for ep in endpoints[:100]:
        tags_str = ",".join(sorted(ep.tags)) if ep.tags else "-"
        auth_str = " \U0001f513" if ep.requires_auth is False else ""
        s_col = GN if ep.status in (200,201) else (YL if ep.status in (301,302,403,405) else CY)
        print(f"  {s_col}{ep.status or '?'}{R}  /{ep.path:<55}  [{tags_str}]{auth_str}")

    print(f"\n  {GN}Total endpoints discovered: {len(endpoints)}{R}")
    print(f"  {RD}High-value attack surfaces: {total_exploitable}{R}\n")

    if out_file:
        report["endpoints"] = [
            {"path": ep.path, "url": ep.url, "status": ep.status,
             "methods": ep.methods, "tags": list(ep.tags),
             "notes": ep.notes, "requires_auth": ep.requires_auth,
             "source": ep.source}
            for ep in endpoints
        ]
        with open(out_file, "w") as f:
            json.dump(report, f, indent=2)
        ok(f"Report saved to {out_file}")


# ── Orchestrator ────────────────────────────────────────────────────────────────────────────

async def run(base: str, concurrency: int = 40, out_file: str | None = None,
              skip_enum: bool = False, skip_verbs: bool = False):
    if not base.startswith(("http://","https://")):
        print("Invalid URL — must start with http:// or https://")
        sys.exit(1)

    print(f"\n{'━'*70}")
    print(f"  TARGET : {base}")
    print(f"  ⚠  AUTHORIZED USE ONLY — bug bounty / owned target")
    print(f"{'━'*70}\n")

    connector = aiohttp.TCPConnector(ssl=False, limit=concurrency)
    async with aiohttp.ClientSession(connector=connector) as session:
        http = HTTP(base, session)
        start = time.monotonic()

        passive_paths  = await phase_passive(http)
        crawl_paths    = await phase_crawl(http)
        wordlist_eps   = await phase_wordlist(http,
                                               extra_paths=passive_paths + crawl_paths,
                                               concurrency=concurrency)
        spec_eps       = await phase_spec(http)

        all_eps = triage(wordlist_eps + spec_eps)

        crawl_set = {ep.path for ep in all_eps}
        for p in crawl_paths:
            p = p.strip("/")
            if p and p not in crawl_set:
                all_eps.append(Endpoint(url=http.abs(p), path=p, status=0,
                                        tags=tag_from_path(p), source="crawl"))

        all_eps = triage(all_eps)

        if not skip_enum:
            await phase_account_enum(http, all_eps)
        await phase_auth_map(http, all_eps)
        if not skip_verbs:
            await phase_verbs(http, all_eps)

        elapsed = time.monotonic() - start
        print(f"\n  Elapsed: {elapsed:.1f}s")

        print_report(all_eps, base, out_file)
        return all_eps


def main():
    import argparse
    p = argparse.ArgumentParser(
        description="recon.py — Endpoint discovery & exploit-relevance triage\n"
                    "Authorized testing only (bug bounty / owned target).",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    p.add_argument("url",                   help="Target base URL  e.g. https://target.example.com")
    p.add_argument("-c","--concurrency",    type=int, default=40,
                   help="Concurrent requests (default 40)")
    p.add_argument("-o","--output",         default=None,
                   help="Save JSON report to file")
    p.add_argument("--no-enum",             action="store_true",
                   help="Skip account enumeration probes")
    p.add_argument("--no-verbs",            action="store_true",
                   help="Skip HTTP verb enumeration")
    args = p.parse_args()
    asyncio.run(run(args.url, concurrency=args.concurrency,
                    out_file=args.output,
                    skip_enum=args.no_enum,
                    skip_verbs=args.no_verbs))


if __name__ == "__main__":
    main()
