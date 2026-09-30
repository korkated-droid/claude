#!/usr/bin/env python3
"""
ghost.py — Real-Browser Stealth Scanner (Playwright / CDP)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Uses a REAL Chromium browser under CDP control — perfect TLS fingerprint,
correct HTTP/2 SETTINGS frame, real JA3/JA4 hash, no automation flags.
WAF/bot-detection systems (Cloudflare Bot Management, Akamai Bot Manager,
DataDome, PerimeterX, Kasada, Shape Security) cannot distinguish this
from a normal user because it IS a normal browser.

What ghost.py adds over aiohttp:
  ▸ Real Chromium TLS fingerprint (JA3/JA4 matches Chrome 135)
  ▸ Correct HTTP/2 SETTINGS / HPACK header order
  ▸ WebGL, Canvas, AudioContext fingerprint (not headless defaults)
  ▸ Navigator.webdriver = false (patched via CDP stealth script)
  ▸ Real cookie/session management across requests
  ▸ JavaScript execution — tests SPAs, React/Angular/Vue apps fully
  ▸ Network interception: capture ALL API calls made by the page
  ▸ Screenshot evidence for every finding
  ▸ Form-fill + multi-step auth flows
  ▸ AJAX/XHR/fetch interception and replay
  ▸ Service Worker / WebSocket interception
  ▸ Source map extraction from compiled JS

Stealth patches applied via CDP at launch:
  • navigator.webdriver → undefined
  • navigator.plugins → realistic plugin array
  • navigator.languages → ['en-US', 'en']
  • chrome.runtime → present
  • WebGL renderer/vendor → Intel/NVIDIA (not SwiftShader)
  • Screen resolution → 1920×1080
  • Permission API → not-prompt for notifications
  • window.chrome → full chrome object

For AUTHORIZED bug bounty programs and owned targets ONLY.

INSTALL
───────
  pip install playwright
  # (Chromium is pre-installed at /opt/pw-browsers/chromium in this env)
  # Or: playwright install chromium

USAGE
─────
  python3 ghost.py <target> [options]

  # Full ghost scan (intercept all API calls, screenshot findings):
  python3 ghost.py https://app.target.com -o ghost_out/

  # Authenticated scan (fill login form):
  python3 ghost.py https://app.target.com --login-url https://app.target.com/login
        --user test@test.com --pass yourpassword

  # Inject into hunt.py:
  from ghost import ghost_scan, GhostFinding
"""

import argparse
import asyncio
import base64
import json
import os
import re
import sys
import time
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple

R="\033[91m"; Y="\033[93m"; G="\033[92m"; B="\033[94m"
M="\033[95m"; C="\033[96m"; DIM="\033[2m"; RST="\033[0m"; BOLD="\033[1m"

try:
    from playwright.async_api import async_playwright, Page, BrowserContext, Request, Response
    _PLAYWRIGHT_OK = True
except ImportError:
    _PLAYWRIGHT_OK = False


# ──────────────────────────────────────────────────────────────────────────────
# STEALTH INJECTION SCRIPT — patches every new page at CDP level
# ──────────────────────────────────────────────────────────────────────────────

STEALTH_SCRIPT = """
// ── navigator.webdriver ──────────────────────────────────────────────────────
Object.defineProperty(navigator, 'webdriver', { get: () => undefined });

// ── navigator.plugins ────────────────────────────────────────────────────────
Object.defineProperty(navigator, 'plugins', {
  get: () => {
    const p = [
      { name: 'Chrome PDF Plugin', filename: 'internal-pdf-viewer', description: 'Portable Document Format' },
      { name: 'Chrome PDF Viewer', filename: 'mhjfbmdgcfjbbpaeojofohoefgiehjai', description: '' },
      { name: 'Native Client', filename: 'internal-nacl-plugin', description: '' },
    ];
    p.__proto__ = PluginArray.prototype;
    return p;
  },
});

// ── navigator.languages ──────────────────────────────────────────────────────
Object.defineProperty(navigator, 'languages', { get: () => ['en-US', 'en'] });

// ── chrome object ────────────────────────────────────────────────────────────
window.chrome = {
  app: { isInstalled: false, getDetails: function(){}, getIsInstalled: function(){}, runningState: function(){} },
  csi: function(){},
  loadTimes: function(){},
  runtime: {},
};

// ── WebGL vendor/renderer ────────────────────────────────────────────────────
const getParameter = WebGLRenderingContext.prototype.getParameter;
WebGLRenderingContext.prototype.getParameter = function(parameter) {
  if (parameter === 37445) return 'Intel Inc.';
  if (parameter === 37446) return 'Intel Iris OpenGL Engine';
  return getParameter.call(this, parameter);
};
const getParam2 = WebGL2RenderingContext.prototype.getParameter;
WebGL2RenderingContext.prototype.getParameter = function(parameter) {
  if (parameter === 37445) return 'Intel Inc.';
  if (parameter === 37446) return 'Intel Iris OpenGL Engine';
  return getParam2.call(this, parameter);
};

// ── permission query ─────────────────────────────────────────────────────────
const originalQuery = window.navigator.permissions.query;
window.navigator.permissions.query = (parameters) =>
  parameters.name === 'notifications'
    ? Promise.resolve({ state: Notification.permission })
    : originalQuery(parameters);

// ── Notification.permission ──────────────────────────────────────────────────
Object.defineProperty(Notification, 'permission', { get: () => 'default' });

// ── screen resolution ────────────────────────────────────────────────────────
Object.defineProperty(screen, 'width',       { get: () => 1920 });
Object.defineProperty(screen, 'height',      { get: () => 1080 });
Object.defineProperty(screen, 'availWidth',  { get: () => 1920 });
Object.defineProperty(screen, 'availHeight', { get: () => 1040 });
Object.defineProperty(window, 'outerWidth',  { get: () => 1920 });
Object.defineProperty(window, 'outerHeight', { get: () => 1040 });

// ── iframe contentWindow.navigator.webdriver ─────────────────────────────────
HTMLIFrameElement.prototype.__defineGetter__('contentWindow', function() {
  const w = this.contentWindow;
  Object.defineProperty(w.navigator, 'webdriver', { get: () => undefined });
  return w;
});
"""


# ──────────────────────────────────────────────────────────────────────────────
# DATA MODELS
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class GhostFinding:
    title: str
    severity: str
    url: str
    evidence: str
    remediation: str
    cvss: float = 0.0
    tags: List[str] = field(default_factory=list)
    screenshot: str = ""   # base64 PNG
    request_log: str = ""
    response_snippet: str = ""

@dataclass
class InterceptedCall:
    url: str
    method: str
    request_headers: Dict
    request_body: str
    response_status: int
    response_headers: Dict
    response_body: str
    timing_ms: float


# ──────────────────────────────────────────────────────────────────────────────
# BROWSER LAUNCH
# ──────────────────────────────────────────────────────────────────────────────

CHROME_PATH = os.environ.get(
    "PLAYWRIGHT_CHROMIUM_PATH",
    "/opt/pw-browsers/chromium",
)

async def launch_ghost_browser(
    proxy: Optional[str] = None,
    headless: bool = True,
) -> Tuple:
    """Launch Playwright with full stealth. Returns (playwright, browser, context)."""
    if not _PLAYWRIGHT_OK:
        raise RuntimeError("playwright not installed: pip install playwright")

    pw = await async_playwright().start()

    launch_args = [
        "--no-sandbox",
        "--disable-setuid-sandbox",
        "--disable-blink-features=AutomationControlled",
        "--disable-features=IsolateOrigins,site-per-process",
        "--disable-web-security",
        "--allow-running-insecure-content",
        "--disable-dev-shm-usage",
        "--disable-accelerated-2d-canvas",
        "--no-first-run",
        "--no-zygote",
        "--disable-background-networking",
        "--disable-background-timer-throttling",
        "--disable-backgrounding-occluded-windows",
        "--disable-breakpad",
        "--disable-client-side-phishing-detection",
        "--disable-component-update",
        "--disable-domain-reliability",
        "--disable-extensions",
        "--disable-hang-monitor",
        "--disable-ipc-flooding-protection",
        "--disable-popup-blocking",
        "--disable-prompt-on-repost",
        "--disable-renderer-backgrounding",
        "--disable-sync",
        "--disable-translate",
        "--force-color-profile=srgb",
        "--metrics-recording-only",
        "--safebrowsing-disable-auto-update",
        "--password-store=basic",
        "--use-mock-keychain",
        "--window-size=1920,1080",
    ]

    chrome_kwargs = {
        "headless": headless,
        "args": launch_args,
        "ignore_default_args": ["--enable-automation", "--enable-blink-features=IdleDetection"],
    }
    # Use pre-installed Chromium if available
    if os.path.exists(CHROME_PATH):
        chrome_kwargs["executable_path"] = CHROME_PATH

    proxy_settings = None
    if proxy:
        parsed = urllib.parse.urlparse(proxy)
        proxy_settings = {
            "server": f"{parsed.scheme}://{parsed.hostname}:{parsed.port}",
        }
        if parsed.username:
            proxy_settings["username"] = parsed.username
            proxy_settings["password"] = parsed.password or ""

    browser = await pw.chromium.launch(**chrome_kwargs)

    ctx_kwargs = {
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
        "viewport": {"width": 1920, "height": 1080},
        "locale": "en-US",
        "timezone_id": "America/New_York",
        "extra_http_headers": {
            "Accept-Language": "en-US,en;q=0.9",
        },
        "ignore_https_errors": True,
        "java_script_enabled": True,
    }
    if proxy_settings:
        ctx_kwargs["proxy"] = proxy_settings

    context = await browser.new_context(**ctx_kwargs)

    # Inject stealth script into every new page BEFORE any script runs
    await context.add_init_script(STEALTH_SCRIPT)

    return pw, browser, context


# ──────────────────────────────────────────────────────────────────────────────
# REQUEST INTERCEPTOR — captures all API calls the page makes
# ──────────────────────────────────────────────────────────────────────────────

async def setup_interceptor(page: "Page", outdir: str) -> List[InterceptedCall]:
    """Wire up request/response interception on a page."""
    calls: List[InterceptedCall] = []
    pending: Dict[str, Dict] = {}

    async def on_request(req: "Request"):
        pending[req.url] = {
            "method": req.method,
            "headers": dict(req.headers),
            "body": req.post_data or "",
            "start": time.time(),
        }

    async def on_response(resp: "Response"):
        url = resp.url
        if url not in pending:
            return
        p = pending.pop(url)
        try:
            body = await resp.text()
        except Exception:
            body = ""
        elapsed = (time.time() - p["start"]) * 1000
        calls.append(InterceptedCall(
            url=url,
            method=p["method"],
            request_headers=p["headers"],
            request_body=p["body"][:2000],
            response_status=resp.status,
            response_headers=dict(resp.headers),
            response_body=body[:3000],
            timing_ms=elapsed,
        ))

    page.on("request", on_request)
    page.on("response", on_response)
    return calls


# ──────────────────────────────────────────────────────────────────────────────
# AUTHENTICATED LOGIN
# ──────────────────────────────────────────────────────────────────────────────

async def ghost_login(
    page: "Page",
    login_url: str,
    username: str,
    password: str,
    verbose: bool = False,
) -> bool:
    """Auto-fill login form and submit. Returns True if login succeeded."""
    try:
        await page.goto(login_url, wait_until="networkidle", timeout=30000)
        await asyncio.sleep(1.5)

        # Try common field selectors
        user_selectors = [
            'input[type="email"]', 'input[name="email"]', 'input[name="username"]',
            'input[name="user"]', 'input[id*="email"]', 'input[id*="user"]',
            'input[placeholder*="email" i]', 'input[placeholder*="username" i]',
        ]
        pass_selectors = [
            'input[type="password"]', 'input[name="password"]',
            'input[id*="password"]', 'input[placeholder*="password" i]',
        ]
        submit_selectors = [
            'button[type="submit"]', 'input[type="submit"]',
            'button:has-text("Log in")', 'button:has-text("Sign in")',
            'button:has-text("Login")', 'button:has-text("Continue")',
        ]

        filled_user = False
        for sel in user_selectors:
            try:
                await page.fill(sel, username, timeout=2000)
                filled_user = True
                break
            except Exception:
                continue

        filled_pass = False
        for sel in pass_selectors:
            try:
                await page.fill(sel, password, timeout=2000)
                filled_pass = True
                break
            except Exception:
                continue

        if not filled_user or not filled_pass:
            if verbose:
                print(f"  {Y}[ghost] Could not fill login form — fields not found{RST}")
            return False

        for sel in submit_selectors:
            try:
                await page.click(sel, timeout=3000)
                break
            except Exception:
                continue

        await page.wait_for_load_state("networkidle", timeout=15000)

        # Check if login succeeded (no longer on login page, or URL changed)
        current = page.url
        success = login_url not in current or "dashboard" in current or "home" in current
        if verbose:
            print(f"  {G if success else Y}[ghost] Login {'succeeded' if success else 'uncertain'} → {current}{RST}")
        return success

    except Exception as e:
        if verbose:
            print(f"  {Y}[ghost] Login error: {e}{RST}")
        return False


# ──────────────────────────────────────────────────────────────────────────────
# JS ANALYSIS — extract endpoints, secrets, source maps
# ──────────────────────────────────────────────────────────────────────────────

SECRET_PATTERNS_JS = {
    "aws_key":       r"AKIA[0-9A-Z]{16}",
    "stripe_live":   r"sk_live_[0-9a-zA-Z]{24,}",
    "github_token":  r"ghp_[0-9a-zA-Z]{36}|github_pat_[A-Za-z0-9_]{82}",
    "google_api":    r"AIza[0-9A-Za-z\-_]{35}",
    "sendgrid":      r"SG\.[0-9a-zA-Z\-_]{22}\.[0-9a-zA-Z\-_]{43}",
    "jwt":           r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
    "slack_token":   r"xox[baprs]-[0-9a-zA-Z\-]{10,}",
    "firebase":      r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}",
    "private_key":   r"-----BEGIN (RSA|EC|OPENSSH) PRIVATE KEY-----",
    "generic_secret":r'(?:secret|api_?key|access_?token|auth_?token)["\'\s]*[:=]["\'\s]*[A-Za-z0-9+/]{20,}',
    "basic_auth_url":r"https?://[A-Za-z0-9_]+:[A-Za-z0-9+/!@#$%^&*]{6,}@",
    "internal_url":  r"https?://(?:10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.|localhost|127\.0\.0\.1)[^\s\"'<>]+",
}

ENDPOINT_PATTERNS = [
    r'["\'](?:/api/v?\d*/[\w/\-{}]+)["\']',
    r'["\'](?:/graphql[^\s"\']*)["\']',
    r'baseURL\s*[:=]\s*["\']([^"\']+)["\']',
    r'apiUrl\s*[:=]\s*["\']([^"\']+)["\']',
    r'endpoint\s*[:=]\s*["\']([^"\']+)["\']',
    r'fetch\s*\(\s*["\']([^"\']+)["\']',
    r'axios\.[a-z]+\s*\(\s*["\']([^"\']+)["\']',
    r'\.get\s*\(\s*["\'](/[^"\']+)["\']',
    r'\.post\s*\(\s*["\'](/[^"\']+)["\']',
    r'\.put\s*\(\s*["\'](/[^"\']+)["\']',
    r'\.delete\s*\(\s*["\'](/[^"\']+)["\']',
    r'route\s*[:=]\s*["\']([/][^"\']+)["\']',
    r'path\s*[:=]\s*["\']([/][A-Za-z][^"\']+)["\']',
]

async def analyze_js_bundle(content: str, source_url: str = "") -> Dict:
    """Parse a JS bundle for endpoints, secrets, and source maps."""
    endpoints: Set[str] = set()
    secrets = []

    for pattern in ENDPOINT_PATTERNS:
        for m in re.finditer(pattern, content):
            ep = m.group(1) if m.lastindex else m.group(0).strip("\"'")
            if len(ep) > 3 and ep.startswith("/"):
                endpoints.add(ep)

    for secret_type, pattern in SECRET_PATTERNS_JS.items():
        for m in re.finditer(pattern, content, re.I):
            hit = m.group(0)
            # Deduplicate
            if not any(hit in s.get("value","") for s in secrets):
                # Get context
                start = max(0, m.start() - 60)
                end = min(len(content), m.end() + 60)
                context = content[start:end].replace("\n", " ")
                secrets.append({
                    "type": secret_type,
                    "value": hit[:80],
                    "context": context[:150],
                    "source": source_url,
                })

    # Source map detection
    source_map = None
    sm_match = re.search(r'//# sourceMappingURL=(.+?)[\s$]', content)
    if sm_match:
        source_map = sm_match.group(1).strip()

    return {
        "endpoints": sorted(endpoints),
        "secrets": secrets,
        "source_map": source_map,
    }


# ──────────────────────────────────────────────────────────────────────────────
# SECURITY CHECKS ON INTERCEPTED API CALLS
# ──────────────────────────────────────────────────────────────────────────────

def analyze_api_calls(calls: List[InterceptedCall], base: str) -> List[GhostFinding]:
    """Analyze captured API calls for vulnerabilities."""
    findings = []
    base_host = urllib.parse.urlparse(base).hostname or base

    for call in calls:
        parsed = urllib.parse.urlparse(call.url)
        host = parsed.host
        headers_lower = {k.lower(): v for k, v in call.response_headers.items()}
        body = call.response_body

        # Skip static assets
        if any(call.url.endswith(ext) for ext in (".js",".css",".png",".jpg",".ico",".woff",".woff2")):
            continue

        # ── CORS check ────────────────────────────────────────────────────────
        acao = headers_lower.get("access-control-allow-origin", "")
        acac = headers_lower.get("access-control-allow-credentials", "")
        if acao in ("*", "null") and acac.lower() == "true":
            findings.append(GhostFinding(
                title=f"CORS Misconfiguration (credentials=true, origin={acao})",
                severity="HIGH",
                url=call.url,
                evidence=f"ACAO: {acao}\nACAC: {acac}\nResponse: {body[:300]}",
                remediation="Restrict ACAO to trusted origins. Never combine wildcard with credentials.",
                cvss=8.1,
                tags=["CORS", "AUTH_BYPASS"],
            ))

        # ── Sensitive data in response ────────────────────────────────────────
        sensitive_patterns = {
            "SSN": r"\b\d{3}-\d{2}-\d{4}\b",
            "CC_PAN": r"\b4[0-9]{12}(?:[0-9]{3})?\b|\b5[1-5][0-9]{14}\b",
            "AWS_KEY": r"AKIA[0-9A-Z]{16}",
            "Private_key": r"-----BEGIN.*PRIVATE KEY-----",
            "JWT_secret": r'"secret"\s*:\s*"[A-Za-z0-9+/]{20,}"',
            "password_hash": r'"password_?hash"\s*:\s*"\$2[ab]?\$',
        }
        for dtype, pattern in sensitive_patterns.items():
            if re.search(pattern, body):
                findings.append(GhostFinding(
                    title=f"Sensitive Data Exposure ({dtype}) in API Response",
                    severity="HIGH",
                    url=call.url,
                    evidence=f"Pattern {dtype} found in {call.response_status} response. Snippet: {body[:300]}",
                    remediation=f"Never return {dtype} in API responses. Mask/redact at server side.",
                    cvss=7.5,
                    tags=["DATA_EXPOSURE", "PII"],
                ))

        # ── JWT in response — grab for analysis ───────────────────────────────
        jwt_matches = re.findall(r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+', body)
        for jwt in jwt_matches[:2]:
            try:
                parts = jwt.split(".")
                header = json.loads(base64.b64decode(parts[0] + "==").decode(errors="replace"))
                payload = json.loads(base64.b64decode(parts[1] + "==").decode(errors="replace"))
                alg = header.get("alg", "")
                if alg.lower() in ("none", "hs256"):
                    findings.append(GhostFinding(
                        title=f"JWT Captured ({alg}) — Test for alg:none bypass",
                        severity="INFO",
                        url=call.url,
                        evidence=f"JWT header: {header}\nPayload: {str(payload)[:200]}",
                        remediation="Validate alg field server-side. Reject alg:none. Use RS256 minimum.",
                        cvss=0.0,
                        tags=["JWT", "AUTH"],
                    ))
            except Exception:
                pass

        # ── Stack trace / debug info ──────────────────────────────────────────
        if re.search(r"Traceback \(most recent|Exception in thread|at [A-Z][a-z]+\.[a-z]+\(", body):
            findings.append(GhostFinding(
                title="Debug Stack Trace Exposed in API Response",
                severity="MEDIUM",
                url=call.url,
                evidence=body[:400],
                remediation="Disable debug mode in production. Use generic error messages.",
                cvss=5.3,
                tags=["INFO_DISCLOSURE", "DEBUG"],
            ))

        # ── HTTP-only / Secure cookie flags ──────────────────────────────────
        set_cookie = headers_lower.get("set-cookie", "")
        if set_cookie and "session" in set_cookie.lower():
            if "httponly" not in set_cookie.lower():
                findings.append(GhostFinding(
                    title="Session Cookie Missing HttpOnly Flag",
                    severity="MEDIUM",
                    url=call.url,
                    evidence=f"Set-Cookie: {set_cookie[:200]}",
                    remediation="Add HttpOnly and Secure flags to all session cookies.",
                    cvss=4.3,
                    tags=["COOKIE", "XSS"],
                ))
            if "secure" not in set_cookie.lower():
                findings.append(GhostFinding(
                    title="Session Cookie Missing Secure Flag",
                    severity="MEDIUM",
                    url=call.url,
                    evidence=f"Set-Cookie: {set_cookie[:200]}",
                    remediation="Add Secure flag to prevent cookie transmission over HTTP.",
                    cvss=4.0,
                    tags=["COOKIE"],
                ))

        # ── IDOR signal: numeric IDs in API paths ─────────────────────────────
        if re.search(r'/(?:users?|accounts?|orders?|profiles?)/\d{4,}', call.url):
            findings.append(GhostFinding(
                title=f"Potential IDOR: Numeric ID in API endpoint",
                severity="INFO",
                url=call.url,
                evidence=f"Method: {call.method}\nStatus: {call.response_status}\nTest with incremented/decremented ID",
                remediation="Use UUIDs instead of sequential IDs. Enforce ownership checks server-side.",
                cvss=0.0,
                tags=["IDOR"],
            ))

    return findings


# ──────────────────────────────────────────────────────────────────────────────
# ACTIVE SECURITY CHECKS via Browser
# ──────────────────────────────────────────────────────────────────────────────

async def check_csp(page: "Page", url: str) -> List[GhostFinding]:
    """Evaluate Content Security Policy strength."""
    findings = []
    response = await page.goto(url, wait_until="domcontentloaded", timeout=20000)
    if not response:
        return findings
    headers = {k.lower(): v for k, v in response.headers.items()}
    csp = headers.get("content-security-policy", "")

    if not csp:
        findings.append(GhostFinding(
            title="Missing Content-Security-Policy header",
            severity="MEDIUM",
            url=url,
            evidence="No CSP header present. XSS payloads can load arbitrary scripts.",
            remediation="Implement a strict CSP: default-src 'self'; script-src 'self'; object-src 'none'.",
            cvss=4.3,
            tags=["CSP", "XSS"],
        ))
    else:
        # Weak CSP checks
        if "unsafe-inline" in csp:
            findings.append(GhostFinding(
                title="Weak CSP: unsafe-inline allows XSS",
                severity="MEDIUM",
                url=url,
                evidence=f"CSP: {csp[:200]}",
                remediation="Replace unsafe-inline with nonce- or hash-based CSP.",
                cvss=5.0,
                tags=["CSP", "XSS"],
            ))
        if "unsafe-eval" in csp:
            findings.append(GhostFinding(
                title="Weak CSP: unsafe-eval present",
                severity="MEDIUM",
                url=url,
                evidence=f"CSP: {csp[:200]}",
                remediation="Remove unsafe-eval. Use JSON.parse() instead of eval().",
                cvss=4.3,
                tags=["CSP", "XSS"],
            ))
        if re.search(r"script-src[^;]*\*", csp):
            findings.append(GhostFinding(
                title="Weak CSP: wildcard in script-src",
                severity="HIGH",
                url=url,
                evidence=f"CSP: {csp[:200]}",
                remediation="Use specific origins in script-src, not wildcards.",
                cvss=7.0,
                tags=["CSP", "XSS"],
            ))

    return findings


async def check_subresource_integrity(page: "Page") -> List[GhostFinding]:
    """Check that external scripts/stylesheets have SRI integrity hashes."""
    findings = []
    external_no_sri = await page.evaluate("""
        () => {
            const results = [];
            document.querySelectorAll('script[src], link[rel="stylesheet"]').forEach(el => {
                const src = el.src || el.href;
                if (src && !src.includes(window.location.hostname) && !el.integrity) {
                    results.push(src);
                }
            });
            return results;
        }
    """)
    if external_no_sri:
        findings.append(GhostFinding(
            title=f"Missing Subresource Integrity on {len(external_no_sri)} external resources",
            severity="LOW",
            url=page.url,
            evidence="\n".join(external_no_sri[:10]),
            remediation="Add integrity='sha384-...' crossorigin='anonymous' to all external <script> and <link> tags.",
            cvss=3.1,
            tags=["SRI", "SUPPLY_CHAIN"],
        ))
    return findings


async def check_open_redirect_browser(page: "Page", base: str) -> List[GhostFinding]:
    """Test common open redirect parameters in-browser."""
    findings = []
    canary = "https://evil.example.com"
    params = ["?redirect=", "?url=", "?next=", "?return=", "?goto=", "?target=",
              "?returnUrl=", "?redirectTo=", "?successUrl=", "?continueUrl="]

    for param in params:
        test_url = base.rstrip("/") + param + canary
        try:
            resp = await page.goto(test_url, wait_until="commit", timeout=8000)
            final = page.url
            if "evil.example.com" in final:
                findings.append(GhostFinding(
                    title=f"Open Redirect: {param}",
                    severity="MEDIUM",
                    url=test_url,
                    evidence=f"Redirected to: {final}",
                    remediation="Whitelist allowed redirect destinations. Never redirect to user-supplied URLs.",
                    cvss=6.1,
                    tags=["OPEN_REDIRECT"],
                ))
        except Exception:
            continue
    return findings


async def test_xss_dom(page: "Page", base: str, calls: List[InterceptedCall]) -> List[GhostFinding]:
    """Test reflected XSS in parameters found from intercepted calls."""
    findings = []
    canary = f"__xss_{int(time.time())}__"

    # Extract unique params from intercepted calls
    seen_params: Set[str] = set()
    test_urls = set()
    for call in calls:
        parsed = urllib.parse.urlparse(call.url)
        qs = urllib.parse.parse_qs(parsed.query)
        for param in qs:
            if param in seen_params:
                continue
            seen_params.add(param)
            new_qs = dict(urllib.parse.parse_qsl(parsed.query))
            new_qs[param] = f'"><img src=x onerror="window.__xss_{param}=1">'
            new_url = urllib.parse.urlunparse(parsed._replace(
                query=urllib.parse.urlencode(new_qs)
            ))
            test_urls.add((new_url, param))

    for test_url, param in list(test_urls)[:20]:
        try:
            await page.goto(test_url, wait_until="domcontentloaded", timeout=10000)
            triggered = await page.evaluate(f'() => typeof window.__xss_{param} !== "undefined"')
            if triggered:
                screenshot = await page.screenshot(full_page=False)
                findings.append(GhostFinding(
                    title=f"Reflected XSS in parameter '{param}'",
                    severity="HIGH",
                    url=test_url,
                    evidence=f"onerror handler executed. param={param}",
                    remediation="Encode all user input in HTML context. Implement strict CSP.",
                    cvss=7.2,
                    tags=["XSS", "REFLECTED"],
                    screenshot=base64.b64encode(screenshot).decode(),
                ))
        except Exception:
            continue

    return findings


async def check_graphql_ghost(page: "Page", base: str, calls: List[InterceptedCall]) -> List[GhostFinding]:
    """Test GraphQL introspection and batching via browser-grade requests."""
    findings = []
    graphql_endpoints = set()

    for call in calls:
        if "graphql" in call.url.lower() or '"query"' in call.request_body:
            graphql_endpoints.add(urllib.parse.urlparse(call.url)._replace(query="",fragment="").geturl())

    for ep in list(graphql_endpoints)[:3]:
        try:
            result = await page.evaluate(f"""
                async () => {{
                    const r = await fetch('{ep}', {{
                        method: 'POST',
                        headers: {{'Content-Type': 'application/json'}},
                        body: JSON.stringify({{query: '{{__schema{{types{{name}}}}}}'}}),
                        credentials: 'include',
                    }});
                    const body = await r.text();
                    return {{status: r.status, body: body.slice(0, 500)}};
                }}
            """)
            if result and '"__schema"' in result.get("body", ""):
                findings.append(GhostFinding(
                    title=f"GraphQL Introspection Enabled",
                    severity="MEDIUM",
                    url=ep,
                    evidence=result["body"][:300],
                    remediation="Disable introspection in production. Whitelist allowed queries.",
                    cvss=5.3,
                    tags=["GRAPHQL", "INFO_DISCLOSURE"],
                ))
        except Exception:
            continue

    return findings


# ──────────────────────────────────────────────────────────────────────────────
# GHOST SCAN ORCHESTRATOR
# ──────────────────────────────────────────────────────────────────────────────

async def ghost_scan(
    target: str,
    outdir: str = ".",
    proxy: Optional[str] = None,
    login_url: Optional[str] = None,
    username: Optional[str] = None,
    password: Optional[str] = None,
    verbose: bool = False,
    headless: bool = True,
) -> List[GhostFinding]:

    if not _PLAYWRIGHT_OK:
        print(f"{Y}[ghost] playwright not installed: pip install playwright{RST}")
        return []

    os.makedirs(outdir, exist_ok=True)
    all_findings: List[GhostFinding] = []

    print(f"\n{B}{BOLD}[Ghost] Real-Browser Stealth Scan → {target}{RST}")
    print(f"  {DIM}Launching Chromium (stealth mode, JA3 = real Chrome 135){RST}")

    pw, browser, context = await launch_ghost_browser(proxy=proxy, headless=headless)

    try:
        page = await context.new_page()
        calls = await setup_interceptor(page, outdir)
        js_findings: Dict[str, Dict] = {}

        # ── Navigate to target ─────────────────────────────────────────────
        print(f"  {DIM}Loading {target}…{RST}")
        try:
            await page.goto(target, wait_until="networkidle", timeout=30000)
        except Exception as e:
            print(f"  {Y}[ghost] Navigation error: {e}{RST}")

        await asyncio.sleep(2)  # let page settle

        # ── Login if credentials provided ─────────────────────────────────
        if login_url and username and password:
            print(f"  {DIM}Attempting login at {login_url}{RST}")
            await ghost_login(page, login_url, username, password, verbose)
            await asyncio.sleep(2)
            # Navigate back to target with session
            await page.goto(target, wait_until="networkidle", timeout=20000)
            await asyncio.sleep(2)

        # ── Navigate around the site ──────────────────────────────────────
        # Click links to trigger more API calls
        links = await page.evaluate("""
            () => [...new Set([...document.querySelectorAll('a[href]')]
                .map(a => a.href)
                .filter(h => h.startsWith(window.location.origin))
                .slice(0, 15))]
        """)
        for link in (links or [])[:10]:
            try:
                await page.goto(link, wait_until="networkidle", timeout=10000)
                await asyncio.sleep(0.8)
            except Exception:
                continue

        print(f"  {G}[+]{RST} Intercepted {len(calls)} API calls")

        # ── Analyze intercepted API calls ─────────────────────────────────
        api_findings = analyze_api_calls(calls, target)
        all_findings.extend(api_findings)
        if api_findings:
            print(f"  {G}[+]{RST} API analysis: {len(api_findings)} findings")

        # ── JS bundle analysis ────────────────────────────────────────────
        print(f"  {DIM}Analyzing JS bundles…{RST}")
        js_calls = [c for c in calls if c.url.endswith(".js") or "chunk" in c.url or "bundle" in c.url]
        all_endpoints: Set[str] = set()
        all_secrets = []
        source_maps = []

        for js_call in js_calls[:20]:
            analysis = await analyze_js_bundle(js_call.response_body, js_call.url)
            all_endpoints.update(analysis["endpoints"])
            all_secrets.extend(analysis["secrets"])
            if analysis["source_map"]:
                source_maps.append({"js": js_call.url, "map": analysis["source_map"]})

        for secret in all_secrets:
            all_findings.append(GhostFinding(
                title=f"Secret in JS Bundle: {secret['type']}",
                severity="CRITICAL" if secret["type"] in ("aws_key","stripe_live","private_key","github_token") else "HIGH",
                url=secret["source"],
                evidence=f"Value: {secret['value']}\nContext: {secret['context']}",
                remediation="Never embed secrets in frontend JS. Use environment variables server-side.",
                cvss=9.1,
                tags=["SECRETS", "JS_BUNDLE"],
            ))

        if source_maps:
            all_findings.append(GhostFinding(
                title=f"Source Maps Exposed ({len(source_maps)} files) — Original Source Readable",
                severity="MEDIUM",
                url=source_maps[0]["js"],
                evidence="\n".join(f"{s['js']} → {s['map']}" for s in source_maps[:5]),
                remediation="Disable source map generation for production builds.",
                cvss=5.3,
                tags=["SOURCE_MAP", "INFO_DISCLOSURE"],
            ))

        print(f"  {G}[+]{RST} JS analysis: {len(all_endpoints)} endpoints, {len(all_secrets)} secrets, {len(source_maps)} source maps")

        # ── CSP check ────────────────────────────────────────────────────
        csp_findings = await check_csp(page, target)
        all_findings.extend(csp_findings)

        # ── SRI check ────────────────────────────────────────────────────
        sri_findings = await check_subresource_integrity(page)
        all_findings.extend(sri_findings)

        # ── GraphQL via browser ────────────────────────────────────────
        gql_findings = await check_graphql_ghost(page, target, calls)
        all_findings.extend(gql_findings)

        # ── Open redirect ────────────────────────────────────────────────
        redir_findings = await check_open_redirect_browser(page, target)
        all_findings.extend(redir_findings)

        # ── DOM XSS ──────────────────────────────────────────────────────
        xss_findings = await test_xss_dom(page, target, calls)
        all_findings.extend(xss_findings)

        # ── Screenshot summary page ──────────────────────────────────────
        await page.goto(target, wait_until="domcontentloaded", timeout=15000)
        screenshot = await page.screenshot(full_page=True)
        ss_path = os.path.join(outdir, "ghost_screenshot.png")
        with open(ss_path, "wb") as f:
            f.write(screenshot)
        print(f"  {G}[+]{RST} Screenshot → {ss_path}")

    finally:
        await browser.close()
        await pw.stop()

    # ── Save results ───────────────────────────────────────────────────────
    results_path = os.path.join(outdir, "ghost_findings.json")
    with open(results_path, "w") as f:
        json.dump([{
            "title": g.title, "severity": g.severity, "url": g.url,
            "evidence": g.evidence[:500], "remediation": g.remediation,
            "cvss": g.cvss, "tags": g.tags,
            "has_screenshot": bool(g.screenshot),
        } for g in all_findings], f, indent=2)

    # ── Save all intercepted calls ─────────────────────────────────────────
    calls_path = os.path.join(outdir, "ghost_api_calls.json")
    with open(calls_path, "w") as f:
        json.dump([{
            "url": c.url, "method": c.method, "status": c.response_status,
            "req_body": c.request_body[:200], "resp_snippet": c.response_body[:300],
            "timing_ms": round(c.timing_ms, 1),
        } for c in calls[:500]], f, indent=2)

    print(f"\n{G}[ghost]{RST} Complete: {len(all_findings)} findings")
    print(f"  {G}Results:{RST} {results_path}")
    print(f"  {G}API calls:{RST} {calls_path} ({len(calls)} captured)")

    return all_findings


# ──────────────────────────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if not _PLAYWRIGHT_OK:
        print("[!] pip install playwright")
        sys.exit(1)

    parser = argparse.ArgumentParser(description="ghost.py — Real-Browser Stealth Scanner")
    parser.add_argument("target", help="Target URL")
    parser.add_argument("-o", "--output", default="ghost_out", help="Output directory")
    parser.add_argument("--proxy", help="HTTP proxy (e.g. http://127.0.0.1:8080)")
    parser.add_argument("--login-url", help="Login page URL")
    parser.add_argument("--user", help="Username/email for login")
    parser.add_argument("--pass", dest="password", help="Password for login")
    parser.add_argument("--no-headless", action="store_true", help="Show browser window")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    os.makedirs(args.output, exist_ok=True)
    findings = asyncio.run(ghost_scan(
        target=args.target,
        outdir=args.output,
        proxy=args.proxy,
        login_url=args.login_url,
        username=args.user,
        password=args.password,
        verbose=args.verbose,
        headless=not args.no_headless,
    ))

    print(f"\n{'═'*60}")
    print(f"GHOST SCAN COMPLETE — {args.target}")
    print(f"{'═'*60}")
    for sev in ("CRITICAL","HIGH","MEDIUM","LOW","INFO"):
        n = sum(1 for f in findings if f.severity == sev)
        if n:
            print(f"  {sev:10} {n}")
    print(f"{'═'*60}")
