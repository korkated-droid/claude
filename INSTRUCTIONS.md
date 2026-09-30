# Bug Bounty Toolkit — Complete Instructions

> **LEGAL**: All tools are for **authorized security testing only** — active bug bounty programs or systems you own/have written permission to test. Unauthorized use is illegal. Respect program scope, rate limits, and responsible disclosure rules.

---

## Tools Overview

| File | Purpose | When to use |
|------|---------|-------------|
| `hunt.py` | **Master orchestrator** — chains everything | Start here, every time |
| `recon.py` | Passive OSINT + endpoint discovery + email oracle | Standalone recon phase |
| `gov_level.py` | 25 advanced red-team checks | After initial recon |
| `sandbox/vuln_app.py` | Deliberately vulnerable practice target | Local testing/dev |

---

## Quick Start (Real Bug Bounty Target)

```bash
# 1. Install dependencies
pip install aiohttp beautifulsoup4 lxml dnspython cryptography

# 2. Full pipeline (recommended)
python3 hunt.py https://app.target.com

# 3. With auth token (authenticated testing)
python3 hunt.py https://app.target.com -t "Bearer eyJhbGci..."

# 4. Through Burp Suite (intercept all requests)
python3 hunt.py https://app.target.com --proxy http://127.0.0.1:8080 -v

# 5. Slower/stealthier (avoid WAF/rate-limit blocks)
python3 hunt.py https://app.target.com --delay 500 -c 10
```

Results land in `results_<host>_<timestamp>/`:
- `report.md` — full Markdown report with evidence
- `findings.json` — machine-readable findings
- `recon.json` — all discovered endpoints
- `gov.json` — gov-level check results

---

## Detailed Usage

### hunt.py — Master Orchestrator

```
python3 hunt.py <target> [options]

Options:
  -t, --token TOKEN       Auth token: JWT, cookie string, or API key
                          Auto-detected format:
                            "Bearer eyJ..."      → Authorization: Bearer ...
                            "session=abc; ..."   → Cookie: session=abc; ...
                            raw JWT              → Authorization: Bearer ...

  -c, --concurrency N     Parallel requests (default 30)
                          Lower for stealth: -c 5
                          Higher for speed:  -c 60

  -o, --output DIR        Output directory (default: results_host_ts/)

  --proxy URL             HTTP proxy for Burp/ZAP intercept
                          e.g. --proxy http://127.0.0.1:8080

  --delay MS              Milliseconds between requests (default 100)
                          Stealth: --delay 500 to 2000

  --cookies STR           Cookie header string
                          e.g. --cookies "session=abc123; csrf=xyz"

  --no-recon              Skip recon.py (use if you already have endpoint list)
  --no-gov                Skip gov_level.py (faster, fewer checks)
  --cve-only              Only run CVE/generic exploit modules (fastest)
  --tech TECH             Force technology detection:
                          spring | laravel | django | rails | next | express

  -v, --verbose           Print every request/response detail
```

### recon.py — Standalone Recon

```
python3 recon.py <target> [options]

Phase 1:  Passive OSINT (crt.sh, Wayback, URLScan, HackerTarget, etc.)
Phase 1b: Third-party provider detection (Firebase, Stripe, LaunchDarkly, etc.)
Phase 2:  JS file crawl + secret scanning
Phase 3:  Wordlist brute (GET + POST with {"email": "test@..."})
Phase 4:  Email/user oracle scan (finds Robinhood-class account enum bugs)
Phase 5:  OpenAPI/GraphQL spec parsing
Phase 6:  Subdomain live probe + per-subdomain scan
Phase 7:  Auth boundary detection
Phase 8:  Exploit triage (tag high-value endpoints)
Phase 9:  HTTP verb tampering

Key outputs:
  - Email oracle findings (ACCOUNT_ENUM tag) → report immediately
  - Admin/internal endpoints (ADMIN tag)
  - JS secrets (AWS keys, Stripe sk_, GitHub tokens)
  - Subdomain takeover candidates
```

### gov_level.py — Advanced Checks

```
python3 gov_level.py <target> [-t token] [-o output.json] [-v]

25 checks including:
  Prototype pollution      JWT advanced (jwk injection, kid traversal)
  Web cache deception      SAML XSW + XXE
  Subdomain takeover       OAuth PKCE bypass
  GraphQL batching DoS     Nginx alias traversal
  Cloud storage enum       Kubernetes IMDS + API
  API gateway bypass       HTTP parameter pollution
  Second-order injection   PostMessage hijacking
  Dependency confusion     Cookie security audit
  WebSocket CSWSH          Business logic (overflow, race, negative)
  DNS rebinding            h2c smuggling
  Cache poisoning adv.     SSRF chains → cloud creds
  Path normalization       Deserialization gadgets
  Info disclosure          (stack traces, .git, source maps)
```

---

## Bug Bounty Workflow

### Step 1: Reconnaissance

```bash
# Passive only (no active requests to target)
python3 recon.py https://target.com --passive-only -o passive.json

# Review providers found — often instant bounties:
# Firebase? → Check for open Realtime DB: https://target-default-rtdb.firebaseio.com/.json
# Stripe?   → Look for secret keys in JS
# Retool?   → Check for default admin panels
```

### Step 2: Unauthenticated Scan

```bash
python3 hunt.py https://target.com --delay 200 -o results_unauth/
```

Review `results_unauth/report.md`. Report any CRITICAL/HIGH immediately.

### Step 3: Authenticated Scan

Log in through browser, grab your session token from DevTools → Network tab → any request → Authorization header or Cookie.

```bash
python3 hunt.py https://target.com \
  -t "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  --proxy http://127.0.0.1:8080 \
  -o results_auth/
```

### Step 4: Manual Follow-up

For each CRITICAL/HIGH finding in the report:

1. **Reproduce in Burp Suite** — confirm it's not a false positive
2. **Establish impact** — what data can you access? Can you pivot?
3. **Document evidence** — screenshot, request/response, PoC
4. **Report responsibly** — submit to the program, don't exploit further

### Step 5: Report Writing

Use `results_*/report.md` as the basis. Programs expect:
- **Title**: `[Severity] Short description of the bug`  
- **Summary**: What the vulnerability is and why it matters
- **Steps to reproduce**: Numbered, exact request/response
- **Impact**: What an attacker can do
- **Evidence**: Screenshots or curl commands
- **Suggested fix**: Brief remediation

---

## CVE Modules in hunt.py

### High-Value Checks (run these first on tech-specific targets)

| CVE | Target | CVSS | What it finds |
|-----|--------|------|---------------|
| CVE-2025-29927 | Next.js apps | 9.1 | Middleware auth bypass via header |
| CVE-2025-24813 | Apache Tomcat | 9.8 | Partial PUT → RCE |
| CVE-2024-38819 | Spring apps | 7.5 | Path traversal → WEB-INF read |
| CVE-2024-22243 | Spring Security | 8.1 | URL encoding auth bypass |
| CVE-2024-27198 | JetBrains CI | 9.8 | Unauthenticated admin API |
| CVE-2024-23897 | Jenkins | 9.8 | CLI LFI → /etc/passwd |
| CVE-2024-34102 | Magento | 9.8 | XXE → SSRF + file read |
| CVE-2024-9264 | Grafana | 9.4 | SQL injection → RCE |
| CVE-2023-50164 | Struts2 | 9.8 | File upload traversal → RCE |

### Always-Run Generic Checks

| ID | What it finds | Severity |
|----|--------------|----------|
| GENERIC-001 | Laravel .env / Ignition debug RCE | CRITICAL |
| GENERIC-005 | GraphQL introspection + batch DoS | HIGH |
| GENERIC-006 | Exposed .git directory | HIGH |
| GENERIC-008 | OpenAPI spec leak (all endpoints exposed) | MEDIUM |
| GENERIC-011 | HTTP request smuggling (CL.TE) | HIGH |
| GENERIC-012 | CORS misconfig (creds + reflection) | HIGH |
| GENERIC-013 | JWT alg:none bypass + weak secret crack | CRITICAL |
| GENERIC-016 | SSTI polyglot (Jinja2/Twig/Freemarker) | CRITICAL |
| GENERIC-018 | SSRF → cloud metadata | CRITICAL |
| GENERIC-019 | Race condition on financial endpoints | HIGH |
| GENERIC-020 | Password reset host header poison | HIGH |
| GENERIC-024 | NoSQL injection auth bypass | CRITICAL |

---

## Practice on Local Sandbox

Test your setup against the intentionally vulnerable app before touching real targets:

```bash
# Terminal 1: Start vulnerable app
pip install flask
python3 sandbox/vuln_app.py
# Listening on http://localhost:7777

# Terminal 2: Run hunt against sandbox
python3 hunt.py http://localhost:7777 --cve-only -v

# Or full pipeline:
python3 hunt.py http://localhost:7777 -v --no-recon
```

Expected findings from sandbox:
- SSTI at `/api/render?template={{7*7}}`
- NoSQL injection at `/api/nosql/login`
- XXE at `/api/v1/import/xml`
- Host header injection at `/api/v1/password/reset`
- Open redirect at `/api/v1/redirect?url=`
- Race condition at `/api/v1/coupon/apply`

---

## Stealth / Avoiding Detection

```bash
# Minimal footprint: passive recon only
python3 recon.py https://target.com --passive-only

# Slow scan: 500ms delay, 5 concurrent
python3 hunt.py https://target.com --delay 500 -c 5

# Through Burp for WAF bypass testing
python3 hunt.py https://target.com --proxy http://127.0.0.1:8080

# Skip active enumeration (just CVE checks)
python3 hunt.py https://target.com --cve-only --delay 300
```

---

## Reading Output

### Severity Levels

- **CRITICAL (9.0+)** — Report immediately. RCE, auth bypass, account takeover.
- **HIGH (7.0–8.9)** — Report same day. Data leak, significant privilege escalation.
- **MEDIUM (4.0–6.9)** — Report within 24h. Info disclosure, partial bypass.
- **LOW (0.1–3.9)** — Include in report. Hardening issues, minor disclosure.
- **INFO** — Interesting but not directly exploitable. Use for chaining.

### Tags Reference

```
AUTH_BYPASS    → Can access authenticated resources without creds
ACCOUNT_ENUM   → Can enumerate valid usernames/emails (oracle)
IDOR           → Can access other users' data via ID manipulation
SSRF           → Can make server-side requests to internal resources
RCE            → Remote code execution (highest severity)
SQLI / NOSQL   → Injection into database queries
SSTI           → Template injection → often leads to RCE
JWT            → JWT implementation weakness
RACE_CONDITION → Concurrent request exploitation
```

---

## Responsible Disclosure

1. **Stop at PoC** — once you've proven the vulnerability, stop. Don't dump databases, don't access real user data.
2. **Report quickly** — CRITICAL within 24h, HIGH within 48h.
3. **Be specific** — exact URL, method, headers, payload, response.
4. **Be patient** — most programs have 90-day SLA for fixes.
5. **Coordinate on CVEs** — if you find a CVE-class bug in open-source, coordinate with vendor before public disclosure.

---

*For authorized bug bounty programs and owned targets only.*
