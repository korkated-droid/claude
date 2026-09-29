"""
Deliberately Vulnerable Flask App — SANDBOX ONLY
Intentional vulns: IDOR, weak JWT, missing auth, CORS, mass assignment,
path traversal, verb tampering, debug endpoint, GraphQL introspection.
"""

import json
import os
import re
from functools import wraps

import jwt as pyjwt
from flask import Flask, jsonify, request, g

app = Flask(__name__)
app.config["DEBUG"] = True

# Intentionally weak secret
JWT_SECRET = "secret123"
JWT_ALGO = "HS256"

# In-memory "database"
USERS = {
    1: {"id": 1, "username": "alice",  "email": "alice@corp.com",  "role": "user",  "balance": 500,  "ssn": "111-22-3333"},
    2: {"id": 2, "username": "bob",    "email": "bob@corp.com",    "role": "user",  "balance": 250,  "ssn": "444-55-6666"},
    3: {"id": 3, "username": "admin",  "email": "admin@corp.com",  "role": "admin", "balance": 9999, "ssn": "000-00-0001"},
}

POSTS = {
    1: {"id": 1, "owner_id": 1, "title": "Alice's Secret Note", "body": "password is hunter2"},
    2: {"id": 2, "owner_id": 2, "title": "Bob's Draft",         "body": "TODO: launch product"},
    3: {"id": 3, "owner_id": 1, "title": "Public Post",         "body": "Hello world"},
}

FILES = {
    "report.txt": "Q1 revenue: $1,230,000",
    "passwords.txt": "admin:Password1\nalice:letmein\nbob:qwerty",
    "config.env": "DB_HOST=10.0.0.5\nDB_PASS=supersecret\nAWS_KEY=AKIA1234FAKE5678",
}


# ── Auth helpers ───────────────────────────────────────────────────────────

def make_token(user_id: int, role: str = "user") -> str:
    return pyjwt.encode({"sub": str(user_id), "role": role}, JWT_SECRET, algorithm=JWT_ALGO)


def decode_token(token: str):
    # Vuln: accepts alg:none (won't reject unsigned tokens when manually patched)
    try:
        return pyjwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO, "none"])
    except Exception:
        return None


def auth_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        token = auth.replace("Bearer ", "")
        claims = decode_token(token)
        if not claims:
            return jsonify({"error": "Unauthorized"}), 401
        g.user_id = int(claims.get("sub", 0))
        g.role = claims.get("role", "user")
        return f(*args, **kwargs)
    return wrapper


# ── Public endpoints ───────────────────────────────────────────────────────

@app.route("/api/v1/health")
def health():
    return jsonify({"status": "ok", "version": "1.0.0", "debug": True,
                    "db_host": "10.0.0.5", "env": "production"})


@app.route("/api/v1/login", methods=["POST"])
def login():
    data = request.get_json() or {}
    username = data.get("username")
    password = data.get("password")
    for uid, u in USERS.items():
        if u["username"] == username:
            # Vuln: no real password check — any password works
            token = make_token(uid, u["role"])
            return jsonify({"token": token, "user_id": uid, "role": u["role"]})
    return jsonify({"error": "Invalid credentials"}), 401


# ── IDOR: user can read ANY user's data by changing the ID ─────────────────

@app.route("/api/v1/users/<int:uid>")
@auth_required
def get_user(uid):
    # Vuln: no ownership check — returns any user's data including SSN
    user = USERS.get(uid)
    if not user:
        return jsonify({"error": "Not found"}), 404
    return jsonify(user)


# ── Broken Function Level Auth: admin endpoint, no role check ─────────────

@app.route("/api/v1/admin/users")
@auth_required
def admin_list_users():
    # Vuln: only checks auth token exists, not that role == admin
    return jsonify({"users": list(USERS.values())})


@app.route("/api/v1/admin/delete_user/<int:uid>", methods=["DELETE"])
def admin_delete_user(uid):
    # Vuln: no auth at all
    if uid in USERS:
        del USERS[uid]
        return jsonify({"deleted": uid})
    return jsonify({"error": "Not found"}), 404


# ── Mass Assignment: PUT accepts unexpected fields ─────────────────────────

@app.route("/api/v1/users/<int:uid>", methods=["PUT"])
@auth_required
def update_user(uid):
    data = request.get_json() or {}
    user = USERS.get(uid)
    if not user:
        return jsonify({"error": "Not found"}), 404
    # Vuln: blindly merges all fields including "role" and "balance"
    USERS[uid].update(data)
    return jsonify(USERS[uid])


# ── IDOR on posts ──────────────────────────────────────────────────────────

@app.route("/api/v1/posts/<int:pid>")
@auth_required
def get_post(pid):
    # Vuln: returns posts belonging to other users
    post = POSTS.get(pid)
    if not post:
        return jsonify({"error": "Not found"}), 404
    return jsonify(post)


# ── HTTP Verb Tampering ────────────────────────────────────────────────────

@app.route("/api/v1/secret", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
def secret_endpoint():
    # Vuln: GET is "protected" but other verbs bypass auth
    if request.method == "GET":
        auth = request.headers.get("Authorization", "")
        if not auth:
            return jsonify({"error": "Unauthorized"}), 401
    return jsonify({"secret": "FLAG{verb_tampering_success}", "method": request.method})


# ── Path Traversal ────────────────────────────────────────────────────────

@app.route("/api/v1/files/<path:filename>")
@auth_required
def read_file(filename):
    # Vuln: no path sanitization
    if filename in FILES:
        return jsonify({"filename": filename, "content": FILES[filename]})
    # Also reads real filesystem files
    safe_base = "/tmp/sandbox_files/"
    os.makedirs(safe_base, exist_ok=True)
    full_path = os.path.normpath(os.path.join(safe_base, filename))
    if os.path.exists(full_path):
        with open(full_path) as f:
            return jsonify({"filename": filename, "content": f.read()})
    return jsonify({"error": "File not found", "attempted_path": filename}), 404


# ── SSRF probe endpoint ────────────────────────────────────────────────────

@app.route("/api/v1/fetch")
@auth_required
def server_fetch():
    # Vuln: fetches any URL the user provides (SSRF)
    target = request.args.get("url", "")
    return jsonify({
        "note": "SSRF endpoint — would fetch internal resources",
        "requested_url": target,
        "simulated_response": "<!DOCTYPE html><html>internal service response</html>"
        if "169.254" in target or "localhost" in target or "127." in target
        else "external fetch simulated"
    })


# ── CORS Misconfiguration ─────────────────────────────────────────────────

@app.after_request
def add_cors(response):
    origin = request.headers.get("Origin", "*")
    # Vuln: reflects any Origin, including null
    response.headers["Access-Control-Allow-Origin"] = origin
    response.headers["Access-Control-Allow-Credentials"] = "true"
    response.headers["Access-Control-Allow-Methods"] = "GET,POST,PUT,DELETE,OPTIONS,PATCH"
    response.headers["Access-Control-Allow-Headers"] = "Authorization,Content-Type,X-Custom-Header"
    return response


# ── Debug / Info Disclosure ────────────────────────────────────────────────

@app.route("/debug")
def debug_info():
    return jsonify({
        "env_vars": dict(os.environ),
        "jwt_secret": JWT_SECRET,
        "users": USERS,
        "flask_debug": app.debug,
    })


@app.route("/.env")
def env_file():
    return "DB_HOST=10.0.0.5\nDB_PASS=supersecret\nAWS_KEY=AKIA1234FAKE5678\nJWT_SECRET=secret123\n", 200, {"Content-Type": "text/plain"}


@app.route("/api/v1/swagger.json")
def swagger():
    return jsonify({
        "openapi": "3.0.0",
        "info": {"title": "VulnApp API", "version": "1.0"},
        "paths": {
            "/api/v1/users/{id}": {"get": {}, "put": {}},
            "/api/v1/admin/users": {"get": {}},
            "/api/v1/admin/delete_user/{id}": {"delete": {}},
            "/api/v1/posts/{id}": {"get": {}},
            "/api/v1/secret": {"get": {}, "post": {}},
            "/api/v1/files/{filename}": {"get": {}},
            "/api/v1/fetch": {"get": {}},
            "/debug": {"get": {}},
            "/.env": {"get": {}},
        }
    })


# ── GraphQL (simple, introspection enabled) ───────────────────────────────

SCHEMA_TYPES = [
    {"name": "Query", "fields": [
        {"name": "user", "args": [{"name": "id", "type": "Int"}]},
        {"name": "users", "args": []},
        {"name": "secretFlag", "args": []},
    ]},
    {"name": "User", "fields": [
        {"name": "id"},{"name": "username"},{"name": "email"},
        {"name": "role"},{"name": "balance"},{"name": "ssn"},
    ]},
]


@app.route("/graphql", methods=["GET", "POST"])
def graphql():
    body = request.get_json() or {}
    query = body.get("query", request.args.get("query", ""))

    # Vuln: full introspection enabled in production
    if "__schema" in query or "__type" in query:
        return jsonify({"data": {"__schema": {"types": SCHEMA_TYPES}}})

    if "secretFlag" in query:
        return jsonify({"data": {"secretFlag": "FLAG{graphql_introspection_pwned}"}})

    if re.search(r"user\s*\(", query):
        m = re.search(r"id\s*:\s*(\d+)", query)
        uid = int(m.group(1)) if m else 1
        return jsonify({"data": {"user": USERS.get(uid, {})}})

    if "users" in query:
        return jsonify({"data": {"users": list(USERS.values())}})

    return jsonify({"data": {}, "errors": [{"message": "unknown query"}]})


# ── JWT with "alg:none" note ───────────────────────────────────────────────

@app.route("/api/v1/whoami")
def whoami():
    auth = request.headers.get("Authorization", "")
    token = auth.replace("Bearer ", "")
    if not token:
        return jsonify({"error": "No token"}), 401
    try:
        # Vuln: decode without verifying — just base64 decode for display
        import base64
        parts = token.split(".")
        payload = json.loads(base64.b64decode(parts[1] + "=="))
        return jsonify({"raw_claims": payload, "note": "token accepted without verification"})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


# ── NoSQL Injection (MongoDB-style auth bypass) ───────────────────────────

@app.route("/api/nosql/login", methods=["POST"])
def nosql_login():
    data = request.get_json() or {}
    username = data.get("username", "")
    password = data.get("password", "")
    # Vuln: accepts operator objects — {"$gt": ""} bypasses check
    if isinstance(password, dict) or isinstance(username, dict):
        return jsonify({"token": make_token(3, "admin"), "note": "FLAG{nosql_injection_auth_bypass}", "user": "admin"})
    for uid, u in USERS.items():
        if u["username"] == username:
            return jsonify({"token": make_token(uid, u["role"]), "user_id": uid})
    return jsonify({"error": "Invalid credentials"}), 401


# ── SSTI (Jinja2-style template rendering) ────────────────────────────────

@app.route("/api/render")
def ssti_render():
    # Vuln: renders user input as Jinja2 template
    template = request.args.get("template", "Hello {{ name }}")
    name = request.args.get("name", "world")
    # Safe simulation — shows reflection without real eval
    if "{{" in template and "}}" in template:
        rendered = template.replace("{{ name }}", name).replace("{{name}}", name)
        # Detect classic SSTI payloads
        if any(p in template for p in ["7*7", "7*'7'", "__class__", "config", "self"]):
            rendered = "49"  # 7*7 = 49 is the classic SSTI canary
            if "__class__" in template or "config" in template:
                rendered = "FLAG{ssti_rce_achieved} <Config {'DEBUG': True, 'SECRET_KEY': 'secret123'}>"
        return jsonify({"rendered": rendered, "input": template})
    return jsonify({"rendered": name, "input": template})


# ── Race Condition (coupon / balance transfer) ────────────────────────────

COUPONS = {"SAVE10": {"discount": 10, "used_by": []}}

@app.route("/api/v1/coupon/apply", methods=["POST"])
@auth_required
def apply_coupon():
    data = request.get_json() or {}
    code = data.get("code", "")
    coupon = COUPONS.get(code)
    if not coupon:
        return jsonify({"error": "Invalid coupon"}), 404
    # Vuln: race condition — check-then-act without atomic lock
    if g.user_id in coupon["used_by"]:
        return jsonify({"error": "Coupon already used"}), 409
    import time; time.sleep(0.05)  # simulate DB latency — widens race window
    coupon["used_by"].append(g.user_id)
    user = USERS[g.user_id]
    user["balance"] += coupon["discount"]
    return jsonify({"message": f"Discount applied: +{coupon['discount']}", "balance": user["balance"]})


# ── XXE / XML Upload ──────────────────────────────────────────────────────

@app.route("/api/v1/import/xml", methods=["POST"])
@auth_required
def import_xml():
    from xml.etree import ElementTree as ET
    body = request.data or b""
    content_type = request.content_type or ""
    if "xml" not in content_type and not body.strip().startswith(b"<"):
        return jsonify({"error": "Expected XML body"}), 400
    try:
        # Vuln: parses XML without disabling external entities
        root = ET.fromstring(body)
        result = {child.tag: child.text for child in root}
        # Simulate XXE — if DOCTYPE entity expansion happened
        for v in result.values():
            if v and ("root:" in str(v) or "FLAG" in str(v)):
                return jsonify({"parsed": result, "note": "FLAG{xxe_file_read_success}"})
        return jsonify({"parsed": result})
    except ET.ParseError as e:
        return jsonify({"error": f"XML parse error: {e}"}), 400


# ── Deserialization Detection ─────────────────────────────────────────────

@app.route("/api/v1/session/restore", methods=["POST"])
def restore_session():
    # Vuln: accepts raw pickle-like blobs (simulated — no real eval)
    import base64
    data = request.data
    content_type = request.content_type or ""
    if not data:
        return jsonify({"error": "No body"}), 400
    # Detect serialization magic bytes
    if data[:2] == b"\xac\xed":
        return jsonify({"error": "Java deserialization not supported", "hint": "FLAG{java_deser_gadget_chain}"})
    if data[:2] == b"\x80\x04" or data[:1] == b"\x80":
        return jsonify({"error": "Python pickle rejected", "hint": "FLAG{python_pickle_rce}"})
    try:
        decoded = base64.b64decode(data)
        return jsonify({"session": decoded.decode(errors="replace")[:200]})
    except Exception:
        return jsonify({"error": "Invalid session data"}), 400


# ── Host Header Injection ─────────────────────────────────────────────────

@app.route("/api/v1/password/reset", methods=["POST"])
def password_reset():
    data = request.get_json() or {}
    email = data.get("email", "")
    host = request.headers.get("Host", "localhost:7777")
    x_host = request.headers.get("X-Forwarded-Host", host)
    # Vuln: uses user-supplied Host header in reset link
    reset_link = f"https://{x_host}/reset?token=FAKE_TOKEN_12345"
    return jsonify({
        "message": f"Password reset sent to {email}",
        "reset_link": reset_link,
        "note": "FLAG{host_header_password_reset_poison}" if x_host != "localhost:7777" else "reset link generated"
    })


# ── Open Redirect ─────────────────────────────────────────────────────────

@app.route("/api/v1/redirect")
def open_redirect():
    # Vuln: no validation of redirect destination
    url = request.args.get("url", "/")
    return jsonify({"redirect": url, "note": "FLAG{open_redirect}" if "://" in url and "localhost" not in url else "internal redirect"})


# ── Cache Poisoning headers reflected ────────────────────────────────────

@app.route("/api/v1/cached")
def cached_endpoint():
    # Vuln: reflects unkeyed headers into response
    x_custom = request.headers.get("X-Forwarded-Host", "")
    x_scheme = request.headers.get("X-Forwarded-Scheme", "https")
    resp = {"data": "cached content", "version": "1.0"}
    if x_custom:
        resp["x_forwarded_host"] = x_custom
        resp["note"] = "FLAG{cache_poison_reflected}"
    return jsonify(resp)


if __name__ == "__main__":
    # Seed a sandbox file for path traversal demo
    os.makedirs("/tmp/sandbox_files", exist_ok=True)
    with open("/tmp/sandbox_files/notes.txt", "w") as f:
        f.write("Internal notes: deploy key = gh_FAKEFAKEFAKE\n")
    app.run(host="127.0.0.1", port=7777, debug=False)
