#!/usr/bin/env python3
"""
app.py — the deliberately vulnerable auth lab (standard library only).

Run vulnerable (default):   python3 app.py
Run patched:                APP_MODE=secure python3 app.py
Reset the DB on boot:       RESET_DB=1 python3 app.py

Every vulnerability has a `# VULN:` comment on the vulnerable branch and a
`# SECURE:` comment on the patched branch. The same endpoint contains both; the
APP_MODE environment variable decides which one runs, so you can attack the app,
then flip the switch and confirm your fix — without changing any code.

See VULNERABILITIES.md for exploit walkthroughs (Burp Suite / curl) and the
patch rationale for each finding.
"""

import os
import re
import json
import html
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

import auth
import db

MODE = os.environ.get("APP_MODE", "vuln").lower()
if MODE not in ("vuln", "secure"):
    raise SystemExit("APP_MODE must be 'vuln' or 'secure'")

HOST = os.environ.get("HOST", "127.0.0.1")
PORT = int(os.environ.get("PORT", "3000"))
HERE = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(HERE, "static")


# ==========================================================================
# Small helpers
# ==========================================================================
def load_user_by_id(conn, uid):
    rows = db.safe_query(conn, "SELECT * FROM users WHERE id = ?", (uid,))
    return rows[0] if rows else None


def load_user_by_username(conn, username):
    rows = db.safe_query(conn, "SELECT * FROM users WHERE username = ?", (username,))
    return rows[0] if rows else None


def public_user(row, include_sensitive=False):
    """Project a user row for output, hiding secrets unless explicitly allowed."""
    out = {
        "id": row["id"],
        "username": row["username"],
        "email": row["email"],
        "full_name": row["full_name"],
        "role": row["role"],
        "created_at": row["created_at"],
    }
    if include_sensitive:
        out["api_key"] = row["api_key"]
        out["password_hash"] = row["password_hash"]
        out["hash_scheme"] = row["hash_scheme"]
    return out


# ==========================================================================
# Request handler
# ==========================================================================
class Handler(BaseHTTPRequestHandler):
    server_version = "AuthLab/1.0"

    # -- plumbing ----------------------------------------------------------
    def log_message(self, fmt, *args):
        print("[%s] %s" % (self.address_string(), fmt % args))

    def _send(self, code, body, ctype="application/json", extra_headers=None):
        if isinstance(body, (dict, list)):
            body = json.dumps(body, indent=2)
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra_headers or {}):
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _json_body(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        if not length:
            return {}
        raw = self.rfile.read(length)
        try:
            return json.loads(raw)
        except Exception:
            return {}

    def _cookies(self):
        c = SimpleCookie()
        if "Cookie" in self.headers:
            c.load(self.headers["Cookie"])
        return {k: m.value for k, m in c.items()}

    def _bearer(self):
        h = self.headers.get("Authorization", "")
        if h.startswith("Bearer "):
            return h[len("Bearer "):].strip()
        return None

    # -- identity ----------------------------------------------------------
    def identity(self, conn):
        """Return the caller's token payload (dict) or None.

        Tries the Authorization: Bearer JWT first, then the remember-me cookie.
        The verification behavior differs by mode (see auth.py).
        """
        token = self._bearer()
        if token:
            if MODE == "vuln":
                payload = auth.jwt_decode_vuln(token)   # does NOT verify signature
            else:
                payload = auth.jwt_decode_secure(token)  # verifies alg+sig+exp
            if payload:
                return payload

        cookies = self._cookies()
        rc = cookies.get("remember")
        if rc:
            if MODE == "vuln":
                # VULN: trust base64(username) with no signature or lookup.
                uname = auth.remember_username_from_vuln_cookie(rc)
                if uname:
                    u = load_user_by_username(conn, uname)
                    if u:
                        return {"sub": u["id"], "username": u["username"], "role": u["role"]}
            else:
                # SECURE: look up the hash of the random token, check expiry.
                digest = auth.hash_remember_token(rc)
                rows = db.safe_query(
                    conn,
                    "SELECT user_id FROM remember_tokens "
                    "WHERE token_hash = ? AND expires_at > datetime('now')",
                    (digest,),
                )
                if rows:
                    u = load_user_by_id(conn, rows[0]["user_id"])
                    if u:
                        return {"sub": u["id"], "username": u["username"], "role": u["role"]}
        return None

    # -- routing -----------------------------------------------------------
    def do_GET(self):
        self.route("GET")

    def do_POST(self):
        self.route("POST")

    def do_PUT(self):
        self.route("PUT")

    def route(self, method):
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)

        # static / frontend
        if method == "GET" and (path == "/" or path == "/index.html"):
            return self.serve_static("index.html")
        if method == "GET" and path.startswith("/static/"):
            return self.serve_static(path[len("/static/"):])

        conn = db.get_conn(MODE)
        try:
            for m, pattern, fn in ROUTES:
                if m != method:
                    continue
                match = pattern.match(path)
                if match:
                    return fn(self, conn, match, query)
            self._send(404, {"error": "not found", "path": path})
        finally:
            conn.close()

    def serve_static(self, rel):
        rel = rel.lstrip("/")
        full = os.path.normpath(os.path.join(STATIC_DIR, rel))
        if not full.startswith(STATIC_DIR) or not os.path.isfile(full):
            return self._send(404, {"error": "not found"})
        ctype = "text/html"
        if full.endswith(".js"):
            ctype = "application/javascript"
        elif full.endswith(".css"):
            ctype = "text/css"
        with open(full, "rb") as f:
            self._send(200, f.read(), ctype=ctype)


# ==========================================================================
# Endpoints
# ==========================================================================
def h_config(self, conn, match, query):
    """Expose the current mode so the frontend can mirror the XSS behavior."""
    self._send(200, {"mode": MODE})


def h_register(self, conn, match, query):
    body = self._json_body()
    username = (body.get("username") or "").strip()
    password = body.get("password") or ""
    if not username or not password:
        return self._send(400, {"error": "username and password required"})
    if load_user_by_username(conn, username):
        return self._send(409, {"error": "username taken"})

    if MODE == "vuln":
        # VULN (Privilege escalation): the role is taken from a client-controlled
        # field. A registrant can simply send {"role": "admin"} to become admin.
        role = body.get("role", "user")
    else:
        # SECURE: role is assigned by the server. Clients cannot request one.
        role = "user"

    pwd_hash, salt, scheme = auth.hash_password(password, MODE)
    api_key = "sk_live_" + auth.secrets.token_hex(16)
    conn.execute(
        "INSERT INTO users (username, email, full_name, password_hash, salt, "
        "hash_scheme, role, api_key) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (username, body.get("email"), body.get("full_name"),
         pwd_hash, salt, scheme, role, api_key),
    )
    conn.commit()
    user = load_user_by_username(conn, username)
    return self._send(201, {"ok": True, "user": public_user(user)})


def h_login(self, conn, match, query):
    body = self._json_body()
    username = body.get("username") or ""
    password = body.get("password") or ""
    remember = bool(body.get("remember"))

    if MODE == "vuln":
        # VULN (SQL injection): username and password are concatenated straight
        # into the SQL string. A payload like  username = admin'--  logs you in
        # as admin with no password. See VULNERABILITIES.md.
        pwd_md5 = auth.hashlib.md5(password.encode()).hexdigest()
        sql = (
            "SELECT * FROM users WHERE username = '" + username + "' "
            "AND password_hash = '" + pwd_md5 + "'"
        )
        rows = db.vuln_query(conn, sql)
        user = rows[0] if rows else None
    else:
        # SECURE: parameterized lookup, then a constant-time password check.
        rows = db.safe_query(
            conn, "SELECT * FROM users WHERE username = ?", (username,)
        )
        user = rows[0] if rows else None
        if user and not auth.verify_password(password, user):
            user = None

    if not user:
        return self._send(401, {"error": "invalid credentials"})

    token = auth.jwt_encode(
        {"sub": user["id"], "username": user["username"], "role": user["role"]}
    )

    headers = []
    if remember:
        if MODE == "vuln":
            # VULN (Auth bypass): remember-me cookie is just base64(username),
            # unsigned and forgeable.
            cookie = auth.remember_cookie_vuln(user)
            headers.append(("Set-Cookie", f"remember={cookie}; Path=/; HttpOnly"))
        else:
            # SECURE: random token; only its hash is stored server-side.
            raw, digest = auth.new_remember_token_secure()
            conn.execute(
                "INSERT INTO remember_tokens (token_hash, user_id, expires_at) "
                "VALUES (?, ?, datetime('now', '+7 days'))",
                (digest, user["id"]),
            )
            conn.commit()
            headers.append((
                "Set-Cookie",
                f"remember={raw}; Path=/; HttpOnly; SameSite=Strict",
            ))

    return self._send(200, {"token": token, "user": public_user(user)},
                      extra_headers=headers)


def h_logout(self, conn, match, query):
    if MODE == "secure":
        cookies = self._cookies()
        rc = cookies.get("remember")
        if rc:
            conn.execute(
                "DELETE FROM remember_tokens WHERE token_hash = ?",
                (auth.hash_remember_token(rc),),
            )
            conn.commit()
    headers = [("Set-Cookie", "remember=; Path=/; Max-Age=0")]
    return self._send(200, {"ok": True}, extra_headers=headers)


def h_me(self, conn, match, query):
    ident = self.identity(conn)
    if not ident:
        return self._send(401, {"error": "authentication required"})
    user = load_user_by_id(conn, ident.get("sub"))
    if not user:
        return self._send(401, {"error": "unknown user"})
    return self._send(200, {"user": public_user(user)})


def h_get_user(self, conn, match, query):
    target_id = int(match.group("id"))

    if MODE == "vuln":
        # VULN (IDOR): no authorization check. Anyone (even unauthenticated)
        # can read ANY user's record, including api_key and password_hash.
        user = load_user_by_id(conn, target_id)
        if not user:
            return self._send(404, {"error": "not found"})
        return self._send(200, {"user": public_user(user, include_sensitive=True)})
    else:
        # SECURE: must be authenticated; may only read your own record unless
        # you are an admin; secrets are never exposed to non-owners.
        ident = self.identity(conn)
        if not ident:
            return self._send(401, {"error": "authentication required"})
        requester = load_user_by_id(conn, ident.get("sub"))
        if not requester:
            return self._send(401, {"error": "unknown user"})
        is_self = requester["id"] == target_id
        is_admin = requester["role"] == "admin"
        if not (is_self or is_admin):
            return self._send(403, {"error": "forbidden"})
        user = load_user_by_id(conn, target_id)
        if not user:
            return self._send(404, {"error": "not found"})
        return self._send(200, {"user": public_user(user, include_sensitive=is_self or is_admin)})


def h_admin_users(self, conn, match, query):
    ident = self.identity(conn)
    if not ident:
        return self._send(401, {"error": "authentication required"})

    if MODE == "vuln":
        # VULN (Privilege escalation / broken authz): the admin gate trusts the
        # 'role' claim from the (unverified) token. Forge role=admin and you're in.
        if ident.get("role") != "admin":
            return self._send(403, {"error": "admins only"})
    else:
        # SECURE: re-derive the role from the database using the verified subject.
        # The token's own 'role' claim is never trusted for authorization.
        requester = load_user_by_id(conn, ident.get("sub"))
        if not requester or requester["role"] != "admin":
            return self._send(403, {"error": "admins only"})

    users = db.safe_query(conn, "SELECT * FROM users ORDER BY id")
    return self._send(200, {"users": [public_user(u, include_sensitive=True) for u in users]})


def h_search(self, conn, match, query):
    ident = self.identity(conn)
    if not ident:
        return self._send(401, {"error": "authentication required"})
    q = (query.get("q", [""])[0])

    if MODE == "vuln":
        # VULN (SQL injection): the search term is concatenated into the query.
        # A UNION-based payload can dump password_hash / api_key from any table.
        sql = (
            "SELECT id, username, full_name, email FROM users "
            "WHERE full_name LIKE '%" + q + "%'"
        )
        rows = db.vuln_query(conn, sql)
    else:
        # SECURE: the term is bound as a parameter; the % wildcards are added
        # to the *value*, not the SQL text.
        rows = db.safe_query(
            conn,
            "SELECT id, username, full_name, email FROM users "
            "WHERE full_name LIKE ?",
            ("%" + q + "%",),
        )
    return self._send(200, {"results": rows})


def h_list_notes(self, conn, match, query):
    ident = self.identity(conn)
    if not ident:
        return self._send(401, {"error": "authentication required"})
    rows = db.safe_query(
        conn, "SELECT * FROM notes WHERE user_id = ? ORDER BY id", (ident.get("sub"),)
    )
    return self._send(200, {"notes": rows})


def h_create_note(self, conn, match, query):
    ident = self.identity(conn)
    if not ident:
        return self._send(401, {"error": "authentication required"})
    body = self._json_body()
    title = body.get("title") or ""
    note_body = body.get("body") or ""

    if MODE == "secure":
        # SECURE: neutralize markup on the way in (defense in depth; the primary
        # XSS fix is output encoding on the frontend — see static/app.js).
        title = html.escape(title)
        note_body = html.escape(note_body)
    # VULN: in vuln mode the raw note body is stored and later rendered with
    # innerHTML by the frontend -> stored XSS.

    conn.execute(
        "INSERT INTO notes (user_id, title, body) VALUES (?, ?, ?)",
        (ident.get("sub"), title, note_body),
    )
    conn.commit()
    return self._send(201, {"ok": True})


# ==========================================================================
# Route table
# ==========================================================================
ROUTES = [
    ("GET",  re.compile(r"^/api/config$"),               h_config),
    ("POST", re.compile(r"^/api/register$"),             h_register),
    ("POST", re.compile(r"^/api/login$"),                h_login),
    ("POST", re.compile(r"^/api/logout$"),               h_logout),
    ("GET",  re.compile(r"^/api/me$"),                    h_me),
    ("GET",  re.compile(r"^/api/users/(?P<id>\d+)$"),     h_get_user),
    ("GET",  re.compile(r"^/api/admin/users$"),           h_admin_users),
    ("GET",  re.compile(r"^/api/search$"),                h_search),
    ("GET",  re.compile(r"^/api/notes$"),                 h_list_notes),
    ("POST", re.compile(r"^/api/notes$"),                 h_create_note),
]


# ==========================================================================
# Entrypoint
# ==========================================================================
def main():
    db.init_db(MODE, reset=bool(os.environ.get("RESET_DB")))
    banner = "VULNERABLE" if MODE == "vuln" else "SECURE (patched)"
    print("=" * 64)
    print(f"  Auth & Crypto Lab — mode: {MODE.upper()}  [{banner}]")
    print(f"  http://{HOST}:{PORT}")
    print(f"  DB: {db.db_path(MODE)}")
    print("=" * 64)
    httpd = ThreadingHTTPServer((HOST, PORT), Handler)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[app] shutting down")
        httpd.server_close()


if __name__ == "__main__":
    main()
