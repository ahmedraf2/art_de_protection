#!/usr/bin/env python3
"""
Student Management System.

Run:
    python3 app.py                      # default, http://127.0.0.1:3000
    APP_MODE=secure python3 app.py      # hardened build
    RESET_DB=1 python3 app.py           # rebuild + reseed the database

The application ships in two builds selected by APP_MODE. The 'vuln' build
contains the flaws to be demonstrated; the 'secure' build is the patched version.
Vulnerable branches are marked  # VULN:  and their fixes  # SECURE:.
"""

import os
import re
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

import auth
import db
import crypto_utils as cu
import blockchain

MODE = os.environ.get("APP_MODE", "vuln").lower()
if MODE not in ("vuln", "secure"):
    raise SystemExit("APP_MODE must be 'vuln' or 'secure'")

HOST = os.environ.get("HOST", "127.0.0.1")
PORT = int(os.environ.get("PORT", "3000"))
HERE = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(HERE, "static")


def load_user(conn, uid):
    rows = db.run(conn, "SELECT * FROM users WHERE id = ?", (uid,))
    return rows[0] if rows else None


def public_user(u, include_secrets=False):
    out = {"id": u["id"], "username": u["username"], "full_name": u["full_name"],
           "email": u["email"], "role": u["role"]}
    if include_secrets:
        out["password_hash"] = u["password_hash"]
        out["hash_scheme"] = u["hash_scheme"]
    return out


def read_body(m):
    if m.get("is_encrypted"):
        try:
            return cu.decrypt(m["body"])
        except Exception:
            return "[decryption failed]"
    return m["body"]


class Handler(BaseHTTPRequestHandler):
    server_version = "CampusPortal"

    def log_message(self, fmt, *a):
        print("[%s] %s" % (self.address_string(), fmt % a))

    def send_json(self, code, body):
        data = json.dumps(body, indent=2).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def body_json(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        if not n:
            return {}
        try:
            return json.loads(self.rfile.read(n))
        except Exception:
            return {}

    def bearer(self):
        h = self.headers.get("Authorization", "")
        return h[7:].strip() if h.startswith("Bearer ") else None

    def whoami(self, conn):
        """Decode the caller's JWT. Which verifier runs depends on the build."""
        tok = self.bearer()
        if not tok:
            return None
        if MODE == "vuln":
            return auth.jwt_decode_vuln(tok)     # does not verify the signature
        return auth.jwt_decode_secure(tok)       # verifies alg + signature + exp

    def do_GET(self):
        self.route("GET")

    def do_POST(self):
        self.route("POST")

    def do_PUT(self):
        self.route("PUT")

    def route(self, method):
        p = urlparse(self.path)
        path, query = p.path, parse_qs(p.query)

        if method == "GET" and path in ("/", "/index.html"):
            return self.static("index.html")
        if method == "GET" and path.startswith("/static/"):
            return self.static(path[len("/static/"):])

        conn = db.get_conn(MODE)
        try:
            for m, pat, fn in ROUTES:
                if m == method:
                    match = pat.match(path)
                    if match:
                        return fn(self, conn, match, query)
            self.send_json(404, {"error": "not found", "path": path})
        finally:
            conn.close()

    def static(self, rel):
        full = os.path.normpath(os.path.join(STATIC_DIR, rel.lstrip("/")))
        if not full.startswith(STATIC_DIR) or not os.path.isfile(full):
            return self.send_json(404, {"error": "not found"})
        ctype = ("application/javascript" if full.endswith(".js")
                 else "text/css" if full.endswith(".css") else "text/html")
        with open(full, "rb") as f:
            data = f.read()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


# ==========================================================================
# Auth endpoints
# ==========================================================================
def h_config(self, conn, match, query):
    self.send_json(200, {"mode": MODE})


def h_pubkey(self, conn, match, query):
    self.send_json(200, {"issuer_public_key": cu.public_key_pem()})


def h_register(self, conn, match, query):
    b = self.body_json()
    username = (b.get("username") or "").strip()
    password = b.get("password") or ""
    if not username or not password:
        return self.send_json(400, {"error": "username and password required"})
    if db.run(conn, "SELECT 1 FROM users WHERE username = ?", (username,)):
        return self.send_json(409, {"error": "username already taken"})

    if MODE == "vuln":
        role = b.get("role", "student")   # VULN: client can pick its own role
    else:
        role = "student"                  # SECURE: the server assigns the role

    h, salt, scheme = auth.hash_password(password, MODE)
    conn.execute("INSERT INTO users (username, password_hash, salt, hash_scheme, role, "
                 "full_name, email) VALUES (?,?,?,?,?,?,?)",
                 (username, h, salt, scheme, role, b.get("full_name"), b.get("email")))
    conn.commit()
    u = db.run(conn, "SELECT * FROM users WHERE username = ?", (username,))[0]
    self.send_json(201, {"user": public_user(u)})


def h_login(self, conn, match, query):
    b = self.body_json()
    username = b.get("username") or ""
    password = b.get("password") or ""

    if MODE == "vuln":
        # VULN: username/password concatenated straight into SQL.
        #   username = admin'--   logs in as admin without a password.
        pwd_md5 = auth.hashlib.md5(password.encode()).hexdigest()
        sql = ("SELECT * FROM users WHERE username = '" + username +
               "' AND password_hash = '" + pwd_md5 + "'")
        rows = db.run_raw(conn, sql)
        user = rows[0] if rows else None
    else:
        # SECURE: parameterized lookup + constant-time password verification.
        rows = db.run(conn, "SELECT * FROM users WHERE username = ?", (username,))
        user = rows[0] if rows else None
        if user and not auth.verify_password(password, user):
            user = None

    if not user:
        return self.send_json(401, {"error": "invalid username or password"})
    token = auth.jwt_encode({"sub": user["id"], "username": user["username"],
                             "role": user["role"]})
    self.send_json(200, {"token": token, "user": public_user(user)})


def h_me(self, conn, match, query):
    ident = self.whoami(conn)
    if not ident:
        return self.send_json(401, {"error": "authentication required"})
    u = load_user(conn, ident.get("sub"))
    if not u:
        return self.send_json(401, {"error": "unknown user"})
    self.send_json(200, {"user": public_user(u)})


# ==========================================================================
# Academic endpoints
# ==========================================================================
def h_courses(self, conn, match, query):
    """Course catalogue (any authenticated user)."""
    if not self.whoami(conn):
        return self.send_json(401, {"error": "authentication required"})
    rows = db.run(conn,
        "SELECT c.id, c.code, c.name, u.full_name AS professor "
        "FROM courses c LEFT JOIN users u ON u.id = c.professor_id ORDER BY c.code")
    self.send_json(200, {"courses": rows})


def h_my_courses(self, conn, match, query):
    ident = self.whoami(conn)
    if not ident:
        return self.send_json(401, {"error": "authentication required"})
    uid, role = ident.get("sub"), ident.get("role")
    if role == "professor":
        rows = db.run(conn,
            "SELECT c.id, c.code, c.name FROM courses c WHERE c.professor_id = ?", (uid,))
    elif role == "admin":
        rows = db.run(conn, "SELECT id, code, name FROM courses ORDER BY code")
    else:
        rows = db.run(conn,
            "SELECT c.id, c.code, c.name FROM courses c "
            "JOIN enrollments e ON e.course_id = c.id WHERE e.student_id = ?", (uid,))
    self.send_json(200, {"courses": rows})


def h_my_grades(self, conn, match, query):
    ident = self.whoami(conn)
    if not ident:
        return self.send_json(401, {"error": "authentication required"})
    rows = db.run(conn,
        "SELECT g.grade, c.code, c.name FROM grades g JOIN courses c ON c.id = g.course_id "
        "WHERE g.student_id = ? ORDER BY c.name", (ident.get("sub"),))
    self.send_json(200, {"grades": rows})


def h_certifications(self, conn, match, query):
    ident = self.whoami(conn)
    if not ident:
        return self.send_json(401, {"error": "authentication required"})
    student_id = query.get("student_id", [str(ident.get("sub"))])[0]

    if MODE == "vuln":
        # VULN: student_id concatenated into SQL (numeric context) AND no check
        # that you may view this student's records.
        #   ?student_id=0 OR 1=1                        -> every student's certs
        #   ?student_id=0 UNION SELECT ... FROM users   -> exfiltrate other tables
        sql = ("SELECT c.*, u.full_name FROM certifications c "
               "JOIN users u ON u.id = c.student_id "
               "WHERE c.student_id = " + str(student_id))
        rows = db.run_raw(conn, sql)
    else:
        # SECURE: parameterized, and students may only read their own certs.
        if ident.get("role") == "student" and str(student_id) != str(ident.get("sub")):
            return self.send_json(403, {"error": "forbidden"})
        rows = db.run(conn,
            "SELECT c.*, u.full_name FROM certifications c "
            "JOIN users u ON u.id = c.student_id WHERE c.student_id = ?", (student_id,))

    for c in rows:
        if MODE == "vuln":
            # VULN: signatures are never checked and the ledger is never consulted,
            # so a forged certificate looks exactly like a real one.
            c["verified"] = True
        else:
            c["verified"] = cu.verify_cert(c["student_id"], c["title"], c["grade"],
                                           c["issued_date"], c.get("signature"))
            # SECURE: also confirm the certificate is anchored on the ledger.
            fp = cu.cert_fingerprint(c["student_id"], c["title"], c["grade"], c["issued_date"])
            c["on_chain"] = bool(blockchain.find(conn, type="certification", fingerprint=fp))
    self.send_json(200, {"certifications": rows})


def h_issue_cert(self, conn, match, query):
    ident = self.whoami(conn)
    if not ident:
        return self.send_json(401, {"error": "authentication required"})
    b = self.body_json()

    if MODE == "secure":
        # SECURE: only admins may issue certificates.
        me = load_user(conn, ident.get("sub"))
        if not me or me["role"] != "admin":
            return self.send_json(403, {"error": "admins only"})
    # VULN: no authorization check — any user can mint a certificate for anyone.

    student_id, title = b.get("student_id"), b.get("title")
    grade, issued = b.get("grade"), b.get("issued_date")
    # SECURE: sign the certificate so it can be verified later. VULN: unsigned.
    sig = cu.sign_cert(student_id, title, grade, issued) if MODE == "secure" else None
    conn.execute("INSERT INTO certifications (student_id, title, grade, issued_date, "
                 "signature) VALUES (?,?,?,?,?)", (student_id, title, grade, issued, sig))
    conn.commit()

    if MODE == "secure":
        # SECURE: anchor the certificate's fingerprint so anyone can later check
        # that it was really issued here (a forged cert will be "not on chain").
        blockchain.add_block(conn, {
            "type": "certification", "student_id": student_id, "title": title,
            "grade": grade, "issued_date": issued,
            "fingerprint": cu.cert_fingerprint(student_id, title, grade, issued)})
    # VULN: the certificate is neither signed nor anchored.
    self.send_json(201, {"ok": True})


def h_set_grade(self, conn, match, query):
    ident = self.whoami(conn)
    if not ident:
        return self.send_json(401, {"error": "authentication required"})
    b = self.body_json()
    course_id, student_id, grade = b.get("course_id"), b.get("student_id"), b.get("grade")

    if MODE == "secure":
        # SECURE: only an admin, or the professor who owns this course, may grade.
        me = load_user(conn, ident.get("sub"))
        course = db.run(conn, "SELECT * FROM courses WHERE id = ?", (course_id,))
        if not me or not course:
            return self.send_json(400, {"error": "bad request"})
        if not (me["role"] == "admin" or
                (me["role"] == "professor" and course[0]["professor_id"] == me["id"])):
            return self.send_json(403, {"error": "not authorized to grade this course"})
    # VULN: no authorization check — any logged-in user (a student!) can set any
    # grade for any student, including their own.

    existing = db.run(conn, "SELECT id FROM grades WHERE course_id = ? AND student_id = ?",
                      (course_id, student_id))
    if existing:
        conn.execute("UPDATE grades SET grade = ?, updated_by = ? WHERE id = ?",
                     (grade, ident.get("sub"), existing[0]["id"]))
    else:
        conn.execute("INSERT INTO grades (course_id, student_id, grade, updated_by) "
                     "VALUES (?,?,?,?)", (course_id, student_id, grade, ident.get("sub")))
    conn.commit()

    if MODE == "secure":
        # SECURE: anchor every legitimate grade change on the integrity ledger,
        # so a later direct edit to the grades table shows up as DB != chain.
        blockchain.add_block(conn, {"type": "grade", "course_id": course_id,
                                    "student_id": student_id, "grade": grade,
                                    "by": ident.get("sub")})
    # VULN: nothing is anchored and nothing is verified, so tampering with the
    # grades table afterwards goes completely unnoticed.
    self.send_json(200, {"ok": True})


# ==========================================================================
# Chat / messaging
# ==========================================================================
def h_recent_messages(self, conn, match, query):
    """Latest messages involving the current user, for the dashboard widget."""
    ident = self.whoami(conn)
    if not ident:
        return self.send_json(401, {"error": "authentication required"})
    uid = ident.get("sub")
    rows = db.run(conn,
        "SELECT m.*, s.full_name AS sender_name, r.full_name AS recipient_name "
        "FROM messages m JOIN users s ON s.id = m.sender_id JOIN users r ON r.id = m.recipient_id "
        "WHERE m.sender_id = ? OR m.recipient_id = ? ORDER BY m.id DESC LIMIT 5", (uid, uid))
    out = []
    for m in rows:
        out.append({
            "id": m["id"],
            "with": m["recipient_name"] if m["sender_id"] == uid else m["sender_name"],
            "with_id": m["recipient_id"] if m["sender_id"] == uid else m["sender_id"],
            "outgoing": m["sender_id"] == uid,
            "body": read_body(m),
            "created_at": m["created_at"],
        })
    self.send_json(200, {"messages": out})


def h_chats(self, conn, match, query):
    """List the current user's conversations (one row per other participant)."""
    ident = self.whoami(conn)
    if not ident:
        return self.send_json(401, {"error": "authentication required"})
    uid = ident.get("sub")
    rows = db.run(conn,
        "SELECT m.*, s.full_name AS sn, s.username AS su, s.role AS srole, "
        "r.full_name AS rn, r.username AS ru, r.role AS rrole "
        "FROM messages m JOIN users s ON s.id = m.sender_id JOIN users r ON r.id = m.recipient_id "
        "WHERE m.sender_id = ? OR m.recipient_id = ? ORDER BY m.id DESC", (uid, uid))
    convos = {}
    for m in rows:
        outgoing = m["sender_id"] == uid
        other_id = m["recipient_id"] if outgoing else m["sender_id"]
        if other_id not in convos:
            convos[other_id] = {
                "user_id": other_id,
                "name": m["rn"] if outgoing else m["sn"],
                "username": m["ru"] if outgoing else m["su"],
                "role": m["rrole"] if outgoing else m["srole"],
                "last": read_body(m),
                "created_at": m["created_at"],
            }
    self.send_json(200, {"chats": list(convos.values()), "me": uid})


def _chat_param(query, i):
    # accepts chat_users[0]/chat_users[1] (as in the URL) or user1/user2
    v = query.get(f"chat_users[{i}]", query.get("user1" if i == 0 else "user2", [None]))
    return v[0] if v and v[0] not in (None, "") else None


def h_chat(self, conn, match, query):
    ident = self.whoami(conn)
    if not ident:
        return self.send_json(401, {"error": "authentication required"})
    u0, u1 = _chat_param(query, 0), _chat_param(query, 1)
    if u0 is None or u1 is None:
        return self.send_json(400, {"error": "chat_users[0] and chat_users[1] required"})
    try:
        u0, u1 = int(u0), int(u1)
    except ValueError:
        return self.send_json(400, {"error": "invalid chat users"})

    if MODE == "secure":
        # SECURE: you may only open a conversation you are part of (or admin).
        me = load_user(conn, ident.get("sub"))
        if not (me["role"] == "admin" or ident.get("sub") in (u0, u1)):
            return self.send_json(403, {"error": "forbidden"})
    # VULN (IDOR): no check that the caller is a participant. Changing
    # chat_users[0]/chat_users[1] in the URL opens anyone's private conversation,
    # including the professor <-> admin chat.

    rows = db.run(conn,
        "SELECT m.*, s.full_name AS sender_name, s.username AS sender_username "
        "FROM messages m JOIN users s ON s.id = m.sender_id "
        "WHERE (m.sender_id = ? AND m.recipient_id = ?) "
        "   OR (m.sender_id = ? AND m.recipient_id = ?) ORDER BY m.id", (u0, u1, u1, u0))
    msgs = [{
        "id": m["id"], "sender_id": m["sender_id"], "sender_name": m["sender_name"],
        "sender_username": m["sender_username"], "body": read_body(m),
        "created_at": m["created_at"],
    } for m in rows]
    parts = db.run(conn, "SELECT id, full_name, username, role FROM users WHERE id IN (?, ?)",
                   (u0, u1))
    self.send_json(200, {"me": ident.get("sub"), "participants": parts, "messages": msgs})


def h_chat_send(self, conn, match, query):
    ident = self.whoami(conn)
    if not ident:
        return self.send_json(401, {"error": "authentication required"})
    b = self.body_json()
    to = b.get("to")
    rec = db.run(conn, "SELECT id FROM users WHERE id = ? OR username = ?", (to, to))
    if not rec:
        return self.send_json(400, {"error": "unknown recipient"})
    text = b.get("body") or ""
    stored, enc = (cu.encrypt(text), 1) if MODE == "secure" else (text, 0)
    conn.execute("INSERT INTO messages (sender_id, recipient_id, body, is_encrypted) "
                 "VALUES (?,?,?,?)", (ident.get("sub"), rec[0]["id"], stored, enc))
    conn.commit()
    self.send_json(201, {"ok": True})


# ==========================================================================
# Admin
# ==========================================================================
def h_admin_users(self, conn, match, query):
    ident = self.whoami(conn)
    if not ident:
        return self.send_json(401, {"error": "authentication required"})

    if MODE == "vuln":
        # VULN: trusts the role claim from the (unverified) token, and leaks hashes.
        if ident.get("role") != "admin":
            return self.send_json(403, {"error": "admins only"})
        users = db.run(conn, "SELECT * FROM users ORDER BY id")
        return self.send_json(200, {"users": [public_user(u, True) for u in users]})
    else:
        # SECURE: re-check the role against the database; never return secrets.
        me = load_user(conn, ident.get("sub"))
        if not me or me["role"] != "admin":
            return self.send_json(403, {"error": "admins only"})
        users = db.run(conn, "SELECT * FROM users ORDER BY id")
        return self.send_json(200, {"users": [public_user(u) for u in users]})


# ==========================================================================
# Integrity ledger (blockchain)
# ==========================================================================
def _block_summary(b):
    d = b.get("data") or {}
    t = d.get("type")
    if t == "genesis":
        return "Genesis block"
    if t == "grade":
        return f"Grade · course {d.get('course_id')} · student {d.get('student_id')} = {d.get('grade')}/20"
    if t == "certification":
        return f"Certification · \"{d.get('title')}\" → student {d.get('student_id')}"
    return t or "record"


def h_blockchain(self, conn, match, query):
    """The integrity ledger and its live verification result (any user)."""
    if not self.whoami(conn):
        return self.send_json(401, {"error": "authentication required"})
    ok, problems = blockchain.verify_chain(conn)
    out = [{
        "idx": b["idx"], "timestamp": b["timestamp"],
        "type": (b["data"] or {}).get("type"), "summary": _block_summary(b),
        "data": b["data"], "prev_hash": b["prev_hash"],
        "hash": b["hash"], "nonce": b["nonce"],
    } for b in blockchain.blocks(conn)]
    self.send_json(200, {"mode": MODE, "height": len(out),
                         "valid": ok, "problems": problems, "blocks": out})


def h_grade_integrity(self, conn, match, query):
    """Compare the caller's grades in the DB against the ledger (tamper check)."""
    ident = self.whoami(conn)
    if not ident:
        return self.send_json(401, {"error": "authentication required"})
    if MODE == "vuln":
        # VULN: the app never cross-checks the grades table against the ledger,
        # so a tampered grade is accepted at face value.
        return self.send_json(200, {"enforced": False, "rows": []})
    uid = ident.get("sub")
    grades = db.run(conn,
        "SELECT g.course_id, g.grade, c.code, c.name FROM grades g "
        "JOIN courses c ON c.id = g.course_id WHERE g.student_id = ? ORDER BY c.name", (uid,))
    ok, _ = blockchain.verify_chain(conn)
    rows = []
    for g in grades:
        anchored = blockchain.find(conn, type="grade", student_id=uid, course_id=g["course_id"])
        ledger_grade = anchored[-1]["data"].get("grade") if anchored else None
        rows.append({"code": g["code"], "name": g["name"], "db_grade": g["grade"],
                     "ledger_grade": ledger_grade, "ok": ledger_grade == g["grade"]})
    self.send_json(200, {"enforced": True, "chain_valid": ok, "rows": rows})


ROUTES = [
    ("GET",  re.compile(r"^/api/config$"),              h_config),
    ("GET",  re.compile(r"^/api/pubkey$"),              h_pubkey),
    ("POST", re.compile(r"^/api/register$"),            h_register),
    ("POST", re.compile(r"^/api/login$"),               h_login),
    ("GET",  re.compile(r"^/api/me$"),                   h_me),
    ("GET",  re.compile(r"^/api/courses$"),              h_courses),
    ("GET",  re.compile(r"^/api/my/courses$"),           h_my_courses),
    ("GET",  re.compile(r"^/api/my/grades$"),            h_my_grades),
    ("GET",  re.compile(r"^/api/certifications$"),        h_certifications),
    ("POST", re.compile(r"^/api/certifications$"),        h_issue_cert),
    ("POST", re.compile(r"^/api/grades$"),               h_set_grade),
    ("GET",  re.compile(r"^/api/messages/recent$"),      h_recent_messages),
    ("GET",  re.compile(r"^/api/chats$"),                h_chats),
    ("GET",  re.compile(r"^/api/chat$"),                 h_chat),
    ("POST", re.compile(r"^/api/chat$"),                 h_chat_send),
    ("GET",  re.compile(r"^/api/admin/users$"),          h_admin_users),
    ("GET",  re.compile(r"^/api/grades/integrity$"),     h_grade_integrity),
    ("GET",  re.compile(r"^/api/blockchain$"),           h_blockchain),
]


def main():
    db.init_db(MODE, reset=bool(os.environ.get("RESET_DB")))
    print("=" * 60)
    print(f"  Campus Portal — Student Management System [{MODE.upper()}]")
    print(f"  http://{HOST}:{PORT}")
    print(f"  database: {db.db_path(MODE)}")
    print("=" * 60)
    httpd = ThreadingHTTPServer((HOST, PORT), Handler)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nshutting down")
        httpd.server_close()


if __name__ == "__main__":
    main()
