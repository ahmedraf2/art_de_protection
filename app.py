#!/usr/bin/env python3
"""
Student Management System — Flask application.

Run:
    python3 app.py                      # default, http://127.0.0.1:3000
    APP_MODE=secure python3 app.py      # hardened build
    RESET_DB=1 python3 app.py           # rebuild + reseed the database

The application ships in two builds selected by APP_MODE. The 'vuln' build
contains the flaws to be demonstrated; the 'secure' build is the patched version.
Vulnerable branches are marked  # VULN:  and their fixes  # SECURE:.
"""

import os
import functools

from flask import Flask, request, jsonify, g, send_from_directory

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

app = Flask(__name__, static_folder=STATIC_DIR, static_url_path="/static")


# ==========================================================================
# Per-request plumbing
# ==========================================================================
def get_db():
    if "db" not in g:
        g.db = db.get_conn(MODE)
    return g.db


@app.teardown_request
def _close_db(_exc):
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


def whoami():
    """Decode the caller's JWT. Which verifier runs depends on the build."""
    h = request.headers.get("Authorization", "")
    tok = h[7:].strip() if h.startswith("Bearer ") else None
    if not tok:
        return None
    if MODE == "vuln":
        return auth.jwt_decode_vuln(tok)     # does not verify the signature
    return auth.jwt_decode_secure(tok)       # verifies alg + signature + exp


def require_auth(fn):
    """Reject the request with 401 unless it carries a usable token.

    On success the decoded identity is available as g.ident."""
    @functools.wraps(fn)
    def wrapper(*a, **k):
        ident = whoami()
        if not ident:
            return jsonify({"error": "authentication required"}), 401
        g.ident = ident
        return fn(*a, **k)
    return wrapper


def public_user(u, include_secrets=False):
    out = {"id": u["id"], "username": u["username"], "full_name": u["full_name"],
           "email": u["email"], "role": u["role"]}
    if include_secrets:
        out["password_hash"] = u["password_hash"]
        out["hash_scheme"] = u["hash_scheme"]
    return out


def load_user(conn, uid):
    rows = db.run(conn, "SELECT * FROM users WHERE id = ?", (uid,))
    return rows[0] if rows else None


def read_body(m):
    if m.get("is_encrypted"):
        try:
            return cu.decrypt(m["body"])
        except Exception:
            return "[decryption failed]"
    return m["body"]


# ==========================================================================
# Front-end
# ==========================================================================
@app.get("/")
@app.get("/index.html")
def index():
    return send_from_directory(STATIC_DIR, "index.html")


# ==========================================================================
# Auth endpoints
# ==========================================================================
@app.get("/api/config")
def h_config():
    return jsonify({"mode": MODE})


@app.get("/api/pubkey")
def h_pubkey():
    return jsonify({"issuer_public_key": cu.public_key_pem()})


@app.post("/api/register")
def h_register():
    conn = get_db()
    b = request.get_json(silent=True) or {}
    username = (b.get("username") or "").strip()
    password = b.get("password") or ""
    if not username or not password:
        return jsonify({"error": "username and password required"}), 400
    if db.run(conn, "SELECT 1 FROM users WHERE username = ?", (username,)):
        return jsonify({"error": "username already taken"}), 409

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
    return jsonify({"user": public_user(u)}), 201


@app.post("/api/login")
def h_login():
    conn = get_db()
    b = request.get_json(silent=True) or {}
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
        return jsonify({"error": "invalid username or password"}), 401
    token = auth.jwt_encode({"sub": user["id"], "username": user["username"],
                             "role": user["role"]})
    return jsonify({"token": token, "user": public_user(user)})


@app.get("/api/me")
@require_auth
def h_me():
    u = load_user(get_db(), g.ident.get("sub"))
    if not u:
        return jsonify({"error": "unknown user"}), 401
    return jsonify({"user": public_user(u)})


# ==========================================================================
# Academic endpoints
# ==========================================================================
@app.get("/api/courses")
@require_auth
def h_courses():
    """Course catalogue (any authenticated user)."""
    rows = db.run(get_db(),
        "SELECT c.id, c.code, c.name, u.full_name AS professor "
        "FROM courses c LEFT JOIN users u ON u.id = c.professor_id ORDER BY c.code")
    return jsonify({"courses": rows})


@app.get("/api/my/courses")
@require_auth
def h_my_courses():
    conn = get_db()
    uid, role = g.ident.get("sub"), g.ident.get("role")
    if role == "professor":
        rows = db.run(conn,
            "SELECT c.id, c.code, c.name FROM courses c WHERE c.professor_id = ?", (uid,))
    elif role == "admin":
        rows = db.run(conn, "SELECT id, code, name FROM courses ORDER BY code")
    else:
        rows = db.run(conn,
            "SELECT c.id, c.code, c.name FROM courses c "
            "JOIN enrollments e ON e.course_id = c.id WHERE e.student_id = ?", (uid,))
    return jsonify({"courses": rows})


@app.get("/api/my/grades")
@require_auth
def h_my_grades():
    rows = db.run(get_db(),
        "SELECT g.grade, c.code, c.name FROM grades g JOIN courses c ON c.id = g.course_id "
        "WHERE g.student_id = ? ORDER BY c.name", (g.ident.get("sub"),))
    return jsonify({"grades": rows})


@app.get("/api/certifications")
@require_auth
def h_certifications():
    conn = get_db()
    student_id = request.args.get("student_id", str(g.ident.get("sub")))

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
        if g.ident.get("role") == "student" and str(student_id) != str(g.ident.get("sub")):
            return jsonify({"error": "forbidden"}), 403
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
    return jsonify({"certifications": rows})


@app.post("/api/certifications")
@require_auth
def h_issue_cert():
    conn = get_db()
    b = request.get_json(silent=True) or {}

    if MODE == "secure":
        # SECURE: only admins may issue certificates.
        me = load_user(conn, g.ident.get("sub"))
        if not me or me["role"] != "admin":
            return jsonify({"error": "admins only"}), 403
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
    return jsonify({"ok": True}), 201


@app.post("/api/grades")
@require_auth
def h_set_grade():
    conn = get_db()
    b = request.get_json(silent=True) or {}
    course_id, student_id, grade = b.get("course_id"), b.get("student_id"), b.get("grade")

    if MODE == "secure":
        # SECURE: only an admin, or the professor who owns this course, may grade.
        me = load_user(conn, g.ident.get("sub"))
        course = db.run(conn, "SELECT * FROM courses WHERE id = ?", (course_id,))
        if not me or not course:
            return jsonify({"error": "bad request"}), 400
        if not (me["role"] == "admin" or
                (me["role"] == "professor" and course[0]["professor_id"] == me["id"])):
            return jsonify({"error": "not authorized to grade this course"}), 403
    # VULN: no authorization check — any logged-in user (a student!) can set any
    # grade for any student, including their own.

    existing = db.run(conn, "SELECT id FROM grades WHERE course_id = ? AND student_id = ?",
                      (course_id, student_id))
    if existing:
        conn.execute("UPDATE grades SET grade = ?, updated_by = ? WHERE id = ?",
                     (grade, g.ident.get("sub"), existing[0]["id"]))
    else:
        conn.execute("INSERT INTO grades (course_id, student_id, grade, updated_by) "
                     "VALUES (?,?,?,?)", (course_id, student_id, grade, g.ident.get("sub")))
    conn.commit()

    if MODE == "secure":
        # SECURE: anchor every legitimate grade change on the integrity ledger,
        # so a later direct edit to the grades table shows up as DB != chain.
        blockchain.add_block(conn, {"type": "grade", "course_id": course_id,
                                    "student_id": student_id, "grade": grade,
                                    "by": g.ident.get("sub")})
    # VULN: nothing is anchored and nothing is verified, so tampering with the
    # grades table afterwards goes completely unnoticed.
    return jsonify({"ok": True})


# ==========================================================================
# Chat / messaging
# ==========================================================================
@app.get("/api/messages/recent")
@require_auth
def h_recent_messages():
    """Latest messages involving the current user, for the dashboard widget."""
    conn = get_db()
    uid = g.ident.get("sub")
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
    return jsonify({"messages": out})


@app.get("/api/chats")
@require_auth
def h_chats():
    """List the current user's conversations (one row per other participant)."""
    conn = get_db()
    uid = g.ident.get("sub")
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
    return jsonify({"chats": list(convos.values()), "me": uid})


def _chat_param(i):
    # accepts chat_users[0]/chat_users[1] (as in the URL) or user1/user2
    v = request.args.get(f"chat_users[{i}]")
    if v is None:
        v = request.args.get("user1" if i == 0 else "user2")
    return v if v not in (None, "") else None


@app.get("/api/chat")
@require_auth
def h_chat():
    conn = get_db()
    u0, u1 = _chat_param(0), _chat_param(1)
    if u0 is None or u1 is None:
        return jsonify({"error": "chat_users[0] and chat_users[1] required"}), 400
    try:
        u0, u1 = int(u0), int(u1)
    except ValueError:
        return jsonify({"error": "invalid chat users"}), 400

    if MODE == "secure":
        # SECURE: you may only open a conversation you are part of (or admin).
        me = load_user(conn, g.ident.get("sub"))
        if not (me["role"] == "admin" or g.ident.get("sub") in (u0, u1)):
            return jsonify({"error": "forbidden"}), 403
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
    return jsonify({"me": g.ident.get("sub"), "participants": parts, "messages": msgs})


@app.post("/api/chat")
@require_auth
def h_chat_send():
    conn = get_db()
    b = request.get_json(silent=True) or {}
    to = b.get("to")
    rec = db.run(conn, "SELECT id FROM users WHERE id = ? OR username = ?", (to, to))
    if not rec:
        return jsonify({"error": "unknown recipient"}), 400
    text = b.get("body") or ""
    stored, enc = (cu.encrypt(text), 1) if MODE == "secure" else (text, 0)
    conn.execute("INSERT INTO messages (sender_id, recipient_id, body, is_encrypted) "
                 "VALUES (?,?,?,?)", (g.ident.get("sub"), rec[0]["id"], stored, enc))
    conn.commit()
    return jsonify({"ok": True}), 201


# ==========================================================================
# Admin
# ==========================================================================
@app.get("/api/admin/users")
@require_auth
def h_admin_users():
    conn = get_db()
    if MODE == "vuln":
        # VULN: trusts the role claim from the (unverified) token, and leaks hashes.
        if g.ident.get("role") != "admin":
            return jsonify({"error": "admins only"}), 403
        users = db.run(conn, "SELECT * FROM users ORDER BY id")
        return jsonify({"users": [public_user(u, True) for u in users]})
    else:
        # SECURE: re-check the role against the database; never return secrets.
        me = load_user(conn, g.ident.get("sub"))
        if not me or me["role"] != "admin":
            return jsonify({"error": "admins only"}), 403
        users = db.run(conn, "SELECT * FROM users ORDER BY id")
        return jsonify({"users": [public_user(u) for u in users]})


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


@app.get("/api/blockchain")
@require_auth
def h_blockchain():
    """The integrity ledger and its live verification result (any user)."""
    conn = get_db()
    ok, problems = blockchain.verify_chain(conn)
    out = [{
        "idx": b["idx"], "timestamp": b["timestamp"],
        "type": (b["data"] or {}).get("type"), "summary": _block_summary(b),
        "data": b["data"], "prev_hash": b["prev_hash"],
        "hash": b["hash"], "nonce": b["nonce"],
    } for b in blockchain.blocks(conn)]
    return jsonify({"mode": MODE, "height": len(out),
                    "valid": ok, "problems": problems, "blocks": out})


@app.get("/api/grades/integrity")
@require_auth
def h_grade_integrity():
    """Compare the caller's grades in the DB against the ledger (tamper check)."""
    conn = get_db()
    if MODE == "vuln":
        # VULN: the app never cross-checks the grades table against the ledger,
        # so a tampered grade is accepted at face value.
        return jsonify({"enforced": False, "rows": []})
    uid = g.ident.get("sub")
    grades = db.run(conn,
        "SELECT g.course_id, g.grade, c.code, c.name FROM grades g "
        "JOIN courses c ON c.id = g.course_id WHERE g.student_id = ? ORDER BY c.name", (uid,))
    ok, _ = blockchain.verify_chain(conn)
    rows = []
    for gr in grades:
        anchored = blockchain.find(conn, type="grade", student_id=uid, course_id=gr["course_id"])
        ledger_grade = anchored[-1]["data"].get("grade") if anchored else None
        rows.append({"code": gr["code"], "name": gr["name"], "db_grade": gr["grade"],
                     "ledger_grade": ledger_grade, "ok": ledger_grade == gr["grade"]})
    return jsonify({"enforced": True, "chain_valid": ok, "rows": rows})


def main():
    db.init_db(MODE, reset=bool(os.environ.get("RESET_DB")))
    print("=" * 60)
    print(f"  Campus Portal — Student Management System [{MODE.upper()}]")
    print(f"  http://{HOST}:{PORT}")
    print(f"  database: {db.db_path(MODE)}")
    print("=" * 60)
    # threaded so concurrent requests behave like the previous server; the Flask
    # dev server is fine for this local lab (not for production).
    app.run(host=HOST, port=PORT, threaded=True)


if __name__ == "__main__":
    main()
