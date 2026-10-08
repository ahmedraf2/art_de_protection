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
import hashlib
import secrets
import functools
from datetime import date

from flask import Flask, request, jsonify, g, send_from_directory, send_file

import auth
import db
import crypto_utils as cu
import eth_ledger

MODE = os.environ.get("APP_MODE", "vuln").lower()
if MODE not in ("vuln", "secure"):
    raise SystemExit("APP_MODE must be 'vuln' or 'secure'")

HOST = os.environ.get("HOST", "127.0.0.1")
PORT = int(os.environ.get("PORT", "3000"))
HERE = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(HERE, "static")
UPLOAD_DIR = os.path.join(HERE, "uploads", MODE)   # document attachments (per build)
os.makedirs(UPLOAD_DIR, exist_ok=True)

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
           "email": u["email"], "role": u["role"],
           "phone": u["phone"], "address": u["address"]}
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


@app.get("/api/search")
@require_auth
def h_search():
    """Course search: find courses by code or name (any student or professor)."""
    conn = get_db()
    query = request.args.get("query", "")

    if MODE == "vuln":
        # VULN (#10): the search term is concatenated straight into SQL and run
        # with a helper that also executes STACKED statements. A classic read works
        # (the result has 3 columns, so a 3-column UNION lines up):
        #   ?query=' UNION SELECT id, password_hash, role FROM users --
        # but because the statement can be stacked, the search box is also a
        # WRITE primitive — no admin login, no Gradebook access needed:
        #   ?query=%'; UPDATE grades SET grade='20.00'
        #           WHERE student_id=4 AND course_id=1; --
        # changes Alice's Mathematics grade, and nothing in this build notices.
        sql = ("SELECT id, code, name FROM courses "
               "WHERE name LIKE '%" + query + "%' OR code LIKE '%" + query + "%' ORDER BY code")
        rows = db.run_raw_multi(conn, sql)
    else:
        # SECURE: the term is bound as a parameter (so it is only ever data, never
        # SQL) and the query is a single statement — stacked writes are impossible.
        rows = db.run(conn,
            "SELECT id, code, name FROM courses WHERE name LIKE ? OR code LIKE ? ORDER BY code",
            ("%" + query + "%", "%" + query + "%"))
    return jsonify({"results": rows})


@app.get("/api/users/directory")
@require_auth
def h_user_directory():
    """Everyone the caller can start a conversation with (any authenticated user).
    Parameterized and read-only — this is the messaging recipient picker, not the
    injectable course search above."""
    uid = g.ident.get("sub")
    rows = db.run(get_db(),
        "SELECT id, full_name, username, role FROM users WHERE id != ? ORDER BY full_name", (uid,))
    return jsonify({"users": rows})


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

    chain_down = False
    for c in rows:
        if MODE == "vuln":
            # VULN: signatures are never checked and the ledger is never consulted,
            # so a forged certificate looks exactly like a real one.
            c["verified"] = True
        else:
            c["verified"] = cu.verify_cert(c["student_id"], c["title"], c["grade"],
                                           c["issued_date"], c.get("signature"))
            # SECURE: also confirm the certificate is anchored in the contract.
            # If the node is down we can't tell: report null ("unavailable").
            fp = cu.cert_fingerprint(c["student_id"], c["title"], c["grade"], c["issued_date"])
            c["on_chain"] = None
            if not chain_down:
                try:
                    c["on_chain"] = eth_ledger.is_cert_anchored(fp)
                except eth_ledger.LedgerUnavailable:
                    chain_down = True
    return jsonify({"certifications": rows})


@app.get("/api/my/roster")
@require_auth
def h_my_roster():
    """A professor's courses with the students enrolled in each (for grading /
    issuing certificates). Admins see every course. Students may not."""
    conn = get_db()
    me = load_user(conn, g.ident.get("sub"))
    if not me or me["role"] not in ("professor", "admin"):
        return jsonify({"error": "professors only"}), 403
    sql = ("SELECT c.id AS course_id, c.code, c.name, u.id AS student_id, u.full_name "
           "FROM courses c JOIN enrollments e ON e.course_id = c.id "
           "JOIN users u ON u.id = e.student_id AND u.role = 'student' ")
    params = ()
    if me["role"] == "professor":
        sql += "WHERE c.professor_id = ? "
        params = (me["id"],)
    sql += "ORDER BY c.name, u.full_name"
    courses = {}
    for r in db.run(conn, sql, params):
        c = courses.setdefault(r["course_id"],
                               {"course_id": r["course_id"], "code": r["code"],
                                "name": r["name"], "students": []})
        c["students"].append({"id": r["student_id"], "full_name": r["full_name"]})
    return jsonify({"courses": list(courses.values()), "cert_types": db.CERT_TYPES})


@app.get("/api/my/certifications-issued")
@require_auth
def h_my_issued_certs():
    """Certificates the current professor/admin has issued, with student names."""
    conn = get_db()
    me = load_user(conn, g.ident.get("sub"))
    if not me or me["role"] not in ("professor", "admin"):
        return jsonify({"error": "professors only"}), 403
    rows = db.run(conn,
        "SELECT c.id, c.title, c.grade, c.issued_date, u.full_name AS student "
        "FROM certifications c JOIN users u ON u.id = c.student_id "
        "WHERE c.issued_by = ? ORDER BY c.id DESC", (me["id"],))
    return jsonify({"certifications": rows})


@app.post("/api/certifications")
@require_auth
def h_issue_cert():
    conn = get_db()
    b = request.get_json(silent=True) or {}

    if MODE == "vuln":
        # VULN: no authorization check — any logged-in user can mint a certificate
        # for anyone, with any client-supplied title, unsigned and unanchored
        # (vulnerabilities #6b and #8). Behaviour unchanged.
        student_id, title = b.get("student_id"), b.get("title")
        grade, issued = b.get("grade"), b.get("issued_date")
        conn.execute("INSERT INTO certifications (student_id, title, grade, issued_date, "
                     "signature, issued_by) VALUES (?,?,?,?,?,?)",
                     (student_id, title, grade, issued, None, g.ident.get("sub")))
        conn.commit()
        return jsonify({"ok": True}), 201

    # SECURE: a professor (or admin) issues a certificate only for a course they
    # teach, only to a student actually enrolled in it, and only a recognised
    # certificate type — so the title cannot be forged client-side and a
    # professor/admin can never be given one.
    me = load_user(conn, g.ident.get("sub"))
    if not me or me["role"] not in ("professor", "admin"):
        return jsonify({"error": "only professors may issue certificates"}), 403
    cert_type = b.get("cert_type")
    if cert_type not in db.CERT_TYPES:
        return jsonify({"error": "unknown certificate type"}), 400
    course = db.run(conn, "SELECT * FROM courses WHERE id = ?", (b.get("course_id"),))
    if not course:
        return jsonify({"error": "unknown course"}), 400
    course = course[0]
    if me["role"] == "professor" and course["professor_id"] != me["id"]:
        return jsonify({"error": "you do not teach this course"}), 403
    student = db.run(conn, "SELECT * FROM users WHERE id = ?", (b.get("student_id"),))
    if not student or student[0]["role"] != "student":
        return jsonify({"error": "certificates can only be issued to students"}), 403
    student = student[0]
    if not db.run(conn, "SELECT 1 FROM enrollments WHERE course_id = ? AND student_id = ?",
                  (course["id"], student["id"])):
        return jsonify({"error": "that student is not enrolled in this course"}), 400

    title = f"{cert_type}: {course['name']}"
    gr = db.run(conn, "SELECT grade FROM grades WHERE course_id = ? AND student_id = ?",
                (course["id"], student["id"]))
    grade = gr[0]["grade"] if gr else "Completed"
    # SECURE: honour the certificate's grade requirement. The vuln build ignores
    # this, so an "Honors Distinction" can be minted for a failing grade.
    min_grade = db.CERT_MIN_GRADE.get(cert_type)
    if min_grade is not None:
        try:
            gval = float(grade)
        except (TypeError, ValueError):
            return jsonify({"error": f"'{cert_type}' requires a recorded grade of at "
                                     f"least {min_grade:g}/20"}), 400
        if gval < min_grade:
            return jsonify({"error": f"'{cert_type}' requires at least {min_grade:g}/20 "
                                     f"(student has {grade}/20)"}), 400
    issued = b.get("issued_date") or date.today().isoformat()
    sig = cu.sign_cert(student["id"], title, grade, issued)   # SECURE: signed
    cur = conn.execute("INSERT INTO certifications (student_id, title, grade, issued_date, "
                       "signature, issued_by) VALUES (?,?,?,?,?,?)",
                       (student["id"], title, grade, issued, sig, me["id"]))
    # SECURE: anchor the fingerprint (from the row as stored); commit only if the
    # contract accepted it, so a forged cert will later show as "not on chain".
    c = db.run(conn, "SELECT * FROM certifications WHERE id = ?", (cur.lastrowid,))[0]
    try:
        eth_ledger.anchor_cert(cu.cert_fingerprint(c["student_id"], c["title"],
                                                   c["grade"], c["issued_date"]))
    except eth_ledger.LedgerUnavailable as e:
        conn.rollback()
        return jsonify({"error": f"integrity ledger unavailable: {e}"}), 503
    conn.commit()
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
        # SECURE: validate the grade is a number on the 0–20 scale. The vuln build
        # accepts anything ("abc", "25", "-5") with no validation at all.
        try:
            gval = float(grade)
        except (TypeError, ValueError):
            return jsonify({"error": "grade must be a number between 0 and 20"}), 400
        if not 0 <= gval <= 20:
            return jsonify({"error": "grade must be between 0 and 20"}), 400
        grade = f"{gval:.2f}"
    # VULN: no authorization check — any logged-in user (a student!) can set any
    # grade for any student, including their own — and no validation of the value.

    existing = db.run(conn, "SELECT id FROM grades WHERE course_id = ? AND student_id = ?",
                      (course_id, student_id))
    if existing:
        conn.execute("UPDATE grades SET grade = ?, updated_by = ? WHERE id = ?",
                     (grade, g.ident.get("sub"), existing[0]["id"]))
    else:
        conn.execute("INSERT INTO grades (course_id, student_id, grade, updated_by) "
                     "VALUES (?,?,?,?)", (course_id, student_id, grade, g.ident.get("sub")))

    if MODE == "secure":
        # SECURE: anchor the hash of every legitimate grade change in the contract,
        # so a later direct edit to the grades table shows up as DB != ledger.
        # The hash is computed from the row as stored, and the DB change is
        # committed only if the transaction succeeded.
        row = db.run(conn, "SELECT course_id, student_id, grade FROM grades "
                           "WHERE course_id = ? AND student_id = ?", (course_id, student_id))[0]
        try:
            eth_ledger.anchor_grade(row["course_id"], row["student_id"],
                                    eth_ledger.grade_hash(**row))
        except eth_ledger.LedgerUnavailable as e:
            conn.rollback()
            return jsonify({"error": f"integrity ledger unavailable: {e}"}), 503
    # VULN: nothing is anchored and nothing is verified, so tampering with the
    # grades table afterwards goes completely unnoticed.
    conn.commit()
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


def _tampered_grades(conn):
    """Every grade whose DB value no longer matches its on-chain hash.

    Raises eth_ledger.LedgerUnavailable if the node can't be reached.
    """
    grades = db.run(conn,
        "SELECT g.course_id, g.student_id, g.grade, c.code, c.name AS course, "
        "u.full_name AS student FROM grades g JOIN courses c ON c.id = g.course_id "
        "JOIN users u ON u.id = g.student_id ORDER BY u.full_name, c.name")
    out = []
    for gr in grades:
        db_hash = eth_ledger.grade_hash(gr["course_id"], gr["student_id"], gr["grade"])
        chain_hash = eth_ledger.get_grade(gr["course_id"], gr["student_id"])
        if db_hash != chain_hash:
            out.append({"course_id": gr["course_id"], "student_id": gr["student_id"],
                        "code": gr["code"], "course": gr["course"], "student": gr["student"],
                        "db_grade": gr["grade"],
                        "true_grade": eth_ledger.recover_grade(gr["course_id"],
                                                               gr["student_id"], chain_hash)})
    return out


@app.get("/api/admin/integrity")
@require_auth
def h_admin_integrity():
    """Admin tamper monitor: list grades whose DB value != the ledger."""
    if MODE == "vuln":
        return jsonify({"error": "no integrity ledger in this build"}), 404
    conn = get_db()
    me = load_user(conn, g.ident.get("sub"))
    if not me or me["role"] != "admin":
        return jsonify({"error": "admins only"}), 403
    try:
        return jsonify({"available": True, "alerts": _tampered_grades(conn)})
    except eth_ledger.LedgerUnavailable as e:
        return jsonify({"available": False, "error": str(e), "alerts": []}), 503


@app.post("/api/admin/integrity/fix")
@require_auth
def h_admin_integrity_fix():
    """Restore tampered grades to the value the issuer anchored in the contract.

    With no body, fixes every tampered grade; with {course_id, student_id}, fixes
    one. The contract holds only the hash, so the correct value is the one
    recovered from it (eth_ledger.recover_grade). After the write the DB hash
    matches the chain again, so the alert clears — the existing anchor is still
    valid, so nothing new is written to the chain.
    """
    if MODE == "vuln":
        return jsonify({"error": "no integrity ledger in this build"}), 404
    conn = get_db()
    me = load_user(conn, g.ident.get("sub"))
    if not me or me["role"] != "admin":
        return jsonify({"error": "admins only"}), 403
    b = request.get_json(silent=True) or {}
    only = (b.get("course_id"), b.get("student_id"))
    try:
        tampered = _tampered_grades(conn)
    except eth_ledger.LedgerUnavailable as e:
        return jsonify({"error": str(e)}), 503

    restored = []
    for a in tampered:
        if only != (None, None) and (a["course_id"], a["student_id"]) != only:
            continue
        if a["true_grade"] is None:
            continue                       # correct value couldn't be recovered
        conn.execute("UPDATE grades SET grade = ?, updated_by = ? "
                     "WHERE course_id = ? AND student_id = ?",
                     (a["true_grade"], g.ident.get("sub"), a["course_id"], a["student_id"]))
        restored.append(a)
    conn.commit()
    return jsonify({"ok": True, "restored": len(restored)})


# ==========================================================================
# Integrity ledger (GradeLedger smart contract on a local anvil node)
# ==========================================================================
@app.get("/api/blockchain")
@require_auth
def h_blockchain():
    """Contract address, issuer and every anchored event (any user)."""
    if MODE == "vuln":
        # VULN: this build has no integrity ledger, so nothing ever checks the
        # grades/certifications tables for tampering (vulnerability #9).
        return jsonify({"error": "no integrity ledger in this build"}), 404
    # SECURE: the raw ledger explorer (every student's anchors, tx hashes, the
    # contract address) is an operations/audit view, not something a student
    # should see — restrict it to admins. Students get their own grades verified
    # inline on the dashboard instead.
    me = load_user(get_db(), g.ident.get("sub"))
    if not me or me["role"] != "admin":
        return jsonify({"error": "admins only"}), 403
    try:
        return jsonify({"mode": MODE, "available": True, **eth_ledger.info()})
    except eth_ledger.LedgerUnavailable as e:
        return jsonify({"mode": MODE, "available": False, "error": str(e), "events": []}), 503


@app.get("/api/grades/integrity")
@require_auth
def h_grade_integrity():
    """Compare the caller's grades in the DB against the contract (tamper check)."""
    if MODE == "vuln":
        # VULN: this build has no integrity ledger, so nothing ever checks the
        # grades/certifications tables for tampering (vulnerability #9).
        return jsonify({"error": "no integrity ledger in this build"}), 404
    conn = get_db()
    # SECURE: recompute each grade's hash from the DB and compare it with the
    # hash the issuer anchored in the contract. Any direct DB edit -> mismatch.
    uid = g.ident.get("sub")
    grades = db.run(conn,
        "SELECT g.course_id, g.student_id, g.grade, c.code, c.name FROM grades g "
        "JOIN courses c ON c.id = g.course_id WHERE g.student_id = ? ORDER BY c.name", (uid,))
    rows = []
    try:
        for gr in grades:
            db_hash = eth_ledger.grade_hash(gr["course_id"], gr["student_id"], gr["grade"])
            chain_hash = eth_ledger.get_grade(gr["course_id"], gr["student_id"])
            ok = db_hash == chain_hash
            # The real (anchored) grade: the DB value when it checks out, else the
            # value recovered from the on-chain hash — so the UI can show the true
            # grade next to a tampered one.
            true_grade = gr["grade"] if ok else \
                eth_ledger.recover_grade(gr["course_id"], gr["student_id"], chain_hash)
            rows.append({"code": gr["code"], "name": gr["name"], "db_grade": gr["grade"],
                         "db_hash": db_hash, "chain_hash": chain_hash,
                         "ok": ok, "true_grade": true_grade})
    except eth_ledger.LedgerUnavailable as e:
        return jsonify({"available": False, "error": str(e), "rows": []}), 503
    return jsonify({"available": True, "rows": rows})


# ==========================================================================
# Announcements (campus news feed)  —  stored-XSS pair (#11)
# ==========================================================================
@app.get("/api/announcements")
@require_auth
def h_announcements():
    rows = db.run(get_db(),
        "SELECT a.id, a.title, a.body, a.created_at, u.full_name AS author, "
        "u.role AS author_role FROM announcements a "
        "LEFT JOIN users u ON u.id = a.author_id ORDER BY a.id DESC")
    return jsonify({"announcements": rows})


@app.post("/api/announcements")
@require_auth
def h_post_announcement():
    conn = get_db()
    me = load_user(conn, g.ident.get("sub"))
    # Only staff may post to the campus feed (same rule in both builds).
    if not me or me["role"] not in ("professor", "admin"):
        return jsonify({"error": "only staff may post announcements"}), 403
    b = request.get_json(silent=True) or {}
    title = (b.get("title") or "").strip()
    if not title:
        return jsonify({"error": "a title is required"}), 400
    # The body is stored exactly as submitted in BOTH builds. The vuln/secure
    # difference is how the browser RENDERS it (see announceBody() in app.js):
    #   VULN   #11: the body is injected as raw HTML, so <script>/<img onerror>
    #               stored here runs in every reader's browser (stored XSS).
    #   SECURE:     the body is HTML-escaped on output (output encoding).
    # Storing the raw text is realistic — encoding is an output-time concern.
    conn.execute("INSERT INTO announcements (author_id, title, body) VALUES (?,?,?)",
                 (me["id"], title, b.get("body") or ""))
    conn.commit()
    return jsonify({"ok": True}), 201


# ==========================================================================
# Administrative documents  —  IDOR pair (#12) + file-upload pair (#15)
# ==========================================================================
def _save_upload(fs):
    """Store an uploaded file and return the filename to record in the DB.
    Raises ValueError (secure build only) when the file is rejected."""
    if MODE == "vuln":
        # VULN (#15): the client-supplied filename is trusted (path traversal on
        # write) and there is NO content-type / extension / size check. Combined
        # with the inline download below, uploading a .svg/.html "document" that
        # contains a <script> becomes a stored XSS that fires for whoever opens it
        # (e.g. the registrar reviewing the request).
        name = fs.filename or "upload.bin"
        dest = os.path.join(UPLOAD_DIR, name)
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        fs.save(dest)
        return name
    # SECURE: ignore the client filename, require a real PDF (magic bytes), cap the
    # size, and store under a random, server-generated name inside the upload dir.
    data = fs.read()
    if len(data) > 5 * 1024 * 1024:
        raise ValueError("file too large (max 5 MB)")
    if not data.startswith(b"%PDF-"):
        raise ValueError("only PDF files are accepted")
    name = secrets.token_hex(16) + ".pdf"
    with open(os.path.join(UPLOAD_DIR, name), "wb") as f:
        f.write(data)
    return name


@app.post("/api/documents")
@require_auth
def h_request_document():
    """A student requests an official document and attaches a supporting PDF."""
    conn = get_db()
    me = load_user(conn, g.ident.get("sub"))
    doc_type = request.form.get("doc_type")
    if doc_type not in db.DOC_TYPES:
        return jsonify({"error": "unknown document type"}), 400
    fs = request.files.get("attachment")
    if not (fs and fs.filename):
        return jsonify({"error": "please attach a supporting PDF"}), 400
    try:
        stored = _save_upload(fs)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    cur = conn.execute("INSERT INTO documents (student_id, doc_type, request_file) VALUES (?,?,?)",
                       (me["id"], doc_type, stored))
    conn.execute("UPDATE documents SET reference = ? WHERE id = ?",
                 (f"DOC-{date.today().year}-{cur.lastrowid:04d}", cur.lastrowid))
    conn.commit()
    return jsonify({"ok": True, "id": cur.lastrowid}), 201


@app.get("/api/my/documents")
@require_auth
def h_my_documents():
    rows = db.run(get_db(),
        "SELECT id, doc_type, status, reference, created_at, decided_at, request_file, "
        "issued_file FROM documents WHERE student_id = ? ORDER BY id DESC", (g.ident.get("sub"),))
    return jsonify({"documents": rows})


@app.get("/api/documents/<int:doc_id>")
@require_auth
def h_get_document(doc_id):
    conn = get_db()
    rows = db.run(conn,
        "SELECT d.*, u.full_name AS student, u.email AS student_email "
        "FROM documents d JOIN users u ON u.id = d.student_id WHERE d.id = ?", (doc_id,))
    if not rows:
        return jsonify({"error": "document not found"}), 404
    doc = rows[0]
    if MODE == "secure":
        # SECURE: a student may read only their OWN document; staff/admin read any.
        me = load_user(conn, g.ident.get("sub"))
        if me["role"] == "student" and doc["student_id"] != me["id"]:
            return jsonify({"error": "forbidden"}), 403
    # VULN (IDOR #12): no ownership check — a student can walk /api/documents/<id>
    # (the ids appear in their own request list) and read any other student's
    # attestation / transcript, including name, email and reference number.
    return jsonify({"document": doc})


@app.get("/api/documents/<int:doc_id>/download")
@require_auth
def h_download_document(doc_id):
    """Download a document's attachment (the student's upload or the issued PDF)."""
    conn = get_db()
    rows = db.run(conn, "SELECT * FROM documents WHERE id = ?", (doc_id,))
    if not rows:
        return jsonify({"error": "document not found"}), 404
    doc = rows[0]
    which = request.args.get("which", "issued")
    stored = doc["issued_file"] if which == "issued" else doc["request_file"]

    if MODE == "vuln":
        # VULN (#15): no ownership check (any logged-in user pulls anyone's files —
        # IDOR), the served path can be overridden with ?name= (directory traversal:
        #   ?name=../../keys/eth_issuer.key   leaks the on-chain signing key,
        #   ?name=../../sms_vuln.db           downloads the whole database)
        # and the file is sent INLINE, so an uploaded .html/.svg runs as stored XSS.
        name = request.args.get("name") or stored
        if not name:
            return jsonify({"error": "no file for this document"}), 404
        return send_file(os.path.join(UPLOAD_DIR, name))
    # SECURE: only the owner (or staff/admin) may download; always serve the file
    # recorded for THIS document, as an attachment with a fixed PDF content type,
    # and never from a client-supplied path.
    me = load_user(conn, g.ident.get("sub"))
    if me["role"] == "student" and doc["student_id"] != me["id"]:
        return jsonify({"error": "forbidden"}), 403
    if not stored:
        return jsonify({"error": "no file for this document"}), 404
    return send_file(os.path.join(UPLOAD_DIR, stored), mimetype="application/pdf",
                     as_attachment=True, download_name=f"{doc['reference'] or doc_id}.pdf")


@app.get("/api/admin/documents")
@require_auth
def h_admin_documents():
    conn = get_db()
    me = load_user(conn, g.ident.get("sub"))
    if not me or me["role"] != "admin":
        return jsonify({"error": "admins only"}), 403
    rows = db.run(conn,
        "SELECT d.id, d.doc_type, d.status, d.reference, d.created_at, d.decided_at, "
        "d.request_file, d.issued_file, u.full_name AS student FROM documents d "
        "JOIN users u ON u.id = d.student_id ORDER BY (d.status = 'pending') DESC, d.id DESC")
    return jsonify({"documents": rows})


@app.post("/api/admin/documents/<int:doc_id>/decide")
@require_auth
def h_decide_document(doc_id):
    conn = get_db()
    me = load_user(conn, g.ident.get("sub"))
    if not me or me["role"] != "admin":
        return jsonify({"error": "admins only"}), 403
    decision = request.form.get("decision")
    if decision not in ("approved", "rejected"):
        return jsonify({"error": "decision must be 'approved' or 'rejected'"}), 400
    if not db.run(conn, "SELECT 1 FROM documents WHERE id = ?", (doc_id,)):
        return jsonify({"error": "document not found"}), 404
    stored = None
    if decision == "approved":
        # The registrar uploads the signed/issued PDF when approving. Same unsafe
        # vs. safe handling as the student upload (#15).
        fs = request.files.get("document")
        if not (fs and fs.filename):
            return jsonify({"error": "attach the issued PDF to approve"}), 400
        try:
            stored = _save_upload(fs)
        except ValueError as e:
            return jsonify({"error": str(e)}), 400
    conn.execute("UPDATE documents SET status = ?, decided_by = ?, decided_at = datetime('now'), "
                 "issued_file = COALESCE(?, issued_file) WHERE id = ?",
                 (decision, me["id"], stored, doc_id))
    conn.commit()
    return jsonify({"ok": True})


# ==========================================================================
# Profile  —  mass-assignment pair (#13) + change password
# ==========================================================================
@app.post("/api/profile")
@require_auth
def h_update_profile():
    conn = get_db()
    uid = g.ident.get("sub")
    b = request.get_json(silent=True) or {}

    if MODE == "vuln":
        # VULN (mass assignment #13): every key in the request body is written to
        # the caller's user row. The profile form only shows name/email/phone/
        # address, but adding e.g. "role":"admin" (or "password_hash":"<md5>") to
        # the JSON in Burp updates those columns too -> privilege escalation.
        cols = {r["name"] for r in conn.execute("PRAGMA table_info(users)")}
        fields = [k for k in b if k in cols and k != "id"]
        if not fields:
            return jsonify({"error": "nothing to update"}), 400
        conn.execute("UPDATE users SET " + ", ".join(f"{k} = ?" for k in fields) +
                     " WHERE id = ?", [b[k] for k in fields] + [uid])
    else:
        # SECURE: only an explicit whitelist of profile fields is writable; role,
        # id, password_hash, username, etc. are never taken from the request. Only
        # the fields actually present in the body are updated, so a partial update
        # never blanks the others.
        allowed = ("full_name", "email", "phone", "address")
        fields = [k for k in allowed if k in b]
        if not fields:
            return jsonify({"error": "nothing to update"}), 400
        conn.execute("UPDATE users SET " + ", ".join(f"{k} = ?" for k in fields) +
                     " WHERE id = ?", [b[k] for k in fields] + [uid])
    conn.commit()
    return jsonify({"user": public_user(load_user(conn, uid))})


@app.post("/api/change-password")
@require_auth
def h_change_password():
    conn = get_db()
    me = load_user(conn, g.ident.get("sub"))
    b = request.get_json(silent=True) or {}
    old, new = b.get("old_password") or "", b.get("new_password") or ""
    # The current password is required in both builds. The secure build additionally
    # enforces a minimum length.
    if not auth.verify_password(old, me):
        return jsonify({"error": "current password is incorrect"}), 403
    if MODE == "secure" and len(new) < 8:
        return jsonify({"error": "new password must be at least 8 characters"}), 400
    if not new:
        return jsonify({"error": "a new password is required"}), 400
    h, salt, scheme = auth.hash_password(new, MODE)
    conn.execute("UPDATE users SET password_hash = ?, salt = ?, hash_scheme = ? WHERE id = ?",
                 (h, salt, scheme, me["id"]))
    conn.commit()
    return jsonify({"ok": True})


# ==========================================================================
# Password reset  —  predictable-token pair (#14)
# ==========================================================================
def _reset_token(username):
    if MODE == "vuln":
        # VULN (#14): the token is a predictable function of the (public) username,
        # with no randomness. Anyone who knows a victim's username can compute the
        # same token and reset the victim's password.
        return hashlib.md5(("reset:" + username).encode()).hexdigest()[:12]
    # SECURE: a cryptographically random, single-use token.
    return secrets.token_urlsafe(24)


@app.post("/api/password-reset/request")
def h_reset_request():
    conn = get_db()
    b = request.get_json(silent=True) or {}
    ident = (b.get("username") or b.get("email") or "").strip()
    rows = db.run(conn, "SELECT * FROM users WHERE username = ? OR email = ?", (ident, ident))
    resp = {"ok": True,
            "message": "If that account exists, a password-reset token has been issued."}
    if rows:
        u = rows[0]
        token = _reset_token(u["username"])
        conn.execute("DELETE FROM password_resets WHERE user_id = ?", (u["id"],))
        if MODE == "secure":
            # SECURE: store only a HASH of the token, and expire it in 15 minutes.
            conn.execute("INSERT INTO password_resets (user_id, token, expires_at) "
                         "VALUES (?,?, datetime('now', '+15 minutes'))",
                         (u["id"], hashlib.sha256(token.encode()).hexdigest()))
        else:
            # VULN: store the token as-is, with no meaningful expiry.
            conn.execute("INSERT INTO password_resets (user_id, token, expires_at) "
                         "VALUES (?,?, datetime('now', '+100 years'))", (u["id"], token))
        conn.commit()
        print(f"[password-reset] token for {u['username']}: {token}")
        if MODE == "vuln":
            # VULN: the token is also returned straight to the caller.
            resp["reset_token"] = token
    # SECURE: the response is identical whether or not the account exists (no user
    # enumeration); the token is only written to the server log (would be emailed).
    return jsonify(resp)


@app.post("/api/password-reset/confirm")
def h_reset_confirm():
    conn = get_db()
    b = request.get_json(silent=True) or {}
    token, new = b.get("token") or "", b.get("new_password") or ""
    if MODE == "secure":
        if len(new) < 8:
            return jsonify({"error": "new password must be at least 8 characters"}), 400
        # SECURE: match the hashed token, and require it be unused and unexpired.
        rows = db.run(conn, "SELECT * FROM password_resets WHERE token = ? AND used = 0 "
                      "AND expires_at > datetime('now')",
                      (hashlib.sha256(token.encode()).hexdigest(),))
    else:
        if not new:
            return jsonify({"error": "a new password is required"}), 400
        # VULN: the token is matched as-is, with no expiry or single-use check.
        rows = db.run(conn, "SELECT * FROM password_resets WHERE token = ?", (token,))
    if not rows:
        return jsonify({"error": "invalid or expired reset token"}), 400
    r = rows[0]
    h, salt, scheme = auth.hash_password(new, MODE)
    conn.execute("UPDATE users SET password_hash = ?, salt = ?, hash_scheme = ? WHERE id = ?",
                 (h, salt, scheme, r["user_id"]))
    conn.execute("UPDATE password_resets SET used = 1 WHERE id = ?", (r["id"],))
    conn.commit()
    return jsonify({"ok": True})


def main():
    db.init_db(MODE, reset=bool(os.environ.get("RESET_DB")))
    print("=" * 60)
    print(f"  Campus Portal — Student Management System [{MODE.upper()}]")
    print(f"  http://{HOST}:{PORT}")
    print(f"  database: {db.db_path(MODE)}")
    if MODE == "secure":
        problem = eth_ledger.check_deployment()
        if problem:
            print(f"  !! integrity ledger: {problem}")
            print("  !! start anvil, then restart with RESET_DB=1 to redeploy + re-anchor.")
            print("  !! until then, grade/cert writes return 503.")
        else:
            print(f"  ledger:   GradeLedger at {eth_ledger.deployment()['address']}")
    print("=" * 60)
    # threaded so concurrent requests behave like the previous server; the Flask
    # dev server is fine for this local lab (not for production).
    app.run(host=HOST, port=PORT, threaded=True)


if __name__ == "__main__":
    main()
