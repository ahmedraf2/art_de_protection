"""
Database access for the Student Management System.

Two query helpers make the SQL-injection lesson concrete:
    run_raw(conn, sql)          -> raw SQL built by concatenation (injectable)
    run(conn, sql, params=())   -> parameterized query (values are bound)

Each build uses its own database file so the seeded password scheme, message
encryption and certificate signatures stay consistent.
"""

import os
import sqlite3

import auth
import crypto_utils as cu
import eth_ledger

HERE = os.path.dirname(os.path.abspath(__file__))
SCHEMA_PATH = os.path.join(HERE, "schema.sql")


def db_path(mode: str) -> str:
    return os.path.join(HERE, f"sms_{mode}.db")


def get_conn(mode: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path(mode))
    conn.row_factory = sqlite3.Row
    return conn


def run_raw(conn, sql):
    cur = conn.execute(sql)
    try:
        return [dict(r) for r in cur.fetchall()]
    except sqlite3.ProgrammingError:
        return []


def run_raw_multi(conn, sql):
    """Like run_raw, but also runs STACKED statements (';'-separated).

    execute() refuses more than one statement ("You can only execute one
    statement at a time"), which stops a classic  '; UPDATE ...; --  payload.
    executescript() runs every statement but returns no rows. So we try the
    normal path first (a benign search returns its matches) and fall back to
    executescript when the input stacked extra statements — which is exactly
    what makes a search box injectable for *writes*, not just reads.
    """
    try:
        cur = conn.execute(sql)
    except sqlite3.ProgrammingError:
        conn.executescript(sql)      # stacked statements: run them all (data changes persist)
        return []
    try:
        return [dict(r) for r in cur.fetchall()]
    except sqlite3.ProgrammingError:
        return []


def run(conn, sql, params=()):
    cur = conn.execute(sql, params)
    try:
        return [dict(r) for r in cur.fetchall()]
    except sqlite3.ProgrammingError:
        return []


# --- seed data -----------------------------------------------------------
USERS = [
    # username,     password,   role,        full_name,          email,              phone,            address
    ("admin",       "admin123", "admin",     "System Admin",     "admin@campus.edu", "+216 71 100 100", "Registrar's Office, Main Building"),
    ("prof_smith",  "teach123", "professor", "Dr. John Smith",   "smith@campus.edu", "+216 71 100 201", "Dept. of Computer Science, Room B204"),
    ("prof_jones",  "teach456", "professor", "Dr. Emily Jones",  "jones@campus.edu", "+216 71 100 202", "Dept. of Science, Room A110"),
    ("alice",       "password1","student",   "Alice Anderson",   "alice@campus.edu", "+216 22 345 678", "12 Rue des Jasmins, Tunis"),
    ("bob",         "hunter2",  "student",   "Bob Brown",        "bob@campus.edu",   "+216 23 456 789", "5 Avenue Habib Bourguiba, Ariana"),
    ("carol",       "qwerty",   "student",   "Carol Clark",      "carol@campus.edu", "+216 24 567 890", "88 Rue de Carthage, La Marsa"),
]

COURSES = [
    # code,   name,          professor
    ("MATH",  "Mathematics",       "prof_jones"),
    ("PHYS",  "Physics",           "prof_jones"),
    ("PROG",  "Programming",       "prof_smith"),
    ("DB",    "Databases",         "prof_smith"),
    ("ALGO",  "Algorithms",        "prof_smith"),
    ("NET",   "Computer Networks", "prof_jones"),
]

ENROLLMENTS = [
    ("alice", "MATH"), ("alice", "PHYS"), ("alice", "PROG"),
    ("alice", "DB"),   ("alice", "ALGO"), ("alice", "NET"),
    ("bob",   "MATH"), ("bob",   "PHYS"), ("bob",   "PROG"), ("bob", "DB"),
    ("carol", "PROG"), ("carol", "DB"),   ("carol", "ALGO"), ("carol", "NET"),
]

# Grades on the /20 scale (Tunisian system).
GRADES = [
    ("alice", "MATH", "14.00"), ("alice", "PHYS", "12.50"), ("alice", "PROG", "16.00"),
    ("alice", "DB",   "15.00"), ("alice", "ALGO", "11.00"), ("alice", "NET",  "13.50"),
    ("bob",   "MATH", "9.00"),  ("bob",   "PHYS", "11.00"), ("bob",   "PROG", "13.00"),
    ("bob",   "DB",   "10.50"),
    ("carol", "PROG", "17.00"), ("carol", "DB",   "14.50"), ("carol", "ALGO", "12.00"),
    ("carol", "NET",  "15.00"),
]

# The fixed menu of certificates a professor may issue (the title is built as
# "<type>: <course name>"). Kept short so it is easy to pick from in class.
CERT_TYPES = [
    "Course Completion",
    "Certificate of Achievement",
    "Online Course Certificate",
    "Honors Distinction",
]

# Minimum grade (/20) a student must have to receive each certificate. None means
# no grade requirement. The SECURE build enforces this; the VULN build ignores it,
# so an Honors certificate can be minted for a failing grade (business-logic flaw).
CERT_MIN_GRADE = {
    "Course Completion": 10.0,
    "Certificate of Achievement": 10.0,
    "Online Course Certificate": None,
    "Honors Distinction": 16.0,
}

# The documents a student can request from the registrar.
DOC_TYPES = [
    "Attestation d'inscription",
    "Relevé de notes",
    "Attestation de réussite",
]

CERTS = [
    # student, cert_type,                  course, issued_date  (issued by that course's professor)
    ("alice", "Course Completion",         "PROG", "2026-06-15"),
    ("alice", "Certificate of Achievement","DB",   "2026-07-01"),
    ("bob",   "Course Completion",         "PHYS", "2026-06-20"),
]

# Chat messages: (sender, recipient, body). Inserted in order.
CHATS = [
    ("alice", "bob", "Hey Bob, are you coming to the study group?"),
    ("bob", "alice", "Yes! Library at 6pm?"),
    ("alice", "bob", "Perfect, see you then."),

    ("prof_smith", "alice", "Alice, please review chapter 5 before the next lab."),
    ("alice", "prof_smith", "Thank you professor, I will."),

    ("carol", "prof_jones", "Professor, will the physics exam cover chapter 8?"),
    ("prof_jones", "carol", "Yes, chapters 6 through 8."),

    # Private professor <-> admin conversation containing a secret.
    ("prof_smith", "admin", "The students keep asking me about the final exam portal."),
    ("admin", "prof_smith", "Do not share it with anyone. The grading portal master "
                            "password is Adm1n_Gu@rd14n_2026 — keep this strictly between us."),
    ("prof_smith", "admin", "Understood, sir. I'll keep it confidential."),

    ("admin", "prof_jones", "Next term budget approved: 250,000 DT. Strictly confidential."),
]


def init_db(mode, reset=False):
    cu.ensure_keys()
    path = db_path(mode)
    if reset and os.path.exists(path):
        os.remove(path)
    fresh = not os.path.exists(path)

    if fresh and mode == "secure":
        # SECURE: a fresh database gets a fresh GradeLedger contract, so the DB
        # and the ledger always start out consistent.
        try:
            dep = eth_ledger.deploy()
        except eth_ledger.LedgerUnavailable as e:
            raise SystemExit(f"cannot deploy the integrity ledger: {e}")
        print(f"  GradeLedger deployed at {dep['address']} (issuer {dep['issuer']})")

    conn = get_conn(mode)
    with open(SCHEMA_PATH) as f:
        # read the entire schema.sql , then execute it as a series of SQL statements using SQLite connection
        conn.executescript(f.read())
    # migrate older databases that predate the certifications.issued_by column
    cols = [r["name"] for r in conn.execute("PRAGMA table_info(certifications)").fetchall()]
    if "issued_by" not in cols:
        conn.execute("ALTER TABLE certifications ADD COLUMN issued_by INTEGER")
    # migrate older databases that predate the users.phone / users.address columns
    ucols = [r["name"] for r in conn.execute("PRAGMA table_info(users)").fetchall()]
    for col in ("phone", "address"):
        if col not in ucols:
            conn.execute(f"ALTER TABLE users ADD COLUMN {col} TEXT")
    # migrate older databases that predate the documents file-upload columns
    dcols = [r["name"] for r in conn.execute("PRAGMA table_info(documents)").fetchall()]
    for col in ("request_file", "issued_file"):
        if col not in dcols:
            conn.execute(f"ALTER TABLE documents ADD COLUMN {col} TEXT")
    # db_file not found means fresh start
    if fresh:
        try:
            _seed(conn, mode)
        except eth_ledger.LedgerUnavailable as e:
            conn.close()
            os.remove(path)               # don't keep a DB whose records aren't anchored
            raise SystemExit(f"seeding failed, ledger unavailable: {e}")
    # announcements / document requests are seeded only if empty, so an existing
    # (persisted) database gets a populated feed without wiping its grades/certs.
    _seed_extras(conn)
    conn.commit()
    conn.close()


def _seed(conn, mode):
    uid = {}
    for username, pwd, role, full_name, email, phone, address in USERS:
        h, salt, scheme = auth.hash_password(pwd, mode)
        cur = conn.execute(
            "INSERT INTO users (username, password_hash, salt, hash_scheme, role, "
            "full_name, email, phone, address) VALUES (?,?,?,?,?,?,?,?,?)",
            (username, h, salt, scheme, role, full_name, email, phone, address))
        uid[username] = cur.lastrowid

    cid = {}
    for code, name, prof in COURSES:
        cur = conn.execute(
            "INSERT INTO courses (code, name, professor_id) VALUES (?,?,?)",
            (code, name, uid[prof]))
        cid[code] = cur.lastrowid

    for student, code in ENROLLMENTS:
        conn.execute("INSERT INTO enrollments (course_id, student_id) VALUES (?,?)",
                     (cid[code], uid[student]))

    for student, code, grade in GRADES:
        prof = uid["prof_smith"]
        conn.execute(
            "INSERT INTO grades (course_id, student_id, grade, updated_by) VALUES (?,?,?,?)",
            (cid[code], uid[student], grade, prof))
        if mode == "secure":
            # SECURE: anchor each grade's hash in the contract so later tampering
            # with the grades table shows up as DB != ledger.
            eth_ledger.anchor_grade(cid[code], uid[student],
                                    eth_ledger.grade_hash(cid[code], uid[student], grade))

    course_name = {code: name for code, name, _ in COURSES}
    course_prof = {code: prof for code, _, prof in COURSES}
    grade_of = {(s, c): g for s, c, g in GRADES}
    for student, ctype, code, date in CERTS:
        title = f"{ctype}: {course_name[code]}"
        grade = grade_of.get((student, code), "Completed")
        issued_by = uid[course_prof[code]]            # the professor who teaches the course
        # SECURE: issuer signs the certificate. VULN mode leaves it unsigned,
        # so a forged certificate cannot be told apart from a real one.
        sig = cu.sign_cert(uid[student], title, grade, date) if mode == "secure" else None
        conn.execute(
            "INSERT INTO certifications (student_id, title, grade, issued_date, signature, issued_by) "
            "VALUES (?,?,?,?,?,?)", (uid[student], title, grade, date, sig, issued_by))
        if mode == "secure":
            # SECURE: anchor the certificate's fingerprint so a forged or
            # injected certificate can be spotted ("not on chain").
            eth_ledger.anchor_cert(cu.cert_fingerprint(uid[student], title, grade, date))

    for i, (sender, recipient, body) in enumerate(CHATS):
        # SECURE: encrypt the body at rest. VULN mode stores plaintext, so anyone
        # who can read the DB file reads every private message.
        if mode == "secure":
            stored, enc = cu.encrypt(body), 1
        else:
            stored, enc = body, 0
        # spread timestamps a little so ordering is stable
        conn.execute(
            "INSERT INTO messages (sender_id, recipient_id, body, is_encrypted, created_at) "
            "VALUES (?,?,?,?, datetime('now', ?))",
            (uid[sender], uid[recipient], stored, enc, f"-{len(CHATS) - i} minutes"))

    conn.commit()


def _seed_extras(conn):
    """Seed the announcements feed and a couple of document requests, but only if
    those tables are empty — so it is safe to run on every startup (including on a
    persisted database) without disturbing existing data."""
    uid = {r["username"]: r["id"] for r in conn.execute("SELECT id, username FROM users")}
    if not uid:
        return

    if not conn.execute("SELECT 1 FROM announcements LIMIT 1").fetchone():
        seed_ann = [
            (uid.get("admin"), "Welcome to the 2025/2026 academic year",
             "The portal is now open for the new academic year. Please keep your "
             "profile details up to date and check this feed regularly for news."),
            (uid.get("admin"), "Exam registration deadline",
             "Registration for the January exam session closes on 20 December. "
             "Late requests must be submitted to the registrar's office in person."),
            (uid.get("prof_smith"), "Programming lab — room change",
             "This week's Programming lab moves to room B204. Please bring your "
             "lab notebooks and last week's exercises."),
        ]
        for author_id, title, body in seed_ann:
            conn.execute("INSERT INTO announcements (author_id, title, body, created_at) "
                         "VALUES (?,?,?, datetime('now', ?))",
                         (author_id, title, body, f"-{len(seed_ann)} hours"))

    if not conn.execute("SELECT 1 FROM documents LIMIT 1").fetchone():
        seed_docs = [
            # student,  type,                        status,     decided_by
            ("alice", "Attestation d'inscription", "approved", uid.get("admin")),
            ("bob",   "Relevé de notes",           "pending",  None),
        ]
        for student, dtype, status, decided_by in seed_docs:
            if student not in uid:
                continue
            cur = conn.execute(
                "INSERT INTO documents (student_id, doc_type, status, decided_by) "
                "VALUES (?,?,?,?)", (uid[student], dtype, status, decided_by))
            conn.execute("UPDATE documents SET reference = ? WHERE id = ?",
                         (f"DOC-2026-{cur.lastrowid:04d}", cur.lastrowid))
            if status != "pending":
                conn.execute("UPDATE documents SET decided_at = datetime('now') WHERE id = ?",
                             (cur.lastrowid,))


if __name__ == "__main__":
    import sys
    m = sys.argv[1] if len(sys.argv) > 1 else "vuln"
    init_db(m, reset=True)
    print(f"initialized {m} database at {db_path(m)}")
