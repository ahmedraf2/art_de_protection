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
    # username,     password,   role,        full_name,          email
    ("admin",       "admin123", "admin",     "System Admin",     "admin@campus.edu"),
    ("prof_smith",  "teach123", "professor", "Dr. John Smith",   "smith@campus.edu"),
    ("prof_jones",  "teach456", "professor", "Dr. Emily Jones",  "jones@campus.edu"),
    ("alice",       "password1","student",   "Alice Anderson",   "alice@campus.edu"),
    ("bob",         "hunter2",  "student",   "Bob Brown",        "bob@campus.edu"),
    ("carol",       "qwerty",   "student",   "Carol Clark",      "carol@campus.edu"),
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
    # db_file not found means fresh start
    if fresh:
        try:
            _seed(conn, mode)
        except eth_ledger.LedgerUnavailable as e:
            conn.close()
            os.remove(path)               # don't keep a DB whose records aren't anchored
            raise SystemExit(f"seeding failed, ledger unavailable: {e}")
    conn.commit()
    conn.close()


def _seed(conn, mode):
    uid = {}
    for username, pwd, role, full_name, email in USERS:
        h, salt, scheme = auth.hash_password(pwd, mode)
        cur = conn.execute(
            "INSERT INTO users (username, password_hash, salt, hash_scheme, role, "
            "full_name, email) VALUES (?,?,?,?,?,?,?)",
            (username, h, salt, scheme, role, full_name, email))
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


if __name__ == "__main__":
    import sys
    m = sys.argv[1] if len(sys.argv) > 1 else "vuln"
    init_db(m, reset=True)
    print(f"initialized {m} database at {db_path(m)}")
