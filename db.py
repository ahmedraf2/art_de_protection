"""
db.py — database access layer for the vulnerable auth lab.

Exposes two DELIBERATELY DIFFERENT query helpers so the SQL-injection lesson is
honest:

    vuln_query(conn, sql)            -> runs raw SQL you built by concatenation
    safe_query(conn, sql, params)    -> runs a parameterized query (bound values)

The security difference between them is real: `safe_query` sends the SQL text and
the user data over separate channels, so user input can never change the meaning
of the statement. `vuln_query` has no such separation.

Each mode gets its own database file so the seeded password-hash scheme is
consistent (MD5 in vuln mode, PBKDF2 in secure mode).
"""

import os
import sqlite3
import secrets

import auth

HERE = os.path.dirname(os.path.abspath(__file__))
SCHEMA_PATH = os.path.join(HERE, "schema.sql")


def db_path(mode: str) -> str:
    return os.path.join(HERE, f"lab_{mode}.db")


def get_conn(mode: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path(mode))
    conn.row_factory = sqlite3.Row  # rows behave like dicts
    return conn


# --------------------------------------------------------------------------
# Query helpers
# --------------------------------------------------------------------------
def vuln_query(conn: sqlite3.Connection, sql: str):
    """Execute raw SQL. Callers build `sql` by string concatenation -> injectable.

    Uses executescript-free execute; note that sqlite3's execute() only runs the
    FIRST statement, which is realistic for many drivers. Stacked-query payloads
    that rely on a second `;` statement will not fire here, but UNION-based and
    boolean/comment-based injection work fully — which is the common real case.
    """
    cur = conn.execute(sql)
    try:
        rows = cur.fetchall()
    except sqlite3.ProgrammingError:
        rows = []
    return [dict(r) for r in rows]


def safe_query(conn: sqlite3.Connection, sql: str, params=()):
    """Execute a parameterized query. User data is bound, never concatenated."""
    cur = conn.execute(sql, params)
    try:
        rows = cur.fetchall()
    except sqlite3.ProgrammingError:
        rows = []
    return [dict(r) for r in rows]


# --------------------------------------------------------------------------
# Initialization + seeding
# --------------------------------------------------------------------------
SEED_USERS = [
    # username, email,               full_name,      role,    password
    ("admin", "admin@lab.local", "Site Administrator", "admin", "admin123"),
    ("alice", "alice@lab.local", "Alice Anderson",     "user",  "password1"),
    ("bob",   "bob@lab.local",   "Bob Brown",          "user",  "hunter2"),
]

SEED_NOTES = [
    ("admin", "Root recovery",   "Master recovery phrase: correct-horse-battery-staple"),
    ("alice", "Diary",           "Note to self: reuse this password everywhere."),
    ("bob",   "TODO",            "Ask admin for a raise."),
]


def init_db(mode: str, reset: bool = False) -> None:
    path = db_path(mode)
    if reset and os.path.exists(path):
        os.remove(path)
    fresh = not os.path.exists(path)

    conn = get_conn(mode)
    with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
        conn.executescript(f.read())

    if fresh:
        _seed(conn, mode)
    conn.commit()
    conn.close()


def _seed(conn: sqlite3.Connection, mode: str) -> None:
    name_to_id = {}
    for username, email, full_name, role, password in SEED_USERS:
        pwd_hash, salt, scheme = auth.hash_password(password, mode)
        api_key = "sk_live_" + secrets.token_hex(16)
        cur = conn.execute(
            "INSERT INTO users (username, email, full_name, password_hash, salt, "
            "hash_scheme, role, api_key) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (username, email, full_name, pwd_hash, salt, scheme, role, api_key),
        )
        name_to_id[username] = cur.lastrowid

    for username, title, body in SEED_NOTES:
        conn.execute(
            "INSERT INTO notes (user_id, title, body) VALUES (?, ?, ?)",
            (name_to_id[username], title, body),
        )
    conn.commit()


if __name__ == "__main__":
    import sys

    mode = sys.argv[1] if len(sys.argv) > 1 else "vuln"
    init_db(mode, reset=True)
    print(f"[db] initialized fresh '{mode}' database at {db_path(mode)}")
