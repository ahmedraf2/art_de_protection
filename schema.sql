-- Student Management System — database schema (SQLite)
-- Roles: 'student', 'professor', 'admin'

CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT UNIQUE NOT NULL,
    email         TEXT,
    full_name     TEXT,
    password_hash TEXT NOT NULL,
    salt          TEXT,
    hash_scheme   TEXT NOT NULL DEFAULT 'md5',   -- 'md5' | 'pbkdf2'
    role          TEXT NOT NULL DEFAULT 'student',
    created_at    TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS courses (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    code         TEXT UNIQUE NOT NULL,
    name         TEXT NOT NULL,
    professor_id INTEGER,
    FOREIGN KEY (professor_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS enrollments (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    course_id  INTEGER NOT NULL,
    student_id INTEGER NOT NULL,
    FOREIGN KEY (course_id) REFERENCES courses(id),
    FOREIGN KEY (student_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS grades (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    course_id  INTEGER NOT NULL,
    student_id INTEGER NOT NULL,
    grade      TEXT,
    updated_by INTEGER,
    updated_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (course_id) REFERENCES courses(id),
    FOREIGN KEY (student_id) REFERENCES users(id)
);

-- Certifications are digitally signed by the issuer (see crypto_utils.py).
CREATE TABLE IF NOT EXISTS certifications (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    student_id  INTEGER NOT NULL,
    title       TEXT NOT NULL,
    grade       TEXT,
    issued_date TEXT,
    signature   TEXT,                 -- Ed25519 signature (base64); NULL = unsigned
    issued_by   INTEGER,              -- the professor/admin who issued it
    FOREIGN KEY (student_id) REFERENCES users(id),
    FOREIGN KEY (issued_by) REFERENCES users(id)
);

-- Private messages between users.
CREATE TABLE IF NOT EXISTS messages (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_id    INTEGER NOT NULL,
    recipient_id INTEGER NOT NULL,
    subject      TEXT,
    body         TEXT,                -- plaintext OR AES-GCM ciphertext (base64)
    is_encrypted INTEGER NOT NULL DEFAULT 0,
    created_at   TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (sender_id) REFERENCES users(id),
    FOREIGN KEY (recipient_id) REFERENCES users(id)
);
