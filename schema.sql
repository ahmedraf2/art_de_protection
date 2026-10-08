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
    phone         TEXT,
    address       TEXT,
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

-- Campus announcements / news feed. The body is stored exactly as submitted;
-- how it is rendered differs by build (vuln injects raw HTML -> stored XSS #11).
CREATE TABLE IF NOT EXISTS announcements (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    author_id  INTEGER,
    title      TEXT NOT NULL,
    body       TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (author_id) REFERENCES users(id)
);

-- Administrative document requests (attestation d'inscription, relevé de notes…).
-- The registrar (admin) approves or rejects; an approved document can be viewed
-- by reference. Reading a document by id is an IDOR in the vuln build (#12).
CREATE TABLE IF NOT EXISTS documents (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    student_id   INTEGER NOT NULL,
    doc_type     TEXT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'pending',   -- 'pending' | 'approved' | 'rejected'
    reference    TEXT,
    request_file TEXT,                               -- student-uploaded supporting PDF
    issued_file  TEXT,                               -- registrar-uploaded issued PDF
    created_at   TEXT DEFAULT (datetime('now')),
    decided_by   INTEGER,
    decided_at   TEXT,
    FOREIGN KEY (student_id) REFERENCES users(id),
    FOREIGN KEY (decided_by) REFERENCES users(id)
);

-- Password-reset tokens. The token value is predictable in the vuln build and a
-- random, hashed, single-use, expiring token in the secure build (#14).
CREATE TABLE IF NOT EXISTS password_resets (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL,
    token      TEXT NOT NULL,
    expires_at TEXT,
    used       INTEGER NOT NULL DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id)
);
