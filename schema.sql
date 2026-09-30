-- ==========================================================================
-- Secure Authentication & Cryptography Lab — Database Schema (SQLite)
-- ==========================================================================
-- This file is the canonical schema. It is executed automatically by db.py
-- when the app first creates a database file. Seed data is inserted by db.py
-- (it differs per mode: MD5 hashes in `vuln` mode, PBKDF2 in `secure` mode).
-- ==========================================================================

CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    UNIQUE NOT NULL,
    email         TEXT,
    full_name     TEXT,
    password_hash TEXT    NOT NULL,          -- MD5 hex (vuln) OR PBKDF2 hex (secure)
    salt          TEXT,                      -- per-user salt, used by PBKDF2 only
    hash_scheme   TEXT    NOT NULL DEFAULT 'md5',  -- 'md5' | 'pbkdf2'
    role          TEXT    NOT NULL DEFAULT 'user', -- 'user' | 'admin'
    api_key       TEXT,                      -- SENSITIVE: leaks via IDOR / SQLi
    created_at    TEXT    DEFAULT (datetime('now'))
);

-- Per-user private notes. Used to demonstrate IDOR and stored XSS.
CREATE TABLE IF NOT EXISTS notes (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL,
    title      TEXT,
    body       TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Server-side "remember me" tokens. Only used by the SECURE remember-me
-- implementation (a random token whose SHA-256 hash is stored here). The
-- vulnerable implementation stores nothing server-side — it trusts a
-- client-forgeable cookie instead.
CREATE TABLE IF NOT EXISTS remember_tokens (
    token_hash TEXT PRIMARY KEY,   -- sha256(random token)
    user_id    INTEGER NOT NULL,
    expires_at TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
