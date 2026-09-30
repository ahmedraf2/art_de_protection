# Architecture

A single-process Python web app (standard library only). One HTTP server exposes a
static frontend plus a JSON API; a thin data layer talks to a per-mode SQLite file.
The `APP_MODE` switch selects the vulnerable or the patched code path at runtime.

## Component diagram

```
                         ┌──────────────────────────────────────────────┐
                         │                Browser / Burp                 │
                         │   static UI (static/*)  ·  curl / Repeater    │
                         └───────────────┬──────────────────────────────┘
                                         │  HTTP (JSON)   Authorization: Bearer <JWT>
                                         │                Cookie: remember=<token>
        ══════════ trust boundary ═══════╪══════════ everything above is attacker-controlled
                                         ▼
   ┌──────────────────────────────────────────────────────────────────────────┐
   │  app.py  —  ThreadingHTTPServer + router                                   │
   │                                                                            │
   │   route() ─▶ endpoint handlers (h_login, h_register, h_get_user, …)        │
   │                 │                 │                                        │
   │                 │ APP_MODE picks  │  vuln branch  # VULN:                  │
   │                 │ one branch ────▶│  secure branch # SECURE:               │
   │                 ▼                 ▼                                        │
   │        ┌─────────────────┐  ┌──────────────────────────────────────────┐  │
   │        │  auth.py         │  │  db.py                                    │  │
   │        │  · JWT HMAC      │  │  · get_conn(mode)                         │  │
   │        │    sign/verify   │  │  · vuln_query(sql)      ← concatenation   │  │
   │        │  · password hash │  │  · safe_query(sql,params) ← bound params  │  │
   │        │  · remember-me   │  │  · init_db / seed                         │  │
   │        └─────────────────┘  └───────────────────┬──────────────────────┘  │
   └──────────────────────────────────────────────────┼─────────────────────────┘
                                                        ▼
                                   ┌──────────────────────────────────┐
                                   │  SQLite file (per mode)          │
                                   │   lab_vuln.db  /  lab_secure.db  │
                                   │   tables: users, notes,          │
                                   │           remember_tokens        │
                                   └──────────────────────────────────┘
```

## Request lifecycle

1. **Browser/Burp** sends an HTTP request. Credentials ride in either the
   `Authorization: Bearer <JWT>` header or the `remember` cookie.
2. **`app.py` router** matches `METHOD + path` (regex table `ROUTES`) to a handler
   and opens a per-request SQLite connection.
3. **`identity()`** resolves the caller: decode the JWT (`auth.jwt_decode_*`), else
   fall back to the remember-me cookie. *Which decoder runs depends on `APP_MODE`.*
4. The **handler** performs its work through **`db.py`** — `vuln_query` (raw SQL) in
   vuln mode, `safe_query` (parameterized) in secure mode — and returns JSON.

## Trust boundary (the key security idea)

Everything above the dashed line is **attacker-controlled**: URL, body, headers,
JWT claims, and cookies can all be forged. The server's job is to treat all of it
as untrusted:

- **Input → data, never code.** `safe_query` binds user input as parameters so it
  cannot alter SQL structure (fixes #1).
- **Tokens are only trustworthy after verification.** `jwt_decode_secure` checks
  algorithm + signature + expiry before any claim is believed (fixes #2).
- **Authentication ≠ authorization.** A verified identity still gets its *role* and
  *object access* re-checked against the database, never from client claims
  (fixes #3, #4).
- **Secrets stored defensively.** Passwords use a salted slow KDF; remember-me
  tokens are stored only as hashes (fixes #5).

## Data model

```
users(id, username⋆, email, full_name,
      password_hash, salt, hash_scheme, role, api_key, created_at)
notes(id, user_id→users.id, title, body, created_at)
remember_tokens(token_hash⋆, user_id→users.id, expires_at)     # secure mode only
```
`⋆` = unique/primary key. See [schema.sql](schema.sql) for the authoritative DDL.

## Why this stack

- **Python stdlib only** → runs with `python3 app.py`, no dependency install.
- **Real SQLite driver** → an honest parameterized-vs-concatenated contrast, which
  is the whole point of the SQL-injection exercise.
- **Hand-rolled JWT/HMAC** → the signing and verification logic is visible and
  editable, so the auth-bypass and its fix are concrete rather than hidden inside
  a library.
