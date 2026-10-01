# Architecture

A single-process Python web application. One HTTP server serves the front-end and a
JSON API; a thin data layer talks to a SQLite database. The `APP_MODE` environment
variable selects the vulnerable or the secure code path at runtime.

## Components

```
        Browser (static/) ── or ── curl / Burp Suite
                    │  HTTP + JSON,  Authorization: Bearer <JWT>
        ════════════╪════════════ trust boundary ════════════
                    ▼        (everything above is attacker-controlled)
   ┌────────────────────────────────────────────────────────────┐
   │  app.py — HTTP server + router                              │
   │     whoami()  ── decodes the JWT (verify depends on mode)   │
   │     endpoints ── each has a  # VULN  and a  # SECURE  branch │
   │        │              │                 │                   │
   │        ▼              ▼                 ▼                   │
   │   auth.py         crypto_utils.py     db.py                 │
   │   · JWT (HMAC)    · AES-256-GCM       · run()  (bound params)│
   │   · pwd hashing   · Ed25519 sign      · run_raw() (concat)   │
   │                   · verify            · seed / schema        │
   └────────────────────────────────┬───────────────────────────┘
                                     ▼
                         ┌───────────────────────────┐
                         │  SQLite (per build)        │
                         │  sms_vuln.db / sms_secure  │
                         │  users, courses,           │
                         │  enrollments, grades,      │
                         │  certifications, messages  │
                         └───────────────────────────┘
                         keys/  (AES key + Ed25519 keypair, generated on first run)
```

## Request lifecycle

1. A request arrives with credentials in the `Authorization: Bearer <JWT>` header.
2. `route()` matches `METHOD + path` against the `ROUTES` table and opens a
   per-request DB connection.
3. `whoami()` decodes the JWT — `jwt_decode_vuln` (no verification) or
   `jwt_decode_secure` (verify alg + signature + expiry), depending on the build.
4. The handler enforces authorization (secure build only), runs its query through
   `db.run` (parameterized) or `db.run_raw` (concatenated), and returns JSON.

## Roles and data model

Three roles — `student`, `professor`, `admin` — stored on `users.role`.

```
users(id, username⋆, email, full_name, password_hash, salt, hash_scheme, role)
courses(id, code⋆, name, professor_id→users)
enrollments(id, course_id→courses, student_id→users)
grades(id, course_id→courses, student_id→users, grade, updated_by)
certifications(id, student_id→users, title, grade, issued_date, signature)
messages(id, sender_id→users, recipient_id→users, subject, body, is_encrypted)
```
`⋆` = unique. Authoritative DDL: [schema.sql](schema.sql).

## Cryptography design

- **Password hashing** (`auth.py`): PBKDF2-HMAC-SHA256, per-user 16-byte salt,
  200k iterations, constant-time verification. (Vuln build: unsalted MD5.)
- **JWT integrity** (`auth.py`): HMAC-SHA256 over `base64url(header).base64url(payload)`.
  The secure verifier pins `alg=HS256`, compares the MAC in constant time, and
  checks `exp`.
- **Encryption at rest** (`crypto_utils.py`): message bodies are sealed with
  AES-256-GCM (random 96-bit nonce per message, authenticated). The key lives in
  `keys/aes.key`.
- **Digital signatures** (`crypto_utils.py`): each certification is signed with an
  Ed25519 issuer key over a canonical JSON of `{student_id, title, grade,
  issued_date}`. The public key is exposed at `GET /api/pubkey` for independent
  verification. Any field change invalidates the signature.

## The security model in one line

Everything above the trust boundary is attacker-controlled, so the server must:
treat input as **data, not code** (bound parameters); trust a token only **after**
verifying it; make every **authorization** decision from server-side state, not from
client claims; and protect data both **in transit/at rest** (encryption, signatures)
and **at the API** (access control) — the two are complementary, not interchangeable.
