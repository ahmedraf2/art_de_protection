# Campus — Student Management System

A small student management system (students, professors, admins) built to study
common web-application security flaws and their fixes: SQL injection, broken JWT
authentication, IDOR, broken access control, insecure password storage, plus a
practical look at encryption and digital signatures.

The application ships in two builds, selected with an environment variable:

```bash
python3 app.py                    # vuln build  (default)  — contains the flaws
APP_MODE=secure python3 app.py    # secure build           — the patched version
```

Both builds share the same code. Vulnerable branches are tagged `# VULN:` and the
corresponding fix `# SECURE:`, so you can read them side by side, exploit the vuln
build, then switch to the secure build and confirm the same request now fails.

## Features

| Role | Can do |
|------|--------|
| **Student** | see own courses, grades and certifications; send/read messages |
| **Professor** | see own courses and students; enter grades; messages |
| **Admin** | manage all users; issue (sign) certifications; full messaging |

Cross-cutting: JWT login, private messaging, digitally-signed certifications,
encrypted message storage, and a blockchain integrity ledger that anchors grades
and certifications (secure build).

## Requirements

- Python 3.8+
- The `cryptography` package (AES-GCM encryption and Ed25519 signatures):

```bash
pip install -r requirements.txt
```

## Run

```bash
# vulnerable build
python3 app.py                      # http://127.0.0.1:3000

# secure build (on a different port so you can compare side by side)
APP_MODE=secure PORT=3001 python3 app.py

# rebuild the database from scratch
RESET_DB=1 python3 app.py
```

The database (`sms_vuln.db` / `sms_secure.db`) and the crypto keys (`keys/`) are
created automatically on first run.

## Demo accounts

| Username | Password | Role |
|----------|----------|------|
| `admin` | `admin123` | admin |
| `prof_smith` | `teach123` | professor |
| `prof_jones` | `teach456` | professor |
| `alice` | `password1` | student |
| `bob` | `hunter2` | student |
| `carol` | `qwerty` | student |

## Vulnerabilities covered

| # | Issue | Location |
|---|-------|----------|
| 1 | SQL injection (login bypass) | `POST /api/login` |
| 2 | SQL injection (certifications) | `GET /api/certifications` |
| 3 | Broken JWT (no signature check / `alg:none`) | `auth.jwt_decode_vuln` |
| 4 | IDOR — read anyone's private chat | `GET /api/chat?chat_users[0]=..&chat_users[1]=..` |
| 5 | Privilege escalation (client-chosen role) | `POST /api/register` |
| 6 | Broken access control (grading, cert issuance, admin) | `POST /api/grades`, `POST /api/certifications`, `GET /api/admin/users` |
| 7 | Insecure password hashing (unsalted MD5) | `auth.hash_password` |
| 8 | Missing signature / encryption at rest | certifications & messages |
| 9 | No integrity anchoring (grade/cert tampering undetected) | `GET /api/grades/integrity`, `GET /api/blockchain` |

Full exploit steps and fixes: **[VULNERABILITIES.md](VULNERABILITIES.md)**.
Step-by-step live-demo script: **[DEMO.md](DEMO.md)**.
Design & data flow: **[ARCHITECTURE.md](ARCHITECTURE.md)**.

## Project structure

```
app.py            HTTP server, routing, all endpoints (vuln + secure branches)
auth.py           JWT (HMAC-SHA256) + password hashing
crypto_utils.py   AES-GCM encryption + Ed25519 certificate signatures
blockchain.py     SHA-256 integrity ledger (anchors grades + certifications)
db.py             database access + seed data
schema.sql        database schema
static/           front-end (index.html, app.js, style.css)
keys/             generated crypto keys (git-ignored)
```

> This project is intentionally insecure in its default build. Run it only on your
> own machine (`127.0.0.1`); never expose it to a network.
