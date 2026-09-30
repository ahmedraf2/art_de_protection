# Auth & Crypto Lab — a deliberately vulnerable web app

A small, intentionally insecure web application for practicing **both** offensive
(red-team) and defensive (blue-team) skills, in the spirit of OWASP Juice Shop /
DVWA / WebGoat. Every vulnerability is documented and paired with a working fix.

> ⚠️ **This app is insecure on purpose.** Run it only on your own machine, bound
> to `127.0.0.1`. Never deploy it to a shared or public host.

## The one-switch design

The same code contains the vulnerable *and* the patched implementation of every
issue. An environment variable chooses which runs:

```bash
python3 app.py                 # APP_MODE=vuln   (default) — everything is broken
APP_MODE=secure python3 app.py # patched — attacks below should now fail
```

Attack it in `vuln` mode, apply your understanding, then flip to `secure` mode
and confirm the same exploit no longer works. In the source, the two branches sit
next to each other, tagged `# VULN:` and `# SECURE:`.

## Requirements

- **Python 3.8+** — standard library only, **no `pip install` needed**.
- (Optional) the `sqlite3` CLI, only if you want to inspect the DB by hand.

The lab is written in Python because it needs a *real* database driver to teach
SQL injection honestly: `sqlite3.execute(sql, params)` binds values on a separate
channel (the fix), versus f-string concatenation (the bug). Note the comment
marker is therefore `# VULN:` (Python) rather than the `// VULN:` in the brief —
the substance is identical.

## Setup & run

```bash
cd art_de_protection

# 1. (optional) create a fresh database — the app also auto-creates one on boot
python3 db.py vuln
python3 db.py secure

# 2. run it
python3 app.py                      # http://127.0.0.1:3000  (vulnerable)
#   or
APP_MODE=secure python3 app.py      # patched

# helpful env vars:
#   PORT=3001        change the port
#   RESET_DB=1       wipe & reseed the DB for this mode on boot
#   JWT_SECRET=...   override the (intentionally weak) signing key
```

Open <http://127.0.0.1:3000> for a clickable UI, or drive the JSON API directly
with `curl` / **Burp Suite** (send requests through Burp's proxy on `127.0.0.1:8080`).

## Seeded accounts

| username | password   | role  |
|----------|------------|-------|
| `admin`  | `admin123` | admin |
| `alice`  | `password1`| user  |
| `bob`    | `hunter2`  | user  |

## The vulnerabilities

Full exploit walkthroughs and patch explanations are in
[VULNERABILITIES.md](VULNERABILITIES.md).

| # | Class | Where | Fixed by |
|---|-------|-------|----------|
| 1 | SQL injection | `/api/login`, `/api/search` | parameterized queries |
| 2 | Authentication bypass | JWT verify + remember-me cookie | HMAC verify, pin `alg`, server-side random tokens |
| 3 | Privilege escalation | `/api/register`, `/api/admin/users` | server-assigned roles, authz from DB |
| 4 | IDOR | `/api/users/:id` | ownership/role check, hide secrets |
| 5 | Weak password hashing | `auth.hash_password` | PBKDF2-HMAC-SHA256 + per-user salt |
| 6 | Stored XSS *(bonus)* | notes rendering | output encoding (`textContent` / `html.escape`) |

## API reference

| Method | Path | Notes |
|--------|------|-------|
| GET  | `/api/config` | returns the running mode |
| POST | `/api/register` | `{username, password, email?, full_name?, role?}` |
| POST | `/api/login` | `{username, password, remember?}` → `{token}` |
| POST | `/api/logout` | clears remember-me |
| GET  | `/api/me` | current user (needs `Authorization: Bearer <jwt>`) |
| GET  | `/api/users/:id` | user profile (**IDOR**) |
| GET  | `/api/admin/users` | all users incl. secrets (**admin only**) |
| GET  | `/api/search?q=` | search users by name (**SQLi**) |
| GET  | `/api/notes` | your notes |
| POST | `/api/notes` | `{title, body}` (**stored XSS**) |

## Project layout

```
art_de_protection/
├── app.py              # HTTP server, routing, all endpoints (vuln + secure branches)
├── auth.py             # JWT (HMAC-SHA256), password hashing, remember-me tokens
├── db.py               # sqlite3 access: vuln_query vs safe_query, init + seed
├── schema.sql          # database schema (the deliverable "DB schema")
├── static/             # minimal frontend (index.html, app.js, style.css)
├── README.md
├── VULNERABILITIES.md  # per-vuln: exploit steps + patch
├── ARCHITECTURE.md     # component & data-flow diagram
└── lab_vuln.db /
    lab_secure.db       # created on first run (git-ignore these)
```

## Suggested lab flow

1. Boot in `vuln` mode. Reproduce each finding in VULNERABILITIES.md with Burp.
2. Read the matching `# VULN:` block and predict the fix.
3. Boot in `secure` mode. Re-run the same requests; confirm they fail.
4. Diff the `# VULN:` vs `# SECURE:` branches and write up *why* the fix works.
