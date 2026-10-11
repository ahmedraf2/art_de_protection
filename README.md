# Campus — Student Management System

A small student management system (students, professors, admins) built to study
common web-application security flaws and their fixes: SQL injection, broken JWT
authentication, IDOR, insecure password storage, plus a practical look at encryption
and digital signatures.

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
| **Student** | see own courses/grades/certifications; request documents; messaging; announcements |
| **Professor** | grade own courses; issue (sign) certificates to enrolled students; messaging; post announcements |
| **Admin** | manage all users; approve document requests; monitor/restore tampered grades; post announcements |

Cross-cutting: JWT login, password reset, editable profile, a campus announcements
feed, administrative document requests, private messaging, digitally-signed
certifications, encrypted message storage, and a blockchain integrity ledger — a
Solidity smart contract on a local Ethereum node — that anchors grades and
certifications and powers the admin tamper monitor (secure build).

## Requirements

- Python 3.8+
- `Flask`, `cryptography` (AES-GCM + Ed25519) and `web3` (talks to the contract):

```bash
pip install -r requirements.txt
```

- [Foundry](https://getfoundry.sh) for the smart contract — `forge` compiles/tests
  it, `anvil` is the local Ethereum node (needed by the secure build only):

```bash
curl -L https://foundry.paradigm.xyz | bash   # then open a new terminal
foundryup
cd contracts && forge build && forge test      # compile + run the 3 tests
```

## Run with Docker (one command)

```bash
docker compose up --build        # anvil + contract build + secure (:3001) + vuln (:3000)
docker compose down              # stop and remove the containers

python3 scripts/try_attack.py    # play the attacker against both builds (see DEMO.md §7)
```

Only the secure build uses the blockchain; the vuln build starts without anvil.

Every service listens on `127.0.0.1` only (`network_mode: host`, Linux). The DB
files and `keys/` are created in this folder, so `sqlite3`, `cast` and the browser
on your machine work exactly as in DEMO.md. Each `up` starts a fresh chain and a
fresh database. After a DB-tamper demo, `docker compose restart secure` resets that
build.

## Run by hand

```bash
# 1. local Ethereum node (own terminal, keep it running; listens on 127.0.0.1 only)
anvil --host 127.0.0.1 --port 8545 --chain-id 31337

# 2. vulnerable build (does not use the chain)
python3 app.py                      # http://127.0.0.1:3000

# 3. secure build (on a different port so you can compare side by side)
RESET_DB=1 APP_MODE=secure PORT=3001 python3 app.py

# rebuild the database from scratch
RESET_DB=1 python3 app.py
```

The database (`sms_vuln.db` / `sms_secure.db`) and the crypto keys (`keys/`) are
created automatically on first run. On a fresh database the secure build also
generates an Ethereum issuer key (`keys/eth_issuer.key`), funds it from anvil's
account #0, deploys `GradeLedger` and anchors the seed data
(`keys/deployment.json` holds the contract address).

anvil keeps no state: **after restarting anvil, restart the secure build with
`RESET_DB=1`** (the app prints a reminder if the contract is missing).

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
| 4 | IDOR — private chats and student documents | `GET /api/chat?chat_users[0]=..&chat_users[1]=..`, `GET /api/documents/<id>` |
| 5 | Privilege escalation (client-chosen role) | `POST /api/register` |
| 6 | Insecure password hashing (unsalted MD5) | `auth.hash_password` |
| 7 | Missing signature / encryption at rest | certifications & messages |
| 8 | No integrity anchoring (grade/cert tampering undetected) | `GET /api/grades/integrity`, `GET /api/blockchain` |
| 9 | Mass assignment (profile update sets `role`) | `POST /api/profile` |
| 10 | Unrestricted file upload | `POST /api/documents` |
| 11 | Path traversal (arbitrary file read on download) | `GET /api/documents/<id>/download?name=..` |

Try every vuln by hand (browser + DevTools): **[MANUAL_TESTING.md](MANUAL_TESTING.md)**.
Full exploit steps and fixes: **[VULNERABILITIES.md](VULNERABILITIES.md)**.
Step-by-step live-demo script: **[DEMO.md](DEMO.md)**.
Design & data flow: **[ARCHITECTURE.md](ARCHITECTURE.md)**.

## Project structure

```
app.py            HTTP server, routing, all endpoints (vuln + secure branches)
auth.py           JWT (HMAC-SHA256) + password hashing
crypto_utils.py   AES-GCM encryption + Ed25519 certificate signatures
eth_ledger.py     web3 client for the GradeLedger contract (anchor + verify)
contracts/        Foundry project: src/GradeLedger.sol + test/
scripts/          try_attack.py — tamper demo, vuln vs secure side by side
docker-compose.yml, Dockerfile   one-command lab (keys, anvil, forge, secure, vuln)
db.py             database access + seed data
schema.sql        database schema
static/           front-end (index.html, app.js, style.css)
keys/             generated crypto keys (git-ignored)
```

> This project is intentionally insecure in its default build. Run it only on your
> own machine (`127.0.0.1`); never expose it to a network.
