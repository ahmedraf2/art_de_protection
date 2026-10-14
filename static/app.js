// Meridian University — Student Portal front-end SPA.
// The auth token is kept in localStorage and sent as a Bearer header, like a
// typical single-page app. Views are rendered from the URL hash, so the chat
// conversation URL (…#chat?chat_users[0]=..&chat_users[1]=..) is visible and
// editable in the address bar.

let USER = null;
let MODE = "vuln";      // build reported by /api/config ("vuln" | "secure")

// ---------------- branding ----------------
const ORG_NAME = "Meridian University";
const ACADEMIC_YEAR = "2025 / 2026";
const DOC_TYPES = ["Attestation d'inscription", "Relevé de notes", "Attestation de réussite"];
const LOGO_SVG = `<svg class="logo" viewBox="0 0 32 32" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
  <path d="M16 3 4 8v8c0 7 5 11.3 12 13 7-1.7 12-6 12-13V8L16 3Z" fill="var(--accent)"/>
  <text x="16" y="21.5" text-anchor="middle" font-size="14" font-weight="800" fill="#fff"
        font-family="Segoe UI, system-ui, sans-serif">M</text></svg>`;

function brandMarkup(sub) {
  return `${LOGO_SVG}<span class="brand-text"><span class="brand-org">${ORG_NAME}</span>` +
         (sub ? `<span class="brand-sub">${sub}</span>` : "") + `</span>`;
}
function applyBranding() {
  ["brand-login", "brand-register", "brand-reset", "brand-top"].forEach(id => {
    const el = $(id); if (el) el.innerHTML = brandMarkup("Student Portal");
  });
  const yp = $("year-pill"); if (yp) yp.textContent = ACADEMIC_YEAR;
  const footText = `© ${new Date().getFullYear()} ${ORG_NAME} · Student Portal · Academic year ${ACADEMIC_YEAR}`;
  ["foot-login", "app-footer"].forEach(id => { const el = $(id); if (el) el.textContent = footText; });
}

function token() { return localStorage.getItem("token") || ""; }
function setToken(t) { localStorage.setItem("token", t); }
function clearToken() { localStorage.removeItem("token"); }
function esc(s) { const d = document.createElement("div"); d.textContent = s == null ? "" : s; return d.innerHTML; }
function initials(name) { return (name || "?").split(" ").map(w => w[0]).slice(0, 2).join("").toUpperCase(); }
function fmtDate(s) { return (s || "").replace("T", " ").slice(0, 16); }
const $ = (id) => document.getElementById(id);

async function api(method, path, body) {
  const h = {};
  if (token()) h["Authorization"] = "Bearer " + token();
  const opts = { method, headers: h };
  if (body !== undefined) { h["Content-Type"] = "application/json"; opts.body = JSON.stringify(body); }
  const res = await fetch(path, opts);
  // Session expiry: if a request with a token comes back 401, the token is
  // invalid or expired — send the user back to login instead of silently
  // breaking the view. (The public auth endpoints never carry a token.)
  if (res.status === 401 && token() &&
      !path.startsWith("/api/login") && !path.startsWith("/api/register")) {
    sessionExpired();
    return { status: 401, data: { error: "session expired" } };
  }
  let data; try { data = await res.json(); } catch { data = {}; }
  return { status: res.status, data };
}
const get = async (p) => (await api("GET", p)).data;

// multipart variant for file uploads (let the browser set the boundary header)
async function apiForm(method, path, formData) {
  const h = {};
  if (token()) h["Authorization"] = "Bearer " + token();
  const res = await fetch(path, { method, headers: h, body: formData });
  if (res.status === 401 && token()) { sessionExpired(); return { status: 401, data: { error: "session expired" } }; }
  let data; try { data = await res.json(); } catch { data = {}; }
  return { status: res.status, data };
}

// Download an attachment (auth header required, so fetch -> blob -> open in a tab).
// In the vuln build the server serves it inline, so an uploaded .html/.svg runs.
async function downloadDoc(id, which) {
  const res = await fetch(`/api/documents/${id}/download?which=${which}`,
    { headers: token() ? { Authorization: "Bearer " + token() } : {} });
  if (!res.ok) { alert("Download failed (" + res.status + ")"); return; }
  const blob = await res.blob();
  window.open(URL.createObjectURL(blob), "_blank");
}

function sessionExpired() {
  if (!token()) return;
  clearToken(); USER = null;
  clearInterval(_integrityTimer);
  $("app").classList.add("hidden");
  showLogin();
  const e = $("li-error");
  if (e) e.textContent = "Your session has expired. Please sign in again.";
}

// ---------------- auth screens ----------------
function hideAuthScreens() {
  ["login-screen", "register-screen", "reset-screen"].forEach(id => $(id).classList.add("hidden"));
}
function showLogin() { hideAuthScreens(); $("login-screen").classList.remove("hidden"); }
function showRegister() { hideAuthScreens(); $("register-screen").classList.remove("hidden"); }
function showReset() {
  hideAuthScreens(); $("reset-screen").classList.remove("hidden");
  $("rs-token-box").classList.add("hidden"); $("rs-msg").textContent = "";
}

async function doLogin() {
  $("li-error").textContent = "";
  const { status, data } = await api("POST", "/api/login", {
    username: $("li-user").value, password: $("li-pass").value,
  });
  if (status === 200 && data.token) { setToken(data.token); enterApp(); }
  else $("li-error").textContent = data.error || "Login failed";
}

async function doRegister() {
  $("rg-error").textContent = "";
  const { status, data } = await api("POST", "/api/register", {
    full_name: $("rg-name").value,
    username: $("rg-user").value,
    email: $("rg-email").value,
    password: $("rg-pass").value,
    // The role is assigned by the server (secure) — the UI never sends one.
  });
  if (status === 201) { alert("Account created. You can sign in now."); showLogin(); }
  else $("rg-error").textContent = data.error || "Registration failed";
}

// ---- password reset ----
async function requestReset() {
  const { data } = await api("POST", "/api/password-reset/request", { username: $("rs-user").value });
  $("rs-token-box").classList.remove("hidden");
  const m = $("rs-msg"); m.style.color = "var(--muted)";
  if (data.reset_token) {        // vuln build returns the token directly
    $("rs-token").value = data.reset_token;
    m.textContent = "Demo token issued (shown here for the lab): " + data.reset_token;
  } else {
    m.textContent = data.message || "If the account exists, a token was issued (see the server log).";
  }
}
async function confirmReset() {
  const { status, data } = await api("POST", "/api/password-reset/confirm", {
    token: $("rs-token").value, new_password: $("rs-new").value,
  });
  const m = $("rs-msg");
  if (status === 200) { m.style.color = "var(--good)"; m.textContent = "Password reset. You can sign in now."; setTimeout(showLogin, 1200); }
  else { m.style.color = "var(--bad)"; m.textContent = data.error || "Reset failed"; }
}

function doLogout() { clearToken(); USER = null; location.hash = ""; location.reload(); }

// ---------------- app shell ----------------
const NAV = [
  { view: "dashboard", label: "Dashboard", icon: "🏠", roles: ["student", "professor", "admin"] },
  { view: "announcements", label: "Announcements", icon: "📢", roles: ["student", "professor", "admin"] },
  { view: "chat", label: "Chat", icon: "💬", roles: ["student", "professor", "admin"] },
  { view: "courses", label: "Courses", icon: "📚", roles: ["student", "professor", "admin"] },
  { view: "search", label: "Course search", icon: "🔍", roles: ["student"] },
  { view: "certifications", label: "Certifications", icon: "🎖️", roles: ["student"] },
  { view: "documents", label: "Documents", icon: "📄", roles: ["student", "admin"] },
  { view: "gradebook", label: "Gradebook", icon: "📝", roles: ["professor"] },
  { view: "certify", label: "Certify", icon: "🎓", roles: ["professor"] },
  { view: "users", label: "Users", icon: "👥", roles: ["admin"] },
  { view: "integrity", label: "Integrity", icon: "🛡️", roles: ["admin"], secureOnly: true },
];

async function enterApp() {
  const { status, data } = await api("GET", "/api/me");
  if (status !== 200) { showLogin(); return; }
  USER = data.user;
  MODE = (await get("/api/config")).mode || "vuln";
  hideAuthScreens();
  $("app").classList.remove("hidden");
  $("tb-name").textContent = USER.full_name;
  $("avatar").textContent = initials(USER.full_name);

  $("sidebar").innerHTML = NAV.filter(n => n.roles.includes(USER.role) && !(n.secureOnly && MODE !== "secure"))
    .map(n => `<button data-view="${n.view}" onclick="nav('${n.view}')"><span>${n.icon}</span> ${n.label}</button>`).join("");

  // the secure build lets an admin watch for DB tampering from anywhere in the app
  if (MODE === "secure" && USER.role === "admin") startIntegrityWatch();

  if (!location.hash) location.hash = "dashboard";
  route();
}

// ---- admin tamper watch (secure build) ----
let _integrityTimer = null;
function startIntegrityWatch() {
  checkIntegrityBadge();
  clearInterval(_integrityTimer);
  _integrityTimer = setInterval(checkIntegrityBadge, 8000);   // near-immediate alert
}
async function checkIntegrityBadge() {
  const { status, data } = await api("GET", "/api/admin/integrity");
  const btn = document.querySelector('#sidebar button[data-view="integrity"]');
  if (!btn) return;
  btn.querySelector(".nav-badge")?.remove();
  const n = (status === 200 && data.available) ? (data.alerts || []).length : 0;
  if (n > 0) {
    const b = document.createElement("span");
    b.className = "nav-badge";
    b.textContent = n;
    btn.appendChild(b);
  }
}

function nav(v) { location.hash = v; }
window.addEventListener("hashchange", route);

function parseRoute() {
  const raw = location.hash.replace(/^#/, "") || "dashboard";
  const [view, qs] = raw.split("?");
  return { view, params: new URLSearchParams(qs || "") };
}

function route() {
  if (!USER) return;
  const { view, params } = parseRoute();
  document.querySelectorAll("#sidebar button").forEach(b =>
    b.classList.toggle("active", b.dataset.view === view));
  const render = VIEWS[view] || VIEWS.dashboard;
  render(params);
}

// dropdown
function toggleMenu(e) { e.stopPropagation(); $("dropdown").classList.toggle("hidden"); }
document.addEventListener("click", () => $("dropdown") && $("dropdown").classList.add("hidden"));

// ---------------- views ----------------
const VIEWS = {};

VIEWS.dashboard = async function () {
  const c = $("content");
  const first = (USER.full_name || "").split(" ")[0];
  if (USER.role === "student") {
    const reqs = [get("/api/my/grades"), get("/api/my/courses"), get("/api/messages/recent"),
                  get("/api/certifications"), get("/api/announcements")];
    if (MODE === "secure") reqs.push(get("/api/grades/integrity"));
    const [g, mc, rm, certs, ann, integ] = await Promise.all(reqs);

    // In the secure build, verify each grade against the integrity ledger: show
    // a tampered DB value in red next to the real (anchored) grade. The average
    // is computed from the verified grades, so editing the DB never moves it.
    const verified = MODE === "secure" && integ && integ.available;
    const grades = verified
      ? (integ.rows || []).map(r => ({ name: r.name, db: r.db_grade, real: r.true_grade, ok: r.ok }))
      : (g.grades || []).map(x => ({ name: x.name, db: x.grade, real: x.grade, ok: true }));
    const anyTampered = grades.some(x => x.ok === false);
    const avgNums = grades.map(x => parseFloat((x.real != null ? x.real : x.db) || 0));
    const avg = avgNums.length
      ? (avgNums.reduce((s, n) => s + n, 0) / avgNums.length).toFixed(2) : "—";
    c.innerHTML = `
      <div class="page-title">Welcome back, ${esc(first)} 👋</div>
      <p class="page-sub">Here's what's happening in your account.</p>
      <div class="grid-4">
        ${stat("📚", grades.length, "Courses")}
        ${stat("📊", avg + "/20", "Average")}
        ${stat("🎖️", (certs.certifications || []).length, "Certifications")}
        ${stat("💬", (rm.messages || []).length, "Recent messages")}
      </div>
      <div class="grid-2 mt">
        <div class="card">
          <h3>My grades ${verified ? `<span class="verified-badge">&#9939; ledger&#8209;verified</span>` : ""}</h3>
          ${anyTampered ? `<p class="tamper-note">&#9888; A grade below does not match the integrity ledger. The value on record (verified) is shown; your average uses it.</p>` : ""}
          <table><thead><tr><th>Subject</th><th>Grade</th></tr></thead><tbody>
          ${grades.map(x => `<tr><td>${esc(x.name)}</td><td>${gradeStatus(x)}</td></tr>`).join("")
            || `<tr><td colspan="2" class="muted">No grades yet.</td></tr>`}
          </tbody></table>
        </div>
        <div class="card">
          <h3>Recent messages</h3>
          ${recentList(rm.messages || [])}
          <button class="btn-ghost mt" onclick="nav('chat')">View all messages</button>
        </div>
      </div>
      ${announceWidget(ann.announcements || [])}
      <div class="card mt"><h3>My courses</h3>
        <div class="grid-3 mt">${(mc.courses || []).map(enrolledCard).join("")
          || `<p class="muted">You are not enrolled in any courses yet.</p>`}</div>
      </div>`;
  } else {
    const [mc, rm, ann] = await Promise.all([get("/api/my/courses"), get("/api/messages/recent"),
                                             get("/api/announcements")]);
    c.innerHTML = `
      <div class="page-title">Welcome back, ${esc(first)} 👋</div>
      <p class="page-sub">${USER.role === "admin" ? "Administrator dashboard." : "Professor dashboard."}</p>
      <div class="grid-2">
        <div class="card"><h3>${USER.role === "admin" ? "All courses" : "My courses"}</h3>
          <div class="grid-2 mt">${(mc.courses || []).map(enrolledCard).join("")}</div>
        </div>
        <div class="card"><h3>Recent messages</h3>${recentList(rm.messages || [])}
          <button class="btn-ghost mt" onclick="nav('chat')">View all messages</button></div>
      </div>
      ${announceWidget(ann.announcements || [])}`;
  }
};

function stat(ic, n, l) { return `<div class="stat"><span class="ic">${ic}</span><div class="n">${esc(n)}</div><div class="l">${esc(l)}</div></div>`; }
function gradePill(v) {
  const n = parseFloat(v); const cls = n >= 14 ? "g" : n >= 10 ? "o" : "b";
  return `<span class="pill ${cls}">${esc(v)} / 20</span>`;
}
// A grade row that may have been tampered with: when the DB value no longer
// matches the ledger, show it struck through in red with the verified grade.
function gradeStatus(x) {
  if (x.ok === false) {
    const real = x.real != null
      ? `<span class="grade-real">&#10004; verified ${esc(x.real)} / 20</span>`
      : `<span class="grade-real warn">&#9888; unverified</span>`;
    return `<span class="pill b strike">${esc(x.db)} / 20</span> ${real}`;
  }
  return gradePill(x.db);
}
function courseCard(x) {
  return `<div class="course"><div class="code">${esc(x.code)}</div><div class="name">${esc(x.name)}</div>
          <div class="muted">${esc(x.professor || "—")}</div></div>`;
}
function enrolledCard(x) {
  return `<div class="course"><div class="code">${esc(x.code)}</div><div class="name">${esc(x.name)}</div></div>`;
}
function recentList(msgs) {
  if (!msgs.length) return `<p class="muted">No messages.</p>`;
  return msgs.map(m => `<div class="rmsg"><div class="dot"></div><div>
    <div class="who">${m.outgoing ? "To " : ""}${esc(m.with)}</div>
    <div class="snip">${esc(m.body)}</div></div></div>`).join("");
}
// A compact "latest news" card for the dashboard. Bodies render through
// announceBody(), which escapes them in both builds.
function announceWidget(items) {
  if (!items.length) return "";
  const top = items.slice(0, 3).map(a => `
    <div class="rmsg"><div class="dot"></div><div style="min-width:0">
      <div class="who">${esc(a.title)} <span class="muted" style="font-weight:400">· ${esc(fmtDate(a.created_at))}</span></div>
      <div class="snip" style="max-width:none">${announceBody(a.body)}</div></div></div>`).join("");
  return `<div class="card mt"><h3>Latest announcements</h3>${top}
    <button class="btn-ghost mt" onclick="nav('announcements')">View all announcements</button></div>`;
}

// ---- courses ----
VIEWS.courses = async function () {
  const d = await get("/api/courses");
  $("content").innerHTML = `
    <div class="page-title">Courses</div><p class="page-sub">Course catalogue</p>
    <div class="grid-3">${(d.courses || []).map(courseCard).join("")}</div>`;
};

// ---- announcements (campus news feed) ----
VIEWS.announcements = async function () {
  const d = await get("/api/announcements");
  const canPost = USER.role === "professor" || USER.role === "admin";
  $("content").innerHTML = `
    <div class="page-title">Announcements</div>
    <p class="page-sub">News from the administration and your professors.</p>
    ${canPost ? `<div class="card" style="max-width:660px">
      <label>Title</label><input id="an-title" placeholder="Announcement title" />
      <label>Message</label><textarea id="an-body" rows="3" placeholder="Write an announcement…"></textarea>
      <div id="an-msg" class="form-error"></div>
      <button class="btn-primary btn-block" onclick="postAnnouncement()">Publish</button>
    </div>` : ""}
    <div id="an-feed" class="mt"></div>`;
  renderAnnouncements(d.announcements || []);
};
function renderAnnouncements(items) {
  const feed = $("an-feed");
  if (!feed) return;
  if (!items.length) { feed.innerHTML = `<p class="muted">No announcements yet.</p>`; return; }
  feed.innerHTML = items.map(a => `
    <div class="card announce">
      <div class="announce-head">
        <h3>${esc(a.title)}</h3>
        <span class="muted">${esc(fmtDate(a.created_at))}</span>
      </div>
      <div class="announce-meta">${esc(a.author || "Staff")}
        <span class="badge-role">${esc(a.author_role || "")}</span></div>
      <div class="announce-body">${announceBody(a.body)}</div>
    </div>`).join("");
}
// Announcement bodies are HTML-escaped on output (output encoding) in BOTH builds,
// so any markup stored in a post renders as inert text instead of executing.
function announceBody(body) {
  return esc(body);
}
async function postAnnouncement() {
  const { status, data } = await api("POST", "/api/announcements", {
    title: $("an-title").value, body: $("an-body").value,
  });
  const m = $("an-msg");
  m.style.color = status === 201 ? "var(--good)" : "var(--bad)";
  m.textContent = status === 201 ? "Published." : (data.error || "Failed");
  if (status === 201) VIEWS.announcements();
}

// ---- course search ----
VIEWS.search = async function () {
  $("content").innerHTML = `
    <div class="page-title">Course search</div>
    <p class="page-sub">Find a course by its code or name.</p>
    <div class="card" style="max-width:640px">
      <div style="display:flex;gap:8px">
        <input id="dir-q" placeholder="e.g. Programming or PROG…" style="flex:1"
               onkeydown="if(event.key==='Enter')runSearch()" />
        <button class="btn-primary" onclick="runSearch()">Search</button>
      </div>
    </div>
    <div class="card mt"><div id="dir-results" class="muted">Type a course code or name and hit Search.</div></div>`;
};
async function runSearch() {
  const q = $("dir-q").value;
  const d = await get("/api/search?query=" + encodeURIComponent(q));
  const rows = d.results || [];
  const box = $("dir-results");
  if (!rows.length) { box.innerHTML = `<p class="muted">No matching courses.</p>`; return; }
  box.innerHTML = `<table><thead><tr><th>Code</th><th>Name</th></tr></thead>
    <tbody>${rows.map(r => `<tr><td><b>${esc(r.code)}</b></td><td>${esc(r.name)}</td></tr>`).join("")}</tbody></table>`;
}

// ---- certifications ----
VIEWS.certifications = async function (params) {
  let sid = params.get("student_id");
  if (sid === null) {            // pin your own id into the URL (recon surface for #2)
    location.hash = "certifications?student_id=" + USER.id;
    return;
  }
  const d = await get("/api/certifications?student_id=" + encodeURIComponent(sid));
  const ledger = MODE === "secure";      // the Ledger column only exists in the secure build
  const ledgerCell = (c) => {
    if (c.on_chain === null) return `<span class="pill o">&#9888; unavailable</span>`;
    return c.on_chain ? `<span class="pill g">&#9939; on&#8209;chain</span>`
                      : `<span class="pill b">&#9888; not on chain</span>`;
  };
  const rows = (d.certifications || []).map(c => `
    <tr><td>${esc(c.full_name || "")}</td><td>${esc(c.title)}</td><td>${esc(c.grade)}</td>
    <td>${esc(c.issued_date)}</td>
    <td>${c.verified ? `<span class="pill g">&#10004; valid</span>` : `<span class="pill b">&#10008; invalid</span>`}</td>
    ${ledger ? `<td>${ledgerCell(c)}</td>` : ""}</tr>`).join("");
  $("content").innerHTML = `
    <div class="page-title">Certifications</div>
    <p class="page-sub">Your issued certifications, verified against the campus signing key and integrity ledger.</p>
    <div class="card"><table><thead><tr><th>Student</th><th>Title</th><th>Grade</th><th>Issued</th><th>Signature</th>${ledger ? "<th>Ledger</th>" : ""}</tr></thead>
    <tbody>${rows || `<tr><td colspan="6" class="muted">No certifications.</td></tr>`}</tbody></table></div>`;
};

// ---- documents (students request; admin approves/rejects; IDOR on viewing #4b) ----
VIEWS.documents = async function (params) {
  const docId = params.get("doc");
  if (docId) return renderDocument(docId);
  if (USER.role === "admin") return renderAdminDocuments();
  return renderMyDocuments();
};
function docStatus(s) {
  const cls = s === "approved" ? "g" : s === "rejected" ? "b" : "o";
  return `<span class="pill ${cls}">${esc(s)}</span>`;
}
async function renderMyDocuments() {
  const d = await get("/api/my/documents");
  const rows = (d.documents || []).map(x => `
    <tr><td>${esc(x.reference || ("#" + x.id))}</td><td>${esc(x.doc_type)}</td>
      <td>${docStatus(x.status)}</td><td>${esc(fmtDate(x.created_at))}</td>
      <td>${x.request_file
        ? `<button class="btn-ghost sm" onclick="downloadDoc(${x.id},'request')">My upload</button>` : ""}
        ${x.status === "approved"
          ? `<button class="btn-ghost sm" onclick="nav('documents?doc=${x.id}')">View</button>
             ${x.issued_file ? `<button class="btn-primary sm" onclick="downloadDoc(${x.id},'issued')">Download PDF</button>` : ""}`
          : ""}</td></tr>`).join("");
  $("content").innerHTML = `
    <div class="page-title">Documents</div>
    <p class="page-sub">Request official documents from the registrar's office.</p>
    <div class="card" style="max-width:520px">
      <label>Document type</label>
      <select id="doc-type">${DOC_TYPES.map(t => `<option>${esc(t)}</option>`).join("")}</select>
      <label>Supporting document (PDF)</label>
      <input id="doc-file" type="file" accept="application/pdf" />
      <div id="doc-msg" class="form-error"></div>
      <button class="btn-primary btn-block" onclick="requestDocument()">Submit request</button>
    </div>
    <div class="card mt"><h3>My requests</h3>
      <table><thead><tr><th>Reference</th><th>Type</th><th>Status</th><th>Requested</th><th></th></tr></thead>
      <tbody>${rows || `<tr><td colspan="5" class="muted">No requests yet.</td></tr>`}</tbody></table></div>`;
}
async function requestDocument() {
  const m = $("doc-msg");
  const f = $("doc-file").files[0];
  if (!f) { m.style.color = "var(--bad)"; m.textContent = "Attach a supporting PDF."; return; }
  const fd = new FormData();
  fd.append("doc_type", $("doc-type").value);
  fd.append("attachment", f);
  const { status, data } = await apiForm("POST", "/api/documents", fd);
  m.style.color = status === 201 ? "var(--good)" : "var(--bad)";
  m.textContent = status === 201 ? "Request submitted." : (data.error || "Failed");
  if (status === 201) renderMyDocuments();
}
async function renderAdminDocuments() {
  const d = await get("/api/admin/documents");
  const rows = (d.documents || []).map(x => {
    const studentUpload = x.request_file
      ? `<button class="btn-ghost sm" onclick="downloadDoc(${x.id},'request')">Student upload</button>` : "";
    const action = x.status === "pending"
      ? `<button class="btn-primary sm" onclick="decideDoc(${x.id},'approved')">Approve</button>
         <button class="btn-ghost sm" onclick="decideDoc(${x.id},'rejected')">Reject</button>`
      : `<button class="btn-ghost sm" onclick="nav('documents?doc=${x.id}')">View</button>`;
    return `<tr><td>${esc(x.reference || ("#" + x.id))}</td><td>${esc(x.student)}</td><td>${esc(x.doc_type)}</td>
      <td>${docStatus(x.status)}</td><td>${studentUpload}</td><td>${action}</td></tr>`;
  }).join("");
  $("content").innerHTML = `
    <div class="page-title">Document requests</div>
    <p class="page-sub">Review each request, then approve or reject it.</p>
    <div class="card"><table><thead><tr><th>Reference</th><th>Student</th><th>Type</th><th>Status</th><th>Upload</th><th>Action</th></tr></thead>
      <tbody>${rows || `<tr><td colspan="6" class="muted">No requests.</td></tr>`}</tbody></table></div>`;
}
async function decideDoc(id, decision) {
  const fd = new FormData();
  fd.append("decision", decision);
  const { status, data } = await apiForm("POST", `/api/admin/documents/${id}/decide`, fd);
  if (status !== 200) { alert((data && data.error) || "Failed"); return; }
  renderAdminDocuments();
}
async function renderDocument(id) {
  const { status, data } = await api("GET", "/api/documents/" + encodeURIComponent(id));
  const c = $("content");
  const back = `<button class="btn-ghost" onclick="nav('documents')">← Back</button>`;
  if (status !== 200) {
    c.innerHTML = `<div class="chat-head"><div class="page-title">Document</div>${back}</div>
      <div class="card"><p class="pill b">${esc((data && data.error) || "Error")}</p></div>`;
    return;
  }
  const d = data.document;
  c.innerHTML = `<div class="chat-head"><div class="page-title">Document</div>${back}</div>
    ${d.status === "approved" ? attestation(d)
      : `<div class="card"><p class="muted">This document is <b>${esc(d.status)}</b> and cannot be viewed yet.</p></div>`}`;
}
function attestation(d) {
  return `<div class="card attestation">
    <div class="att-head">${LOGO_SVG}
      <div><div class="att-org">${ORG_NAME}</div><div class="muted">Office of the Registrar</div></div></div>
    <h2 class="att-title">${esc(d.doc_type)}</h2>
    <p>This is to certify that <b>${esc(d.student)}</b> is a registered student at
       ${ORG_NAME} for the ${ACADEMIC_YEAR} academic year.</p>
    <div class="att-grid">
      <div><span class="k">Reference</span>${esc(d.reference || ("#" + d.id))}</div>
      <div><span class="k">Issued</span>${esc(fmtDate(d.decided_at || d.created_at))}</div>
      <div><span class="k">Student e-mail</span>${esc(d.student_email || "—")}</div>
    </div>
    ${d.issued_file ? `<button class="btn-primary" onclick="downloadDoc(${d.id},'issued')">Download issued PDF</button>` : ""}
    <p class="att-foot muted">Generated by the ${ORG_NAME} Student Portal.
       Verify authenticity at the registrar's office.</p></div>`;
}

// ---- on-chain audit log (rendered inside the admin Integrity page) ----
function shortHash(h) { return h ? h.slice(0, 10) + "…" + h.slice(-6) : ""; }

async function renderLedger() {
  const box = $("ledger-box");
  if (!box) return;
  const chain = await get("/api/blockchain");
  let banner;
  if (!chain.available)
    banner = `<div class="chain-banner bad">&#9888; Ledger unavailable — ${esc(chain.error)}</div>`;
  else
    banner = `<div class="chain-banner ok">&#9939; Connected to GradeLedger (chain ${chain.chain_id}, block ${chain.block_number}).
      <div class="hashline"><span class="k">contract</span><code>${esc(chain.contract)}</code></div>
      <div class="hashline"><span class="k">issuer</span><code>${esc(chain.issuer)}</code> <span class="muted">— the only key allowed to write</span></div></div>`;

  const events = (chain.events || []).slice().reverse().map(e => `
    <div class="block ${esc(e.type)}">
      <div class="block-top"><span class="block-idx">block ${e.block}</span>
        <span class="block-type">${esc(e.type)}</span>
        <span class="muted">${esc(fmtDate(new Date(e.timestamp * 1000).toISOString()))}</span></div>
      <div class="block-sum">${e.type === "grade"
        ? `Grade · course ${e.course_id} · student ${e.student_id}` : `Certification fingerprint`}</div>
      <div class="hashline"><span class="k">hash</span><code>${shortHash(e.hash)}</code></div>
      <div class="hashline"><span class="k">sender</span><code>${esc(e.sender)}</code></div>
      <div class="hashline"><span class="k">tx</span><code>${shortHash(e.tx_hash)}</code></div>
    </div>`).join("");

  box.innerHTML = `
    ${banner}
    <div class="card mt"><h3>Anchored events (${(chain.events || []).length}, newest first)</h3>
      <div class="chain">${events || `<p class="muted">No events.</p>`}</div></div>`;
}

// ---- chat ----
VIEWS.chat = async function (params) {
  const u0 = params.get("chat_users[0]"), u1 = params.get("chat_users[1]");
  if (u0 && u1) return renderConversation(u0, u1);
  const [d, dir] = await Promise.all([get("/api/chats"), get("/api/users/directory")]);
  const opts = (dir.users || []).map(u =>
    `<option value="${u.id}">${esc(u.full_name)} — ${esc(u.role)}</option>`).join("");
  const items = (d.chats || []).map(ch => `
    <div class="chat-item" onclick="openChat(${d.me}, ${ch.user_id})">
      <div class="ci-avatar">${initials(ch.name)}</div>
      <div style="flex:1;min-width:0">
        <div class="ci-name">${esc(ch.name)} <span class="badge-role">${esc(ch.role)}</span></div>
        <div class="ci-last">${esc(ch.last)}</div>
      </div>
    </div>`).join("");
  $("content").innerHTML = `
    <div class="page-title">Chat</div><p class="page-sub">Message anyone on the platform</p>
    <div class="card" style="max-width:640px">
      <h3>New message</h3>
      <label>To</label>
      <select id="nm-to">${opts || `<option value="">— no other users —</option>`}</select>
      <label>Message</label>
      <textarea id="nm-body" rows="2" placeholder="Write a message…"
                onkeydown="if(event.key==='Enter'&&!event.shiftKey){event.preventDefault();startNewMessage();}"></textarea>
      <div id="nm-msg" class="form-error"></div>
      <button class="btn-primary" onclick="startNewMessage()">Send message</button>
    </div>
    <h3 class="mt">Your conversations</h3>
    <div class="chat-list">${items || `<p class="muted">No conversations yet.</p>`}</div>`;
};

async function startNewMessage() {
  const to = Number($("nm-to").value);
  const body = $("nm-body").value.trim();
  const m = $("nm-msg");
  if (!to || !body) { m.style.color = "var(--bad)"; m.textContent = "Pick a recipient and type a message."; return; }
  const { status, data } = await api("POST", "/api/chat", { to, body });
  if (status === 201) openChat(USER.id, to);   // jump into the conversation
  else { m.style.color = "var(--bad)"; m.textContent = (data && data.error) || "Failed to send."; }
}

function openChat(me, other) { location.hash = `chat?chat_users[0]=${me}&chat_users[1]=${other}`; }

async function renderConversation(u0, u1) {
  const { status, data } = await api("GET", `/api/chat?chat_users[0]=${encodeURIComponent(u0)}&chat_users[1]=${encodeURIComponent(u1)}`);
  const c = $("content");
  if (status !== 200) {
    c.innerHTML = `<div class="chat-head"><div class="page-title">Chat</div>
      <button class="btn-primary" onclick="nav('chat')">← Back to Chats</button></div>
      <div class="card"><p class="pill b">${esc(data.error || "Error")}</p></div>`;
    return;
  }
  // The viewer of this conversation is chat_users[0]: their messages are "mine"
  // (green, right). chat_users[1] is the other party (grey, left). This is driven
  // by the URL, so swapping chat_users[0]/[1] swaps the sides — it does NOT depend
  // on who is logged in (that's what makes the #4 IDOR view readable from either side).
  const self = Number(u0);
  const bubbles = (data.messages || []).map(m => {
    const mine = m.sender_id === self;
    return `<div class="bubble-row ${mine ? "mine" : ""}"><div class="bubble">
      <div class="meta"><b>${esc(m.sender_name)}</b> · ${esc(fmtDate(m.created_at))}</div>${esc(m.body)}</div></div>`;
  }).join("");
  const iAmIn = [Number(u0), Number(u1)].includes(data.me);
  const other = Number(u0) === data.me ? u1 : u0;
  const names = (data.participants || []).map(p => esc(p.full_name)).join(" & ");
  c.innerHTML = `
    <div class="chat-head"><div><div class="page-title">Chat</div><p class="page-sub" style="margin:0">${names}</p></div>
      <button class="btn-primary" onclick="nav('chat')">← Back to Chats</button></div>
    <div class="chat-window">${bubbles || `<p class="muted">No messages.</p>`}</div>
    ${iAmIn ? `<div class="chat-compose">
      <input id="chat-input" placeholder="Type a message..." onkeydown="if(event.key==='Enter')sendChat(${other})" />
      <button class="btn-primary" onclick="sendChat(${other})">Send</button></div>` : ""}`;
}

async function sendChat(to) {
  const inp = $("chat-input"); const body = inp.value.trim(); if (!body) return;
  await api("POST", "/api/chat", { to: Number(to), body });
  inp.value = "";
  route();
}

// ---- roster helpers (shared by the professor's Gradebook and Certify pages) ----
let ROSTER = [];        // the professor's courses, each with its enrolled students
function courseOptions(courses) {
  return courses.map(c => `<option value="${c.course_id}">${esc(c.code)} — ${esc(c.name)}</option>`).join("");
}
function fillStudents(prefix) {
  const course = ROSTER.find(c => c.course_id === Number($(prefix + "-course").value));
  const students = course ? course.students : [];
  $(prefix + "-student").innerHTML = students.length
    ? students.map(s => `<option value="${s.id}">${esc(s.full_name)}</option>`).join("")
    : `<option value="">— no enrolled students —</option>`;
}

// ---- gradebook (professors: their own courses only) ----
VIEWS.gradebook = async function () {
  const r = await get("/api/my/roster");
  ROSTER = r.courses || [];
  $("content").innerHTML = `
    <div class="page-title">Gradebook</div>
    <p class="page-sub">Enter or update a grade for a student in one of your courses.</p>
    <div class="card" style="max-width:520px">
      <label>Course</label>
      <select id="gb-course" onchange="fillStudents('gb')">${courseOptions(ROSTER)}</select>
      <label>Student</label>
      <select id="gb-student"></select>
      <label>Grade (/20)</label><input id="gb-grade" placeholder="e.g. 15.5" />
      <div id="gb-msg" class="form-error"></div>
      <button class="btn-primary btn-block" onclick="saveGrade()">Save grade</button>
    </div>
    <div class="card mt"><h3>My courses</h3>
      <table><thead><tr><th>Code</th><th>Name</th><th>Students</th></tr></thead><tbody>
      ${ROSTER.map(x => `<tr><td>${esc(x.code)}</td><td>${esc(x.name)}</td><td>${x.students.length}</td></tr>`).join("")
        || `<tr><td colspan="3" class="muted">You have no courses.</td></tr>`}
      </tbody></table></div>`;
  fillStudents("gb");
};
async function saveGrade() {
  const sid = Number($("gb-student").value);
  if (!sid) { $("gb-msg").style.color = "var(--bad)"; $("gb-msg").textContent = "Select a student."; return; }
  const { status, data } = await api("POST", "/api/grades", {
    course_id: Number($("gb-course").value), student_id: sid, grade: $("gb-grade").value,
  });
  $("gb-msg").style.color = status === 200 ? "var(--good)" : "var(--bad)";
  $("gb-msg").textContent = status === 200 ? "Saved." : (data.error || "Failed");
}

// ---- users (admin: account list only) ----
VIEWS.users = async function () {
  $("content").innerHTML = `
    <div class="page-title">Users</div><p class="page-sub">All accounts in the system</p>
    <div class="card"><div id="admin-users" class="muted">Loading…</div></div>`;
  const d = await get("/api/admin/users");
  const box = $("admin-users");
  if (!d.users) { box.innerHTML = `<span class="pill b">${esc(d.error || "error")}</span>`; return; }
  // A realistic portal shows a clean account list — name, username, email, phone,
  // role. (The vuln build STILL leaks password_hash in the API response; you find
  // it in the Network tab / Burp, not on this screen.)
  const COLS = [["full_name", "Name"], ["username", "Username"], ["email", "Email"],
                ["phone", "Phone"], ["role", "Role"]];
  box.innerHTML = `<table><thead><tr>${COLS.map(c => `<th>${c[1]}</th>`).join("")}</tr></thead>
    <tbody>${d.users.map(u => `<tr>${COLS.map(c =>
      c[0] === "role" ? `<td><span class="badge-role">${esc(u.role)}</span></td>`
                      : `<td>${esc(u[c[0]] || "—")}</td>`).join("")}</tr>`).join("")}</tbody></table>`;
};

// ---- certify (professors: issue a signed certificate to an enrolled student) ----
VIEWS.certify = async function () {
  const r = await get("/api/my/roster");
  ROSTER = r.courses || [];
  const types = r.cert_types || [];
  $("content").innerHTML = `
    <div class="page-title">Issue certificate</div>
    <p class="page-sub">Issue a certificate to a student enrolled in one of your courses.</p>
    <div class="card" style="max-width:560px">
      <label>Certificate</label>
      <select id="cf-type">${types.map(t => `<option>${esc(t)}</option>`).join("")}</select>
      <label>Course</label>
      <select id="cf-course" onchange="fillStudents('cf')">${courseOptions(ROSTER)}</select>
      <label>Student</label>
      <select id="cf-student"></select>
      <div id="cf-msg" class="form-error"></div>
      <button class="btn-primary btn-block" onclick="issueCert()">Issue &amp; sign</button>
    </div>
    <div class="card mt"><h3>Certificates you have issued</h3>
      <div id="cf-issued" class="muted">Loading…</div></div>`;
  fillStudents("cf");
  renderIssuedCerts();
};
async function renderIssuedCerts() {
  const d = await get("/api/my/certifications-issued");
  const rows = d.certifications || [];
  $("cf-issued").innerHTML = rows.length
    ? `<table><thead><tr><th>Student</th><th>Certificate</th><th>Grade</th><th>Issued</th></tr></thead>
       <tbody>${rows.map(c => `<tr><td>${esc(c.student)}</td><td>${esc(c.title)}</td>
         <td>${esc(c.grade)}</td><td>${esc(c.issued_date)}</td></tr>`).join("")}</tbody></table>`
    : `<p class="muted">You haven't issued any certificates yet.</p>`;
}
async function issueCert() {
  const cid = Number($("cf-course").value);
  const course = ROSTER.find(c => c.course_id === cid);
  const type = $("cf-type").value;
  const sid = Number($("cf-student").value);
  if (!sid) { $("cf-msg").style.color = "var(--bad)"; $("cf-msg").textContent = "Select a student."; return; }
  const { status, data } = await api("POST", "/api/certifications", {
    cert_type: type, course_id: cid, student_id: sid,
    // title/issued_date are also sent so the vuln build (which trusts the client,
    // vuln #6b/#8) still works unchanged; the secure build rebuilds them server-side.
    title: course ? `${type}: ${course.name}` : type,
    issued_date: new Date().toISOString().slice(0, 10),
  });
  $("cf-msg").style.color = status === 201 ? "var(--good)" : "var(--bad)";
  $("cf-msg").textContent = status === 201 ? "Issued and signed." : (data.error || "Failed");
  if (status === 201) renderIssuedCerts();
}

// ---- integrity (admin: tamper monitor + on-chain audit log, secure build) ----
VIEWS.integrity = async function () {
  $("content").innerHTML = `
    <div class="page-title">Integrity &amp; ledger</div>
    <p class="page-sub">Live tamper alerts for every grade, and the on-chain audit log.</p>
    <div id="integrity-box" class="mt muted">Checking integrity ledger…</div>
    <div id="ledger-box" class="mt"></div>`;
  renderIntegrityAlerts();
  renderLedger();
};

// Admin tamper monitor: shows grades whose DB value no longer matches the ledger,
// with a one-click restore to the issuer-anchored value.
async function renderIntegrityAlerts() {
  const box = $("integrity-box");
  if (!box) return;
  const { status, data } = await api("GET", "/api/admin/integrity");
  if (status !== 200 || !data.available) {
    box.className = "card alert-card warn mt";
    box.innerHTML = `<h3>&#9888; Integrity monitor</h3>
      <p class="muted">Ledger unavailable — ${esc((data && data.error) || "cannot reach the node")}.</p>`;
    return;
  }
  const alerts = data.alerts || [];
  if (!alerts.length) {
    box.className = "card alert-card ok mt";
    box.innerHTML = `<h3>&#9939; Integrity monitor</h3>
      <p class="ok-text">&#10004; All grades match the integrity ledger. No tampering detected.</p>`;
    return;
  }
  box.className = "card alert-card bad mt";
  const rows = alerts.map(a => `
    <tr>
      <td>${esc(a.student)}</td><td>${esc(a.course)}</td>
      <td><span class="pill b strike">${esc(a.db_grade)}</span></td>
      <td>${a.true_grade != null ? `<span class="pill g">${esc(a.true_grade)}</span>`
                                  : `<span class="pill o">unknown</span>`}</td>
      <td>${a.true_grade != null
            ? `<button class="btn-ghost sm" onclick="fixGrade(${a.course_id}, ${a.student_id})">Restore</button>`
            : `<span class="muted">manual</span>`}</td>
    </tr>`).join("");
  box.innerHTML = `
    <div class="alert-head">
      <h3>&#9888; Tampering detected — ${alerts.length} grade${alerts.length > 1 ? "s" : ""}</h3>
      <button class="btn-primary sm" onclick="fixGrade()">Restore all from ledger</button>
    </div>
    <p class="muted">A grade below was changed directly in the database and no longer matches the value
      the issuer anchored on-chain. Restoring rewrites the database back to the verified value.</p>
    <table><thead><tr><th>Student</th><th>Course</th><th>In database</th><th>Verified (ledger)</th><th></th></tr></thead>
      <tbody>${rows}</tbody></table>`;
}

async function fixGrade(course_id, student_id) {
  const body = (course_id === undefined) ? {} : { course_id, student_id };
  const { status, data } = await api("POST", "/api/admin/integrity/fix", body);
  if (status !== 200) { alert((data && data.error) || "Restore failed"); return; }
  await renderIntegrityAlerts();   // alerts clear once the DB matches the ledger again
  checkIntegrityBadge();           // refresh the sidebar badge
}

// ---- profile (editable + change password) ----
VIEWS.profile = async function () {
  const u = USER;
  $("content").innerHTML = `
    <div class="page-title">Profile</div><p class="page-sub">Your account details</p>
    <div class="card" style="max-width:560px">
      <div style="display:flex;align-items:center;gap:16px;margin-bottom:14px">
        <div class="avatar" style="width:56px;height:56px;font-size:1.2rem">${initials(u.full_name)}</div>
        <div><div style="font-size:1.2rem;font-weight:700">${esc(u.full_name)}</div>
        <div class="muted">${esc(u.username)} · <span class="badge-role">${esc(u.role)}</span></div></div>
      </div>
      <label>Full name</label><input id="pf-name" value="${esc(u.full_name || "")}" />
      <label>Email</label><input id="pf-email" value="${esc(u.email || "")}" />
      <label>Phone</label><input id="pf-phone" value="${esc(u.phone || "")}" />
      <label>Address</label><input id="pf-address" value="${esc(u.address || "")}" />
      <div id="pf-msg" class="form-error"></div>
      <button class="btn-primary btn-block" onclick="saveProfile()">Save changes</button>
    </div>
    <div class="card mt" style="max-width:560px">
      <h3>Change password</h3>
      <label>Current password</label><input id="pf-old" type="password" />
      <label>New password</label><input id="pf-new" type="password" />
      <div id="pf-pwmsg" class="form-error"></div>
      <button class="btn-ghost btn-block" onclick="changePassword()">Update password</button>
    </div>`;
};
async function saveProfile() {
  const { status, data } = await api("POST", "/api/profile", {
    full_name: $("pf-name").value, email: $("pf-email").value,
    phone: $("pf-phone").value, address: $("pf-address").value,
  });
  const m = $("pf-msg");
  m.style.color = status === 200 ? "var(--good)" : "var(--bad)";
  if (status === 200) {
    USER = data.user;
    $("tb-name").textContent = USER.full_name;
    $("avatar").textContent = initials(USER.full_name);
    m.textContent = "Saved.";
  } else m.textContent = data.error || "Failed";
}
async function changePassword() {
  const { status, data } = await api("POST", "/api/change-password", {
    old_password: $("pf-old").value, new_password: $("pf-new").value,
  });
  const m = $("pf-pwmsg");
  m.style.color = status === 200 ? "var(--good)" : "var(--bad)";
  m.textContent = status === 200 ? "Password updated." : (data.error || "Failed");
  if (status === 200) { $("pf-old").value = ""; $("pf-new").value = ""; }
}

// ---------------- boot ----------------
applyBranding();
if (token()) enterApp(); else showLogin();
