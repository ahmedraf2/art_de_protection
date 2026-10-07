// Campus Portal — front-end SPA.
// The auth token is kept in localStorage and sent as a Bearer header, like a
// typical single-page app. Views are rendered from the URL hash, so the chat
// conversation URL (…#chat?chat_users[0]=..&chat_users[1]=..) is visible and
// editable in the address bar.

let USER = null;

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
  let data; try { data = await res.json(); } catch { data = {}; }
  return { status: res.status, data };
}
const get = async (p) => (await api("GET", p)).data;

// ---------------- auth screens ----------------
function showLogin() { $("register-screen").classList.add("hidden"); $("login-screen").classList.remove("hidden"); }
function showRegister() { $("login-screen").classList.add("hidden"); $("register-screen").classList.remove("hidden"); }

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
    // account type is fixed to student in the UI
  });
  if (status === 201) { alert("Account created. You can sign in now."); showLogin(); }
  else $("rg-error").textContent = data.error || "Registration failed";
}

function doLogout() { clearToken(); USER = null; location.hash = ""; location.reload(); }

// ---------------- app shell ----------------
const NAV = [
  { view: "dashboard", label: "Dashboard", icon: "🏠", roles: ["student", "professor", "admin"] },
  { view: "chat", label: "Chat", icon: "💬", roles: ["student", "professor", "admin"] },
  { view: "courses", label: "Courses", icon: "📚", roles: ["student", "professor", "admin"] },
  { view: "certifications", label: "Certifications", icon: "🎖️", roles: ["student", "professor", "admin"] },
  { view: "blockchain", label: "Blockchain", icon: "⛓️", roles: ["student", "professor", "admin"] },
  { view: "gradebook", label: "Gradebook", icon: "📝", roles: ["professor", "admin"] },
  { view: "admin", label: "Admin", icon: "⚙️", roles: ["admin"] },
];

async function enterApp() {
  const { status, data } = await api("GET", "/api/me");
  if (status !== 200) { showLogin(); return; }
  USER = data.user;
  $("login-screen").classList.add("hidden");
  $("register-screen").classList.add("hidden");
  $("app").classList.remove("hidden");
  $("tb-name").textContent = USER.full_name;
  $("avatar").textContent = initials(USER.full_name);

  $("sidebar").innerHTML = NAV.filter(n => n.roles.includes(USER.role))
    .map(n => `<button data-view="${n.view}" onclick="nav('${n.view}')"><span>${n.icon}</span> ${n.label}</button>`).join("");

  if (!location.hash) location.hash = "dashboard";
  route();
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
    const [g, courses, rm, certs] = await Promise.all([
      get("/api/my/grades"), get("/api/courses"), get("/api/messages/recent"), get("/api/certifications"),
    ]);
    const grades = g.grades || [];
    const avg = grades.length
      ? (grades.reduce((s, x) => s + parseFloat(x.grade || 0), 0) / grades.length).toFixed(2) : "—";
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
          <h3>My grades</h3>
          <table><thead><tr><th>Subject</th><th>Grade</th></tr></thead><tbody>
          ${grades.map(x => `<tr><td>${esc(x.name)}</td><td>${gradePill(x.grade)}</td></tr>`).join("")
            || `<tr><td colspan="2" class="muted">No grades yet.</td></tr>`}
          </tbody></table>
        </div>
        <div class="card">
          <h3>Recent messages</h3>
          ${recentList(rm.messages || [])}
          <button class="btn-ghost mt" onclick="nav('chat')">View all messages</button>
        </div>
      </div>
      <div class="card mt"><h3>Available courses</h3>
        <div class="grid-3 mt">${(courses.courses || []).map(courseCard).join("")}</div>
      </div>`;
  } else {
    const [mc, rm] = await Promise.all([get("/api/my/courses"), get("/api/messages/recent")]);
    c.innerHTML = `
      <div class="page-title">Welcome back, ${esc(first)} 👋</div>
      <p class="page-sub">${USER.role === "admin" ? "Administrator dashboard." : "Professor dashboard."}</p>
      <div class="grid-2">
        <div class="card"><h3>${USER.role === "admin" ? "All courses" : "My courses"}</h3>
          <div class="grid-2 mt">${(mc.courses || []).map(x =>
            `<div class="course"><div class="code">${esc(x.code)}</div><div class="name">${esc(x.name)}</div><div class="muted">id: ${x.id}</div></div>`).join("")}</div>
        </div>
        <div class="card"><h3>Recent messages</h3>${recentList(rm.messages || [])}
          <button class="btn-ghost mt" onclick="nav('chat')">View all messages</button></div>
      </div>`;
  }
};

function stat(ic, n, l) { return `<div class="stat"><span class="ic">${ic}</span><div class="n">${esc(n)}</div><div class="l">${esc(l)}</div></div>`; }
function gradePill(v) {
  const n = parseFloat(v); const cls = n >= 14 ? "g" : n >= 10 ? "o" : "b";
  return `<span class="pill ${cls}">${esc(v)} / 20</span>`;
}
function courseCard(x) {
  return `<div class="course"><div class="code">${esc(x.code)}</div><div class="name">${esc(x.name)}</div>
          <div class="muted">${esc(x.professor || "—")}</div></div>`;
}
function recentList(msgs) {
  if (!msgs.length) return `<p class="muted">No messages.</p>`;
  return msgs.map(m => `<div class="rmsg"><div class="dot"></div><div>
    <div class="who">${m.outgoing ? "To " : ""}${esc(m.with)}</div>
    <div class="snip">${esc(m.body)}</div></div></div>`).join("");
}

// ---- courses ----
VIEWS.courses = async function () {
  const d = await get("/api/courses");
  $("content").innerHTML = `
    <div class="page-title">Courses</div><p class="page-sub">Course catalogue</p>
    <div class="grid-3">${(d.courses || []).map(courseCard).join("")}</div>`;
};

// ---- certifications ----
VIEWS.certifications = async function (params) {
  const sid = params.get("student_id");
  const d = await get("/api/certifications" + (sid ? "?student_id=" + encodeURIComponent(sid) : ""));
  const ledgerCell = (c) => {
    if (c.on_chain === undefined) return `<span class="muted">—</span>`;
    return c.on_chain ? `<span class="pill g">&#9939; on&#8209;chain</span>`
                      : `<span class="pill b">&#9888; not on chain</span>`;
  };
  const rows = (d.certifications || []).map(c => `
    <tr><td>${esc(c.full_name || "")}</td><td>${esc(c.title)}</td><td>${esc(c.grade)}</td>
    <td>${esc(c.issued_date)}</td>
    <td>${c.verified ? `<span class="pill g">&#10004; valid</span>` : `<span class="pill b">&#10008; invalid</span>`}</td>
    <td>${ledgerCell(c)}</td></tr>`).join("");
  $("content").innerHTML = `
    <div class="page-title">Certifications</div>
    <p class="page-sub">Your issued certifications, verified against the campus signing key and integrity ledger.</p>
    <div class="card"><table><thead><tr><th>Student</th><th>Title</th><th>Grade</th><th>Issued</th><th>Signature</th><th>Ledger</th></tr></thead>
    <tbody>${rows || `<tr><td colspan="6" class="muted">No certifications.</td></tr>`}</tbody></table></div>`;
};

// ---- blockchain / integrity ledger ----
function shortHash(h) { return h ? h.slice(0, 10) + "…" + h.slice(-6) : ""; }

VIEWS.blockchain = async function () {
  const [chain, integ] = await Promise.all([get("/api/blockchain"), get("/api/grades/integrity")]);
  const banner = chain.valid
    ? `<div class="chain-banner ok">&#9939; Ledger intact — ${chain.height} blocks verified (SHA-256 links + proof-of-work).</div>`
    : `<div class="chain-banner bad">&#9888; Ledger BROKEN — ${(chain.problems || []).map(p => `block ${p.idx}: ${esc(p.error)}`).join("; ")}</div>`;

  let integrityCard;
  if (integ.enforced) {
    const rows = (integ.rows || []).map(r => `
      <tr><td>${esc(r.name)}</td><td>${gradePill(r.db_grade)}</td>
      <td>${r.ledger_grade == null ? `<span class="muted">—</span>` : gradePill(r.ledger_grade)}</td>
      <td>${r.ok ? `<span class="pill g">&#10004; matches</span>` : `<span class="pill b">&#10008; TAMPERED</span>`}</td></tr>`).join("");
    integrityCard = `<div class="card mt"><h3>Grade integrity check</h3>
      <p class="muted">Every grade in the database is compared against the value anchored on the ledger.</p>
      <table><thead><tr><th>Subject</th><th>Database</th><th>Ledger</th><th>Status</th></tr></thead>
      <tbody>${rows || `<tr><td colspan="4" class="muted">No grades to check.</td></tr>`}</tbody></table></div>`;
  } else {
    integrityCard = `<div class="card mt"><h3>Grade integrity check</h3>
      <p class="pill b">&#9888; Disabled in this build — the application never cross-checks grades against the ledger, so a tampered grade is accepted.</p></div>`;
  }

  const blocks = (chain.blocks || []).map(b => `
    <div class="block ${esc(b.type || "")}">
      <div class="block-top"><span class="block-idx">#${b.idx}</span>
        <span class="block-type">${esc(b.type || "record")}</span>
        <span class="muted">${esc(fmtDate(b.timestamp))}</span></div>
      <div class="block-sum">${esc(b.summary)}</div>
      <div class="hashline"><span class="k">prev</span><code>${shortHash(b.prev_hash)}</code></div>
      <div class="hashline"><span class="k">hash</span><code>${shortHash(b.hash)}</code><span class="muted">nonce ${b.nonce}</span></div>
    </div>`).join("");

  $("content").innerHTML = `
    <div class="page-title">Integrity ledger</div>
    <p class="page-sub">A tamper-evident blockchain anchoring grades and certifications. Build: <b>${esc(chain.mode)}</b>.</p>
    ${banner}
    ${integrityCard}
    <div class="card mt"><h3>Ledger blocks (${chain.height})</h3>
      <div class="chain">${blocks || `<p class="muted">Empty ledger.</p>`}</div></div>`;
};

// ---- chat ----
VIEWS.chat = async function (params) {
  const u0 = params.get("chat_users[0]"), u1 = params.get("chat_users[1]");
  if (u0 && u1) return renderConversation(u0, u1);
  const d = await get("/api/chats");
  const items = (d.chats || []).map(ch => `
    <div class="chat-item" onclick="openChat(${d.me}, ${ch.user_id})">
      <div class="ci-avatar">${initials(ch.name)}</div>
      <div style="flex:1;min-width:0">
        <div class="ci-name">${esc(ch.name)} <span class="badge-role">${esc(ch.role)}</span></div>
        <div class="ci-last">${esc(ch.last)}</div>
      </div>
    </div>`).join("");
  $("content").innerHTML = `
    <div class="page-title">Chat</div><p class="page-sub">Your conversations</p>
    <div class="chat-list">${items || `<p class="muted">No conversations yet.</p>`}</div>`;
};

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
  const bubbles = (data.messages || []).map(m => {
    const mine = m.sender_id === data.me;
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

// ---- gradebook ----
VIEWS.gradebook = async function () {
  const mc = await get("/api/my/courses");
  $("content").innerHTML = `
    <div class="page-title">Gradebook</div><p class="page-sub">Enter or update a student's grade</p>
    <div class="card" style="max-width:520px">
      <label>Course ID</label><input id="gb-course" placeholder="course id" />
      <label>Student ID</label><input id="gb-student" placeholder="student id" />
      <label>Grade (/20)</label><input id="gb-grade" placeholder="e.g. 15.5" />
      <div id="gb-msg" class="form-error"></div>
      <button class="btn-primary btn-block" onclick="saveGrade()">Save grade</button>
    </div>
    <div class="card mt"><h3>${USER.role === "admin" ? "All courses" : "My courses"}</h3>
      <table><thead><tr><th>ID</th><th>Code</th><th>Name</th></tr></thead><tbody>
      ${(mc.courses || []).map(x => `<tr><td>${x.id}</td><td>${esc(x.code)}</td><td>${esc(x.name)}</td></tr>`).join("")}
      </tbody></table></div>`;
};
async function saveGrade() {
  const { status, data } = await api("POST", "/api/grades", {
    course_id: Number($("gb-course").value), student_id: Number($("gb-student").value), grade: $("gb-grade").value,
  });
  $("gb-msg").style.color = status === 200 ? "var(--good)" : "var(--bad)";
  $("gb-msg").textContent = status === 200 ? "Saved." : (data.error || "Failed");
};

// ---- admin ----
VIEWS.admin = async function () {
  $("content").innerHTML = `
    <div class="page-title">Administration</div><p class="page-sub">Manage users and issue certifications</p>
    <div class="card"><h3>All users</h3><div id="admin-users" class="mt muted">Loading…</div></div>
    <div class="card mt" style="max-width:640px"><h3>Issue certification</h3>
      <div class="grid-2">
        <div><label>Student ID</label><input id="ic-sid" /></div>
        <div><label>Title</label><input id="ic-title" /></div>
        <div><label>Grade</label><input id="ic-grade" /></div>
        <div><label>Issued date</label><input id="ic-date" placeholder="2026-09-30" /></div>
      </div>
      <div id="ic-msg" class="form-error"></div>
      <button class="btn-primary mt" onclick="issueCert()">Issue &amp; sign</button>
    </div>`;
  const d = await get("/api/admin/users");
  const box = $("admin-users");
  if (!d.users) { box.innerHTML = `<span class="pill b">${esc(d.error || "error")}</span>`; return; }
  const cols = Object.keys(d.users[0]);
  box.innerHTML = `<table><thead><tr>${cols.map(c => `<th>${esc(c)}</th>`).join("")}</tr></thead>
    <tbody>${d.users.map(u => `<tr>${cols.map(c => `<td>${esc(u[c])}</td>`).join("")}</tr>`).join("")}</tbody></table>`;
};
async function issueCert() {
  const { status, data } = await api("POST", "/api/certifications", {
    student_id: Number($("ic-sid").value), title: $("ic-title").value,
    grade: $("ic-grade").value, issued_date: $("ic-date").value,
  });
  $("ic-msg").style.color = status === 201 ? "var(--good)" : "var(--bad)";
  $("ic-msg").textContent = status === 201 ? "Issued." : (data.error || "Failed");
}

// ---- profile ----
VIEWS.profile = async function () {
  const u = USER;
  $("content").innerHTML = `
    <div class="page-title">Profile</div><p class="page-sub">Your account details</p>
    <div class="card" style="max-width:520px">
      <div style="display:flex;align-items:center;gap:16px;margin-bottom:10px">
        <div class="avatar" style="width:56px;height:56px;font-size:1.2rem">${initials(u.full_name)}</div>
        <div><div style="font-size:1.2rem;font-weight:700">${esc(u.full_name)}</div>
        <div class="muted">${esc(u.username)}</div></div>
      </div>
      <div class="profile-row"><span class="k">User ID</span><span>${u.id}</span></div>
      <div class="profile-row"><span class="k">Email</span><span>${esc(u.email || "—")}</span></div>
      <div class="profile-row"><span class="k">Role</span><span class="badge-role">${esc(u.role)}</span></div>
    </div>`;
};

// ---------------- boot ----------------
if (token()) enterApp(); else showLogin();
