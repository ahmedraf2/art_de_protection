// Minimal vanilla-JS client for the lab. The real testing surface is the JSON
// API (use curl / Burp Suite); this UI just makes it clickable.

let MODE = "vuln";
const out = document.getElementById("out");
const tokenBox = document.getElementById("token");

// Restore any saved token across reloads.
tokenBox.value = localStorage.getItem("token") || "";

function show(x) {
  out.textContent = typeof x === "string" ? x : JSON.stringify(x, null, 2);
}

function authHeaders() {
  const t = tokenBox.value.trim();
  return t ? { Authorization: "Bearer " + t } : {};
}

async function api(method, path, body) {
  const opts = { method, headers: { ...authHeaders() }, credentials: "same-origin" };
  if (body !== undefined) {
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(body);
  }
  const res = await fetch(path, opts);
  let data;
  try { data = await res.json(); } catch { data = await res.text(); }
  show({ status: res.status, data });
  return { res, data };
}

async function register() {
  const role = document.getElementById("reg-role").value.trim();
  const payload = {
    username: document.getElementById("reg-username").value,
    password: document.getElementById("reg-password").value,
    email: document.getElementById("reg-email").value || undefined,
    full_name: document.getElementById("reg-fullname").value || undefined,
  };
  if (role) payload.role = role; // <- privilege-escalation probe
  await api("POST", "/api/register", payload);
}

async function login() {
  const { data } = await api("POST", "/api/login", {
    username: document.getElementById("login-username").value,
    password: document.getElementById("login-password").value,
    remember: document.getElementById("login-remember").checked,
  });
  if (data && data.token) {
    tokenBox.value = data.token;
    localStorage.setItem("token", data.token);
  }
}

async function logout() {
  await api("POST", "/api/logout");
  tokenBox.value = "";
  localStorage.removeItem("token");
}

const me = () => api("GET", "/api/me");
const adminUsers = () => api("GET", "/api/admin/users");
const getUser = () =>
  api("GET", "/api/users/" + encodeURIComponent(document.getElementById("lookup-id").value));
const search = () =>
  api("GET", "/api/search?q=" + encodeURIComponent(document.getElementById("search-q").value));

async function createNote() {
  await api("POST", "/api/notes", {
    title: document.getElementById("note-title").value,
    body: document.getElementById("note-body").value,
  });
  listNotes();
}

async function listNotes() {
  const { data } = await api("GET", "/api/notes");
  const box = document.getElementById("notes");
  box.innerHTML = "";
  (data.notes || []).forEach((n) => {
    const div = document.createElement("div");
    div.className = "note";
    const t = document.createElement("strong");
    t.textContent = (n.title || "") + ": ";
    div.appendChild(t);
    const bodySpan = document.createElement("span");
    if (MODE === "vuln") {
      // VULN (Stored XSS): note body rendered as HTML without encoding.
      bodySpan.innerHTML = n.body || "";
    } else {
      // SECURE: render as text so markup can never execute.
      bodySpan.textContent = n.body || "";
    }
    div.appendChild(bodySpan);
    box.appendChild(div);
  });
}

// Learn the server mode so the XSS demo mirrors the backend, and label the UI.
fetch("/api/config")
  .then((r) => r.json())
  .then((c) => {
    MODE = c.mode;
    const badge = document.getElementById("mode-badge");
    badge.textContent = "mode: " + MODE;
    badge.classList.add(MODE === "vuln" ? "bad" : "good");
  })
  .catch(() => {});
