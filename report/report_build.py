#!/usr/bin/env python3
"""Generate the Meridian Campus Portal security assessment report as self-contained HTML."""
import base64, os, html

PROJ = os.path.dirname(os.path.abspath(__file__))   # the report/ folder
OUT  = os.path.join(PROJ, "Meridian_Portal_Security_Report.html")

def img(name):
    # REPORT_IMG_MODE=path -> reference images by relative path (small, editable HTML).
    # default -> base64-embed (self-contained HTML).
    if os.environ.get("REPORT_IMG_MODE") == "path":
        return name
    p = os.path.join(PROJ, name)
    with open(p, "rb") as f:
        b = base64.b64encode(f.read()).decode()
    return f"data:image/png;base64,{b}"

def figure(name, caption):
    return (f'<figure><img src="{img(name)}" alt="{html.escape(caption)}"/>'
            f'<figcaption>{caption}</figcaption></figure>')

# ---------------------------------------------------------------- CSS
CSS = r"""
:root{
  --ink:#1c1710; --paper:#ffffff; --cream:#faf6ee; --cream2:#f3ecdd;
  --rule:#e0d8c6; --rule2:#c3b89f; --muted:#766c5a;
  --accent:#8a2320;        /* oxblood */
  --fix:#285045;           /* pine */
  --crit:#7c1d1a; --high:#a2521c; --med:#8a6c10; --low:#2b5676; --info:#5a5346;
  --serif:"Bitstream Charter","Charter",Georgia,"Times New Roman",serif;
  --sans:"DejaVu Sans Condensed","DejaVu Sans","Liberation Sans",Arial,sans-serif;
  --mono:"DejaVu Sans Mono","Liberation Mono",monospace;
}
@page{
  size:A4; margin:21mm 18mm 18mm 18mm;
  @top-right{ content:"Business Confidential"; font-family:var(--sans);
    font-size:7pt; letter-spacing:.14em; text-transform:uppercase; color:#a99e88; }
  @bottom-left{ content:"Meridian Campus Portal \2014 Security Assessment";
    font-family:var(--sans); font-size:7pt; letter-spacing:.1em;
    text-transform:uppercase; color:#a99e88; }
  @bottom-right{ content:counter(page); font-family:var(--sans); font-size:8.5pt;
    color:#8a7f69; }
}
@page:first{ margin:0;
  @top-right{content:none} @bottom-left{content:none} @bottom-right{content:none} }
*{ box-sizing:border-box; }
html{ -weasy-hyphens:none; }
body{ font-family:var(--serif); color:var(--ink); font-size:10.4pt;
      line-height:1.56; margin:0; }
p{ margin:7px 0; text-align:justify; }
a{ color:var(--accent); text-decoration:none; }
.rc-link{ color:var(--accent); border-bottom:1px solid #dcb9b7; }
strong,b{ font-weight:700; }

/* ---- headings ---- */
h2{ font-family:var(--serif); font-size:19pt; font-weight:700; color:var(--ink);
    margin:0 0 13px; padding-top:4px; line-height:1.15; page-break-after:avoid;
    -weasy-hyphens:none; }
h2::before{ content:""; display:block; width:48px; height:3px;
            background:var(--accent); margin-bottom:11px; }
h3{ font-family:var(--sans); font-size:11pt; font-weight:700; letter-spacing:.05em;
    text-transform:uppercase; color:#2c251b; margin:21px 0 7px; padding-bottom:4px;
    border-bottom:1px solid var(--rule); page-break-after:avoid; }
h4{ font-family:var(--sans); font-size:9pt; font-weight:700; letter-spacing:.1em;
    text-transform:uppercase; color:var(--accent); margin:15px 0 5px;
    page-break-after:avoid; }

/* ---- code ---- */
code{ font-family:var(--mono); font-size:8.9pt; background:var(--cream2);
      padding:1px 4px; color:#5f2b28; border-radius:0; }
pre{ font-family:var(--mono); font-size:8.7pt; line-height:1.5; background:var(--cream2);
     border:1px solid var(--rule); border-left:3px solid #2c251b; color:#2a2317;
     padding:10px 13px; margin:9px 0; white-space:pre-wrap; word-break:break-word; }
pre.cmd{ background:#10140f; border:1px solid #10140f; border-left:3px solid var(--fix);
         color:#d9e4d2; }
pre .c{ color:#9a7638; font-style:italic; }
pre.cmd .c{ color:#8aa07e; }

/* ---- tables ---- */
table{ border-collapse:collapse; width:100%; margin:11px 0; font-size:9.4pt;
       font-family:var(--serif); }
th{ font-family:var(--sans); font-size:8pt; font-weight:700; letter-spacing:.07em;
    text-transform:uppercase; color:var(--muted); text-align:left;
    border-bottom:1.5px solid var(--ink); padding:5px 10px 5px 0; vertical-align:bottom; }
td{ padding:7px 10px 7px 0; border-bottom:1px solid var(--rule); vertical-align:top; }
.ftable th{ width:25%; border-bottom:1px solid var(--rule); color:var(--muted);
    font-size:7.8pt; vertical-align:top; padding-right:14px; }
.ftable td{ border-bottom:1px solid var(--rule); }

/* ---- severity tags (outlined, sharp) ---- */
.badge{ display:inline-block; font-family:var(--sans); font-size:7.4pt; font-weight:700;
    letter-spacing:.13em; text-transform:uppercase; padding:2px 7px 1px;
    border:1.3px solid currentColor; line-height:1.3; }
.b-crit{color:var(--crit)} .b-high{color:var(--high)} .b-med{color:var(--med)}
.b-low{color:var(--low)} .b-info{color:var(--info)}

/* ---- callouts: vertical rule + kicker, faint warm tint ---- */
.callout{ margin:12px 0; padding:9px 14px; border-left:3px solid var(--rule2);
          font-size:9.7pt; }
.callout .lbl{ display:block; font-family:var(--sans); font-size:7.6pt; font-weight:700;
    letter-spacing:.1em; text-transform:uppercase; margin-bottom:4px; }
.callout.vuln{ background:#fbf2f0; border-left-color:var(--accent); }
.callout.vuln .lbl{ color:var(--accent); }
.callout.secure{ background:#eef4f0; border-left-color:var(--fix); }
.callout.secure .lbl{ color:var(--fix); }
.callout.info{ background:var(--cream); border-left-color:var(--rule2); }
.callout.info .lbl{ color:var(--muted); }

/* ---- figures ---- */
figure{ margin:13px 0; page-break-inside:avoid; text-align:center; }
figure img{ max-width:100%; border:1px solid var(--rule2); }
figcaption{ font-family:var(--sans); font-size:8pt; color:var(--muted); line-height:1.4;
    margin-top:6px; padding:0 4px; text-align:left; }

/* ---- lists ---- */
ul.tight,ol.tight{ margin:6px 0; padding-left:18px; }
ul.tight li,ol.tight li{ margin:3px 0; }
.lead{ font-size:11pt; line-height:1.55; color:#393124; }

/* ---- section / finding page breaks ---- */
.section{ page-break-before:always; }
.finding{ page-break-before:always; }
.finding h2{ border-bottom:1.5px solid var(--ink); padding-bottom:8px; }
.finding h2 .badge{ float:right; margin-top:5px; font-size:8pt; }

/* ---- report card stat row ---- */
.sev-counts{ display:flex; border-top:1.5px solid var(--ink);
    border-bottom:1.5px solid var(--ink); margin:16px 0; }
.sev-counts div{ flex:1; padding:13px 6px 10px; text-align:center;
    border-right:1px solid var(--rule); font-family:var(--sans); font-size:7.6pt;
    font-weight:700; letter-spacing:.11em; text-transform:uppercase; color:var(--muted); }
.sev-counts div:last-child{ border-right:none; }
.sev-counts .n{ display:block; font-family:var(--serif); font-size:27pt; font-weight:700;
    line-height:1; letter-spacing:0; margin-bottom:5px; color:var(--ink); }
.sev-counts .crit .n{color:var(--crit)} .sev-counts .high .n{color:var(--high)}
.sev-counts .med .n{color:var(--med)} .sev-counts .low .n{color:var(--low)}
.sev-counts .info .n{color:var(--info)}

/* ---- TOC ---- */
.toc{ padding-left:0; margin-top:6px; }
.toc li{ list-style:none; margin:2.5px 0; }
.toc .l1{ font-family:var(--sans); font-weight:700; font-size:9.6pt; letter-spacing:.02em;
    color:var(--ink); margin-top:9px; text-transform:uppercase; }
.toc .l2{ padding-left:18px; font-family:var(--serif); font-size:9.7pt; color:#473e2f; }

/* ---- architecture grid ---- */
.arch-grid{ display:flex; gap:11px; margin:13px 0; }
.arch-grid .box{ flex:1; background:var(--cream); border:1px solid var(--rule);
    border-top:2.5px solid var(--accent); padding:11px 13px; font-size:9.1pt; }
.arch-grid .box h4{ color:var(--ink); margin:0 0 5px; }

.kv{ font-size:9.3pt; }
.small{ font-family:var(--sans); font-size:8.3pt; color:var(--muted); }
.hl{ background:#f6e3c6; padding:0 2px; }

/* ================= COVER ================= */
.cover{ position:relative; height:297mm; padding:30mm 24mm 22mm 30mm;
    display:flex; flex-direction:column; color:var(--ink);
    background:var(--paper); page-break-after:always; overflow:hidden; }
.cover::before{ content:""; position:absolute; top:0; left:0; bottom:0; width:11mm;
    background:var(--accent); }
.cover::after{ content:""; position:absolute; top:0; left:11mm; bottom:0; width:2.3mm;
    background:var(--ink); }
.cover .cv-org{ font-family:var(--sans); font-size:9pt; letter-spacing:.04em;
    color:#3b3326; font-weight:700; text-transform:uppercase; }
.cover .cv-mod{ font-family:var(--sans); font-size:8.3pt; letter-spacing:.03em;
    color:var(--muted); margin-top:3px; }
.cover .cv-mid{ flex:1; display:flex; flex-direction:column; justify-content:center; }
.cover .cv-kick{ font-family:var(--sans); font-size:9.5pt; font-weight:700;
    letter-spacing:.32em; text-transform:uppercase; color:var(--accent);
    margin-bottom:14px; }
.cover h1{ font-family:var(--serif); font-size:47pt; font-weight:700; line-height:1.02;
    margin:0; color:var(--ink); letter-spacing:-.5px; }
.cover h1 .thin{ display:block; font-size:25pt; font-weight:400; font-style:italic;
    color:#4a4133; margin-top:8px; letter-spacing:0; }
.cover .cv-rule{ width:118px; height:3px; background:var(--ink); margin:26px 0; }
.cover .cv-sub{ font-family:var(--sans); font-size:11.5pt; font-weight:700;
    color:#2c251b; line-height:1.5; max-width:120mm; }
.cover .cv-tag{ display:inline-block; align-self:flex-start; margin-top:26px;
    font-family:var(--sans); font-size:8.3pt; font-weight:700; letter-spacing:.22em;
    text-transform:uppercase; color:var(--accent); border:1.4px solid var(--accent);
    padding:5px 13px; }
.cover .cv-meta{ margin-top:30px; border-top:1px solid var(--rule2); }
.cover .cv-meta .row{ display:flex; border-bottom:1px solid var(--rule);
    padding:6px 0; font-size:9.6pt; }
.cover .cv-meta .k{ width:52mm; font-family:var(--sans); font-size:8pt; font-weight:700;
    letter-spacing:.07em; text-transform:uppercase; color:var(--muted);
    padding-top:1px; }
.cover .cv-meta .v{ flex:1; font-family:var(--serif); color:var(--ink); }
.cover .cv-foot{ font-family:var(--sans); font-size:7.6pt; letter-spacing:.06em;
    text-transform:uppercase; color:#a99e88; border-top:1px solid var(--rule2);
    padding-top:9px; }
"""

def cmd(s):   return f'<pre class="cmd">{s}</pre>'
def code(s):  return f'<pre>{s}</pre>'
def vuln(t):  return f'<div class="callout vuln"><span class="lbl">Vulnerable build (meridian.tn:3000)</span>{t}</div>'
def secure(t):return f'<div class="callout secure"><span class="lbl">Secure build (meridian.tn:3001) — the fix</span>{t}</div>'
def info(t):  return f'<div class="callout info"><span class="lbl">Note</span>{t}</div>'

def ftable(owasp, like, imp, comp, tools, refs):
    return f"""<table class="ftable">
<tr><th>OWASP Top 10 (2021)</th><td>{owasp}</td></tr>
<tr><th>Risk — Likelihood</th><td>{like}</td></tr>
<tr><th>Risk — Impact</th><td>{imp}</td></tr>
<tr><th>Affected Component</th><td>{comp}</td></tr>
<tr><th>Tools Used</th><td>{tools}</td></tr>
<tr><th>References</th><td>{refs}</td></tr>
</table>"""

P = []  # page/section buffer
def add(s): P.append(s)

# =========================================================== COVER
add("""<div class="cover">
  <div class="cv-top">
    <div class="cv-org">TEK-UP &mdash; &Eacute;cole Sup&eacute;rieure Priv&eacute;e de Technologie &amp; d'Ing&eacute;nierie</div>
    <div class="cv-mod">Applied Cryptography &amp; Web Application Security &middot; Acad&eacute;mique 2025 / 2026</div>
  </div>
  <div class="cv-mid">
    <div class="cv-kick">Security Assessment Report</div>
    <h1>Meridian<br/>Campus Portal<span class="thin">Vulnerability findings &amp; secure-build remediation</span></h1>
    <div class="cv-rule"></div>
    <div class="cv-sub">A hands-on study of eleven vulnerabilities we built into our own
      application, and how a layered cryptographic &amp; blockchain architecture neutralises each one.</div>
    <span class="cv-tag">Business Confidential</span>
  </div>
  <div class="cv-meta">
    <div class="row"><div class="k">Vulnerable build</div><div class="v">http://meridian.tn:3000</div></div>
    <div class="row"><div class="k">Hardened build</div><div class="v">http://meridian.tn:3001</div></div>
    <div class="row"><div class="k">Application</div><div class="v">Meridian University &mdash; Student Portal &nbsp;(Flask &middot; SQLite &middot; Ed25519 &middot; Ethereum)</div></div>
    <div class="row"><div class="k">Prepared by</div><div class="v">Ahmed Rafraf &nbsp;&middot;&nbsp; Rached Yesser</div></div>
    <div class="row"><div class="k">Supervising professor</div><div class="v">Oussama Bakali</div></div>
    <div class="row"><div class="k">Date / Version</div><div class="v">11 October 2026 &nbsp;&middot;&nbsp; Version 1.0</div></div>
  </div>
  <div style="flex:0" ></div>
  <div class="cv-foot">Business Confidential &mdash; TEK-UP / Web Security Module 2025-2026</div>
</div>""")

# =========================================================== FRONT MATTER
add("""<div class="section">
<h2>Confidentiality Statement</h2>
<p>This document relates to the <b>Meridian University Student Portal</b>, an application we
designed and built ourselves as a course project to study common web-application security
flaws and their cryptographic and blockchain-based remediations. It is intended for the
authors and the supervising professor. Duplication or redistribution requires the authors'
consent.</p>

<h2 style="margin-top:22px">Disclaimer</h2>
<p>The Meridian Campus Portal is an application we built ourselves, deliberately including a
set of common web-application flaws together with their fixes. All testing described here was
carried out on our own local instances, with no impact on third parties. The application
ships as two builds from a single code base — a <b>vulnerable</b> build (every flaw tagged
<code># VULN:</code>) and a <b>secure</b> build (each matching fix tagged
<code># SECURE:</code>) — so each weakness can be exploited, then re-run against the hardened
version to confirm the control works.</p>

<h2 style="margin-top:22px">Authors &amp; Supervision</h2>
<table>
<tr><th>Name</th><th>Role</th><th>Contact</th></tr>
<tr><td>Ahmed Rafraf</td><td>Author</td><td>mohamedrafraf99@gmail.com</td></tr>
<tr><td>Rached Yesser</td><td>Author</td><td>TEK-UP</td></tr>
<tr><td>Oussama Bakali</td><td>Supervising Professor</td><td>TEK-UP — Web Security Module</td></tr>
</table>
</div>""")

# =========================================================== TOC
add("""<div class="section">
<h2>Table of Contents</h2>
<ul class="toc">
<li class="l1"><a href="#s1">1. Assessment Overview</a></li>
<li class="l1"><a href="#s2">2. Test Environment Setup — Local DNS Mapping for Burp Suite Interception</a></li>
<li class="l1"><a href="#s3">3. Finding Severity Ratings &amp; Risk Factors</a></li>
<li class="l1"><a href="#s4">4. Scope</a></li>
<li class="l1"><a href="#s5">5. Executive Summary</a></li>
<li class="l1"><a href="#s6">6. Vulnerability Summary &amp; Report Card</a></li>
<li class="l1"><a href="#s7">7. Security Architecture of the Hardened Build (Cryptography &amp; Blockchain)</a></li>
<li class="l1"><a href="#s8">8. Technical Findings</a></li>
<li class="l2"><a href="#f-001">WAPT-001 — SQL Injection: Authentication Bypass (Critical)</a></li>
<li class="l2"><a href="#f-002">WAPT-002 — SQL Injection: UNION-based Hash Exfiltration (Critical)</a></li>
<li class="l2"><a href="#f-003">WAPT-003 — Broken JWT: Admin Token Forgery (Critical)</a></li>
<li class="l2"><a href="#f-004">WAPT-004 — IDOR: Private Chats &amp; Student Documents (High)</a></li>
<li class="l2"><a href="#f-005">WAPT-005 — Mass Assignment: Privilege Escalation at Registration (High)</a></li>
<li class="l2"><a href="#f-006">WAPT-006 — Cryptographic Failure: Unsalted MD5 Password Storage (High)</a></li>
<li class="l2"><a href="#f-007">WAPT-007 — Cryptographic Failure: Unsigned / Un-anchored Certificates (High)</a></li>
<li class="l2"><a href="#f-008">WAPT-008 — Data Integrity Failure: Silent Grade Tampering (High)</a></li>
<li class="l2"><a href="#f-009">WAPT-009 — Mass Assignment: Privilege Escalation from Profile Update (High)</a></li>
<li class="l2"><a href="#f-010">WAPT-010 — Unrestricted File Upload &rarr; Stored XSS (High)</a></li>
<li class="l2"><a href="#f-011">WAPT-011 — Path Traversal: Local File Disclosure (Critical)</a></li>
<li class="l1"><a href="#appA">Appendix A — Methodology &amp; Tools</a></li>
<li class="l1"><a href="#appB">Appendix B — Cryptographic &amp; Blockchain Reference</a></li>
</ul>
</div>""")

# =========================================================== 1. OVERVIEW
add("""<div class="section">
<h2 id="s1">1. Assessment Overview</h2>
<p>This assessment evaluated the security posture of the Meridian University Student Portal,
a role-based campus application (students, professors, administrators) covering authenticated
login, grade and certification management, private messaging, administrative document
requests and an administrative user-management console. Testing followed an industry-standard
methodology aligned with the <b>OWASP Web Security Testing Guide (WSTG)</b> and the
<b>OWASP Top 10 (2021)</b>, supplemented by manual exploitation.</p>
<p>The engagement had a second objective beyond discovery: to verify that the project's
<b>secure build</b> genuinely neutralises each flaw. Particular attention was paid to the two
defence mechanisms that distinguish this application from a conventional web app — a
<b>digital-signature and encryption layer</b> (Ed25519, AES-256-GCM, PBKDF2) and a
<b>blockchain integrity ledger</b> (a Solidity smart contract on a local Ethereum node that
anchors grades and certificates). The testing activities followed four phases:</p>
<ul class="tight">
<li><b>Planning</b> — define objectives, scope and rules of engagement.</li>
<li><b>Discovery</b> — reconnaissance, fingerprinting and enumeration of the attack surface.</li>
<li><b>Attack</b> — confirm each vulnerability through controlled exploitation on the vuln build.</li>
<li><b>Verification &amp; Reporting</b> — repeat each exploit against the secure build, document
    evidence, impact and the exact control that defeats it.</li>
</ul>
</div>""")

# =========================================================== 2. DNS / HOSTS
add(f"""<div class="section">
<h2 id="s2">2. Test Environment Setup — Local DNS Mapping for Burp Suite Interception</h2>
<p>Before any request tampering could be performed, the lab environment had to be prepared so
that an intercepting proxy (Burp Suite) could reliably capture and modify traffic. By default,
both Firefox and Burp Suite <b>bypass the proxy for <code>localhost</code> and
<code>127.0.0.1</code></b> traffic (the "do not proxy local addresses" behaviour), which means
requests sent straight to <code>http://127.0.0.1:3000</code> never appear in Burp's HTTP
history and cannot be intercepted.</p>
<p>The standard workaround is to give the loopback instance a <b>real-looking domain name</b>
by adding a static entry to the local DNS resolver — the operating system's hosts file
(<code>/etc/hosts</code>). Mapping the fictitious domain <code>meridian.tn</code> to
<code>127.0.0.1</code> makes the browser treat it as a normal remote host (so the proxy is
used), while the traffic still terminates on the local lab instance.</p>
<pre class="cmd"><span class="c"># edit the local DNS / hosts file</span>
sudo nano /etc/hosts

<span class="c"># add this line (maps the lab domain to the loopback instance)</span>
127.0.0.1    meridian.tn</pre>
{figure("fig_hosts.png", "Figure 1 — The local hosts file (/etc/hosts) with the <code>127.0.0.1 meridian.tn</code> entry. This is why every request capture in this report shows <b>Host: meridian.tn</b> rather than localhost.")}
<p>The application is therefore reached at <code>http://meridian.tn:3000</code> (vulnerable) and
<code>http://meridian.tn:3001</code> (secure) — the same local instances as
<code>127.0.0.1:3000/3001</code>. With this mapping in place and Firefox pointed at Burp's
listener on <code>127.0.0.1:8080</code>, every request is visible in Proxy &rarr; HTTP history
and can be sent to Repeater or edited on the fly in Intercept.</p>
</div>""")

# =========================================================== 3. SEVERITY
add("""<div class="section">
<h2 id="s3">3. Finding Severity Ratings &amp; Risk Factors</h2>
<p>The following table defines the severity levels and corresponding CVSS v3.1 score ranges
used throughout this report.</p>
<table>
<tr><th>Severity</th><th>CVSS v3 Range</th><th>Definition</th></tr>
<tr><td><span class="badge b-crit">Critical</span></td><td>9.0 – 10.0</td>
<td>Exploitation is straightforward and usually results in full compromise. Patch immediately.</td></tr>
<tr><td><span class="badge b-high">High</span></td><td>7.0 – 8.9</td>
<td>Exploitation is more difficult but can cause elevated privileges, data loss or integrity loss. Patch as soon as possible.</td></tr>
<tr><td><span class="badge b-med">Moderate</span></td><td>4.0 – 6.9</td>
<td>Vulnerabilities exist but are harder to exploit or require extra steps. Patch after high-priority issues.</td></tr>
<tr><td><span class="badge b-low">Low</span></td><td>0.1 – 3.9</td>
<td>Non-exploitable issues that would reduce attack surface. Patch during the next window.</td></tr>
<tr><td><span class="badge b-info">Info</span></td><td>N/A</td>
<td>No vulnerability. Information noted during testing or a strong observed control.</td></tr>
</table>
<h3>Risk Factors</h3>
<p>Risk is measured by two factors: <b>Likelihood</b> and <b>Impact</b>.</p>
<p><b>Likelihood</b> measures the potential of a vulnerability being exploited, based on the
difficulty of the attack, available tooling, attacker skill and the environment.
<b>Impact</b> measures the effect on confidentiality, integrity and availability of the
application and its data, plus reputational and operational harm.</p>
</div>""")

# =========================================================== 4. SCOPE
add("""<div class="section">
<h2 id="s4">4. Scope</h2>
<p>The assessment was limited to the two locally hosted builds of the Meridian Campus Portal:</p>
<ul class="tight">
<li><b>Vulnerable build:</b> http://meridian.tn:3000 (<code>APP_MODE</code> default)</li>
<li><b>Secure build:</b> http://meridian.tn:3001 (<code>APP_MODE=secure</code>)</li>
<li><b>Stack:</b> Python/Flask backend, SQLite database, a static JavaScript single-page
front-end, the <code>cryptography</code> library (AES-256-GCM + Ed25519) and a Solidity
<code>GradeLedger</code> smart contract on a local <code>anvil</code> Ethereum node.</li>
<li><b>Environment:</b> Kali/Ubuntu Linux local lab, Firefox + Burp Suite Community.</li>
</ul>
<p>Six seeded accounts were used for testing, spanning all three roles
(admin, professor, student):</p>
<table class="kv">
<tr><th>Username</th><th>Password</th><th>Role</th><th>Notes</th></tr>
<tr><td>admin</td><td>admin123</td><td>admin</td><td>id 1</td></tr>
<tr><td>prof_smith</td><td>teach123</td><td>professor</td><td>teaches PROG, DB, ALGO (id 2)</td></tr>
<tr><td>prof_jones</td><td>teach456</td><td>professor</td><td>teaches MATH, PHYS, NET (id 3)</td></tr>
<tr><td>alice</td><td>password1</td><td>student</td><td>id 4, enrolled in everything</td></tr>
<tr><td>bob</td><td>hunter2</td><td>student</td><td>id 5</td></tr>
<tr><td>carol</td><td>qwerty</td><td>student</td><td>id 6</td></tr>
</table>
<h3>Scope Exclusions</h3>
<p>Denial-of-Service attacks and attacks against any system other than the two local lab
instances were out of scope. No real users or third-party systems were involved. As the
authors of the application, we cite the exact file and line locations for every finding.</p>
</div>""")

# =========================================================== 5. EXEC SUMMARY
add("""<div class="section">
<h2 id="s5">5. Executive Summary</h2>
<p>This report summarises eleven vulnerabilities confirmed in the vulnerable build of the
Meridian Campus Portal, spanning most of the OWASP Top 10 (2021) categories, and documents
exactly how the hardened build neutralises each one. Several findings allow complete compromise
of the application and its data.</p>
<h3>Testing Summary</h3>
<p>The most serious findings cluster around <b>injection</b> and <b>broken access control</b>.
A SQL injection in the login form grants immediate administrator access with no valid
credentials, and a second, UNION-based injection on the certifications endpoint dumps every
user's password hash. Because those hashes are stored as <b>unsalted MD5</b>, five of six
crack instantly in an online lookup. Authentication itself is undermined by a <b>broken JWT
implementation</b> that never verifies the token signature, letting an attacker self-promote to
<code>admin</code> by editing one claim. Broken access control recurs as two <b>IDOR</b> bugs
and two <b>mass-assignment</b> privilege escalations (at registration and via the profile form).
An <b>unrestricted file upload</b> enables stored XSS against the approving administrator, and a
<b>path-traversal</b> flaw on the document-download endpoint leaks arbitrary server files —
including the certificate signing key and the entire SQLite database.</p>
<p>Two findings are specifically about the integrity and authenticity controls that this
application was built to showcase. In the vuln build, certificates are stored <b>unsigned and
never anchored</b>, so a forged certificate injected via SQLi displays as "valid"; and grades
have <b>no integrity anchoring</b> at all, so a direct database edit silently changes a
student's record with nothing to flag it. The secure build answers both with a combination of
<b>Ed25519 digital signatures</b> and an <b>on-chain hash ledger</b> (the GradeLedger smart
contract): a record is trusted only if its signature verifies <i>and</i> its fingerprint is
found on the blockchain, and any post-hoc tampering is detected and reversible from the ledger.</p>
<h3>Key Weaknesses (vulnerable build)</h3>
<ol class="tight">
<li>User input is concatenated into SQL, enabling authentication bypass and data exfiltration.</li>
<li>JWTs are decoded but never cryptographically verified; <code>alg:none</code> is accepted.</li>
<li>Object- and function-level access control is missing (IDOR, mass assignment, privilege escalation).</li>
<li>Passwords are stored as unsalted MD5; admin responses leak the hashes.</li>
<li>Certificates are neither signed nor anchored, so forgeries are indistinguishable from genuine records.</li>
<li>Grades have no integrity reference, so database tampering is silent and undetectable.</li>
<li>File uploads are unrestricted (enabling stored XSS) and downloads are vulnerable to path traversal.</li>
</ol>
<p>Collectively, these demonstrate that an attacker requires little skill or tooling to fully
compromise the application, exfiltrate all user data, forge academic records and obtain
administrative control — and, conversely, that the secure build's layered cryptographic and
blockchain controls defeat each of these attacks.</p>
</div>""")

# =========================================================== 6. REPORT CARD
add("""<div class="section">
<h2 id="s6">6. Vulnerability Summary &amp; Report Card</h2>
<div class="sev-counts">
<div class="crit"><span class="n">3</span>Critical</div>
<div class="high"><span class="n">8</span>High</div>
<div class="med"><span class="n">0</span>Moderate</div>
<div class="low"><span class="n">0</span>Low</div>
<div class="info"><span class="n">0</span>Info</div>
</div>
<table>
<tr><th>#</th><th>Finding</th><th>Severity</th><th>Secure-build control</th></tr>
<tr><td>001</td><td><a class="rc-link" href="#f-001">SQL Injection — Authentication Bypass</a></td><td><span class="badge b-crit">Critical</span></td><td>Parameterized queries; verified password hash</td></tr>
<tr><td>002</td><td><a class="rc-link" href="#f-002">SQL Injection — UNION Hash Exfiltration</a></td><td><span class="badge b-crit">Critical</span></td><td>Parameterized queries; object-level authz; secrets never returned</td></tr>
<tr><td>003</td><td><a class="rc-link" href="#f-003">Broken JWT — Admin Token Forgery</a></td><td><span class="badge b-crit">Critical</span></td><td>HMAC-SHA256 signature verified; <code>alg</code> pinned; role re-checked in DB</td></tr>
<tr><td>004</td><td><a class="rc-link" href="#f-004">IDOR — Private Chats &amp; Documents</a></td><td><span class="badge b-high">High</span></td><td>Server-side ownership checks on every object</td></tr>
<tr><td>005</td><td><a class="rc-link" href="#f-005">Mass Assignment — Registration Escalation</a></td><td><span class="badge b-high">High</span></td><td>Role fixed to <code>student</code> server-side; body ignored</td></tr>
<tr><td>006</td><td><a class="rc-link" href="#f-006">Cryptographic Failure — Unsalted MD5</a></td><td><span class="badge b-high">High</span></td><td>PBKDF2-HMAC-SHA256, per-user salt, 200,000 iterations</td></tr>
<tr><td>007</td><td><a class="rc-link" href="#f-007">Cryptographic Failure — Forged Certificates</a></td><td><span class="badge b-high">High</span></td><td>Ed25519 signature + on-chain fingerprint anchoring</td></tr>
<tr><td>008</td><td><a class="rc-link" href="#f-008">Data Integrity — Silent Grade Tampering</a></td><td><span class="badge b-high">High</span></td><td>On-chain SHA-256 anchor; tamper monitor; ledger restore</td></tr>
<tr><td>009</td><td><a class="rc-link" href="#f-009">Mass Assignment — Profile Escalation</a></td><td><span class="badge b-high">High</span></td><td>Field allow-list; only UI fields written</td></tr>
<tr><td>010</td><td><a class="rc-link" href="#f-010">Unrestricted File Upload &rarr; Stored XSS</a></td><td><span class="badge b-high">High</span></td><td>PDF magic-byte check, 5&nbsp;MB cap, random server name</td></tr>
<tr><td>011</td><td><a class="rc-link" href="#f-011">Path Traversal — Local File Disclosure</a></td><td><span class="badge b-crit">Critical</span></td><td>Client path ignored; only the record's own file served</td></tr>
</table>
<p class="small">Severity reflects exploitability and impact on the vulnerable build; every finding is
fully remediated in the secure build, as verified in Section 8.</p>
</div>""")
# =========================================================== 7. ARCHITECTURE (crypto + blockchain deep dive)
add(f"""<div class="section">
<h2 id="s7">7. Security Architecture of the Hardened Build (Cryptography &amp; Blockchain)</h2>
<p class="lead">Three findings in this report (WAPT-006, 007 and 008) are defended not by a
one-line input check but by a layered <b>cryptographic + blockchain integrity architecture</b>.
Because that architecture is the centrepiece of the application, it is described here once and
referenced from each finding.</p>

<h3>7.1 The trust problem</h3>
<p>A student management system makes three security promises about academic records:
<b>confidentiality</b> (private messages and documents stay private), <b>authenticity</b>
(a certificate was really issued by the university) and <b>integrity</b> (a grade in the
database is the grade the professor actually recorded). A conventional application stores all
of this in a single SQLite database and trusts that database completely. That trust is the
flaw: anyone who reaches the database — through SQL injection (WAPT-002/007), path traversal
(WAPT-011) or direct shell access — can rewrite a grade or forge a certificate, and the
application has <b>no independent reference</b> to contradict the tampered row. The secure
build breaks this single point of trust by signing records with a key the database never holds,
and by anchoring an immutable fingerprint of each record on a blockchain the database cannot
reach.</p>

<div class="arch-grid">
  <div class="box"><h4>Confidentiality</h4>
    <b>AES-256-GCM</b> (authenticated encryption). Private message bodies are encrypted at rest
    with a 256-bit key kept in <code>keys/aes.key</code> (file mode <code>0600</code>, outside
    the DB). Each message uses a fresh 12-byte random nonce; the GCM authentication tag also
    detects any tampering of the ciphertext.</div>
  <div class="box"><h4>Authenticity</h4>
    <b>Ed25519</b> digital signatures. Each certificate is signed by the issuer's private key
    (<code>keys/issuer_ed25519.pem</code>). Anyone can verify with the public key, but only the
    university can produce a valid signature — so a certificate inserted by an attacker fails
    verification.</div>
  <div class="box"><h4>Integrity</h4>
    <b>GradeLedger smart contract</b> on an Ethereum node. The SHA-256 fingerprint of every
    legitimate grade and certificate is anchored on-chain by an issuer-only key. The DB and the
    chain are compared on every read; any divergence is tamper.</div>
</div>

<h3>7.2 Cryptographic primitives (crypto_utils.py / auth.py)</h3>
<table>
<tr><th>Control</th><th>Algorithm</th><th>Purpose &amp; why it is sound</th></tr>
<tr><td>Password storage</td><td>PBKDF2-HMAC-SHA256, 200,000 iterations, 16-byte per-user salt</td>
<td>A unique salt defeats rainbow tables and makes identical passwords hash differently; 200k
iterations slow each guess ~200,000&times; versus raw MD5, making wordlist attacks impractical.
Verification uses constant-time comparison (<code>hmac.compare_digest</code>).</td></tr>
<tr><td>Encryption at rest</td><td>AES-256-GCM</td>
<td>Authenticated encryption: provides both confidentiality <i>and</i> integrity of the
ciphertext. A random 96-bit nonce per message; the 128-bit GCM tag rejects any modified
ciphertext on decrypt.</td></tr>
<tr><td>Certificate signatures</td><td>Ed25519 (EdDSA over Curve25519)</td>
<td>A modern, fast, misuse-resistant elliptic-curve signature. The issuer's private key signs a
<b>canonical</b> JSON payload of the certificate; verification needs only the public key, so the
web/database tier can verify but never forge.</td></tr>
<tr><td>Token integrity</td><td>HMAC-SHA256 (JWT HS256)</td>
<td>The session JWT is signed with a server secret; the secure decoder pins <code>alg=HS256</code>,
verifies the MAC in constant time and checks <code>exp</code> before trusting any claim.</td></tr>
<tr><td>On-chain fingerprint</td><td>SHA-256</td>
<td>The 32-byte hash of a canonical grade/certificate payload is what gets stored on-chain —
never the plaintext grade or any personal data.</td></tr>
</table>
<p>The <b>canonical payload</b> is the detail that makes signatures and anchors meaningful. A
certificate is serialised with sorted keys and no whitespace before it is signed or hashed:</p>
{code('''<span class="c"># crypto_utils.py — the exact bytes that get signed AND hashed</span>
def cert_payload(student_id, title, grade, issued_date) -> bytes:
    return json.dumps(
        {"student_id": student_id, "title": title,
         "grade": grade, "issued_date": issued_date},
        sort_keys=True, separators=(",", ":"),
    ).encode()

def cert_fingerprint(...):   return sha256(cert_payload(...)).hexdigest()   # anchored on-chain
def sign_cert(...):          return ed25519_private.sign(cert_payload(...)) # stored in the DB''')}
<p>Because the signature and the on-chain fingerprint are both bound to this canonical payload,
changing <i>any</i> field — the grade, the title, the student — breaks the signature
<b>and</b> changes the fingerprint, so the record no longer matches the chain. The attacker
cannot re-sign (no private key) and cannot re-anchor (the contract rejects non-issuer writers).</p>

<h3>7.3 The blockchain integrity ledger (GradeLedger.sol)</h3>
<p>The ledger is a Solidity smart contract deployed to a local Ethereum development node
(<code>anvil</code>, chain id <code>31337</code>). It is deliberately minimal: it stores only
<b>hashes</b>, never names or grades, and it accepts writes from exactly one account — the
issuer. This is the independent reference the SQLite database is checked against.</p>
{code('''<span class="c">// contracts/src/GradeLedger.sol  (abridged)</span>
contract GradeLedger {
    address public immutable issuer;                 <span class="c">// fixed forever at deployment</span>
    mapping(uint =&gt; mapping(uint =&gt; bytes32)) private grades;      <span class="c">// course =&gt; student =&gt; hash</span>
    mapping(bytes32 =&gt; bool) private certificates;                 <span class="c">// fingerprint =&gt; anchored</span>

    modifier onlyIssuer() {                           <span class="c">// THE key control</span>
        if (msg.sender != issuer) revert NotIssuer();
        _;
    }
    function anchorGrade(uint c, uint s, bytes32 h) external onlyIssuer { grades[c][s] = h; ... }
    function anchorCertificate(bytes32 fp)          external onlyIssuer { certificates[fp] = true; ... }
    function getGrade(uint c, uint s) external view returns (bytes32) { return grades[c][s]; }
    function isCertificateAnchored(bytes32 fp) external view returns (bool) { ... }
}''')}
<p>Why the blockchain, and not just a second database table? Three properties the SQLite file
cannot provide on its own:</p>
<ul class="tight">
<li><b>Write authorisation by cryptographic key, not by application code.</b> The
<code>onlyIssuer</code> modifier is enforced by the Ethereum network itself. An attacker who
fully owns the web server and the SQLite file still cannot anchor a forged record, because they
do not hold the issuer's Ethereum private key (<code>keys/eth_issuer.key</code>, mode
<code>0600</code>). Contrast this with a second DB table, which that same attacker would simply
rewrite.</li>
<li><b>Append-only, tamper-evident history.</b> Every anchor is a transaction in an immutable,
hash-linked block; the admin "Anchored events" explorer lists each one with its block number
and transaction hash. There is no UPDATE or DELETE.</li>
<li><b>Separation of duties.</b> The anchoring key lives in the application layer only long
enough to sign a transaction; the record of truth lives on a separate system with a different
trust model. Compromising one does not compromise the other.</li>
</ul>
<p>The application talks to the contract through <code>eth_ledger.py</code>, which refuses any
non-loopback RPC endpoint and any chain id other than 31337, funds a freshly generated issuer
key from the dev faucet, and exposes four operations: <code>anchor_grade</code>,
<code>get_grade</code>, <code>anchor_cert</code>, <code>is_cert_anchored</code>. If the node is
unreachable it raises <code>LedgerUnavailable</code>, which the API turns into an HTTP 503 —
the secure build <b>fails closed</b>: it will not issue a certificate it could not anchor.</p>

<h3>7.4 Recovering the true value from a hash</h3>
<p>The contract stores only a SHA-256 hash, so there is no "read the grade back from the chain"
call. Yet the admin tamper monitor shows the <i>correct</i> grade beside a tampered one (see
WAPT-008). This works because grades live on a tiny, known domain — 0.00 to 20.00 in 0.25
steps, 81 possible values. The secure build simply hashes each candidate and compares it to the
anchored hash to recover the real value:</p>
{code('''<span class="c"># eth_ledger.py — recover the anchored grade by exhaustive match over a tiny domain</span>
for step in range(0, 81):                      # 0.00, 0.25, ..., 20.00
    candidate = f"{step * 0.25:.2f}"
    if grade_hash(course_id, student_id, candidate) == target_chain_hash:
        return candidate</tt>''')}
{info("This brute-force recovery is sound <b>only because</b> the input space is small and the hash is unsalted. It is a deliberate design choice for a non-confidential value (a grade on a fixed scale); a field that needed confidentiality would be anchored with a salted commitment instead, which this report notes as the correct pattern for secret data.")}
</div>""")

# =========================================================== 8. TECHNICAL FINDINGS header
add("""<div class="section">
<h2 id="s8">8. Technical Findings</h2>
<p>Each finding below includes a description, OWASP Top 10 (2021) mapping, a risk rating
(likelihood and impact), the affected component with source references, tools used, references,
a reproducible proof-of-concept with evidence, and — the focus of this assessment — the exact
control in the secure build that defeats the attack. All captures were taken on the tester's own
local instances.</p>
</div>""")

def finding(num, title, sev, sevclass, body):
    badge = {'crit':'b-crit','high':'b-high','med':'b-med'}[sevclass]
    sevlabel = {'crit':'Critical','high':'High','med':'Moderate'}[sevclass]
    add(f'<div class="finding" id="f-{num}"><h2>Finding WAPT-{num}: {title} '
        f'<span class="badge {badge}">{sevlabel}</span></h2>{body}</div>')

# ---------- WAPT-001
finding("001", "SQL Injection — Authentication Bypass", "crit", "crit", f"""
<p><b>Description.</b> The login handler builds its SQL query by concatenating the
client-supplied username directly into the statement, with no parameterization. A crafted
username comments out the password check, authenticating the attacker as the first matching
row — the administrator — without any password.</p>
{ftable("A03:2021 — Injection",
        "High — a single, well-known payload typed into the login form; no tooling required.",
        "Very High — complete administrator takeover, exposing all user data and privileged functions.",
        "<code>POST /api/login</code> (username field) — login SQL built by string concatenation (vuln build).",
        "Web browser, Burp Suite",
        "OWASP A03 Injection; WSTG-INPV-05; OWASP SQL Injection Prevention Cheat Sheet")}
<h4>Proof of concept</h4>
<p>On the vulnerable login page, submit the following and any password:</p>
{code('Username:  admin\'--  <span class="c">(note the trailing space after --)</span>\nPassword:  anything')}
<p>The trailing <code>--</code> turns the rest of the query (the password comparison) into a
comment, so the server authenticates the <code>admin</code> row directly. The dashboard loads as
<b>admin</b> with no valid credentials.</p>
{secure("The secure build uses a parameterized query (<code>... WHERE username = ?</code>) so the payload is treated as a literal username string that does not exist, and the supplied password is verified against the stored PBKDF2 hash. The same input returns <b>&ldquo;invalid username or password&rdquo;</b>.")}
""")

# ---------- WAPT-002
finding("002", "SQL Injection — UNION-based Password-Hash Exfiltration", "crit", "crit", f"""
<p><b>Description.</b> The certifications endpoint concatenates the <code>student_id</code> query
parameter into a numeric SQL context with no validation and no authorization check. An attacker
logged in as an ordinary student can inject a <code>UNION SELECT</code> to read arbitrary tables
— including every user's password hash — and render them straight into the Certifications table
in the browser.</p>
{ftable("A03:2021 — Injection (with A01 Broken Access Control)",
        "High — exploitable from the address bar by any authenticated student.",
        "Very High — full database read: all users' password hashes, enabling mass account compromise after cracking.",
        "<code>GET /api/certifications?student_id=</code> — <code>app.py:280-288</code> (vuln build).",
        "Web browser, Burp Suite, hashcat / CrackStation",
        "OWASP A03 Injection; WSTG-INPV-05")}
<h4>Proof of concept</h4>
<p>Logged in as <code>alice</code>, browse to the Certifications page, then drive the injection
from the address bar. <code>?student_id=0 OR 1=1</code> returns every student's certificates;
the UNION payload exfiltrates the user table:</p>
{code('/#certifications?student_id=0 union select 1,2,password_hash,4,5,6,7,8 from users--')}
<p>The six MD5 digests render directly in the <code>grade</code>/<code>title</code> columns of
the Certifications table. These hashes feed directly into WAPT-006 (cracking).</p>
{figure("docs/img/sqli-certifications-hashes.png", "Figure 2.1 — The Certifications page rendering every user's MD5 password hash, exfiltrated through the UNION-based SQL injection.")}
{secure("Two independent controls: the query is <b>parameterized</b> (<code>WHERE c.student_id = ?</code>), so <code>OR 1=1</code> / <code>UNION</code> are inert text; and an <b>object-level authorization check</b> ensures a student may read only their own <code>student_id</code> — any other id returns <b>403</b>. Password hashes are never selected into this response in the first place.")}
""")

# ---------- WAPT-003
finding("003", "Broken JWT — Admin Token Forgery", "crit", "crit", f"""
<p><b>Description.</b> After login the server issues a JSON Web Token (JWT) carrying the user's
<code>sub</code>, <code>username</code> and <code>role</code>. The vulnerable build
<b>decodes the token but never verifies its signature</b> (<code>jwt_decode_vuln</code>,
<code>auth.py</code>), and even accepts <code>alg:none</code>. Privileged endpoints trust the
<code>role</code> claim straight from the token. An attacker can therefore flip
<code>&quot;role&quot;:&quot;student&quot;</code> to <code>&quot;admin&quot;</code> in their own
token — with no re-signing — and the server believes it.</p>
{ftable("A02:2021 — Cryptographic Failures (signature not verified) / A07 Identification &amp; Authentication Failures",
        "High — a logged-in user edits one claim in Burp's JWT editor; the signature is left untouched or deleted.",
        "Very High — horizontal and vertical privilege escalation to admin; exposes the full user list with every password hash.",
        "JWT verification in <code>auth.py:jwt_decode_vuln</code>; admin endpoint trusting the role claim (<code>app.py</code>).",
        "Firefox, Burp Suite (Proxy / Repeater / JWT Editor)",
        "OWASP A02 Cryptographic Failures; A07; WSTG-SESS-10; RFC 7519")}
<h4>Proof of concept</h4>
<ol class="tight">
<li>With Firefox proxied through Burp, log in as <code>alice</code> / <code>password1</code>.
In Proxy &rarr; HTTP history find an authenticated request (<code>GET /api/me</code> carries the
<code>Authorization: Bearer</code> header) and send it to <b>Repeater</b>.</li>
<li>Aim it at the admin endpoint — change the first line to
<code>GET /api/admin/users HTTP/1.1</code> and Send. You get
<code>403 {{"error":"admins only"}}</code>: the token is accepted, you are just not admin yet.</li>
<li>In the <b>JSON Web Token</b> tab, change <code>"role":"student"</code> to
<code>"role":"admin"</code>. <b>Leave the signature alone.</b> Send &rarr; <b>200 OK</b> and the
full user list, including every <code>password_hash</code>.</li>
</ol>
{code('{ "users": [ { "id":1, "username":"admin", "role":"admin",\n               "password_hash":"0192023a7bbd73250516f069df18b500", ... }, ... ] }')}
<p>The signature is irrelevant: deleting the entire third segment (leaving a trailing dot) still
returns 200. Setting <code>"sub":1</code> promotes the whole UI to admin, since
<code>/api/me</code> loads the user by <code>sub</code>.</p>
<h4>Evidence</h4>
{figure("docs/img/jwt-01-baseline-403.png", "Figure 3.1 — Repeater: GET /api/admin/users with alice's genuine token returns 403 'admins only' — the token is accepted, but not yet admin.")}
{figure("docs/img/jwt-02-editor-role-admin.png", "Figure 3.2 — The JSON Web Token editor: the payload role changed from 'student' to 'admin', with the signature left untouched.")}
{figure("docs/img/jwt-03-200-users-hashes.png", "Figure 3.3 — The forged-role token now returns 200 OK and the full user list, including every password_hash.")}
{figure("docs/img/jwt-04-no-signature-200.png", "Figure 3.4 — The same request with the entire signature segment deleted still returns 200 OK: the signature is never checked.")}
{secure("The secure decoder (<code>jwt_decode_secure</code>) <b>pins <code>alg=HS256</code></b>, recomputes the HMAC-SHA256 over the header and payload and compares it in constant time, and rejects expired tokens. The edited token fails the MAC check and returns <b>401</b>. As defence in depth, the admin endpoint re-loads the caller's role <b>from the database</b> rather than trusting the token claim, and never returns password hashes.")}
""")

# ---------- WAPT-004
finding("004", "IDOR — Private Chats &amp; Student Documents", "high", "high", f"""
<p><b>Description.</b> Two insecure-direct-object-reference bugs share one pattern: the object
is selected by an id in the request, with no check that the caller may access it. A student can
read any private conversation and any other student's official document by changing an id.</p>
{ftable("A01:2021 — Broken Access Control (IDOR)",
        "High — ids are visible in the user's own URLs; the attack is a single value change.",
        "High — disclosure of confidential conversations (including a leaked master password) and other students' personal data.",
        "<code>GET /api/documents/&lt;id&gt;</code> (<code>app.py:875-893</code>); chat retrieval by <code>chat_users[]</code>.",
        "Web browser, Burp Suite",
        "OWASP A01; WSTG-ATHZ-04 (IDOR)")}
<h4>Proof of concept — 4a: read anyone's private chat</h4>
<p>As <code>alice</code>, open Chat and a conversation; the URL shows
<code>#chat?chat_users[0]=4&amp;chat_users[1]=5</code>. Change it to read the private
admin&nbsp;&harr;&nbsp;professor conversation:</p>
{code('#chat?chat_users[0]=1&chat_users[1]=2')}
<p>The conversation is disclosed, including the line
&ldquo;the grading portal master password is <code>Adm1n_Gu@rd14n_2026</code>&rdquo;.</p>
{figure("docs/img/idor-chat-secret.png", "Figure 4.1 — Alice (a student) reading the private admin &harr; professor conversation by editing chat_users[] in the URL; the grading-portal master password is exposed.")}
<h4>Proof of concept — 4b: read another student's document</h4>
{code('<span class="c">// address bar</span>  #documents?doc=1\n<span class="c">// or console</span>  call(\'GET\',\'/api/documents/1\')')}
<p>Alice sees another student's document — name, e-mail and reference number.</p>
{secure("Both endpoints add a server-side ownership check: a student may read a document or a conversation only if they are a participant/owner; staff and admins are allowed by role. Any other id returns <b>403 forbidden</b>.")}
""")

# ---------- WAPT-005
finding("005", "Mass Assignment — Privilege Escalation at Registration", "high", "high", f"""
<p><b>Description.</b> The sign-up form sends only <code>full_name</code>, <code>username</code>,
<code>email</code> and <code>password</code>. The vulnerable build, however, reads a
<code>role</code> from the request body if one is present and writes it straight into the new
user row. A new account is a <code>student</code> only because the form omits <code>role</code>
— an attacker who adds the field chooses their own role.</p>
{ftable("A01:2021 — Broken Access Control (Mass Assignment)",
        "High — a single intercepted registration request with one extra JSON field.",
        "High — immediate creation of an attacker-controlled administrator account.",
        "<code>POST /api/register</code> — <code>role = b.get(&quot;role&quot;,&quot;student&quot;)</code> (<code>app.py:140-148</code>, vuln build).",
        "Firefox, Burp Suite (Intercept)",
        "OWASP A01; WSTG-BUSLOGIC; Mass Assignment Cheat Sheet")}
<h4>Proof of concept</h4>
<p>With Intercept on, submit the registration form and edit the captured body to add a role:</p>
{code('{ "full_name":"ahmed", "username":"ahmed", "email":"ahmed@campus.edu",\n  "password":"ahmed123", <span class="hl">"role":"admin"</span> }')}
<p>Forward the request, then log in as <code>ahmed</code> / <code>ahmed123</code>: the dashboard
greets &ldquo;Administrator dashboard&rdquo; and the admin menus appear.</p>
{figure("docs/img/register-01-intercept.png", "Figure 5.1 — Burp intercept: POST /api/register captured; the registration body contains no role field.")}
{figure("docs/img/register-02-add-role.png", "Figure 5.2 — The intercepted body edited to add <code>&quot;role&quot;:&quot;admin&quot;</code> before forwarding the request.")}
{figure("docs/img/register-03-admin-dashboard.png", "Figure 5.3 — Logged in as the new account: the Administrator dashboard and the admin-only menus (Users, Documents, Integrity) are present.")}
{secure("The secure build fixes <code>role = &quot;student&quot;</code> on the server and ignores any role in the body (<code>app.py:143</code>). The same tampered request produces a plain student account.")}
""")

# ---------- WAPT-006 (CRYPTO)
finding("006", "Cryptographic Failure — Unsalted MD5 Password Storage", "high", "high", f"""
<p><b>Description.</b> The vulnerable build stores passwords as <b>unsalted MD5</b> digests. MD5
is fast and broken for password hashing, and the absence of a salt means identical passwords
share a hash and precomputed rainbow tables / online lookups apply directly. Combined with the
hash leaks in WAPT-002/003, this converts a database read into full credential compromise.</p>
{ftable("A02:2021 — Cryptographic Failures",
        "High — once hashes leak, cracking is instant with free online tables; no GPU needed.",
        "High — plaintext recovery of most user passwords, enabling account takeover across roles.",
        "Password hashing in <code>auth.py:hash_password</code> / <code>verify_password</code>.",
        "hashcat, CrackStation, sqlite3",
        "OWASP A02; WSTG-ATHN; OWASP Password Storage Cheat Sheet; NIST SP 800-63B")}
<h4>Proof of concept</h4>
<p>Take the six MD5 digests leaked via WAPT-002 and crack them — e.g. paste into CrackStation
or run hashcat:</p>
{cmd('hashcat -m 0 -a 0 hashes.txt rockyou.txt')}
<p>Five of six crack instantly (<code>admin123</code>, <code>hunter2</code>,
<code>password1</code>, <code>teach123</code>, <code>qwerty</code>) — the sixth simply is not in
that wordlist. Cracking is instant precisely because MD5 is cheap and unsalted.</p>
{figure("docs/img/md5-crackstation.png", "Figure 6.1 — CrackStation instantly recovering five of the six leaked MD5 hashes (admin123, hunter2, password1, teach123, qwerty); the sixth is simply absent from the wordlist.")}
{secure('''The secure build hashes with <b>PBKDF2-HMAC-SHA256</b>, a <b>unique 16-byte salt per user</b> and <b>200,000 iterations</b>, verified in constant time. The salt kills rainbow tables and makes identical passwords hash differently; the iteration count makes each guess ~200,000&times; slower, so a wordlist attack is impractical. Confirm with:''' + cmd('sqlite3 sms_secure.db "SELECT username,hash_scheme,salt FROM users"\n<span class="c"># scheme = pbkdf2, a distinct salt per row</span>'))}
""")

# ---------- WAPT-007 (CRYPTO + BLOCKCHAIN) with figure
finding("007", "Cryptographic Failure — Unsigned &amp; Un-anchored Certificates (Forgery)", "high", "high", f"""
<p><b>Description.</b> Academic certifications are the application's highest-value authenticity
asset. The vulnerable build stores a certificate <b>without any digital signature</b> and
<b>never anchors it</b>, and on read it is reported &ldquo;verified&rdquo; with no check at all
(<code>c["verified"] = True</code>, <code>app.py:299-302</code>). Consequently a certificate an
attacker injects directly — e.g. via the stacked-query SQLi below — displays as a genuine,
valid credential. This is the exact threat the secure build's Ed25519 + blockchain layer
(Section 7) is designed to defeat.</p>
{ftable("A02:2021 — Cryptographic Failures / A08:2021 — Software &amp; Data Integrity Failures",
        "Medium–High — requires an injection or DB write, but the forged record is then indistinguishable from a real one.",
        "High — forged academic credentials (e.g. a fake &quot;PhD&quot;) presented as university-verified; reputational and legal harm.",
        "Certificate issue/verify path — <code>app.py:299-315</code> (read), <code>426-450</code> (issue); <code>crypto_utils.verify_cert</code>; <code>eth_ledger.is_cert_anchored</code>.",
        "Burp Suite, sqlite3, browser",
        "OWASP A02 / A08; WSTG-CRYP; NIST FIPS 186-5 (EdDSA)")}
<h4>Proof of concept — forge a &ldquo;valid&rdquo; certificate</h4>
<p>As <code>alice</code>, inject an unsigned certificate through the Course-search box with a
stacked-query SQLi (no DB access needed on the vuln build):</p>
{code("%'; INSERT INTO certifications (student_id,title,grade,issued_date,signature,issued_by)\n       VALUES (4,'PhD in Computer Science','A+','2026-01-01',NULL,1); --")}
<p>The search shows no matches, but the Certifications page now lists a
&ldquo;PhD in Computer Science&rdquo; marked <b>valid</b> — a forged credential accepted by the
vuln build because it never checks a signature or the ledger.</p>
<h4>How the secure build defeats it (Ed25519 signature + on-chain anchor)</h4>
<p>In the secure build, issuing a certificate signs its canonical payload with the issuer's
Ed25519 private key and anchors the SHA-256 fingerprint on the GradeLedger contract; the row is
committed only if the on-chain anchor succeeded (otherwise HTTP 503 — fail closed). On
<b>read</b>, two independent checks must both pass:</p>
{code('''<span class="c"># app.py (secure) — a certificate is trusted only if BOTH hold</span>
c["verified"] = verify_cert(student_id, title, grade, issued_date, signature)  <span class="c"># Ed25519</span>
fp            = cert_fingerprint(student_id, title, grade, issued_date)
c["on_chain"] = is_cert_anchored(fp)                                           <span class="c"># blockchain</span>''')}
<p>A certificate inserted straight into the secure database has <code>signature = NULL</code>
(the attacker cannot produce a valid Ed25519 signature without the private key) <b>and</b> a
fingerprint that was never anchored (the attacker cannot write to the contract without the
issuer's Ethereum key). It therefore shows as <b>&#10007; invalid</b> and <b>not on chain</b>.
Reproduce the DB-level forgery against the secure build:</p>
{cmd("sqlite3 sms_secure.db &quot;INSERT INTO certifications (student_id,title,grade,issued_date,signature,issued_by) VALUES (4,'PhD in Computer Science','17','2026-01-01',NULL,1)&quot;")}
{figure("image.png", "Figure 7.1 — The same forged certificate on the <b>secure</b> build: the signature fails Ed25519 verification and the fingerprint is absent from the ledger, so it is flagged <b>invalid</b> and <b>not on chain</b>. The vuln build showed the identical record as &ldquo;valid&rdquo;.")}
{secure("Authenticity is anchored in two keys the attacker never holds: the <b>Ed25519 signing key</b> (so forgeries fail signature verification) and the <b>issuer's Ethereum key</b> (so forgeries are absent from the immutable ledger). Both must succeed for a certificate to read as genuine.")}
""")

# ---------- WAPT-008 (BLOCKCHAIN) with two figures
finding("008", "Data Integrity Failure — Silent Grade Tampering", "high", "high", f"""
<p><b>Description.</b> The vulnerable build keeps grades in SQLite with <b>no integrity
reference</b>. Anyone who reaches the database — via SQLi, path traversal (WAPT-011) or shell
access — can rewrite a grade and nothing flags it, because the application has no independent
record of the correct value. The secure build anchors the SHA-256 hash of every legitimate
grade on the GradeLedger contract and compares the database against the chain on every read, so
any out-of-band edit is detected and reversible.</p>
{ftable("A08:2021 — Software &amp; Data Integrity Failures",
        "Medium — requires database access, but that access is reachable through other findings in this report.",
        "High — undetected alteration of official academic records (grade inflation / sabotage) with no audit trail.",
        "Grade write/verify — <code>app.py:491-507</code> (anchor on write), <code>645-776</code> (tamper monitor); <code>GradeLedger.anchorGrade/getGrade</code>.",
        "sqlite3, Ethereum node (anvil), browser",
        "OWASP A08; NIST SP 800-57 (key management)")}
<h4>Proof of concept — tamper with a grade directly in the database</h4>
<p>Simulate an attacker who has reached the database and inflates Alice's Mathematics grade to
the maximum:</p>
{cmd("sqlite3 sms_vuln.db   &quot;UPDATE grades SET grade='20.00' WHERE student_id=4 AND course_id=1;&quot;\nsqlite3 sms_secure.db &quot;UPDATE grades SET grade='20.00' WHERE student_id=4 AND course_id=1;&quot;")}
<p><b>Vulnerable build:</b> log in as <code>alice</code> — the dashboard simply shows 20/20.
Nothing anywhere indicates the record was altered.</p>
<h4>How the secure build detects and reverses it (on-chain anchor)</h4>
<p>Every legitimate grade change anchors its hash on the contract
(<code>anchor_grade(course_id, student_id, grade_hash)</code>), committed only if the
transaction succeeded. On read, the build recomputes the hash of the stored grade and compares
it with the anchored hash; a mismatch is tamper. The <b>true</b> value is recovered from the
on-chain hash by matching candidates on the 0&ndash;20 scale (Section 7.4).</p>
{figure("image-5.png", "Figure 8.1 — The student dashboard on the <b>secure</b> build after the same DB edit: the tampered value (20.00) is struck through in red and the <b>verified</b> grade recovered from the ledger is shown beside it; the computed average is unaffected.")}
<p>The administrator's <b>Integrity &amp; ledger</b> console raises a live alert and offers a
one-click restore that rewrites the database back to the anchored value:</p>
{figure("image-6.png", "Figure 8.2 — Admin Integrity console: &ldquo;Tampering detected &mdash; 1 grade&rdquo; for Alice Anderson / Mathematics (In database 20.00 vs Verified-ledger 14.00), with <b>Restore all from ledger</b>. Below: &ldquo;Connected to GradeLedger (chain 31337)&rdquo;, the contract address <code>0x1196&hellip;546D</code>, the issuer key (&ldquo;the only key allowed to write&rdquo;) and the append-only anchored-event log with per-event transaction hashes.")}
{secure("Integrity is enforced by comparing the database against an <b>independent, append-only on-chain anchor</b> written only by the issuer key. A direct DB edit changes the hash, so DB &ne; chain and the tamper is flagged instantly; <b>Restore all from ledger</b> rewrites the DB back to the verified value. The attacker cannot hide the edit because they cannot re-anchor the forged value without the issuer's Ethereum key.")}
""")

# ---------- WAPT-009 (mass assignment) with figures
finding("009", "Mass Assignment — Privilege Escalation from Profile Update", "high", "high", f"""
<p><b>Description.</b> The Profile form edits only name, e-mail, phone and address, but the
vulnerable build writes <b>any</b> field present in the request body onto the user's own row —
the textbook mass-assignment flaw. A student can add <code>role</code> and promote themselves to
administrator.</p>
{ftable("A01:2021 — Broken Access Control (Mass Assignment)",
        "High — one intercepted &ldquo;Save Changes&rdquo; request with an added field.",
        "High — self-service privilege escalation from student to admin.",
        "Profile update handler (vuln build writes arbitrary body keys to the user row).",
        "Firefox, Burp Suite (Intercept)",
        "OWASP A01; WSTG-BUSLOGIC; Mass Assignment Cheat Sheet")}
<h4>Proof of concept</h4>
{figure("image-3.png", "Figure 9.1 — The Profile &ldquo;Save Changes&rdquo; request captured in Burp; the body carries only the visible profile fields.")}
{figure("image-4.png", "Figure 9.2 — The intercepted request edited to add <code>&quot;role&quot;:&quot;admin&quot;</code> before forwarding. On the next login the account has full administrator access.")}
{secure("The secure build writes only an explicit <b>allow-list</b> of the fields the UI actually exposes (name, e-mail, phone, address). <code>role</code> and any other unexpected key are ignored, so the user stays a student.")}
""")

# ---------- WAPT-010 (file upload)
finding("010", "Unrestricted File Upload &rarr; Stored XSS", "high", "high", f"""
<p><b>Description.</b> The document-request upload accepts <b>any file, of any type and size,
stored verbatim under the client-supplied filename</b>. A student can upload an SVG/HTML file
containing JavaScript; when an administrator opens it during approval, the script executes in
the admin's authenticated session (stored XSS), enabling theft of the admin JWT and full
account takeover.</p>
{ftable("A05:2021 — Security Misconfiguration / A03 Injection (Stored XSS) / A08 Integrity",
        "Medium–High — a student uploads a crafted file; execution waits for an admin to view it.",
        "High — stored XSS in an admin context &rarr; session/JWT theft &rarr; administrative takeover.",
        "Upload handler <code>_save_upload</code> (<code>app.py:816-839</code>, vuln branch).",
        "Web browser, Burp Suite",
        "OWASP A05 / A03; WSTG-BUSLOGIC-09 (upload); File Upload Cheat Sheet")}
<h4>Proof of concept</h4>
<p>As <code>alice</code>, create a non-PDF &ldquo;document&rdquo; carrying an XSS payload and
submit it as a document request:</p>
{cmd("printf '&lt;svg xmlns=&quot;http://www.w3.org/2000/svg&quot;&gt;&lt;script&gt;alert(document.domain)&lt;/script&gt;&lt;/svg&gt;' &gt; evil.svg")}
<p>The vuln build accepts and stores it verbatim, under the attacker's chosen filename. When the
administrator opens the attachment to approve the request, the payload runs in the admin origin —
in a real attack, exfiltrating the admin's JWT rather than calling <code>alert()</code>.</p>
{secure("The secure build <b>ignores the client filename</b>, requires a genuine PDF by checking the <code>%PDF-</code> magic bytes, caps the size at 5&nbsp;MB, and stores the file under a random server-generated name (<code>secrets.token_hex(16)+&quot;.pdf&quot;</code>) inside the upload directory. Non-PDF content is rejected with &ldquo;only PDF files are accepted&rdquo;, so no active content can be stored or served.")}
""")

# ---------- WAPT-011 (path traversal) with figures
finding("011", "Path Traversal — Local File Disclosure", "crit", "crit", f"""
<p><b>Description.</b> The document-download endpoint serves whatever filename the client passes
in <code>?name=</code>, joined onto the uploads directory with <b>no sanitisation</b>. By
supplying <code>../</code> sequences, an attacker escapes the uploads folder and downloads
arbitrary server files — including the certificate signing key and the entire SQLite database,
which directly undermines every other control in the application.</p>
{ftable("A01:2021 — Broken Access Control (Path Traversal) / A05 Misconfiguration",
        "High — an authenticated user appends a crafted query parameter to a normal download URL.",
        "Critical — disclosure of the Ed25519 signing key and the full database (all hashes, messages, grades); enables certificate forgery and total compromise.",
        "<code>GET /api/documents/&lt;id&gt;/download?name=</code> (<code>app.py:896-918</code>, vuln branch).",
        "Web browser, Burp Suite",
        "OWASP A01 / A05; WSTG-ATHZ-01 (Directory Traversal); Path Traversal Cheat Sheet")}
<h4>Proof of concept</h4>
<p><b>Step 1.</b> When a student views an uploaded document, a request is sent that returns the
PDF in the response:</p>
{figure("image-7.png", "Figure 11.1 — The normal document-download request that returns the student's own uploaded PDF.")}
<p><b>Step 2.</b> Fuzzing the query parameters shows that <code>?name</code> changes the response
— indicating the value is used to build the served file path:</p>
{figure("image-8.png", "Figure 11.2 — Probing parameters: only <code>?name</code> alters the response, revealing it is processed server-side to locate the file.")}
<p><b>Step 3.</b> Supplying a traversal path discloses arbitrary server files. Downloading the
whole database:</p>
{code('GET /api/documents/5/download?<span class="hl">name=../../sms_vuln.db</span> HTTP/1.1\nHost: meridian.tn:3000')}
{figure("image-9.png", "Figure 11.3 — Path traversal confirmed: <code>?name=../../sms_vuln.db</code> returns <b>200 OK</b> with the raw SQLite database (note <code>SQLite format 3</code> in the body and <code>filename=sms_vuln.db</code>). The same technique with <code>?name=../../keys/issuer_ed25519.pem</code> leaks the certificate signing key.")}
{secure("The secure build <b>ignores the <code>name</code> parameter entirely</b> and serves only the file recorded for that specific document, with a fixed <code>application/pdf</code> content type and an ownership check (students may download only their own). The client never influences the served path, so traversal is impossible.")}
""")

# =========================================================== APPENDIX A
add("""<div class="section">
<h2 id="appA">Appendix A — Methodology &amp; Tools</h2>
<p>Testing followed the OWASP Web Security Testing Guide (WSTG) and mapped findings to the
OWASP Top 10 (2021). Each vulnerability was first confirmed on the vulnerable build, then
re-tested against the secure build to verify the control.</p>
<table>
<tr><th>Tool</th><th>Use in this assessment</th></tr>
<tr><td>Firefox + Burp Suite (Proxy, Repeater, Intercept, JWT Editor)</td>
<td>Request interception and tampering: JWT forgery, mass assignment, path traversal.</td></tr>
<tr><td>Local DNS / hosts file (<code>meridian.tn &rarr; 127.0.0.1</code>)</td>
<td>Route loopback traffic through Burp (Section 2).</td></tr>
<tr><td>sqlite3</td><td>Simulate database-level tampering and inspect password schemes/salts.</td></tr>
<tr><td>hashcat / CrackStation</td><td>Crack the leaked unsalted MD5 password hashes.</td></tr>
<tr><td>anvil (Foundry) + web3.py</td><td>Local Ethereum node hosting the GradeLedger contract; anchor/verify operations.</td></tr>
<tr><td>Browser DevTools console</td><td>Drive IDOR and API calls directly (<code>call('GET', ...)</code>).</td></tr>
</table>
<h2 style="margin-top:24px" id="appB">Appendix B — Cryptographic &amp; Blockchain Reference</h2>
<table>
<tr><th>Mechanism</th><th>Where</th><th>Parameters</th></tr>
<tr><td>Password KDF</td><td><code>auth.py</code></td><td>PBKDF2-HMAC-SHA256, 200,000 iterations, 16-byte per-user salt, constant-time verify</td></tr>
<tr><td>JWT</td><td><code>auth.py</code></td><td>HS256; secure decoder pins alg, verifies HMAC in constant time, checks <code>exp</code></td></tr>
<tr><td>Encryption at rest</td><td><code>crypto_utils.py</code></td><td>AES-256-GCM, random 96-bit nonce, 128-bit tag; key in <code>keys/aes.key</code> (0600)</td></tr>
<tr><td>Certificate signature</td><td><code>crypto_utils.py</code></td><td>Ed25519 over canonical JSON; private key in <code>keys/issuer_ed25519.pem</code> (0600)</td></tr>
<tr><td>On-chain anchor</td><td><code>eth_ledger.py</code> / <code>GradeLedger.sol</code></td><td>SHA-256 fingerprint; <code>onlyIssuer</code> writes; chain id 31337; fail-closed (503 if node down)</td></tr>
</table>
<p class="small" style="margin-top:18px">End of report — BUSINESS CONFIDENTIAL — TEK-UP / Web Security Module 2025-2026.</p>
</div>""")

# =========================================================== RENDER
DOC = f"""<!doctype html><html lang="en"><head><meta charset="utf-8"/>
<title>Meridian Campus Portal — Security Assessment Report</title>
<style>{CSS}</style></head><body>{''.join(P)}</body></html>"""

with open(OUT, "w") as f:
    f.write(DOC)
print("wrote", OUT, "(%d KB)" % (len(DOC)//1024), "blocks:", len(P))

# Render the PDF too, if WeasyPrint is importable (one-command build).
try:
    from weasyprint import HTML
    pdf = os.path.join(PROJ, "Meridian_Portal_Security_Report.pdf")
    HTML(OUT, base_url=PROJ).write_pdf(pdf)
    print("wrote", pdf)
except ImportError:
    print("WeasyPrint not installed in this interpreter — HTML written, PDF skipped.")
