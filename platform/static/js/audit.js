/* Looking Glass · the audit log (/audit, audit_page.py): every sign-in, change, export, decision and advisory, newest
   first, with search, paging and the built-in security test's events hidden unless asked for. Read only; data is
   inserted as text only. The data: GET /api/admin/audit (permission 'audit', checked on the server). */
(() => {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const el = (t, c, x) => { const e = document.createElement(t); if (c) e.className = c; if (x != null) e.textContent = x; return e; };
  const fmtT = (t) => (t ? new Date(t * 1000).toISOString().replace("T", " ").slice(0, 16) : "–");
  const shortUA = (ua) => {
    if (!ua) return "–";
    const b = /Edg\//.test(ua) ? "Edge" : /OPR\//.test(ua) ? "Opera" : /Chrome\//.test(ua) ? "Chrome" : /Firefox\//.test(ua) ? "Firefox" : /Safari\//.test(ua) ? "Safari" : ua.split(" ")[0];
    const os = /Windows/.test(ua) ? "Windows" : /Android/.test(ua) ? "Android" : /iPhone|iPad/.test(ua) ? "iOS" : /Mac OS/.test(ua) ? "macOS" : /Linux/.test(ua) ? "Linux" : "";
    return os ? `${b} · ${os}` : b;
  };
  function banner(msg, bad) { const b = $("banner"); b.className = "st-banner" + (bad ? " err" : ""); b.textContent = msg; b.hidden = false; }
  const EVENT_NAMES = { login: "Logged in", login_failed: "Failed login", login_locked: "Locked out", login_refused: "Login refused", logout: "Logged out",
    registered: "Account created", mfa_enrolled: "Authenticator set up", recovery_code_used: "Recovery code used", session_misuse: "Session misuse",
    kicked: "Kicked", user_approve: "Approved", user_role: "Role changed", user_revoke: "Revoked", user_restore: "Restored", user_reset_mfa: "Authenticator reset",
    user_delete: "Deleted", roles_changed: "Roles changed", settings_changed: "Settings changed", register_limited: "Registration limit", setup_code_wrong: "Wrong setup code (first administrator)",
    reset_requested: "Password reset requested", reset_failed: "Password reset failed", password_reset: "Password reset", user_allow_reset: "Password reset allowed",
    networks_identify: "Networks identified", network_edited: "Network name edited", network_type_added: "Network type added",
    definition_saved: "Definition saved", note_added: "Note added", note_removed: "Note removed", report_pdf: "Report downloaded",
    finding_created: "Finding opened", finding_status: "Finding moved", finding_decision: "Finding decided", finding_reply: "Finding replied",
    finding_review_decision: "Review decided", combo_review_sent: "Sent to management", combo_export: "Combination report",
    advisory_saved: "Advisory saved", advisory_report: "Advisory report generated", advisory_drafted: "Advisory drafted", advisory_sent: "Advisory sent",
    advisory_export: "Advisory exported", advisory_download: "Advisory report downloaded", organisation_set: "Organisation set", peace_of_mind: "Peace of mind" };
  let offset = 0;
  async function load(reset) {
    if (reset) offset = 0;
    const q = encodeURIComponent($("auditSearch").value.trim());
    const tests = $("auditTests").checked ? 1 : 0;
    let d;
    try {
      const r = await fetch(`/api/admin/audit?limit=200&offset=${offset}&q=${q}&selftests=${tests}`, { cache: "no-store" });
      d = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(d.error || r.statusText);
    } catch (e) { banner(`Could not load the audit log: ${e.message}`, true); return; }
    finally { $("auLoading")?.remove(); window.LGLoader?.ready(); }
    const tb = $("auditTable").querySelector("tbody"); if (reset) tb.replaceChildren();
    for (const r of d.rows) {
      const tr = el("tr", (/failed|locked|misuse|refused|revoke|delete|limited/.test(r.event) ? "adm-alert" : "") + (r.selftest ? " adm-selftest" : ""));
      if (r.selftest) tr.title = "Made by the built-in security test (temporary lg-selftest accounts)";
      const br = el("td", null, shortUA(r.ua)); br.title = r.ua || "";
      tr.append(el("td", "mono", fmtT(r.t)), el("td", null, EVENT_NAMES[r.event] || r.event), el("td", null, r.user_label || r.user || "–"),
        el("td", null, r.target_label || r.target || "–"), el("td", "mono", r.ip || "–"), el("td", null, r.location || "–"), br, el("td", "adm-detail", r.detail || ""));
      tb.append(tr);
    }
    offset += d.rows.length;
    $("auditCount").textContent = `${offset.toLocaleString()} of ${d.total.toLocaleString()} events` +
      (d.selftests_hidden ? ` · ${d.selftests_hidden.toLocaleString()} self-test events hidden` : "");
    $("auditMore").hidden = offset >= d.total;
  }
  let st; $("auditSearch").addEventListener("input", () => { clearTimeout(st); st = setTimeout(() => load(true), 300); });
  $("auditMore").addEventListener("click", () => load(false));
  $("auditTests").addEventListener("change", () => load(true));

  // ---------------- the live sessions (roles that manage users): who is signed in now; end one to sign it out
  const csrf = document.querySelector('meta[name="csrf-token"]')?.content || "";
  const fmtAgo = (s) => (s < 60 ? `${s}s ago` : s < 3600 ? `${Math.round(s / 60)} min ago` : `${Math.round(s / 3600)} h ago`);
  async function loadSessions() {
    if (!$("sessionsTable")) return;
    let d;
    try {
      const r = await fetch("/api/admin/sessions", { cache: "no-store" });
      d = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(d.error || r.statusText);
    } catch (e) { banner(`Could not load sessions: ${e.message}`, true); return; }
    const tb = $("sessionsTable").querySelector("tbody"); tb.replaceChildren();
    if (!d.sessions.length) { const tr = el("tr"); const td = el("td", "muted", "No active sessions."); td.colSpan = 8; tr.append(td); tb.append(tr); }
    for (const s of d.sessions) {
      const tr = el("tr");
      const who = el("td"); who.append(el("b", null, s.user)); if (s.current) who.append(el("span", "adm-you", " (this session)"));
      const br = el("td", null, shortUA(s.browser)); br.title = s.browser || "";
      const end = el("td");
      if (!s.current && d.can_end) {
        const b = el("button", "pill-btn warn", "End session"); b.type = "button";
        b.addEventListener("click", async () => {
          b.disabled = true;
          try {
            const r = await fetch(`/api/admin/sessions/${encodeURIComponent(s.id)}/end`, { method: "POST", headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf }, body: "{}" });
            const j = await r.json().catch(() => ({}));
            if (!r.ok) throw new Error(j.error || r.statusText);
            banner(`Session of ${s.user} ended.`);
          } catch (e) { banner(e.message, true); }
          loadSessions();
        });
        end.append(b);
      }
      const type = el("td", "adm-meta"); type.append(el("div", null, s.persist ? "Stay signed in" : "Browser session"), el("div", "muted", `until ${fmtT(s.expires)}`));
      tr.append(who, el("td", "mono", s.ip), el("td", null, s.location), br, type, el("td", null, fmtT(s.created)), el("td", null, fmtAgo(s.idle_s)), end);
      tb.append(tr);
    }
  }

  // ---------------- tabs: the audit log, and the sessions where this role may see them
  const tabs = [...document.querySelectorAll(".adm-tabs [data-tab]")];
  function show(tab) {
    for (const b of tabs) b.setAttribute("aria-pressed", String(b.dataset.tab === tab));
    for (const p of document.querySelectorAll(".adm-pane")) p.hidden = p.id !== `pane-${tab}`;
    // each tab shows its loading animation while its data comes (the audit log has its own line on the first visit)
    if (tab === "sessions") { if (window.LGLoader?.pane) window.LGLoader.pane($("pane-sessions"), "Opening who is signed in…", loadSessions); else loadSessions(); }
    else if (tab === "audit" && !$("auLoading") && window.LGLoader?.pane) window.LGLoader.pane($("pane-audit"), "Opening the audit log…", () => load(true));
    try { history.replaceState(null, "", tab === "audit" ? location.pathname : `#${tab}`); } catch { /* */ }
  }
  for (const b of tabs) b.addEventListener("click", () => show(b.dataset.tab));
  const want = (location.hash || "").slice(1);
  show(tabs.some((b) => b.dataset.tab === want) ? want : "audit");
  load(true);
  setInterval(() => { if (tabs.find((b) => b.getAttribute("aria-pressed") === "true")?.dataset.tab === "sessions") loadSessions(); }, 30000);
})();
