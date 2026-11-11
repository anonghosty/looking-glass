/* Looking Glass · admin: users (approve, role, revoke, restore, reset authenticator, kick, delete), live sessions
   and roles & permissions (the audit log and the live sessions: /audit, audit.js). Every change is a JSON POST with the session's CSRF
   token; the server checks the permission again (auth.py). Data is inserted as text only. */
(() => {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const el = (t, c, x) => { const e = document.createElement(t); if (c) e.className = c; if (x != null) e.textContent = x; return e; };
  const csrf = document.querySelector('meta[name="csrf-token"]').content;
  const PERMS = new Set((document.body.dataset.perms || "").split(",").filter(Boolean));
  const fmtT = (t) => (t ? new Date(t * 1000).toISOString().replace("T", " ").slice(0, 16) : "–");
  const ago = (s) => (s < 60 ? `${s}s ago` : s < 3600 ? `${Math.round(s / 60)} min ago` : `${Math.round(s / 3600)} h ago`);
  const shortUA = (ua) => {
    if (!ua) return "–";
    const b = /Edg\//.test(ua) ? "Edge" : /OPR\//.test(ua) ? "Opera" : /Chrome\//.test(ua) ? "Chrome" : /Firefox\//.test(ua) ? "Firefox" : /Safari\//.test(ua) ? "Safari" : ua.split(" ")[0];
    const os = /Windows/.test(ua) ? "Windows" : /Android/.test(ua) ? "Android" : /iPhone|iPad/.test(ua) ? "iOS" : /Mac OS/.test(ua) ? "macOS" : /Linux/.test(ua) ? "Linux" : "";
    return os ? `${b} · ${os}` : b;
  };
  function banner(msg, bad) { const b = $("banner"); b.className = "st-banner" + (bad ? " err" : ""); b.textContent = msg; b.hidden = false; clearTimeout(banner.t); banner.t = setTimeout(() => { b.hidden = true; }, 6000); }
  async function getJSON(u) { const r = await fetch(u, { cache: "no-store" }); const j = await r.json().catch(() => ({})); if (!r.ok) throw new Error(j.error || r.statusText); return j; }
  async function post(u, body) {
    const r = await fetch(u, { method: "POST", headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf }, body: JSON.stringify(body || {}) });
    const j = await r.json().catch(() => ({})); if (!r.ok) throw new Error(j.error || r.statusText); return j;
  }

  // ---------------- tabs
  const tabs = [...document.querySelectorAll(".adm-tabs [data-tab]")];
  function show(tab) {
    for (const b of tabs) b.setAttribute("aria-pressed", String(b.dataset.tab === tab));
    for (const p of document.querySelectorAll(".adm-pane")) p.hidden = p.id !== `pane-${tab}`;
    ({ users: loadUsers, roles: loadRoles })[tab]?.();
    try { history.replaceState(null, "", `#${tab}`); } catch { /* */ }
  }
  for (const b of tabs) b.addEventListener("click", () => show(b.dataset.tab));

  // ---------------- users
  let roleNames = [], ROLE_INFO = {};
  async function loadUsers() {
    let d; try { d = await getJSON("/api/admin/users"); } catch (e) { banner(`Could not load users: ${e.message}`, true); return; }
    finally { $("adLoading")?.remove(); window.LGLoader?.ready(); }
    roleNames = d.roles; ROLE_INFO = d.info || {};
    drawRoleLegend();
    const pend = d.users.filter((u) => u.status === "pending").length;
    $("pendingBadge").hidden = !pend; $("pendingBadge").textContent = pend;
    const tb = $("usersTable").querySelector("tbody"); tb.replaceChildren();
    if (!d.users.length) { const tr = el("tr"); const td = el("td", "muted", "No accounts."); td.colSpan = 8; tr.append(td); tb.append(tr); }
    for (const u of d.users) {
      const tr = el("tr", `st-${u.status}`);
      const name = el("td", "adm-meta adm-name"); name.append(el("b", null, u.name)); if (u.you) name.append(el("span", "adm-you", " (you)"));
      const pf = u.profile || {};
      if (pf.full_name) name.append(el("div", null, pf.full_name));
      if (pf.organisation || pf.country) name.append(el("div", "muted", [pf.organisation, pf.country].filter(Boolean).join(" · ")));
      if (pf.email) { const m = el("div", "muted mono", pf.email); name.append(m); }
      const st = el("td", "adm-state"); st.append(el("span", `adm-status ${u.status}`, { active: "Active", pending: "Pending approval", disabled: "Revoked" }[u.status] || u.status));
      if (u.reset_requested) {
        const r = el("div", "adm-flag"); r.append(el("span", null, "Password reset requested"), el("span", "adm-flag-when mono", fmtT(u.reset_requested.at)));
        r.title = `${u.reset_requested.ip} · ${u.reset_requested.location} · ${u.reset_requested.ua}`; st.append(r);
      }
      if (u.reset_allowed) st.append(el("div", "adm-flag ok", "Reset allowed (24 h)"));
      const roleTd = el("td", "adm-role"); const sel = el("select", "adm-select lg-enhance"); for (const r of roleNames) { const o = el("option", null, r); o.value = r; sel.append(o); } sel.value = u.role;
      // active accounts: the new role applies at once; pending accounts: it is kept in the list and applied by Approve
      sel.addEventListener("change", () => { if (u.status !== "pending") act(u.name, "role", { role: sel.value }, `Role of ${u.name} changed to ${sel.value}.`); });
      sel.title = ROLE_INFO[u.role] || "";
      roleTd.append(sel);
      const mfa = el("td", null, u.mfa ? `On · ${u.recovery_left} recovery` : "Not set up");
      const reg = el("td", "adm-meta"); reg.append(el("div", null, fmtT(u.registered.at || u.created)), el("div", "muted", [u.registered.ip, u.registered.location].filter(Boolean).join(" · ") || "–"), el("div", "muted", shortUA(u.registered.ua)));
      if (u.registered.ua) reg.title = u.registered.ua;
      const last = el("td", "adm-meta"); last.append(el("div", null, fmtT(u.last_login.at)), el("div", "muted", [u.last_login.ip, u.last_login.location].filter(Boolean).join(" · ") || "–"), el("div", "muted", shortUA(u.last_login.ua)));
      if (u.last_login.ua) last.title = u.last_login.ua;
      const ses = el("td", null, String(u.sessions));
      // the buttons sit in a flex box INSIDE the cell: a flex <td> stops being a table cell and breaks the row
      const actTd = el("td", "adm-act-cell"), acts = el("div", "adm-actions"); actTd.append(acts);
      const btn = (label, cls, fn) => { const b = el("button", `pill-btn ${cls || ""}`, label); b.type = "button"; b.addEventListener("click", fn); acts.append(b); };
      if (u.status === "pending") btn("Approve", "primary", () => act(u.name, "approve", { role: sel.value }, `${u.name} approved as ${sel.value}.`));
      if (u.status === "disabled") btn("Restore", "", () => act(u.name, "restore", {}, `${u.name} restored.`));
      if (!u.you) {
        if (u.sessions) btn("Kick", "", () => act(u.name, "kick", {}, `${u.name} logged out everywhere.`));
        if (u.mfa && u.status === "active" && !u.reset_allowed) btn(u.reset_requested ? "Allow password reset" : "Allow password reset (24 h)", u.reset_requested ? "primary" : "",
          () => confirm(`Let ${u.name} set a new password with their authenticator code during the next 24 hours?`) && act(u.name, "allow_reset", {}, `${u.name} may reset their password for 24 hours.`));
        if (u.status !== "disabled") btn("Revoke", "warn", () => confirm(`Revoke ${u.name}? They are logged out and can no longer log in.`) && act(u.name, "revoke", {}, `${u.name} revoked.`));
        if (u.mfa) btn("Reset authenticator", "", () => confirm(`Remove ${u.name}'s authenticator? They set it up again at next login and need approval again.`) && act(u.name, "reset_mfa", {}, `${u.name}'s authenticator reset.`));
        btn("Delete", "danger", () => confirm(`Delete the account ${u.name}? This cannot be undone.`) && act(u.name, "delete", {}, `${u.name} deleted.`));
      }
      tr.append(name, st, roleTd, mfa, reg, last, ses, actTd); tb.append(tr);
    }
  }
  function drawRoleLegend() {
    let box = document.getElementById("roleLegend");
    if (!box) { box = el("dl", "adm-roles-legend"); box.id = "roleLegend"; document.getElementById("usersTable").closest(".table-wrap").after(box); }
    box.replaceChildren();
    for (const r of roleNames) { box.append(el("dt", null, r), el("dd", null, ROLE_INFO[r] || "")); }
  }
  async function act(name, action, extra, ok) {
    if (!action) { loadUsers(); return; }           // pending: the role is applied on approval
    try { await post(`/api/admin/users/${encodeURIComponent(name)}`, { action, ...extra }); banner(ok); } catch (e) { banner(e.message, true); }
    loadUsers();
  }

  // the audit log and the live sessions are a page of their own (/audit, audit.js)

  // ---------------- roles & permissions
  let rolesState = null;
  async function loadRoles() {
    try { rolesState = await getJSON("/api/admin/roles"); } catch (e) { banner(`Could not load roles: ${e.message}`, true); return; }
    drawRoles();
  }
  function drawRoles() {
    const { roles, perms, in_use: used } = rolesState;
    const names = Object.keys(roles).sort((a, b) => (a === "admin") - (b === "admin") || a.localeCompare(b));
    const th = el("tr"); th.append(el("th", null, "Permission"));
    for (const r of names) {
      const h = el("th", "adm-rolehead"); h.append(el("div", null, r), el("div", "muted", `${used[r] || 0} account(s)`)); h.title = (rolesState.info || {})[r] || "";
      if (r !== "admin" && !(used[r] > 0) && !["external", "analyst", "researcher", "management"].includes(r)) { const x = el("button", "pill-btn danger", "Remove"); x.type = "button";
        x.addEventListener("click", () => { delete rolesState.roles[r]; drawRoles(); }); h.append(x); }
      th.append(h);
    }
    $("rolesTable").querySelector("thead").replaceChildren(th);
    const tb = $("rolesTable").querySelector("tbody"); tb.replaceChildren();
    for (const [p, desc] of Object.entries(perms)) {
      const tr = el("tr"); const d = el("td"); d.append(el("b", null, p), el("div", "muted", desc)); tr.append(d);
      for (const r of names) {
        const td = el("td", "adm-check"); const cb = el("input"); cb.type = "checkbox"; cb.checked = (roles[r] || []).includes(p);
        // the management portal belongs to the management role only (the server enforces it too)
        const locked = r === "admin" || r === "management" || p === "management";
        cb.disabled = locked;
        cb.title = r === "admin" ? "Admins always have every permission"
          : r === "management" ? "The management role has the management portal only; it cannot be changed"
          : p === "management" ? "Only the management role has the management portal" : `${p} for ${r}`;
        cb.addEventListener("change", () => { const s = new Set(rolesState.roles[r]); cb.checked ? s.add(p) : s.delete(p); rolesState.roles[r] = [...s]; });
        td.append(cb); tr.append(td);
      }
      tb.append(tr);
    }
  }
  $("addRole").addEventListener("click", () => {
    const n = $("newRole").value.trim().toLowerCase();
    if (!/^[a-z][a-z0-9_-]{1,30}$/.test(n)) { banner("Role names: lower-case letters, digits, - and _ (2-31 characters).", true); return; }
    if (rolesState.roles[n]) { banner("That role exists.", true); return; }
    rolesState.roles[n] = ["view"]; rolesState.in_use[n] = 0; $("newRole").value = ""; drawRoles();
  });
  $("saveRoles").addEventListener("click", async () => {
    try { const d = await post("/api/admin/roles", { roles: rolesState.roles }); rolesState.roles = d.roles; banner("Roles saved. Users with a changed role get the new permissions straight away."); drawRoles(); }
    catch (e) { banner(e.message, true); }
  });

  // ---------------- start
  const first = (location.hash || "").slice(1);
  if (first === "audit" || first === "sessions") { location.replace(first === "sessions" ? "/audit#sessions" : "/audit"); return; }   // moved to the audit page
  const avail = tabs.map((b) => b.dataset.tab);
  show(avail.includes(first) ? first : avail[0]);
  setInterval(() => { const t = tabs.find((b) => b.getAttribute("aria-pressed") === "true")?.dataset.tab; if (t === "users") loadUsers(); }, 30000);
  void PERMS;
})();
