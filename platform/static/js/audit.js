/* Looking Glass · the Audit portal (/audit, audit_portal.py). Read only: the audit log split into tabs, the dashboard
   with the control checks, the access review, who is signed in, and the log's integrity with the evidence exports.
   Every value is inserted as text. Data: /api/audit/* (permission 'audit', checked on the server). */
(() => {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const el = (t, c, x) => { const e = document.createElement(t); if (c) e.className = c; if (x != null) e.textContent = x; return e; };
  const svgEl = (t, a) => { const e = document.createElementNS("http://www.w3.org/2000/svg", t); for (const k in a) e.setAttribute(k, a[k]); return e; };
  const fmt = (n) => (n == null ? "–" : Number(n).toLocaleString("en-GB"));
  const fmtT = (t) => (t ? new Date(t * 1000).toISOString().replace("T", " ").slice(0, 16) : "–");
  const shortUA = (ua) => {
    if (!ua) return "–";
    const b = /Edg\//.test(ua) ? "Edge" : /OPR\//.test(ua) ? "Opera" : /Chrome\//.test(ua) ? "Chrome" : /Firefox\//.test(ua) ? "Firefox" : /Safari\//.test(ua) ? "Safari" : ua.split(" ")[0];
    const os = /Windows/.test(ua) ? "Windows" : /Android/.test(ua) ? "Android" : /iPhone|iPad/.test(ua) ? "iOS" : /Mac OS/.test(ua) ? "macOS" : /Linux/.test(ua) ? "Linux" : "";
    return os ? `${b} · ${os}` : b;
  };
  function banner(msg, bad) { const b = $("banner"); b.className = "st-banner" + (bad ? " err" : ""); b.textContent = msg; b.hidden = false; }
  async function getJSON(url) {
    const r = await fetch(url, { cache: "no-store" });
    const d = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(d.error || r.statusText);
    return d;
  }
  const HINTS = {
    auth: "Sign-ins and sign-outs, failed sign-ins and lockouts, authenticator set-ups, recovery codes and password resets.",
    accounts: "Registrations, approvals, role changes, revocations, restores, deletions, authenticator resets and changes to what a role may do.",
    sessions: "Sessions ended by an administrator, and session misuse (a session used from another address or browser).",
    config: "Settings (country, constituency), network names and types, definitions, the organisation, and Peace of mind.",
    data: "Report and CSV downloads, combination reports, advisory files, and the audit evidence exported here.",
    workflow: "Findings, reviews and decisions, analyst and combination codes, notes, and advisories from saved to sent.",
    system: "The built-in security self-test (temporary lg-selftest accounts, attacks simulated on purpose), the checks on this computer, and integrity checks.",
  };
  const TAB_NAMES = {};
  document.querySelectorAll(".au-tabs [data-tab]").forEach((b) => { TAB_NAMES[b.dataset.tab] = b.firstChild.textContent.trim(); });

  // ---------------- the period, shared by every tab
  const today = new Date().toISOString().slice(0, 10);
  const daysAgo = (n) => new Date(Date.now() - n * 86400000).toISOString().slice(0, 10);
  $("auTo").value = today; $("auFrom").value = daysAgo(29); $("auTo").max = today; $("auFrom").max = today;
  const per = () => `from=${encodeURIComponent($("auFrom").value)}&to=${encodeURIComponent($("auTo").value)}`;
  const presets = [...document.querySelectorAll(".au-presets button")];
  presets.forEach((b) => b.addEventListener("click", () => {
    presets.forEach((x) => x.setAttribute("aria-pressed", String(x === b)));
    $("auTo").value = today; $("auFrom").value = daysAgo(+b.dataset.days - 1); reloadCurrent();
  }));
  ["auFrom", "auTo"].forEach((id) => $(id).addEventListener("change", () => { presets.forEach((x) => x.setAttribute("aria-pressed", "false")); reloadCurrent(); }));

  // ---------------- small drawing helpers
  function kpi(label, value, note, tone) {
    const k = el("div", `au-kpi${tone ? " " + tone : ""}`); k.append(el("span", "au-kpi-k", label), el("b", null, value));
    if (note) k.append(el("small", null, note)); return k;
  }
  function card(title, sub) { const c = el("div", "au-card"); c.append(el("h3", null, title)); if (sub) c.append(el("p", "au-sub", sub)); return c; }
  function bars(rows, key, fmtv) {                 // horizontal bars: [{label, n}]
    const box = el("div", "au-bars"); const max = Math.max(1, ...rows.map((r) => r[key]));
    if (!rows.length) { box.append(el("p", "muted", "None in the period.")); return box; }
    for (const r of rows) {
      const row = el("div", "au-bar"); const b = el("span", "au-bar-f"); b.style.width = `${Math.max(2, (100 * r[key]) / max)}%`;
      const t = el("span", "au-bar-l", r.label); t.title = r.label;
      row.append(t, el("span", "au-bar-t", "")); row.lastChild.append(b); row.append(el("span", "au-bar-n", fmtv ? fmtv(r[key]) : fmt(r[key]))); box.append(row);
    }
    return box;
  }
  function dayChart(days) {                       // sign-ins per day: successful, failed and lockouts stacked
    const W = 720, H = 180, P = 24, n = Math.max(1, days.length), bw = (W - P * 2) / n;
    const max = Math.max(1, ...days.map((d) => d.ok + d.failed + d.locked));
    const s = svgEl("svg", { viewBox: `0 0 ${W} ${H}`, class: "au-chart", role: "img", "aria-label": "Sign-ins per day" });
    for (let i = 0; i <= 4; i++) { const y = H - P - ((H - P * 2) * i) / 4; s.append(svgEl("line", { x1: P, x2: W - P, y1: y, y2: y, class: "au-grid" })); }
    days.forEach((d, i) => {
      let y = H - P; const x = P + i * bw + bw * 0.15, w = Math.max(1, bw * 0.7);
      for (const [k, cls] of [["ok", "au-c-ok"], ["failed", "au-c-fail"], ["locked", "au-c-lock"]]) {
        const h = ((H - P * 2) * d[k]) / max; if (!h) continue; y -= h;
        const r = svgEl("rect", { x, y, width: w, height: h, class: cls }); const t = svgEl("title", {}); t.textContent = `${d.day}: ${d.ok} signed in, ${d.failed} failed, ${d.locked} locked out`; r.append(t); s.append(r);
      }
    });
    const lab = (x, t, a) => { const e = svgEl("text", { x, y: H - 6, class: "au-ax", "text-anchor": a }); e.textContent = t; s.append(e); };
    lab(P, days[0]?.day || "", "start"); lab(W - P, days[days.length - 1]?.day || "", "end");
    const top = svgEl("text", { x: P, y: P - 8, class: "au-ax" }); top.textContent = `${max} per day`; s.append(top);
    return s;
  }
  function hourChart(hours, work) {
    const W = 720, H = 150, P = 22, bw = (W - P * 2) / 24, max = Math.max(1, ...hours);
    const s = svgEl("svg", { viewBox: `0 0 ${W} ${H}`, class: "au-chart", role: "img", "aria-label": "Sign-ins by hour of the day (UTC)" });
    s.append(svgEl("rect", { x: P + work[0] * bw, y: P - 6, width: (work[1] - work[0]) * bw, height: H - P * 2 + 6, class: "au-work" }));
    hours.forEach((v, h) => {
      const hh = ((H - P * 2) * v) / max, r = svgEl("rect", { x: P + h * bw + bw * 0.15, y: H - P - hh, width: bw * 0.7, height: hh, class: h >= work[0] && h < work[1] ? "au-c-ok" : "au-c-late" });
      const t = svgEl("title", {}); t.textContent = `${String(h).padStart(2, "0")}:00–${String(h + 1).padStart(2, "0")}:00 UTC: ${v} sign-in(s)`; r.append(t); s.append(r);
      if (h % 3 === 0) { const e = svgEl("text", { x: P + h * bw, y: H - 6, class: "au-ax" }); e.textContent = String(h).padStart(2, "0"); s.append(e); }
    });
    return s;
  }
  function legend(items) { const l = el("div", "au-legend"); for (const [cls, t] of items) { const i = el("span"); i.append(el("i", cls), document.createTextNode(t)); l.append(i); } return l; }
  function eventTable(rows, cols) {
    const t = el("table", "hosts adm-table au-table"); const h = el("tr"); cols.forEach(([n]) => h.append(el("th", null, n)));
    const th = el("thead"); th.append(h); t.append(th); const tb = el("tbody");
    for (const r of rows) { const tr = el("tr", r.alert ? "adm-alert" : ""); cols.forEach(([, f, cls]) => tr.append(el("td", (typeof cls === "function" ? cls(r) : cls) || null, f(r)))); tb.append(tr); }
    t.append(tb); const w = el("div", "table-wrap"); w.append(t); return w;
  }

  // ---------------- Overview: the figures, the charts and the control checks
  async function loadOverview() {
    const d = await getJSON(`/api/audit/overview?${per()}`);
    const body = $("ovBody"); body.replaceChildren();
    const k = d.kpis, nistN = new Set(d.checks.flatMap((c) => (c.nist || []).map((x) => x.id))).size;
    const top = el("div", "au-kpis");
    // the checks carry evidence, not a verdict: the auditor decides
    top.append(kpi("Control checks", fmt(d.checks.length), `evidence for ${nistN} NIST controls`),
      kpi("Audit log", d.integrity.ok ? "Unbroken" : "Broken", `${fmt(d.integrity.entries)} entries kept`, d.integrity.ok ? "good" : "bad"),
      kpi("Sign-ins", fmt(k.signins), `${fmt(k.people)} people`), kpi("Failed sign-ins", fmt(k.failed), `${k.failure_rate} % of attempts`, k.failed ? "warn" : ""),
      kpi("Lockouts", fmt(k.lockouts), null, k.lockouts ? "warn" : ""), kpi("Privileged changes", fmt(k.privileged), "roles, accounts, settings"),
      kpi("Exports", fmt(k.exports), "reports, CSV, evidence"), kpi("Outside working hours", fmt(k.after_hours), `sign-ins outside ${String(d.work_hours[0]).padStart(2, "0")}:00–${String(d.work_hours[1]).padStart(2, "0")}:00 UTC`, k.after_hours ? "warn" : ""));
    body.append(el("p", "au-sub", `${d.period.from} to ${d.period.to} (UTC) · ${fmt(k.events)} events, self-test left out · access mode: ${d.access_mode}`
      + (d.started ? ` · system started ${d.started} (running ${fmt(d.running_days)} day${d.running_days === 1 ? "" : "s"})` : "")), top);

    // the control checks, by area
    const cc = card("Control checks", `Automated checks of Looking Glass's own controls (LG-01…), each mapped to the ${d.nist_release || "NIST SP 800-53 Rev. 5"} controls it supports, with its evidence. They give no pass or fail: the conclusion is the auditor's. Click a check to open the records behind it; the PDF report carries the same, with its scope and limits.`);
    const areas = [...new Set(d.checks.map((c) => c.area))];
    for (const a of areas) {
      const g = el("div", "au-check-g"); g.append(el("h4", null, a));
      for (const c of d.checks.filter((x) => x.area === a)) {
        // a check with evidence behind it opens it: the tab with the events or accounts it is about
        const r = el(c.view ? "button" : "div", `au-check${c.view ? " link" : ""}`);
        r.append(el("code", null, c.id));
        const t = el("div"); t.append(el("b", null, c.control));
        if ((c.nist || []).length) {        // the NIST SP 800-53 Rev. 5 controls this check supports (official titles)
          const n = el("div", "au-nist");
          for (const x of c.nist) { const s = el("span", null, x.id); s.title = `${d.nist_release || "NIST SP 800-53 Rev. 5"}: ${x.id} ${x.title}`; n.append(s); }
          n.append(el("small", null, c.nist.map((x) => x.title).join(" · ")));
          t.append(n);
        }
        t.append(el("p", null, c.evidence)); r.append(t);
        if (c.view) {
          r.type = "button"; r.title = `Open the evidence: ${TAB_NAMES[c.view.tab] || c.view.tab}`;
          r.append(el("span", "au-check-go", "View →"));
          r.addEventListener("click", () => { $("logAlerts").checked = !!c.view.alerts; show(c.view.tab); window.scrollTo({ top: 0, behavior: "smooth" }); });
        }
        g.append(r);
      }
      cc.append(g);
    }
    const grid = el("div", "au-grid2");
    const c1 = card("Sign-ins per day"); c1.append(dayChart(d.per_day), legend([["au-c-ok", "signed in"], ["au-c-fail", "failed"], ["au-c-lock", "locked out"]]));
    const c2 = card("Sign-ins by hour of the day (UTC)", "The shaded band is working hours (AUDIT_WORK_HOURS)."); c2.append(hourChart(d.hours, d.work_hours), legend([["au-c-ok", "within working hours"], ["au-c-late", "outside"]]));
    const c3 = card("Events by kind"); c3.append(bars(d.tabs.map((t) => ({ label: t.label, n: t.n })), "n"));
    const c4 = card("Failed sign-ins by address", "Failed sign-ins, refusals and lockouts."); c4.append(bars(d.fail_sources.map((s) => ({ label: `${s.ip} · ${s.location}`, n: s.n })), "n"));
    const c5 = card("Exports by person"); c5.append(bars(d.exports_by.map((s) => ({ label: s.who, n: s.n })), "n"));
    const c6 = card("Recent privileged changes", "Roles, accounts, settings, Peace of mind, sessions ended.");
    c6.append(d.privileged_recent.length ? eventTable(d.privileged_recent, [["Time", (r) => r.when, "mono"], ["Change", (r) => r.label], ["By", (r) => r.user_label || r.user], ["Account", (r) => r.target_label || r.target || "–"], ["Detail", (r) => r.detail, "adm-detail"]]) : el("p", "muted", "None in the period."));
    grid.append(c1, c2, c3, c4, c5, c6);
    body.append(cc, grid);
  }

  // ---------------- one tab of the log
  let logTab = "auth", logOffset = 0;
  async function loadLog(reset) {
    if (reset) logOffset = 0;
    const q = encodeURIComponent($("logSearch").value.trim());
    const d = await getJSON(`/api/audit/events?tab=${logTab}&${per()}&q=${q}&limit=200&offset=${logOffset}&alerts=${$("logAlerts").checked ? 1 : 0}&selftests=${$("logTests").checked ? 1 : 0}`);
    for (const [key, n] of Object.entries(d.counts || {})) { const s = document.querySelector(`[data-n="${key}"]`); if (s) s.textContent = fmt(n); }
    document.querySelectorAll("[data-n]").forEach((s) => { if (!(s.dataset.n in (d.counts || {}))) s.textContent = "0"; });
    const tb = $("logTable").querySelector("tbody"); if (reset) tb.replaceChildren();
    if (reset && !d.rows.length) { const tr = el("tr"); const td = el("td", "muted", "No events of this kind in the period."); td.colSpan = 8; tr.append(td); tb.append(tr); }
    for (const r of d.rows) {
      const tr = el("tr", (r.alert ? "adm-alert" : "") + (r.selftest ? " adm-selftest" : "") + (r.privileged ? " au-priv" : ""));
      if (r.selftest) tr.title = "Made by the built-in security self-test or a check on this computer";
      const br = el("td", null, shortUA(r.ua)); br.title = r.ua || "";
      tr.append(el("td", "mono", fmtT(r.t)), el("td", null, r.label), el("td", null, r.user_label || r.user || "–"),
        el("td", null, r.target_label || r.target || "–"), el("td", "mono", r.ip || "–"), el("td", null, r.location || "–"), br, el("td", "adm-detail", r.detail || ""));
      tb.append(tr);
    }
    logOffset += d.rows.length;
    $("logCount").textContent = `${fmt(logOffset)} of ${fmt(d.total)} events`;
    $("logMore").hidden = logOffset >= d.total;
  }
  let lst; $("logSearch").addEventListener("input", () => { clearTimeout(lst); lst = setTimeout(() => loadLog(true).catch((e) => banner(e.message, true)), 300); });
  $("logAlerts").addEventListener("change", () => loadLog(true).catch((e) => banner(e.message, true)));
  $("logTests").addEventListener("change", () => loadLog(true).catch((e) => banner(e.message, true)));
  $("logMore").addEventListener("click", () => loadLog(false).catch((e) => banner(e.message, true)));

  // ---------------- access review
  async function loadAccess() {
    const d = await getJSON("/api/audit/access");
    const body = $("accBody"); body.replaceChildren();
    const a = d.accounts, act = a.filter((x) => x.status === "active");
    const k = el("div", "au-kpis");
    k.append(kpi("Accounts", fmt(a.length), `${fmt(act.length)} active`), kpi("Administrators", fmt(act.filter((x) => x.role === "admin").length), `limit ${d.thresholds.max_admins}`, act.filter((x) => x.role === "admin").length > d.thresholds.max_admins ? "warn" : ""),
      kpi("Without an authenticator", fmt(act.filter((x) => !x.mfa).length), null, act.some((x) => !x.mfa) ? "bad" : "good"),
      kpi("Dormant", fmt(act.filter((x) => x.flags.some((f) => f.startsWith("no sign-in"))).length), `no sign-in for ${d.thresholds.dormant_days}+ days`),
      kpi("Waiting for approval", fmt(a.filter((x) => x.status === "pending").length)), kpi("Revoked", fmt(a.filter((x) => x.status === "disabled").length)));
    body.append(k);
    const c1 = card("Accounts", "Sorted by name. Flags: no authenticator, dormant, pending too long, every permission (administrators).");
    c1.append(eventTable(a, [["Account", (x) => (x.full_name ? `${x.full_name} (${x.name})` : x.name)], ["Organisation", (x) => x.organisation || "–"], ["Role", (x) => x.role],
      ["Status", (x) => ({ active: "Active", pending: "Pending", disabled: "Revoked" }[x.status] || x.status)], ["Authenticator", (x) => (x.mfa ? `yes · ${x.recovery_left} recovery codes` : "NO")],
      ["Last sign-in", (x) => (x.last_login ? `${x.last_login} · ${x.last_login_location}` : "never"), "mono"], ["Approved", (x) => [x.approved_by, x.approved_at].filter(Boolean).join(" · ") || "–"],
      ["Signed in now", (x) => (x.sessions ? `${x.sessions} session(s)` : "–")], ["Flags", (x) => x.flags.join("; ") || "–", (x) => (x.flags.length ? "au-flags" : "muted")]]));
    const c2 = card("Roles and what they may do", "Fixed roles cannot be changed by anyone: admin (every permission), management (the Executive portal only), auditor (this portal only, read only).");
    const perms = Object.keys(d.perms);
    const t = el("table", "hosts adm-table au-roles"); const h = el("tr"); h.append(el("th", null, "Permission"));
    for (const r of d.roles) { const th = el("th"); th.append(el("div", null, r.role), el("small", "muted", `${r.accounts} account(s)${r.fixed ? " · fixed" : ""}`)); h.append(th); }
    const th0 = el("thead"); th0.append(h); t.append(th0); const tb = el("tbody");
    for (const p of perms) {
      const tr = el("tr"); const d0 = el("td"); d0.append(el("b", null, p), el("div", "muted", d.perms[p])); tr.append(d0);
      for (const r of d.roles) tr.append(el("td", "au-dot", r.permissions.includes(p) ? "●" : ""));
      tb.append(tr);
    }
    t.append(tb); const w = el("div", "table-wrap"); w.append(t); c2.append(w);
    body.append(c1, c2);
  }

  // ---------------- signed in now
  const fmtAgo = (s) => (s < 60 ? `${s}s ago` : s < 3600 ? `${Math.round(s / 60)} min ago` : `${Math.round(s / 3600)} h ago`);
  async function loadSessions() {
    const d = await getJSON("/api/admin/sessions");
    const tb = $("sessionsTable").querySelector("tbody"); tb.replaceChildren();
    if (!d.sessions.length) { const tr = el("tr"); const td = el("td", "muted", "No active sessions."); td.colSpan = 7; tr.append(td); tb.append(tr); }
    for (const s of d.sessions) {
      const tr = el("tr"); const who = el("td"); who.append(el("b", null, s.user)); if (s.current) who.append(el("span", "adm-you", " (this session)"));
      const br = el("td", null, shortUA(s.browser)); br.title = s.browser || "";
      const type = el("td", "adm-meta"); type.append(el("div", null, s.persist ? "Stay signed in" : "Browser session"), el("div", "muted", `until ${fmtT(s.expires)}`));
      tr.append(who, el("td", "mono", s.ip), el("td", null, s.location), br, type, el("td", null, fmtT(s.created)), el("td", null, fmtAgo(s.idle_s)));
      tb.append(tr);
    }
  }

  // ---------------- integrity and evidence
  function showVerify(v) {
    const b = $("vfBody"); b.replaceChildren(); b.className = "";
    const st = el("p", `au-vf ${v.ok ? "ok" : "bad"}`, v.ok ? "The chain is whole: no entry was changed, inserted or removed." : `BROKEN at entry ${v.break.entry}${v.break.t ? ` (${fmtT(v.break.t)})` : ""}: ${v.break.what}.`);
    const dl = el("dl", "au-dl");
    const row = (k, x, mono) => { dl.append(el("dt", null, k), el("dd", mono ? "mono" : null, x)); };
    row("Entries", `${fmt(v.entries)} kept · ${fmt(v.chained)} chained${v.before_chain ? ` · ${fmt(v.before_chain)} written before the chain started` : ""}`);
    row("From – to", `${v.first || "–"} – ${v.last || "–"}`);
    row("Archives", `${v.archives} file(s) · ${v.removed_archives} removed by the retention of ${v.retention_days} days · rotated at ${v.rotate_mb} MB`);
    row("Head", `${v.head}@${v.head_entry ?? v.entries}`, true);
    if (v.checked) row("Checked", v.checked);
    b.append(st, dl, el("p", "st-hint", "Note the head (hash@entry) with your evidence. At the next audit, compare it (Proof to take away): if it is still at that entry, the log up to it is unchanged."));
  }
  $("vfRun").addEventListener("click", async () => {
    $("vfRun").disabled = true; window.LGLoader?.busy("Verifying the audit log");
    try { showVerify(await getJSON("/api/audit/verify")); } catch (e) { banner(e.message, true); }
    finally { $("vfRun").disabled = false; window.LGLoader?.ready(); }
  });
  async function sha256hex(buf) { const h = await crypto.subtle.digest("SHA-256", buf); return [...new Uint8Array(h)].map((x) => x.toString(16).padStart(2, "0")).join(""); }
  async function download(url, label, boxId = "evDone") {
    window.LGLoader?.busy(`Preparing ${label}`);
    try {
      const r = await fetch(url, { cache: "no-store" });
      if (!r.ok) { const d = await r.json().catch(() => ({})); throw new Error(d.error || r.statusText); }
      const buf = await r.arrayBuffer();
      const name = (/filename="([^"]+)"/.exec(r.headers.get("Content-Disposition") || "") || [])[1] || "audit-evidence";
      const a = el("a"); a.href = URL.createObjectURL(new Blob([buf], { type: r.headers.get("Content-Type") || "application/octet-stream" })); a.download = name;
      document.body.append(a); a.click(); setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 1000);
      let hex = ""; try { hex = await sha256hex(buf); } catch { /* an old browser without SubtleCrypto */ }
      const box = $(boxId); box.hidden = false; box.replaceChildren(); box.className = "au-ev-done";
      box.append(el("b", null, `Downloaded ${name}`), el("span", "muted", ` · ${fmt(buf.byteLength)} bytes`));
      if (hex) { const p = el("p"); p.append(el("span", null, "SHA-256 "), el("code", "au-hash", hex)); box.append(p); }
      const head = r.headers.get("X-Audit-Head");          // the proof package: the head it holds, to keep for the next audit
      if (head) { const p = el("p"); p.append(el("span", null, "Head "), el("code", "au-hash", head)); box.append(p, el("p", "muted", "Keep both with your working papers.")); }
    } catch (e) { banner(`Could not prepare ${label}: ${e.message}`, true); }
    finally { window.LGLoader?.ready(); }
  }
  $("pfZip").addEventListener("click", () => download("/api/audit/proof.zip", "the proof package", "ctOut"));
  // compare with an earlier audit's head (hash@entry): the log up to it must be unchanged
  $("ctForm").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const v = $("ctIn").value.trim(); if (!v) return;
    const out = $("ctOut"); window.LGLoader?.busy("Comparing with the earlier head");
    try {
      const d = await getJSON(`/api/audit/continuity?earlier=${encodeURIComponent(v)}`), e = d.earlier;
      out.hidden = false; out.replaceChildren(); out.className = `au-ct-out ${e.proven ? "ok" : "bad"}`;
      const msg = !e.found ? "Not found: this hash is not in the log. The log was rewritten since, or the hash was noted wrongly."
        : e.where !== "kept" ? `Found as ${e.where} (entry ${fmt(e.entry)}): the entries up to it are no longer kept, so they cannot be compared.`
        : !e.same_entry ? `Found at entry ${fmt(e.entry)}, not at entry ${fmt(e.entry_given)} as noted: entries before it were added or removed.`
        : !d.chain_ok ? `Found at entry ${fmt(e.entry)}, but the chain is broken (verify the log for where).`
        : `Found at entry ${fmt(e.entry)}${e.when ? ` (${e.when})` : ""}: the log up to it is exactly the log of that audit.`;
      out.append(el("b", null, e.proven ? "Unchanged since the earlier audit" : "Not proven"), el("p", null, msg));
      const p = el("p", "muted"); p.append(el("span", null, "Head now "), el("code", "au-hash", `${d.head}@${d.head_entry}`)); out.append(p);
    } catch (e) { banner(e.message, true); }
    finally { window.LGLoader?.ready(); }
  });
  $("evPdf").addEventListener("click", () => download(`/api/audit/report.pdf?${per()}`, "the evidence report"));
  $("evCsv").addEventListener("click", () => download(`/api/audit/export.csv?tab=all&${per()}`, "the events"));
  $("logCsv").addEventListener("click", () => download(`/api/audit/export.csv?tab=${logTab}&${per()}`, "this tab's events"));
  const evPeriod = () => { $("evPeriod").textContent = `For ${$("auFrom").value} to ${$("auTo").value} (UTC, both days included), as chosen above.`; };

  // ---------------- tabs
  const tabs = [...document.querySelectorAll(".au-tabs [data-tab]")];
  const LOG_TABS = new Set(Object.keys(HINTS));
  let current = "overview";
  const work = (tab) => tab === "overview" ? loadOverview : tab === "access" ? loadAccess : tab === "live" ? loadSessions
    : tab === "evidence" ? async () => evPeriod() : () => loadLog(true);
  function show(tab, first) {
    current = tab;
    for (const b of tabs) b.setAttribute("aria-selected", String(b.dataset.tab === tab));
    const pane = LOG_TABS.has(tab) ? "log" : tab;
    for (const p of document.querySelectorAll(".au-pane")) p.hidden = p.id !== `pane-${pane}`;
    if (LOG_TABS.has(tab)) {
      logTab = tab; $("logTitle").textContent = TAB_NAMES[tab]; $("logHint").textContent = HINTS[tab];
      $("logTestsBox").hidden = tab === "system";
    }
    try { history.replaceState(null, "", tab === "overview" ? location.pathname : `#${tab}`); } catch { /* */ }
    const run = () => work(tab)().catch((e) => banner(`Could not load: ${e.message}`, true));
    if (first) return run().finally(() => { $("auLoading")?.remove(); window.LGLoader?.ready(); });
    if (window.LGLoader?.pane) window.LGLoader.pane($(`pane-${pane}`), `Opening ${TAB_NAMES[tab] || tab}…`, run); else run();
  }
  function reloadCurrent() { show(current); }
  for (const b of tabs) b.addEventListener("click", () => show(b.dataset.tab));
  const want = (location.hash || "").slice(1);
  show(tabs.some((b) => b.dataset.tab === want) ? want : "overview", true);
  // the tab counts appear from the start (the overview does not load the log)
  getJSON(`/api/audit/events?tab=none&${per()}&limit=1`).then((d) => {
    document.querySelectorAll("[data-n]").forEach((s) => { s.textContent = fmt((d.counts || {})[s.dataset.n] || 0); });
  }).catch(() => {});
  setInterval(() => { if (current === "live") loadSessions().catch(() => {}); }, 30000);
})();
