/* Looking Glass · Settings → Workers (pipeline_settings.py): the database pipeline's settings, locked until the
   administrator enters their own password; the Shadowserver report API key (write-only, checked with Shadowserver
   before it is kept); the reports held back by the sender check, released after the password. Passwords of the
   mailbox and the database are never shown or edited here. */
(() => {
  "use strict";
  const pane = document.getElementById("tabWorkers");
  if (!pane) return;
  const $ = (id) => document.getElementById(id);
  const el = (t, c, x) => { const e = document.createElement(t); if (c) e.className = c; if (x != null) e.textContent = x; return e; };
  const csrf = () => document.querySelector('meta[name="csrf-token"]')?.content || "";
  const fmt = (n) => Number(n || 0).toLocaleString("en-US");
  async function api(url, body) {
    const r = await fetch(url, body === undefined ? { cache: "no-store" } : { method: "POST", credentials: "same-origin",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf() }, body: JSON.stringify(body) });
    const d = await r.json().catch(() => ({}));
    if (!r.ok) { const e = new Error(d.error || `HTTP ${r.status}`); e.locked = d.locked; throw e; }
    return d;
  }

  // ---------------- the tabs: General (the cards that were there) and Workers
  const tabs = [...document.querySelectorAll(".st-tabs [data-st-tab]")];
  const general = () => [...document.querySelectorAll("#stMain > .st-card, #stMain > .st-access")].filter((x) => !pane.contains(x) && x !== pane);
  let loaded = false;
  function show(which) {
    for (const b of tabs) b.setAttribute("aria-selected", String(b.dataset.stTab === which));
    for (const c of general()) c.classList.toggle("st-tab-off", which !== "general");
    pane.hidden = which !== "workers";
    const bar = $("applyBar"); if (bar) bar.classList.toggle("st-tab-off", which !== "general");
    try { history.replaceState(null, "", which === "workers" ? "#workers" : location.pathname); } catch { /* */ }
    if (which === "workers" && !loaded) { loaded = true; load(); }
  }
  for (const b of tabs) b.addEventListener("click", () => show(b.dataset.stTab));

  // ---------------- state
  let S = null, timer = null;
  const body = $("wkBody"), msg = $("wkMsg");
  const say = (t, bad) => { msg.textContent = t || ""; msg.classList.toggle("bad", !!bad); };

  async function load(keepMsg) {
    try { S = await api("/api/pipeline/settings"); } catch (e) { body.replaceChildren(el("p", "fd-empty", e.message)); return; }
    if (!keepMsg) say("");
    draw();
    loadHeld();
  }

  function field(f, locked) {
    const w = el("label", "st-field wk-field");
    let inp;
    if (f.kind === "bool") {           // the box first, its label beside it, the help underneath (like the sender check)
      inp = el("input"); inp.type = "checkbox"; inp.checked = String(f.value).toLowerCase() === "true";
      inp.dataset.key = f.key; inp.dataset.kind = f.kind; inp.disabled = locked;
      const row = el("span", "check-row wk-check"); row.append(inp, el("span", null, f.label)); w.append(row);
      if (f.help) w.append(el("small", "muted", f.help));
      return w;
    }
    if (f.kind === "choice") {          // one of a few: radio buttons, the value read back by values()
      const box = el("div", "wk-field wk-choice"); box.append(el("span", null, f.label));
      const grp = el("div", "wk-radios"); grp.dataset.key = f.key; grp.dataset.kind = "choice"; grp.setAttribute("role", "radiogroup");
      for (const c of f.choices) {
        const l = el("label", "check-row wk-check"); const r = el("input"); r.type = "radio"; r.name = `wk-${f.key}`; r.value = c.value;
        r.checked = String(f.value) === c.value; r.disabled = locked; l.append(r, el("span", null, c.label)); grp.append(l);
      }
      box.append(grp);
      if (f.help) box.append(el("small", "muted", f.help));
      return box;
    }
    w.append(el("span", null, f.label));
    if (f.kind === "int") {
      inp = el("input", "wk-in mono"); inp.type = "number"; inp.min = f.min; inp.max = f.max; inp.step = 1; inp.value = f.value;
    } else {
      inp = el("input", "wk-in mono"); inp.type = "text"; inp.value = f.value; inp.maxLength = 253; inp.spellcheck = false;
    }
    inp.dataset.key = f.key; inp.dataset.kind = f.kind; inp.disabled = locked;
    w.append(inp);
    if (f.help) w.append(el("small", "muted", f.help + (f.kind === "int" ? ` (${fmt(f.min)}-${fmt(f.max)})` : "")));
    return w;
  }

  function senderFields(f, locked) {
    // MAIL_AUTH as two checkboxes: check the sender; block what does not pass (needs the first)
    const w = el("div", "wk-sender");
    const mk = (id, text, hint) => { const l = el("label", "check-row wk-check"); const c = el("input"); c.type = "checkbox"; c.id = id; c.disabled = locked;
      l.append(c, el("span", null, text)); const box = el("div"); box.append(l, el("small", "muted", hint)); w.append(box); return c; };
    const on = mk("wkAuthOn", "Check the sender of every report (DKIM)",
      "Each report e-mail's signature is verified with the sender's key from DNS and the result recorded (Audit portal → Sender check).");
    const blk = mk("wkAuthBlock", "Block reports that do not pass",
      "A report that is not validly signed by the expected domain is held back (quarantine) and not loaded, until an administrator releases it below.");
    on.checked = f.value !== "off"; blk.checked = f.value === "enforce";
    const sync = () => { if (!on.checked) blk.checked = false; blk.disabled = locked || !on.checked; };
    on.addEventListener("change", sync); sync();
    return w;
  }

  function draw() {
    body.replaceChildren();
    if (!S.found) { body.append(el("p", "fd-empty", S.message)); return; }
    const locked = !S.unlocked;
    // the lock bar
    const lockBar = el("div", `wk-lock ${locked ? "is-locked" : "is-open"}`);
    if (locked) {
      lockBar.append(el("span", null, "Locked. Changing these settings needs your password."));
      const ed = el("button", "lg-btn primary", "Edit"); ed.type = "button"; ed.addEventListener("click", askPassword); lockBar.append(ed);
    } else {
      const left = el("span", null, ""); lockBar.append(left);
      const tick = () => { const s = Math.max(0, S._until - Date.now() / 1000); left.textContent = `Unlocked for ${Math.floor(s / 60)}:${String(Math.floor(s % 60)).padStart(2, "0")}. Saving locks it again.`; if (s <= 0) load(); };
      S._until = S._until || Date.now() / 1000 + S.unlocked_for; clearInterval(timer); timer = setInterval(tick, 1000); tick();
      const lk = el("button", "pill-btn", "Lock now"); lk.type = "button";
      lk.addEventListener("click", async () => { await api("/api/pipeline/lock", {}).catch(() => {}); S._until = 0; clearInterval(timer); load(); });
      lockBar.append(lk);
    }
    body.append(lockBar);
    body.append(el("p", "st-hint", `Mailbox: ${({ imap: "IMAP", gmail_api: "Gmail API", microsoft_graph: "Microsoft Graph" })[S.provider] || S.provider}. `
      + "Mailbox and database passwords are not shown or changed here: they stay in the pipeline's .env, set by the installer. The pipeline uses these settings from its next run."));
    const grid = el("div", "wk-groups");
    for (const g of S.groups) {
      const fs = S.fields.filter((f) => f.group === g.key);
      if (!fs.length) continue;
      const box = el("fieldset", "wk-group"); box.append(el("legend", null, g.label));
      for (const f of fs) box.append(f.key === "MAIL_AUTH" ? senderFields(f, locked) : field(f, locked));
      grid.append(box);
    }
    body.append(grid);
    // changes go to the pipeline as requests: what waits for its next run, and what it did with the last ones
    const pend = S.pending || [], res = S.results || [];
    if (pend.length || res.length) {
      const box = el("div", "wk-requests");
      if (pend.length) {
        box.append(el("h4", null, `Waiting for the pipeline's next run (${pend.length})`));
        const ul = el("ul");
        pend.forEach((r) => ul.append(el("li", null, `${r.at.replace("T", " ").slice(0, 16)} UTC · ${r.by} · ${r.kind === "settings" ? Object.entries(r.values || {}).map(([k, v]) => `${k} → ${v}`).join(", ") : r.kind === "release" ? `release ${r.qid}` : r.values}`)));
        box.append(ul);
      }
      if (res.length) {
        box.append(el("h4", null, "Done by the pipeline"));
        const ul = el("ul");
        res.slice(0, 5).forEach((r) => ul.append(el("li", r.status === "applied" ? null : "bad",
          `${(r.applied_at || "").replace("T", " ").slice(0, 16)} UTC · ${r.status === "applied" ? "applied" : "REFUSED"} · ${r.by} · ${(r.changed || []).join("; ") || r.reason || "nothing changed"}`)));
        box.append(ul);
      }
      body.append(box);
    }
    if (!locked) {
      const acts = el("div", "wk-acts");
      const sv = el("button", "lg-btn primary", "Save the settings"); sv.type = "button"; sv.addEventListener("click", () => save(sv));
      acts.append(sv); body.append(acts);
    }
    drawApi(locked);
  }

  function values() {
    const out = {};
    for (const inp of body.querySelectorAll(".wk-groups [data-key]")) {
      out[inp.dataset.key] = inp.dataset.kind === "bool" ? String(inp.checked)
        : inp.dataset.kind === "choice" ? (inp.querySelector("input:checked")?.value ?? "") : inp.value;
    }
    const on = $("wkAuthOn"), blk = $("wkAuthBlock");
    if (on) out.MAIL_AUTH = !on.checked ? "off" : blk.checked ? "enforce" : "log";
    return out;
  }

  async function save(btn) {
    const v = values();
    const was = Object.fromEntries(S.fields.map((f) => [f.key, String(f.value)]));
    if (v.MAIL_AUTH === "enforce" && was.MAIL_AUTH !== "enforce"
        && !confirm("Block reports that do not pass the sender check?\n\nA report that is not validly signed is then held back and NOT loaded until an administrator releases it. A footer or forwarding rule added on the way also breaks a genuine signature: check the Audit portal's Sender check first.")) return;
    btn.disabled = true; say("Saving…");
    try {
      const d = await api("/api/pipeline/settings", { values: v });
      S._until = 0; clearInterval(timer);
      await load(true);
      say(d.changed.length ? `${d.changed.join(", ")}: ${d.note}` : d.note);
    } catch (e) { say(e.message, true); btn.disabled = false; if (e.locked) load(true); }
  }

  // ---------------- the password, to unlock
  function askPassword() {
    const back = el("div", "st-modal-back"), m = el("section", "st-modal wk-modal");
    m.setAttribute("role", "dialog"); m.setAttribute("aria-modal", "true");
    m.append(el("h2", null, "Your password"), el("p", "st-hint", "Enter the password you sign in with. The settings stay unlocked for 10 minutes, for this session only, and the unlock is written to the audit log."));
    const f = el("form", "wk-pw"); const inp = el("input", "wk-in"); inp.type = "password"; inp.autocomplete = "current-password"; inp.required = true;
    const go = el("button", "lg-btn primary", "Unlock"); go.type = "submit";
    const no = el("button", "pill-btn", "Cancel"); no.type = "button";
    const out = el("p", "wk-err"); out.setAttribute("role", "alert");
    f.append(inp, go, no); m.append(f, out);
    const close = () => { back.remove(); m.remove(); };
    no.addEventListener("click", close); back.addEventListener("click", close);
    f.addEventListener("submit", async (ev) => {
      ev.preventDefault(); go.disabled = true; out.textContent = "";
      try { const d = await api("/api/pipeline/unlock", { password: inp.value }); inp.value = ""; close(); S._until = Date.now() / 1000 + d.unlocked_for; await load(true); say("Unlocked."); }
      catch (e) { out.textContent = e.message; go.disabled = false; inp.select(); }
    });
    document.body.append(back, m); inp.focus();
  }

  // ---------------- the Shadowserver report API key
  function drawApi(locked) {
    const c = $("wkApi"); c.replaceChildren();
    c.append(el("h3", null, "Shadowserver report API"));
    const a = S.api || {};
    const st = el("p", "st-hint");
    st.textContent = a.key_waiting
      ? `A new key and secret, accepted by Shadowserver ${a.checked_at || ""}, wait for the pipeline's next run to be saved (never shown again).`
      : a.key_set
      ? `Key and secret saved (never shown again). Last checked ${a.checked_at || "not yet"}${a.checked_at ? `: ${a.ok ? "accepted" : "NOT accepted"}${a.message ? ` (${a.message})` : ""}` : ""}.`
      : "No key saved. Shadowserver gives each organisation an API key and a secret for its report API.";
    c.append(st);
    const acts = el("div", "wk-acts");
    if (a.key_set) {
      const chk = el("button", "pill-btn", "Check with Shadowserver now"); chk.type = "button";
      chk.addEventListener("click", async () => { chk.disabled = true; try { const d = await api("/api/pipeline/apikey/check", {}); say(d.ok ? d.message : `Not accepted: ${d.message}`, !d.ok); await load(true); } catch (e) { say(e.message, true); chk.disabled = false; } });
      acts.append(chk);
    }
    c.append(acts);
    if (locked) { c.append(el("p", "muted", "Edit (with your password) to enter or replace the key.")); return; }
    const f = el("form", "wk-api"); f.autocomplete = "off";
    const k = el("input", "wk-in mono"); k.placeholder = "API key"; k.autocomplete = "off"; k.spellcheck = false;
    const s = el("input", "wk-in mono"); s.type = "password"; s.placeholder = "Secret"; s.autocomplete = "new-password";
    const go = el("button", "lg-btn", "Check with Shadowserver and save"); go.type = "submit";
    f.append(k, s, go);
    f.addEventListener("submit", async (ev) => {
      ev.preventDefault(); go.disabled = true; say("Asking Shadowserver…");
      try { const d = await api("/api/pipeline/apikey", { key: k.value, secret: s.value }); k.value = s.value = ""; S._until = 0; clearInterval(timer); await load(true); say(`${d.message}. ${d.note} Locked again.`); }
      catch (e) { say(e.message, true); go.disabled = false; }
    });
    c.append(f, el("small", "muted", "Kept only if Shadowserver accepts it; the pipeline then saves it at its next run. Only the key and a signature made with the secret are sent to Shadowserver."));
  }

  // ---------------- held-back reports
  async function loadHeld() {
    const c = $("wkHeld"); c.replaceChildren(el("h3", null, "Reports held back by the sender check"));
    let d; try { d = await api("/api/pipeline/held"); } catch (e) { c.append(el("p", "fd-empty", e.message)); return; }
    if (!d.held.length) { c.append(el("p", "muted", d.mode === "enforce" ? "None held back." : "None held back (blocking is off: reports that do not pass are recorded, not held back).")); return; }
    const t = el("table", "hosts adm-table"); const th = el("thead"); const hr = el("tr");
    ["Held since", "Result", "Why", "From", "Subject", "Files", ""].forEach((x) => hr.append(el("th", null, x))); th.append(hr); t.append(th);
    const tb = el("tbody");
    for (const h of d.held) {
      const tr = el("tr");
      [`${String(h.at || "").replace("T", " ").slice(0, 16)} UTC`, h.result, h.reason, h.from_domain || "?", h.subject, `${h.files} file(s), ${h.links} link(s)`].forEach((x) => tr.append(el("td", null, x)));
      const td = el("td");
      if (h.release_asked) td.append(el("span", "muted", "Release requested: goes through at the pipeline's next run"));
      else {
        const b = el("button", "pill-btn", "Release"); b.type = "button";
        b.addEventListener("click", async () => {
          if (!S.unlocked) { say("Edit (with your password) first, then release.", true); askPassword(); return; }
          if (!confirm(`Release this report?\n\n${h.subject}\n${h.result}: ${h.reason}\n\nIt is loaded like any other at the pipeline's next run. Release only a report you know is genuine.`)) return;
          b.disabled = true;
          try { const r = await api("/api/pipeline/release", { id: h.id }); say(r.note); loadHeld(); } catch (e) { say(e.message, true); b.disabled = false; }
        });
        td.append(b);
      }
      tr.append(td); tb.append(tr);
    }
    t.append(tb); const wrap = el("div", "table-wrap"); wrap.append(t); c.append(wrap);
  }

  show((location.hash || "") === "#workers" ? "workers" : "general");
})();
