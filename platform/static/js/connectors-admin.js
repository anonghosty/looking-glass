/* SPDX-License-Identifier: AGPL-3.0-only
   SPDX-FileCopyrightText: the Looking Glass contributors */
/* Looking Glass · Settings -> Connectors (connectors.py; the user 2026-11-24).
   The targets (OpenCTI, MISP), each with what it receives, its TLP, on or off, where its key comes from and its last
   send; Add a target: the platform's own steps first (a checklist), then the details, then Test: every check with a
   tick or the fix in plain words; Save appears only after a test that passed, for exactly those values (the server
   checks it too). Turning on, changing or deleting asks for the fresh check every time (loader.js, lg-stepup.js).
   Built with the DOM only: no HTML strings. */
(() => {
  "use strict";
  const pane = document.getElementById("tabConnectors"), box = document.getElementById("cnBody");
  if (!pane || !box) return;
  const csrf = () => document.querySelector('meta[name="csrf-token"]')?.content || "";
  const el = (tag, cls, text) => { const e = document.createElement(tag); if (cls) e.className = cls; if (text != null) e.textContent = text; return e; };
  const btn = (label, cls, fn) => { const b = el("button", `pill-btn ${cls || ""}`.trim(), label); b.type = "button"; b.addEventListener("click", fn); return b; };
  const when = (t) => (t ? new Date(t * 1000).toISOString().slice(0, 16).replace("T", " ") + " UTC" : "never");
  async function api(url, body) {
    const r = await fetch(url, { method: body === undefined ? "GET" : "POST", credentials: "same-origin", cache: "no-store",
      headers: body === undefined ? {} : { "Content-Type": "application/json", "X-CSRF-Token": csrf() },
      body: body === undefined ? undefined : JSON.stringify(body) });
    const j = await r.json().catch(() => ({}));
    if (!r.ok) { const e = new Error(j.error || `Looking Glass answered ${r.status}`); e.data = j; throw e; }
    return j;
  }
  const STEPS = {
    opencti: ["In OpenCTI, create a user only for Looking Glass (for example looking-glass-feed) in a group that can create and update knowledge, nothing more.",
      "Allow that user the markings up to the TLP you will send (TLP:AMBER unless you choose another), and give it a confidence level of about 50.",
      "Data -> Ingestion -> TAXII Push -> +: a TAXII Push ingester owned by that user. Copy the collection's address it shows.",
      "Copy that user's API token (its profile -> API access)."],
    misp: ["In MISP, add a role for Looking Glass (Administration -> Add Role): Add, Tagger and Tag Editor rights only; no publishing, no sync, no admin. (MISP's built-in roles that can create tags can also publish or sync.)",
      "Create a user only for Looking Glass in your organisation, with that role, and an auth key for it (Administration -> Auth keys) restricted to this Looking Glass server's address.",
      "Enable the tlp taxonomy (Event Actions -> Taxonomies), and update the galaxies (Galaxies -> Update Galaxies) so the ATT&CK techniques show as galaxy entries.",
      "Copy MISP's address (it starts with https://) and the auth key."] };
  let D = null;

  async function load() {
    try { D = await api("/api/connectors"); draw(); } catch (e) { box.classList.remove("st-loading"); box.textContent = window.LGLoader.errorText(e); }
  }

  function draw() {
    box.classList.remove("st-loading", "lg-has-logo");
    box.replaceChildren();
    if (!D.vault_ready) {
      const w = el("p", "st-access", "Keys cannot be stored yet: add CONNECTOR_KEY_SECRET to .env (64 random hex characters, for example from: openssl rand -hex 32), then restart Looking Glass. The installer does this on new installations.");
      box.append(w);
    }
    if (!D.sender_installed) {
      box.append(el("p", "st-access", `The sender is not installed yet, so nothing is sent: on the server, run deploy/connectors_timer.sh install (it sends every 15 minutes as its own service, ${D.sender_unit}).`));
    }
    if (!D.targets.length) box.append(el("p", "st-hint", "No connector yet."));
    for (const t of D.targets) box.append(card(t));
    box.append(btn("Add a target", "primary", () => addFlow()));
  }

  function card(t) {
    const c = el("article", "cn-target st-card");
    const head = el("h3", null, `${t.name} · ${t.kind_name}`);
    const state = t.paused ? `Paused: ${t.paused}` : t.on ? "On" : "Off";
    c.append(head, el("p", "st-meta", `${t.address} · TLP:${t.tlp.toUpperCase()} · ${state}`),
      el("p", "st-meta", `Key: ${t.key === ".env" ? `from .env (${t.env_name})` : t.key === "stored" ? `stored, encrypted (never shown; or ${t.env_name} in .env)` : "missing"} · last send: ${t.last && t.last.at ? `${when(t.last.at)} ${t.last.ok ? "ok" : "failed"}` : "never"}`));
    const msg = el("p", "st-msg", ""); msg.setAttribute("role", "status");
    const say = (txt, bad) => { msg.textContent = txt || ""; msg.className = `st-msg ${bad ? "err" : "ok"}`; };
    const act = async (path, body, okText) => {
      say("");
      try { await api(path, body || {}); say(okText); await load(); } catch (e) { say(window.LGLoader.errorText(e, true), true); }
    };
    const row = el("div", "st-row");
    row.append(t.on && !t.paused ? btn("Turn off", "", () => act(`/api/connectors/${t.id}/off`, {}, "Turned off."))
      : btn("Turn on", "primary", () => act(`/api/connectors/${t.id}/on`, {}, "Turned on: the back-fill of 30 days starts with the next send.")));
    row.append(btn("What it receives", "", () => scopeEditor(t, c)));
    const tlp = el("select", "adm-select lg-enhance"); tlp.setAttribute("aria-label", "TLP");
    for (const x of D.tlps) { const o = el("option", null, `TLP:${x.toUpperCase()}`); o.value = x; tlp.append(o); }
    tlp.value = t.tlp;
    tlp.addEventListener("change", () => act(`/api/connectors/${t.id}/tlp`, { tlp: tlp.value }, `TLP:${tlp.value.toUpperCase()} from the next send.`));
    row.append(tlp);
    row.append(btn("New key", "", async () => {
      const k = prompt("The new key (tested before it replaces the old one):"); if (!k) return;
      act(`/api/connectors/${t.id}/key`, { key: k }, "The new key passed and replaced the old one.");
    }));
    // the send log: the newest 30, and when there are more, "30 of N" with a button for all of them (2026-11-26: it
    // stopped at 30 without a word)
    const sends = async (all) => {
      try {
        const j = await api(`/api/connectors/${t.id}/log${all ? `?n=${all}` : ""}`);
        const total = j.totals?.log ?? j.log.length, shown = all ? j.log : j.log.slice(0, 30);
        const ul = el("ul", "cn-log");
        for (const e of shown) ul.append(el("li", null, `${when(e.at)} · ${e.day || ""} · ${e.status}${e.devices != null ? ` · ${e.devices} device(s)` : ""}${e.detail ? ` · ${e.detail}` : ""}`));
        if (!j.log.length) ul.append(el("li", null, "Nothing sent yet."));
        if (total > shown.length) {
          const li = el("li", "cn-log-more", `The newest ${shown.length.toLocaleString()} of ${total.toLocaleString()} entries.`);
          // all of them in one answer up to the server's most (5,000, connectors.LOG_MAX); beyond it the line says so
          if (!all) li.append(" ", btn(`Show all ${total.toLocaleString()}`, "", () => sends(Math.min(total, 5000))));
          ul.append(li);
        }
        c.querySelector(".cn-log")?.remove(); c.append(ul);
      } catch (e) { say(window.LGLoader.errorText(e), true); }
    };
    row.append(btn("Sends", "", () => sends(0)));
    row.append(btn("Delete", "warn", () => { if (confirm(`Delete ${t.name}? Its stored key is deleted too. What was already sent stays on the platform.`)) act(`/api/connectors/${t.id}/delete`, {}, "Deleted."); }));
    const sc = t.scope || {}; const n = Object.keys(sc.networks || {}).length + (sc.cidrs || []).length;
    c.append(el("p", "st-meta", n ? `Receives: ${Object.entries(sc.networks || {}).map(([a, v]) => `AS${a} ${v === "whole" ? "(whole network)" : `(${v.length} block(s))`}`).join(", ")}${(sc.cidrs || []).length ? `; ${(sc.cidrs || []).length} other range(s)` : ""}` : "Receives: nothing ticked yet"), row, msg);
    return c;
  }

  async function scopeEditor(t, c) {
    c.querySelector(".cn-scope")?.remove();
    const wrap = el("div", "cn-scope st-loading", "Loading the constituency's networks…"); c.append(wrap);
    let S;
    try { S = await api("/api/settings"); } catch (e) { wrap.textContent = window.LGLoader.errorText(e); return; }
    wrap.classList.remove("st-loading", "lg-has-logo"); wrap.replaceChildren();
    const sc = JSON.parse(JSON.stringify(t.scope || {})); sc.networks = sc.networks || {}; sc.cidrs = sc.cidrs || [];
    const chosen = new Set(((S.settings || {}).networks || []).map(String));
    const names = {}; for (const n of S.networks || []) for (const a of (n.asns || [n.asn]).filter(Boolean)) names[String(a)] = n.name || n.company || "";
    const asns = chosen.size ? [...chosen] : Object.keys(names);
    wrap.append(el("p", "st-hint", "Only networks and ranges of the constituency. Whole network follows it as it grows; Some address blocks stays exactly as ticked."));
    const tbl = el("table", "st-table"); const tb = tbl.createTBody();
    for (const a of asns.sort((x, y) => Number(x) - Number(y))) {
      const tr = tb.insertRow(); tr.insertCell().textContent = `AS${a} ${names[a] || ""}`;
      const cell = tr.insertCell(); const g = `cn-${t.id}-${a}`;
      for (const [v, label] of [["whole", "Whole network"], ["some", "Some address blocks"], ["none", "Not sent"]]) {
        const l = el("label", "cn-radio"); const r = el("input"); r.type = "radio"; r.name = g; r.value = v;
        r.checked = v === "whole" ? sc.networks[a] === "whole" : v === "some" ? Array.isArray(sc.networks[a]) : !sc.networks[a];
        r.addEventListener("change", async () => {
          tr.nextElementSibling?.classList.contains("cn-blocks") && tr.nextElementSibling.remove();
          if (v === "whole") sc.networks[a] = "whole"; else if (v === "none") delete sc.networks[a];
          else {
            sc.networks[a] = Array.isArray(sc.networks[a]) ? sc.networks[a] : [];
            const sub = tb.insertRow(tr.rowIndex); sub.className = "cn-blocks"; const td = sub.insertCell(); td.colSpan = 2; td.textContent = "Loading the network's blocks…";
            try {
              const b = await api(`/api/settings/address-blocks?asn=${encodeURIComponent(a)}`); td.textContent = "";
              for (const blk of (b.blocks || []).map((x) => x.block || x.cidr || x)) {
                const l2 = el("label", "cn-check"); const cb = el("input"); cb.type = "checkbox"; cb.checked = sc.networks[a].includes(blk);
                cb.addEventListener("change", () => { const s = new Set(sc.networks[a]); cb.checked ? s.add(blk) : s.delete(blk); sc.networks[a] = [...s]; });
                l2.append(cb, ` ${blk}`); td.append(l2);
              }
            } catch (e) { td.textContent = window.LGLoader.errorText(e); }
          }
        });
        l.append(r, ` ${label}`); cell.append(l);
      }
    }
    wrap.append(tbl);
    for (const cidr of (S.settings || {}).cidrs || []) {
      const l = el("label", "cn-check"); const cb = el("input"); cb.type = "checkbox"; cb.checked = sc.cidrs.includes(cidr);
      cb.addEventListener("change", () => { const s = new Set(sc.cidrs); cb.checked ? s.add(cidr) : s.delete(cidr); sc.cidrs = [...s]; });
      l.append(cb, ` ${cidr} (other range)`); wrap.append(l);
    }
    const m = el("p", "st-msg");
    wrap.append(btn("Save what it receives", "primary", async () => {
      for (const [a, v] of Object.entries(sc.networks)) if (Array.isArray(v) && !v.length) delete sc.networks[a];
      try { await api(`/api/connectors/${t.id}/scope`, { scope: sc }); m.textContent = "Saved."; m.className = "st-msg ok"; await load(); }
      catch (e) { m.textContent = window.LGLoader.errorText(e, true); m.className = "st-msg err"; }
    }), m);
  }

  function addFlow() {
    box.querySelector(".cn-add")?.remove();
    const f = el("section", "cn-add st-card"); f.append(el("h3", null, "Add a target"));
    const kind = el("select", "adm-select lg-enhance"); kind.setAttribute("aria-label", "Platform");
    for (const [k, v] of Object.entries(D.kinds)) { const o = el("option", null, v); o.value = k; kind.append(o); }
    const steps = el("ol", "cn-steps"), done = el("input"); done.type = "checkbox"; done.id = "cnDone";
    const drawSteps = () => { steps.replaceChildren(...STEPS[kind.value].map((s) => el("li", null, s))); };
    kind.addEventListener("change", () => { drawSteps(); done.checked = false; form.hidden = true; }); drawSteps();
    const dl = el("label", "cn-check"); dl.append(done, " I have done these steps on the platform");
    const form = el("div", "cn-form"); form.hidden = true;
    done.addEventListener("change", () => { form.hidden = !done.checked; });
    const inp = (label, type, ph) => { const l = el("label", "st-field", label); const i = el("input"); i.type = type; i.placeholder = ph || ""; i.autocomplete = "off"; l.append(i); form.append(l); return i; };
    const name = inp("Name", "text", "e.g. CSIRT OpenCTI"), addr = inp("Address", "url", "e.g. https://platform.example.org"), key = inp("Key (never shown again)", "password", "");
    const tlpL = el("label", "st-field", "TLP"); const tlp = el("select", "adm-select lg-enhance");
    for (const x of D.tlps) { const o = el("option", null, `TLP:${x.toUpperCase()}`); o.value = x; tlp.append(o); }
    tlp.value = "amber"; tlpL.append(tlp); form.append(tlpL);
    const results = el("ul", "cn-checks"), msg = el("p", "st-msg");
    let pass = null;
    const save = btn("Save (off)", "primary", async () => {
      try { await api("/api/connectors", { kind: kind.value, name: name.value, address: addr.value, key: key.value, tlp: tlp.value, pass });
        msg.textContent = "Saved, and off. Tick what it receives, then turn it on."; msg.className = "st-msg ok"; f.remove(); await load(); }
      catch (e) { msg.textContent = window.LGLoader.errorText(e, true); msg.className = "st-msg err"; }
    });
    save.disabled = true;
    // any change after a test needs a new test: the pass is for exactly the tested values
    for (const i of [name, addr, key, tlp, kind]) i.addEventListener("input", () => { pass = null; save.disabled = true; });
    const test = btn("Test", "", async () => {
      results.replaceChildren(); msg.textContent = ""; save.disabled = true; pass = null; test.disabled = true;
      try {
        const j = await api("/api/connectors/test", { kind: kind.value, name: name.value, address: addr.value, key: key.value, tlp: tlp.value });
        for (const c of j.checks) results.append(el("li", c.ok ? "ok" : "err", `${c.ok ? "✓" : "✗"} ${c.text}`));
        if (j.ok) { pass = j.pass; save.disabled = false; msg.textContent = "Every check passed: you may save it."; msg.className = "st-msg ok"; }
        else { msg.textContent = "Fix the step marked ✗ on the platform, then Test again: what you typed stays."; msg.className = "st-msg err"; }
      } catch (e) { msg.textContent = window.LGLoader.errorText(e, true); msg.className = "st-msg err"; }
      finally { test.disabled = false; }
    });
    const row = el("div", "st-row"); row.append(test, save, btn("Cancel", "", () => f.remove()));
    form.append(row, results, msg);
    f.append(kind, el("p", "st-hint", "First, on the platform:"), steps, dl, form);
    box.append(f);
  }

  document.addEventListener("lg:settings-tab", (e) => { if (e.detail === "connectors" && !D) load(); });
  if (location.hash === "#connectors") load();
})();
