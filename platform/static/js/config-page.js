/* SPDX-License-Identifier: AGPL-3.0-only
   SPDX-FileCopyrightText: the Looking Glass contributors */
/* Settings → Configuration (config_page.py): every setting Looking Glass runs with, in plain words. Tuning settings can
   be changed (kept in data/config.json, applied after a restart); security, audit and database settings are shown
   with the .env line to change on the server; secrets only say whether one is set. Built as text, never as HTML. */
(() => {
  "use strict";
  const pane = document.getElementById("tabConfig");
  if (!pane) return;
  const $ = (id) => document.getElementById(id);
  const el = (t, c, x) => { const e = document.createElement(t); if (c) e.className = c; if (x != null) e.textContent = x; return e; };
  const csrf = () => document.querySelector('meta[name="csrf-token"]')?.content || "";
  const fmt = (v) => (typeof v === "number" || /^-?\d+(\.\d+)?$/.test(String(v)) ? Number(v).toLocaleString("en-US") : String(v));
  async function api(url, body) {
    const r = await fetch(url, body === undefined ? { cache: "no-store" } : { method: "POST", credentials: "same-origin",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf() }, body: JSON.stringify(body) });
    const d = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
    return d;
  }

  const body = $("cfBody"), msg = $("cfMsg"), save = $("cfSave"), undo = $("cfUndo"), restart = $("cfRestart"), search = $("cfSearch");
  const say = (t, bad) => { msg.textContent = t || ""; msg.classList.toggle("bad", !!bad); };
  let S = null, loaded = false;
  const edits = new Map();             // key -> the value typed (a string; "" = back to .env or the default)

  function sourceText(i) {
    if (i.source === "this page") return "set on this page";
    if (i.source === ".env") return "from .env";
    if (i.source === "default") return "the default";
    return `from ${i.source}`;
  }

  function row(i) {
    const r = el("div", "cf-row"); r.dataset.find = `${i.key} ${i.label} ${i.help || ""}`.toLowerCase();
    const head = el("div", "cf-head");
    const id = `cf_${i.key}`;
    const lab = el("label", "cf-label", i.label); lab.htmlFor = id;
    head.append(lab, el("span", "cf-key mono", i.key));
    r.append(head);
    if (i.help) r.append(el("small", "muted cf-help", i.help));
    const line = el("div", "cf-line");
    if (i.secret) {
      const v = el("span", `cf-secret ${i.set ? "on" : "off"}`, i.set ? "Set (not shown)" : "Not set");
      v.id = id; line.append(v);
    } else if (i.editable) {
      const inp = el("input", "cf-input"); inp.type = "number"; inp.id = id; inp.min = i.min; inp.max = i.max;
      inp.step = i.kind === "float" ? "any" : "1"; inp.inputMode = i.kind === "float" ? "decimal" : "numeric";
      const shown = edits.has(i.key) ? edits.get(i.key) : (i.saved != null ? i.saved : i.value);
      inp.value = shown;
      inp.setAttribute("aria-describedby", `${id}_meta`);
      // outside its range: marked, and Save stays off (also for a value kept from before a redraw)
      const check = () => {
        const n = Number(inp.value);
        inp.classList.toggle("bad", inp.value !== "" && (!Number.isFinite(n) || n < i.min || n > i.max || (i.kind !== "float" && !Number.isInteger(n))));
      };
      check();
      inp.addEventListener("input", () => {
        const base = i.saved != null ? String(i.saved) : String(i.value);
        if (inp.value === base) edits.delete(i.key); else edits.set(i.key, inp.value);
        check();
        state();
      });
      const back = el("button", "pill-btn cf-back", "Use the default");
      back.type = "button"; back.title = `Forget the value kept here: ${fmt(i.default)} unless .env sets another`;
      back.hidden = i.saved == null;
      // back to the default: the value typed before is gone, so is its "outside its range" mark (2026-11-27 audit: it
      // stayed, and Save stayed off)
      back.addEventListener("click", () => { edits.set(i.key, ""); inp.value = ""; inp.placeholder = `default ${fmt(i.default)}`; check(); state(); });
      line.append(inp, back);
      const meta = el("small", "muted cf-meta",
        `In use: ${fmt(i.value)} (${sourceText(i)}) · default ${fmt(i.default)} · from ${fmt(i.min)} to ${fmt(i.max)}`);
      meta.id = `${id}_meta`;
      r.append(line, meta);
      if (i.pending) r.append(el("small", "cf-pending", `Saved as ${fmt(i.saved ?? `the default`)}: applies after a restart`));
      return r;
    } else {
      const v = el("span", "cf-value mono", i.value === "" ? "(empty)" : String(i.value)); v.id = id;
      line.append(v, el("span", "muted cf-src", sourceText(i)));
      r.append(line);
      if (i.where) {
        r.append(el("small", "muted cf-how", `To change it: ${i.where}. It applies at once, no restart.`));
      } else if (i.env_line) {
        const how = el("small", "muted cf-how");
        how.append("To change it: in ", el("span", "mono", ".env"), " on the server, ", el("code", "mono", i.env_line), ", then restart.");
        r.append(how);
      }
      return r;
    }
    r.append(line);
    return r;
  }

  function draw() {
    const groups = S.groups.filter((g) => S.items.some((i) => i.group === g));
    const out = [];
    for (const g of groups) {
      const items = S.items.filter((i) => i.group === g);
      const box = el("section", "cf-group"); box.dataset.group = g;
      const editable = items.some((i) => i.editable);
      const h = el("h3", null, g);
      h.append(el("span", `cf-kind ${editable ? "edit" : "ro"}`, editable ? "can be changed here" : (g === "Secrets" ? "never shown" : "shown only")));
      box.append(h);
      for (const i of items) box.append(row(i));
      out.push(box);
    }
    body.replaceChildren(...out);
    filter();
    state();
  }

  function state() {
    const bad = [...body.querySelectorAll(".cf-input.bad")].length;
    save.disabled = !edits.size || bad > 0;
    undo.disabled = !edits.size;
    restart.hidden = !(S && S.pending_restart);
    if (edits.size) say(`${edits.size} change${edits.size === 1 ? "" : "s"} not saved yet` + (bad ? "; a value is outside its range" : "."), !!bad);
  }

  function filter() {
    const q = (search.value || "").trim().toLowerCase();
    for (const r of body.querySelectorAll(".cf-row")) r.hidden = !!q && !r.dataset.find.includes(q);
    for (const g of body.querySelectorAll(".cf-group")) g.hidden = ![...g.querySelectorAll(".cf-row")].some((r) => !r.hidden);
  }
  search.addEventListener("input", filter);

  async function load() {
    const work = async () => {
      try { S = await api("/api/admin/config"); draw(); } catch (e) { body.replaceChildren(el("p", "fd-empty", window.LGLoader.errorText(e))); }
    };
    if (window.LGLoader) await window.LGLoader.pane(pane, "Opening the configuration…", work); else await work();
  }

  save.addEventListener("click", async () => {
    const values = {};
    for (const [k, v] of edits) values[k] = v === "" ? null : v;
    save.disabled = true; say("Saving…");
    try {
      S = await api("/api/admin/config", { values });
      edits.clear(); draw();
      say(S.pending_restart ? "Saved. It applies after a restart: use Restart now when it suits (about a minute)." : "Saved.");
    } catch (e) {
      // the buttons back first, then the server's refusal in its own words, so "N changes not saved yet" never hides
      // why the save was refused (2026-11-26); the changes stay in the boxes to correct or undo
      state(); say(window.LGLoader.errorText(e, true), true);
    }
  });
  undo.addEventListener("click", () => { edits.clear(); draw(); say(""); });

  restart.addEventListener("click", async () => {
    if (!confirm("Restart Looking Glass now? Everyone's pages pause for about a minute while the days are loaded again.")) return;
    restart.disabled = true; say("Restarting…");
    try {
      await api("/api/admin/config/restart", {});
    } catch (e) { restart.disabled = false; say(window.LGLoader.errorText(e, true), true); return; }
    window.LGLoader?.busy("Restarting Looking Glass");
    const t0 = Date.now();
    await new Promise((r) => setTimeout(r, 4000));
    for (;;) {                              // back when the service answers again, then the page opens anew
      try { const r = await fetch("/healthz", { cache: "no-store" }); if (r.ok) break; } catch { /* still restarting */ }
      if (Date.now() - t0 > 180000) { say("The service has not come back yet. Check it on the server: journalctl -u looking-glass", true); window.LGLoader?.ready(); return; }
      await new Promise((r) => setTimeout(r, 2000));
    }
    location.hash = "config"; location.reload();
  });

  document.addEventListener("lg:settings-tab", (e) => { if (e.detail === "config" && !loaded) { loaded = true; load(); } });
  window.addEventListener("beforeunload", (e) => { if (edits.size) { e.preventDefault(); e.returnValue = ""; } });
  if (location.hash === "#config" && !loaded && !pane.hidden) { loaded = true; load(); }
})();
