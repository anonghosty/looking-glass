/* Looking Glass · the quarterly reports (quarterly.py): every kept quarter, on
   - the Executive portal (the management role: the management PDF and summary CSV),
   - the advisory portal (the advisor role: the advisor PDF and their three CSVs),
   - Settings → Quarterly (administrators: only the purge CSV, each accuracy check, the purge's status and "Make it
     again"), with the purge's switch at the top: off until an administrator turns it on after reading what it
     deletes, with their own password (r88).
   Each role downloads only its own files (r89): an admin previewing a portal sees the card with a note instead of the
   downloads. Every card says what is true now (where the quarter stands, the purge's switch today, each quarter's
   purge as it stands, an empty quarter in plain words), as the server words it; the PDFs keep what was true when they
   were made.
   Downloads go through LGLoader.download (loader.js: fetch, then the file; busy on the button; once more on its own
   when Looking Glass could not be reached), never a plain link with a download attribute. Every request here says in
   plain words when Looking Glass could not be reached (a restart), tries again a few times with longer waits, then
   offers Retry; never the browser's own error text.
   The card is #lgQuarterly or #tabQuarterly with data-scope="management|advisor|admin". It shows its loading line
   (LGLoader.card / LGLoader.pane) while it reads. Texts are set as text, never as HTML. Every download is sealed,
   stamped and in the audit log on the server (insider.py, quarterly.py). */
(() => {
  "use strict";
  const box = document.getElementById("lgQuarterly") || document.getElementById("tabQuarterly");
  if (!box) return;
  const scope = box.dataset.scope;
  const API = { management: "/api/mgmt/quarterly", advisor: "/api/advisory/quarterly", admin: "/api/admin/quarterly" }[scope];
  if (!API) return;
  const body = box.querySelector(".q-body") || box;
  const el = (t, c, x) => { const e = document.createElement(t); if (c) e.className = c; if (x != null) e.textContent = x; return e; };
  const csrf = () => document.querySelector('meta[name="csrf-token"]')?.content || "";
  const kb = (n) => (n >= 1048576 ? `${(n / 1048576).toFixed(1)} MB` : `${Math.max(1, Math.round((n || 0) / 1024))} KB`);
  const day = (iso) => {
    if (!iso) return "";
    const d = new Date(`${String(iso).slice(0, 10)}T00:00:00Z`);
    return isNaN(d) ? String(iso) : d.toLocaleDateString("en-GB", { weekday: "long", day: "numeric", month: "long", year: "numeric", timeZone: "UTC" });
  };
  const sleep = (ms) => new Promise((ok) => setTimeout(ok, ms));
  let timer = null, confirmQ = null, drawnOnce = false;

  // ---------------- Looking Glass not reachable (a restart): plain words, a few tries with longer waits, then Retry
  const UNREACH = window.LGLoader?.UNREACHABLE || "Looking Glass could not be reached just now (it may be restarting).";
  const WAITING = `${UNREACH} Trying again…`;
  const isNet = (e) => (window.LGLoader?.unreachable ? window.LGLoader.unreachable(e) : !!e && e.name === "TypeError");
  const WAITS = [2000, 4000, 8000, 15000];
  /** a request and its JSON answer; when no answer came, tries again after 2, 4, 8 and 15 s (onWait says so), then
      throws an error that isNet() knows */
  async function ask(url, opts, onWait) {
    for (let i = 0; ; i++) {
      try {
        const r = await fetch(url, { credentials: "same-origin", ...opts });
        const j = await r.json().catch(() => ({}));
        return { r, j, tries: i };
      } catch (e) {
        if (!isNet(e) || i >= WAITS.length) throw e;
        onWait?.(WAITING);
        await sleep(WAITS[i]);
      }
    }
  }
  const plain = (e) => (isNet(e) ? UNREACH : "That did not work. Try again.");
  const net = el("div", "q-net"); net.setAttribute("role", "status"); net.tabIndex = -1; net.hidden = true;
  body.before(net);
  function showNet(text, retry) {
    const line = box.querySelector(":scope > .lg-pane-loading");       // still opening: the loading line says it
    if (line && !retry) { line.textContent = text; return; }
    net.replaceChildren(el("span", null, text));
    if (retry) {
      const b = el("button", "pill-btn", "Retry"); b.type = "button";
      b.addEventListener("click", () => { net.replaceChildren(el("span", "lg-loading", WAITING)); net.focus(); poll(); });
      net.append(b);
    }
    net.hidden = false;
  }
  const hideNet = () => { net.hidden = true; net.replaceChildren(); };

  // ---------------- the downloads: buttons, through the one shared helper (LGLoader.download)
  function fileButtons(files) {
    const w = el("div", "q-files");
    const msg = el("p", "q-msg q-files-msg"); msg.setAttribute("role", "status");
    for (const f of files) {
      const b = el("button", "pill-btn", f.label); b.type = "button";
      b.title = `${f.name} · downloading it is recorded under your name`;
      b.append(el("small", null, kb(f.bytes)));
      b.addEventListener("click", async () => {
        msg.textContent = ""; msg.classList.remove("bad");
        const res = await window.LGLoader.download(f.url, { button: b, name: f.name, busy: `Downloading ${f.label}…` });
        if (!res.ok && res.message) { msg.textContent = res.message; msg.classList.add("bad"); }
      });
      w.append(b);
    }
    const out = document.createDocumentFragment(); out.append(w, msg);
    return out;
  }

  function row(q, admin, preview) {
    const r = el("div", "q-row");
    const h = el("div", "q-head");
    h.append(el("b", null, q.quarter), el("span", `q-tag ${q.valid ? "valid" : "invalid"}`, q.valid ? "VALID" : "NOT VALID"));
    h.append(el("span", "q-meta", `${q.made ? q.made[0].toUpperCase() + q.made.slice(1) : "Made"} · ${String(q.generated_at || "").replace("T", " ").slice(0, 16)} UTC`));
    r.append(h);
    if (!q.valid) r.append(el("p", "q-why", `Not valid: ${q.why}. Do not rely on these figures until the report is made again and says VALID.`));
    if (q.counted_for) {
      r.append(el("p", "q-meta", `Counted for: ${q.counted_for}.${q.other_constituency
        ? ` That is not the constituency set in Settings now${admin ? ": Make it again counts it for the current one." : "."}` : ""}`));
    }
    if (q.empty_text) r.append(el("p", "q-emptyq", q.empty_text));
    if (q.purge_text) r.append(el("p", "q-meta", q.purge_text));
    if (q.files.length) r.append(fileButtons(q.files));
    else if (!preview) r.append(el("p", "q-meta", "No file of this quarter is kept for you."));
    if (admin) {
      if (q.permit && !(q.purge_result && q.purge_result.outcome === "done")) {
        r.append(el("p", "q-meta", `Purge permit written. Rows the purge would delete, counted when it was made: ${Number(q.rows_purge_deletes || 0).toLocaleString("en-US")}.`));
      }
      const g = el("details", "q-guards");
      const bad = (q.guards || []).filter((x) => !x.ok).length;
      g.append(el("summary", null, bad ? `Accuracy checks: ${bad} failed` : `Accuracy checks: all ${(q.guards || []).length} passed`));
      const ul = el("ul");
      for (const x of q.guards || []) ul.append(el("li", x.ok ? "" : "bad", `${x.ok ? "passed" : "FAILED"} · ${x.name}${x.detail ? ` · ${x.detail}` : ""}`));
      for (const c of q.failed_collections || []) ul.append(el("li", "bad", `could not be read: ${c}`));
      g.append(ul); r.append(g);
    }
    return r;
  }

  // ---------------- what is true now: the purge's switch (the portals) and where the quarter stands (every card)
  function nowBox(d, admin) {
    const w = el("div", "q-now");
    if (!admin && d.purge_state) w.append(el("p", null, d.purge_state));
    for (const t of d.now || []) w.append(el("p", null, t));
    w.append(el("p", "q-meta", admin
      ? "The PDFs and the purge CSV say what was true when each report was made; this page says what is true now."
      : "Each report's PDF says what was true when it was made; this card says what is true now."));
    return w;
  }

  function adminTools(d) {
    const w = el("div", "q-row");
    w.append(el("b", null, "Make it again"));
    w.append(el("p", "q-hint", `Counts an ended quarter again and replaces its kept report, for example once its last day's reports `
      + `are loaded, or after a NOT VALID run. Only ended quarters of the last four with report rows are offered (from the oldest report day in the database on), `
      + `never one whose raw rows were purged. A VALID report made before its purge day writes the purge permit again while the purge is on; a NOT VALID one `
      + `removes it, so nothing is deleted. The timing cannot be changed: `
      + `${d.rules.working_days} working days (Monday to Friday) after the quarter, the purge on the next working day, always keeping the last ${d.rules.keep_days} days.`));
    const t = el("div", "q-tools");
    const sel = el("select", "lg-enhance"); sel.setAttribute("aria-label", "Quarter to make again");
    for (const q of d.can_make || []) { const o = el("option", null, q); o.value = q; sel.append(o); }
    const btn = el("button", "pill-btn", "Make it again"); btn.type = "button";
    const msg = el("span", "q-msg"); msg.setAttribute("role", "status");
    if (d.making) { btn.disabled = true; msg.textContent = `${d.making} is being made…`; msg.classList.add("lg-loading"); }
    else if (d.error) { msg.textContent = d.error; msg.classList.add("bad"); }
    if (!(d.can_make || []).length) { btn.disabled = true; sel.disabled = true; }
    btn.addEventListener("click", async () => {
      const q = sel.value;
      if (confirmQ !== q) { confirmQ = q; btn.textContent = `Make ${q} again: click to confirm`; return; }
      confirmQ = null; btn.disabled = true; msg.className = "q-msg lg-loading"; msg.textContent = `Making ${q}…`;
      try {
        const { r, j, tries } = await ask("/api/admin/quarterly/make", { method: "POST",
          headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf() }, body: JSON.stringify({ quarter: q }) },
        (text) => { msg.textContent = text; });
        // tried again after no answer, and now "being made": the first request did reach Looking Glass
        if (!r.ok && !(r.status === 409 && tries)) {
          msg.className = "q-msg bad"; msg.textContent = j.error || `Looking Glass answered ${r.status}.`;
          btn.disabled = false; btn.textContent = "Make it again"; return;
        }
        poll();
      } catch (e) { msg.className = "q-msg bad"; msg.textContent = plain(e); btn.disabled = false; btn.textContent = "Make it again"; }
    });
    t.append(sel, btn, msg); w.append(t);
    if (!(d.can_make || []).length && d.can_make_note) w.append(el("p", "q-meta", d.can_make_note));
    const p = d.pipeline || {};
    const last = p.last || {};
    w.append(el("p", "q-meta", p.found
      ? `The database pipeline's last purge check${last.at ? ` (${String(last.at).replace("T", " ").slice(0, 16)} UTC)` : ""}: `
        + `${last.outcome ? `${last.quarter || ""} ${last.outcome}${last.why ? `: ${last.why}` : ""}` : "none yet"}.`
        + (p.purged_before ? ` Rows dated before ${day(p.purged_before)} have been purged.` : "")
      : "The database pipeline has not checked for a purge yet (or it runs on another computer)."));
    return w;
  }

  // ---------------- the purge's switch (Settings → Quarterly, r88): off until an administrator turns it on, once, after
  // seeing what it deletes; the Settings permission, CSRF and their own password again (checked on the server)
  const num = (n) => (typeof n === "number" ? `${n.toLocaleString("en-US")} rows` : "an unknown number of rows");
  function whatItDeletes(pv, on) {
    const nx = pv.next || {};
    if (pv.quarter && !pv.passed) {
      return `${on ? `The next purge, on ${day(pv.purge_day)}, deletes` : "Once it is on, the database pipeline deletes"} the raw report rows `
        + `dated before ${day(pv.cutoff)}${on ? "" : ` on ${day(pv.purge_day)}`}: ${num(pv.rows)}, counted when the ${pv.quarter} report was made.`;
    }
    const later = `the next purge is on ${day(nx.purge_day)}, if the ${nx.quarter} report is made and VALID by then: the raw report rows dated before ${day(nx.cutoff)}.`;
    if (pv.quarter) {
      return `The ${pv.quarter} report's purge day (${day(pv.purge_day)}) has passed, so nothing is deleted for it; ${on ? "" : "once it is on, "}${later} `
        + `The ${pv.quarter} report counted ${num(pv.rows)} dated before its own cutoff.`;
    }
    return `No VALID quarterly report yet (none made, or the latest is NOT VALID), so there is no count of the rows it would delete. `
      + (on ? later[0].toUpperCase() + later.slice(1) : `Once it is on, ${later}`);
  }

  function askToSwitch(d, turnOn, opener, say) {
    const p = d.purge, pv = p.preview || {};
    const back = el("div", "st-modal-back"), m = el("section", "st-modal q-modal");
    m.setAttribute("role", "dialog"); m.setAttribute("aria-modal", "true"); m.setAttribute("aria-labelledby", "qPurgeTitle");
    const h = el("h2", null, turnOn ? "Turn on the quarterly purge" : "Turn off the quarterly purge"); h.id = "qPurgeTitle";
    m.append(h);
    if (turnOn) {
      m.append(el("p", "q-hint", "Read what it deletes, and when:"));
      const ul = el("ul", "q-list-plain");
      ul.append(el("li", null, whatItDeletes(pv, false)),
        el("li", null, `Only from the report collections: the rows of the Shadowserver reports the database pipeline loads. The last ${pv.keep_days || 31} days are always kept.`),
        el("li", null, "Never deleted: findings, cases, advisories and the quarterly reports."),
        el("li", null, `After that, once every quarter: ${d.rules.working_days} working days (Monday to Friday) after the quarter ends, on the next working day, when that quarter's report is VALID. The timing cannot be changed.`),
        el("li", null, "Deleted rows cannot be brought back. You can turn the purge off here at any time before a purge day."));
      m.append(ul);
    } else {
      m.append(el("p", "q-hint", "Nothing is deleted while it is off. A waiting purge permit is removed, so a purge that has not run yet does not run"
        + `${pv.permit ? ` (the one on ${day(pv.purge_day)})` : ""}. Turning it on again later needs your password again.`));
    }
    const f = el("form", "wk-pw");
    const lab = el("label", "q-pw-label", "Confirm with the password you sign in with");
    const inp = el("input", "wk-in"); inp.type = "password"; inp.autocomplete = "current-password"; inp.required = true; inp.id = "qPurgePw";
    lab.htmlFor = inp.id;
    const go = el("button", "lg-btn primary", turnOn ? "Turn on the quarterly purge" : "Turn off the quarterly purge"); go.type = "submit";
    const no = el("button", "pill-btn", "Cancel"); no.type = "button";
    const msg = el("p", "q-msg"); msg.setAttribute("role", "status");
    f.append(lab, inp, go, no); m.append(f, msg);
    const close = () => { back.remove(); m.remove(); opener?.focus(); };
    no.addEventListener("click", close); back.addEventListener("click", close);
    m.addEventListener("keydown", (e) => { if (e.key === "Escape") { e.preventDefault(); close(); } });
    f.addEventListener("submit", async (ev) => {
      ev.preventDefault();
      go.disabled = true; no.disabled = true; msg.className = "q-msg lg-loading";
      msg.textContent = turnOn ? "Turning the quarterly purge on" : "Turning the quarterly purge off";
      try {
        const payload = { enabled: turnOn, password: inp.value };
        if (turnOn) payload.shown = { quarter: pv.quarter, rows: pv.rows, purge_day: pv.purge_day || (pv.next || {}).purge_day };
        const { r, j } = await ask("/api/admin/quarterly/purge", { method: "POST",
          headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf() }, body: JSON.stringify(payload) },
        (text) => { msg.textContent = text; });
        if (!r.ok) {
          msg.className = "q-msg bad"; msg.textContent = j.error || `Looking Glass answered ${r.status}.`;
          go.disabled = false; no.disabled = false; inp.value = ""; inp.focus();
          if (r.status === 409 && j.purge) { close(); await load().catch(() => {}); say(j.error, true); }
          return;
        }
        close();
        await load().catch(() => {});
        say(turnOn ? "The quarterly purge is on. It is in the audit log." : "The quarterly purge is off: nothing is deleted. It is in the audit log.");
      } catch (e) { msg.className = "q-msg bad"; msg.textContent = plain(e); go.disabled = false; no.disabled = false; }
    });
    document.body.append(back, m); inp.focus();
  }

  function purgeCard(d) {
    const p = d.purge || { enabled: false, preview: {} };
    const pv = p.preview || {};
    const w = el("div", `q-row q-purge ${p.enabled ? "on" : "off"}`); w.id = "qPurge";
    const h = el("div", "q-head");
    h.append(el("b", null, "The quarterly purge"), el("span", `q-tag ${p.enabled ? "on" : "off"}`, p.enabled ? "ON" : "OFF"));
    w.append(h);
    w.append(el("p", "q-state", p.enabled
      ? `On since ${day(p.since)}, confirmed by ${p.by_name || p.by}.`
      : "The quarterly purge is off on this installation: no report rows are deleted."));
    w.append(el("p", "q-meta", whatItDeletes(pv, p.enabled)));
    w.append(el("p", "q-meta", "The purge works on all networks in the database, not only the constituency: it clears old stored rows. The quarterly reports themselves are counted for the constituency set in Settings."));
    if (!p.enabled) {
      w.append(el("p", "q-hint", "Looking Glass never deletes report rows until an administrator turns the purge on here, once, after reading what "
        + "it deletes. It stays on for every quarter after that, until someone turns it off. Turning it on or off needs your password, and each "
        + "change is in the audit log."));
    }
    const t = el("div", "q-tools");
    const btn = el("button", p.enabled ? "pill-btn" : "lg-btn primary", p.enabled ? "Turn off the quarterly purge" : "Turn on the quarterly purge");
    btn.type = "button"; btn.id = "qPurgeBtn";
    const msg = el("span", "q-msg"); msg.setAttribute("role", "status");
    const say = (text, bad) => {
      const m2 = body.querySelector("#qPurge .q-msg") || msg;
      m2.textContent = text || ""; m2.classList.toggle("bad", !!bad);
    };
    btn.addEventListener("click", () => askToSwitch(d, !p.enabled, btn, say));
    t.append(btn, msg); w.append(t);
    return w;
  }

  function draw(d) {
    body.replaceChildren();
    const admin = scope === "admin";
    if (admin) body.append(purgeCard(d));
    body.append(nowBox(d, admin));
    if (d.note) body.append(el("p", "q-note", d.note));
    if (admin) body.append(adminTools(d));
    const list = el("div", "q-list");
    for (const q of d.quarters || []) list.append(row(q, admin, !!d.note));
    if (!(d.quarters || []).length) list.append(el("p", "q-empty", "No quarterly report is kept yet."));
    body.append(list);
  }

  async function load() {
    let res;
    try {
      res = await ask(API, { cache: "no-store" }, (text) => showNet(text));
    } catch (e) {
      if (!isNet(e)) throw e;
      showNet(UNREACH, true);
      if (!drawnOnce) body.replaceChildren();
      return true;
    }
    hideNet();
    const { r, j: d } = res;
    if (!r.ok) { body.replaceChildren(el("p", "q-empty", d.error || `Could not open the quarterly reports (Looking Glass answered ${r.status}).`)); return true; }
    draw(d); drawnOnce = true;
    clearTimeout(timer);
    if (d.making) timer = setTimeout(poll, 5000);
    return true;
  }
  const failed = () => { body.replaceChildren(el("p", "q-empty", "The quarterly reports could not be opened. Try again in a moment.")); return true; };
  const poll = () => load().catch(failed);

  if (scope === "admin") {
    let opened = false;
    document.addEventListener("lg:settings-tab", (e) => {
      if (e.detail !== "quarterly" || opened) return;
      opened = true;
      window.LGLoader?.pane ? window.LGLoader.pane(box, "Opening the quarterly reports…", () => load().catch(failed)) : poll();
    });
  } else {
    const work = () => load().catch(failed);
    (window.LGLoader?.card ? window.LGLoader.card(box, "Opening the quarterly reports…", work) : work()).then(() => {
      if (location.hash === "#quarterly") box.scrollIntoView({ block: "start" });
    });
  }
})();
