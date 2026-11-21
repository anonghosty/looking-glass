/* Looking Glass · PDF reports: download a report built on the server, showing progress on the button. The download
   itself is the platform's one shared helper (LGLoader.download in loader.js, r89): this only words the button. */
(() => {
  "use strict";
  async function download(btn, url) {
    if (btn.disabled) return;
    const label = btn.textContent;
    const res = await window.LGLoader.download(url, { button: btn, busy: "Preparing the report…", name: "looking-glass-report.zip" });
    if (res.ok) {
      btn.textContent = "Report downloaded ✓"; btn.disabled = true;
      setTimeout(() => { btn.textContent = label; btn.disabled = false; }, 2500);
    } else if (res.message) {
      btn.textContent = `${res.message} (retry)`;
    }
  }
  window.LGPdf = { download };
})();

/* Looking Glass · look-up jobs with a progress window: CVE / issue look-ups and Malpedia look-ups run on the server in
   batches; this window shows the progress bar, the counts and a detailed log while they run. */
(() => {
  "use strict";
  const el = (t, c, x) => { const e = document.createElement(t); if (c) e.className = c; if (x != null) e.textContent = x; return e; };
  let win = null;
  function build() {
    if (win) return win;
    const back = el("div", "lk-back"); back.hidden = true;
    const box = el("section", "lk-modal"); box.hidden = true; box.setAttribute("role", "dialog"); box.setAttribute("aria-modal", "true");
    const head = el("div", "lk-head"), title = el("h2", null, "Looking up…"), close = el("button", "icon-btn", "×");
    close.type = "button"; close.setAttribute("aria-label", "Close (a look-up still running stops)");
    close.title = "Close: a look-up still running stops (the user, 2026-11-19)";
    head.append(title, close);
    const intro = el("p", "lk-intro");
    const bar = el("div", "lk-bar"), fill = el("i"); bar.append(fill); bar.setAttribute("role", "progressbar"); bar.setAttribute("aria-valuemin", "0"); bar.setAttribute("aria-valuemax", "100");
    const stats = el("div", "lk-stats");
    const mk = (lbl) => { const d = el("div"), b = el("b", null, "0"); d.append(b, el("span", null, lbl)); stats.append(d); return b; };
    const sDone = mk("done"), sTotal = mk("to look up"), sFail = mk("not checked"), sTime = mk("seconds");
    const now = el("div", "lk-now mono"), log = el("ol", "lk-log mono"), msg = el("p", "lk-msg");
    box.append(head, intro, bar, stats, now, log, msg);
    document.body.append(back, box);
    // closing the window while a look-up runs STOPS it (the list being gathered, and the server's job): the user,
    // 2026-11-19: "I should be able to close it even when it's loading so it stops searching"
    const hide = () => { box.hidden = true; back.hidden = true; if (win.onClose) win.onClose(); };
    close.addEventListener("click", hide); back.addEventListener("click", hide);
    document.addEventListener("keydown", (e) => { if (e.key === "Escape" && !box.hidden) hide(); });
    win = { box, back, title, intro, fill, bar, sDone, sTotal, sFail, sTime, now, log, msg, onClose: null, show() { box.hidden = false; back.hidden = false; close.focus(); } };
    return win;
  }
  const csrfOf = () => document.querySelector('meta[name="csrf-token"]')?.content || "";
  function stoppedError() { const e = new Error("stopped: the window was closed"); e.stopped = true; return e; }
  // values: the names; or prepare(signal) -> the names, gathered with the window already open (a long list); intro: a
  // text, or (names) -> text. Throws an error with .stopped when the window is closed before the end.
  async function run({ kind, values, prepare, title, intro, doneText }) {
    const w = build();
    const ctrl = new AbortController();
    let jid = null, running = true;
    w.onClose = () => {
      if (!running) return;
      running = false; ctrl.abort();
      if (jid) fetch(`/api/lookups/${jid}/stop`, { method: "POST", credentials: "same-origin", headers: { "X-CSRF-Token": csrfOf() } }).catch(() => {});
    };
    const done = () => { running = false; w.onClose = null; };
    w.title.textContent = title || "Looking up…"; w.intro.textContent = typeof intro === "string" ? intro : "";
    w.log.replaceChildren(); w.msg.textContent = ""; w.msg.className = "lk-msg";
    w.fill.style.width = "0%"; w.sDone.textContent = "0"; w.sFail.textContent = "0"; w.sTime.textContent = "0";
    w.sTotal.textContent = values ? values.length.toLocaleString("en-US") : "…";
    w.now.textContent = prepare ? "Gathering the names in this list… (close to stop)" : "Starting…";
    w.show();
    try {
      if (prepare) {
        try { values = await prepare(ctrl.signal); } catch (err) { if (!running) throw stoppedError(); throw err; }
        if (!running) throw stoppedError();
        w.sTotal.textContent = values.length.toLocaleString("en-US");
        if (typeof intro === "function") w.intro.textContent = intro(values);
        if (!values.length) { w.now.textContent = ""; w.msg.className = "lk-msg"; w.msg.textContent = "No names in this list to look up."; done(); return {}; }
        w.now.textContent = "Starting…";
      }
      const r = await fetch("/api/lookups", { method: "POST", credentials: "same-origin", signal: ctrl.signal, headers: { "Content-Type": "application/json", "X-CSRF-Token": csrfOf() }, body: JSON.stringify({ kind, values }) });
      const j = await r.json().catch(() => ({}));
      if (!r.ok) { w.msg.className = "lk-msg bad"; w.msg.textContent = j.error || `Refused (${r.status})`; w.now.textContent = ""; throw new Error(j.error || `Refused (${r.status})`); }
      jid = j.id;
      if (!running) {                                  // closed while it was being started: stop it at once
        fetch(`/api/lookups/${jid}/stop`, { method: "POST", credentials: "same-origin", headers: { "X-CSRF-Token": csrfOf() } }).catch(() => {});
        throw stoppedError();
      }
      return await follow(w, j, title, doneText, () => running);
    } catch (err) {
      if (err.name === "AbortError" || (!running && !err.stopped && w.box.hidden)) throw stoppedError();
      throw err;
    } finally { done(); }
  }
  async function follow(w, j, title, doneText, alive) {
    let since = 0, misses = 0;
    for (;;) {
      await new Promise((ok) => setTimeout(ok, 700));
      if (!alive()) throw stoppedError();
      let s;
      try { s = await (await fetch(`/api/lookups/${j.id}?since=${since}`, { credentials: "same-origin", cache: "no-store" })).json(); misses = 0; }
      catch (err) {   // give up after 10 failed polls in a row, so the caller's "(retry)" shows (review 2026-11-13)
        if (++misses < 10) continue;
        w.msg.className = "lk-msg bad"; w.msg.textContent = window.LGLoader.errorText(err); w.now.textContent = "";
        throw new Error(window.LGLoader.errorText(err));
      }
      if (s.error && !s.state) throw new Error(s.error);
      if (s.state === "stopped") throw stoppedError();
      since = s.log_len;
      for (const line of s.log) w.log.append(el("li", null, line));
      w.log.scrollTop = w.log.scrollHeight;
      const pct = s.total ? Math.round((100 * s.done) / s.total) : 0;
      w.fill.style.width = `${pct}%`; w.bar.setAttribute("aria-valuenow", String(pct));
      w.sDone.textContent = s.done.toLocaleString("en-US"); w.sFail.textContent = s.failed.toLocaleString("en-US"); w.sTime.textContent = String(s.elapsed);
      w.now.textContent = s.state === "running" ? (s.current ? `Now: ${s.current}` : "Working…") : "";
      if (s.state === "done") {
        w.fill.style.width = "100%"; w.title.textContent = `${title || "Look-up"}: finished`;
        w.msg.className = "lk-msg good"; w.msg.textContent = `Done in ${s.elapsed} s. ${doneText || "The results are shown in the list. You can close this window."}`;
        return s.results || {};
      }
      if (s.state === "failed") { w.msg.className = "lk-msg bad"; w.msg.textContent = `Stopped: ${s.error}`; throw new Error(s.error); }
    }
  }
  window.LGLookup = { run };
})();
