/* Looking Glass · PDF reports: download a report built on the server, showing progress on the button. */
(() => {
  "use strict";
  async function download(btn, url) {
    if (btn.disabled) return;
    const label = btn.textContent;
    btn.disabled = true; btn.textContent = "Preparing the report…";
    try {
      const r = await fetch(url, { credentials: "same-origin", cache: "no-store" });
      if (!r.ok) {
        let msg = `${r.status}`;
        try { msg = (await r.json()).error || msg; } catch { /* not JSON */ }
        throw new Error(msg);
      }
      const blob = await r.blob();
      const cd = r.headers.get("Content-Disposition") || "";
      const name = (cd.match(/filename="([^"]+)"/) || [])[1] || "looking-glass-report.zip";
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob); a.download = name;
      document.body.append(a); a.click(); a.remove();
      setTimeout(() => URL.revokeObjectURL(a.href), 4000);
      btn.textContent = "Report downloaded ✓";
      setTimeout(() => { btn.textContent = label; btn.disabled = false; }, 2500);
    } catch (e) {
      btn.textContent = `Report failed: ${e.message} (retry)`; btn.disabled = false;
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
    close.type = "button"; close.setAttribute("aria-label", "Close (the look-up continues)");
    head.append(title, close);
    const intro = el("p", "lk-intro");
    const bar = el("div", "lk-bar"), fill = el("i"); bar.append(fill); bar.setAttribute("role", "progressbar"); bar.setAttribute("aria-valuemin", "0"); bar.setAttribute("aria-valuemax", "100");
    const stats = el("div", "lk-stats");
    const mk = (lbl) => { const d = el("div"), b = el("b", null, "0"); d.append(b, el("span", null, lbl)); stats.append(d); return b; };
    const sDone = mk("done"), sTotal = mk("to look up"), sFail = mk("not checked"), sTime = mk("seconds");
    const now = el("div", "lk-now mono"), log = el("ol", "lk-log mono"), msg = el("p", "lk-msg");
    box.append(head, intro, bar, stats, now, log, msg);
    document.body.append(back, box);
    const hide = () => { box.hidden = true; back.hidden = true; };
    close.addEventListener("click", hide); back.addEventListener("click", hide);
    document.addEventListener("keydown", (e) => { if (e.key === "Escape" && !box.hidden) hide(); });
    win = { box, back, title, intro, fill, bar, sDone, sTotal, sFail, sTime, now, log, msg, show() { box.hidden = false; back.hidden = false; close.focus(); } };
    return win;
  }
  async function run({ kind, values, title, intro, doneText }) {
    const w = build();
    w.title.textContent = title || "Looking up…"; w.intro.textContent = intro || "";
    w.log.replaceChildren(); w.msg.textContent = ""; w.msg.className = "lk-msg"; w.now.textContent = "Starting…";
    w.fill.style.width = "0%"; w.sTotal.textContent = values.length.toLocaleString("en-US"); w.sDone.textContent = "0"; w.sFail.textContent = "0"; w.sTime.textContent = "0";
    w.show();
    const csrf = document.querySelector('meta[name="csrf-token"]')?.content || "";
    const r = await fetch("/api/lookups", { method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf }, body: JSON.stringify({ kind, values }) });
    const j = await r.json().catch(() => ({}));
    if (!r.ok) { w.msg.className = "lk-msg bad"; w.msg.textContent = j.error || `Refused (${r.status})`; w.now.textContent = ""; throw new Error(j.error || `Refused (${r.status})`); }
    let since = 0, misses = 0;
    for (;;) {
      await new Promise((ok) => setTimeout(ok, 700));
      let s;
      try { s = await (await fetch(`/api/lookups/${j.id}?since=${since}`, { credentials: "same-origin", cache: "no-store" })).json(); misses = 0; }
      catch (err) {   // give up after 10 failed polls in a row, so the caller's "(retry)" shows (review 2026-11-13)
        if (++misses < 10) continue;
        w.msg.className = "lk-msg bad"; w.msg.textContent = `Lost contact with the server: ${err.message}`; w.now.textContent = "";
        throw new Error(`lost contact with the server (${err.message})`);
      }
      if (s.error && !s.state) throw new Error(s.error);
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
