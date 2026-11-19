/* Looking Glass · copying (insider.py, the user's insider package 2026-11-18).
   Text on the pages cannot be selected, copied, cut or dragged out, except in fields people type in. Copying happens
   only through the copy buttons, and every one goes through LGCopy.copy(): it asks the server to record the copy FIRST
   (who, what, which page, sealed with keyed fingerprints) and copies only when that is done. When the copy cannot be
   recorded, nothing is copied (fail closed). A deterrent, said plainly: a technical user can still get round it. */
(() => {
  "use strict";
  if (window.LGCopy) return;
  const root = document.documentElement;
  root.classList.add("lg-nocopy");
  const editable = (n) => {
    const e = n && (n.nodeType === 1 ? n : n.parentElement);
    return !!(e && e.closest && e.closest("input, textarea, select, [contenteditable=''], [contenteditable='true']"));
  };
  let allowed = false;                                   // set only while LGCopy writes a recorded copy
  let told = 0;
  function tell(msg) {
    const now = Date.now(); if (now - told < 2500) return; told = now;
    let t = document.getElementById("lgCopyNote");
    if (!t) { t = document.createElement("div"); t.id = "lgCopyNote"; t.className = "lg-copy-note"; t.setAttribute("role", "status"); document.body.append(t); }
    t.textContent = msg; t.hidden = false;
    clearTimeout(tell.tm); tell.tm = setTimeout(() => { t.hidden = true; }, 3800);
  }
  const NO = "Copying is only through the copy buttons: each copy is recorded under your name.";
  for (const ev of ["copy", "cut"]) {
    document.addEventListener(ev, (e) => {
      if (allowed || editable(e.target) || editable(document.activeElement)) return;
      e.preventDefault(); tell(NO);
    }, true);
  }
  document.addEventListener("dragstart", (e) => { if (!editable(e.target)) { e.preventDefault(); } }, true);

  const csrf = () => document.querySelector('meta[name="csrf-token"]')?.content || "";
  async function write(text) {
    allowed = true;
    try {
      try { await navigator.clipboard.writeText(text); return true; } catch { /* not a secure page, or refused */ }
      const ta = document.createElement("textarea"); ta.value = text; ta.className = "lg-copy-buf"; ta.setAttribute("aria-hidden", "true");
      document.body.append(ta); ta.select(); let ok = false; try { ok = document.execCommand("copy"); } catch { /* */ } ta.remove(); return ok;
    } finally { allowed = false; }
  }
  /* LGCopy.copy({text, what, kind, page}) -> {ok, message}. kind: event, record, addresses, code, indicators, note,
     text, recovery (a person's own recovery codes: recorded, never fingerprinted). */
  async function copy(o) {
    const text = String(o.text ?? "");
    if (!text.trim()) return { ok: false, message: "Nothing to copy." };
    let r, d = {};
    try {
      r = await fetch("/api/copy/record", { method: "POST", headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf() },
        body: JSON.stringify({ kind: o.kind || "text", what: o.what || "", page: o.page || document.title.replace(/^Looking Glass · /, ""),
          text: o.kind === "recovery" ? undefined : text }) });
      d = await r.json().catch(() => ({}));
    } catch { return { ok: false, message: "Not copied: the copy could not be recorded (no connection)." }; }
    if (!r.ok) return { ok: false, message: `Not copied: ${d.error || "the copy could not be recorded"}` };
    const ok = await write(text);
    return ok ? { ok: true, message: "Copied (recorded under your name)" } : { ok: false, message: "Recorded, but the browser refused to copy." };
  }
  window.LGCopy = { copy, tell };
})();
