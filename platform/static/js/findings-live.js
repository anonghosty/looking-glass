/* SPDX-License-Identifier: AGPL-3.0-only
   SPDX-FileCopyrightText: the Looking Glass contributors */
/* Looking Glass · findings pages that keep up on their own (findings_live.py; the user, 2026-11-18: a finding sent to
   management did not show on their open Findings page until they refreshed it).
   LGFindingsLive.watch({ refresh, busy }) asks /api/findings/stamp every 15 seconds while the page is in front, and at
   once when it comes back to the front. When the fingerprint changes, someone changed a finding this person sees:
   - refresh(): the page reads it again (the Findings page redraws in place);
   - when busy() says the person is typing or choosing, nothing is thrown away: a notice offers "Show the changes".
   Without refresh, the notice is always shown and its button reloads the page (the review and advisory pages, whose
   embedded views are too heavy to redraw under someone's eyes). */
(() => {
  "use strict";
  const EVERY = 15000;
  let base = null, timer = null, asking = false, opts = null, bar = null;

  function notice() {
    if (bar && document.body.contains(bar)) return;
    bar = document.createElement("div");
    bar.className = "fl-notice"; bar.setAttribute("role", "status");
    const t = document.createElement("span");
    t.textContent = "A finding here has changed since you opened this page.";
    const b = document.createElement("button");
    b.type = "button"; b.className = "lg-btn sm primary"; b.textContent = "Show the changes";
    b.addEventListener("click", () => { bar.remove(); bar = null; if (opts.refresh) opts.refresh(); else location.reload(); });
    bar.append(t, b);
    document.body.append(bar);
  }

  async function check() {
    if (asking || document.hidden) return;
    asking = true;
    try {
      const r = await fetch("/api/findings/stamp", { cache: "no-store", credentials: "same-origin" });
      if (!r.ok) return;                                   // signed out or refused: the page's own requests say so
      const s = (await r.json().catch(() => ({}))).stamp;
      if (!s) return;
      if (base === null) { base = s; return; }
      if (s === base) return;
      base = s;
      if (opts.refresh && !(opts.busy && opts.busy())) opts.refresh(); else notice();
    } catch { /* the connection dropped: the next turn asks again */ }
    finally { asking = false; }
  }

  window.LGFindingsLive = {
    watch(o) {
      opts = o || {};
      base = null; check();                                // the fingerprint of what the page opened with
      clearInterval(timer); timer = setInterval(check, EVERY);
      document.addEventListener("visibilitychange", () => { if (!document.hidden) check(); });
    },
    // after this person's own change: take the new fingerprint as known, so their own action does not ask them to reload
    mine() { base = null; check(); },
  };
})();
