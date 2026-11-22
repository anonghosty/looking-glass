/* SPDX-License-Identifier: AGPL-3.0-only
   SPDX-FileCopyrightText: the Looking Glass contributors */
/* Looking Glass · right after signing in (/welcome, signin_welcome.py; the user, 2026-11-19: "it zooms way deep into the
   globe into pitch black and the looking glass animation"). The globe dives in until the screen is black, the Looking
   Glass logo draws itself on the black (LGLoader, loader.js), and the loading screen opens the page the sign-in was for,
   where the same logo carries on until it is ready. Without motion (the person's setting): straight there.
   Loaded BEFORE loader.js: an "arriving" mark left in this tab by an earlier page (lg.arrive) is cleared first, so the
   logo is not shown at once and again after the dive (seen in the preview, 2026-11-19). */
(() => {
  "use strict";
  try { sessionStorage.removeItem("lg.arrive"); } catch { /* private mode */ }
  const next = document.body.dataset.next || "/overview";
  // only a path on this site (the server checked it too; signin_welcome.py)
  const safe = /^\/(?!\/)[^\s\\]*$/.test(next) ? next : "/overview";
  const still = matchMedia("(prefers-reduced-motion: reduce)").matches;
  const start = () => {
    if (still || !window.LGLoader) { location.replace(safe); return; }
    requestAnimationFrame(() => setTimeout(() => document.body.classList.add("diving"), 120));
    // pitch black at ~2 s: the logo draws itself on the black, then the platform opens with it carrying on
    setTimeout(() => window.LGLoader.busy("Opening Looking Glass"), 2050);
    setTimeout(() => window.LGLoader.go(safe, "Opening Looking Glass"), 3300);
  };
  if (document.readyState === "complete") start(); else addEventListener("load", start, { once: true });
})();
