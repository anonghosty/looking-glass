/* SPDX-License-Identifier: AGPL-3.0-only
   SPDX-FileCopyrightText: the Looking Glass contributors */
/* Looking Glass · animated logo for loading and page transitions (shared by all pages).

   1. Loading: every element with class i-loading, stream-empty (while loading) or st-loading gets the animated logo
      in front of its text: the lens moves over lines of records as if searching them, the arc draws and the hit pulses.
   2. Transitions: LGLoader.go(url, label) shows a centred logo that draws itself with "Opening …", then navigates;
      on the next page LGLoader.arrive() shows the same logo and fades it out once the page is ready
      (LGLoader.ready() or after a short maximum). LGLoader.flash(label) is the same within one page
      (the intro opening the map).
   Lite display mode (html.lite, TVs / slow devices) and "reduce motion" get a still logo and no delays. */
(() => {
  "use strict";
  // the session ended (timeout, logout elsewhere, password changed): any API answer 401 goes to the login page,
  // which brings the viewer back to the same place afterwards
  const nativeFetch = window.fetch.bind(window);
  let leaving = false;
  // Looking Glass could not be reached (r90: never the browser's own error text on a page): a READ (GET or HEAD) that
  // got no answer, or a gateway page instead of Looking Glass's answer (502, 503, 504 that is not JSON), is tried again
  // on its own after 2, 4, 8 and 15 s, saying so in plain words in a small line at the foot of the page (or through
  // the caller's lgWait(text)); after the last try that line offers Retry. An ACTION (POST, PUT, PATCH, DELETE) is
  // never sent again on its own: it could be done twice. The page words what happened with LGLoader.errorText.
  const UNREACH = "Looking Glass could not be reached just now (it may be restarting).";
  const WAITING = `${UNREACH} Trying again…`;
  const WAITS = [2000, 4000, 8000, 15000];
  // the browsers' own words for a request that got no answer (Chrome and Edge, Firefox, Safari, older ones), for an
  // answer that was not JSON (a gateway or sign-in page instead of Looking Glass's answer) and a gateway's status line
  const NET_RE = /^(Failed to fetch|NetworkError when attempting to fetch resource|Load failed|Network request failed|The network connection was lost|The Internet connection appears to be offline|A network error occurred|net::ERR_)/i;
  const JSON_RE = /" is not valid JSON|^Unexpected token|^Unexpected end of JSON input|^Unexpected non-whitespace character|^JSON\.parse:|^JSON Parse error|^The string did not match the expected pattern|^Unrecognized token/i;
  const GATEWAY_RE = /^50[234]\b/;
  const msgOf = (e) => (typeof e === "string" ? e : String((e && e.message) || ""));
  /** true when no usable answer came from Looking Glass: no answer at all, or something that is not its JSON */
  function lost(e) {
    if (!e) return false;
    const m = msgOf(e);
    return e.unreachable === true || e.name === "SyntaxError" || e.name === "TimeoutError"
      || NET_RE.test(m) || JSON_RE.test(m) || GATEWAY_RE.test(m);
  }
  const sleep = (ms) => new Promise((ok) => setTimeout(ok, ms));
  // the line at the foot of the page while reads are being tried again (built with the DOM: no HTML, no inline style
  // attribute; the CSSOM is allowed by the page's Content-Security-Policy)
  let netBar = null, netWaiting = 0;
  function netLine(text, retry) {
    if (!document.body) return;
    if (!netBar) {
      netBar = document.createElement("div"); netBar.className = "lg-net-bar"; netBar.setAttribute("role", "status");
      Object.assign(netBar.style, { position: "fixed", left: "50%", bottom: "16px", transform: "translateX(-50%)", zIndex: "2147483000",
        maxWidth: "calc(100vw - 32px)", boxSizing: "border-box", display: "flex", gap: "10px", alignItems: "center", flexWrap: "wrap",
        padding: "8px 14px", borderRadius: "10px", background: "#1d1d22", color: "#ededef", border: "1px solid #3a3a42",
        boxShadow: "0 6px 24px rgba(0,0,0,.35)", font: "14px/1.4 system-ui, sans-serif" });
    }
    const span = document.createElement("span"); span.textContent = text;
    netBar.replaceChildren(span);
    if (retry) {
      const b = document.createElement("button"); b.type = "button"; b.className = "pill-btn"; b.textContent = "Retry";
      b.title = "Opens this page again, which reads everything again";
      b.addEventListener("click", () => { span.textContent = WAITING; b.disabled = true; location.reload(); });
      netBar.append(b);
    }
    if (!netBar.isConnected) document.body.append(netBar);
  }
  const netHide = () => { if (netBar && !netWaiting) netBar.remove(); };
  window.fetch = async (input, init) => {
    const opts = init || {};
    const method = String(opts.method || (input instanceof Request ? input.method : "GET")).toUpperCase();
    const again = (method === "GET" || method === "HEAD") && opts.lgRetry !== false;
    const onWait = typeof opts.lgWait === "function" ? opts.lgWait : null;
    let r = null, waited = false;
    try {
      for (let i = 0; ; i++) {
        let failed = null;
        try {
          r = await nativeFetch(input, init);
          if (again && i < WAITS.length && [502, 503, 504].includes(r.status) && !/json/i.test(r.headers.get("Content-Type") || "")) failed = "gateway";
        } catch (e) {
          if (!again || !lost(e) || opts.signal?.aborted) throw e;
          if (i >= WAITS.length) {
            const out = new Error(UNREACH); out.unreachable = true; out.lgTried = true; out.cause = e;
            throw out;
          }
          failed = e;
        }
        if (!failed) break;
        if (onWait) onWait(WAITING);
        else { if (!waited) netWaiting++; netLine(WAITING); }
        waited = true;
        await sleep(WAITS[i]);
        if (opts.signal?.aborted) throw new DOMException("The request was stopped.", "AbortError");
      }
    } catch (e) {
      if (waited && !onWait) { netWaiting--; if (e && e.lgTried) netLine(UNREACH, true); else netHide(); }
      throw e;
    }
    if (waited && !onWait) netWaiting--;
    if (r.ok) netHide();                         // Looking Glass answers again: the line goes
    else if (waited && !onWait && r.status >= 500) netLine(UNREACH, true);
    // a high-value action asks for a fresh check first (stepup.py, the user 2026-11-24): the person confirms with a
    // passkey or an authenticator code in a small dialog (lg-stepup.js), then the same request is sent once more,
    // with the one-time grant for an action that asks every time. Cancelled or failed: the refusal stands.
    if (r.status === 403 && !opts.lgStepupDone && /json/i.test(r.headers.get("Content-Type") || "")) {
      const info = await r.clone().json().catch(() => null);
      if (info && info.stepup && window.LGStepUp?.ask) {
        const path = new URL(input instanceof Request ? input.url : String(input), location.href).pathname;
        const res = await window.LGStepUp.ask(info, { method, path });
        if (res && res.ok) {
          const headers = new Headers(opts.headers || (input instanceof Request ? input.headers : undefined));
          if (res.grant) headers.set("X-LG-Stepup", res.grant);
          return window.fetch(input, { ...opts, headers, lgStepupDone: true });
        }
      }
    }
    if (r.status === 401 && !leaving) {
      leaving = true;
      location.href = `/login?next=${encodeURIComponent(location.pathname + location.search)}`;
    }
    return r;
  };
  const calm = () => document.documentElement.classList.contains("lite") || matchMedia("(prefers-reduced-motion: reduce)").matches;
  let uid = 0;
  // the logo: lens (with records scrolling inside while searching), arc to the hit, pulsing ring, rim and handle
  function svg(size = 28) {
    const id = `lgl${++uid}`;
    return `<svg class="lg-logo" width="${size}" height="${size}" viewBox="0 0 32 32" aria-hidden="true">
      <defs>
        <linearGradient id="${id}a" x1="8" y1="18" x2="20" y2="11" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="#5b8def"/><stop offset="1" stop-color="#e5484d"/></linearGradient>
        <clipPath id="${id}c"><circle cx="14" cy="14" r="8.9"/></clipPath>
      </defs>
      <circle cx="14" cy="14" r="8.9" fill="#141417"/>
      <g clip-path="url(#${id}c)">
        <g class="lgl-records" fill="#5b8def">
          <rect x="7" y="7" width="11" height="1.3" rx=".6" opacity=".55"/><rect x="7" y="10.5" width="14" height="1.3" rx=".6" opacity=".35"/>
          <rect x="7" y="14" width="9" height="1.3" rx=".6" opacity=".55"/><rect x="7" y="17.5" width="13" height="1.3" rx=".6" opacity=".35"/>
          <rect x="7" y="21" width="10" height="1.3" rx=".6" opacity=".55"/><rect x="7" y="24.5" width="12" height="1.3" rx=".6" opacity=".35"/>
          <rect x="7" y="28" width="11" height="1.3" rx=".6" opacity=".55"/><rect x="7" y="31.5" width="14" height="1.3" rx=".6" opacity=".35"/>
        </g>
        <g fill="none" stroke="#ededef" stroke-opacity=".16" stroke-width=".8"><ellipse cx="14" cy="14" rx="9" ry="3.4"/><ellipse cx="14" cy="14" rx="3.6" ry="9"/></g>
      </g>
      <path class="lgl-arc" d="M8.4 18.2 Q12.4 6.6 19.4 11.6" fill="none" stroke="url(#${id}a)" stroke-width="1.7" stroke-linecap="round" pathLength="100"/>
      <circle cx="8.4" cy="18.2" r="1.5" fill="#5b8def"/>
      <circle class="lgl-ring" cx="19.4" cy="11.6" r="2.7" fill="none" stroke="#e5484d" stroke-width=".8"/>
      <circle cx="19.4" cy="11.6" r="1.5" fill="#e5484d"/>
      <circle class="lgl-rim" cx="14" cy="14" r="10" fill="none" stroke="#ededef" stroke-width="2" pathLength="100"/>
      <path class="lgl-handle" d="M21.4 21.4 L27.6 27.6" stroke="#ededef" stroke-width="3" stroke-linecap="round" pathLength="100"/>
    </svg>`;
  }

  // ---- 1. loading messages get the searching logo
  // svc-loading, kbn-loading, mp-loading: the services, notes and Malpedia panes' own lines (2026-11-15: they had no logo)
  const SELECTOR = ".i-loading, .st-loading, .stream-empty, .lg-loading, .svc-loading, .kbn-loading, .mp-loading";
  function decorate(node) {
    if (!node || node.querySelector?.(":scope > .lg-logo-wrap")) return;
    if (node.classList.contains("stream-empty") && !/waiting|loading/i.test(node.textContent)) return;
    const wrap = document.createElement("span"); wrap.className = "lg-logo-wrap searching"; wrap.innerHTML = svg(node.classList.contains("i-loading") ? 34 : 26);
    node.prepend(wrap);
    node.classList.add("lg-has-logo");
  }
  function scan(root) {
    if (!(root instanceof Element)) return;
    if (root.matches(SELECTOR)) decorate(root);
    for (const n of root.querySelectorAll(SELECTOR)) decorate(n);
  }
  const mo = new MutationObserver((list) => {
    for (const m of list) {
      for (const n of m.addedNodes) scan(n);
      if (m.type === "characterData" || m.type === "childList") {
        const t = m.target instanceof Element ? m.target : m.target.parentElement;
        if (t && t.matches?.(SELECTOR)) decorate(t);
      }
    }
  });
  function start() { scan(document.body); mo.observe(document.body, { childList: true, subtree: true, characterData: true }); }
  if (document.body) start(); else document.addEventListener("DOMContentLoaded", start);

  // ---- 2. page transitions with the drawing logo
  function overlay() {
    let o = document.getElementById("lgTransition");
    if (!o) {
      o = document.createElement("div"); o.id = "lgTransition"; o.className = "lg-transition"; o.setAttribute("role", "status");
      o.innerHTML = `<div class="lg-transition-box"><span class="lg-logo-wrap drawing">${svg(84)}</span><div class="lg-transition-label"></div><div class="lg-transition-sub">Looking Glass</div></div>`;
      document.body.append(o);
    }
    return o;
  }
  // the logo draws itself ONCE (2026-11-15: "it seems it loads twice"): already on screen, only its words change; arriving
  // from another page (which drew it as it left) it carries on, already drawn, instead of drawing again
  function show(label, carryOn) {
    const o = overlay(); o.querySelector(".lg-transition-label").textContent = label || "";
    const w = o.querySelector(".lg-logo-wrap");
    const already = o.classList.contains("on") && !o.classList.contains("leaving");
    o.classList.remove("leaving"); o.classList.add("on");
    if (already) return o;
    if (carryOn) { w.classList.remove("drawing"); w.classList.add("searching"); return o; }
    w.classList.remove("searching", "drawing"); void w.offsetWidth; w.classList.add("drawing");
    return o;
  }
  function hide() {
    const o = document.getElementById("lgTransition"); if (!o || !o.classList.contains("on")) return;
    o.classList.add("leaving");
    setTimeout(() => o.classList.remove("on", "leaving"), calm() ? 0 : 520);
  }
  const LABELS = { "/advisory/": "Opening the advisory", "/advisory": "Opening the advisory portal", "/findings": "Opening the findings",
    "/review/": "Opening the review", "/combinations": "Opening the combination search", "/management": "Opening the Executive portal",
    "/intel/": "Opening the analyst's selection", "/intelligence": "Opening Abused or Compromised", "/audit": "Opening the Audit portal", "/overview": "Opening the overview",
    "/services": "Opening publicly accessible / vulnerable services", "/settings": "Opening settings",
    "/definitions": "Opening definitions and intel", "/admin": "Opening administration", "/?intro": "Opening the overview", "/": "Opening reported network communications" };
  const labelFor = (url) => LABELS[Object.keys(LABELS).find((k) => url.startsWith(k) && (k !== "/" || url === "/" || url.startsWith("/?") && !url.startsWith("/?intro")))] || "Opening";
  let arrived = null, arriveTimer = null, ownedByWait = false, cameDrawn = 0;
  const pending = new Set();       // the cards still loading as the page opens (LGLoader.wait)
  window.LGLoader = {
    /** a card that loads when the page opens (2026-11-15: "any card loading with data uses the loading animation, so
        cards never break"): the page's logo stays until it, and every other card registered this way, has its data,
        so nothing pops in, grows or is drawn twice in front of the reader. On a reload (no logo yet) it starts the
        logo itself. Returns the promise it was given. */
    wait(p, label) {
      // never longer than 15 s for one card: a request that hangs must not keep the page covered
      const q = Promise.race([Promise.resolve(p).catch(() => {}), new Promise((r) => setTimeout(r, 15000))]);
      pending.add(q);
      if (arrived == null) { window.LGLoader.busy(label || "Loading"); ownedByWait = true; }
      q.finally(() => {
        pending.delete(q);
        if (!pending.size && ownedByWait) { ownedByWait = false; window.LGLoader.ready(); }
      });
      return p;
    },
    svg,
    /** leave for another page with the logo animation */
    go(url, label) {
      // a place on THIS page (only the #part differs, e.g. the bell's /settings#monitor while on Settings): the browser
      // would only scroll, nothing would arrive to take the logo down (2026-11-25: stuck on "Opening settings"). Open
      // the page again at that place instead, without the logo.
      const u = new URL(url, location.href);
      if (u.origin === location.origin && u.pathname === location.pathname && u.search === location.search) {
        if (u.hash && u.hash !== location.hash) location.hash = u.hash;
        location.reload();
        return;
      }
      const text = label || labelFor(url);
      try { sessionStorage.setItem("lg.arrive", text); } catch { /* private mode */ }
      show(text);
      setTimeout(() => { location.href = url; }, calm() ? 0 : 700);
    },
    /** on arrival: keep showing the logo until the page is ready (or at most ~1.6 s) */
    arrive() {
      let text = null;
      try { text = sessionStorage.getItem("lg.arrive"); sessionStorage.removeItem("lg.arrive"); } catch { /* */ }
      if (!text) return;
      cameDrawn = Date.now();       // the last page drew the logo: a busy() in the next moments carries it on
      // a page with its own loading line (st-loading, i-loading, lg-loading) shows that, with the searching logo: the
      // opening logo again on top of it would look like a second load
      // (only a line that is showing: the platforms keep a hidden one in their insight panel, which used to stop the
      // logo on / and /services altogether; 2026-11-15)
      if ([...document.querySelectorAll(".st-loading, .i-loading, .lg-loading")].some((e) => e.offsetParent !== null)) return;
      arrived = Date.now(); show(text, true);      // the same logo the last page drew, carrying on
      arriveTimer = setTimeout(() => window.LGLoader.ready(), calm() ? 0 : 1600);
    },
    /** the page has its data: let the logo finish (at least ~0.7 s on screen) and fade into the platform */
    ready() {
      if (arrived == null) return;
      if (pending.size) {                          // cards still loading: the logo stays until they are in
        Promise.allSettled([...pending]).then(() => window.LGLoader.ready());
        return;
      }
      const wait = calm() ? 0 : Math.max(0, 700 - (Date.now() - arrived));
      arrived = null; clearTimeout(arriveTimer);
      setTimeout(hide, wait);
    },
    /** a card that fills itself from the server (2026-11-15: "any card loading with data uses the loading animation,
        so cards never break"): it is shown at once with its loading line, its body hidden, and only drawn when
        everything it needs has come; hidden again if work() says there is nothing for this person (returns false) */
    async card(el, label, work) {
      if (!el) return work();
      el.hidden = false;
      let shown;
      await window.LGLoader.pane(el, label, async () => { shown = await work(); });
      if (shown === false) el.hidden = true;
      return shown;
    },
    /** within one page while data loads: the drawing logo until ready() (at least ~0.7 s on screen) */
    busy(label) {
      // arriving from another page, the first busy() carries on the logo that page drew (it does not draw again)
      const carry = cameDrawn && Date.now() - cameDrawn < 4000; cameDrawn = 0;
      clearTimeout(arriveTimer); arrived = Date.now(); show(label, carry);
      arriveTimer = setTimeout(() => window.LGLoader.ready(), 20000);
    },
    /** within one page (intro -> map): logo, then the platform appears */
    flash(label, ms = 900) {
      show(label); setTimeout(hide, calm() ? 0 : ms);
    },
    /** a tab or pane that loads its data: its loading line with the searching logo under the heading, the rest of the
        pane hidden, until work() settles (at least ~0.45 s, so a quick answer does not just flicker) */
    async pane(el, label, work) {
      if (!el) return work();
      el.querySelector(":scope > .lg-pane-loading")?.remove();
      const line = document.createElement("div"); line.className = "st-loading lg-pane-loading"; line.setAttribute("role", "status");
      line.textContent = label || "Loading…";
      const head = el.querySelector(":scope > header, :scope > h2"); if (head) head.after(line); else el.prepend(line);
      el.classList.add("lg-pane-busy");
      const t0 = Date.now();
      try { return await work(); } finally {
        const wait = calm() ? 0 : Math.max(0, 450 - (Date.now() - t0));
        await new Promise((r) => setTimeout(r, wait));
        line.remove(); el.classList.remove("lg-pane-busy");
      }
    },
    hide,
    /** the plain words when the server could not be reached (a restart, a dropped connection), never the browser's
        own "Failed to fetch" */
    UNREACHABLE: UNREACH,
    /** the same while a read is tried again on its own (2, 4, 8, 15 s) */
    WAITING,
    /** an action (save, send, approve…) that got no usable answer: never sent again on its own (it could be done twice) */
    NOT_DONE: "Looking Glass could not be reached (it may be restarting), so this may not have been done. Try again in a moment; if you are not sure, open the page again to check first.",
    /** true for an error that means the request never got an answer (fetch's TypeError), not a refusal */
    unreachable(e) { return !!e && (e.name === "TypeError" || e.unreachable === true); },
    /** true when no usable answer came from Looking Glass: none at all (the browser's "Failed to fetch", "NetworkError
        when attempting to fetch resource.", "Load failed"), or one that is not its JSON (a gateway page) */
    lost,
    /** The words a page shows for a caught error (r90: one shared function, tests/check_error_text.py). The server's
        own message (an Error the page made from its JSON "error") is kept as it is; the browser's own text never
        reaches the page: no answer or no JSON answer gives UNREACHABLE for a read and NOT_DONE for an action
        (action = true: the person clicked to change something); a fault in the page's script gives plain words. */
    errorText(e, action) {
      if (lost(e)) return action ? window.LGLoader.NOT_DONE : UNREACH;
      const m = msgOf(e).trim();
      const own = typeof e === "string" || !!e && (!e.name || e.name === "Error");     // words a page or the server wrote
      if (own && m) return m;
      return action ? "That did not work, so it may not have been done. Try again in a moment." : "Something went wrong on this page. Open it again to try once more.";
    },
    /** a request and its JSON answer ({r, j, tries}; j is {} when the answer is not JSON): a read is tried again on its
        own after 2, 4, 8 and 15 s when Looking Glass could not be reached (onWait(text) says so meanwhile, instead of
        the line at the foot of the page), then it throws an error that lost() knows; an action is sent once */
    async ask(url, opts, onWait) {
      let tries = 0;
      const r = await fetch(url, { credentials: "same-origin", ...opts, lgWait: (text) => { tries++; onWait?.(text); } });
      const j = await r.json().catch(() => ({}));
      return { r, j, tries };
    },
    /** a file from the server (r89, the user 2026-11-21: quarterly downloads failed with "Network error"): through
        fetch, a blob and a temporary link, never a plain <a href download> (on a self-signed certificate the browser's
        download manager makes its own request, which often fails before it reaches Looking Glass). The button shows
        that it is busy; the file name comes from Content-Disposition; when Looking Glass could not be reached it tries
        once more on its own. The server seals, stamps and audit-logs the file as before (the same route).
        Returns {ok, message}: message is plain words for the page to show. */
    /** Every download of the platform goes through here (r89: one shared function, tests/check_downloads.py).
        options: button (shown busy), busy (its words meanwhile), name (when the server gives none), method, body and
        headers (a POST with the CSRF token). Returns {ok, message, status, data, headers, name}: message is plain
        words for the page to show (empty on success); status and data (the server's JSON answer) let a page act on a
        refusal itself (a search that expired, a review that is not decided yet); headers and blob are the file's
        response headers and content (the Audit portal shows the package's head and SHA-256). */
    async download(url, { button, name, busy, method, body, headers } = {}) {
      const b = button || null;
      if (b && b.getAttribute("aria-busy") === "true") return { ok: false, message: "" };
      const kept = b ? [...b.childNodes] : [];
      if (b) {
        b.setAttribute("aria-busy", "true"); b.disabled = true;
        b.classList.add("lg-loading"); b.textContent = busy || "Downloading…";
      }
      const restore = () => {
        if (!b) return;
        b.classList.remove("lg-loading", "lg-has-logo"); b.replaceChildren(...kept);
        b.disabled = false; b.removeAttribute("aria-busy");
      };
      try {
        const r = await window.LGLoader.fetchOnceMore(url, { method: method || "GET", body, headers, credentials: "same-origin", cache: "no-store" });
        if (!r.ok) {
          let data = {};
          try { data = (await r.json()) || {}; } catch { /* not JSON */ }
          return { ok: false, status: r.status, data, message: window.LGLoader.downloadMessage(null, data.error || `Looking Glass answered ${r.status}`) };
        }
        const blob = await r.blob();
        const file = window.LGLoader.fileName(r.headers.get("Content-Disposition")) || name || "looking-glass-download";
        window.LGLoader.saveBlob(blob, file);
        return { ok: true, status: r.status, message: "", headers: r.headers, name: file, blob };
      } catch (e) {
        return { ok: false, status: 0, message: window.LGLoader.downloadMessage(e) };
      } finally { restore(); }
    },
    /** the data for a file the page builds itself (a drill-down list saved as CSV with saveBlob): fetched like
        download(), once more when Looking Glass could not be reached, with the same plain words.
        Returns {ok, status, data, message}. */
    async fetchForFile(url) {
      try {
        const r = await window.LGLoader.fetchOnceMore(url, { credentials: "same-origin", cache: "no-store" });
        let data = {};
        try { data = (await r.json()) || {}; } catch { /* not JSON */ }
        if (!r.ok) return { ok: false, status: r.status, data, message: window.LGLoader.downloadMessage(null, data.error || `Looking Glass answered ${r.status}`) };
        return { ok: true, status: r.status, data, message: "" };
      } catch (e) {
        return { ok: false, status: 0, data: {}, message: window.LGLoader.downloadMessage(e) };
      }
    },
    /** fetch, trying once more on its own when Looking Glass could not be reached (a restart takes seconds) */
    async fetchOnceMore(url, opts) {
      let r = null;
      for (let attempt = 0; attempt < 2 && !r; attempt++) {
        try { r = await fetch(url, opts); }
        catch (e) {
          if (!window.LGLoader.unreachable(e) || attempt || e.lgTried) throw e;     // lgTried: a read already tried 2, 4, 8, 15 s
          await new Promise((ok) => setTimeout(ok, 1500));
        }
      }
      return r;
    },
    /** the plain words for a download that did not finish: e (an error thrown) or why (the server's own words) */
    downloadMessage(e, why) {
      if (why) return `The download did not finish: ${why}`;
      return window.LGLoader.unreachable(e)
        ? "The download did not finish: Looking Glass could not be reached (it may be restarting). Try again."
        : "The download did not finish. Try again.";
    },
    /** the file name in a Content-Disposition header: filename* (RFC 6266, UTF-8) first, then filename="…" or filename=… */
    fileName(cd) {
      const h = cd || "";
      const star = /filename\*\s*=\s*([^']*)'[^']*'([^;]+)/i.exec(h);
      if (star) {
        try { return decodeURIComponent(star[2].trim().replace(/^"|"$/g, "")); } catch { /* badly encoded: the plain name */ }
      }
      const quoted = /filename\s*=\s*"((?:[^"\\]|\\.)*)"/i.exec(h);
      if (quoted) return quoted[1].replace(/\\(.)/g, "$1");
      const bare = /filename\s*=\s*([^;\s]+)/i.exec(h);
      return bare ? bare[1] : "";
    },
    /** save a file made in the browser (a drill-down list as CSV) or fetched by download(): a temporary link, removed */
    saveBlob(blob, file) {
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob); a.download = file || "looking-glass-download"; a.hidden = true;
      document.body.append(a); a.click(); a.remove();
      setTimeout(() => URL.revokeObjectURL(a.href), 4000);
    },
    /** a path that answers with a file, never a page: the loader's link handling leaves it alone */
    isDownload(path) {
      return /\.(pdf|csv|zip|json|txt|png|svg)$/i.test(path) || /\/(report|preview|export|download|file)(\/|$)/.test(path);
    },
  };
  if (document.body) window.LGLoader.arrive(); else document.addEventListener("DOMContentLoaded", () => window.LGLoader.arrive());
  // Back (or Forward) to a page the browser kept as it was, the leaving logo still on it (2026-11-25: Back "hangs on
  // the loading screen"): take it down, and forget the label the next page would have carried on
  window.addEventListener("pageshow", (e) => {
    if (!e.persisted) return;
    try { sessionStorage.removeItem("lg.arrive"); } catch { /* private mode */ }
    const o = document.getElementById("lgTransition");
    if (o) o.classList.remove("on", "leaving");
  });

  // every page opens with the logo animation: the header's page buttons (templates/_page_nav.html) and any other link
  // to a page of the platform
  document.addEventListener("click", (e) => {
    // the page buttons of the platforms' headers and the overview too (account-btn: Executive, Admin, Definitions,
    // Combinations, Findings), so every page opens with the logo, also one without a loading line of its own
    // (Combinations opened plainly before, 2026-11-13)
    // …and every other link to another page of the platform (the user, 2026-11-20: Write the advisory, Open the review
    // and an advisory's Open on the Findings page "just appear"): downloads, files, the API, the sign-in pages and a
    // place on the same page are left to the browser
    const a = e.target.closest?.("a[href]");
    if (!a || e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey || a.target === "_blank") return;
    if (a.hasAttribute("download") || a.dataset.noLoader != null) return;
    const href = a.getAttribute("href");
    if (!href || !href.startsWith("/") || href.startsWith("//")) return;
    const u = new URL(href, location.href);
    if (u.origin !== location.origin) return;
    if (/^\/(api|static|login|logout|forgot|enrol|welcome|organisation\/logo)(\/|$)/.test(u.pathname)) return;
    if (window.LGLoader.isDownload(u.pathname)) return;     // a file (an advisory's report too): never "Opening …"
    if (u.pathname === location.pathname && u.search === location.search) return;     // a place on this page
    e.preventDefault();
    window.LGLoader.go(u.pathname + u.search + u.hash);
  });

  // keyboard focus for every dialog on every page (dialog-focus.js) and the fresh check before high-value actions
  // (lg-stepup.js): loaded from here, which every page already has
  for (const f of ["dialog-focus.js", "lg-stepup.js"]) {
    if (document.querySelector(`script[src*="${f}"]`)) continue;
    const s = document.createElement("script");
    s.src = (document.currentScript?.src || "/static/js/loader.js").replace(/loader\.js(\?.*)?$/, f);
    s.defer = true;
    document.head.append(s);
  }
})();

// every form field has a name and a label (the user, 2026-11-25: Chrome's Issues panel, "A form field element should
// have an id or name attribute" and "No label associated with a form field"). Page scripts build many fields; as each
// appears, one without an id or a name gets a name from what it is about, and one without a label gets a real <label
// for> holding the words a person sees beside it (its aria-label, placeholder, title, the table's column and row, or
// the text right before it), visually hidden so nothing moves. Fields of a form posted by the browser itself are left
// alone (their names are the server's). The DOM and the CSSOM only.
(() => {
  const FIELD = "input:not([type=hidden]):not([type=submit]):not([type=button]), select, textarea";
  let n = 0;
  const words = (s) => String(s || "").replace(/\s+/g, " ").trim().slice(0, 80);
  const slug = (s) => words(s).toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 40) || "field";
  const labelled = (e) => (e.id && document.querySelector(`label[for="${CSS.escape(e.id)}"]`)) || e.closest("label");
  function about(e) {
    const own = e.getAttribute("aria-label") || e.getAttribute("placeholder") || e.getAttribute("title");
    if (own) return words(own);
    const by = (e.getAttribute("aria-labelledby") || "").split(/\s+/).map((id) => document.getElementById(id)?.textContent).filter(Boolean).join(" ");
    if (by) return words(by);
    const td = e.closest("td, th");
    if (td) {                                   // a field in a table: its column's heading and its row's first cell
      const tr = td.parentElement, table = td.closest("table");
      const col = table?.querySelector("thead tr")?.children[[...tr.children].indexOf(td)]?.textContent;
      const row = tr.children[0] !== td ? tr.children[0].textContent : "";
      if (col || row) return words([col, row].filter(Boolean).join(": "));
    }
    let p = e.previousElementSibling;           // the text right before it (a heading, a <b>, a span)
    while (p && !words(p.textContent)) p = p.previousElementSibling;
    if (p) return words(p.textContent);
    const box = e.closest("fieldset, section, article, [role=dialog]");
    return words(box?.querySelector("legend, h2, h3, h4")?.textContent) || (e.type === "checkbox" ? "Choose" : "Field");
  }
  const fix = (e) => {
    if (e.dataset.lgForm || e.closest("form[action]")) return;
    e.dataset.lgForm = "1";
    const what = about(e);
    if (!e.id && !e.name) e.name = `lg-${slug(what)}`;
    if (!labelled(e)) {
      if (!e.id) e.id = `lg-field-${++n}`;
      const l = document.createElement("label");
      l.htmlFor = e.id; l.textContent = what;
      box().append(l);             // a label works from anywhere in the page: none sits beside the field
    }
  };
  let holder = null;
  function box() {                 // one visually hidden holder at the end of the page for these labels
    if (holder && holder.isConnected) return holder;
    holder = document.createElement("div"); holder.className = "lg-sr-labels";
    Object.assign(holder.style, { position: "absolute", width: "1px", height: "1px", padding: "0", margin: "-1px", overflow: "hidden",
      clip: "rect(0 0 0 0)", clipPath: "inset(50%)", whiteSpace: "nowrap", border: "0" });
    document.body.append(holder);
    return holder;
  }
  const scan = (root) => {
    if (!root || !root.querySelectorAll) return;
    if (root.matches && root.matches(FIELD)) fix(root);
    for (const e of root.querySelectorAll(FIELD)) fix(e);
  };
  window.LGForms = { scan, about };
  // a field a page redraws goes away: its label goes too (a label for nothing is its own Issues entry)
  const prune = () => { if (holder) for (const l of [...holder.children]) if (!document.getElementById(l.htmlFor)) l.remove(); };
  const start = () => {
    scan(document);
    new MutationObserver((ms) => {
      let gone = false;
      for (const m of ms) {
        if (m.removedNodes.length) gone = true;
        for (const x of m.addedNodes) if (x.nodeType === 1 && !x.closest(".lg-sr-labels")) scan(x);
      }
      if (gone) prune();
    }).observe(document.body, { childList: true, subtree: true });
  };
  if (document.body) start(); else document.addEventListener("DOMContentLoaded", start);
})();

// a scrolling table or list the keyboard can reach (WCAG: scrollable region focusable; sweep 2026-11-14): any
// .table-wrap or scrolling list, as it appears, gets tabindex 0 and a name from its card's heading
(() => {
  const SEL = ".table-wrap, .cb-table-wrap, .av-ipwrap, .it-tablewrap, .intro-svc-reports";
  const mark = (root) => {
    for (const e of (root.querySelectorAll ? root.querySelectorAll(SEL) : [])) {
      if (e.hasAttribute("tabindex")) continue;
      e.tabIndex = 0; e.setAttribute("data-lg-scroll", "");
      if (!e.getAttribute("aria-label")) {
        const h = e.closest("section, article, .au-card, .card, div")?.querySelector("h2, h3, h4");
        e.setAttribute("aria-label", h ? h.textContent.trim().slice(0, 80) : "Scrolling table");
      }
    }
  };
  // devices are matched by IP address (external review follow-up, 2026-11-14): one sentence wherever Looking Glass links
  // reports by device; the same text as device_note.py (tests/check_device_note.py keeps them equal)
  window.LG_DEVICE_NOTE = "Devices are matched by IP address, as Shadowserver reports them: one address can sometimes be several devices (NAT, shared mobile connections).";
  window.lgDeviceNote = () => { const p = document.createElement("p"); p.className = "lg-device-note"; p.textContent = window.LG_DEVICE_NOTE; return p; };
  const start = () => { mark(document); new MutationObserver((ms) => { for (const m of ms) for (const n of m.addedNodes) if (n.nodeType === 1) mark(n.parentElement || n); }).observe(document.body, { childList: true, subtree: true }); };
  if (document.body) start(); else document.addEventListener("DOMContentLoaded", start);
})();
