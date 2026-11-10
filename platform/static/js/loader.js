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
  window.fetch = async (...args) => {
    const r = await nativeFetch(...args);
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
  const SELECTOR = ".i-loading, .st-loading, .stream-empty, .lg-loading";
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
  function show(label) {
    const o = overlay(); o.querySelector(".lg-transition-label").textContent = label || "";
    o.classList.remove("leaving"); o.classList.add("on");
    // restart the drawing animation
    const w = o.querySelector(".lg-logo-wrap"); w.classList.remove("drawing"); void w.offsetWidth; w.classList.add("drawing");
    return o;
  }
  function hide() {
    const o = document.getElementById("lgTransition"); if (!o || !o.classList.contains("on")) return;
    o.classList.add("leaving");
    setTimeout(() => o.classList.remove("on", "leaving"), calm() ? 0 : 520);
  }
  const LABELS = { "/services": "Opening publicly accessible / vulnerable services", "/settings": "Opening settings",
    "/definitions": "Opening definitions and intel", "/admin": "Opening administration", "/?intro": "Opening the overview", "/": "Opening reported network communications" };
  const labelFor = (url) => LABELS[Object.keys(LABELS).find((k) => url.startsWith(k) && (k !== "/" || url === "/" || url.startsWith("/?") && !url.startsWith("/?intro")))] || "Opening";
  let arrived = null, arriveTimer = null;
  window.LGLoader = {
    svg,
    /** leave for another page with the logo animation */
    go(url, label) {
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
      arrived = Date.now(); show(text);
      arriveTimer = setTimeout(() => window.LGLoader.ready(), calm() ? 0 : 1600);
    },
    /** the page has its data: let the logo finish (at least ~0.7 s on screen) and fade into the platform */
    ready() {
      if (arrived == null) return;
      const wait = calm() ? 0 : Math.max(0, 700 - (Date.now() - arrived));
      arrived = null; clearTimeout(arriveTimer);
      setTimeout(hide, wait);
    },
    /** within one page while data loads: the drawing logo until ready() (at least ~0.7 s on screen) */
    busy(label) {
      clearTimeout(arriveTimer); arrived = Date.now(); show(label);
      arriveTimer = setTimeout(() => window.LGLoader.ready(), 20000);
    },
    /** within one page (intro -> map): logo, then the platform appears */
    flash(label, ms = 900) {
      show(label); setTimeout(hide, calm() ? 0 : ms);
    },
    hide,
  };
  if (document.body) window.LGLoader.arrive(); else document.addEventListener("DOMContentLoaded", () => window.LGLoader.arrive());
})();
