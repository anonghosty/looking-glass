/* SPDX-License-Identifier: AGPL-3.0-only
   SPDX-FileCopyrightText: the Looking Glass contributors */
/* Looking Glass · hover labels on the header and portal buttons (the user, 2026-11-19: "when you hover in a portal it
   should say what the button is"). The browser's own tooltip (title) comes late and not on every system; this shows
   the button's name at once, under it, on hover and on keyboard focus, on every page. The name is the button's
   aria-label, else its title's first sentence, else its text. Nothing is fetched; the label is plain text. */
(() => {
  const SEL = ".hud-right a, .hud-right button, .intro-gear-row a, .intro-gear-row button, .mg-top-actions a, " +
    ".mg-top-actions button, .lg-nav a, .lg-nav button, .nav-ic, .brand-btn, .icon-btn";
  let tip = null, cur = null;
  const nameOf = (b) => {
    const a = (b.getAttribute("aria-label") || "").trim();
    if (a) return a;
    const t = (b.getAttribute("title") || b.dataset.lgTitle || "").trim();
    if (t) return t.split(/(?<=[.:])\s/)[0].replace(/[.:]$/, "");
    return (b.textContent || "").replace(/\s+/g, " ").trim();
  };
  function show(b) {
    const name = nameOf(b);
    if (!name) return;
    if (!tip) { tip = document.createElement("div"); tip.className = "lg-htip"; tip.setAttribute("role", "tooltip"); tip.id = "lgHtip"; document.body.append(tip); }
    // the browser's late tooltip would repeat it: kept aside while ours shows, put back after
    if (b.hasAttribute("title")) { b.dataset.lgTitle = b.getAttribute("title"); b.removeAttribute("title"); }
    if (!b.getAttribute("aria-label") && !b.textContent.trim()) b.setAttribute("aria-label", name);
    tip.textContent = name; tip.hidden = false; cur = b;
    const r = b.getBoundingClientRect(), w = tip.offsetWidth;
    tip.style.left = `${Math.max(6, Math.min(innerWidth - w - 6, r.left + r.width / 2 - w / 2))}px`;
    tip.style.top = `${r.bottom + 6}px`;
  }
  function hide() {
    // the browser's tooltip text back, unless the page gave the button a new one meanwhile (the bell's count)
    if (cur && cur.dataset.lgTitle != null) { if (!cur.hasAttribute("title")) cur.setAttribute("title", cur.dataset.lgTitle); delete cur.dataset.lgTitle; }
    cur = null; if (tip) tip.hidden = true;
  }
  const target = (e) => e.target.closest?.(SEL);
  document.addEventListener("mouseover", (e) => { const b = target(e); if (b && b !== cur) { hide(); show(b); } });
  document.addEventListener("mouseout", (e) => { const b = target(e); if (b && b === cur && !b.contains(e.relatedTarget)) hide(); });
  document.addEventListener("focusin", (e) => { const b = target(e); if (b) { hide(); if (b.matches(":focus-visible")) show(b); } });
  document.addEventListener("focusout", hide);
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") hide(); });
  addEventListener("scroll", hide, true);
})();
