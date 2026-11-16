/* Looking Glass · keyboard focus for every dialog (review 2026-11-13: focus left dialogs with Tab, was lost to the page
   when they closed, and one Escape closed several layers at once).
   Loaded on every page by loader.js. It needs nothing from the pages: any element marked aria-modal="true" counts as a
   dialog while it is shown, however the page shows it (the hidden attribute, a class, a style, added to the page).
   - opening: focus moves into it, unless the page already put it there;
   - Tab and Shift+Tab stay inside the top-most dialog;
   - closing: focus goes back to what had it before the dialog opened (the button that opened it), if it is still there;
   - Escape with two or more dialogs open closes only the top-most (by its own Close button); with one, the page's own
     Escape handling goes first, and only a dialog it leaves open is closed by its Cancel or Close button. */
(() => {
  "use strict";
  if (window.LGDialogs) return;
  const SEL = '[aria-modal="true"]';
  const FOC = 'a[href], button:not([disabled]), input:not([disabled]):not([type="hidden"]), select:not([disabled]), '
            + 'textarea:not([disabled]), summary, [tabindex]:not([tabindex="-1"])';
  const open = [];                                 // [{el, opener}], the top-most last
  const history = [];                              // the elements focus was on, newest last (to find a dialog's opener)

  const shown = (el) => el.isConnected && !el.hidden && el.getAttribute("aria-hidden") !== "true"
    && el.getClientRects().length > 0 && getComputedStyle(el).visibility !== "hidden";
  const visible = (n) => n.getClientRects().length > 0 && !n.closest("[hidden]");
  const focusables = (el) => [...el.querySelectorAll(FOC)].filter(visible);
  const closeButton = (el) => el.querySelector('[aria-label^="Close"], [data-close], button[id$="Close"]')
    || [...el.querySelectorAll("button")].find((b) => /^\s*(cancel|close)\s*$/i.test(b.textContent));
  const focus = (n) => { try { n.focus({ preventScroll: true }); } catch { /* not focusable */ } };

  document.addEventListener("focusin", (e) => {
    history.push(e.target);
    if (history.length > 20) history.shift();
  }, true);

  function sync() {
    const now = [...document.querySelectorAll(SEL)].filter(shown);
    for (let i = open.length - 1; i >= 0; i--) {   // closed since the last look
      const d = open[i];
      if (now.includes(d.el)) continue;
      open.splice(i, 1);
      const a = document.activeElement;
      if (!a || a === document.body || !a.isConnected || d.el.contains(a)) {
        const under = open.length ? open[open.length - 1].el : null;
        const back = d.opener && d.opener.isConnected && visible(d.opener) && (!under || under.contains(d.opener))
          ? d.opener : (under ? focusables(under)[0] : null);
        if (back) focus(back);
      }
    }
    for (const el of now) {                        // opened since the last look
      if (open.some((d) => d.el === el)) continue;
      const opener = [...history].reverse().find((n) => n.isConnected && !el.contains(n) && n !== document.body) || null;
      open.push({ el, opener });
      setTimeout(() => {                           // after the page's own focus call, if it makes one
        if (!shown(el) || el.contains(document.activeElement)) return;
        const first = focusables(el)[0];
        if (first) focus(first);
        else { if (!el.hasAttribute("tabindex")) el.setAttribute("tabindex", "-1"); focus(el); }
      }, 80);
    }
  }

  let queued = false;
  const later = () => { if (!queued) { queued = true; requestAnimationFrame(() => { queued = false; sync(); }); } };
  new MutationObserver(later).observe(document.documentElement, {
    subtree: true, childList: true, attributes: true, attributeFilter: ["hidden", "class", "style", "aria-hidden", "aria-modal", "open"],
  });

  document.addEventListener("keydown", (e) => {
    if (!open.length) return;
    const top = open[open.length - 1].el;
    if (e.key === "Tab") {
      const f = focusables(top);
      if (!f.length) { e.preventDefault(); return; }
      const first = f[0], last = f[f.length - 1], a = document.activeElement;
      if (!top.contains(a)) { e.preventDefault(); focus(e.shiftKey ? last : first); }
      else if (e.shiftKey && a === first) { e.preventDefault(); focus(last); }
      else if (!e.shiftKey && a === last) { e.preventDefault(); focus(first); }
    } else if (e.key === "Escape" && open.length > 1) {
      const btn = closeButton(top);
      if (btn) { e.preventDefault(); e.stopImmediatePropagation(); btn.click(); }
    }
  }, true);

  // one dialog and a page that does not close it on Escape (the password prompts): after the page had its turn, its own
  // Cancel or Close button is pressed. A dialog the page already closed on Escape is gone by then, so nothing happens twice.
  document.addEventListener("keydown", (e) => {
    if (e.key !== "Escape" || open.length !== 1 || e.defaultPrevented) return;
    const top = open[0].el;
    setTimeout(() => { if (shown(top) && open.length === 1 && open[0].el === top) closeButton(top)?.click(); }, 60);
  });

  window.LGDialogs = { open: () => open.map((d) => d.el), sync };
  sync();
})();
