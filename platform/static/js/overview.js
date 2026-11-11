/* Looking Glass · the Overview page: rendered on the server, nothing to load; the cards open the pages with the logo. */
(() => {
  "use strict";
  window.LGLoader?.ready();
  document.addEventListener("click", (e) => {
    const a = e.target.closest?.("a.portal-card[href]");
    if (!a || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
    const href = a.getAttribute("href");
    if (!href || !href.startsWith("/") || href.startsWith("//")) return;
    e.preventDefault();
    window.LGLoader ? window.LGLoader.go(href) : (location.href = href);
  });
})();
