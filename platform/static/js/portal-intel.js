/* Looking Glass · the Intelligence card on the Overview ("Your pages", _portal_cards.html): today's Intelligence records
   against the usual, and whether the day's reports are still arriving (counts only, /api/intelligence/totals). Only
   where the card is drawn: analysts and admins. */
(() => {
  "use strict";
  const box = document.getElementById("pcIntel");
  if (!box) return;
  const fmt = (n) => Number(n || 0).toLocaleString("en-US");
  // the page's logo stays until the card has its line (LGLoader.wait, 2026-11-15: it used to appear after the page)
  (window.LGLoader?.wait || ((p) => p))(fetch("/api/intelligence/totals", { cache: "no-store" }).then((r) => (r.ok ? r.json() : null)).then((d) => {
    if (!d || !d.groups) return;
    const today = d.groups.reduce((s, g) => s + g.today, 0);
    const usual = d.groups.reduce((s, g) => s + g.median, 0);
    const a = d.arriving || {};
    const day = new Date(`${d.today}T00:00:00Z`).toLocaleDateString("en-GB", { weekday: "short", day: "numeric", month: "short", timeZone: "UTC" });
    box.textContent = `${day}: ${fmt(today)} record${today === 1 ? "" : "s"} (usually ${fmt(usual)})`
      + ` · today's reports so far: ${a.in} of the usual ${a.usual}`;
    box.hidden = false;
  }).catch(() => { /* the card stays as it is */ }));
})();
