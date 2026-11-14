/* Looking Glass · the Intelligence card on the Overview ("Your pages", _portal_cards.html): today's Intelligence records
   against the usual, and whether the day's reports are still arriving (counts only, /api/intelligence/totals). Only
   where the card is drawn: analysts and admins. */
(() => {
  "use strict";
  const box = document.getElementById("pcIntel");
  if (!box) return;
  const fmt = (n) => Number(n || 0).toLocaleString("en-US");
  fetch("/api/intelligence/totals", { cache: "no-store" }).then((r) => (r.ok ? r.json() : null)).then((d) => {
    if (!d || !d.groups) return;
    const today = d.groups.reduce((s, g) => s + g.today, 0);
    const usual = d.groups.reduce((s, g) => s + g.median, 0);
    const a = d.arriving || {};
    box.textContent = `Today ${fmt(today)} record${today === 1 ? "" : "s"} (usually ${fmt(usual)})`
      + (a.still ? ` · still arriving: ${a.in} of the usual ${a.usual} reports in so far` : ` · ${a.in} report${a.in === 1 ? "" : "s"} in`);
    box.hidden = false;
  }).catch(() => { /* the card stays as it is */ });
})();
