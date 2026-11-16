/* The spike notice on the Overview's buttons (spike_notice.py): the latest report day against the day before, and
   what is behind a spike or a drop. Analysts and admins see it on the two platform buttons, management on the
   Executive portal's, researchers on Definitions'. Counts and names only; shown only when there is a spike or a drop.
   Every [data-spike] line on the page: "comms", "services" or "both". */
(() => {
  "use strict";
  const lines = [...document.querySelectorAll("[data-spike]")];
  if (!lines.length) return;
  const fmt = (n) => Number(n || 0).toLocaleString("en-US");
  const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
  const day = (iso) => { const [y, m, d] = String(iso || "").split("-").map(Number); return d ? `${d} ${MONTHS[m - 1]}` : ""; };
  const PLATFORM = { comms: ["Network communications", "events"], services: ["Services", "records"] };

  function sentence(p, x, named) {
    if (!x || !x.kind) return "";
    const [name, unit] = PLATFORM[p];
    const up = x.kind === "spike";
    const pctOf = (t, b) => (b ? `${t >= b ? "+" : "−"}${Math.abs(Math.round((t - b) / b * 100))}%` : "new");
    if (x.scope === "part") {
      // the total is steady; one report (services) or one infection (communications) moved on its own
      const parts = (x.causes || []).map((c) => `${c.what}${c.report ? ` in ${c.report}` : ""}: ${fmt(c.before)} to ${fmt(c.today)} (${pctOf(c.today, c.before)})`);
      return `${named ? name + ": " : ""}${up ? "Spike" : "Drop"} on ${day(x.day)} against ${day(x.before_day)}. ${parts.join("; ")}. ` +
        `The total is steady (${fmt(x.today)} ${unit}).`;
    }
    const pct = x.change == null ? "" : pctOf(x.today, x.before);
    const head = `${up ? "Spike" : "Drop"} on ${day(x.day)}: ${fmt(x.today)} ${unit}, ${pct} on ${day(x.before_day)} (${fmt(x.before)}).`;
    const why = (x.causes || []).map((c) => {
      const d = c.today - c.before;
      return `${c.what}${c.report ? ` in ${c.report}` : ""} (${d > 0 ? "+" : "−"}${fmt(Math.abs(d))})`;
    });
    const cause = why.length ? ` Mostly ${why.length > 1 ? why.slice(0, -1).join(", ") + " and " + why[why.length - 1] : why[0]}.` : "";
    return `${named ? name + ": " : ""}${head}${cause}`;
  }

  fetch("/api/overview/spikes", { credentials: "same-origin" })
    .then((r) => (r.ok ? r.json() : null))
    .then((d) => {
      if (!d) return;
      for (const el of lines) {
        const which = el.dataset.spike === "both" ? ["comms", "services"] : [el.dataset.spike];
        const texts = which.map((p) => ({ p, t: sentence(p, d[p], which.length > 1) })).filter((x) => x.t);
        if (!texts.length) continue;
        el.replaceChildren(...texts.map((x) => {
          const s = document.createElement("span");
          s.className = `pc-spike-line ${d[x.p].kind}`;
          s.textContent = x.t;
          return s;
        }));
        el.hidden = false;
      }
    })
    .catch(() => { /* no notice: the buttons stay as they are */ });
})();
