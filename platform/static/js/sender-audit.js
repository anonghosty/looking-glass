/* Looking Glass · Audit portal → Sender check (sender_audit.py): the pipeline's DKIM check of every report e-mail,
   for the period chosen in the portal. Read only, evidence only: figures, results per day, the signing keys seen,
   every report that did not pass and what happened to it, the settings and releases, and the standards next to the
   evidence. audit.js calls LGSender.load(period) when the tab opens. */
(() => {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const el = (t, c, x) => { const e = document.createElement(t); if (c) e.className = c; if (x != null) e.textContent = x; return e; };
  const fmt = (n) => Number(n || 0).toLocaleString("en-US");
  const NS = "http://www.w3.org/2000/svg";
  const sv = (t, a) => { const e = document.createElementNS(NS, t); for (const k in a) e.setAttribute(k, a[k]); return e; };
  const ORDER = ["pass", "other", "fail", "none", "temperror", "permerror"];
  const COLOR = { pass: "#5fc79b", other: "#7f9cf5", fail: "#ef6b6b", none: "#e8b04b", temperror: "#9aa0a6", permerror: "#b98be0" };
  const LABEL = { pass: "Valid, expected signer", other: "Valid, other signer", fail: "Signature fails", none: "Not signed",
                  temperror: "DNS did not answer", permerror: "Cannot be checked" };

  function kpi(label, value, note, tone) {
    const k = el("div", `au-kpi${tone ? " " + tone : ""}`); k.append(el("span", "au-kpi-k", label), el("b", null, value));
    if (note) k.append(el("small", "muted", note));
    return k;
  }

  function chart(days) {
    // stacked bars, one per day; the numbers are in the table below for anyone who cannot read the colours
    const W = 760, H = 180, P = 28, n = days.length || 1, bw = Math.max(2, (W - P - 8) / n - 2);
    const max = Math.max(1, ...days.map((d) => ORDER.reduce((s, r) => s + d[r], 0)));
    const svg = sv("svg", { viewBox: `0 0 ${W} ${H + 22}`, class: "sn-chart", role: "img",
      "aria-label": `Report e-mails checked per day, by result, ${days[0]?.day || ""} to ${days[days.length - 1]?.day || ""}` });
    for (const f of [0, 0.5, 1]) {
      const y = H - f * (H - 10);
      svg.append(sv("line", { x1: P, x2: W, y1: y, y2: y, stroke: "currentColor", "stroke-opacity": f ? 0.12 : 0.3 }));
      const t = sv("text", { x: P - 4, y: y + 4, "text-anchor": "end", "font-size": 10, fill: "currentColor", opacity: 0.6 }); t.textContent = fmt(Math.round(max * f)); svg.append(t);
    }
    days.forEach((d, i) => {
      let y = H; const x = P + 4 + i * ((W - P - 8) / n);
      for (const r of ORDER) {
        if (!d[r]) continue;
        const h = (d[r] / max) * (H - 10);
        const rect = sv("rect", { x, y: y - h, width: bw, height: Math.max(1, h), fill: COLOR[r], rx: 1 });
        const tt = sv("title", {}); tt.textContent = `${d.day}: ${fmt(d[r])} ${LABEL[r].toLowerCase()}`; rect.append(tt);
        svg.append(rect); y -= h;
      }
      if (i % Math.max(1, Math.ceil(n / 8)) === 0 || i === n - 1) {      // at most about 9 dates, never overlapping
        const t = sv("text", { x: x + bw / 2, y: H + 14, "text-anchor": "middle", "font-size": 9, fill: "currentColor", opacity: 0.6 });
        t.textContent = d.day.slice(5); svg.append(t);
      }
    });
    const wrap = el("div", "sn-chart-wrap"); wrap.append(svg);
    const leg = el("div", "sn-legend");
    for (const r of ORDER) { const s = el("span"); const sw = el("i"); sw.style.background = COLOR[r]; s.append(sw, document.createTextNode(LABEL[r])); leg.append(s); }
    wrap.append(leg);
    return wrap;
  }

  function table(head, rows) {
    const t = el("table", "hosts adm-table"); const th = el("thead"); const tr = el("tr");
    head.forEach((h) => tr.append(el("th", null, h))); th.append(tr); t.append(th);
    const tb = el("tbody");
    for (const r of rows) { const row = el("tr"); r.forEach((c) => row.append(el("td", null, c))); tb.append(row); }
    t.append(tb); const w = el("div", "table-wrap"); w.append(t); return w;
  }

  async function load(per) {
    const box = $("snBody");
    const r = await fetch(`/api/audit/sender?${per}`, { cache: "no-store" });
    const d = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
    box.replaceChildren();
    if (!d.found) { box.append(el("p", "fd-empty", d.message)); return; }
    const k = d.kpis, mode = { enforce: "Blocking", log: "Record only", off: "Off" }[d.mode] || d.mode;
    const top = el("div", "au-kpis");
    top.append(kpi("Mode now", mode, d.mode === "enforce" ? "reports that do not pass are held back" : d.mode === "log" ? "results recorded, nothing held back" : "not checked"),
      kpi("Reports checked", fmt(k.checked), `${d.period.from} to ${d.period.to}`),
      kpi("Valid, expected signer", k.pass_rate == null ? "–" : `${(k.pass_rate * 100).toFixed(1)} %`, `${fmt(k.pass)} signed by ${d.domain}`, k.checked && k.pass < k.checked ? "warn" : "good"),
      kpi("Did not pass", fmt(k.checked - k.pass - k.temperror), `${fmt(k.fail)} fail · ${fmt(k.none)} unsigned · ${fmt(k.other)} other signer · ${fmt(k.permerror)} cannot be checked`, (k.fail || k.none || k.other) ? "warn" : ""),
      kpi("Held back", fmt(k.held_back), `${fmt(k.released)} released · ${fmt(k.held_now)} held now`, k.held_now ? "warn" : ""),
      kpi("DNS did not answer", fmt(k.temperror), "not held against the report"),
      kpi("Fetched through the API", fmt(d.api.files), d.source === "api" ? "the pipeline fetches by API now: requests signed with the API secret, files from Shadowserver over HTTPS (no e-mail, so no DKIM)" : "the pipeline fetches by e-mail now"));
    box.append(top);

    box.append(el("h3", "au-sub-h", "Results per day"), chart(d.per_day));

    box.append(el("h3", "au-sub-h", "Signing keys seen"),
      d.keys.length ? table(["Signing domain", "Selector", "Algorithm", "Key size", "Reports"], d.keys.map((x) => [x.signer, x.selector, x.alg, x.bits ? `${x.bits} bits` : "–", fmt(x.reports)]))
        : el("p", "muted", "No valid signature in the period."));

    // new report types (report_types.py): a type that arrived for the first time, by e-mail or by API
    const ty = d.types || { new: [], recorded: 0 };
    box.append(el("h3", "au-sub-h", `New report types${ty.new_without_definition ? ` (${fmt(ty.new_without_definition)} without a definition yet)` : ""}`));
    box.append(el("p", "st-hint", ty.recorded
      ? `${fmt(ty.recorded)} report types have arrived since ${ty.since}. A type that arrives for the first time after that is listed here (and logged by the pipeline). It is loaded like any other; its definition comes when the report definitions, kept current from Shadowserver's schema, know it.`
      : "No report has been sorted yet, so there is no starting point."));
    if (ty.new.length) box.append(table(["Report type", "First arrived", "Report definitions"],
      ty.new.map((x) => [x.name, x.first_seen, x.known ? `${x.note}${x.title ? `: ${x.title}` : ""}` : `NEW: ${x.note}`])));
    else if (ty.recorded) box.append(el("p", "muted", "No new report type since then."));

    box.append(el("h3", "au-sub-h", "What the standards ask, and what the evidence shows"));
    const st = el("div", "sn-std");
    for (const s of d.standards) {
      const c = el("div", "au-card sn-std-card");
      c.append(el("div", "sn-ref mono", s.ref), el("h4", null, s.title), el("p", "sn-asks", s.asks), el("p", "sn-shows", s.shows));
      st.append(c);
    }
    box.append(st);

    box.append(el("h3", "au-sub-h", `Reports that did not pass (${fmt(d.odd.length)}${d.odd.length >= 300 ? ", newest 300" : ""})`),
      d.odd.length ? table(["Checked (UTC)", "Result", "What it means", "What happened", "From", "Signer", "Why", "Subject", "Files"],
        d.odd.map((x) => [x.at.replace("T", " ").slice(0, 16), x.result, x.meaning, x.action_label, x.from_domain || "?", x.signer || "–", x.reason, x.subject, x.files]))
        : el("p", "muted", "Every report in the period passed."));

    box.append(el("h3", "au-sub-h", "Settings and releases in the period"),
      d.changes.length ? table(["When (UTC)", "What", "By", "Detail"], d.changes.map((x) => [x.at, x.event.replace(/_/g, " "), x.user, x.detail]))
        : el("p", "muted", "No change to the sender check and no release in the period."));
  }

  window.LGSender = { load };
})();
