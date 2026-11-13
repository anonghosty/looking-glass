/* Looking Glass · the advisor's portal (/advisory, advisory.py): the findings waiting for an advisory, the advisories
   written and sent, to whom and when, the open findings in their channels, and the impacts most seen. */
(() => {
  "use strict";
  const el = (t, c, x) => { const e = document.createElement(t); if (c) e.className = c; if (x != null) e.textContent = x; return e; };
  const fmt = (n) => Number(n || 0).toLocaleString("en-US");
  const main = document.getElementById("apMain");

  const card = (title, sub, cls) => {
    const s = el("section", `av-card ${cls || ""}`);
    s.append(el("h2", null, title));
    if (sub) s.append(el("p", "av-sub", sub));
    return s;
  };
  const bars = (rows, label, value, cls, sub) => {
    const w = el("div", "ap-bars"), max = Math.max(1, ...rows.map(value));
    rows.forEach((r) => {
      const row = el("div", "ap-bar");
      const t = el("span", "ap-bar-l", label(r)); t.title = label(r);
      if (sub) t.append(el("small", null, sub(r)));
      const b = el("span", `ap-bar-b ${cls ? cls(r) : ""}`); b.style.width = `${Math.max(3, 100 * value(r) / max)}%`;
      const track = el("span", "ap-bar-t"); track.append(b);
      row.append(t, track, el("b", null, fmt(value(r)))); w.append(row);
    });
    return w;
  };
  const table = (cols, rows) => {
    const t = el("table", "hosts ap-table"), h = el("tr");
    cols.forEach((c) => h.append(el("th", null, c)));
    const th = el("thead"); th.append(h); t.append(th);
    const tb = el("tbody"); rows.forEach((r) => tb.append(r)); t.append(tb);
    const w = el("div", "table-wrap"); w.append(t); return w;
  };
  const link = (href, text) => { const a = el("a", null, text); a.href = href; return a; };

  async function load() {
    let r;
    try { r = await fetch("/api/advisory/dashboard", { cache: "no-store" }); }
    catch (e) {                                // the connection dropped: say so, never a page that loads for ever (review 2026-11-13)
      document.getElementById("apLoading")?.remove(); window.LGLoader?.ready();
      main.append(el("p", "fd-empty", `Could not open it: ${e.message}`)); return;
    }
    const d = await r.json().catch(() => ({}));
    document.getElementById("apLoading")?.remove();
    window.LGLoader?.ready();
    if (!r.ok) { main.append(el("p", "fd-empty", d.error || `Could not open the portal (HTTP ${r.status})`)); return; }
    const k = d.kpis;
    const hero = el("section", "av-hero ap-hero");
    const ht = el("div", "av-head");
    ht.append(el("div", "fd-eyebrow", d.admin ? "Advisory portal · every advisor's work (admin)" : "Advisory portal"),
              el("h1", null, k.waiting ? `${fmt(k.waiting)} finding${k.waiting === 1 ? "" : "s"} waiting for an advisory` : "No finding is waiting for an advisory"));
    hero.append(ht); main.append(hero);

    const tiles = el("div", "ap-kpis");
    [["Waiting for you", k.waiting, "decided by management, sent to you", "amber"],
     ["Drafts", k.drafts, "being written", "violet"],
     ["Drafted", k.drafted, "ready to go out: mark as sent on Findings", "blue"],
     ["Advisories sent", k.sent, `${fmt(k.sends)} sending${k.sends === 1 ? "" : "s"} in all`, "teal"],
     ["Recipients", k.recipients, "organisations, teams or people", "blue"],
     ["Reports ready", k.reports, `advisories with their report · ${fmt(k.generations)} generated in all`, "violet"],
     ["Open findings", k.open_findings, "in your channels", "slate"],
     ["Findings closed", k.closed_findings, "by their advisory sent", "teal"],
     ["Cases closed", k.closed_cases, `${fmt(k.open_cases)} still open`, "teal"],
     ["Days to send", k.days_to_send == null ? "–" : k.days_to_send, "on average, from management's decision", "red"]].forEach(([l, v, s, c]) => {
      const t = el("div", `ap-kpi ${c}`); t.append(el("b", null, typeof v === "number" ? fmt(v) : v), el("span", null, l), el("small", null, s)); tiles.append(t);
    });
    main.append(tiles);

    const w = card("Waiting for an advisory", "Findings management decided and sent to you. Open one to write its advisory.");
    if (d.waiting.length) {
      w.append(table(["Finding", "Title", "Since", "Advisories"], d.waiting.map((x) => {
        const tr = el("tr"), td = el("td"); td.append(link(`/advisory/${x.fid}`, x.number));
        const t2 = el("td"); t2.append(link(`/advisory/${x.fid}`, x.title));
        if (x.case) t2.append(el("small", "muted", ` · case #${x.case}`));
        tr.append(td, t2, el("td", null, x.since),
                  el("td", null, [x.networks ? `${x.sent_networks} of ${x.networks} sent` : "", x.drafted ? `${x.drafted} drafted` : "", x.drafts ? `${x.drafts} draft${x.drafts === 1 ? "" : "s"}` : ""].filter(Boolean).join(" · ") || "Not started"));
        return tr;
      })));
    } else w.append(el("p", "fd-empty", "Nothing waiting: management's next decision sent to you appears here."));
    main.append(w);

    const grid = el("div", "ap-grid");
    const rc = card("Sent to", "Advisories per recipient, with the last one sent");
    if (d.recipients.length) rc.append(bars(d.recipients, (x) => x.name, (x) => x.advisories, null, (x) => `last sent ${x.last}`));
    else rc.append(el("p", "fd-empty", "No advisory sent yet."));
    const mc = card("Sent per month", "The last 12 months with a sending");
    if (d.per_month.length) mc.append(bars(d.per_month, (x) => x.month, (x) => x.sent));
    else mc.append(el("p", "fd-empty", "No advisory sent yet."));
    const ic = card("Impacts in the advisories sent", "How many advisories carried each impact flag");
    if (d.impacts.length) ic.append(bars(d.impacts, (x) => x.label, (x) => x.advisories, (x) => x.level));
    else ic.append(el("p", "fd-empty", "Appears once advisories are sent."));
    const pc = card("Reports in the advisories sent", "The Shadowserver reports named most");
    if (d.reports.length) pc.append(bars(d.reports, (x) => x.title, (x) => x.advisories));
    else pc.append(el("p", "fd-empty", "Appears once advisories are sent."));
    grid.append(rc, mc, ic, pc);
    main.append(grid);

    const ac = card("Advisories", "Every advisory, the latest change first");
    if (d.advisories.length) {
      ac.append(table(["Reference", "TLP", "Organisation", "Subject", "Finding", "Status", "Reports", "Recipients", "Last sent", "Updated", "By"], d.advisories.map((a) => {
        const tr = el("tr"), r0 = el("td"); r0.append(link(`/advisory/${a.fid}#${encodeURIComponent(a.network === "All networks" ? "" : a.network)}`, a.ref)); r0.className = "mono";
        const st = el("td"); st.append(el("span", `ap-st ${a.status}`, a.status_label));
        const tl = el("td"); const tk = a.tlp || "TLP:AMBER";
        tl.append(el("span", `tlp-badge ${tk === "TLP:RED" ? "tlp-red" : tk.startsWith("TLP:AMBER") ? "tlp-amber" : tk === "TLP:GREEN" ? "tlp-green" : "tlp-clear"}`, tk));
        tr.append(r0, tl, el("td", null, a.network), el("td", null, a.subject), el("td", null, a.finding), st, el("td", null, fmt(a.reports)),
                  el("td", null, a.recipients.join(", ") || "–"), el("td", null, a.sent || "–"), el("td", null, a.updated), el("td", null, a.by));
        return tr;
      })));
    } else ac.append(el("p", "fd-empty", "No advisory written yet."));
    main.append(ac);

    const oc = card("Open findings in your channels", "Where each one stands (the Findings page has their trail)");
    if (d.open_findings.length) {
      oc.append(table(["Finding", "Title", "Status", "With", "Since"], d.open_findings.map((x) => {
        const tr = el("tr"), td = el("td"); td.append(link("/findings", x.number));
        tr.append(td, el("td", null, x.title), el("td", null, x.status_label), el("td", null, x.assignee || "–"), el("td", null, x.since));
        return tr;
      })));
    } else oc.append(el("p", "fd-empty", "No open finding in your channels."));
    main.append(oc);
  }
  load();
})();
