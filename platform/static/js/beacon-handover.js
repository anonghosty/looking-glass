/* Handing decoded beacons over (beacon_findings.py), and a finding's beacons at the viewer's level.
 *
 * LGBeaconHandover.button(sel, label): a "Hand over" button that opens a small form under it: an analyst or a manager,
 *   the person (a hand-over always names one), a comment; it becomes a finding (POST /api/beacon/finding).
 *   sel: {name, format?, operator?, version?, os_family?}. Used by intel.js (Intel gathered, Looking Glass asks) and
 *   beacon.js (the map's event details).
 * LGBeaconHandover.block(f): the "Decoded beacons" block of a finding on the Findings page (GET /api/beacon/finding/<id>):
 *   analysts and admins get every record (host, time, report, decoded JSON); everyone else counts only.
 */
(function () {
  "use strict";
  const el = (tag, cls, text) => { const e = document.createElement(tag); if (cls) e.className = cls; if (text != null) e.textContent = text; return e; };
  const csrf = () => document.querySelector('meta[name="csrf-token"]')?.content || "";
  const plural = (n, w) => `${Number(n || 0).toLocaleString("en-GB")} ${w}${n === 1 ? "" : "s"}`;

  function button(sel, label) {
    const wrap = el("span", "bh-wrap");
    const b = el("button", "lg-btn sm bh-btn", label || "Hand over"); b.type = "button";
    b.title = "Send these decoded beacons to an analyst or a manager as a finding";
    let form = null;
    b.addEventListener("click", (ev) => {
      ev.stopPropagation();
      if (form) { form.remove(); form = null; return; }
      form = el("div", "bh-form"); form.addEventListener("click", (e) => e.stopPropagation());
      const kind = el("select", "fd-in lg-enhance"); kind.setAttribute("aria-label", "Send to");
      for (const [v, t] of [["analyst", "An analyst"], ["management", "A manager"]]) { const o = el("option", null, t); o.value = v; kind.append(o); }
      const who = el("select", "fd-in lg-enhance"); who.setAttribute("aria-label", "Person");
      const note = el("textarea", "fd-in"); note.rows = 3; note.maxLength = 1000;
      note.placeholder = "What to look into (optional): Looking Glass writes what it decoded";
      const go = el("button", "lg-btn sm primary", "Send"); go.type = "button";
      const msg = el("span", "fd-msg"); msg.setAttribute("role", "status");
      const people = async () => {
        who.replaceChildren(el("option", null, "Loading…")); go.disabled = true;
        try {
          const r = await fetch(`/api/findings/people?kind=${encodeURIComponent(kind.value)}`, { credentials: "same-origin" });
          const d = await r.json();
          who.replaceChildren();
          for (const p of d.people || []) { const o = el("option", null, p.name); o.value = p.user; who.append(o); }
          if (!who.options.length) who.append(el("option", null, kind.value === "analyst" ? "No analyst account" : "No manager account"));
          go.disabled = !(d.people || []).length;
        } catch { who.replaceChildren(el("option", null, "Could not load the people")); }
      };
      kind.addEventListener("change", people); people();
      go.addEventListener("click", async () => {
        go.disabled = true; msg.textContent = "Sending…";
        try {
          const r = await fetch("/api/beacon/finding", { method: "POST", credentials: "same-origin",
            headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf() },
            body: JSON.stringify({ ...sel, kind: kind.value, to: who.value, comment: note.value }) });
          const d = await r.json().catch(() => ({}));
          if (!r.ok) { msg.textContent = d.error || `Not sent (${r.status}).`; go.disabled = false; return; }
          msg.replaceChildren(document.createTextNode(`Sent as finding ${d.finding.number}. `));
          const a = el("a", null, "Open it"); a.href = `/findings#f${d.finding.id}`; msg.append(a);
        } catch (e) { msg.textContent = `Not sent: ${e.message}`; go.disabled = false; }
      });
      form.append(el("label", "bh-l", "Send to"), kind, who, note, go, msg);
      wrap.append(form);
    });
    wrap.prepend(b);
    return wrap;
  }

  function block(f) {
    const s = el("section", "bh-block");
    s.append(el("h3", null, "Decoded beacons"), el("div", "lg-loading", "Gathering the beacons…"));
    (async () => {
      let d;
      try {
        const r = await fetch(`/api/beacon/finding/${encodeURIComponent(f.id)}`, { credentials: "same-origin" });
        d = await r.json();
        if (!r.ok) throw new Error(d.error || r.status);
      } catch (e) { s.replaceChildren(el("h3", null, "Decoded beacons"), el("p", "fd-msg", `Could not load them: ${e.message}`)); return; }
      s.replaceChildren(el("h3", null, "Decoded beacons"), el("p", "bh-said", d.said));
      if (d.selection.length) {
        const chips = el("div", "bh-chips");
        for (const x of d.selection) { const c = el("span", "bh-chip"); c.append(el("small", null, x.label), el("b", null, x.value)); chips.append(c); }
        s.append(chips);
      }
      const facts = el("p", "bh-facts",
        `${plural(d.records, "record")} from ${plural(d.devices, "device")} in ${d.reports.join(", ") || "no report"}${d.days.length ? ` (${d.days.join(", ")})` : ""}, in the days in memory.`);
      s.append(facts);
      if (d.held) s.append(el("p", "bh-note", "Fewer than 5 devices carry these beacons: what they say is held back here. An analyst sees every record."));
      if (d.contradicts) s.append(el("p", "bh-note", "The beacons name a different operating system than the infection they are filed under."));
      // no address on the Findings page until an analyst asks for the devices (that view is logged)
      if (d.can_records && d.records) {
        const show = el("button", "lg-btn sm", `Show the devices (${plural(d.devices, "device")})`); show.type = "button";
        show.title = "Every record with its host, time, report and decoded JSON. Opening it is recorded in the audit log.";
        const holder = el("div");
        show.addEventListener("click", async () => {
          show.disabled = true; holder.replaceChildren(el("div", "lg-loading", "Gathering the devices…"));
          try {
            const r = await fetch(`/api/beacon/finding/${encodeURIComponent(f.id)}?records=1`, { credentials: "same-origin" });
            const dd = await r.json(); if (!r.ok) throw new Error(dd.error || r.status);
            holder.replaceChildren(); records(holder, dd); show.remove();
          } catch (e) { holder.replaceChildren(el("p", "fd-msg", `Could not load them: ${e.message}`)); show.disabled = false; }
        });
        s.append(show, holder);
      }
    })();
    return s;
  }

  function records(s, d) {
    {
      if (d.records_list) {
        if (!d.records_list.length) { s.append(el("p", "bh-note", "None of these records is in the days in memory any more.")); return; }
        const t = el("table", "bh-table");
        const hr = el("tr"); for (const h of ["Host", "Time (UTC)", "Report", "C2 host", "What the beacon says"]) hr.append(el("th", null, h));
        t.append(el("thead")); t.tHead.append(hr);
        const tb = el("tbody");
        for (const row of d.records_list) {
          const tr = el("tr");
          const b = row.beacons[0] || {};
          const says = b.decoded === false ? `${b.title} (${b.status || "not decoded"})` : b.generic ? b.title : [b.operator, b.version, b.os].filter(Boolean).join(" · ");
          tr.append(el("td", "bh-mono", `${row.host}${row.port ? ":" + row.port : ""}`), el("td", "bh-mono", row.time.replace("T", " ")),
            el("td", null, row.report), el("td", "bh-mono", row.c2));
          const td = el("td"); td.append(el("div", null, says));
          if (b.decoded !== false) {
            const det = el("details", "bh-det"); det.append(el("summary", null, "Decoded JSON and notes"));
            if (b.notes?.length) { const ul = el("ul", "bc-notes"); b.notes.forEach((n) => ul.append(el("li", null, n))); det.append(ul); }
            if (b.key) det.append(el("div", "bh-key", `XOR key ${b.key}`));
            det.append(el("pre", "bh-pre", b.json ? JSON.stringify(b.json, null, 2) : (b.text || "")));
            td.append(det);
          }
          tr.append(td); tb.append(tr);
        }
        t.append(tb);
        const scroll = el("div", "bh-scroll"); scroll.append(t); s.append(scroll);
        if (d.more) s.append(el("p", "bh-note", `${plural(d.more, "more record")} not listed (the first 500 are).`));
      }
    }
  }

  window.LGBeaconHandover = { button, block };
})();
