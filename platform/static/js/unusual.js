/* SPDX-License-Identifier: AGPL-3.0-only
   SPDX-FileCopyrightText: the Looking Glass contributors */
/* Looking Glass · Unusual activity (unusual.py; the user 2026-11-24): the latest report day's suggestions as cards (in words,
   with the thread's chart against its normal), the devices behind each (analysts and administrators), Confirm (a name:
   a thread the team watches, followed every day) and Dismiss (quiet for 30 days), and the watched threads. */
(() => {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const csrf = () => document.querySelector('meta[name="csrf-token"]')?.content || "";
  const decide = document.body.dataset.decide === "1";
  const KIND = { network: "Network and report", report: "Whole constituency", pair: "Reports together" };

  function el(tag, cls, text) {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = text;
    return e;
  }

  async function call(url, body) {
    const r = await fetch(url, { method: body === undefined ? "GET" : "POST", credentials: "same-origin", cache: "no-store",
      headers: body === undefined ? {} : { "Content-Type": "application/json", "X-CSRF-Token": csrf() },
      body: body === undefined ? undefined : JSON.stringify(body) });
    const j = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(j.error || `Looking Glass answered ${r.status}`);
    return j;
  }

  // the thread's days as bars, the latest in red, its normal as a dashed line
  function chart(history, normal) {
    const ns = "http://www.w3.org/2000/svg";
    const svg = document.createElementNS(ns, "svg");
    svg.setAttribute("class", "pt-chart");
    svg.setAttribute("viewBox", "0 0 300 72");
    svg.setAttribute("preserveAspectRatio", "none");
    svg.setAttribute("role", "img");
    const vals = history.map((h) => h.value);
    const top = Math.max(1, ...vals, normal || 0);
    const w = 300 / Math.max(1, history.length);
    history.forEach((h, i) => {
      const r = document.createElementNS(ns, "rect");
      const hgt = Math.max(1, (h.value / top) * 66);
      r.setAttribute("x", (i * w + w * 0.15).toFixed(2)); r.setAttribute("width", (w * 0.7).toFixed(2));
      r.setAttribute("y", (70 - hgt).toFixed(2)); r.setAttribute("height", hgt.toFixed(2));
      r.setAttribute("class", i === history.length - 1 ? "bar today" : "bar");
      const t = document.createElementNS(ns, "title"); t.textContent = `${h.day}: ${h.value} devices`; r.append(t);
      svg.append(r);
    });
    if (normal != null) {
      const y = (70 - (normal / top) * 66).toFixed(2);
      const l = document.createElementNS(ns, "line");
      l.setAttribute("x1", "0"); l.setAttribute("x2", "300"); l.setAttribute("y1", y); l.setAttribute("y2", y); l.setAttribute("class", "norm");
      svg.append(l);
    }
    const first = history[0]?.day, last = history[history.length - 1]?.day;
    svg.setAttribute("aria-label", `Devices per day from ${first} to ${last}; the dashed line is the normal (${normal ?? "not known yet"})`);
    return svg;
  }

  async function showDevices(c, box, btn) {
    btn.disabled = true;
    box.replaceChildren(el("p", "pt-empty", "Finding the devices…"));
    try {
      const d = await call(`/api/unusual/${c.id}/devices`);
      box.replaceChildren();
      if (!d.devices.length) { box.append(el("p", "pt-empty", "No device of the constituency on that day any more.")); return; }
      const t = el("table");
      const hr = t.createTHead().insertRow();
      for (const [h, num] of [["Address", false], ["Network", false], ["Records", true]]) { const th = el("th", num ? "num" : "", h); hr.append(th); }
      const tb = t.createTBody();
      for (const x of d.devices) {
        const tr = tb.insertRow();
        tr.insertCell().textContent = x.ip; tr.insertCell().textContent = x.network || "";
        const n = tr.insertCell(); n.className = "num"; n.textContent = x.records;
      }
      box.append(el("p", "pt-by", `${d.total} device(s) on ${d.day}` + (d.more ? `; the first ${d.devices.length} shown, by records` : "")), t);
    } catch (e) {
      box.replaceChildren(el("p", "pt-empty", window.LGLoader.errorText(e, true)));
    } finally { btn.disabled = false; }
  }

  function card(c, confirmed) {
    const a = el("article", "pt-card");
    a.append(el("h3", null, confirmed ? `${c.name}: ${c.words}` : c.words));
    const meta = el("div", "pt-meta");
    meta.append(el("span", "pt-chip kind", KIND[c.kind] || c.kind));
    if (c.new) meta.append(el("span", "pt-chip new", "New: normally none"));
    if (c.lift) meta.append(el("span", "pt-chip", `${c.lift}x more often together than chance`));
    if (c.first_day) meta.append(el("span", "pt-chip", `First in these weeks: ${c.first_day}`));
    if (c.days_above != null) meta.append(el("span", "pt-chip", `${c.days_above} earlier day(s) at this size`));
    a.append(meta);
    if (c.history?.length) {
      a.append(chart(c.history, c.normal));
      a.append(el("p", "pt-legend", `${c.history[0].day} to ${c.history[c.history.length - 1].day}: devices per day; the last bar is ${c.day || "the latest day"}, the dashed line its normal.`));
    }
    if (c.learned) a.append(el("p", "pt-by", c.learned));
    if (confirmed && c.growing) a.append(el("p", "pt-growing", `Growing again today: ${c.growing}`));
    if (confirmed) a.append(el("p", "pt-by", `Confirmed by ${c.confirmed_by || "the team"}${c.confirmed_at ? " on " + new Date(c.confirmed_at * 1000).toISOString().slice(0, 10) : ""}.`));
    const act = el("div", "pt-actions");
    const devBox = el("div", "pt-devices");
    if (decide) {
      if (c.kind) {
        const b = el("button", "pill-btn", "Show the devices");
        b.type = "button"; b.addEventListener("click", () => showDevices(c, devBox, b)); act.append(b);
      }
      for (const l of c.links || []) { const x = el("a", "pill-btn", l.text); x.href = l.href; act.append(x); }
      const msg = el("span", "cb-msg"); msg.setAttribute("role", "status");
      if (confirmed) {
        const u = el("button", "pill-btn", "Stop watching");
        u.type = "button";
        u.addEventListener("click", async () => {
          if (!window.confirm(`Stop watching "${c.name}"? It can be suggested again.`)) return;
          try { await call(`/api/unusual/${c.id}/untrack`, {}); await load(); } catch (e) { msg.textContent = window.LGLoader.errorText(e, true); msg.className = "cb-msg bad"; }
        });
        act.append(u);
      } else {
        const ok = el("button", "pill-btn primary", "Confirm");
        ok.type = "button";
        ok.addEventListener("click", async () => {
          const name = window.prompt("A name for this thread, as your team will call it:", c.report_names?.join(" + ") || "");
          if (!name) return;
          try { await call(`/api/unusual/${c.id}/confirm`, { name }); await load(); } catch (e) { msg.textContent = window.LGLoader.errorText(e, true); msg.className = "cb-msg bad"; }
        });
        const no = el("button", "pill-btn", "Dismiss");
        no.type = "button";
        no.addEventListener("click", async () => {
          if (!window.confirm("Dismiss it? This thread stays quiet for 30 days, unless it doubles.")) return;
          try { await call(`/api/unusual/${c.id}/dismiss`, {}); await load(); } catch (e) { msg.textContent = window.LGLoader.errorText(e, true); msg.className = "cb-msg bad"; }
        });
        act.append(ok, no);
      }
      act.append(msg);
    }
    if (act.childNodes.length) a.append(act);
    a.append(devBox);
    return a;
  }

  async function load() {
    const list = $("ptList"), mine = $("ptConfirmed"), status = $("ptStatus");
    try {
      const d = await call("/api/unusual");
      list.classList.remove("st-loading", "lg-has-logo");
      list.replaceChildren(); mine.replaceChildren();
      if (!d.ready) {
        status.textContent = "No count yet: the unusual-activity service has not run. An administrator installs it once with deploy/unusual_timer.sh install.";
      } else {
        const bits = [`Report day ${d.day}`, `normal = the middle of the last ${d.config?.window || 28} days`,
          `suggested at ${d.config?.ratio || 2}x normal and ${d.config?.min_devices || 10}+ devices`];
        if (d.quieted) bits.push(`${d.quieted} dismissed thread(s) kept quiet`);
        if (d.partial_days?.length) bits.push(`still counting: ${d.partial_days.join(", ")}`);
        status.textContent = bits.join(" · ") + ".";
      }
      const wrap = el("div", "pt-cards");
      for (const c of d.suggestions) wrap.append(card(c, false));
      if (!d.suggestions.length && d.ready) wrap.append(el("p", "pt-empty", "Nothing unusual: every thread is within its normal."));
      list.append(wrap);
      const w2 = el("div", "pt-cards");
      for (const c of d.confirmed) w2.append(card(c, true));
      if (!d.confirmed.length) w2.append(el("p", "pt-empty", decide ? "None yet: confirm a suggestion to watch it here." : "None yet."));
      mine.append(w2);
    } catch (e) {
      list.classList.remove("st-loading", "lg-has-logo");
      status.textContent = window.LGLoader.errorText(e); status.className = "cb-msg bad";
    } finally {
      window.LGLoader?.ready();
    }
  }
  load();
})();
