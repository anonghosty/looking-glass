/* Looking Glass · Services on the researchers' page, the patterns (services_intel.py, svc_patterns.py): the tabs
   Patterns, Across reports and Pattern fields of a report's Details window (kb-services.js calls
   window.LGServicePatterns.panes(name, titleOf)). Values are shown only when at least 5 hosts share them (free text:
   in two networks too); researchers never see a host. */
(() => {
  "use strict";
  const el = (t, c, x) => { const e = document.createElement(t); if (c) e.className = c; if (x != null) e.textContent = x; return e; };
  const fmt = (n) => Number(n || 0).toLocaleString("en-US");
  const pct = (x) => `${(x * 100).toFixed(x < 0.1 ? 1 : 0)}%`;
  const nh = (n) => `${fmt(n)} host${n === 1 ? "" : "s"}`;
  const csrf = () => document.querySelector('meta[name="csrf-token"]')?.content || "";
  const post = (url, body) => fetch(url, { method: "POST", headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf() }, body: JSON.stringify(body) });
  const KIND = { exact: "As it is", template: "Text, hosts masked", product: "Product and version", tags: "Tags (set)" };
  let intelCache = {};

  async function intel(name) {
    if (!intelCache[name]) {
      const r = await fetch(`/api/kb/service/intel?name=${encodeURIComponent(name)}`, { cache: "no-store" });
      intelCache[name] = r.ok ? await r.json() : { error: (await r.json().catch(() => ({}))).error || `HTTP ${r.status}` };
    }
    return intelCache[name];
  }
  async function copy(text, btn) {
    try { await navigator.clipboard.writeText(text); btn.textContent = "Copied"; } catch { btn.textContent = "Copy failed"; }
    setTimeout(() => { btn.textContent = "Copy"; }, 1400);
  }
  function code(c) {
    const s = el("span", "svp-code"); s.append(el("code", null, c));
    const b = el("button", "lg-btn sm ghost", "Copy"); b.type = "button"; b.title = `Copy ${c}: an analyst pastes it on the Combinations page`;
    b.addEventListener("click", () => copy(c, b)); s.append(b); return s;
  }
  function block(title, sub) {
    const s = el("section", "svc-block"); s.append(el("h4", null, title)); if (sub) s.append(el("p", "muted svp-sub", sub)); return s;
  }

  // ---------------- Patterns
  async function patternsPane(pane, name) {
    pane.replaceChildren(el("p", "svc-loading", "Counting the patterns of this report…"));
    const d = await intel(name);
    if (d.error) { pane.replaceChildren(el("p", "svc-loading", d.error)); return; }
    pane.replaceChildren();
    const intro = block("Patterns", `What the pattern fields show across the ${fmt(d.hosts)} hosts of this report in the days in memory. A value is shown when at least ${d.min_hosts} hosts share it` +
      " (free text: in two networks too), never what names a host.");
    pane.append(intro);
    const grid = el("div", "svp-grid");
    for (const p of d.patterns) {
      const b = block(p.label, `${KIND[p.kind] || p.kind} · field ${p.field}`);
      if (!p.values.length) b.append(el("p", "muted", "No value shared by enough hosts yet."));
      const max = Math.max(1, ...p.values.map((v) => v.hosts));
      const ul = el("ul", "svc-bars");
      for (const v of p.values) {
        const li = el("li"), bar = el("span", "svc-bar"), i = el("i"); i.style.width = `${Math.max(3, (v.hosts / max) * 100)}%`; bar.append(i);
        li.append(el("span", "svc-bk mono", v.value), bar, el("b", null, nh(v.hosts))); ul.append(li);
      }
      b.append(ul);
      if (p.shown > p.values.length) b.append(el("p", "muted svp-foot", `The ${p.values.length} shared by most hosts, of ${fmt(p.shown)}.`));
      if (p.hidden) b.append(el("p", "muted svp-foot", `${fmt(p.hidden)} other value${p.hidden === 1 ? "" : "s"} on fewer hosts (or one network): not shown.`));
      grid.append(b);
    }
    pane.append(grid);
    const cb = block("Exact combinations", "The full set of pattern items records carry, with its combination code for the analysts (paste it on the Combinations page, or attach it to a note).");
    if (!d.combinations.length) cb.append(el("p", "muted", "No combination is shared by enough hosts yet."));
    for (const c of d.combinations) {
      const row = el("div", "svp-combo");
      const items = el("div", "svp-items"); for (const it of c.items) items.append(el("span", "svp-chip", it));
      const fig = el("div", "svp-fig");
      fig.append(el("b", null, nh(c.hosts)), el("span", null, `${pct(c.share)} · ${fmt(c.records)} records${c.repeat_hosts ? ` · ${fmt(c.repeat_hosts)} repeating` : ""}`));
      row.append(items, fig, code(c.code)); cb.append(row);
    }
    if (d.combinations_small) cb.append(el("p", "muted svp-foot", `${fmt(d.combinations_small)} other combination${d.combinations_small === 1 ? "" : "s"} on fewer than ${d.min_hosts} hosts: not shown.`));
    pane.append(cb);
  }

  // ---------------- Across reports (and sinkholes)
  async function acrossPane(pane, name, titleOf) {
    pane.replaceChildren(el("p", "svc-loading", "Looking for these hosts in the other reports…"));
    const d = await intel(name);
    if (d.error) { pane.replaceChildren(el("p", "svc-loading", d.error)); return; }
    pane.replaceChildren();
    const s = d.sinkholes;
    const sk = block("Also calling botnet sinkholes", "Hosts of this report that the network communications reports also show: an exposed service on a device that is already infected.");
    const nums = el("div", "svc-nums"); const a = el("div"), b = el("div");
    a.append(el("b", null, fmt(s.hosts)), el("span", null, "hosts also in the communications reports")); b.append(el("b", null, pct(s.share)), el("span", null, "of this report's hosts"));
    nums.append(a, b); sk.append(nums);
    if (s.names.length) {
      const ul = el("ul", "svc-bars"), max = Math.max(...s.names.map((n) => n.hosts));
      for (const n of s.names) {
        const li = el("li"), bar = el("span", "svc-bar"), i = el("i"); i.style.width = `${Math.max(3, (n.hosts / max) * 100)}%`; bar.append(i);
        li.append(el("span", "svc-bk mono", n.name), bar, el("b", null, nh(n.hosts))); ul.append(li);
      }
      sk.append(ul);
    } else sk.append(el("p", "muted", "None of these hosts is in the communications reports of the days in memory."));
    if (s.hosts) sk.classList.add("svp-alert");
    pane.append(sk);
    const rs = block("The same hosts in other services reports", `${fmt(d.across.hosts_in_other_reports)} of the ${fmt(d.hosts)} hosts are in other services reports too. The sets of reports, ${d.min_hosts} hosts or more:`);
    if (!d.across.report_sets.length) rs.append(el("p", "muted", "No set of reports shared by enough hosts."));
    const ul = el("ul", "svp-sets");
    for (const x of d.across.report_sets) {
      const li = el("li"); const names = el("span"); names.textContent = x.reports.map(titleOf).join("  +  ");
      li.append(names, el("b", null, nh(x.hosts))); ul.append(li);
    }
    rs.append(ul); pane.append(rs);
    const cp = block("Exact patterns across reports", "Per report, the pattern items the same hosts carried there, with the code for the analysts.");
    if (!d.across.cross_patterns.length) cp.append(el("p", "muted", "No cross-report pattern shared by enough hosts."));
    for (const x of d.across.cross_patterns) {
      const row = el("div", "svp-combo svp-cross"), parts = el("div", "svp-parts");
      for (const p of x.parts) {
        const pr = el("div", "svp-part"); pr.append(el("b", null, titleOf(p.report)));
        const items = el("div", "svp-items"); if (!p.items.length) items.append(el("span", "muted", "the report only"));
        for (const it of p.items) items.append(el("span", "svp-chip", it));
        pr.append(items); parts.append(pr);
      }
      const fig = el("div", "svp-fig"); fig.append(el("b", null, nh(x.hosts)));
      row.append(parts, fig, code(x.code)); cp.append(row);
    }
    pane.append(cp);
  }

  // ---------------- Pattern fields (the researcher's choice) and product rules
  async function fieldsPane(pane, name, onSaved) {
    pane.replaceChildren(el("p", "svc-loading", "Measuring how each field groups the hosts…"));
    const r = await fetch(`/api/kb/service/fields?name=${encodeURIComponent(name)}`, { cache: "no-store" });
    const d = await r.json().catch(() => ({}));
    if (!r.ok) { pane.replaceChildren(el("p", "svc-loading", d.error || `HTTP ${r.status}`)); return; }
    pane.replaceChildren();
    const head = block("Pattern fields", (d.chosen_by ? `Chosen by ${d.chosen_by.by || "a researcher"} on ${d.chosen_by.date}.` : d.shipped ? "The pattern fields that come with Looking Glass." : "Only the tags are read so far: choose its pattern fields.") +
      ` Measured on ${fmt(d.records)} records in memory. Tick the fields whose values say what a host is (software, versions, fingerprints, models); fields that name or locate a host cannot be ticked.`);
    pane.append(head);
    const chosen = new Map(d.fields.map((f) => [f.field, f]));
    const tbl = el("table", "svp-ftab"), tb = el("tbody");
    tbl.append(Object.assign(el("thead"), { innerHTML: "<tr><th></th><th>Field</th><th>Kind</th><th>Label</th><th>On hosts</th><th>What it does</th></tr>" }));
    const rows = [];
    for (const s of d.suggestions) {
      const tr = el("tr", s.may ? (s.noise ? "svp-noise" : "") : "svp-off");
      const cb = el("input"); cb.type = "checkbox"; cb.checked = chosen.has(s.field); cb.disabled = !s.may;
      cb.setAttribute("aria-label", `Use ${s.field} as a pattern field`);
      const kind = el("select"); for (const [k, l] of Object.entries(KIND)) { const o = el("option", null, l); o.value = k; kind.append(o); }
      kind.value = chosen.get(s.field)?.kind || s.kind; kind.disabled = !s.may;
      const lbl = el("input", "svp-lbl"); lbl.value = chosen.get(s.field)?.label || s.field.replace(/_/g, " ").replace(/^./, (c) => c.toUpperCase()); lbl.maxLength = 60; lbl.disabled = !s.may;
      const c1 = el("td"); c1.append(cb);
      const c3 = el("td"); c3.append(kind); const c4 = el("td"); c4.append(lbl);
      tr.append(c1, el("td", "mono", s.field), c3, c4, el("td", "svc-num", pct(s.present)), el("td", "svp-why", s.why));
      tb.append(tr); rows.push({ s, cb, kind, lbl });
    }
    tbl.append(tb); head.append(tbl);
    const msg = el("span", "kbn-msg"), save = el("button", "lg-btn sm primary", "Save pattern fields"); save.type = "button";
    const reset = el("button", "lg-btn sm ghost", "Back to the shipped ones"); reset.type = "button"; reset.hidden = !d.chosen_by;
    const bar = el("div", "svp-actions"); bar.append(msg, reset, save); head.append(bar);
    save.addEventListener("click", async () => {
      const fields = rows.filter((x) => x.cb.checked && !x.cb.disabled).map((x) => ({ field: x.s.field, kind: x.kind.value, label: x.lbl.value.trim() }));
      save.disabled = true; msg.className = "kbn-msg"; msg.textContent = "Saving…";
      try {
        const rr = await post("/api/kb/service/fields", { name, fields });
        const j = await rr.json().catch(() => ({}));
        if (!rr.ok) throw new Error(j.error || `HTTP ${rr.status}`);
        msg.className = "kbn-msg ok"; msg.textContent = "Saved: the patterns are counted again with these fields.";
        delete intelCache[name]; onSaved?.();
      } catch (e) { msg.className = "kbn-msg bad"; msg.textContent = e.message; } finally { save.disabled = false; }
    });
    reset.addEventListener("click", async () => {
      const rr = await post("/api/kb/service/fields", { name, reset: true });
      if (rr.ok) { delete intelCache[name]; onSaved?.(); fieldsPane(pane, name, onSaved); }
    });
    // a product rule: how to read a product and its version out of a response
    const pr = block("Add a product rule", "When a banner, a system description or a server header holds a product Looking Glass does not recognise yet: the text it contains, and the product's name. Your rules are tried first.");
    const f = el("div", "svp-rule");
    const contains = el("input", "svp-in"); contains.placeholder = "the text, e.g. Cisco-1"; contains.maxLength = 60;
    const product = el("input", "svp-in"); product.placeholder = "the product, e.g. Cisco SSH"; product.maxLength = 60;
    const vl = el("label", "svp-v"), vcb = el("input"); vcb.type = "checkbox"; vcb.checked = true; vl.append(vcb, el("span", null, "the version follows the text"));
    const add = el("button", "lg-btn sm", "Add rule"); add.type = "button"; const m2 = el("span", "kbn-msg");
    f.append(contains, product, vl, add, m2); pr.append(f);
    add.addEventListener("click", async () => {
      const rr = await post("/api/kb/product-rules", { contains: contains.value, product: product.value, version: vcb.checked });
      const j = await rr.json().catch(() => ({}));
      if (!rr.ok) { m2.className = "kbn-msg bad"; m2.textContent = j.error || `HTTP ${rr.status}`; return; }
      m2.className = "kbn-msg ok"; m2.textContent = "Rule added."; contains.value = ""; product.value = ""; delete intelCache[name];
    });
    pane.append(pr);
  }

  window.LGServicePatterns = {
    panes(name, titleOf, onSaved) {
      intelCache = {};
      return [
        ["Patterns", (pane) => patternsPane(pane, name)],
        ["Across reports", (pane) => acrossPane(pane, name, titleOf)],
        ["Pattern fields", (pane) => fieldsPane(pane, name, onSaved)],
      ];
    },
  };
})();
