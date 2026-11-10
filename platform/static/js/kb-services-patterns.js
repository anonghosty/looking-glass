/* Looking Glass · Services on the researchers' page: a report's pattern fields (svc_patterns.py), drawn in the Intel
   gathered window (intel.js calls window.LGServicePatterns.fields(pane, name, onSaved)). The patterns, combinations,
   across reports and sinkholes are drawn by intel.js itself (services_intel.py, /api/intel?section=services).
   Values are shown only when at least 5 hosts share them (free text: in two networks too); researchers never see a host. */
(() => {
  "use strict";
  const el = (t, c, x) => { const e = document.createElement(t); if (c) e.className = c; if (x != null) e.textContent = x; return e; };
  const fmt = (n) => Number(n || 0).toLocaleString("en-US");
  const pct = (x) => `${(x * 100).toFixed(x < 0.1 ? 1 : 0)}%`;
  const csrf = () => document.querySelector('meta[name="csrf-token"]')?.content || "";
  const post = (url, body) => fetch(url, { method: "POST", headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf() }, body: JSON.stringify(body) });
  // how a field's value is read; every kind shows a value only when 5 or more hosts share it
  const KIND = {
    exact: ["Exact value", "The value as the report gives it, e.g. a version number or a fingerprint. A value that holds an address, a host name, an e-mail, a date or a long ID is never read."],
    template: ["Text, hosts masked", "Free text such as a banner: addresses, host names, e-mails, dates and IDs are replaced by placeholders, and a text is shown only when hosts in two or more networks share it."],
    product: ["Product and version", "Only the product and its version are read out of the text (product rules); the rest of the text is dropped."],
    tags: ["Tags (set)", "Each tag on its own, CVEs left out (they are in Issues)."],
  };
  function block(title, sub) {
    const s = el("section", "svc-block"); s.append(el("h4", null, title)); if (sub) s.append(el("p", "muted svp-sub", sub)); return s;
  }

  async function fieldsPane(pane, name, onSaved) {
    pane.replaceChildren(el("p", "svc-loading", "Measuring how each field groups the hosts…"));
    const r = await fetch(`/api/kb/service/fields?name=${encodeURIComponent(name)}`, { cache: "no-store" });
    const d = await r.json().catch(() => ({}));
    if (!r.ok) { pane.replaceChildren(el("p", "svc-loading", d.error || `HTTP ${r.status}`)); return; }
    pane.replaceChildren();
    const head = block("Pattern fields", (d.chosen_by ? `Chosen by ${d.chosen_by.by || "a researcher"} on ${d.chosen_by.date}.` : d.shipped ? "The pattern fields that come with Looking Glass." : "Only the tags are read so far: choose its pattern fields.") +
      ` Measured on ${fmt(d.records)} records in memory. Tick the fields whose values say what a host is (software, versions, fingerprints, models); fields that name or locate a host cannot be ticked.`);
    pane.append(head);
    // what each kind does, said once above the table
    const kinds = el("dl", "svp-kinds");
    for (const [l, t] of Object.values(KIND)) kinds.append(el("dt", null, l), el("dd", null, t));
    head.append(kinds, el("p", "muted svp-sub", `Whatever the kind, a value is shown only when ${d.min_hosts || 5} or more hosts share it, so no value points at one host.`));
    const chosen = new Map(d.fields.map((f) => [f.field, f]));
    const tbl = el("table", "svp-ftab"), tb = el("tbody");
    tbl.append(Object.assign(el("thead"), { innerHTML: "<tr><th></th><th>Field</th><th>Kind</th><th>Label</th><th>On hosts</th><th>What it does</th></tr>" }));
    const rows = [];
    for (const s of d.suggestions) {
      const tr = el("tr", s.may ? (s.noise ? "svp-noise" : "") : "svp-off");
      const cb = el("input"); cb.type = "checkbox"; cb.checked = chosen.has(s.field); cb.disabled = !s.may;
      cb.setAttribute("aria-label", `Use ${s.field} as a pattern field`);
      const kind = el("select"); for (const [k, [l, t]] of Object.entries(KIND)) { const o = el("option", null, l); o.value = k; o.title = t; kind.append(o); }
      kind.value = chosen.get(s.field)?.kind || s.kind; kind.disabled = !s.may;
      const tip = () => { kind.title = KIND[kind.value]?.[1] || ""; }; tip(); kind.addEventListener("change", tip);
      const lbl = el("input", "svp-lbl"); lbl.value = chosen.get(s.field)?.label || s.field.replace(/_/g, " ").replace(/^./, (c) => c.toUpperCase()); lbl.maxLength = 60; lbl.disabled = !s.may;
      const c1 = el("td"); c1.append(cb);
      const c3 = el("td"); c3.append(kind); const c4 = el("td"); c4.append(lbl);
      tr.append(c1, el("td", "mono", s.field), c3, c4, el("td", "svc-num", pct(s.present)), el("td", "svp-why", s.why));
      tb.append(tr); rows.push({ s, cb, kind, lbl });
    }
    tbl.append(tb);
    const wrap = el("div", "svp-twrap"); wrap.append(tbl); head.append(wrap);
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
        setTimeout(() => onSaved?.(), 700);
      } catch (e) { msg.className = "kbn-msg bad"; msg.textContent = e.message; } finally { save.disabled = false; }
    });
    reset.addEventListener("click", async () => {
      const rr = await post("/api/kb/service/fields", { name, reset: true });
      if (rr.ok) onSaved?.();
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
      m2.className = "kbn-msg ok"; m2.textContent = "Rule added: the patterns are counted with it from now on."; contains.value = ""; product.value = "";
    });
    pane.append(pr);
  }

  window.LGServicePatterns = { fields: fieldsPane };
})();
