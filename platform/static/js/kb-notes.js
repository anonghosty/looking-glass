/* Looking Glass · the researchers' Notes window (Definitions page and Settings), apart from the define window.
   New findings on a name ("the C2 moved to …", "seen with … since Monday"), dated and signed with the author's full
   name (data/notes.json, notes.py), shown on every card and in the PDF reports as "Notes shared by Researcher: <name>".
   A note can carry combination codes (combos.py): the exact combinations it points at, picked from what Intel gathered
   saw, built from ticked indicators, or pasted. An analyst pastes a code on the Combinations page to get those devices.
   kb-settings.js puts a Notes button on every row: window.LGNotes.open(name, section). */
(() => {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const el = (t, c, x) => { const e = document.createElement(t); if (c) e.className = c; if (x != null) e.textContent = x; return e; };
  const fmt = (n) => Number(n || 0).toLocaleString("en-US");
  const pl = (n, w) => `${fmt(n)} ${w}${n === 1 ? "" : "s"}`;
  const csrf = () => document.querySelector('meta[name="csrf-token"]')?.content || "";
  const post = (url, body) => fetch(url, { method: "POST", headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf() }, body: JSON.stringify(body) });
  const me = document.body.dataset.user || "";
  const admin = document.body.dataset.admin === "1";
  const CODE_RX = /^LG-[CX]-[0-9A-F]{8}$/;
  // the kinds a combination is made of (intel.py: COMMS_COMBO_KINDS, COMBO_KINDS)
  const KINDS = { infections: ["C2 domain", "DNS lookup", "TLS server name (SNI)", "User agent", "Associated tags"],
                  issues: ["Associated tags", "Other CVEs on the same hosts"], services: null };   // services: every pattern field
  const ofKinds = (k) => !KINDS[cur.section] || KINDS[cur.section].includes(k.kind);
  const rn = (x) => (intel?.labels || {})[x] || x;                    // a services report's title
  async function clip(text) {
    try { await navigator.clipboard.writeText(text); return true; } catch { /* not a secure page */ }
    const ta = el("textarea"); ta.value = text; ta.style.position = "fixed"; ta.style.opacity = "0"; document.body.append(ta); ta.select();
    let ok = false; try { ok = document.execCommand("copy"); } catch { /* */ } ta.remove(); return ok;
  }

  // ---------------- the window
  const back = el("div", "kbn-back"); back.hidden = true;
  const box = el("section", "kbn-modal"); box.hidden = true; box.setAttribute("role", "dialog"); box.setAttribute("aria-modal", "true"); box.setAttribute("aria-labelledby", "kbnTitle");
  const head = el("header", "kbn-mhead");
  const titles = el("div"); const eyebrow = el("div", "kbn-eyebrow", "Notes"); const title = el("h2", "kbn-title"); title.id = "kbnTitle";
  const sub = el("p", "kbn-sub", "New findings on this name, for everyone who reads about it: they appear on the cards and in the PDF reports as " +
    "“Notes shared by Researcher: your name”, with the date. Saved straight away, apart from the definition.");
  titles.append(eyebrow, title, sub);
  const close = el("button", "icon-btn kbn-close"); close.type = "button"; close.setAttribute("aria-label", "Close"); close.textContent = "✕";
  head.append(titles, close);
  const bodyEl = el("div", "kbn-body");
  // the list of notes
  const listHead = el("div", "kbn-h"); listHead.append(el("h3", null, "Notes"), el("span", "kbn-count", ""));
  const list = el("ul", "kbn-list");
  // the composer
  const comp = el("div", "kbn-compose");
  const ta = el("textarea", "kbn-text"); ta.rows = 4; ta.maxLength = 2000;
  ta.placeholder = "What did you find? e.g. the C2 domain moved to …, seen together with … since 9 November";
  const combosH = el("div", "kbn-h"); combosH.append(el("h3", null, "Combinations for this note"),
    el("span", "kbn-hint", "optional · the exact combinations the note is about, by code: an analyst pulls exactly those devices"));
  const picked = el("div", "kbn-picked");
  const tabs = el("div", "kbn-tabs"); tabs.setAttribute("role", "tablist");
  const pane = el("div", "kbn-pane");
  const row = el("div", "kbn-row"), msg = el("span", "kbn-msg"), add = el("button", "lg-btn sm primary", "Add note"); add.type = "button";
  row.append(msg, add);
  // "Track as a finding": the team follows it up on the Findings page, researcher → management → analyst → advisory
  const track = el("div", "kbn-track");
  const tl = el("label", "kbn-track-l"), tcb = el("input"); tcb.type = "checkbox";
  tl.append(tcb, el("span", null, "Track as a finding"), el("small", null, "gets a number and a status on the Findings page, so management and the analysts can follow it up"));
  const tt = el("input", "kbn-in kbn-track-t"); tt.maxLength = 140; tt.placeholder = "A short title, e.g. New BadBox2 C2 cluster on Android TV boxes"; tt.hidden = true;
  tt.setAttribute("aria-label", "Finding title");
  // the manager it goes to: a finding is a channel, only the people in it see it (people-pick.js)
  const toMgr = window.LGPeople ? window.LGPeople.picker("management") : null;
  if (toMgr) toMgr.el.hidden = true;
  tcb.addEventListener("change", () => { tt.hidden = !tcb.checked; if (toMgr) toMgr.el.hidden = !tcb.checked; add.textContent = tcb.checked ? "Add note and send it" : "Add note"; if (tcb.checked) tt.focus(); });
  track.append(tl, tt);
  if (toMgr) track.append(toMgr.el);
  comp.append(ta, combosH, picked, tabs, pane, track, row);
  bodyEl.append(listHead, list, el("h3", "kbn-newh", "New note"), comp);
  box.append(head, bodyEl);
  document.body.append(back, box);

  let cur = { name: "", section: "infections" }, codes = [], intel = null, tab = "seen", groupSel = "";

  // ---------------- notes
  function codeTag(c, removable) {
    const t = el("span", "kbn-code"); t.title = c.text || c.code;
    const b = el("button", "kbn-code-b"); b.type = "button"; b.append(el("code", null, c.code)); b.title = `Copy ${c.code}`;
    b.addEventListener("click", async () => { msg.textContent = (await clip(c.code)) ? `Copied ${c.code}` : "Copy failed"; msg.className = "kbn-msg ok"; });
    t.append(b, el("span", "kbn-code-t", c.text || ""));
    if (removable) {
      const x = el("button", "kbn-code-x", "✕"); x.type = "button"; x.setAttribute("aria-label", `Remove ${c.code} from this note`);
      x.addEventListener("click", () => { codes = codes.filter((y) => y.code !== c.code); renderPicked(); renderPane(); }); t.append(x);
    }
    return t;
  }
  function render(notes) {
    list.replaceChildren();
    listHead.querySelector(".kbn-count").textContent = notes.length ? `${notes.length}` : "";
    if (!notes.length) { list.append(el("li", "kbn-empty", "No notes yet.")); return; }
    for (const n of notes) {
      const li = el("li", "kbn-item");
      const meta = el("div", "kbn-meta"); meta.append(el("b", null, `${n.role}: ${n.by}`), el("span", null, n.date || ""));
      if (n.finding) {
        const a = el("a", `kbn-finding s-${n.finding.status}`, `Finding ${n.finding.number} · ${n.finding.status_label}`);
        a.href = `/findings#f${n.finding.number.slice(1)}`; a.title = "Open it on the Findings page"; meta.append(a);
      }
      li.append(meta, el("p", null, n.text));
      if (n.codes?.length) { const cs = el("div", "kbn-codes"); for (const c of n.codes) cs.append(codeTag(c, false)); li.append(cs); }
      if (n.user === me || admin) {
        const del = el("button", "kbn-del", "Remove"); del.type = "button";
        del.addEventListener("click", async () => {
          if (!confirm("Remove this note? It disappears from the cards and future reports.")) return;
          const r = await post("/api/notes/delete", { id: n.id });
          const d = await r.json().catch(() => ({}));
          if (!r.ok) { msg.textContent = d.error || `Not removed (HTTP ${r.status})`; msg.className = "kbn-msg bad"; return; }
          load();
        });
        meta.append(del);
      }
      list.append(li);
    }
  }
  async function load() {
    try {
      const r = await fetch(`/api/notes?section=${cur.section}&name=${encodeURIComponent(cur.name)}`, { cache: "no-store" });
      render(r.ok ? (await r.json()).notes : []);
    } catch { render([]); }
  }

  // ---------------- combinations: picked, and three ways to pick
  function renderPicked() {
    picked.replaceChildren();
    if (!codes.length) { picked.append(el("span", "kbn-none", "No combination attached.")); return; }
    for (const c of codes) picked.append(codeTag(c, true));
  }
  function pick(c) {
    if (codes.some((x) => x.code === c.code)) return;
    if (codes.length >= 10) { msg.textContent = "At most 10 combinations on one note."; msg.className = "kbn-msg bad"; return; }
    codes.push({ code: c.code, text: c.text }); renderPicked(); renderPane();
  }
  const TABS = [["seen", "Seen in the reports"], ["build", "Build one"], ["paste", "Paste a code"]];
  for (const [k, l] of TABS) {
    const b = el("button", null, l); b.type = "button"; b.setAttribute("role", "tab"); b.dataset.k = k;
    b.addEventListener("click", () => { tab = k; renderPane(); }); tabs.append(b);
  }
  function stat(t, cls) { return el("span", `kbn-stat ${cls || ""}`, t); }
  function choice(code, text, figures, show) {
    const li = el("li", "kbn-choice");
    const on = codes.some((x) => x.code === code);
    const b = el("button", `kbn-pick${on ? " on" : ""}`, on ? "Attached" : "Attach"); b.type = "button"; b.disabled = on;
    b.addEventListener("click", () => pick({ code, text }));
    const what = el("div", "kbn-what"); what.append(el("code", "kbn-c", code), el("span", null, show || text));
    const figs = el("div", "kbn-figs"); for (const f of figures) figs.append(f);
    li.append(what, figs, b); return li;
  }
  async function ensureIntel() {
    if (intel) return intel;
    pane.replaceChildren(el("p", "kbn-loading", "Reading what Intel gathered saw for this name…"));
    try {
      const r = await fetch(`/api/intel?section=${cur.section}&name=${encodeURIComponent(cur.name)}`, { cache: "no-store" });
      intel = r.ok ? await r.json() : { reports: [], across: {} };
    } catch { intel = { reports: [], across: {} }; }
    return intel;
  }
  async function renderPane() {
    // no list of every combination (noise): a code comes from "Move to notes" in Intel gathered, or is pasted
    tab = "paste";
    for (const b of tabs.children) { b.hidden = b.dataset.k !== "paste"; b.setAttribute("aria-selected", String(b.dataset.k === tab)); }
    if (tab === "paste") return pastePane();
    const d = await ensureIntel();
    if (tab === "seen") return seenPane(d);
    return buildPane(d);
  }
  // every combination of this name, grouped by report like a detailed drop-down list, with a filter: nothing to type
  function seenPane(d) {
    pane.replaceChildren();
    const groups = [];
    for (const r of d.reports || []) {
      const all = (r.combinations?.length ? r.combinations : r.single ? [r.single] : []).filter((c) => c.code);
      const svc = cur.section === "services";
      if (all.length) groups.push({ label: svc ? "Combinations" : r.report, sub: `${fmt(r.records)} records`, rows: all.map((c) => ({ code: c.code,
        text: `${rn(r.report)}: ${c.items.join(" + ") || "the name only"}`, show: c.items.join(" + ") || "the name only", figs: () =>
          [stat(pl(c.count, "record")), stat(pl(c.hosts, "device")), c.repeat_hosts ? stat(`${fmt(c.repeat_hosts)} repeating`, "rep") : stat("")] })) });
    }
    const xs = (d.across?.cross_combos || []).filter((x) => x.code);
    // a name seen in two or more reports always gets its Across reports tab, even when no device is shared (it says why)
    if (xs.length || (d.reports || []).length > 1 || d.across_always) groups.push({ label: "Across reports", sub: "devices seen in several reports", empty: !xs.length, rows: xs.map((x) => ({ code: x.code,
      text: `Across ${x.parts.map((p) => `${rn(p.report)}: ${p.items.join(" + ") || "the name only"}`).join(" | ")}`,
      show: x.parts.map((p) => `${rn(p.report)}: ${p.items.join(" + ") || "the report only"}`).join("  |  "), figs: () => [stat(pl(x.devices, "device")), stat("across reports", "x")] })) });
    // services: the hosts also calling botnet sinkholes, per infection
    const sk = (d.sinkholes?.names || []).filter((x) => x.code);
    if (sk.length) groups.push({ label: "Calling sinkholes", sub: "hosts also in the network communications reports", rows: sk.map((x) => ({ code: x.code,
      text: `${d.title || cur.name}: hosts also calling botnet sinkholes as ${x.name}`, show: `Also calling botnet sinkholes as ${x.name}`,
      figs: () => [stat(pl(x.hosts, "device")), stat("sinkholes", "x")] })) });
    if (!groups.length) { pane.append(el("p", "kbn-empty", "Intel gathered saw no combination for this name in the days in memory. Build one, or paste a code.")); return; }
    // one tab per report, and "Across reports" as a tab of its own; the list shows the chosen one
    if (!groups.some((g) => g.label === groupSel)) groupSel = groups[0].label;
    const tabsG = el("div", "kbn-gtabs"); tabsG.setAttribute("role", "tablist"); tabsG.setAttribute("aria-label", "Combinations of which report");
    const head = el("div", "kbn-ghead");
    const filt = el("input", "kbn-in kbn-filter"); filt.type = "text"; filt.spellcheck = false; filt.setAttribute("aria-label", "Filter the combinations");
    const lists = el("div", "kbn-groups");
    const draw = () => {
      for (const b of tabsG.children) b.setAttribute("aria-selected", String(b.dataset.g === groupSel));
      const g = groups.find((x) => x.label === groupSel);
      head.replaceChildren(el("b", null, g.label), el("span", null, `${g.sub} · ${g.rows.length} combination${g.rows.length === 1 ? "" : "s"}`));
      filt.placeholder = `Filter the ${g.rows.length} combination${g.rows.length === 1 ? "" : "s"} of ${g.label} (a domain, a tag, a user agent…)`;
      const q = filt.value.trim().toLowerCase(); lists.replaceChildren();
      const rows = g.rows.filter((x) => !q || x.text.toLowerCase().includes(q) || x.code.toLowerCase().includes(q));
      const ul = el("ul", "kbn-choices");
      for (const x of rows) ul.append(choice(x.code, x.text, x.figs(), x.show));
      if (g.empty) {
        const reps = (d.reports || []).map((r) => r.report), v6 = reps.filter((r) => /ipv6/i.test(r));
        const why = [cur.section === "services"
          ? `No exact pattern across reports is shared by ${d.min_hosts || 5} or more of this report's devices in the days in memory, so there is none to attach.`
          : `No device of ${cur.name} was seen in more than one report in the days in memory, so there is no cross-report combination to attach.`];
        if (v6.length && v6.length < reps.length) why.push(`${v6.join(", ")} records a different IP address for a machine than the other reports, so their devices never match.`);
        if (reps.some((r) => /dns/i.test(r)) && reps.some((r) => !/dns/i.test(r))) why.push("A DNS report often sees the resolver that looked the name up, not the infected machine, so it rarely shares a device with the other reports.");
        const box = el("div", "kbn-empty kbn-why"); for (const t of why) box.append(el("p", null, t)); lists.append(box);
      } else lists.append(rows.length ? ul : el("p", "kbn-empty", "Nothing matches the filter."));
    };
    for (const g of groups) {
      const b = el("button", `kbn-gtab${g.label === "Across reports" ? " x" : ""}`); b.type = "button"; b.setAttribute("role", "tab"); b.dataset.g = g.label;
      b.append(el("span", null, g.label), el("small", null, String(g.rows.length)));
      b.addEventListener("click", () => { groupSel = g.label; filt.value = ""; draw(); }); tabsG.append(b);
    }
    filt.addEventListener("input", draw);
    pane.append(tabsG, head, filt, lists, el("p", "kbn-foot", `Every combination Intel gathered saw for ${cur.name} in the days in memory (${(d.days || []).join(", ")}), the most frequent first.`));
    draw();
  }
  function buildPane(d) {
    pane.replaceChildren();
    const reps = (d.reports || []).filter((r) => r.indicators.some(ofKinds));
    if (!reps.length) { pane.append(el("p", "kbn-empty", cur.section === "services"
      ? "There is nothing to build from yet: no pattern value of this report is shared by 5 or more hosts in the days in memory."
      : "There is nothing to build from: the reports in memory carry no C2 domain, lookup, user agent or tag for this name.")); return; }
    const form = el("div", "kbn-build");
    const sel = el("select", "kbn-sel"); sel.setAttribute("aria-label", "Report");
    for (const r of reps) { const o = el("option", null, `${rn(r.report)} (${fmt(r.records)} records)`); o.value = r.report; sel.append(o); }
    const vals = el("div", "kbn-vals");
    const res = el("div", "kbn-res");
    const go = el("button", "lg-btn sm", "Make the code"); go.type = "button";
    const draw = () => {
      vals.replaceChildren(); res.replaceChildren();
      const r = reps.find((x) => x.report === sel.value);
      for (const k of r.indicators.filter(ofKinds)) {
        const g = el("fieldset", "kbn-kind"); g.append(el("legend", null, k.kind));
        for (const v of k.values) {
          // services: an item is "Label: value" (svc_patterns / services_intel), the value shown as it is
          const l = el("label", "kbn-tick"); const cb = el("input"); cb.type = "checkbox"; cb.value = cur.section === "services" ? `${k.kind}: ${v.value}` : v.value;
          l.append(cb, el("span", null, v.value), el("small", null, `${fmt(v.count)}`)); l.title = `${fmt(v.count)} records carry it`; g.append(l);
        }
        vals.append(g);
      }
    };
    sel.addEventListener("change", draw);
    go.addEventListener("click", async () => {
      const items = [...vals.querySelectorAll("input:checked")].map((x) => x.value);
      go.disabled = true; res.replaceChildren(el("span", "kbn-loading", "Making the code…"));
      try {
        const r = await post("/api/combo-codes/new", { section: cur.section, name: cur.name, report: sel.value, items });
        const x = await r.json().catch(() => ({}));
        res.replaceChildren();
        if (!r.ok) { res.append(el("span", "kbn-msg bad", x.error || `Failed (HTTP ${r.status})`)); return; }
        const line = el("div", "kbn-made");
        line.append(el("code", "kbn-c", x.code), el("span", null, x.text),
          el("span", `kbn-stat${x.records ? "" : " warn"}`, x.records ? `${pl(x.records, "record")} · ${pl(x.devices, "device")} carry exactly this now`
            : "No record carries exactly this set in the days in memory: an analyst may still find it in older days"));
        const a = el("button", "lg-btn sm primary", "Attach"); a.type = "button"; a.addEventListener("click", () => pick({ code: x.code, text: x.text }));
        line.append(a); res.append(line);
      } finally { go.disabled = false; }
    });
    form.append(el("p", "kbn-foot", "Pick a report and tick the indicators that must come together. “Exactly” means: a record with these and no other indicator of these kinds. Tick nothing for records that carry only the name."),
      sel, vals, go, res);
    pane.append(form); draw();
  }
  function pastePane() {
    pane.replaceChildren();
    const f = el("div", "kbn-paste"), inp = el("input", "kbn-in"); inp.placeholder = "LG-C-1A2B3C4D"; inp.maxLength = 13; inp.spellcheck = false;
    inp.setAttribute("aria-label", "Combination code");
    const b = el("button", "lg-btn sm", "Attach"); b.type = "button"; const out = el("div", "kbn-res");
    const run = async () => {
      const code = inp.value.trim().toUpperCase();
      if (!CODE_RX.test(code)) { out.replaceChildren(el("span", "kbn-msg bad", "A code looks like LG-C-1A2B3C4D or LG-X-1A2B3C4D.")); return; }
      const r = await fetch(`/api/combo-codes/${code}`, { cache: "no-store" }); const x = await r.json().catch(() => ({}));
      if (!r.ok) { out.replaceChildren(el("span", "kbn-msg bad", x.error || `Unknown (HTTP ${r.status})`)); return; }
      pick({ code, text: x.text }); inp.value = ""; out.replaceChildren(el("span", "kbn-msg ok", `Attached: ${x.text}`));
    };
    b.addEventListener("click", run); inp.addEventListener("keydown", (e) => { if (e.key === "Enter") { e.preventDefault(); run(); } });
    const svcHint = el("div", "kbn-svc-hint");
    svcHint.append(el("b", null, cur.section === "services" ? "To attach a pattern of this report: " : "To attach a combination: "),
      document.createTextNode("open Intel gathered, find the combination, the pattern across reports or the group that matters, and press “Move to notes”: it arrives here attached. Or paste a code below."));
    const go = el("button", "lg-btn sm", "Open Intel gathered"); go.type = "button";
    go.addEventListener("click", () => { const n = cur.name, s = cur.section; shut(); window.LGIntel?.open(n, s); }); svcHint.append(go);
    f.append(inp, b);
    pane.append(svcHint,
      el("p", "kbn-foot", "A code from another note, report or colleague, for example a combination of another name this finding ties in with."), f, out);
  }

  add.addEventListener("click", async () => {
    const text = ta.value.trim(); if (!text) { msg.textContent = "Write the note first."; msg.className = "kbn-msg bad"; return; }
    add.disabled = true;
    try {
      const body = { section: cur.section, name: cur.name, text, codes: codes.map((c) => c.code) };
      if (tcb.checked) {
        if (toMgr && !toMgr.check()) { msg.textContent = "Choose the manager it goes to."; msg.className = "kbn-msg bad"; return; }
        body.finding = { title: tt.value.trim(), to: toMgr ? toMgr.value() : "" };
      }
      const r = await post("/api/notes", body);
      const d = await r.json().catch(() => ({}));
      if (!r.ok) { msg.textContent = d.error || `Not saved (HTTP ${r.status})`; msg.className = "kbn-msg bad"; return; }
      const tracked = tcb.checked;
      ta.value = ""; codes = []; tcb.checked = false; tt.value = ""; tt.hidden = true; add.textContent = "Add note";
      if (toMgr) { toMgr.reset(); toMgr.el.hidden = true; } renderPicked(); renderPane();
      const f = (d.notes || []).find((n) => n.id === d.note?.id)?.finding;
      msg.textContent = tracked && f ? `Note saved and sent as finding ${f.number}: only you and the manager you chose see it.` : "Note saved and shared."; msg.className = "kbn-msg ok"; render(d.notes || []);
    } finally { add.disabled = false; }
  });

  // ---------------- open / close
  let opener = null;
  function shut() { box.hidden = true; back.hidden = true; document.body.classList.remove("kbn-open"); opener?.focus?.(); }
  close.addEventListener("click", shut); back.addEventListener("click", shut);
  box.addEventListener("keydown", (e) => { if (e.key === "Escape") { e.stopPropagation(); shut(); } });
  // label: the readable title to show (e.g. a report's official name); the notes stay keyed on name
  // attach: [{code, text}] already on the new note ("Move to notes" in Intel gathered)
  function open(name, section, label, attach) {
    opener = document.activeElement;
    cur = { name: name || "", section: section || "infections" }; codes = (attach || []).slice(0, 10); intel = null; tab = "seen"; groupSel = "";
    const svc = cur.section === "services";              // a services report: its pattern combinations, as for any name
    title.textContent = label || cur.name; eyebrow.textContent = `Notes · ${svc ? "services report" : cur.section === "issues" ? "issue" : "infection / category"}`;
    title.classList.toggle("kbn-title-text", !!label);
    ta.value = ""; msg.textContent = ""; msg.className = "kbn-msg";
    render([]); renderPicked(); renderPane(); load();
    if (codes.length) { msg.textContent = `${codes.length === 1 ? "The combination is" : `${codes.length} combinations are`} attached: write what you found and add the note.`; msg.className = "kbn-msg ok"; }
    box.hidden = false; back.hidden = false; document.body.classList.add("kbn-open");
    setTimeout(() => ta.focus(), 30);
  }
  window.LGNotes = { open };
})();
