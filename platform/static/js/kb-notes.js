/* SPDX-License-Identifier: AGPL-3.0-only
   SPDX-FileCopyrightText: the Looking Glass contributors */
/* Looking Glass · the researchers' Notes window (Definitions page and Settings), apart from the define window.
   New findings on a name ("the C2 moved to …", "seen with … since Monday"), dated and signed with the author's full
   name (data/notes.json, notes.py), shown on every card and in the PDF reports as "Notes shared by Researcher/TI: <name>".
   A note can carry combination codes (combos.py): the exact combinations it points at, moved here from Intel gathered
   ("Move to notes") or pasted. An analyst pastes a code on the Combinations page to get those devices.
   kb-settings.js puts a Notes button on every row: window.LGNotes.open(name, section). */
(() => {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const el = (t, c, x) => { const e = document.createElement(t); if (c) e.className = c; if (x != null) e.textContent = x; return e; };
  const csrf = () => document.querySelector('meta[name="csrf-token"]')?.content || "";
  const post = (url, body) => fetch(url, { method: "POST", headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf() }, body: JSON.stringify(body) });
  const admin = document.body.dataset.admin === "1";
  const CODE_RX = /^LG-[CXB]-[0-9A-F]{8}$/;   // combinations, and decoded beacons (LG-B)
  // recorded before it is copied, under the person's name (lg-copy.js, insider.py); not recorded = not copied
  async function clip(text) {
    const r = await window.LGCopy.copy({ text, kind: "code", what: "a combination code (notes)", page: "Definitions" });
    if (!r.ok) window.LGCopy.tell(r.message);
    return r.ok;
  }

  // ---------------- the window
  const back = el("div", "kbn-back"); back.hidden = true;
  const box = el("section", "kbn-modal"); box.hidden = true; box.setAttribute("role", "dialog"); box.setAttribute("aria-modal", "true"); box.setAttribute("aria-labelledby", "kbnTitle");
  const head = el("header", "kbn-mhead");
  const titles = el("div"); const eyebrow = el("div", "kbn-eyebrow", "Notes"); const title = el("h2", "kbn-title"); title.id = "kbnTitle";
  const sub = el("p", "kbn-sub", "New findings on this name, for everyone who reads about it: they appear on the cards and in the PDF reports as " +
    "“Notes shared by Researcher/TI: your name”, with the date. Saved straight away, apart from the definition.");
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

  let cur = { name: "", section: "infections" }, codes = [];

  // ---------------- notes
  function codeTag(c, removable) {
    const t = el("span", "kbn-code"); t.title = c.text || c.code;
    const b = el("button", "kbn-code-b"); b.type = "button"; b.append(el("code", null, c.code)); b.title = `Copy ${c.code}`;
    b.addEventListener("click", async () => { msg.textContent = (await clip(c.code)) ? `Copied ${c.code}` : "Not copied"; msg.className = "kbn-msg ok"; });
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
      if (n.mine || admin) {                 // the server says whose it is (notes.py): no sign-in name on the page
        const del = el("button", "kbn-del", "Remove"); del.type = "button";
        del.addEventListener("click", async () => {
          if (!confirm("Remove this note? It disappears from the cards and future reports.")) return;
          del.disabled = true;                 // one request at a time; a dropped connection said (review 2026-11-13)
          try {
            const r = await post("/api/notes/delete", { id: n.id });
            const d = await r.json().catch(() => ({}));
            if (!r.ok) { msg.textContent = d.error || `Not removed (HTTP ${r.status})`; msg.className = "kbn-msg bad"; return; }
            load();
          } catch { msg.textContent = "The connection was interrupted. Try again."; msg.className = "kbn-msg bad"; }
          finally { del.disabled = false; }
        });
        meta.append(del);
      }
      list.append(li);
    }
  }
  // only the latest name's notes are drawn: A's arriving after B was opened are dropped (review 2026-11-13)
  let loadSeq = 0;
  async function load() {
    const mine = ++loadSeq;
    try {
      const r = await fetch(`/api/notes?section=${cur.section}&name=${encodeURIComponent(cur.name)}`, { cache: "no-store" });
      const notes = r.ok ? (await r.json()).notes : [];
      if (mine === loadSeq) render(notes);
    } catch { if (mine === loadSeq) render([]); }
  }

  // ---------------- combinations: picked, moved here from Intel gathered or pasted
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
  // one way to attach a code here: paste it (a combination comes from "Move to notes" in Intel gathered); the tabs
  // "Seen in the reports" and "Build one" were always hidden and are gone (2026-11-27 audit)
  const pasteTab = el("button", null, "Paste a code"); pasteTab.type = "button"; pasteTab.setAttribute("role", "tab");
  pasteTab.dataset.k = "paste"; pasteTab.setAttribute("aria-selected", "true"); tabs.append(pasteTab);
  function renderPane() { pastePane(); }
  function pastePane() {
    pane.replaceChildren();
    const f = el("div", "kbn-paste"), inp = el("input", "kbn-in"); inp.placeholder = "LG-C-1A2B3C4D"; inp.maxLength = 13; inp.spellcheck = false;
    inp.setAttribute("aria-label", "Combination code");
    const b = el("button", "lg-btn sm", "Attach"); b.type = "button"; const out = el("div", "kbn-res");
    const run = async () => {
      const code = inp.value.trim().toUpperCase();
      if (!CODE_RX.test(code)) { out.replaceChildren(el("span", "kbn-msg bad", "A code looks like LG-C-1A2B3C4D, LG-X-1A2B3C4D or LG-B-1A2B3C4D.")); return; }
      if (b.disabled) return;                  // Enter while it runs (review 2026-11-13)
      b.disabled = true;
      try {
        const r = await fetch(`/api/combo-codes/${code}`, { cache: "no-store" }); const x = await r.json().catch(() => ({}));
        if (!r.ok) { out.replaceChildren(el("span", "kbn-msg bad", x.error || `Unknown (HTTP ${r.status})`)); return; }
        pick({ code, text: x.text }); inp.value = ""; out.replaceChildren(el("span", "kbn-msg ok", `Attached: ${x.text}`));
      } catch { out.replaceChildren(el("span", "kbn-msg bad", "The connection was interrupted. Try again.")); }
      finally { b.disabled = false; }
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
    } catch { msg.textContent = "The connection was interrupted. Try again."; msg.className = "kbn-msg bad"; }   // (review 2026-11-13)
    finally { add.disabled = false; }
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
    cur = { name: name || "", section: section || "infections" }; codes = (attach || []).slice(0, 10);
    const svc = cur.section === "services";              // a services report: its pattern combinations, as for any name
    title.textContent = label || cur.name; eyebrow.textContent = `Notes · ${svc ? "services report" : cur.section === "issues" ? "issue" : "infection / category"}`;
    title.classList.toggle("kbn-title-text", !!label);
    ta.value = ""; msg.textContent = ""; msg.className = "kbn-msg";
    // the list says it is loading, not "No notes yet.", until the notes are in (2026-11-15)
    list.replaceChildren(el("li", "kbn-loading", "Loading the notes…")); listHead.querySelector(".kbn-count").textContent = "";
    renderPicked(); renderPane(); load();
    if (codes.length) {
      const beacons = codes.every((c) => String(c.code).startsWith("LG-B-"));
      msg.textContent = `${codes.length === 1 ? (beacons ? "The decoded beacons are" : "The combination is") : `${codes.length} codes are`} attached: write what you found and add the note${beacons ? "; track it as a finding to have it worked on" : ""}.`;
      msg.className = "kbn-msg ok";
    }
    box.hidden = false; back.hidden = false; document.body.classList.add("kbn-open");
    setTimeout(() => ta.focus(), 30);
  }
  window.LGNotes = { open };
})();
