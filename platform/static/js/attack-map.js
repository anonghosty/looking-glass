/* Looking Glass · MITRE ATT&CK mappings on the Definitions page (attack_map.py), built from the page's own parts:
   st-card dz, dz-stats tabs (click to filter), dz-toolbar search, dz-pill statuses, lg-btn buttons, dz-panel for the picker,
   dz-input fields. Each Shadowserver report is shown by its readable name (the collection id only in a small line).
   Researchers Confirm or Change a suggestion (short list first, then a search over the local copy of ATT&CK, grouped by
   tactic; chosen techniques as removable chips), or record "No ATT&CK technique fits". A retired technique is shown as
   before -> after. Text from the server is always set as text; links only http(s), in a new tab. */
(() => {
  "use strict";
  const $ = (id) => document.getElementById(id);
  if (!$("cardAttack")) return;
  const el = (t, c, x) => { const e = document.createElement(t); if (c) e.className = c; if (x != null) e.textContent = x; return e; };
  const fmt = (n) => Number(n || 0).toLocaleString("en-US");
  const csrf = () => document.querySelector('meta[name="csrf-token"]')?.content || "";
  const get = async (u) => { const r = await fetch(u, { cache: "no-store" }); const j = await r.json().catch(() => ({})); if (!r.ok) throw new Error(j.error || `HTTP ${r.status}`); return j; };
  const post = async (u, b) => {
    const r = await fetch(u, { method: "POST", headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf() }, body: JSON.stringify(b) });
    const j = await r.json().catch(() => ({})); if (!r.ok) throw new Error(j.error || `Refused (${r.status})`); return j;
  };
  const httpUrl = (u) => { try { return ["http:", "https:"].includes(new URL(u).protocol); } catch { return false; } };
  const STATUS = { check: ["Please check", "warn"], suggested: ["Suggested", "info"], none: ["Not mapped yet", ""], reviewed: ["Reviewed", "ok"] };
  const CERT = { observed: ["Observed", "the report saw it"], possible: ["Possible", "an exposure an attacker could use"], known: ["Known for this malware", "MITRE's links"] };
  const PAGE = 40;
  let data = null, tab = "suggested", shown = PAGE, onlyNotice = false;

  // a technique as a chip: ID (MITRE's page, new tab) + name + tactic badge
  function chip(t, opts = {}) {
    const c = el("span", `am-chip${opts.old ? " am-chip-old" : ""}`);
    // hover: MITRE's short definition and how to defend (MITRE's mitigations)
    const tip = [t.desc && `What it is (MITRE): ${t.desc}`, t.defend?.length && `How to defend: ${t.defend.map((m) => `${m.id} ${m.name}`).join("; ")}`].filter(Boolean).join("\n");
    if (tip) c.title = tip;
    if (httpUrl(t.url)) { const a = el("a", "am-chip-id mono", t.id); a.href = t.url; a.target = "_blank"; a.rel = "noopener noreferrer"; a.title = `${t.id} on attack.mitre.org`; c.append(a); }
    else c.append(el("span", "am-chip-id mono", t.id));
    c.append(el("span", "am-chip-name", t.name));
    for (const ta of (t.tactics || []).slice(0, 2)) c.append(el("span", "am-tactic", ta));
    if (opts.remove) {
      const x = el("button", "am-chip-x", "×"); x.type = "button"; x.title = `Remove ${t.id}`; x.setAttribute("aria-label", `Remove ${t.id} ${t.name}`);
      x.addEventListener("click", opts.remove); c.append(x);
    }
    return c;
  }
  const chips = (list, opts) => { const d = el("div", "am-chips"); for (const t of list) d.append(chip(t, opts)); return d; };
  const certBadge = (c) => { const [w, why] = CERT[c] || []; if (!w) return null; const b = el("span", `am-cert am-cert-${c}`, w); b.title = `${w}: ${why}`; return b; };

  async function load(first) {
    try { data = await get("/api/attack"); }
    catch (e) { if (first) { $("cardAttack").hidden = true; return; } $("amStatus").textContent = `Could not load: ${e.message}`; return; }
    $("cardAttack").hidden = false;
    if (first) {                                     // open on the tab that needs work first
      const c = data.summary.counts || {};
      tab = c.check ? "check" : c.suggested ? "suggested" : c.none ? "none" : "reviewed";
    }
    render();
  }
  function rows() {
    const all = [...data.todo, ...data.reviewed];
    let r = all.filter((x) => x.status === tab);
    if (onlyNotice && data.summary.notice) r = all.filter((x) => (data.summary.notice.items || []).includes(x.report));
    const q = $("amSearch").value.trim().toLowerCase();
    if (q) r = all.filter((x) => [x.title, x.report, x.why, ...(x.techniques || []).flatMap((t) => [t.id, t.name, ...(t.tactics || [])])].join(" ").toLowerCase().includes(q));
    return r;
  }
  function render() {
    const s = data.summary, c = s.counts || {};
    $("amN1").textContent = fmt(c.check); $("amN2").textContent = fmt(c.suggested); $("amN3").textContent = fmt(c.none); $("amN4").textContent = fmt(c.reviewed);
    for (const b of document.querySelectorAll("[data-am]")) b.setAttribute("aria-selected", String(!onlyNotice && !$("amSearch").value.trim() && b.dataset.am === tab));
    // one notice per ATT&CK update, with a button that shows just its mappings
    const nb = $("amNotice"); nb.replaceChildren();
    if (s.notice) {
      const n = s.notice, left = data.todo.filter((x) => x.status === "check" && (n.items || []).includes(x.report)).length;
      const box = el("div", "dz-panel am-notice");
      const row = el("div", "dz-panel-row");
      const txt = el("p", "am-notice-text"); txt.append(el("b", null, n.text), el("span", "dz-by", `Noticed on ${String(n.at).slice(0, 10)}${left ? ` · ${left} still to check` : n.to_check ? " · all checked" : ""}`));
      row.append(txt);
      if (left) {
        const b = el("button", `lg-btn sm${onlyNotice ? " active" : ""}`, onlyNotice ? "Show every report" : `Show the ${left} to check`); b.type = "button";
        b.addEventListener("click", () => { onlyNotice = !onlyNotice; shown = PAGE; render(); });
        row.append(b);
      }
      box.append(row); nb.append(box);
    }
    $("amStatus").textContent = !s.version ? "MITRE ATT&CK is not downloaded yet: an administrator refreshes the sources above."
      : `MITRE ATT&CK v${s.version}` + (s.kev ? ` · CVEs: CTID KEV mappings (made with ATT&CK v${s.kev.attack_version}, ${fmt(s.kev.count)} CVEs)` : "");
    const box = $("amList"); box.replaceChildren();
    const list = rows();
    if (!list.length) {
      box.append(el("p", "am-empty", $("amSearch").value.trim() ? "Nothing matches the search." : tab === "reviewed" ? "No mapping reviewed yet."
        : tab === "check" ? "Nothing to check: no report or ATT&CK change touches a mapping." : "Nothing here: every report in this group has been looked at."));
      return;
    }
    for (const x of list.slice(0, shown)) box.append(item(x));
    if (list.length > shown) {
      const more = el("button", "lg-btn sm ghost am-more", `Show ${Math.min(PAGE, list.length - shown)} more of ${fmt(list.length - shown)}`); more.type = "button";
      more.addEventListener("click", () => { shown += PAGE; render(); });
      box.append(more);
    }
  }
  function item(x) {
    const card = el("article", `am-report am-${x.status}`);
    card.setAttribute("aria-label", x.title);
    const head = el("div", "am-report-head");
    const h = el("h3", "am-report-title", x.title); h.title = `Report: ${x.report}`;
    const [lbl, kind] = x.status === "reviewed" && x.nofit ? ["No technique fits", ""] : STATUS[x.status] || ["", ""];
    head.append(h, el("span", `dz-pill ${kind}`, lbl));
    const cb = certBadge(x.certainty); if (cb && !(x.status === "reviewed" && x.nofit)) head.append(cb);
    card.append(head, el("p", "dz-by mono", [x.report, x.section, x.type].filter(Boolean).join(" · ")));
    if (x.why) card.append(el("p", "am-why", x.why));
    if (x.status === "check") {
      if (x.check_reason) card.append(el("p", "am-reason", x.check_reason));
      // before -> after: what it was (retired ones struck, "retired in vNN") and what is suggested now
      const ba = el("div", "am-ba");
      const before = el("div", "am-ba-side"); before.append(el("span", "am-ba-label", "Before"));
      const bl = el("div", "am-chips");
      for (const t of x.previous || []) { bl.append(chip(t, { old: !!x.retired?.[t.id] })); if (x.retired?.[t.id]) bl.append(el("span", "am-retired", `retired in ${x.retired[t.id]}`)); }
      if (!(x.previous || []).length) bl.append(el("span", "dz-by", "no technique"));
      before.append(bl);
      const after = el("div", "am-ba-side"); after.append(el("span", "am-ba-label", "Suggested now"));
      after.append((x.check_suggest || []).length ? chips(x.check_suggest) : el("span", "dz-by", "MITRE names no replacement: choose from the short list"));
      ba.append(before, el("span", "am-ba-arrow", "→"), after);
      card.append(ba);
    } else if (x.status === "reviewed") {
      if (x.nofit) card.append(el("p", "am-why", "Recorded: no ATT&CK technique fits this report."));
      else card.append(chips(x.techniques || []));
      card.append(el("p", "dz-by", `Reviewed by ${x.by || "?"}${x.at ? ` on ${String(x.at).slice(0, 10)}` : ""}${x.version ? ` · ATT&CK v${x.version}` : ""}${x.note ? ` · Note: ${x.note}` : ""}`));
    } else if ((x.techniques || []).length) card.append(chips(x.techniques));
    const sug = x.status === "check" ? (x.check_suggest || []) : x.status === "suggested" ? (x.techniques || []) : [];
    const acts = el("div", "am-acts");
    if (sug.length) {
      const ok = el("button", "lg-btn sm primary", "Confirm"); ok.type = "button";
      ok.title = `Confirm ${sug.map((t) => t.id).join(", ")} for ${x.title}`;
      ok.addEventListener("click", () => save(x, sug.map((t) => t.id), false, "", ok));
      acts.append(ok);
    }
    const ch = el("button", "lg-btn sm", sug.length || x.status === "reviewed" ? "Change" : "Choose techniques"); ch.type = "button";
    ch.setAttribute("aria-expanded", "false");
    ch.addEventListener("click", () => picker(card, x, ch));
    acts.append(ch);
    card.append(acts);
    return card;
  }
  async function save(x, ids, nofit, note, btn) {
    if (btn) { btn.disabled = true; btn.classList.add("is-busy"); }
    window.LGLoader?.busy("Saving the mapping");
    try {
      await post("/api/attack/mapping", { report: x.report, techniques: ids, nofit, note });
      data = await get("/api/attack");
      render();
      $("amStatus").textContent = `Saved: ${x.title} is reviewed.`; $("amStatus").className = "dz-status ok";
    } catch (e) {
      $("amStatus").textContent = `Not saved: ${e.message}`; $("amStatus").className = "dz-status bad";
      if (btn) { btn.disabled = false; btn.classList.remove("is-busy"); }
    } finally { window.LGLoader?.ready(); }
  }

  // the picker: a dz-panel inside the report's card. Short list first, then a search; both grouped by tactic.
  function grouped(list, into, isOn, toggle) {
    into.replaceChildren();
    const by = {};
    for (const t of list) (by[(t.tactics || ["Other"])[0]] ||= []).push(t);
    for (const [ta, ts] of Object.entries(by)) {
      const g = el("fieldset", "am-group"); g.append(el("legend", null, ta));
      for (const t of ts) {
        const lab = el("label", "am-opt"), cb = el("input"); cb.type = "checkbox"; cb.checked = isOn(t.id); cb.dataset.tid = t.id;
        cb.addEventListener("change", () => toggle(t, cb.checked));
        lab.append(cb, chip(t)); g.append(lab);
      }
      into.append(g);
    }
  }
  async function picker(card, x, btn) {
    const open = card.querySelector(".am-picker");
    if (open) { open.remove(); btn.setAttribute("aria-expanded", "false"); btn.focus(); return; }
    btn.setAttribute("aria-expanded", "true");
    const chosen = new Map(), current = (x.status === "check" ? x.check_suggest : x.techniques) || [];
    for (const t of current) chosen.set(t.id, t);
    let nofit = !!x.nofit && x.status === "reviewed";
    const panel = el("div", "dz-panel am-picker");
    panel.setAttribute("role", "group"); panel.setAttribute("aria-label", `Choose ATT&CK techniques for ${x.title}`);
    const sel = el("div", "am-chosen"), short = el("div", "am-groups"), found = el("div", "am-groups");
    const nf = el("label", "am-opt am-nofit"), nfc = el("input"); nfc.type = "checkbox"; nfc.checked = nofit;
    const sync = () => {
      sel.replaceChildren(el("span", "am-ba-label", "Chosen"));
      if (nofit) sel.append(el("span", "dz-pill", "No ATT&CK technique fits"));
      else if (!chosen.size) sel.append(el("span", "dz-by", "nothing yet: tick techniques below, or say that none fits"));
      else for (const t of chosen.values()) sel.append(chip(t, { remove: () => toggle(t, false) }));
      panel.querySelectorAll("input[data-tid]").forEach((c) => { c.checked = !nofit && chosen.has(c.dataset.tid); });
      nfc.checked = nofit;
    };
    const toggle = (t, on) => { if (on) { chosen.set(t.id, t); nofit = false; } else chosen.delete(t.id); sync(); };
    nfc.addEventListener("change", () => { nofit = nfc.checked; if (nofit) chosen.clear(); sync(); });
    nf.append(nfc, el("span", null, "No ATT&CK technique fits this report"));
    const q = el("input", "dz-input am-q"); q.type = "search"; q.maxLength = 60;
    q.placeholder = "Search all of ATT&CK: an ID (T1071), a word (proxy) or a tactic (credential access)"; q.setAttribute("aria-label", "Search ATT&CK techniques");
    const note = el("textarea", "dz-input am-note"); note.rows = 2; note.maxLength = 600; note.value = x.note || "";
    note.placeholder = "Note (optional): why these techniques, or why none fits"; note.setAttribute("aria-label", "Note");
    const ok = el("button", "lg-btn sm primary", "Save mapping"), cancel = el("button", "lg-btn sm ghost", "Cancel"); ok.type = cancel.type = "button";
    const close = () => { panel.remove(); btn.setAttribute("aria-expanded", "false"); btn.focus(); };
    ok.addEventListener("click", () => save(x, nofit ? [] : [...chosen.keys()], nofit, note.value, ok));
    cancel.addEventListener("click", close);
    panel.addEventListener("keydown", (e) => { if (e.key === "Escape") { e.stopPropagation(); close(); } });
    const foot = el("div", "am-acts"); foot.append(ok, cancel);
    panel.append(el("h4", "am-picker-h", `Techniques for ${x.title}`), sel, el("p", "am-ba-label", "Fit this kind of report"), short,
      el("label", "am-ba-label", "Or search"), q, found, nf, note, foot);
    card.append(panel);
    short.append(el("div", "st-loading", "Finding techniques that fit…"));
    try {
      const j = await get(`/api/attack/shortlist?report=${encodeURIComponent(x.report)}`);
      const list = [...j.results, ...[...chosen.values()].filter((t) => !j.results.some((y) => y.id === t.id))];
      grouped(list, short, (id) => chosen.has(id), toggle);
    } catch (e) { short.replaceChildren(el("p", "dz-status bad", `Could not load: ${e.message}`)); }
    let timer = 0;
    q.addEventListener("input", () => {
      clearTimeout(timer);
      timer = setTimeout(async () => {
        const v = q.value.trim();
        if (v.length < 2) { found.replaceChildren(); return; }
        found.replaceChildren(el("div", "st-loading", "Searching…"));
        try {
          const j = await get(`/api/attack/search?q=${encodeURIComponent(v)}`);
          if (!j.results.length) found.replaceChildren(el("p", "dz-by", "No current technique matches (retired ones are hidden)."));
          else grouped(j.results, found, (id) => chosen.has(id), toggle);
        } catch (e) { found.replaceChildren(el("p", "dz-status bad", e.message)); }
      }, 250);
    });
    sync(); q.focus();
  }

  for (const b of document.querySelectorAll("[data-am]")) b.addEventListener("click", () => { tab = b.dataset.am; onlyNotice = false; $("amSearch").value = ""; shown = PAGE; render(); });
  $("amSearch").addEventListener("input", () => { shown = PAGE; if (data) render(); });
  load(true);
})();
