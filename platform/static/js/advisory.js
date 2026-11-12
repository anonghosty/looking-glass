/* Looking Glass · the advisory page (/advisory/<id>, advisory.py): one advisory per organisation (network).
   1. The advisor picks the organisation the advisory goes to (the networks in the finding's kept search).
   2. Its data shows: the IP addresses with their ports, reports, CVEs and issues; the impact of those reports.
   3. The template: subject, Description, Recommended Actions (with bold, bullets and numbering), recipients.
   4. Generate the report: kept and listed with its download; then mark it as sent and move on to the next one. */
(() => {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const el = (t, c, x) => { const e = document.createElement(t); if (c) e.className = c; if (x != null) e.textContent = x; return e; };
  const fmt = (n) => Number(n || 0).toLocaleString("en-US");
  const csrf = () => document.querySelector('meta[name="csrf-token"]')?.content || "";
  const fid = document.body.dataset.fid, main = $("avMain");
  const LEVEL = { critical: "Critical", high: "High", medium: "Medium", low: "Low" };
  let IDX = null, NET = null, D = null;
  // switching organisations quickly (external review, 2026-11-12): an organisation's data that arrives after another
  // was picked is dropped (SEQ), every button works on the organisation its form was drawn for, and the organisation
  // cannot be switched while a save, generation or marking is under way (BUSY)
  let SEQ = 0, BUSY = false;

  const card = (title, sub, cls) => {
    const s = el("section", `av-card ${cls || ""}`);
    s.append(el("h2", null, title));
    if (sub) s.append(el("p", "av-sub", sub));
    return s;
  };
  const chips = (vals, cls) => { const w = el("div", "av-chips"); vals.forEach((v) => w.append(el("span", `av-chip ${cls || ""}`, v))); return w; };
  const q = (n) => `network=${encodeURIComponent(n)}`;

  async function post(url, body) {
    const r = await fetch(url, { method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf() },
      body: JSON.stringify(body) });
    const d = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
    return d;
  }

  // ---------------- the light markup: **bold**, "- " bullets, "1. " numbers (kept as text, drawn the same in the PDF)
  function toolbar(ta, preview) {
    const bar = el("div", "av-tools");
    const wrapSel = (pre, post) => {
      const s = ta.selectionStart, e = ta.selectionEnd, v = ta.value;
      ta.value = v.slice(0, s) + pre + v.slice(s, e) + post + v.slice(e);
      ta.focus(); ta.setSelectionRange(s + pre.length, e + pre.length); ta.dispatchEvent(new Event("input"));
    };
    const lines = (fn) => {
      const v = ta.value, s = v.lastIndexOf("\n", ta.selectionStart - 1) + 1;
      let e = v.indexOf("\n", ta.selectionEnd); if (e < 0) e = v.length;
      const block = v.slice(s, e).split("\n").map(fn).join("\n");
      ta.value = v.slice(0, s) + block + v.slice(e); ta.focus(); ta.setSelectionRange(s, s + block.length); ta.dispatchEvent(new Event("input"));
    };
    const strip = (l) => l.replace(/^\s*([-*•]|\d{1,3}[.)])\s+/, "");
    [["B", "Bold (**text**)", () => wrapSel("**", "**"), "b"],
     ["• List", "Bulleted list", () => lines((l) => (l.trim() ? `- ${strip(l)}` : l))],
     ["1. List", "Numbered list", () => { let i = 0; lines((l) => (l.trim() ? `${++i}. ${strip(l)}` : l)); }],
     ["Plain", "Remove list marks and bold", () => lines((l) => strip(l).replace(/\*\*/g, ""))]].forEach(([t, title, fn, cls]) => {
      const b = el("button", `av-tool ${cls || ""}`, t); b.type = "button"; b.title = title; b.addEventListener("click", fn); bar.append(b);
    });
    const draw = () => {
      preview.replaceChildren();
      let list = null, kind = "";
      for (const raw of ta.value.split("\n")) {
        const mb = raw.match(/^\s*[-*•]\s+(.*)$/), mn = raw.match(/^\s*\d{1,3}[.)]\s+(.*)$/);
        const k = mb ? "ul" : mn ? "ol" : "";
        if (k !== kind) { list = k ? el(k) : null; if (list) preview.append(list); kind = k; }
        const body = mb ? mb[1] : mn ? mn[1] : raw;
        const host = k ? el("li") : el("p");
        body.split("**").forEach((seg, i) => host.append(i % 2 ? el("b", null, seg) : document.createTextNode(seg)));
        if (k) list.append(host); else if (raw.trim()) preview.append(host);
      }
      preview.hidden = !ta.value.trim();
    };
    ta.addEventListener("input", draw); draw();
    return bar;
  }

  // ---------------- step 1: the organisation
  function picker() {
    const c = card("1 · The organisation it goes to", "Pick the network (organisation) the advisory is for: its data and its advisory open below. Each organisation gets its own advisory and report.");
    const row = el("div", "av-netrow");
    const sel = el("select", "av-in av-netsel");
    sel.append(new Option("Choose the organisation (network)…", ""));
    for (const n of IDX.networks) {
      const st = n.status === "sent" ? " · sent" : n.status === "drafted" ? " · drafted" : n.ref ? " · draft" : "";
      sel.append(new Option(`${n.network || "All networks"} · ${fmt(n.devices)} IP address${n.devices === 1 ? "" : "es"}, ${fmt(n.records)} records${st}`, n.network));
    }
    sel.value = NET ?? "";
    sel.addEventListener("change", () => {
      if (BUSY) { sel.value = NET ?? ""; return; }
      if (sel.value || IDX.networks.some((n) => n.network === "")) openNet(sel.value);
    });
    const done = IDX.networks.filter((n) => n.status === "sent").length;
    row.append(sel, el("span", "muted", `${done} of ${IDX.networks.length} sent`));
    c.append(row);
    // every organisation at a glance, to move through them
    const list = el("div", "av-nets");
    for (const n of IDX.networks) {
      const b = el("button", `av-net ${n.status || "todo"}${n.network === NET ? " on" : ""}`); b.type = "button";
      b.append(el("b", null, n.network || "All networks"), el("small", null, `${fmt(n.devices)} IP · ${n.status === "sent" ? `sent ${n.sent}` : n.status === "drafted" ? `drafted ${n.ref}` : n.ref ? `draft ${n.ref}` : "not started"}`));
      b.addEventListener("click", () => openNet(n.network)); list.append(b);
    }
    c.append(list);
    return c;
  }

  function hero() {
    const h = el("section", "av-hero");
    const logo = el("div", "av-logo");
    if (IDX.has_logo) { const i = el("img"); i.src = `/organisation/logo?t=${Date.now()}`; i.alt = `${IDX.organisation} logo`; logo.append(i); }
    else logo.append(el("span", null, (IDX.organisation || "?").slice(0, 1).toUpperCase()));
    const ht = el("div", "av-head");
    ht.append(el("div", "fd-eyebrow", `Advisories · finding ${IDX.finding.number}`), el("h1", null, `${IDX.organisation} Security Advisory`));
    const meta = el("div", "av-meta"); meta.append(el("span", null, IDX.finding.title));
    ht.append(meta);
    if (!IDX.org_set) ht.append(el("p", "av-warn", "The CSIRT's name is not set yet: an admin sets it (and the logo) in Settings → Organisation."));
    h.append(logo, ht);
    return h;
  }

  function draw() {
    main.replaceChildren(hero(), picker());
    if (NET == null || !D) return;
    const a = D.advisory, edit = IDX.can_edit && !a.locked;     // sent: read-only, the record of what went out
    // step 2: the organisation's data, as the PDF carries it
    const dc = card(`2 · ${a.network || "All networks"}: its data`, `${fmt(a.affected.devices)} IP address${a.affected.devices === 1 ? "" : "es"} and ${fmt(a.affected.records)} records in ${a.data_title}. This is what the advisory and its report carry.`);
    const g = el("div", "av-aff");
    [["CVEs", a.affected.cves, "cve"], ["Issues", a.affected.issues, "iss"], ["Categories", a.affected.categories, "cat"],
     ["Seen as", a.affected.labels || [], "lbl"]].forEach(([k, v, cls]) => {
      if (!v.length) return;
      const row = el("div", "av-row"); row.append(el("b", null, k), chips(v, cls));
      if (cls === "lbl") row.title = "What the devices are (product and protocol tags in the reports): context, not issues";
      g.append(row);
    });
    if (a.reports.length) {
      const row = el("div", "av-row"); row.append(el("b", null, "Reports"));
      const list = el("div", "av-reps");
      a.reports.forEach((r) => {
        const it = el("div", "av-rep");
        it.append(el("span", "av-rep-t", r.title), el("small", null, [r.section, r.group].filter(Boolean).join(" · ")));
        const fl = el("div", "av-chips");
        r.flags.forEach((f) => { const z = a.impact.find((x) => x.flag === f); if (z) fl.append(el("span", `av-flag ${z.level}`, z.label)); });
        it.append(fl); list.append(it);
      });
      row.append(list); g.append(row);
    }
    dc.append(g);
    if ((a.devices || []).length) {
      const t = el("table", "hosts av-ips"), h = el("tr");
      ["IP address", "Host name", "Ports", "Reports", "CVEs", "Issues", "Seen as", "Records", "Last seen (UTC)"].forEach((x) => h.append(el("th", null, x)));
      const th = el("thead"); th.append(h); t.append(th);
      const tb = el("tbody");
      a.devices.forEach((d) => {
        const tr = el("tr");
        tr.append(el("td", "mono", d.ip), el("td", null, d.hostname || "–"), el("td", "mono", d.ports.join(", ") || "–"), el("td", null, d.reports.join(", ")),
                  el("td", "mono", d.cves.join(", ") || "–"), el("td", null, [...d.issues, ...(d.categories || [])].join(", ") || "–"),
                  el("td", "muted", (d.labels || []).join(", ") || "–"), el("td", "num", fmt(d.records)), el("td", "mono", d.last || ""));
        tb.append(tr);
      });
      t.append(tb);
      const w = el("div", "table-wrap av-ipwrap"); w.append(t); dc.append(w);
      if (D.devices_total > a.devices.length) dc.append(el("p", "av-sub", `The first ${fmt(a.devices.length)} of ${fmt(D.devices_total)} here; the report has all of them.`));
    }
    if (a.impact.length) {
      const im = el("div", "av-impact");
      im.append(el("b", null, "Impact (shown in the advisory on its own, from the reports)"));
      a.impact.forEach((f) => {
        const r = el("div", "av-imp");
        r.append(el("span", `av-flag ${f.level}`, LEVEL[f.level] || f.level), el("b", null, f.label), el("span", null, f.text), el("small", "muted", `Reports: ${f.reports.join(", ")}`));
        im.append(r);
      });
      dc.append(im);
    }
    main.append(dc);

    // step 3: the template
    const w = card("3 · The advisory", a.locked
      ? `As it was sent to ${a.network || "all networks"}. A sent advisory can no longer be changed, so the record of what the organisation received stays exact; a correction goes out as a new message.`
      : `Your words for ${a.network || "all networks"}: the subject, the Description on the impact, the Recommended Actions. Bold, bullets and numbering carry into the PDF.`);
    const head = el("input", "av-in av-heading"); head.type = "text"; head.maxLength = IDX.limits.subject; head.value = a.heading || "";
    head.placeholder = a.heading_default;          // empty: the CSIRT's name + "Security Advisory"
    const subj = el("input", "av-in"); subj.type = "text"; subj.maxLength = IDX.limits.subject; subj.value = a.subject;
    const mk = (val, ph) => { const ta = el("textarea", "av-ta"); ta.rows = 7; ta.maxLength = IDX.limits.text; ta.value = val; ta.placeholder = ph; return ta; };
    const desc = mk(a.description, "Describe the impact: what is exposed or happening on these IP addresses, and why it matters.");
    const act = mk(a.recommended_actions, "- Patch to a supported version\n- Close the management ports to the internet\n- Check the hosts for signs of compromise");
    const rec = el("input", "av-in"); rec.type = "text"; rec.value = a.recipients.join(", ");
    rec.placeholder = "To whom it goes: the organisation, its teams or people, separated by commas";
    // the TLP level (TLP 2.0): how far the recipients may pass it on; printed at the top and bottom of every page
    let tlpVal = a.tlp;
    const tlpBox = el("div", "av-tlp");
    const tlpNote = el("p", "av-sub");
    const tlpPick = el("div", "av-tlp-pick"); tlpPick.setAttribute("role", "radiogroup"); tlpPick.setAttribute("aria-label", "TLP level");
    for (const lv of IDX.tlp_levels || []) {
      const b = el("button", `av-tlp-opt${lv.key === tlpVal ? " on" : ""}`); b.type = "button"; b.setAttribute("role", "radio");
      b.setAttribute("aria-checked", String(lv.key === tlpVal)); b.disabled = !edit;
      b.append(el("span", `tlp-badge ${lv.cls}`, lv.key), el("b", null, lv.short), el("small", null, lv.text));
      b.title = `When: ${lv.when}`;
      b.addEventListener("click", () => {
        tlpVal = lv.key;
        for (const o of tlpPick.children) { const on = o === b; o.classList.toggle("on", on); o.setAttribute("aria-checked", String(on)); }
      });
      tlpPick.append(b);
    }
    const tlpLink = el("a", null, "TLP 2.0 by FIRST"); tlpLink.href = IDX.tlp_url || "https://www.first.org/tlp/"; tlpLink.target = "_blank"; tlpLink.rel = "noopener noreferrer";
    tlpNote.append(document.createTextNode("How far the recipients may pass it on: printed at the top and bottom of every page of the report and kept in its JSON. "
      + "This advisory lists the organisation's IP addresses, so TLP:AMBER (its organisation and clients) or stricter is usual. The colours follow "), tlpLink, document.createTextNode("."));
    tlpBox.append(el("span", "av-field-h", "Traffic Light Protocol (TLP)"), tlpNote, tlpPick);
    const lab = (t, x, hint, tools) => { const l = el("div", "av-field"); l.append(el("span", null, t)); if (tools) l.append(tools); l.append(x); if (hint) l.append(el("small", "muted", hint)); return l; };
    const pv1 = el("div", "av-preview"), pv2 = el("div", "av-preview");
    w.append(tlpBox, lab("Heading", head, `The advisory's title, large at the top of the first page. Left empty: "${a.heading_default}".`),
             lab("Subject", subj, "The line under the heading."),
             lab("Description", desc, a.kinds_line ? `Below it the advisory adds: "${a.kinds_line}"` : "", toolbar(desc, pv1)), pv1,
             lab("Recommended Actions", act, D.has_report ? 'After them: "See below for further insight into the activity." and the report on this organisation\'s devices.' : "", toolbar(act, pv2)), pv2,
             lab("Recipients", rec));
    [head, subj, desc, act, rec].forEach((x) => { x.disabled = !edit; });
    w.querySelectorAll(".av-tool").forEach((b) => { b.disabled = !edit; });
    const bar = el("div", "av-acts"), msg = el("span", "muted av-msg"); msg.setAttribute("role", "status");
    const say = (t, bad) => { msg.textContent = t; msg.style.color = bad ? "#ff8f8f" : ""; };
    // this form's organisation and data: fixed when it is drawn, whatever is picked afterwards
    const net = NET, seq = SEQ, here = D;
    const body = () => ({ network: net, tlp: tlpVal, heading: head.value, subject: subj.value, description: desc.value, actions: act.value, recipients: rec.value });
    const save = async () => { const d = await post(`/api/advisory/${fid}/net`, body()); here.advisory = d.advisory; here.saved = true; return d; };
    // one action at a time; the page is drawn again only if this organisation is still the one shown
    const run = async (button, work) => {
      if (BUSY) return;
      BUSY = true; button.disabled = true;
      try { const done = await work(); if (seq === SEQ) { await reloadIndex(); draw(); if (done) sayLater(done); } }
      catch (e) { if (seq === SEQ) { say(e.message, true); button.disabled = false; } }
      finally { BUSY = false; }
    };
    if (edit) {
      const sv = el("button", "lg-btn primary", "Save the advisory"); sv.type = "button";
      sv.addEventListener("click", () => { say("Saving…"); run(sv, async () => { await save(); return `Saved as ${here.advisory.ref}.`; }); });
      bar.append(sv);
    }
    const prev = el("a", "pill-btn", "Preview the PDF"); prev.href = `/advisory/${fid}/preview?${q(NET)}`; prev.target = "_blank"; prev.rel = "noopener";
    prev.title = "The PDF as it stands, in the browser (save first to include your latest text); not recorded";
    bar.append(prev);
    if (edit) {
      const gen = el("button", "lg-btn", "Generate the report"); gen.type = "button";
      gen.title = `Saves, then makes ${D.file_base}${D.has_report ? ".zip: the PDF and the devices CSV, what goes to the organisation" : ".pdf"} and keeps it with this advisory`;
      gen.addEventListener("click", () => {
        say("Saving and generating the report…");
        run(gen, async () => {
          window.LGLoader?.busy(`Generating the report for ${net || "all networks"}`);
          try { await save(); const d = await post(`/api/advisory/${fid}/generate`, { network: net }); here.advisory = d.advisory; return `Generated ${d.file.name}.`; }
          finally { window.LGLoader?.ready(); }
        });
      });
      bar.append(gen);
    }
    if (D.saved) {
      const js = el("a", "pill-btn", "Export JSON"); js.href = `/api/advisory/${fid}/export?${q(NET)}`; js.title = "The advisory as a JSON file (no address in it), for other tools";
      bar.append(js);
    }
    bar.append(msg);
    w.append(el("p", "av-sub av-fname", `Files: ${D.has_report ? `${D.file_base}.zip (to the organisation: ${D.file_base}.pdf + ${D.file_base}_devices.csv)` : `${D.file_base}.pdf`}`), bar);
    main.append(w);

    // step 4: the reports generated, and sending
    const r = card("4 · The report, drafted and sent", a.locked
      ? "The report that was sent, with its download. It is kept as it was sent and is never replaced."
      : "The latest report generated for this organisation, with its download: generating again replaces it (each generation is in the history below).");
    if (a.generated.length) {
      const ul = el("ul", "av-files");
      a.generated.slice().reverse().forEach((x) => {
        const li = el("li"), l = el("a", null, x.name); l.href = `/advisory/${fid}/file/${a.ref}/${x.n}`;
        li.append(l, el("small", "muted", ` · ${x.at} · ${x.by} · ${fmt(Math.round(x.size / 1024))} KB`)); ul.append(li);
      });
      r.append(ul);
    } else r.append(el("p", "fd-empty", "No report generated yet for this organisation."));
    const sb = el("div", "av-acts");
    // drafted here; marked as sent on the Findings page, where the finding (and its case) then closes
    const fl = el("a", null, "the Findings page"); fl.href = `/findings#f${fid}`;
    if (a.status === "sent") {
      const p = el("p", "av-state sent"); p.append(el("b", null, "Sent"), document.createTextNode(` to ${a.recipients.join(", ")} (${a.sends.at(-1)?.at || ""}). Its finding is closed once nothing else of it waits.`));
      sb.append(p);
    } else if (a.status === "drafted") {
      const p = el("p", "av-state drafted"); p.append(el("b", null, "Drafted"), document.createTextNode(": ready to go out. Once it has, mark it as sent on "), fl,
        document.createTextNode(" (changing it here makes it a draft again)."));
      sb.append(p);
    } else if (edit && D.saved) {
      const dr = el("button", "lg-btn av-send", "Mark as drafted"); dr.type = "button";
      dr.disabled = !a.generated.length;
      dr.title = a.generated.length ? "The advisory is finished: its text and its report. It is then marked as sent on the Findings page." : "Generate the report first: it is what goes out";
      dr.addEventListener("click", () => run(dr, async () => {
        await save(); const d = await post(`/api/advisory/${fid}/drafted`, { network: net }); here.advisory = d.advisory;
        return "Marked as drafted: mark it as sent on the Findings page once it has gone out.";
      }));
      sb.append(dr);
    }
    const next = IDX.networks.find((n) => n.network !== NET && n.status !== "sent");
    if (next) { const nb = el("button", "pill-btn", `Next organisation: ${next.network || "All networks"}`); nb.type = "button"; nb.addEventListener("click", () => openNet(next.network)); sb.append(nb); }
    r.append(sb);
    if (a.sends.length || a.history.length) {
      const ul = el("ul", "av-trail");
      a.sends.forEach((s) => ul.append(el("li", null, `${s.at}: sent to ${s.to.join(", ")} by ${s.by}${s.report ? ` (${s.report})` : ""}`)));
      a.history.forEach((h) => ul.append(el("li", "muted", `${h.at}: ${h.what} by ${h.by}`)));
      r.append(ul);
    }
    main.append(r);
    const back = el("a", "pill-btn av-back", "Back to the advisory portal"); back.href = "/advisory"; main.append(back);
  }
  let pending = "";
  const sayLater = (t) => { const m = main.querySelector(".av-msg"); if (m) m.textContent = t; else pending = t; };

  async function reloadIndex() {
    const r = await fetch(`/api/advisory/${encodeURIComponent(fid)}`, { cache: "no-store" });
    const d = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
    IDX = d;
  }
  async function openNet(n) {
    if (BUSY) return;                            // a save or generation is under way: it finishes first
    const my = ++SEQ;
    NET = n; D = null;
    try { history.replaceState(null, "", `#${encodeURIComponent(n)}`); } catch { /* */ }
    // the organisation's data takes a moment (its records, read again): the searching logo meanwhile
    if (IDX && main.children.length > 2) [...main.children].slice(2).forEach((x) => x.remove());     // keep the head and the picker
    const wait = el("div", "st-loading", `Opening ${n || "all networks"}: its IP addresses, reports and impact…`); main.append(wait);
    let r, d;
    try {
      r = await fetch(`/api/advisory/${encodeURIComponent(fid)}/net?${q(n)}`, { cache: "no-store" });
      d = await r.json().catch(() => ({}));
    } finally { wait.remove(); }
    if (my !== SEQ) return;                      // another organisation was picked meanwhile: this one is not shown
    if (!r.ok) { D = null; draw(); main.append(el("p", "fd-empty", d.error || `Could not open it (HTTP ${r.status})`)); return; }
    D = d; draw(); if (pending) { sayLater(pending); pending = ""; }
    main.querySelectorAll(".av-card")[1]?.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  (async () => {
    try { await reloadIndex(); } catch (e) { $("avLoading")?.remove(); main.append(el("p", "fd-empty", e.message)); return; }
    $("avLoading")?.remove();
    window.LGLoader?.ready();
    const want = decodeURIComponent(location.hash.slice(1) || "");
    if (IDX.networks.length === 1) return openNet(IDX.networks[0].network);
    if (want && IDX.networks.some((n) => n.network === want)) return openNet(want);
    draw();
  })();
})();
