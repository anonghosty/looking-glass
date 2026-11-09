/* Looking Glass · the researchers' work (Settings and the Definitions page):
   1. Infections & categories (network communications): Malpedia look-ups; definitions for the names Malpedia does not know.
   2. Issues (publicly accessible / vulnerable services): CVEs looked up (CISA KEV, EPSS, CVE.org, NVD); definitions for the rest.
   Both look-ups run on the server in batches and show the progress window (LGLookup in pdf.js). */
(() => {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const el = (t, c, x) => { const e = document.createElement(t); if (c) e.className = c; if (x != null) e.textContent = x; return e; };
  const fmt = (n) => Number(n || 0).toLocaleString("en-US");
  const csrf = () => document.querySelector('meta[name="csrf-token"]')?.content || "";
  const token = () => { try { return sessionStorage.getItem("lg.settingsToken") || ""; } catch { return ""; } };
  const hdr = (json) => ({ ...(json ? { "Content-Type": "application/json", "X-CSRF-Token": csrf() } : {}), ...(token() ? { "X-Settings-Token": token() } : {}) });
  const isCve = (n) => /^CVE-\d{4}-\d{4,7}$/i.test(n || "");
  let data = null, infTab = "unresolved", issTab = "needs";
  if (!$("cardInf")) return;

  // ---------------- buttons that show what they are doing
  function busy(btn, on, label) {
    const span = btn.querySelector("span") || btn;
    if (on) { btn.dataset.label = span.textContent; span.textContent = label; btn.classList.add("is-busy"); btn.disabled = true; }
    else { span.textContent = btn.dataset.label || span.textContent; btn.classList.remove("is-busy"); btn.disabled = false; }
  }
  function flash(node, text, kind) { node.className = `dz-status ${kind || ""}`; node.textContent = text; }
  const pill = (text, kind) => el("span", `dz-pill ${kind || ""}`, text);

  async function load() {
    const r = await fetch("/api/kb/unresolved", { cache: "no-store", headers: hdr(false) });
    if (!r.ok) { $("cardInf").hidden = true; $("cardIss").hidden = true; return; }
    data = await r.json();
    $("cardInf").hidden = false; $("cardIss").hidden = false;
    $("infN1").textContent = fmt(data.unresolved.length); $("infN2").textContent = fmt(data.unchecked.length);
    $("infN3").textContent = fmt(data.defined.length); $("infN4").textContent = fmt((data.all || []).length);
    const iss = data.issues || [];
    $("issN1").textContent = fmt(iss.filter((x) => !x.cve && !x.defined).length); $("issN2").textContent = fmt(iss.filter((x) => x.exploited).length);
    $("issN3").textContent = fmt(iss.filter((x) => x.cve).length); $("issN4").textContent = fmt(iss.filter((x) => x.defined).length);
    const c = data.check || {};
    flash($("infStatus"), !data.malpedia ? "Malpedia is not set up (MALPEDIA_TOKEN in .env): the look-up uses your definitions; you can still write them."
      : c.running ? `Background check running: ${c.done} done, ${c.left} to go…`
      : data.unchecked.length ? `${data.unchecked.length} new name${data.unchecked.length === 1 ? "" : "s"} from the reports not checked yet.` : "Every name in the loaded reports has been checked.",
      data.unchecked.length ? "warn" : "ok");
    renderInf(); renderIss();
  }

  // ---------------- 1. infections & categories
  function infRows() {
    const q = $("infSearch").value.trim().toLowerCase();
    const rows = infTab === "all" ? data.all || [] : data[infTab] || [];
    return rows.filter((x) => !q || [x.name, x.title, x.family_found, (x.reports || []).join(" "), x.description].join(" ").toLowerCase().includes(q));
  }
  function renderInf() {
    for (const b of document.querySelectorAll("[data-inf]")) b.setAttribute("aria-selected", String(b.dataset.inf === infTab));
    const tb = $("infTable").querySelector("tbody"); tb.replaceChildren();
    const rows = infRows();
    if (!rows.length) {
      const msg = $("infSearch").value.trim() ? "Nothing matches the search." : infTab === "unresolved" ? "Nothing to do: every name Malpedia does not know has a definition."
        : infTab === "unchecked" ? "No new names waiting: they are checked with Malpedia every 30 minutes, or now with Look up with Malpedia." : "Nothing here yet.";
      const tr = el("tr", "dz-empty"), td = el("td", null, msg); td.colSpan = 5; tr.append(td); tb.append(tr); return;
    }
    for (const x of rows.slice(0, 400)) {
      const tr = el("tr");
      const status = el("td");
      if (x.defined) status.append(pill(x.malpedia ? "Malpedia (set by you)" : "Defined", "ok"));
      else if (x.family_found) status.append(pill(x.family_found.startsWith("actor:") ? "Threat actor" : "Malpedia", "info"));
      else if (infTab === "unchecked" || x.unchecked) status.append(pill("Not checked yet", ""));
      else status.append(pill("Needs a definition", "warn"));
      const def = el("td", "dz-def");
      if (x.defined) def.append(el("b", null, x.malpedia ? x.malpedia : x.title || "Defined"), el("small", null, `${x.references.length} reference${x.references.length === 1 ? "" : "s"}${x.by ? ` · ${x.by}` : ""}${x.updated ? `, ${x.updated}` : ""}`));
      else if (x.family_found) def.append(el("b", "mono", x.family_found.replace("actor:", "")), el("small", null, "found in Malpedia"));
      else def.append(el("span", "muted", x.title ? `${x.title} (no references yet)` : x.kinds?.length ? `Seen as: ${x.kinds.join(", ")}` : "—"));
      const act = el("td", "dz-act"), b = el("button", `lg-btn sm${x.defined || x.family_found ? "" : " primary"}`, x.defined ? "Edit" : "Define"); b.type = "button";
      b.addEventListener("click", () => openEditor(x.name, "infections"));
      act.append(b);
      tr.append(el("td", "mono dz-name", x.name), el("td", "dz-seen", (x.reports || []).join(", ") || "—"), status, def, act);
      tb.append(tr);
    }
  }
  for (const b of document.querySelectorAll("[data-inf]")) b.addEventListener("click", () => { infTab = b.dataset.inf; renderInf(); });
  $("infSearch").addEventListener("input", renderInf);

  $("infLookup").addEventListener("click", async () => {
    const btn = $("infLookup");
    // the names that need it; when every name is known, all names again (Malpedia answers come from the week-long cache)
    let names = [...data.unchecked, ...data.unresolved].map((x) => x.name);
    const recheck = !names.length;
    if (recheck) names = (data.all || []).map((x) => x.name);
    if (!names.length) { flash($("infStatus"), "No infection names in the loaded reports.", "warn"); return; }
    busy(btn, true, "Looking up…");
    try {
      await window.LGLookup.run({ kind: "malpedia", values: names, title: "Looking up infections and categories",
        intro: `${names.length} name${names.length === 1 ? "" : "s"}${recheck ? " (every name in the reports, to refresh them)" : " not known yet"}. ` +
          (data.malpedia ? "Malpedia's answers are kept a week, so known names come back at once; new names are asked at most 30 a minute." :
            "Malpedia is not set up: the Looking Glass definitions answer.") });
      flash($("infStatus"), "Look-up finished: the lists below are up to date.", "ok");
      await load();
    } catch (e) { flash($("infStatus"), `Look-up failed: ${e.message}`, "bad"); }
    finally { busy(btn, false); }
  });

  // ---------------- 2. issues (services)
  function issRows() {
    const q = $("issSearch").value.trim().toLowerCase();
    const all = data.issues || [];
    const rows = issTab === "needs" ? all.filter((x) => !x.cve && !x.defined) : issTab === "kev" ? all.filter((x) => x.exploited)
      : issTab === "cves" ? all.filter((x) => x.cve) : all.filter((x) => x.defined);
    return rows.filter((x) => !q || [x.name, x.title, x.by].join(" ").toLowerCase().includes(q))
      .sort((a, b) => Number(!!b.exploited) - Number(!!a.exploited) || (b.cvss || 0) - (a.cvss || 0) || b.hosts - a.hosts);
  }
  function renderIss() {
    for (const b of document.querySelectorAll("[data-iss]")) b.setAttribute("aria-selected", String(b.dataset.iss === issTab));
    const tb = $("issTable").querySelector("tbody"); tb.replaceChildren();
    const rows = issRows();
    if (!rows.length) {
      const msg = $("issSearch").value.trim() ? "Nothing matches the search." : issTab === "needs" ? "Nothing to do: every issue that is not a CVE has a definition."
        : issTab === "kev" ? "None of the CVEs in the data is in CISA's catalog of exploited vulnerabilities." : "Nothing here yet.";
      const tr = el("tr", "dz-empty"), td = el("td", null, msg); td.colSpan = 5; tr.append(td); tb.append(tr); return;
    }
    for (const x of rows) {
      const tr = el("tr");
      const status = el("td", "dz-pills");
      if (x.cve) {
        if (x.exploited) status.append(pill("Actively exploited", "bad"));
        if (x.cvss != null) status.append(pill(`CVSS ${x.cvss}${x.severity ? ` ${x.severity.toLowerCase()}` : ""}`, x.cvss >= 9 ? "bad" : x.cvss >= 7 ? "warn" : "info"));
        if (x.epss != null) status.append(pill(`EPSS ${(x.epss * 100).toFixed(1)}%`, x.epss >= 0.1 ? "warn" : ""));
        if (x.pending) status.append(pill("Not looked up yet", ""));
        else if (!x.found) status.append(pill("No public record", ""));
        if (x.defined) status.append(pill("Note", "ok"));
      } else status.append(pill(x.defined ? "Defined" : "Needs a definition", x.defined ? "ok" : "warn"));
      const what = el("td", "dz-def");
      what.append(el("b", null, x.title || (x.cve ? "CVE" : "—")));
      if (x.by) what.append(el("small", null, `${x.cve ? "Note" : "Definition"} by ${x.by}${x.updated ? `, ${x.updated}` : ""}`));
      const act = el("td", "dz-act"), b = el("button", `lg-btn sm${!x.cve && !x.defined ? " primary" : ""}`, x.cve ? (x.defined ? "Edit note" : "Add note") : x.defined ? "Edit" : "Define"); b.type = "button";
      b.addEventListener("click", () => openEditor(x.name, "issues"));
      act.append(b);
      tr.append(el("td", "mono dz-name", x.name), el("td", "dz-seen", `${fmt(x.hosts)} hosts · ${fmt(x.records)} records`), status, what, act);
      tb.append(tr);
    }
  }
  for (const b of document.querySelectorAll("[data-iss]")) b.addEventListener("click", () => { issTab = b.dataset.iss; renderIss(); });
  $("issSearch").addEventListener("input", renderIss);

  $("issLookup").addEventListener("click", async () => {
    const btn = $("issLookup");
    const names = (data.issues || []).map((x) => x.name);
    if (!names.length) { flash($("issStatus"), "No issues in the services data loaded.", "warn"); return; }
    const n = names.filter(isCve).length;
    busy(btn, true, "Looking up…");
    try {
      await window.LGLookup.run({ kind: "issues", values: names, title: "Looking up the issues",
        intro: `${names.length} issues: ${n} CVEs, looked up in batches (CISA's exploited-vulnerabilities catalog once a day, EPSS 100 at a time, the ` +
          `official CVE.org records four at a time; NVD's own analysis follows in the background at NVD's pace), and ${names.length - n} other issues, explained from their definitions.` });
      flash($("issStatus"), "Look-up finished: the lists below are up to date.", "ok");
      await load();
    } catch (e) { flash($("issStatus"), `Look-up failed: ${e.message}`, "bad"); }
    finally { busy(btn, false); }
  });

  // ---------------- the editor (one form for both)
  function refRow(v) {
    const d = el("div", "kb-ref"), i = el("input"); i.type = "url"; i.placeholder = "https://…"; i.value = v || ""; i.maxLength = 500;
    const x = el("button", "lg-btn sm ghost", "Remove"); x.type = "button"; x.addEventListener("click", () => d.remove());
    d.append(i, x); $("kbRefs").append(d);
  }
  function show(on) { $("kbModal").hidden = !on; $("kbBack").hidden = !on; if (on) ($("kbName").value ? $("kbTitleIn") : $("kbName")).focus(); }
  let section = "infections";
  async function openEditor(name, sec) {
    section = sec || "infections";
    const isIssue = section === "issues", cve = isIssue && isCve(name);
    $("kbMpBox").hidden = isIssue; $("kbCveHint").hidden = !cve;
    $("kbDescLbl").textContent = cve ? "Note for your organisation (optional)" : "Description: what it is";
    $("kbName").placeholder = isIssue ? "Exposed admin panel" : "android.midnight-mimosa";
    $("kbForm").reset(); $("kbRefs").replaceChildren(); $("kbMsg").textContent = ""; $("kbMsg").className = "id-msg"; $("kbMpHits").replaceChildren(); $("kbBy").textContent = ""; $("kbSeen").textContent = "";
    $("kbName").readOnly = !!name;
    let e = { references: [] };
    if (name) {
      const r = await fetch(`/api/kb/entry?name=${encodeURIComponent(name)}&section=${section}`, { cache: "no-store", headers: hdr(false) });
      if (r.ok) e = await r.json();
      const row = !isIssue && [...data.unresolved, ...data.unchecked, ...data.defined, ...(data.all || [])].find((x) => x.name === name);
      if (row && row.reports?.length) $("kbSeen").textContent = `Seen in: ${row.reports.join(", ")}${row.kinds?.length ? ` (${row.kinds.join(", ")})` : ""}.`;
      const iss = isIssue && (data.issues || []).find((x) => x.name === name);
      if (iss) $("kbSeen").textContent = `Seen on ${fmt(iss.hosts)} hosts (${fmt(iss.records)} records) of the publicly accessible / vulnerable services.`
        + (iss.cve && iss.exploited ? " CISA confirms it is being actively exploited." : "");
    }
    $("kbTitle").textContent = name ? (cve ? `Note on ${name}` : `Define “${name}”`) : (isIssue ? "Define an issue" : "Define a name");
    $("kbName").value = name || ""; $("kbMp").value = e.malpedia || ""; $("kbTitleIn").value = e.title || "";
    $("kbType").value = e.type || ""; $("kbDesc").value = e.description || "";
    for (const u of (e.references.length ? e.references : [""])) refRow(u);
    if (e.by || e.updated) $("kbBy").textContent = `Last changed${e.by ? ` by ${e.by}` : ""}${e.updated ? ` on ${e.updated}` : ""}`;
    show(true);
  }
  $("infAdd").addEventListener("click", () => openEditor("", "infections"));
  $("issAdd").addEventListener("click", () => openEditor("", "issues"));
  async function mpFind() {
    const q = $("kbMpQ").value.trim() || $("kbTitleIn").value.trim() || $("kbName").value.trim().split(".").pop();
    const box = $("kbMpHits"), btn = $("kbMpFind"); box.replaceChildren(el("span", "muted", `Searching Malpedia for “${q}”…`));
    busy(btn, true, "Searching…");
    try {
      const r = await fetch(`/api/kb/malpedia-search?q=${encodeURIComponent(q)}`, { cache: "no-store", headers: hdr(false) });
      const j = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(j.error || `Refused (${r.status})`);
      box.replaceChildren();
      if (!j.results.length) { box.append(el("span", "muted", `Malpedia has nothing for “${q}”. Leave the field empty: your definition and references are used instead.`)); return; }
      for (const h of j.results) {
        const b = el("button", "lg-btn sm", h.id); b.type = "button";
        b.title = `${h.matched_by}${h.alt_names.length ? ` · also: ${h.alt_names.join(", ")}` : ""}`;
        b.addEventListener("click", () => { $("kbMp").value = h.id; box.replaceChildren(el("span", "dz-pill ok", `Selected ${h.id}`)); });
        box.append(b);
      }
    } catch (e) { box.replaceChildren(el("span", "muted", e.message)); }
    finally { busy(btn, false); }
  }
  $("kbMpFind").addEventListener("click", mpFind);
  $("kbMpQ").addEventListener("keydown", (e) => { if (e.key === "Enter") { e.preventDefault(); mpFind(); } });
  $("kbRefAdd").addEventListener("click", () => refRow(""));
  $("kbClose").addEventListener("click", () => show(false));
  $("kbBack").addEventListener("click", () => show(false));
  document.addEventListener("keydown", (e) => { if (e.key === "Escape" && !$("kbModal").hidden) show(false); });
  $("kbForm").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const body = { section, name: $("kbName").value.trim(), malpedia: section === "issues" ? "" : $("kbMp").value.trim(), title: $("kbTitleIn").value.trim(), type: $("kbType").value.trim(),
      description: $("kbDesc").value.trim(), references: [...$("kbRefs").querySelectorAll("input")].map((i) => i.value.trim()).filter(Boolean) };
    const btn = $("kbSave"); btn.disabled = true; btn.classList.add("is-busy"); $("kbMsg").className = "id-msg"; $("kbMsg").textContent = "Saving…";
    try {
      const r = await fetch("/api/kb/entry", { method: "POST", headers: hdr(true), body: JSON.stringify(body) });
      const j = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(j.error || `Refused (${r.status})`);
      $("kbMsg").className = "id-msg good"; $("kbMsg").textContent = "Saved ✓ Every user now sees this definition.";
      if (section === "issues") issTab = isCve(body.name) ? "cves" : "defined"; else infTab = "defined";
      await load(); setTimeout(() => show(false), 900);
    } catch (e) { $("kbMsg").className = "id-msg bad"; $("kbMsg").textContent = e.message; }
    finally { btn.disabled = false; btn.classList.remove("is-busy"); }
  });
  load().catch((e) => {
    console.error("Definitions could not be loaded:", e);
    for (const id of ["infStatus", "issStatus"]) flash($(id), `Could not load: ${e.message}`, "bad");
  });
})();
