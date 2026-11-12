/* Looking Glass · network names and types (AS-number registry): admins in Settings, researchers on the Definitions page.
   Same design as the definitions cards: stat tabs, search, type filter, pills, buttons that show what they do. */
(() => {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const el = (t, c, x) => { const e = document.createElement(t); if (c) e.className = c; if (x != null) e.textContent = x; return e; };
  const fmt = (n) => Number(n || 0).toLocaleString("en-US");
  const csrf = () => document.querySelector('meta[name="csrf-token"]')?.content || "";
  const hdr = (json) => (json ? { "Content-Type": "application/json", "X-CSRF-Token": csrf() } : {});
  const TYPES = {};
  let rows = [], typeList = [], view = "todo", identifying = false, lastKey = "";
  if (!$("cardNets")) return;
  // Settings shows the networks read-only; they are edited on the Definitions page
  const RO = $("cardNets").dataset.readonly === "1";
  if (RO) view = "all";                             // for reference: every network, not the review queue
  const pill = (text, kind) => el("span", `dz-pill ${kind || ""}`, text);
  const flash = (node, text, kind) => { node.className = `dz-status ${kind || ""}`; node.textContent = text; };
  function busy(btn, on, label) {
    const span = btn.querySelector("span") || btn;
    if (on) { btn.dataset.label = span.textContent; span.textContent = label; btn.classList.add("is-busy"); btn.disabled = true; }
    else { span.textContent = btn.dataset.label || span.textContent; btn.classList.remove("is-busy"); btn.disabled = false; }
  }
  function setTypes(list) {
    if (!list?.length) return;
    typeList = list; for (const t of list) TYPES[t.key] = t.label;
    const f = $("netTypeFilter"), cur = f.value;
    f.replaceChildren(el("option", null, "All types")); f.firstChild.value = "";
    for (const t of list) { const o = el("option", null, t.label); o.value = t.key; f.append(o); }
    f.value = cur;
    const own = list.filter((t) => !t.builtin).length;
    $("netN4").textContent = fmt(list.length); $("netN4sub").textContent = own ? `${list.length - own} built-in · ${own} your own` : "built-in sectors";
  }
  function counts() {
    $("netN1").textContent = fmt(rows.filter((x) => !x.reviewed).length);
    $("netN3").textContent = fmt(rows.filter((x) => x.reviewed).length);
    $("netN2").textContent = fmt(rows.length);
  }

  async function load() {
    const r = await fetch("/api/networks", { cache: "no-store", headers: hdr(false) });
    if (!r.ok) { $("cardNets").hidden = true; return; }
    const j = await r.json();
    rows = j.networks; identifying = j.identifying; setTypes(j.types);
    $("cardNets").hidden = false; counts();
    // nothing left to review: open on every network, each still editable (a company renames, rebrands, merges…)
    if (view === "todo" && !rows.some((x) => !x.reviewed)) view = "all";
    flash($("netStatus"), identifying ? "Networks are being identified right now (Settings → Identify networks): changes can be saved when it has finished."
      : `${fmt(rows.length)} networks · ${fmt(rows.filter((x) => !x.reviewed).length)} to review`, identifying ? "warn" : "");
    render();
  }

  function renderTypes(tb) {
    const thead = $("netEdTable").querySelector("thead tr");
    thead.replaceChildren(...["Type (sector)", "Key", "Word in Demo mode", "Networks", "Origin"].map((h) => el("th", null, h)));
    const q = $("netEdSearch").value.trim().toLowerCase();
    for (const t of typeList.filter((t) => !q || `${t.label} ${t.key} ${t.alias}`.toLowerCase().includes(q))) {
      const tr = el("tr"), n = rows.filter((x) => x.type === t.key).length;
      const origin = el("td"); origin.append(t.builtin ? pill("Built-in", "info") : pill(`Added${t.by ? ` by ${t.by}` : ""}${t.added ? `, ${t.added}` : ""}`, "ok"));
      tr.append(el("td", "dz-name", t.label), el("td", "mono muted", t.key), el("td", null, t.alias), el("td", "num mono", fmt(n)), origin);
      tb.append(tr);
    }
  }
  function render() {
    for (const b of document.querySelectorAll("[data-net]")) b.setAttribute("aria-selected", String(b.dataset.net === view));
    const tb = $("netEdTable").querySelector("tbody"); tb.replaceChildren();
    $("netTypeFilter").hidden = view === "types";
    if (view === "types") { renderTypes(tb); return; }
    const C = RO ? window.LGConstituency : null;      // Settings: this list also picks the constituency (settings.js)
    $("netEdTable").querySelector("thead tr").replaceChildren(...[["AS number"], ["Company name"], ["Type"], ["Note"], ["Registry holder"], ["Events", "num"], ["Status"],
      [C ? "Constituent" : "", "dz-act"]].map(([h, c]) => el("th", c || null, h)));
    lastKey = C ? C.key() : "";
    const q = $("netEdSearch").value.trim().toLowerCase().replace(/^as/, ""), tf = $("netTypeFilter").value;
    // a search looks through every network, whatever the tab: a reviewed one is found and edited the same way
    const shown = rows.filter((x) => (q || view === "all" || (view === "todo" ? !x.reviewed : x.reviewed)) && (!tf || x.type === tf)
      && (!q || x.asn.includes(q) || x.name.toLowerCase().includes(q) || (x.holder || "").toLowerCase().includes(q) || (TYPES[x.type] || x.type).toLowerCase().includes(q)));
    if (!shown.length) {
      const tr = el("tr", "dz-empty"), td = el("td", null, q || tf ? "No network matches." : view === "todo" ? "Nothing to review: every network has been checked. " : "No networks yet.");
      if (!q && !tf && view === "todo" && rows.length) {
        td.append(el("span", "muted", "Every network stays editable (a company renames or rebrands): "));
        const b = el("button", "lg-btn sm", "Show every network"); b.type = "button"; b.addEventListener("click", () => { view = "all"; render(); }); td.append(b);
      }
      td.colSpan = 8; tr.append(td); tb.append(tr); return;
    }
    for (const x of shown.slice(0, 300)) {
      const tr = el("tr");
      if (RO) {                                     // read-only: the values, no inputs or Save
        const st = el("td"); st.append(x.reviewed ? pill("Reviewed", "ok") : pill("Not reviewed", "warn"));
        if (x.reviewed && (x.by || x.updated)) st.append(el("small", "dz-by", `${x.by || ""}${x.updated ? ` · ${x.updated}` : ""}`));
        const pick = el("td", "dz-act");
        if (C) {                                    // tick = part of the constituency (applied for everyone with Apply settings)
          const cb = el("input"); cb.type = "checkbox"; cb.checked = C.has(x.asn);
          cb.setAttribute("aria-label", `AS${x.asn} ${x.name} is a constituent`);
          cb.title = "Part of your constituency: both platforms then show only your constituents' networks (Apply settings, at the bottom)";
          cb.addEventListener("change", () => C.set(x.asn, cb.checked));
          tr.classList.toggle("dz-constituent", cb.checked);
          pick.append(cb);
        }
        tr.append(el("td", "mono dz-name", `AS${x.asn}`), el("td", "dz-w-name", x.name), el("td", null, TYPES[x.type] || x.type), el("td", "muted", x.note || "—"),
          el("td", "dz-seen", `${x.holder || "—"}${x.country ? ` (${x.country})` : ""}`), el("td", "num mono", fmt(x.events)), st, pick);
        tb.append(tr); continue;
      }
      const name = el("input", "dz-input"); name.value = x.name; name.maxLength = 80; name.setAttribute("aria-label", `Company name for AS${x.asn}`);
      const type = el("select", "dz-input lg-enhance"); type.setAttribute("aria-label", `Type of AS${x.asn}`);
      for (const t of typeList) { const o = el("option", null, t.label); o.value = t.key; type.append(o); }
      type.value = TYPES[x.type] ? x.type : "unknown";
      const note = el("input", "dz-input"); note.value = x.note || ""; note.maxLength = 200; note.placeholder = "optional note"; note.setAttribute("aria-label", `Note for AS${x.asn}`);
      const save = el("button", "lg-btn sm", ""); save.type = "button"; save.append(el("span", null, "Save")); save.disabled = true; save.title = "Change the name, type or note to save";
      const status = el("td");
      const showStatus = () => status.replaceChildren(x.reviewed ? pill("Reviewed", "ok") : pill("Not reviewed", "warn"),
        x.reviewed && (x.by || x.updated) ? el("small", "dz-by", `${x.by || ""}${x.updated ? ` · ${x.updated}` : ""}`) : "");
      showStatus();
      const dirty = () => {
        const changed = !(name.value.trim() === x.name && type.value === x.type && note.value.trim() === (x.note || ""));
        save.disabled = !changed; save.classList.toggle("primary", changed); tr.classList.toggle("dz-dirty", changed);
        save.title = changed ? "Save this network (it is then marked reviewed)" : "Change the name, type or note to save";
      };
      for (const i of [name, type, note]) { i.addEventListener("input", dirty); i.addEventListener("change", dirty); }
      name.addEventListener("keydown", (e) => { if (e.key === "Enter" && !save.disabled) save.click(); });
      note.addEventListener("keydown", (e) => { if (e.key === "Enter" && !save.disabled) save.click(); });
      save.addEventListener("click", async () => {
        busy(save, true, "Saving…");
        try {
          const r = await fetch("/api/networks/entry", { method: "POST", headers: hdr(true), body: JSON.stringify({ asn: x.asn, name: name.value.trim(), type: type.value, note: note.value.trim() }) });
          const j = await r.json().catch(() => ({}));
          if (!r.ok) throw new Error(j.error || `Refused (${r.status})`);
          Object.assign(x, { name: name.value.trim(), type: type.value, note: note.value.trim(), reviewed: true, by: "you", updated: new Date().toISOString().slice(0, 10) });
          busy(save, false); dirty(); showStatus(); status.prepend(pill("Saved ✓", "ok")); counts();
          tr.classList.add("dz-saved"); setTimeout(() => tr.classList.remove("dz-saved"), 1500);
        } catch (e) { busy(save, false); save.disabled = false; status.replaceChildren(pill(e.message, "bad")); }
      });
      const td = (node, cls) => { const c = el("td", cls || null); c.append(node); return c; };
      tr.append(el("td", "mono dz-name", `AS${x.asn}`), td(name, "dz-w-name"), td(type, "dz-w-type"), td(note, "dz-w-note"),
        el("td", "dz-seen", `${x.holder || "—"}${x.country ? ` (${x.country})` : ""}`), el("td", "num mono", fmt(x.events)), status, td(save, "dz-act"));
      tb.append(tr);
    }
    if (shown.length > 300) { const tr = el("tr", "dz-empty"), td = el("td", null, `Showing 300 of ${fmt(shown.length)}: search or choose a type to narrow the list.`); td.colSpan = 8; tr.append(td); tb.append(tr); }
  }
  for (const b of document.querySelectorAll("[data-net]")) b.addEventListener("click", () => { view = b.dataset.net; render(); });
  $("netEdSearch").addEventListener("input", render);
  $("netTypeFilter").addEventListener("change", render);

  // a sector the list does not cover: add it (then it can be chosen for any network, here and in Settings)
  if (!RO) $("netTypeOpen").addEventListener("click", () => {
    const p = $("netTypePanel"), open = p.hidden;
    p.hidden = !open; $("netTypeOpen").setAttribute("aria-expanded", String(open)); $("netTypeOpen").classList.toggle("active", open);
    if (open) $("netTypeLabel").focus();
  });
  $("netTypeAdd").addEventListener("click", async () => {
    const btn = $("netTypeAdd"), msg = $("netTypeMsg"), label = $("netTypeLabel").value.trim();
    if (!label) { flash(msg, "Give the type a name first.", "warn"); $("netTypeLabel").focus(); return; }
    busy(btn, true, "Adding…");
    try {
      const r = await fetch("/api/networks/types", { method: "POST", headers: hdr(true), body: JSON.stringify({ label, alias: $("netTypeAlias").value.trim() }) });
      const j = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(j.error || `Refused (${r.status})`);
      setTypes(j.types); render();
      flash(msg, `Added “${label}” ✓ It can now be chosen for any network.`, "ok");
      $("netTypeLabel").value = ""; $("netTypeAlias").value = "";
    } catch (e) { flash(msg, e.message, "bad"); }
    finally { busy(btn, false); }
  });
  $("netTypeLabel").addEventListener("keydown", (e) => { if (e.key === "Enter") $("netTypeAdd").click(); });
  $("netTypeAlias").addEventListener("keydown", (e) => { if (e.key === "Enter") $("netTypeAdd").click(); });
  load().catch((e) => { console.error("Network names could not be loaded:", e); flash($("netStatus"), `Could not load: ${e.message}`, "bad"); });
  // Settings: redraw the ticks when the constituency changes in the Constituency card (or here), only when it did
  if (RO && window.LGConstituency) window.LGConstituency.onChange(() => {
    if (rows.length && view !== "types" && window.LGConstituency.key() !== lastKey) render();
  });
})();
