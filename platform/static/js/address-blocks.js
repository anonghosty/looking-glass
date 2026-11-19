/* Looking Glass · Settings → Constituency: pick address blocks from the reports (address_blocks.py; the user,
   2026-11-19: "i still cant select ip ranges"). The blocks (/24) seen yesterday on both platforms, with their records
   and network, ticked into the "Extra address ranges" box; typing a range there stays possible. Nothing is looked up
   outside: only what the reports hold. Saved with Apply settings, like the rest of the constituency. */
(() => {
  const $ = (id) => document.getElementById(id);
  const box = $("blockPick"), area = $("cidrs");
  if (!box || !area) return;
  const SHOW = 300;                  // rows drawn at once; the search looks through every block listed
  let rows = null, loading = false;
  const fmt = (n) => Number(n || 0).toLocaleString();
  const el = (tag, cls, text) => { const n = document.createElement(tag); if (cls) n.className = cls; if (text != null) n.textContent = text; return n; };
  const lines = () => area.value.split(/[\s,]+/).map((x) => x.trim()).filter(Boolean);
  let own = false;                   // our own change to the box: the list is already right (and keeps the focus)
  function setLines(list) {
    area.value = list.join("\n");
    own = true;
    try { area.dispatchEvent(new Event("input", { bubbles: true })); } finally { own = false; }   // settings.js: the preview and Apply follow
  }

  async function load() {
    if (rows || loading) return;
    loading = true; $("blockCount").textContent = "Loading the address blocks…";
    try {
      const r = await fetch("/api/settings/address-blocks", { credentials: "same-origin", cache: "no-store" });
      const d = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
      rows = d.blocks || [];
      box.dataset.total = d.total || 0;
      render();
    } catch (e) {
      $("blockCount").textContent = `The address blocks could not be read: ${e.message}`;
    } finally { loading = false; }
  }

  function render() {
    if (!rows) return;
    const q = $("blockSearch").value.trim().toLowerCase();
    const have = new Set(lines());
    const match = rows.filter((r) => !q || r.block.includes(q) || (r.network || "").toLowerCase().includes(q) || (r.asn && `as${r.asn}`.includes(q)) || (r.asn && r.asn === q));
    const tb = $("blockTable").tBodies[0]; tb.replaceChildren();
    for (const r of match.slice(0, SHOW)) {
      const tr = el("tr"), cb = el("input");
      cb.type = "checkbox"; cb.checked = have.has(r.block) || r.covered; cb.disabled = r.covered;
      cb.setAttribute("aria-label", `Add ${r.block} (${r.network || "network unknown"}) to the extra address ranges`);
      cb.addEventListener("change", () => {
        const cur = lines().filter((x) => x !== r.block);
        setLines(cb.checked ? [...cur, r.block] : cur);
        count();
      });
      const net = el("td", null, r.network || (r.asn ? `AS${r.asn}` : "Not known"));
      if (r.asn) net.append(el("span", "muted", ` AS${r.asn}`));
      const state = el("td", "muted", r.covered ? "Already in (its network is chosen, or a range holds it)" : "");
      const c0 = el("td"); c0.append(cb);
      tr.append(c0, el("td", "mono", r.block), net, el("td", "num", fmt(r.records)), state);
      tb.append(tr);
    }
    if (!match.length) { const tr = el("tr"); const td = el("td", "muted", q ? "No block matches." : "No address blocks in yesterday's reports."); td.colSpan = 5; tr.append(td); tb.append(tr); }
    count(match.length);
  }

  function count(n) {
    if (!rows) return;
    const picked = rows.filter((r) => lines().includes(r.block)).length;
    const shown = n == null ? null : Math.min(n, SHOW);
    const total = Number(box.dataset.total || rows.length);
    $("blockCount").textContent = `${picked} picked from this list` +
      (shown == null ? "" : ` · showing ${fmt(shown)} of ${fmt(n)} matching` + (total > rows.length ? ` (the ${fmt(rows.length)} busiest of ${fmt(total)} blocks; search to narrow)` : ""));
  }

  box.addEventListener("toggle", () => { if (box.open) load(); });
  $("blockSearch").addEventListener("input", render);
  area.addEventListener("input", () => { if (rows && !own) render(); });   // a range typed or removed by hand ticks or unticks
})();
