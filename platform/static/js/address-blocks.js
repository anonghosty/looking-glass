/* Looking Glass · Settings → Network names & types → Constituent column: a network's address blocks (address_blocks.py;
   the user's design, 2026-11-21: one picker instead of two). "Some address blocks" opens the network's row in place with
   its blocks (/24) that have records, busiest first, a search and the full list on demand; ticked blocks are saved as
   address ranges with Apply settings (settings.js holds the choice, net-editor.js draws the row). Nothing is looked up
   outside: only this server's list of what the reports hold. */
(() => {
  "use strict";
  const API = "/api/settings/address-blocks";
  const FIRST = 50;                     // blocks drawn before "Show all N blocks"
  const fmt = (n) => Number(n || 0).toLocaleString("en-US");
  const el = (tag, cls, text) => { const n = document.createElement(tag); if (cls) n.className = cls; if (text != null) n.textContent = text; return n; };
  const plural = (n, one, many) => `${fmt(n)} ${n === 1 ? one : (many || `${one}s`)}`;
  const cache = new Map(), done = new Set();   // AS number -> the promise of its blocks; the ones already answered

  async function get(url) {
    const r = await fetch(url, { credentials: "same-origin", cache: "no-store" });
    const d = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
    return d;
  }
  /** one network's blocks, asked once per page */
  function list(asn) {
    const k = String(asn);
    if (!cache.has(k)) {
      const p = get(`${API}?asn=${encodeURIComponent(k)}`);
      p.then(() => done.add(k), () => cache.delete(k));
      cache.set(k, p);
    }
    return cache.get(k);
  }
  /** how many blocks each network has, and which network each saved range that is one of its blocks belongs to */
  const summary = () => get(`${API}?summary=1`);
  /** "3 of 120 blocks chosen" (the collapsed row) */
  function chosenText(n, total) {
    return total == null ? `${plural(n, "block")} chosen` : `${fmt(n)} of ${plural(total, "block")} chosen`;
  }

  /** the open row's content: o = {asn, name, picked() -> Set, toggle(block, on), onClose()} -> {node, focus()} */
  function panel(o) {
    const box = el("div", "nb-panel"); box.id = `nbPanel${o.asn}`;
    box.setAttribute("role", "group"); box.setAttribute("aria-label", `Address blocks of ${o.name} (AS${o.asn})`);
    const intro = el("p", "nb-intro", `The address blocks (/24) of ${o.name} (AS${o.asn}) with records yesterday, busiest first. ` +
      "Tick the blocks that are your constituents; Apply settings, at the bottom, saves them.");
    const tools = el("div", "nb-tools");
    const q = el("input", "dz-search nb-search"); q.type = "search"; q.autocomplete = "off";
    q.placeholder = "Search a block, for example 192.0.2"; q.setAttribute("aria-label", `Search the address blocks of ${o.name}`);
    const status = el("span", "nb-count muted"); status.setAttribute("role", "status");
    const close = el("button", "lg-btn sm", "Close"); close.type = "button";
    close.setAttribute("aria-label", `Close the address blocks of ${o.name}`);
    close.addEventListener("click", () => o.onClose());
    tools.append(q, status, close);
    const ul = el("ul", "nb-list"); ul.setAttribute("aria-label", `Address blocks of ${o.name}`);
    const more = el("button", "lg-btn sm nb-more"); more.type = "button"; more.hidden = true;
    box.append(intro, tools, ul, more);
    let rows = null, all = false;

    const counted = (shown, hits) => {
      if (!rows) return;
      status.textContent = `${chosenText(o.picked().size, rows.length)} · showing ${fmt(shown)} of ${plural(hits, "block")}` +
        (q.value.trim() ? " matching" : "");
    };
    const draw = () => {
      if (!rows) return;
      const s = q.value.trim().toLowerCase();
      const hits = s ? rows.filter((r) => r.block.includes(s)) : rows;
      const shown = all ? hits : hits.slice(0, FIRST);
      const have = o.picked();
      ul.replaceChildren();
      for (const r of shown) {
        const li = el("li"), lab = el("label"), cb = el("input");
        cb.type = "checkbox"; cb.checked = have.has(r.block); cb.value = r.block;
        cb.addEventListener("change", () => { o.toggle(r.block, cb.checked); counted(shown.length, hits.length); });
        lab.append(cb, el("span", "mono", r.block), el("span", "nb-recs", plural(r.records, "record")));
        li.append(lab); ul.append(li);
      }
      if (!hits.length) ul.append(el("li", "nb-empty muted", s ? "No block matches." : "No address blocks with records yesterday."));
      more.hidden = all || hits.length <= FIRST;
      more.textContent = `Show all ${plural(hits.length, "block")}`;
      counted(shown.length, hits.length);
    };
    q.addEventListener("input", () => { all = false; draw(); });
    more.addEventListener("click", () => {
      all = true; draw();
      ul.querySelectorAll("input")[FIRST]?.focus();   // the first block that was not shown before
    });

    // a network asked for the first time: the page's loading animation while its list comes (LGLoader.busy)
    const k = String(o.asn), L = window.LGLoader, slow = !done.has(k);
    status.textContent = "Loading the address blocks…";
    if (slow) L?.busy?.("Loading the address blocks");
    list(k).then((d) => { rows = d.blocks || []; draw(); },
      (e) => { status.textContent = `The address blocks could not be read: ${e.message}`; })
      .finally(() => { if (slow) L?.ready?.(); });
    return { node: box, focus: () => q.focus() };
  }

  window.LGBlocks = { list, summary, panel, chosenText };
})();
