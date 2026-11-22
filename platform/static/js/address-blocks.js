/* SPDX-License-Identifier: AGPL-3.0-only
   SPDX-FileCopyrightText: the Looking Glass contributors */
/* Looking Glass · Settings → Network names & types → Constituent column: a network's address blocks (address_blocks.py;
   the user's design, 2026-11-21: one picker instead of two). "Some address blocks" opens the network's row in place with
   its blocks (/24) that have records, busiest first, a search and the full list on demand; ticked blocks are saved as
   address ranges with Apply settings (settings.js holds the choice, net-editor.js draws the row). r90: the chosen
   blocks come first and stay until unticked, with or without records, and "Add a block" adds one that is not listed.
   Nothing is looked up outside: only this server's list of what the reports hold. */
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
  /** how many blocks each network has, and the network each saved range belongs to (yesterday, else any day in memory) */
  const summary = () => get(`${API}?summary=1`);
  /** a range or a single address as Apply settings takes it (checked again by this server, which writes it the
      standard way): IPv4 a.b.c.d or a.b.c.d/0-32, IPv6 with an optional /0-128 */
  function looksLikeRange(s) {
    s = String(s || "").trim();
    if (!s || s.length > 64) return false;
    const [ip, len, extra] = s.split("/");
    if (extra !== undefined || (len !== undefined && !/^\d{1,3}$/.test(len))) return false;
    const v4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip);
    if (v4) return v4.slice(1).every((x) => Number(x) < 256) && (len === undefined || Number(len) <= 32);
    return ip.includes(":") && /^[0-9a-fA-F:.]+$/.test(ip) && (len === undefined || Number(len) <= 128);
  }
  /** Other address ranges' Add: the range written the standard way, or the server's reason */
  const check = (text) => get(`${API}?check=${encodeURIComponent(text)}`);
  /** a network row's Add a block: {range, info} (an address adds its /24), or the server's reason */
  const addTo = (asn, text) => get(`${API}?add=${encodeURIComponent(text)}&for=${encodeURIComponent(String(asn))}`);
  /** what a block shows beside it in a network's row: its records yesterday in that network */
  function recordsText(asn, records, info) {
    const n = records != null ? records : ((info && info.nets && info.nets[String(asn)]) || 0);
    if (!n) return "no records yesterday";
    return info && info.part && records == null ? `in a block with ${plural(n, "record")} yesterday` : `${plural(n, "record")} yesterday`;
  }
  /** "3 of 120 blocks chosen" (the collapsed row) */
  function chosenText(n, total) {
    return total == null ? `${plural(n, "block")} chosen` : `${fmt(n)} of ${plural(total, "block")} chosen`;
  }

  /** the open row's content: o = {asn, name, picked() -> Set (this network's chosen ranges), isChosen(range),
      info(range), toggle(range, on, info), onClose()} -> {node, focus()} */
  function panel(o) {
    const box = el("div", "nb-panel"); box.id = `nbPanel${o.asn}`;
    box.setAttribute("role", "group"); box.setAttribute("aria-label", `Address blocks of ${o.name} (AS${o.asn})`);
    const intro = el("p", "nb-intro", `The address blocks (/24) in which ${o.name} (AS${o.asn}) had records yesterday, busiest first, ` +
      "after the blocks you chose. Tick the blocks that are your constituents; Apply settings, at the bottom, saves them. " +
      "Your choice is kept until you untick it; blocks without records stay chosen.");
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
    // Add a block: one of this network's blocks or ranges that is not listed (no records yesterday)
    const add = el("div", "nb-add"), addId = `nbAdd${o.asn}`;
    const addLab = el("label", "nb-add-label", "Add a block"); addLab.htmlFor = addId;
    const addIn = el("input", "dz-input mono nb-add-input"); addIn.id = addId; addIn.type = "text"; addIn.autocomplete = "off";
    addIn.spellcheck = false; addIn.maxLength = 64; addIn.placeholder = "for example 192.0.2.0/24";
    addIn.setAttribute("aria-describedby", `${addId}Hint`);
    const addBtn = el("button", "lg-btn sm", "Add"); addBtn.type = "button";
    addBtn.setAttribute("aria-label", `Add a block to ${o.name}`);
    const addMsg = el("span", "nb-add-msg muted"); addMsg.setAttribute("role", "status");
    const addHint = el("p", "nb-add-hint muted", "A block or address range of this network that is not listed because it had no records " +
      "yesterday. A single address adds the /24 it is in."); addHint.id = `${addId}Hint`;
    add.append(addLab, addIn, addBtn, addMsg, addHint);
    box.append(intro, tools, ul, more, add);
    let rows = null, all = false;

    /** the chosen ranges first (whether or not they have records), then the network's other blocks */
    const ordered = () => {
      const by = new Map(rows.map((r) => [r.block, r]));
      const mine = new Set([...o.picked(), ...rows.filter((r) => o.isChosen(r.block)).map((r) => r.block)]);
      const first = [...mine].sort((a, b) => ((by.get(b) || {}).records || 0) - ((by.get(a) || {}).records || 0) || a.localeCompare(b))
        .map((b) => by.get(b) || { block: b, records: null });
      return { list: [...first, ...rows.filter((r) => !mine.has(r.block))], chosen: mine.size, extra: first.filter((r) => r.records == null).length };
    };
    const counted = (shown, hits) => {
      if (!rows) return;
      const k = ordered();
      status.textContent = `${chosenText(k.chosen, rows.length + k.extra)} · showing ${fmt(shown)} of ${plural(hits, "block")}` +
        (q.value.trim() ? " matching" : "");
    };
    const draw = () => {
      if (!rows) return;
      const s = q.value.trim().toLowerCase();
      const k = ordered();
      const hits = s ? k.list.filter((r) => r.block.includes(s)) : k.list;
      const shown = all ? hits : hits.slice(0, FIRST);
      ul.replaceChildren();
      for (const r of shown) {
        const li = el("li"), lab = el("label"), cb = el("input");
        cb.type = "checkbox"; cb.checked = o.isChosen(r.block); cb.value = r.block;
        cb.addEventListener("change", () => {
          o.toggle(r.block, cb.checked, r.records != null
            ? { asn: String(o.asn), nets: { [String(o.asn)]: r.records }, exact: true, part: false, seen: "yesterday" } : null);
          counted(shown.length, hits.length);
        });
        lab.append(cb, el("span", "mono", r.block), el("span", "nb-recs", recordsText(o.asn, r.records, o.info(r.block))));
        li.append(lab); ul.append(li);
      }
      if (!hits.length) ul.append(el("li", "nb-empty muted", s ? "No block matches."
        : "No address blocks with records yesterday. If a block of this network is yours, add it below."));
      more.hidden = all || hits.length <= FIRST;
      more.textContent = `Show all ${plural(hits.length, "block")}`;
      counted(shown.length, hits.length);
    };
    q.addEventListener("input", () => { all = false; draw(); });
    more.addEventListener("click", () => {
      all = true; draw();
      ul.querySelectorAll("input")[FIRST]?.focus();   // the first block that was not shown before
    });
    async function addBlock() {
      const text = addIn.value.trim();
      if (!looksLikeRange(text)) {
        addMsg.textContent = text ? `Not an address range: ${text}. Type a block such as 192.0.2.0/24, or a single address.`
          : "Type a block or a single address first.";
        addIn.focus(); return;
      }
      addBtn.disabled = true;
      try {
        const d = await addTo(o.asn, text);
        if (o.isChosen(d.range)) { addMsg.textContent = `${d.range} is already chosen.`; return; }
        o.toggle(d.range, true, d.info);
        addIn.value = ""; q.value = ""; all = false; draw();
        addMsg.textContent = `Added ${d.range} (${recordsText(o.asn, null, d.info)}). Apply settings, at the bottom, saves it.`;
      } catch (e) { addMsg.textContent = window.LGLoader.errorText(e, true); }
      finally { addBtn.disabled = false; addIn.focus(); }
    }
    addBtn.addEventListener("click", addBlock);
    addIn.addEventListener("keydown", (e) => { if (e.key === "Enter") { e.preventDefault(); addBlock(); } });

    // a network asked for the first time: the page's loading animation while its list comes (LGLoader.busy)
    const k = String(o.asn), L = window.LGLoader, slow = !done.has(k);
    status.textContent = "Loading the address blocks…";
    if (slow) L?.busy?.("Loading the address blocks");
    list(k).then((d) => { rows = d.blocks || []; draw(); },
      (e) => { status.textContent = `The address blocks could not be read: ${window.LGLoader.errorText(e)}`; })
      .finally(() => { if (slow) L?.ready?.(); });
    return { node: box, focus: () => q.focus() };
  }

  window.LGBlocks = { list, summary, panel, chosenText, looksLikeRange, check, addTo, recordsText };
})();
