/* Looking Glass · dropdowns in the platform's own design (instead of the browser's plain lists).
   Any <select class="lg-enhance"> becomes a styled button with a dark list, a search box for long lists, a tick on the
   current choice and full keyboard use (arrows, Home/End, Enter, Escape, typing to search). The real <select> stays in
   the page, hidden, and keeps the value: code that reads it, sets it or listens to "change" works unchanged.
   Options: data-caption="Region" shows a small caption above the value. */
(() => {
  "use strict";
  const el = (t, c, x) => { const e = document.createElement(t); if (c) e.className = c; if (x != null) e.textContent = x; return e; };
  let open = null;                                   // the list that is open

  function label(sel) {
    const o = sel.options[sel.selectedIndex];
    return o ? o.textContent : "";
  }
  function sync(sel) {
    const ui = sel._lgs; if (!ui) return;
    ui.value.textContent = label(sel);
    ui.btn.classList.toggle("set", !!sel.value);
    ui.btn.disabled = sel.disabled;
    ui.btn.title = `${sel.dataset.caption || sel.getAttribute("aria-label") || ""}${sel.dataset.caption || sel.getAttribute("aria-label") ? ": " : ""}${label(sel)}`;
  }

  function close(focusBack) {
    if (!open) return;
    const { pop, sel } = open;
    pop.remove(); sel._lgs.btn.setAttribute("aria-expanded", "false"); sel._lgs.wrap.classList.remove("open");
    if (focusBack) sel._lgs.btn.focus();
    open = null;
  }

  function choose(sel, value) {
    if (sel.value !== value) {
      sel.value = value;
      sel.dispatchEvent(new Event("input", { bubbles: true }));
      sel.dispatchEvent(new Event("change", { bubbles: true }));
    }
    sync(sel); close(true);
  }

  function openList(sel) {
    if (open && open.sel === sel) { close(true); return; }
    close(false);
    const ui = sel._lgs, opts = [...sel.options];
    const pop = el("div", "lgs-pop"); pop.setAttribute("role", "listbox");
    const search = opts.length > 8 ? el("input", "lgs-search") : null;
    if (search) { search.type = "search"; search.placeholder = "Search…"; search.setAttribute("aria-label", "Search the list"); pop.append(search); }
    const list = el("div", "lgs-list"); pop.append(list);
    let items = [];
    const draw = (q) => {
      list.replaceChildren(); items = [];
      for (const o of opts) {
        if (q && !o.textContent.toLowerCase().includes(q) && o.value !== "") continue;
        const b = el("button", `lgs-opt${o.value === sel.value ? " on" : ""}`); b.type = "button"; b.setAttribute("role", "option");
        b.setAttribute("aria-selected", String(o.value === sel.value)); b.dataset.value = o.value;
        b.append(el("span", null, o.textContent), el("i", null, o.value === sel.value ? "✓" : ""));
        b.addEventListener("click", () => choose(sel, o.value));
        list.append(b); items.push(b);
      }
      if (!items.length) list.append(el("p", "lgs-none", "Nothing matches."));
    };
    draw("");
    document.body.append(pop);
    // place it under the button (or above when there is no room), at least as wide as the button
    const r = ui.btn.getBoundingClientRect(), vw = document.documentElement.clientWidth, vh = window.innerHeight;
    pop.style.minWidth = `${Math.max(r.width, 200)}px`;
    const pw = pop.offsetWidth, ph = Math.min(pop.offsetHeight, 340);
    const below = vh - r.bottom > ph + 12 || r.top < ph + 12;
    pop.style.left = `${Math.max(8, Math.min(r.left, vw - pw - 8))}px`;
    pop.style.top = below ? `${r.bottom + 6}px` : `${r.top - ph - 6}px`;
    ui.btn.setAttribute("aria-expanded", "true"); ui.wrap.classList.add("open");
    open = { sel, pop };
    const current = items.find((b) => b.classList.contains("on")) || items[0];
    current?.scrollIntoView({ block: "nearest" });
    (search || current)?.focus();
    const move = (d) => {
      const i = items.indexOf(document.activeElement);
      const n = i < 0 ? (d > 0 ? 0 : items.length - 1) : Math.max(0, Math.min(items.length - 1, i + d));
      items[n]?.focus();
    };
    pop.addEventListener("keydown", (e) => {
      if (e.key === "ArrowDown") { e.preventDefault(); move(1); }
      else if (e.key === "ArrowUp") { e.preventDefault(); if (items.indexOf(document.activeElement) <= 0 && search) search.focus(); else move(-1); }
      else if (e.key === "Home") { e.preventDefault(); items[0]?.focus(); }
      else if (e.key === "End") { e.preventDefault(); items[items.length - 1]?.focus(); }
      else if (e.key === "Escape") { e.preventDefault(); close(true); }
      else if (e.key === "Tab") { close(false); }
      else if (e.key === "Enter" && document.activeElement === search && items[0]) { e.preventDefault(); choose(sel, (items[1] && search.value ? items[1] : items[0]).dataset.value); }
    });
    search?.addEventListener("input", () => draw(search.value.trim().toLowerCase()));
  }

  function enhance(sel) {
    if (sel._lgs || sel.multiple) return;
    const wrap = el("span", `lgs${sel.dataset.caption ? " captioned" : ""}`);
    for (const c of sel.classList) if (c !== "lg-enhance") wrap.classList.add(`lgs-${c}`);
    const btn = el("button", "lgs-btn"); btn.type = "button";
    btn.setAttribute("aria-haspopup", "listbox"); btn.setAttribute("aria-expanded", "false");
    const name = sel.getAttribute("aria-label") || sel.dataset.caption || sel.labels?.[0]?.textContent?.trim();
    if (name) btn.setAttribute("aria-label", name);
    const body = el("span", "lgs-body");
    if (sel.dataset.caption) body.append(el("small", null, sel.dataset.caption));
    const value = el("span", "lgs-value");
    body.append(value);
    btn.append(body, el("span", "lgs-chev", ""));
    sel.parentNode.insertBefore(wrap, sel);
    wrap.append(btn, sel);
    sel.classList.add("lgs-native"); sel.tabIndex = -1; sel.setAttribute("aria-hidden", "true");
    sel._lgs = { wrap, btn, value };
    btn.addEventListener("click", () => openList(sel));
    btn.addEventListener("keydown", (e) => { if (["ArrowDown", "ArrowUp", "Enter", " "].includes(e.key)) { e.preventDefault(); openList(sel); } });
    sel.addEventListener("change", () => sync(sel));
    // options or value replaced by code: follow
    new MutationObserver(() => sync(sel)).observe(sel, { childList: true, subtree: true, attributes: true, attributeFilter: ["disabled"] });
    const desc = Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, "value");
    Object.defineProperty(sel, "value", { configurable: true, get() { return desc.get.call(this); }, set(v) { desc.set.call(this, v); sync(this); } });
    sync(sel);
  }

  function scan(root) {
    (root.querySelectorAll ? root : document).querySelectorAll("select.lg-enhance").forEach(enhance);
    if (root.matches?.("select.lg-enhance")) enhance(root);
  }
  document.addEventListener("click", (e) => { if (open && !open.pop.contains(e.target) && !open.sel._lgs.wrap.contains(e.target)) close(false); }, true);
  window.addEventListener("resize", () => close(false));
  document.addEventListener("scroll", (e) => { if (open && !open.pop.contains(e.target)) close(false); }, true);
  const start = () => {
    scan(document);
    new MutationObserver((ms) => { for (const m of ms) for (const n of m.addedNodes) if (n.nodeType === 1) scan(n); })
      .observe(document.body, { childList: true, subtree: true });
  };
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", start); else start();
  window.LGSelect = { enhance, sync, close };
})();
