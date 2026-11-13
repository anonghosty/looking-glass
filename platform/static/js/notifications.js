/* Looking Glass · the notification bell in every page's header (notifications.py): what changed in the findings this
   person takes part in, the ones waiting for them first and highlighted. One click opens the place to act (the
   advisory, the review, the finding) and clears that notification; "Clear all" clears theirs. Refreshed every minute
   and when the page comes back into view. Texts are shown as text, links are this site's own paths only. */
(() => {
  "use strict";
  if (new URLSearchParams(location.search).get("embed") === "1") return;        // the portal framed inside the review page
  const css = document.createElement("link"); css.rel = "stylesheet"; css.href = "/static/css/notifications.css"; document.head.append(css);
  const el = (t, c, x) => { const e = document.createElement(t); if (c) e.className = c; if (x != null) e.textContent = x; return e; };
  const csrf = () => document.querySelector('meta[name="csrf-token"]')?.content || "";
  const safe = (u) => typeof u === "string" && u.startsWith("/") && !u.startsWith("//") && !u.includes("\\");
  const bells = [];
  let data = { count: 0, waiting: 0, items: [] }, panel = null, openFor = null;

  const BELL = "M6 16V11a6 6 0 0 1 12 0v5l1.5 2h-15zM10 20a2 2 0 0 0 4 0";
  function makeBell(host) {
    // it looks like the header's other buttons: an icon button beside the page icons, on every page (the Executive
    // portal's header has icon buttons too since 2026-11-13)
    const b = el("button", "demo-btn nav-ic lg-bell"); b.type = "button";
    b.setAttribute("aria-haspopup", "dialog"); b.setAttribute("aria-expanded", "false");
    b.innerHTML = `<svg viewBox="0 0 24 24" width="16" height="16" aria-hidden="true"><path fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" d="${BELL}"/></svg>`;
    const badge = el("span", "lg-bell-n"); badge.hidden = true; b.append(badge, el("span", "lg-bell-label", "Notifications"));
    b.addEventListener("click", (e) => { e.stopPropagation(); panel && !panel.hidden && openFor === b ? close() : open(b); });
    return b;
  }
  function place() {
    for (const host of document.querySelectorAll(".hud-right, .intro-gear-row, .mg-top-actions")) {
      if (host.querySelector(".lg-bell")) continue;
      const b = makeBell(host);
      // Settings then Log out close the header: the bell goes before Settings (or before Log out where there is none)
      const settings = host.querySelector('#introSettings, a.nav-ic[href="/settings"], button.nav-ic[data-go="/settings"]');
      const logout = host.querySelector(":scope > .account-form, :scope > .mg-logout");
      settings ? settings.before(b) : logout ? logout.before(b) : host.append(b);
      bells.push(b);
    }
  }
  function paint() {
    for (const b of bells) {
      const n = b.querySelector(".lg-bell-n");
      n.hidden = !data.count; n.textContent = data.count > 99 ? "99+" : String(data.count);
      b.classList.toggle("has-new", !!data.count); b.classList.toggle("has-waiting", !!data.waiting);
      b.title = data.count ? `${data.count} notification${data.count === 1 ? "" : "s"}${data.waiting ? `, ${data.waiting} waiting for you` : ""}` : "No new notification";
      b.setAttribute("aria-label", b.title);
    }
    if (panel && !panel.hidden) fill();
  }
  async function refresh() {
    try {
      const r = await fetch("/api/notifications", { cache: "no-store", credentials: "same-origin" });
      if (!r.ok) return;
      data = await r.json();
      if (data.peace) { for (const b of bells) b.remove(); bells.length = 0; close(); return; }   // Peace of mind: no bell
      paint();
    } catch { /* offline for a moment: the next refresh catches up */ }
  }
  async function clear(body) {
    const r = await fetch("/api/notifications/clear", { method: "POST", credentials: "same-origin",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf() }, body: JSON.stringify(body) });
    if (r.ok) { const d = await r.json(); data.count = d.count; data.waiting = d.waiting; }
    return r.ok;
  }
  function fill() {
    panel.replaceChildren();
    const head = el("div", "lg-notif-head");
    head.append(el("b", null, "Notifications"), el("span", "lg-notif-sub", data.count ? `${data.count} new${data.waiting ? ` · ${data.waiting} waiting for you` : ""}` : "Nothing new"));
    if (data.count) {
      const all = el("button", "lg-notif-clear", "Clear all"); all.type = "button";
      all.addEventListener("click", async () => {          // a dropped connection must not leave it disabled (review 2026-11-13)
        all.disabled = true;
        try { if (await clear({ all: true })) { data.items = []; paint(); } } catch { /* offline for a moment: try again */ } finally { all.disabled = false; }
      });
      head.append(all);
    }
    panel.append(head);
    const list = el("div", "lg-notif-list");
    if (!data.items.length) list.append(el("p", "lg-notif-empty", "You are up to date: what changes in the findings you take part in shows here."));
    for (const n of data.items) {
      const a = el("a", `lg-notif${n.waiting ? " waiting" : ""}`);
      a.href = safe(n.link) ? n.link : "/findings";
      const top = el("div", "lg-notif-top");
      top.append(el("span", "lg-notif-no", n.case ? `Case ${n.number}` : n.number), el("b", null, n.network ? `${n.network}` : n.title));
      if (n.waiting) top.append(el("span", "lg-notif-tag", "Waiting for you"));
      a.append(top);
      if (n.network) a.append(el("span", "lg-notif-title", n.title));
      a.append(el("span", "lg-notif-text", `${n.by}: ${n.text}`),
               el("small", null, `${n.when} · ${n.status_label}${n.updates > 1 ? ` · ${n.updates} updates` : ""}`));
      a.addEventListener("click", async (e) => {
        e.preventDefault();
        await clear({ ids: [n.id] }).catch(() => {});
        const to = a.getAttribute("href");
        if (location.pathname === "/findings" && to.startsWith("/findings#")) { location.hash = to.slice(9); location.reload(); return; }
        window.LGLoader ? window.LGLoader.go(to) : (location.href = to);
      });
      list.append(a);
    }
    panel.append(list);
  }
  function open(b) {
    if (!panel) {
      panel = el("div", "lg-notif-panel"); panel.setAttribute("role", "dialog"); panel.setAttribute("aria-label", "Notifications"); panel.hidden = true;
      document.body.append(panel);
      panel.addEventListener("click", (e) => e.stopPropagation());
    }
    openFor = b; fill(); panel.hidden = false;
    const r = b.getBoundingClientRect();
    panel.style.top = `${Math.round(r.bottom + 8 + window.scrollY)}px`;
    panel.style.right = `${Math.max(8, Math.round(document.documentElement.clientWidth - r.right))}px`;
    b.setAttribute("aria-expanded", "true");
    refresh();
    // focus into the list, so Tab from the bell reaches it (it sits at the end of the page; review 2026-11-13)
    setTimeout(() => panel.querySelector("a, button")?.focus({ preventScroll: true }), 0);
  }
  function close() {
    if (!panel || panel.hidden) return;
    const inside = panel.contains(document.activeElement);
    panel.hidden = true; for (const b of bells) b.setAttribute("aria-expanded", "false");
    if (inside) openFor?.focus({ preventScroll: true });   // back to the bell, not lost to the page
  }
  document.addEventListener("click", close);
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") close(); });
  document.addEventListener("visibilitychange", () => { if (!document.hidden) refresh(); });
  const start = () => { place(); refresh(); setInterval(refresh, 60000); };
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", start); else start();
})();
