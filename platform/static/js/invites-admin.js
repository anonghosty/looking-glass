/* SPDX-License-Identifier: AGPL-3.0-only
   SPDX-FileCopyrightText: the Looking Glass contributors */
/* Looking Glass · Admin → Users → Add a person (invites.py; the user 2026-11-19): a one-time sign-up link, shown once,
   copied through the recorded copy button (lg-copy.js; a link is a secret: recorded, not fingerprinted), and the open
   links with Revoke. Administrators only (checked on the server). Text from the server is set as text. */
(() => {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const box = $("invBox");
  if (!box) return;
  const el = (t, c, x) => { const e = document.createElement(t); if (c) e.className = c; if (x != null) e.textContent = x; return e; };
  const csrf = () => document.querySelector('meta[name="csrf-token"]')?.content || "";
  const when = (t) => new Date(t * 1000).toISOString().replace("T", " ").slice(0, 16) + " UTC";
  async function api(url, body) {
    const r = await fetch(url, body === undefined ? { cache: "no-store" }
      : { method: "POST", headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf() }, body: JSON.stringify(body) });
    const d = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(d.error || r.statusText);
    return d;
  }
  function draw(d) {
    const tb = $("invTable").querySelector("tbody"); tb.replaceChildren();
    if (!d.open.length) {
      const tr = el("tr"), td = el("td", "muted", "No open sign-up links."); td.colSpan = 6; tr.append(td); tb.append(tr);
    }
    for (const x of d.open) {
      const tr = el("tr"), act = el("td");
      const b = el("button", "pill-btn", "Revoke"); b.type = "button";
      b.setAttribute("aria-label", `Revoke the sign-up link for ${x.name || x.role}`);
      b.addEventListener("click", async () => {
        b.disabled = true;
        try { await api(`/api/admin/invites/${encodeURIComponent(x.id)}/revoke`, {}); $("invMsg").textContent = "Revoked: that link no longer works."; load(); }
        catch (e) { $("invMsg").textContent = `Not revoked: ${window.LGLoader.errorText(e, true)}`; b.disabled = false; }
      });
      act.append(b);
      tr.append(el("td", null, x.name || "–"), el("td", null, x.role), el("td", null, x.by), el("td", "mono", when(x.at)), el("td", "mono", when(x.expires)), act);
      tb.append(tr);
    }
  }
  async function load(first) {
    let d;
    try { d = await api("/api/admin/invites"); } catch { box.hidden = true; return; }
    box.hidden = false;
    $("invHours").textContent = String(d.hours);
    if (first) {
      const sel = $("invRole"); sel.replaceChildren();
      for (const r of d.roles) sel.append(new Option(r, r, false, r === "analyst"));
      sel.dispatchEvent(new Event("change"));
    }
    draw(d);
  }
  let link = "";
  $("invMake").addEventListener("click", async () => {
    $("invMake").disabled = true; $("invMsg").textContent = "Making the link…";
    try {
      const d = await api("/api/admin/invites", { role: $("invRole").value, name: $("invName").value.trim() });
      link = d.link; $("invLink").textContent = link; $("invDone").hidden = false;
      $("invMsg").textContent = `Made for the role ${d.invite.role}. It is in the audit log (the link itself never is).`;
      $("invName").value = ""; load();
    } catch (e) { $("invMsg").textContent = `Not made: ${window.LGLoader.errorText(e, true)}`; }
    finally { $("invMake").disabled = false; }
  });
  $("invCopy").addEventListener("click", async () => {
    if (!link) return;
    const r = window.LGCopy ? await window.LGCopy.copy({ text: link, kind: "invite", what: "a sign-up link", page: "Admin" })
      : { ok: false, message: "Copying is not available on this page." };
    $("invCopy").textContent = r.ok ? "Copied" : "Not copied";
    if (!r.ok) $("invMsg").textContent = r.message;
    setTimeout(() => { $("invCopy").textContent = "Copy the link"; }, 1500);
  });
  load(true);
})();
