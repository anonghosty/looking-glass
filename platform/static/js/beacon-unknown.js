/* "Requests Looking Glass could not decode" on the Findings page (beacon_unknown.py), for analysts and admins.
 *
 * Each family: its request shape (path, parameter, encoding, what the value looks like), the C2 hosts, names, reports,
 * records and devices, and the exact request lines a decoding request would hold. "Ask to send" (with a reason) puts it
 * before an administrator, who approves or does not (with a reason); only then is the decoding request downloaded
 * (JSON: only the HTTP request lines, no host) and pasted into a private report: nothing is sent by Looking Glass itself.
 * "Not a beacon" puts a family away (a session token, an ID); "Mark as sent" records that it went to the creator.
 */
(function () {
  "use strict";
  const el = (tag, cls, text) => { const e = document.createElement(tag); if (cls) e.className = cls; if (text != null) e.textContent = text; return e; };
  const csrf = () => document.querySelector('meta[name="csrf-token"]')?.content || "";
  const fmt = (n) => Number(n || 0).toLocaleString("en-GB");
  const plural = (n, w) => `${fmt(n)} ${w}${n === 1 ? "" : "s"}`;

  async function state(id, st, why) {
    const r = await fetch(`/api/beacon/unknown/${encodeURIComponent(id)}/state`, { method: "POST", credentials: "same-origin",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf() }, body: JSON.stringify({ state: st, why: why || "" }) });
    if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error || r.status);
  }

  const STATE_LINE = (f) => ({
    asked: `Waiting for an administrator's approval${f.asked_by ? `: asked by ${f.asked_by}` : ""}${f.asked_at ? ` on ${f.asked_at}` : ""}`,
    approved: `Approved by ${f.state_by || "an administrator"}${f.state_at ? ` on ${f.state_at}` : ""}: ready to send`,
    rejected: `Not approved by ${f.state_by || "an administrator"}${f.state_at ? ` on ${f.state_at}` : ""}`,
    sent: `Sent to the creator${f.state_by ? " by " + f.state_by : ""}${f.state_at ? " on " + f.state_at : ""}${f.approved_by ? `, approved by ${f.approved_by}` : ""}`,
    dismissed: `Not a beacon${f.state_by ? " (" + f.state_by + ")" : ""}`,
  })[f.state] || "";

  function reasonForm(label, placeholder, button, primary, onGo) {
    const box = el("div", "bu-reason");
    const ta = el("textarea", "fd-in"); ta.rows = 2; ta.maxLength = 300; ta.placeholder = placeholder; ta.setAttribute("aria-label", label);
    const go = el("button", `lg-btn sm${primary ? " primary" : ""}`, button); go.type = "button";
    const msg = el("span", "fd-msg"); msg.setAttribute("role", "status");
    go.addEventListener("click", async () => {
      if (!ta.value.trim()) { msg.textContent = "Say why first."; ta.focus(); return; }
      go.disabled = true;
      try { await onGo(ta.value.trim()); } catch (e) { msg.textContent = e.message; go.disabled = false; }
    });
    box.append(el("span", "bh-l", label), ta, go, msg);
    return box;
  }

  function family(f, redraw, canApprove) {
    const c = el("article", `bu-fam s-${f.state}`);
    const h = el("div", "bu-h");
    h.append(el("code", "bu-label", f.label), el("span", "bu-n", `${plural(f.records, "record")} · ${plural(f.devices, "device")}`));
    if (f.state !== "open") h.append(el("span", `bu-state st-${f.state}`, STATE_LINE(f)));
    c.append(h);
    const dl = el("dl", "bu-dl");
    const rows = [["What it looks like", `${f.encoding}, ${f.lengths[0] === f.lengths[1] ? f.lengths[0] : `${f.lengths[0]}–${f.lengths[1]}`} bytes: ${f.hint}${f.constant ? " (the same value every time: a token, not device data)" : ""}`],
      ["Sent to", `${f.hosts.join(", ")}${f.hosts_total > f.hosts.length ? ` and ${fmt(f.hosts_total - f.hosts.length)} more` : ""}`],
      ["Filed under", f.names.join(", ")], ["Reports", f.reports.join(", ")], ["User agents", f.agents.join(" · ")],
      ["Days", f.days.join(", ")], ["Distinct values", fmt(f.distinct)]];
    if (f.asked_why) rows.push(["Why send it", f.asked_why]);
    if (f.state_why && f.state !== "asked") rows.push([f.state === "rejected" ? "Why not approved" : "Note", f.state_why]);
    for (const [k, v] of rows) { dl.append(el("dt", null, k)); dl.append(el("dd", v ? null : "empty", v || "Not recorded")); }
    c.append(dl);
    // exactly what the decoding request holds, before anyone asks to send it
    const pv = el("details", "bu-preview"); pv.open = f.state === "asked" && canApprove;
    pv.append(el("summary", null, `What would be sent (${plural((f.requests || []).length, "request")})`));
    pv.append(el("p", "bu-note", "Only these request lines, each with the infection name it is filed under: every other value reads <value> and any address <address>. No host, user agent or count."));
    const pre = el("pre", "bh-pre");
    pre.textContent = (f.requests || []).map((r) => `${r.infection}\n  ${r.request}`).join("\n");
    pv.append(pre);
    c.append(pv);
    const act = el("div", "bu-act");
    if (f.state === "open" || f.state === "rejected") {
      const ask = el("details", "bu-send"); ask.append(el("summary", null, "Ask to send to the Looking Glass creator"));
      ask.append(el("p", null, "An administrator looks at the request lines above and approves before anything is sent. Once approved, the decoding request is downloaded and pasted into a private report on the HTTP Requests Decoding repository, so a future release decodes this family automatically."));
      ask.append(reasonForm("Why it should be decoded", "e.g. seen on many devices under android.badbox2, a new C2", "Ask for approval", true,
        async (why) => { await state(f.id, "asked", why); redraw(); }));
      act.append(ask);
    } else if (f.state === "asked") {
      if (canApprove) {
        const rv = el("div", "bu-review");
        const ok = el("button", "lg-btn sm primary", "Approve sending"); ok.type = "button";
        const msg = el("span", "fd-msg"); msg.setAttribute("role", "status");
        ok.addEventListener("click", async () => { ok.disabled = true; try { await state(f.id, "approved", ""); redraw(); } catch (e) { msg.textContent = e.message; ok.disabled = false; } });
        const no = el("details", "bu-send"); no.append(el("summary", null, "Do not approve"));
        no.append(reasonForm("Why it is not approved", "e.g. TLP:RED source, or not a beacon", "Do not approve", false,
          async (why) => { await state(f.id, "rejected", why); redraw(); }));
        rv.append(ok, msg, no);
        act.append(rv);
      } else {
        act.append(el("p", "bu-note", "An administrator approves it before it can be sent."));
      }
    } else if (f.state === "approved") {
      const ask = el("details", "bu-send"); ask.open = true; ask.append(el("summary", null, "Send to the Looking Glass creator"));
      ask.append(el("p", null, "Approved. Download the decoding request, then paste its contents into the private report that opens on the HTTP Requests Decoding repository (only you and the Looking Glass creator see it)."));
      const lab = el("label", "bu-chk"); const cb = el("input"); cb.type = "checkbox";
      lab.append(cb, document.createTextNode(" Our organisation's rules (TLP) allow sharing these requests. Decoded, a value may hold the device's own data. The download is recorded in the audit log."));
      const go = el("button", "lg-btn sm primary", "Download the decoding request"); go.type = "button"; go.disabled = true;
      cb.addEventListener("change", () => { go.disabled = !cb.checked; });
      const msg = el("span", "fd-msg"); msg.setAttribute("role", "status");
      go.addEventListener("click", async () => {
        go.disabled = true;
        try {
          const r = await fetch(`/api/beacon/unknown/${encodeURIComponent(f.id)}/request`, { credentials: "same-origin" });
          if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error || r.status);
          const blob = await r.blob(); const a = el("a"); a.href = URL.createObjectURL(blob); a.download = `looking-glass-decoding-request-${f.id}.json`;
          document.body.append(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(a.href), 4000);
          const link = el("a", "lg-btn sm primary", "Open a private report for the Looking Glass creator");
          link.href = f.issue_url; link.target = "_blank"; link.rel = "noopener noreferrer";
          msg.replaceChildren(document.createTextNode("Downloaded. Title the report \"Decoding request\", paste the file's contents into it, then mark it as sent. "), link);
          const sent = el("button", "lg-btn sm", "Mark as sent"); sent.type = "button";
          sent.addEventListener("click", async () => { try { await state(f.id, "sent"); redraw(); } catch (e) { msg.textContent = e.message; } });
          act.append(sent);
        } catch (e) { msg.textContent = `Not downloaded: ${e.message}`; }
        go.disabled = !cb.checked;
      });
      ask.append(lab, go, msg);
      act.append(ask);
    }
    if (f.state !== "sent" && f.state !== "approved") {
      const away = f.state === "dismissed";
      const tog = el("button", "lg-btn sm", away ? "Reopen" : "Not a beacon"); tog.type = "button";
      tog.title = away ? "Back to the open families" : "A session token, an ID or the like: put it away (it stays listed under Put away)";
      tog.addEventListener("click", async () => {
        try { await state(f.id, away ? "open" : "dismissed", away ? "" : "Not a beacon"); redraw(); }
        catch (e) { tog.textContent = e.message; }
      });
      act.append(tog);
    }
    c.append(act);
    return c;
  }

  async function mount(holder) {
    let d;
    try {
      const r = await fetch("/api/beacon/unknown", { credentials: "same-origin" });
      if (r.status === 403) { holder.hidden = true; return; }
      d = await r.json(); if (!r.ok) throw new Error(d.error || r.status);
    } catch (e) { holder.hidden = false; holder.replaceChildren(el("h2", null, "Requests Looking Glass could not decode"), el("p", "fd-msg", `Could not load them: ${e.message}`)); return; }
    holder.hidden = false;
    const AWAY = ["sent", "dismissed"];
    const open = d.families.filter((f) => !AWAY.includes(f.state)), away = d.families.filter((f) => AWAY.includes(f.state));
    const waiting = open.filter((f) => f.state === "asked").length;
    holder.replaceChildren(el("h2", null, "Requests Looking Glass could not decode"),
      el("p", "bu-intro", open.length
        ? `${plural(open.length, "family")} of encoded requests in the days in memory that no known format and no generic layer decodes. Look at each and its request lines: ask to send the real ones to the Looking Glass creator for future automated decoding (an administrator approves first), and put away what is not a beacon.${waiting ? ` ${plural(waiting, "family")} ${waiting === 1 ? "waits" : "wait"} for an administrator's approval.` : ""}`
        : "Every encoded request in the days in memory is decoded or known. Nothing waits for the Looking Glass creator."));
    const redraw = () => mount(holder);
    // waiting for approval first, so an administrator sees them at the top
    open.sort((a, b) => (b.state === "asked") - (a.state === "asked"));
    for (const f of open) holder.append(family(f, redraw, !!d.can_approve));
    if (away.length) {
      const det = el("details", "bu-away"); det.append(el("summary", null, `Sent or put away (${away.length})`));
      for (const f of away) det.append(family(f, redraw, !!d.can_approve));
      holder.append(det);
    }
  }

  document.addEventListener("DOMContentLoaded", () => { const h = document.getElementById("beaconUnknown"); if (h) mount(h); });
  window.LGBeaconUnknown = { mount };
})();
