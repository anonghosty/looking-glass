/* "Requests Looking Glass could not decode" on the Findings page (beacon_unknown.py), for analysts and admins.
 *
 * Each family: its request shape (path, parameter, encoding, what the value looks like), the C2 hosts, names, reports,
 * records and devices. "Send to the Looking Glass creator" downloads a decoding request (JSON: only the HTTP request
 * lines, no host) and opens a new issue on the project's GitHub page to attach it to: nothing is sent by Looking Glass itself.
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

  function family(f, redraw) {
    const c = el("article", `bu-fam s-${f.state}`);
    const h = el("div", "bu-h");
    h.append(el("code", "bu-label", f.label), el("span", "bu-n", `${plural(f.records, "record")} · ${plural(f.devices, "device")}`));
    if (f.state !== "open") h.append(el("span", "bu-state", f.state === "sent" ? `Sent to the creator${f.state_by ? " by " + f.state_by : ""}${f.state_at ? " on " + f.state_at : ""}` : `Not a beacon${f.state_by ? " (" + f.state_by + ")" : ""}`));
    c.append(h);
    const dl = el("dl", "bu-dl");
    const rows = [["What it looks like", `${f.encoding}, ${f.lengths[0] === f.lengths[1] ? f.lengths[0] : `${f.lengths[0]}–${f.lengths[1]}`} bytes: ${f.hint}${f.constant ? " (the same value every time: a token, not device data)" : ""}`],
      ["Sent to", `${f.hosts.join(", ")}${f.hosts_total > f.hosts.length ? ` and ${fmt(f.hosts_total - f.hosts.length)} more` : ""}`],
      ["Filed under", f.names.join(", ")], ["Reports", f.reports.join(", ")], ["User agents", f.agents.join(" · ")],
      ["Days", f.days.join(", ")], ["Distinct values", fmt(f.distinct)]];
    if (f.state_why) rows.push(["Note", f.state_why]);
    for (const [k, v] of rows) { dl.append(el("dt", null, k)); dl.append(el("dd", v ? null : "empty", v || "Not recorded")); }
    c.append(dl);
    const act = el("div", "bu-act");
    if (f.state !== "sent") {
      const ask = el("details", "bu-send"); ask.append(el("summary", null, "Send to the Looking Glass creator"));
      ask.append(el("p", null, "Looking Glass could not decode this family. Send it to the Looking Glass creator so a future release decodes it automatically: download the decoding request, then paste its contents into the private report that opens on the HTTP Requests Decoding repository (only you and the Looking Glass creator see it). The file holds only the HTTP requests (up to 5), with no host, address, name or count."));
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
    const tog = el("button", "lg-btn sm", f.state === "open" ? "Not a beacon" : "Reopen"); tog.type = "button";
    tog.title = f.state === "open" ? "A session token, an ID or the like: put it away (it stays listed under Put away)" : "Back to the open families";
    tog.addEventListener("click", async () => {
      try { await state(f.id, f.state === "open" ? "dismissed" : "open", f.state === "open" ? "Not a beacon" : ""); redraw(); }
      catch (e) { tog.textContent = e.message; }
    });
    act.append(tog);
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
    const open = d.families.filter((f) => f.state === "open"), away = d.families.filter((f) => f.state !== "open");
    holder.replaceChildren(el("h2", null, "Requests Looking Glass could not decode"),
      el("p", "bu-intro", open.length
        ? `${plural(open.length, "family")} of encoded requests in the days in memory that no known format and no generic layer decodes. Look at each: send the real ones to the Looking Glass creator for future automated decoding, and put away what is not a beacon.`
        : "Every encoded request in the days in memory is decoded or known. Nothing waits for the Looking Glass creator."));
    const redraw = () => mount(holder);
    for (const f of open) holder.append(family(f, redraw));
    if (away.length) {
      const det = el("details", "bu-away"); det.append(el("summary", null, `Sent or put away (${away.length})`));
      for (const f of away) det.append(family(f, redraw));
      holder.append(det);
    }
  }

  document.addEventListener("DOMContentLoaded", () => { const h = document.getElementById("beaconUnknown"); if (h) mount(h); });
  window.LGBeaconUnknown = { mount };
})();
