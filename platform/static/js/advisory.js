/* Looking Glass · the advisory page (/advisory/<id>, advisory.py): the advisor writes the advisory on a decided finding.
   Filled in on its own (only what holds something): the CVEs, issues and categories, the reports with their impact
   flags, the Technical Details line. Written by the advisor: the subject, the Description (on the impact), the
   Recommended Actions and the recipients. Then: preview the report, download it (ZIP: PDF + CSV + JSON), export the
   JSON, mark it as sent. */
(() => {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const el = (t, c, x) => { const e = document.createElement(t); if (c) e.className = c; if (x != null) e.textContent = x; return e; };
  const csrf = () => document.querySelector('meta[name="csrf-token"]')?.content || "";
  const fid = document.body.dataset.fid, main = $("avMain");
  const LEVEL = { critical: "Critical", high: "High", medium: "Medium", low: "Low" };
  let D = null;

  const card = (title, sub) => {
    const s = el("section", "av-card");
    s.append(el("h2", null, title));
    if (sub) s.append(el("p", "av-sub", sub));
    return s;
  };
  const chips = (vals, cls) => { const w = el("div", "av-chips"); vals.forEach((v) => w.append(el("span", `av-chip ${cls || ""}`, v))); return w; };

  async function post(url, body) {
    const r = await fetch(url, { method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf() },
      body: JSON.stringify(body) });
    const d = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
    return d;
  }

  function draw() {
    const a = D.advisory, edit = D.can_edit && a.status !== "locked";
    main.textContent = "";
    // the head: the organisation's logo section and title
    const hero = el("section", "av-hero");
    const logo = el("div", "av-logo");
    if (D.has_logo) { const i = el("img"); i.src = `/organisation/logo?t=${Date.now()}`; i.alt = `${a.organisation} logo`; logo.append(i); }
    else logo.append(el("span", null, (a.organisation || "?").slice(0, 1).toUpperCase()));
    const ht = el("div", "av-head");
    ht.append(el("div", "fd-eyebrow", `Security advisory · ${a.ref || "not saved yet"} · ${a.status_label}`), el("h1", null, a.title));
    const meta = el("div", "av-meta");
    meta.append(el("span", null, `Finding ${a.finding}: ${a.finding_title}`));
    if (a.decision) meta.append(el("span", null, `Management: ${a.decision}`));
    if (a.ref) meta.append(el("span", null, `Last saved ${a.updated} by ${a.by}`));
    ht.append(meta);
    if (!D.org_set) ht.append(el("p", "av-warn", "The organisation's name is not set yet: an admin sets it (and the logo) in Settings → Organisation."));
    hero.append(logo, ht);
    main.append(hero);

    // what is filled in on its own
    const af = a.affected, any = af.cves.length || af.issues.length || af.categories.length;
    if (any || a.reports.length) {
      const c = card("Affected", "Filled in from the finding's combinations (and the analyst's views when management added them). Only what holds something is listed.");
      const g = el("div", "av-aff");
      [["CVEs", af.cves, "cve"], ["Issues", af.issues, "iss"], ["Categories", af.categories, "cat"]].forEach(([k, v, cls]) => {
        if (!v.length) return;
        const row = el("div", "av-row"); row.append(el("b", null, k), chips(v, cls)); g.append(row);
      });
      if (a.reports.length) {
        const row = el("div", "av-row"); row.append(el("b", null, "Reports"));
        const list = el("div", "av-reps");
        a.reports.forEach((r) => {
          const it = el("div", "av-rep");
          it.append(el("span", "av-rep-t", r.title), el("small", null, [r.section, r.group].filter(Boolean).join(" · ")));
          const fl = el("div", "av-chips");
          r.flags.forEach((f) => { const z = a.impact.find((x) => x.flag === f); if (z) fl.append(el("span", `av-flag ${z.level}`, z.label)); });
          it.append(fl); list.append(it);
        });
        row.append(list); g.append(row);
      }
      c.append(g); main.append(c);
    }

    // the advisor's text
    const w = card("The advisory", "Your words: the subject, the Description on the impact, and the Recommended Actions.");
    const subj = el("input"); subj.type = "text"; subj.maxLength = D.limits.subject; subj.value = a.subject; subj.className = "av-in";
    const desc = el("textarea", "av-ta"); desc.rows = 7; desc.maxLength = D.limits.text; desc.value = a.description;
    desc.placeholder = "Describe the impact: what is exposed or happening, who is affected, and why it matters.";
    const act = el("textarea", "av-ta"); act.rows = 7; act.maxLength = D.limits.text; act.value = a.recommended_actions;
    act.placeholder = "What the recipients should do: patch, close the service, restrict access, clean the device, reset credentials…";
    const rec = el("input"); rec.type = "text"; rec.className = "av-in"; rec.value = a.recipients.join(", ");
    rec.placeholder = "To whom it goes: organisations, teams or people, separated by commas";
    const lab = (t, x, hint) => { const l = el("label", "av-field"); l.append(el("span", null, t), x); if (hint) l.append(el("small", "muted", hint)); return l; };
    w.append(lab("Subject", subj), lab("Description", desc, a.kinds_line ? `The advisory adds below it: "${a.kinds_line}"` : ""));
    if (a.impact.length) {
      const im = el("div", "av-impact");
      im.append(el("b", null, "Impact flags (shown in the advisory on their own, from the reports)"));
      a.impact.forEach((f) => {
        const r = el("div", "av-imp");
        r.append(el("span", `av-flag ${f.level}`, LEVEL[f.level] || f.level), el("b", null, f.label), el("span", null, f.text),
                 el("small", "muted", `Reports: ${f.reports.join(", ")}`));
        im.append(r);
      });
      w.append(im);
    }
    w.append(lab("Recommended Actions", act, D.has_report ? 'The advisory adds after them: "See below for further insight into the activity." and the analyst\'s report.' : ""),
             lab("Recipients", rec));
    [subj, desc, act, rec].forEach((x) => { x.disabled = !edit; });
    const bar = el("div", "av-acts"), msg = el("span", "muted av-msg"); msg.setAttribute("role", "status");
    const say = (t, bad) => { msg.textContent = t; msg.style.color = bad ? "#ff8f8f" : ""; };
    const body = () => ({ subject: subj.value, description: desc.value, actions: act.value, recipients: rec.value });
    if (edit) {
      const save = el("button", "intro-cta", "Save the advisory"); save.type = "button";
      save.addEventListener("click", async () => {
        save.disabled = true; say("Saving…");
        try { const d = await post(`/api/advisory/${fid}`, body()); D.advisory = d.advisory; D.saved = true; draw(); say2(`Saved as ${d.advisory.ref}.`); }
        catch (e) { say(e.message, true); save.disabled = false; }
      });
      bar.append(save);
    }
    const prev = el("a", "pill-btn", "Preview the report"); prev.href = `/advisory/${fid}/report?as=pdf`; prev.target = "_blank"; prev.rel = "noopener";
    prev.title = "The PDF as it stands (save first to include your latest text)";
    bar.append(prev);
    if (D.saved) {
      const dl = el("a", "pill-btn", D.has_report ? "Download the report (ZIP)" : "Download the PDF"); dl.href = `/advisory/${fid}/report`;
      dl.title = D.has_report ? "The advisory's PDF with the analyst's report, the CSV files and the advisory as JSON" : "The advisory's PDF";
      const js = el("a", "pill-btn", "Export JSON"); js.href = `/api/advisory/${fid}/export`; js.title = "The advisory as a JSON file (no address in it), for other tools";
      bar.append(dl, js);
      if (edit) {
        const send = el("button", "pill-btn av-send", a.status === "sent" ? "Mark as sent again" : "Mark as sent"); send.type = "button";
        send.title = "Record that it went to the recipients above: the finding moves to Advisory sent";
        send.addEventListener("click", async () => {
          if (!rec.value.trim()) { say("Name at least one recipient first.", true); return; }
          send.disabled = true; say("Saving and marking as sent…");
          try {
            await post(`/api/advisory/${fid}`, body());
            const d = await post(`/api/advisory/${fid}/send`, { recipients: rec.value });
            D.advisory = d.advisory; draw(); say2(`Marked as sent to ${d.advisory.sends.at(-1).to.join(", ")}.`);
          } catch (e) { say(e.message, true); send.disabled = false; }
        });
        bar.append(send);
      }
    }
    bar.append(msg);
    w.append(bar);
    main.append(w);

    // sent so far, and the trail
    if (a.sends.length || a.history.length) {
      const t = card("Sent and changed");
      const ul = el("ul", "av-trail");
      a.sends.forEach((s) => ul.append(el("li", null, `${s.at}: sent to ${s.to.join(", ")} by ${s.by}`)));
      a.history.forEach((h) => ul.append(el("li", "muted", `${h.at}: ${h.what} by ${h.by}`)));
      t.append(ul); main.append(t);
    }
    if (a.reports.length) {
      const r = card("Shadowserver Report References", "At the end of the report: every report this advisory names.");
      const ul = el("ul", "av-refs");
      a.reports.forEach((x) => { const li = el("li"); const l = el("a", null, x.title); l.href = x.url; l.target = "_blank"; l.rel = "noopener noreferrer"; li.append(l); if (x.note) li.append(el("small", "muted", ` (${x.note})`)); ul.append(li); });
      r.append(ul); main.append(r);
    }
    const back = el("a", "pill-btn av-back", "Back to the advisory portal"); back.href = "/advisory";
    main.append(back);
  }
  let pending = "";
  const say2 = (t) => { const m = main.querySelector(".av-msg"); if (m) m.textContent = t; else pending = t; };

  async function load() {
    const r = await fetch(`/api/advisory/${encodeURIComponent(fid)}`, { cache: "no-store" });
    const d = await r.json().catch(() => ({}));
    $("avLoading")?.remove();
    if (!r.ok) { main.append(el("p", "fd-empty", d.error || `Could not open the advisory (HTTP ${r.status})`)); return; }
    D = d; draw(); if (pending) say2(pending);
  }
  load();
})();
