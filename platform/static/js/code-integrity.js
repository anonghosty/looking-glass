/* SPDX-License-Identifier: AGPL-3.0-only
   SPDX-FileCopyrightText: the Looking Glass contributors */
/* Looking Glass · Settings → Code check (code_integrity.py, r91): the code files the daily check found changed or
   added, against the release's fingerprints. Per file: "This is ours, keep it" or "Not ours, move to quarantine", each
   with the administrator's own password; both are in the audit log. Then the command that checks the whole
   installation against the signed release. */
(() => {
  "use strict";
  const body = document.getElementById("ciBody");
  if (!body) return;
  const el = (t, c, x) => { const e = document.createElement(t); if (c) e.className = c; if (x != null) e.textContent = x; return e; };
  const csrf = () => document.querySelector('meta[name="csrf-token"]')?.content || "";
  async function api(url, payload) {
    const r = await fetch(url, payload === undefined ? { cache: "no-store" } : { method: "POST", credentials: "same-origin",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf() }, body: JSON.stringify(payload) });
    const d = await r.json().catch(() => ({}));
    if (!r.ok) { const e = new Error(d.error || `HTTP ${r.status}`); e.view = d.findings ? d : null; throw e; }
    return d;
  }

  // what the action does, then the administrator's own password, in a small window; resolves to the password or null
  function askPassword(title, text) {
    return new Promise((resolve) => {
      const back = el("div", "st-modal-back"), m = el("section", "st-modal wk-modal");
      m.setAttribute("role", "dialog"); m.setAttribute("aria-modal", "true"); m.setAttribute("aria-label", title);
      m.append(el("h2", null, title), el("p", "st-hint", text));
      const f = el("form", "wk-pw"); const inp = el("input", "wk-in"); inp.type = "password"; inp.autocomplete = "current-password"; inp.required = true;
      inp.placeholder = "Your password"; inp.setAttribute("aria-label", "Your password");
      const go = el("button", "lg-btn primary", "Confirm"); go.type = "submit";
      const no = el("button", "pill-btn", "Cancel"); no.type = "button";
      f.append(inp, go, no); m.append(f);
      const close = (v) => { back.remove(); m.remove(); document.removeEventListener("keydown", esc); resolve(v); };
      const esc = (ev) => { if (ev.key === "Escape") close(null); };
      no.addEventListener("click", () => close(null)); back.addEventListener("click", () => close(null));
      document.addEventListener("keydown", esc);
      f.addEventListener("submit", (ev) => { ev.preventDefault(); close(inp.value); });
      document.body.append(back, m); inp.focus();
    });
  }

  let V = null;
  const msg = el("p", "wk-msg muted"); msg.setAttribute("role", "status");
  const say = (t, bad) => { msg.textContent = t || ""; msg.classList.toggle("bad", !!bad); };

  // a redraw replaces every button: the one used gets the focus back (same file, same action), else the status line that
  // says what happened (the keepFocus pattern of app.js; audit 2026-11-27, 9-8: the focus fell to the page's top)
  function keepFocus(build, from) {
    const k = from?.dataset?.fk, v = from?.dataset?.fv;
    build();
    if (k == null) return;
    const back = [...body.querySelectorAll("[data-fk]")].find((n) => n.dataset.fk === k && n.dataset.fv === v && !n.disabled);
    if (back) { back.focus({ preventScroll: true }); return; }
    msg.tabIndex = -1; msg.focus({ preventScroll: true });
  }

  async function act(f, kind, btn) {
    const keep = kind === "approve";
    const title = keep ? "Keep this file as yours" : "Not ours: move it to quarantine";
    const text = keep
      ? `${f.key} will be accepted with this exact content (SHA-256 ${f.sha256}). If it changes later, the code check finds it again. Confirm with the password you sign in with.`
      : `Your decision that ${f.key} is not yours is recorded. ${V.not_service} You then get the command that moves it to a quarantine folder (never deleted).`
        + (f.kind === "changed" ? " It is a file the release ships: until its released copy is put back (see below), Looking Glass may not start again." : "")
        + " Confirm with the password you sign in with.";
    const pw = await askPassword(title, text);
    if (pw == null) return;
    btn.disabled = true;
    try {
      const d = await api(keep ? "/api/admin/code-check/approve" : "/api/admin/code-check/quarantine", { key: f.key, sha256: f.sha256, password: pw });
      say(keep ? `Kept: ${f.key} is accepted as yours (recorded in the audit log).`
        : `Recorded in the audit log. Now run the command shown under ${f.key} on the server; the next check sees the file gone.`);
      V = d; keepFocus(draw, btn);
    } catch (e) {
      say(window.LGLoader.errorText(e, true), true);
      btn.disabled = false;
      if (e.view) { V = e.view; keepFocus(draw, btn); }
    }
  }

  function draw() {
    body.replaceChildren();
    const state = el("p", "pp-state");
    if (!V.checked) state.textContent = `Not checked: ${V.why || "nothing to check"}.`;
    else if (!V.findings.length) state.textContent = `Last checked ${V.at}: every code file is as the release shipped it` + (V.approved ? `, apart from ${V.approved} file${V.approved === 1 ? "" : "s"} kept as yours.` : ".");
    else state.textContent = `Last checked ${V.at}: ${V.findings.length} code file${V.findings.length === 1 ? " is" : "s are"} not as the release shipped ${V.findings.length === 1 ? "it" : "them"}.`;
    body.append(state);
    if (V.problem) body.append(el("p", "st-hint bad", `The check could not run: ${V.problem}.`));
    const parts = Object.entries(V.parts || {}).map(([k, p]) => `${k === "platform" ? "the platform" : "the database pipeline"}: ${p.checked ? `${p.files} code files checked` : p.why}`);
    if (parts.length) body.append(el("p", "st-hint", parts.join("; ") + `. Checked every ${V.every_hours} hours.`));
    if (V.findings.length) {
      const wrap = el("div", "table-wrap"); const t = el("table", "hosts ci-table");
      const hr = el("tr"); for (const h of ["File", "What was found", "SHA-256 now", "Found", "Action"]) hr.append(el("th", null, h));
      t.append(el("thead")); t.tHead.append(hr);
      const tb = el("tbody");
      for (const f of V.findings) {
        const tr = el("tr");
        tr.append(el("td", "mono", f.key));
        const what = el("td", null, f.kind_text + (f.former ? " (an earlier release shipped a file of this name)" : ""));
        if (f.expected) what.append(el("small", "muted mono ci-sha", ` The release lists ${f.expected}.`));
        tr.append(what, el("td", "mono ci-sha", f.sha256), el("td", null, f.first_seen));
        const acts = el("td", "ci-acts");
        const keep = el("button", "pill-btn", "This is ours, keep it"); keep.type = "button"; keep.dataset.fk = f.key; keep.dataset.fv = "approve";
        keep.addEventListener("click", () => act(f, "approve", keep));
        if (f.decided) {
          // decided "not ours": the service cannot move its own code; the administrator runs this on the server
          const box = el("div", "ci-cmd");
          box.append(el("small", "muted", `Marked not ours by ${f.decided.by} (${f.decided.at}). ${V.not_service} Run on the server:`),
            el("pre", "st-env mono", f.decided.command));
          acts.append(box, keep);
        } else {
          const out = el("button", "lg-btn", "Not ours, move to quarantine"); out.type = "button"; out.dataset.fk = f.key; out.dataset.fv = "quarantine";
          out.addEventListener("click", () => act(f, "quarantine", out));
          acts.append(keep, out);
        }
        tr.append(acts); tb.append(tr);
      }
      t.append(tb); wrap.append(t); body.append(wrap);
    }
    body.append(el("h3", null, "Checking against the signed release"), el("p", "st-hint", V.guide));
    const cmd = el("pre", "st-env mono", "platform/deploy/verify_install.py --fetch\nplatform/deploy/verify_install.py --fetch --folder database");
    body.append(cmd, msg);
  }

  window.LGLoader.wait(api("/api/admin/code-check").then((d) => { V = d; draw(); })
    .catch((e) => body.replaceChildren(el("p", "fd-empty", window.LGLoader.errorText(e)))), "Reading the last code check");
})();
