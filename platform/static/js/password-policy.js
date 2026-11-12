/* Looking Glass · Settings → Password policy (password_policy.py): passwords expire after N days, and a button that makes
   every account choose a new password at its next sign-in. Both ask for the administrator's own password. */
(() => {
  "use strict";
  const body = document.getElementById("ppBody");
  if (!body) return;
  const el = (t, c, x) => { const e = document.createElement(t); if (c) e.className = c; if (x != null) e.textContent = x; return e; };
  const csrf = () => document.querySelector('meta[name="csrf-token"]')?.content || "";
  async function api(url, payload) {
    const r = await fetch(url, payload === undefined ? { cache: "no-store" } : { method: "POST", credentials: "same-origin",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf() }, body: JSON.stringify(payload) });
    const d = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
    return d;
  }

  // the administrator's own password, asked in a small window; resolves to the password or null
  function askPassword(title, text) {
    return new Promise((resolve) => {
      const back = el("div", "st-modal-back"), m = el("section", "st-modal wk-modal");
      m.setAttribute("role", "dialog"); m.setAttribute("aria-modal", "true");
      m.append(el("h2", null, title), el("p", "st-hint", text));
      const f = el("form", "wk-pw"); const inp = el("input", "wk-in"); inp.type = "password"; inp.autocomplete = "current-password"; inp.required = true;
      inp.placeholder = "Your password";
      const go = el("button", "lg-btn primary", "Confirm"); go.type = "submit";
      const no = el("button", "pill-btn", "Cancel"); no.type = "button";
      f.append(inp, go, no); m.append(f);
      const close = (v) => { back.remove(); m.remove(); resolve(v); };
      no.addEventListener("click", () => close(null)); back.addEventListener("click", () => close(null));
      f.addEventListener("submit", (ev) => { ev.preventDefault(); close(inp.value); });
      document.body.append(back, m); inp.focus();
    });
  }

  let P = null;
  const msg = el("p", "wk-msg muted"); msg.setAttribute("role", "status");
  const say = (t, bad) => { msg.textContent = t || ""; msg.classList.toggle("bad", !!bad); };

  function draw() {
    body.replaceChildren();
    const state = el("p", "pp-state");
    state.textContent = P.enabled
      ? `On since ${P.since}: passwords last ${P.days} days.`
      : "Off: passwords do not expire.";
    if (P.forced) state.textContent += ` Every account was last asked to choose a new password on ${P.forced}${P.by ? ` (by ${P.by})` : ""}.`;
    const due = el("p", "st-hint", `${P.due} of ${P.accounts} active account${P.accounts === 1 ? "" : "s"} must choose a new password at their next sign-in.`);
    const row = el("div", "pp-row");
    const onL = el("label", "check-row wk-check"); const on = el("input"); on.type = "checkbox"; on.checked = P.enabled;
    onL.append(on, el("span", null, "Make passwords expire"));
    const daysL = el("label", "st-field pp-days"); daysL.append(el("span", null, `Days a password lasts (${P.min}-${P.max.toLocaleString("en-US")})`));
    const days = el("input", "wk-in mono"); days.type = "number"; days.min = P.min; days.max = P.max; days.step = 1; days.value = P.days;
    daysL.append(days);
    const save = el("button", "lg-btn primary", "Save the policy"); save.type = "button";
    row.append(onL, daysL, save);
    save.addEventListener("click", async () => {
      const turningOn = on.checked && !P.enabled;
      if (turningOn && !confirm(`Switch the password policy on?\n\nEvery account will have to choose a new password at its next sign-in, then every ${days.value} days.`)) return;
      const pw = await askPassword("Your password", "Confirm the password policy change with the password you sign in with.");
      if (pw == null) return;
      save.disabled = true;
      try { P = await api("/api/password-policy", { enabled: on.checked, days: Number(days.value), password: pw }); draw(); say(turningOn ? "Saved: every account chooses a new password at its next sign-in." : "Saved."); }
      catch (e) { say(e.message, true); save.disabled = false; }
    });
    const force = el("button", "lg-btn pp-force", "Require every account to change its password at next sign-in"); force.type = "button";
    force.addEventListener("click", async () => {
      if (!confirm("Make EVERY account (yours too) choose a new password at its next sign-in?\n\nUse it for example after a suspected leak. People keep working until they next sign in.")) return;
      const pw = await askPassword("Your password", "Confirm with the password you sign in with.");
      if (pw == null) return;
      force.disabled = true;
      try { P = await api("/api/password-policy/force", { password: pw }); draw(); say("Done: every account chooses a new password at its next sign-in."); }
      catch (e) { say(e.message, true); force.disabled = false; }
    });
    body.append(state, due, row, el("div", "wk-acts"), msg);
    body.lastChild.previousSibling.append(force);
  }

  api("/api/password-policy").then((d) => { P = d; draw(); }).catch((e) => body.replaceChildren(el("p", "fd-empty", e.message)));
})();
