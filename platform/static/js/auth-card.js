/* Looking Glass · sign-in and account pages
   * buttons open the matching form in place (sign in, create an account); Back returns to the choice
   * the eye shows / hides a password
   * live password strength: the same rules the server enforces (12+ characters, upper and lower case, a number,
     a symbol); the form cannot be sent until they are met and the two passwords match */
(() => {
  "use strict";
  // ---------------- views
  const card = document.getElementById("authCard");
  if (card) {
    const views = [...card.querySelectorAll(".auth-view")];
    const show = (v, focus) => {
      if (!views.some((x) => x.dataset.v === v)) v = "choice";
      card.dataset.view = v;
      for (const x of views) {
        const on = x.dataset.v === v;
        x.hidden = !on;
        if (on) { x.classList.remove("auth-in"); void x.offsetWidth; x.classList.add("auth-in"); }
      }
      if (focus) { const f = card.querySelector(`.auth-view[data-v="${v}"] input:not([type=hidden]), .auth-view[data-v="${v}"] button`); if (f) f.focus(); }
      try { history.replaceState(null, "", v === "choice" ? location.pathname : `/login?form=${v}`); } catch { /* */ }
    };
    card.addEventListener("click", (e) => {
      const b = e.target.closest("[data-show]");
      if (!b) return;
      e.preventDefault();
      for (const a of card.querySelectorAll(".auth-alert")) a.remove();   // alerts belong to the view they came with
      show(b.dataset.show, true);
    });
    show(card.dataset.view || "choice", card.dataset.view !== "choice");
  }

  // ---------------- show / hide password
  document.addEventListener("click", (e) => {
    const b = e.target.closest("[data-eye]");
    if (!b) return;
    const inp = document.getElementById(b.dataset.eye);
    if (!inp) return;
    const showing = inp.type === "text";
    inp.type = showing ? "password" : "text";
    b.setAttribute("aria-pressed", String(!showing));
    b.setAttribute("aria-label", showing ? "Show password" : "Hide password");
    b.classList.toggle("on", !showing);
    inp.focus({ preventScroll: true });
    try { inp.setSelectionRange(inp.value.length, inp.value.length); } catch { /* */ }
  });

  // ---------------- strength meter and matching
  const RULES = {
    len: (p) => p.length >= 12,
    case: (p) => /[a-z]/.test(p) && /[A-Z]/.test(p),
    num: (p) => /\d/.test(p),
    sym: (p) => /[^A-Za-z0-9]/.test(p),
  };
  const COMMON = ["password", "passw0rd", "welcome", "admin", "qwerty", "letmein", "123456", "shadowserver", "lookingglass", "changeme"];
  function check(inp) {
    const p = inp.value, meter = document.getElementById(inp.dataset.strength);
    const ok = Object.fromEntries(Object.entries(RULES).map(([k, f]) => [k, f(p)]));
    let score = Object.values(ok).filter(Boolean).length;
    const weak = /(.)\1\1\1/.test(p) || COMMON.some((w) => p.toLowerCase().includes(w));
    if (weak) score = Math.min(score, 1);
    if (score === 4 && p.length >= 16) score = 5;
    if (meter) {
      meter.dataset.score = p ? String(score) : "0";
      for (const li of meter.querySelectorAll("[data-r]")) li.classList.toggle("ok", ok[li.dataset.r]);
    }
    const all = Object.values(ok).every(Boolean) && !weak;
    inp.setCustomValidity(!p || all ? "" : weak ? "Avoid common words and repeated characters." : "Use 12+ characters with upper and lower case letters, a number and a symbol.");
    for (const m of document.querySelectorAll(`[data-match="${inp.id}"]`)) match(m);
  }
  function match(inp) {
    const other = document.getElementById(inp.dataset.match), ok = inp.value && other && inp.value === other.value;
    inp.setCustomValidity(!inp.value || ok ? "" : "The two passwords differ.");
    const mark = document.querySelector(`[data-ok-for="${inp.id}"]`);
    if (mark) mark.classList.toggle("on", !!ok);
  }
  for (const inp of document.querySelectorAll("[data-strength]")) { inp.addEventListener("input", () => check(inp)); check(inp); }

  // e-mail and names: the server's own rules (auth.py EMAIL_RE / profile_problem), checked while typing
  const EMAIL = /^(?=.{6,254}$)(?=[^@]{1,64}@)[A-Za-z0-9_%+\-]+(?:\.[A-Za-z0-9_%+\-]+)*@(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+(?:[A-Za-z]{2,24}|xn--[A-Za-z0-9\-]{2,59})$/;
  function note(inp, msg) {
    let n = inp.parentElement.querySelector(".fl-note");
    if (!n) { n = document.createElement("div"); n.className = "fl-note"; n.setAttribute("aria-live", "polite"); inp.parentElement.appendChild(n); }
    n.textContent = msg; inp.setCustomValidity(msg); inp.toggleAttribute("aria-invalid", !!msg);
  }
  function checkEmail(inp, final) {
    const v = inp.value.trim();
    let msg = "";
    if (v && !v.includes("@")) msg = final ? "An email address needs an @, like name@organisation.org." : "";
    else if (v && /\s/.test(v)) msg = "An email address has no spaces.";
    else if (v && /\.\.|^\.|\.@|@\./.test(v)) msg = "Dots cannot be first, last, next to the @ or twice in a row.";
    else if (v && (final || /@.+\.[A-Za-z]{2,}$/.test(v)) && !EMAIL.test(v)) msg = "Enter a valid email address, like name@organisation.org.";
    note(inp, msg);
  }
  for (const inp of document.querySelectorAll("[data-email]")) {
    inp.addEventListener("input", () => checkEmail(inp, false));
    inp.addEventListener("blur", () => checkEmail(inp, true));
    if (inp.value) checkEmail(inp, true);
  }
  for (const inp of document.querySelectorAll("[data-person]")) {
    const chk = (final) => {
      const v = inp.value.trim(), letters = (v.match(/\p{L}/gu) || []).length;
      note(inp, v && (final || v.length >= 2) && letters < 2 ? `${inp.dataset.person}: use letters (2-100 characters).` : "");
    };
    inp.addEventListener("input", () => chk(false)); inp.addEventListener("blur", () => chk(true));
  }
  // before sending: check every field once more, so the first problem is shown at once
  for (const f of document.querySelectorAll('form[action$="/register"]')) {
    f.addEventListener("submit", (e) => {
      for (const inp of f.querySelectorAll("[data-email]")) checkEmail(inp, true);
      for (const inp of f.querySelectorAll("[data-person]")) inp.dispatchEvent(new Event("blur"));
      if (!f.checkValidity()) { e.preventDefault(); f.reportValidity(); }
    });
  }
  for (const inp of document.querySelectorAll("[data-match]")) inp.addEventListener("input", () => match(inp));

  // TV remotes and keyboards without a mouse: arrows move through the sign-in card (buttons, fields, links), OK presses.
  // With nothing focused yet, the first arrow goes to the card's main button. Up from the first item reaches the globe.
  const focusables = () => [...document.querySelectorAll(".auth-card .auth-view:not([hidden]) :is(a[href], button, input:not([type=hidden]), select, textarea), .auth-card > :is(a[href], button)")]
    .filter((x) => !x.disabled && x.offsetParent !== null);
  document.addEventListener("keydown", (e) => {
    if (e.defaultPrevented || e.altKey || e.ctrlKey || e.metaKey) return;
    const k = e.key, act = document.activeElement, list = focusables();
    if (!list.length || !["ArrowUp", "ArrowDown", "ArrowLeft", "ArrowRight"].includes(k)) return;
    const inCard = act && list.includes(act);
    if (!inCard) {
      if (act && act !== document.body && act.id !== "authBg") return;      // something else has focus: leave it
      if (act && act.id === "authBg") return;                              // the globe handles its own arrows
      e.preventDefault(); (list.find((x) => x.classList.contains("auth-btn")) || list[0]).focus(); return;
    }
    const typing = act.tagName === "TEXTAREA" || (act.tagName === "INPUT" && (k === "ArrowLeft" || k === "ArrowRight"));
    if (typing || act.tagName === "SELECT") return;                        // left/right move the cursor in a field
    const i = list.indexOf(act), down = k === "ArrowDown" || k === "ArrowRight";
    if (!down && i === 0) { const g = document.getElementById("authBg"); if (g) { e.preventDefault(); g.focus(); } return; }
    const next = list[Math.max(0, Math.min(list.length - 1, i + (down ? 1 : -1)))];
    if (next && next !== act) { e.preventDefault(); next.focus(); }
  });
})();
