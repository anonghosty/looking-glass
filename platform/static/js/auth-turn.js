/* The sign-in card turns over (2026-11-19), in the page's usual look. Served before sign-in: it names no product
   (anti-fingerprinting, neutral.py).
   * LGTurn.turn(card, swap): the card turns away, swap() changes its side at the half turn, the new side turns in
     (auth-card.js: Sign in, Create an account, Back);
   * a step that sends the form (details -> authenticator -> recovery codes, password -> code, a new password): the next
     page's card turns in when the step changed, not when the same step comes back with an error;
   * the last step's button fades away as it is sent (then /welcome zooms into the globe, welcome.js).
   A real 3D turn (the page gives the depth, .auth-wrap's perspective), never a fade. Without motion (the person's
   setting) every change is at once. Nothing is stored but the step's name, in this tab only (sessionStorage). */
(() => {
  "use strict";
  const still = matchMedia("(prefers-reduced-motion: reduce)").matches;
  const OUT_MS = 230, IN_MS = 380;
  const sideOf = (card) => `${location.pathname}|${card.dataset.view || ""}|${(card.querySelector("h1") || {}).textContent || ""}`;

  function turn(card, swap) {
    if (still || !card) { swap(); return; }
    card.classList.add("lg-settled");                 // the entrance never plays again once a turn has begun
    card.classList.remove("lg-turn-in"); card.classList.add("lg-turn-out");
    setTimeout(() => {
      card.classList.remove("lg-turn-out"); swap();
      // the new side arrives whole: its own slide-and-fade (auth-in) would read as a fade inside the turn
      for (const v of card.querySelectorAll(".auth-in")) v.classList.remove("auth-in");
      void card.offsetWidth; card.classList.add("lg-turn-in");
      setTimeout(() => card.classList.remove("lg-turn-in"), IN_MS + 40);
    }, OUT_MS);
  }
  window.LGTurn = { turn };

  const card = document.querySelector(".auth-card");
  if (!card) return;
  // arriving: the card turns in when the step is a new one
  let from = null;
  try { from = sessionStorage.getItem("lg.turn"); sessionStorage.removeItem("lg.turn"); } catch { /* private mode */ }
  if (from && from !== sideOf(card) && !still) {         // a new step: it turns in instead of the usual entrance
    card.classList.add("lg-settled", "lg-turn-in");
    setTimeout(() => card.classList.remove("lg-turn-in"), IN_MS + 40);
  } else {
    // the entrance (fade and rise) once; afterwards the card stays put
    card.addEventListener("animationend", (e) => { if (e.target === card) card.classList.add("lg-settled"); }, { once: true });
    setTimeout(() => card.classList.add("lg-settled"), 1200);
  }
  // sending a step: remember which side was sent; the button of a step that can finish signing in fades away
  document.addEventListener("submit", (e) => {
    const f = e.target;
    if (e.defaultPrevented || !card.contains(f) && !f.classList.contains("auth-card")) return;
    try { sessionStorage.setItem("lg.turn", sideOf(card)); } catch { /* */ }
    const last = f.matches('[data-v="mfa"], [data-v="expired"]') || (f.matches('[data-v="signin"]') && !f.querySelector('[name="code"]'));
    if (last && !still) {
      const b = e.submitter || f.querySelector('button[type="submit"], .auth-btn');
      if (b) b.classList.add("lg-going");
      // then the card and the name beside it leave together, so only the globe is left when /welcome takes over
      // (it starts from the globe alone); a wrong code brings the page, and the card, back as before
      setTimeout(() => document.body.classList.add("lg-leaving"), 260);
    }
  });
})();
