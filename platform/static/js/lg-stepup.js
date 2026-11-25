/* SPDX-License-Identifier: AGPL-3.0-only
   SPDX-FileCopyrightText: the Looking Glass contributors */
/* Looking Glass · the fresh check before a high-value action (stepup.py, the user 2026-11-24).

   loader.js's fetch sees the server's refusal {stepup: "passkey" | "code"} and calls LGStepUp.ask(info, {method, path}):
   a small dialog asks for a passkey (public installations) or an authenticator code (internal ones; a passkey too when
   the person has one), the server checks it, and loader.js sends the same request once more. A confirmation covers
   10 minutes; the most dangerous actions ask every time (the server then gives a one-time grant for that request).
   LGPasskey.get(options) and LGPasskey.create(options) are the browser's passkey calls with the server's JSON options,
   shared with the account page (account.js). No HTML strings and no inline styles: the DOM and the CSSOM only. */
(() => {
  "use strict";
  const csrf = () => document.querySelector('meta[name="csrf-token"]')?.content || "";
  const b64u = {
    toBuf(s) {
      const p = String(s || "").replace(/-/g, "+").replace(/_/g, "/");
      const bin = atob(p + "===".slice((p.length + 3) % 4));
      return Uint8Array.from(bin, (c) => c.charCodeAt(0)).buffer;
    },
    fromBuf(b) {
      let s = ""; for (const x of new Uint8Array(b)) s += String.fromCharCode(x);
      return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    },
  };
  const credJSON = (c) => {
    if (typeof c.toJSON === "function") return c.toJSON();
    const r = c.response, out = { id: c.id, rawId: b64u.fromBuf(c.rawId), type: c.type, response: {},
      clientExtensionResults: c.getClientExtensionResults ? c.getClientExtensionResults() : {} };
    for (const k of ["clientDataJSON", "attestationObject", "authenticatorData", "signature", "userHandle"]) {
      if (r[k]) out.response[k] = b64u.fromBuf(r[k]);
    }
    if (r.getTransports) out.response.transports = r.getTransports();
    if (c.authenticatorAttachment) out.authenticatorAttachment = c.authenticatorAttachment;
    return out;
  };
  window.LGPasskey = {
    supported: () => !!(window.PublicKeyCredential && navigator.credentials && window.isSecureContext),
    async get(o) {
      const pk = { ...o, challenge: b64u.toBuf(o.challenge),
        allowCredentials: (o.allowCredentials || []).map((c) => ({ ...c, id: b64u.toBuf(c.id) })) };
      return credJSON(await navigator.credentials.get({ publicKey: pk }));
    },
    async create(o) {
      const pk = { ...o, challenge: b64u.toBuf(o.challenge), user: { ...o.user, id: b64u.toBuf(o.user.id) },
        excludeCredentials: (o.excludeCredentials || []).map((c) => ({ ...c, id: b64u.toBuf(c.id) })) };
      return credJSON(await navigator.credentials.create({ publicKey: pk }));
    },
    /** plain words for the browser's own passkey errors */
    words(e) {
      const n = e && e.name;
      if (n === "NotAllowedError") return "The passkey request was cancelled or timed out.";
      if (n === "InvalidStateError") return "This device's passkey is already registered.";
      if (n === "SecurityError") return "Passkeys need this site's host name over HTTPS with a trusted certificate.";
      return window.LGLoader?.errorText ? window.LGLoader.errorText(e, true) : "The passkey did not work. Try again.";
    },
  };

  async function post(url, body) {
    const r = await fetch(url, { method: "POST", credentials: "same-origin", lgStepupDone: true,
      headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf() }, body: JSON.stringify(body || {}) });
    const j = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(j.error || `Looking Glass answered ${r.status}`);
    return j;
  }

  function el(tag, cls, text) {
    const e = document.createElement(tag); if (cls) e.className = cls; if (text != null) e.textContent = text; return e;
  }

  let open = null;               // one dialog at a time: a second refusal waits for the first answer
  window.LGStepUp = {
    ask(info, target) {
      if (open) return open;
      open = new Promise((resolve) => {
        const d = el("dialog", "lg-stepup");
        Object.assign(d.style, { maxWidth: "440px", width: "calc(100vw - 32px)", boxSizing: "border-box", padding: "20px 22px",
          borderRadius: "12px", border: "1px solid #3a3a42", background: "#16161a", color: "#ededef", font: "14px/1.5 system-ui, sans-serif" });
        const h = el("h2", "lg-stepup-title", "Confirm it is you");
        Object.assign(h.style, { margin: "0 0 8px", fontSize: "18px" });
        const p = el("p", "lg-stepup-text", `To ${info.action || "do this"}, confirm with ${info.stepup === "passkey" ? "your passkey" : "a code from your authenticator app"}.`
          + (info.every_time ? " This action asks every time." : " This covers the next 10 minutes."));
        const err = el("p", "lg-stepup-error"); err.setAttribute("role", "alert"); Object.assign(err.style, { color: "#ff8a8a", minHeight: "1.2em", margin: "8px 0" });
        const row = el("div", "lg-stepup-row"); Object.assign(row.style, { display: "flex", gap: "8px", flexWrap: "wrap", alignItems: "center", marginTop: "10px" });
        const cancel = el("button", "pill-btn", "Cancel"); cancel.type = "button";
        const done = (res) => { d.close(); d.remove(); open = null; resolve(res); };
        cancel.addEventListener("click", () => done({ ok: false }));
        d.addEventListener("cancel", (e) => { e.preventDefault(); done({ ok: false }); });
        const usePasskey = async (btn) => {
          err.textContent = ""; btn.disabled = true;
          try {
            if (!window.LGPasskey.supported()) throw new Error("This browser or address cannot use passkeys here.");
            const opts = await post("/api/stepup/passkey/options");
            const credential = await window.LGPasskey.get(opts);
            done(await post("/api/stepup/passkey", { credential, ...target }));
          } catch (e) { err.textContent = e && e.name ? window.LGPasskey.words(e) : window.LGLoader.errorText(e, true); btn.disabled = false; }
        };
        d.append(h, p);
        if (info.stepup === "code") {
          const lab = el("label", "lg-stepup-label", "Authenticator code");
          const inp = el("input", "lg-stepup-code"); inp.type = "text"; inp.inputMode = "numeric"; inp.autocomplete = "one-time-code";
          inp.maxLength = 8; inp.setAttribute("aria-label", "Authenticator code");
          Object.assign(inp.style, { display: "block", width: "100%", boxSizing: "border-box", marginTop: "4px", padding: "8px 10px",
            borderRadius: "8px", border: "1px solid #3a3a42", background: "#0f0f12", color: "#ededef", fontSize: "18px", letterSpacing: "3px" });
          lab.append(inp);
          const ok = el("button", "pill-btn primary", "Confirm"); ok.type = "button";
          const send = async () => {
            err.textContent = ""; ok.disabled = true;
            try { done(await post("/api/stepup/code", { code: inp.value, ...target })); }
            catch (e) { err.textContent = window.LGLoader.errorText(e, true); ok.disabled = false; inp.select(); }
          };
          ok.addEventListener("click", send);
          inp.addEventListener("keydown", (e) => { if (e.key === "Enter") { e.preventDefault(); send(); } });
          row.append(ok, cancel);
          if (info.also_passkey) {
            const pk = el("button", "pill-btn", "Use a passkey instead"); pk.type = "button";
            pk.addEventListener("click", () => usePasskey(pk)); row.append(pk);
          }
          d.append(lab, err, row);
          document.body.append(d); d.showModal(); inp.focus();
        } else {
          const pk = el("button", "pill-btn primary", "Use your passkey"); pk.type = "button";
          pk.addEventListener("click", () => usePasskey(pk));
          row.append(pk, cancel);
          d.append(err, row);
          document.body.append(d); d.showModal(); pk.focus();
        }
      });
      return open;
    },
  };
})();
