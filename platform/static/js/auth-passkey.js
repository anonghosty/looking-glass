/* SPDX-License-Identifier: AGPL-3.0-only
   SPDX-FileCopyrightText: the project's contributors */
/* The sign-in's passkey step (public installations): ask the device, put its answer in the form, send it. */
(() => {
  "use strict";
  const go = document.getElementById("pkGo"), form = document.getElementById("pkForm"), err = document.getElementById("pkErr");
  if (!go || !form) return;
  const toBuf = (s) => {
    const p = String(s || "").replace(/-/g, "+").replace(/_/g, "/");
    return Uint8Array.from(atob(p + "===".slice((p.length + 3) % 4)), (c) => c.charCodeAt(0)).buffer;
  };
  const fromBuf = (b) => { let s = ""; for (const x of new Uint8Array(b)) s += String.fromCharCode(x); return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""); };
  const show = (t) => { err.textContent = t; err.hidden = !t; };
  go.addEventListener("click", async () => {
    show(""); go.disabled = true;
    try {
      if (!(window.PublicKeyCredential && navigator.credentials && window.isSecureContext)) throw new Error("This browser or address cannot use passkeys.");
      const r = await fetch("/login/passkey-options", { method: "POST", credentials: "same-origin" });
      const o = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(o.error || "The sign-in step expired. Enter your name and password again.");
      const c = await navigator.credentials.get({ publicKey: { ...o, challenge: toBuf(o.challenge),
        allowCredentials: (o.allowCredentials || []).map((x) => ({ ...x, id: toBuf(x.id) })) } });
      const out = typeof c.toJSON === "function" ? c.toJSON() : { id: c.id, rawId: fromBuf(c.rawId), type: c.type,
        response: { clientDataJSON: fromBuf(c.response.clientDataJSON), authenticatorData: fromBuf(c.response.authenticatorData),
          signature: fromBuf(c.response.signature), userHandle: c.response.userHandle ? fromBuf(c.response.userHandle) : null },
        clientExtensionResults: c.getClientExtensionResults ? c.getClientExtensionResults() : {} };
      document.getElementById("pkCredential").value = JSON.stringify(out);
      form.submit();
    } catch (e) {
      show(e && e.name === "NotAllowedError" ? "The passkey request was cancelled or timed out. Try again." : "The passkey did not work. Try again, or use another of your passkeys.");
      go.disabled = false;
    }
  });
})();
