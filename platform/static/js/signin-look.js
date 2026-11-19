/* Looking Glass · Settings → Organisation → Sign-in page logo (neutral.py; the user's choice 2026-11-19): the
   organisation's logo (default), the Looking Glass logo, or none. Administrators only (checked on the server); each
   change is audited. A dropdown: one stop for the keyboard. Text from the server is set as text. */
(() => {
  "use strict";
  const box = document.getElementById("signinLook");
  const sel = document.getElementById("signinLogo");
  if (!box || !sel) return;
  const msg = document.getElementById("signinMsg"), note = document.getElementById("signinOrgNote");
  const csrf = () => document.querySelector('meta[name="csrf-token"]')?.content || "";
  let current = "";
  // lg-select.js redraws on "change"; the handler below ignores a change to the value already saved
  const setValue = (v) => { sel.value = v; sel.dispatchEvent(new Event("change")); };
  fetch("/api/settings/signin-look", { cache: "no-store" }).then((r) => (r.ok ? r.json() : Promise.reject(r)))
    .then((d) => {
      current = d.logo; setValue(d.logo);
      note.textContent = d.has_org_logo ? "" : "No organisation logo is set yet: with the first choice the pages show no logo.";
    })
    .catch(() => { box.hidden = true; });
  sel.addEventListener("change", async () => {
    const v = sel.value;
    if (!v || v === current) return;
    msg.textContent = "Saving…";
    try {
      const res = await fetch("/api/settings/signin-look", { method: "POST", headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf() },
        body: JSON.stringify({ logo: v }) });
      const d = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(d.error || res.statusText);
      current = d.logo; msg.textContent = "Saved: the sign-in pages show it now.";
    } catch (e) {
      msg.textContent = `Not saved: ${e.message}`;
      setValue(current);
    }
  });
})();
