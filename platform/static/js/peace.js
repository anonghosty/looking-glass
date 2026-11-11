/* Looking Glass · Peace of mind (peace.py), on the Admin page: the admin's own switch. Turning it on or off reloads the
   page, so the header, the Overview and the bell follow at once. */
(() => {
  "use strict";
  const box = document.getElementById("peaceOn");
  if (!box) return;
  const msg = document.getElementById("peaceMsg");
  const csrf = () => document.querySelector('meta[name="csrf-token"]')?.content || "";
  box.addEventListener("change", async () => {
    const on = box.checked;
    box.disabled = true; msg.textContent = on ? "Turning Peace of mind on…" : "Turning Peace of mind off…"; msg.classList.add("lg-loading");
    try {
      const r = await fetch("/api/peace", { method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf() },
        body: JSON.stringify({ on }) });
      const d = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
      window.LGLoader ? window.LGLoader.go("/admin", on ? "Peace of mind: admin, audit and Settings only" : "Everything back") : location.reload();
    } catch (e) {
      box.checked = !on; msg.classList.remove("lg-loading"); msg.querySelector(".lg-logo-wrap")?.remove(); msg.textContent = e.message;
    } finally { box.disabled = false; }
  });
})();
