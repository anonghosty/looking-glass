/* Looking Glass · Settings: the organisation's name and logo, which head every advisory (organisation.py).
   Saved on its own, with its own button (not with Apply settings). */
(() => {
  const $ = (id) => document.getElementById(id);
  const card = $("cardOrg");
  if (!card) return;
  const csrf = document.querySelector('meta[name="csrf-token"]')?.content || "";
  let saved = { name: "", has_logo: false }, logo, maxKb = 40;   // logo: undefined = keep, "" = remove, data URL = new

  const msg = (t, bad) => { $("orgMsg").textContent = t; $("orgMsg").style.color = bad ? "#ff8f8f" : ""; };
  const dirty = () => $("orgName").value.trim() !== saved.name || logo !== undefined;
  const sync = () => { $("orgSave").disabled = !dirty() || !$("orgName").value.trim(); };
  const show = (src) => {
    $("orgLogo").hidden = !src; $("orgNoLogo").hidden = !!src; $("orgRemove").hidden = !src;
    if (src) $("orgLogo").src = src;
  };

  async function load() {
    try {
      const r = await fetch("/api/organisation", { credentials: "same-origin" });
      const d = await r.json();
      if (!r.ok) throw new Error(d.error || r.status);
      saved = { name: d.name || "", has_logo: !!d.has_logo }; maxKb = d.max_logo_kb || 40;
      $("orgName").value = saved.name; logo = undefined;
      show(saved.has_logo ? `/organisation/logo?t=${Date.now()}` : "");
      $("orgLogoHint").textContent = `At most ${maxKb} KB.`;
      sync();
    } catch (e) { msg(`The organisation could not be read: ${e.message}`, true); }
  }

  $("orgName").addEventListener("input", sync);
  $("orgFile").addEventListener("change", () => {
    const f = $("orgFile").files[0];
    $("orgFile").value = "";
    if (!f) return;
    if (!/^image\/(png|jpeg)$/.test(f.type)) { msg("The logo must be a PNG or JPEG image.", true); return; }
    if (f.size > maxKb * 1024) { msg(`The logo is ${Math.ceil(f.size / 1024)} KB: at most ${maxKb} KB, please.`, true); return; }
    const rd = new FileReader();
    rd.onload = () => { logo = rd.result; show(logo); msg("New logo chosen: save to keep it."); sync(); };
    rd.readAsDataURL(f);
  });
  $("orgRemove").addEventListener("click", () => { logo = ""; show(""); msg("The logo will be removed when you save."); sync(); });
  $("orgSave").addEventListener("click", async () => {
    const body = { name: $("orgName").value.trim() };
    if (logo !== undefined) body.logo = logo;
    $("orgSave").disabled = true; msg("Saving…");
    try {
      const r = await fetch("/api/organisation", { method: "POST", credentials: "same-origin",
        headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf }, body: JSON.stringify(body) });
      const d = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
      await load(); msg("Saved: the next advisories carry it.");
    } catch (e) { msg(e.message, true); sync(); }
  });
  load();
})();
