/* SPDX-License-Identifier: AGPL-3.0-only
   SPDX-FileCopyrightText: the Looking Glass contributors */
/* Looking Glass · Settings: the organisation's name and logo, which head every advisory (organisation.py). The PDF's
   look and page name are the advisor's choice on each advisory (2026-11-20).
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
      saved = { name: d.name || "", has_logo: !!d.has_logo };
      maxKb = d.max_logo_kb || 40;
      $("orgName").value = saved.name; logo = undefined;
      show(saved.has_logo ? `/organisation/logo?t=${Date.now()}` : "");
      $("orgLogoHint").textContent = window.LGLogoTool
        ? `A wide logo works best, about ${window.LGLogoTool.OUT_W} × ${window.LGLogoTool.OUT_H} pixels (2:1). You size and crop it next, and see it on the advisory.`
        : `At most ${maxKb} KB.`;
      sync();
    } catch (e) { msg(`The organisation could not be read: ${window.LGLoader.errorText(e)}`, true); }
  }

  $("orgName").addEventListener("input", sync);
  $("orgFile").addEventListener("change", () => {
    const f = $("orgFile").files[0];
    $("orgFile").value = "";
    if (!f) return;
    if (!/^image\/(png|jpeg)$/.test(f.type)) { msg("The logo must be a PNG or JPEG image.", true); return; }
    // the size and crop tool (logo-tool.js, 2026-11-19): any picture up to 5 MB is fitted to the advisory's frame and
    // made small enough here, in the browser; without it, a picture already within the limit as before
    if (window.LGLogoTool) {
      if (f.size > 5 * 1024 * 1024) { msg("Choose a picture under 5 MB.", true); return; }
      window.LGLogoTool.open(f).then((url) => {
        if (!url) { msg("Logo not changed."); return; }
        logo = url; show(logo); msg("New logo chosen: save to keep it."); sync();
      });
      return;
    }
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
    } catch (e) { msg(window.LGLoader.errorText(e, true), true); sync(); }
  });
  load();
})();
