/* Looking Glass · authenticator set-up: draws the QR code (otpauth URI) in the browser, so the key is never sent to
   a third-party QR service; copies recovery codes. Uses qrcode-generator (cdnjs, pinned with an integrity hash). */
(() => {
  "use strict";
  const img = document.getElementById("qr");
  if (img && window.qrcode) {
    try {
      const qr = window.qrcode(0, "M");
      qr.addData(img.dataset.uri);
      qr.make();
      img.src = qr.createDataURL(5, 4);
    } catch { img.alt = "QR code unavailable: use the key below"; }
  }
  const btn = document.getElementById("copyCodes");
  if (btn) btn.addEventListener("click", async () => {
    const text = [...document.querySelectorAll(".auth-codes li")].map((li) => li.textContent).join("\n");
    try { await navigator.clipboard.writeText(text); btn.textContent = "Copied"; } catch { btn.textContent = "Select and copy the codes"; }
  });
})();
