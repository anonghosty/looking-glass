/* Looking Glass · Settings → Organisation: size and crop the organisation's logo before it is saved (the user,
   2026-11-19: a wide logo with white margins "looks bad", PNGs without a background, "accommodate sizes and cropping
   ratios which the admin will see ... and the recommended size"). The logo now appears on advisories only (the sign-in
   pages show none since r79), so the preview is the advisory's logo card, in both looks.

   LGLogoTool.open(file) -> Promise<data URL | null>: a dialog with the picture in the advisory's frame (2:1), the
   frame's border highlighted; Trim empty margins, zoom and drag to place it, a background for a picture without one
   (keep it see-through, white, dark), live previews of the card on the designed and the plain advisory, the
   recommended size, and the size of the result. The result is a PNG (a JPEG when it is opaque and the PNG would be
   too big), at most MAX_KB, made in the browser: nothing is sent anywhere until the organisation is saved. */
(() => {
  "use strict";
  const MAX_KB = 40;                                   // organisation.py MAX_LOGO
  const OUT_W = 464, OUT_H = 232;                      // 4x the card's picture area (116 x 58 points), 2:1
  const BG = { clear: null, white: "#ffffff", dark: "#10131c" };
  const el = (tag, cls, text) => { const n = document.createElement(tag); if (cls) n.className = cls; if (text != null) n.textContent = text; return n; };

  function loadImage(file) {
    return new Promise((res, rej) => {
      const url = URL.createObjectURL(file), img = new Image();
      img.onload = () => res({ img, url }); img.onerror = () => { URL.revokeObjectURL(url); rej(new Error("This picture could not be read.")); };
      img.src = url;
    });
  }

  // the picture's content box: pixels that are not see-through and not near the corner colour (its margins)
  function contentBox(img) {
    const w = Math.min(img.naturalWidth, 1200), k = w / img.naturalWidth, h = Math.round(img.naturalHeight * k);
    const c = document.createElement("canvas"); c.width = w; c.height = h;
    const x = c.getContext("2d", { willReadFrequently: true }); x.drawImage(img, 0, 0, w, h);
    const d = x.getImageData(0, 0, w, h).data, at = (i) => [d[i], d[i + 1], d[i + 2], d[i + 3]];
    const corner = at(0), near = (p) => p[3] < 16 || (Math.abs(p[0] - corner[0]) + Math.abs(p[1] - corner[1]) + Math.abs(p[2] - corner[2]) < 36 && corner[3] > 200);
    let x0 = w, y0 = h, x1 = -1, y1 = -1;
    for (let y = 0; y < h; y += 1) for (let xx = 0; xx < w; xx += 1) {
      if (!near(at((y * w + xx) * 4))) { if (xx < x0) x0 = xx; if (xx > x1) x1 = xx; if (y < y0) y0 = y; if (y > y1) y1 = y; }
    }
    if (x1 < 0) return { x: 0, y: 0, w: img.naturalWidth, h: img.naturalHeight };
    const pad = 2;
    return { x: Math.max(0, (x0 - pad) / k), y: Math.max(0, (y0 - pad) / k), w: Math.min(img.naturalWidth, (x1 - x0 + 1 + 2 * pad) / k), h: Math.min(img.naturalHeight, (y1 - y0 + 1 + 2 * pad) / k) };
  }

  function hasClear(img) {
    const c = document.createElement("canvas"), w = Math.min(img.naturalWidth, 400), h = Math.max(1, Math.round(img.naturalHeight * w / img.naturalWidth));
    c.width = w; c.height = h; const x = c.getContext("2d", { willReadFrequently: true }); x.drawImage(img, 0, 0, w, h);
    const d = x.getImageData(0, 0, w, h).data; for (let i = 3; i < d.length; i += 16) if (d[i] < 250) return true; return false;
  }

  // draw the picture's chosen part into a 2:1 canvas: fitted inside, centred, then zoomed and moved
  function render(canvas, st) {
    const x = canvas.getContext("2d"), W = canvas.width, H = canvas.height;
    x.clearRect(0, 0, W, H);
    if (BG[st.bg]) { x.fillStyle = BG[st.bg]; x.fillRect(0, 0, W, H); }
    const b = st.trim ? st.box : { x: 0, y: 0, w: st.img.naturalWidth, h: st.img.naturalHeight };
    const s = Math.min(W / b.w, H / b.h) * st.zoom, dw = b.w * s, dh = b.h * s;
    x.imageSmoothingQuality = "high";
    x.drawImage(st.img, b.x, b.y, b.w, b.h, (W - dw) / 2 + st.dx * W, (H - dh) / 2 + st.dy * H, dw, dh);
  }

  async function encode(st) {
    for (const [w, h] of [[OUT_W, OUT_H], [348, 174], [232, 116]]) {
      const c = document.createElement("canvas"); c.width = w; c.height = h; render(c, st);
      const png = c.toDataURL("image/png");
      if (png.length * 0.75 <= MAX_KB * 1024) return { url: png, w, h, kind: "PNG" };
      if (BG[st.bg] || !st.clear) {                  // opaque: a JPEG is far smaller
        for (const q of [0.92, 0.85, 0.75]) {
          const j = c.toDataURL("image/jpeg", q);
          if (j.length * 0.75 <= MAX_KB * 1024) return { url: j, w, h, kind: "JPEG" };
        }
      }
    }
    return null;
  }

  function open(file) {
    return new Promise(async (resolve) => {
      let pic;
      try { pic = await loadImage(file); } catch (e) { alert(e.message); resolve(null); return; }
      const st = { img: pic.img, box: contentBox(pic.img), clear: hasClear(pic.img), trim: true, zoom: 1, dx: 0, dy: 0, bg: "clear" };
      if (!st.clear) st.bg = "clear";
      const prev = document.activeElement;
      const dlg = el("dialog", "lt-dialog"); dlg.setAttribute("aria-labelledby", "ltTitle");
      const head = el("h2", null, "Size the logo for the advisories"); head.id = "ltTitle";
      const rec = el("p", "lt-hint", `Recommended: a wide logo, about ${OUT_W} × ${OUT_H} pixels (2:1), PNG. On the advisory it is shown in a white card, ` +
        `about 4 × 2 cm. Your picture: ${pic.img.naturalWidth} × ${pic.img.naturalHeight} pixels${st.clear ? ", with see-through parts" : ""}.`);
      const stage = el("div", "lt-stage"), frame = el("canvas", "lt-frame"); frame.width = OUT_W; frame.height = OUT_H;
      frame.setAttribute("role", "img"); frame.setAttribute("aria-label", "The logo inside the advisory's frame; drag to move it, or use the arrow keys");
      frame.tabIndex = 0; stage.append(frame, el("span", "lt-border", null));
      const ctl = el("div", "lt-controls");
      const trim = el("label", "lt-check"); const trimBox = el("input"); trimBox.type = "checkbox"; trimBox.checked = true; trim.append(trimBox, el("span", null, "Trim empty margins"));
      const zoomL = el("label", "lt-field"); const zoom = el("input"); zoom.type = "range"; zoom.min = "0.5"; zoom.max = "2.5"; zoom.step = "0.01"; zoom.value = "1";
      zoomL.append(el("span", null, "Size in the frame"), zoom);
      const bgL = el("label", "lt-field"); const bg = el("select", "lt-bg lg-enhance");
      for (const [v, t] of [["clear", "Keep see-through (the card is white)"], ["white", "White background"], ["dark", "Dark background"]]) bg.append(new Option(t, v));
      bgL.append(el("span", null, st.clear ? "Background (the picture has see-through parts)" : "Background"), bg);
      const reset = el("button", "pill-btn", "Centre again"); reset.type = "button";
      ctl.append(trim, zoomL, bgL, reset);
      const pv = el("div", "lt-previews");
      const card = (label, cls) => { const f = el("figure", `lt-card ${cls}`); const box = el("div", "lt-card-box"); const c = el("canvas"); c.width = 232; c.height = 116; box.append(c); f.append(box, el("figcaption", null, label)); pv.append(f); return c; };
      const cDesigned = card("On the advisory (designed, dark pages)", "lt-on-dark"), cPlain = card("On the advisory (plain, white pages)", "lt-on-light");
      const size = el("p", "lt-size"); size.setAttribute("role", "status");
      const acts = el("div", "lt-acts"); const use = el("button", "intro-cta", "Use this logo"); use.type = "button";
      const cancel = el("button", "pill-btn", "Cancel"); cancel.type = "button"; acts.append(use, cancel);
      dlg.append(head, rec, stage, ctl, pv, size, acts); document.body.append(dlg);
      let timer = null;
      const redraw = () => {
        render(frame, st); render(cDesigned, st); render(cPlain, st);
        clearTimeout(timer); timer = setTimeout(async () => {
          const r = await encode(st);
          size.textContent = r ? `The saved logo: ${r.kind}, ${r.w} × ${r.h} pixels, ${Math.ceil(r.url.length * 0.75 / 1024)} KB (at most ${MAX_KB} KB).`
            : `Too detailed to fit in ${MAX_KB} KB even when smaller: choose a white or dark background, or a simpler picture.`;
          use.disabled = !r;
        }, 120);
      };
      trimBox.addEventListener("change", () => { st.trim = trimBox.checked; redraw(); });
      zoom.addEventListener("input", () => { st.zoom = +zoom.value; redraw(); });
      bg.addEventListener("change", () => { st.bg = bg.value; redraw(); });
      reset.addEventListener("click", () => { st.zoom = 1; st.dx = 0; st.dy = 0; zoom.value = "1"; redraw(); });
      let drag = null;
      frame.addEventListener("pointerdown", (e) => { drag = { x: e.clientX, y: e.clientY, dx: st.dx, dy: st.dy }; frame.setPointerCapture(e.pointerId); });
      frame.addEventListener("pointermove", (e) => {
        if (!drag) return; const r = frame.getBoundingClientRect();
        st.dx = Math.max(-0.5, Math.min(0.5, drag.dx + (e.clientX - drag.x) / r.width)); st.dy = Math.max(-0.5, Math.min(0.5, drag.dy + (e.clientY - drag.y) / r.height)); redraw();
      });
      frame.addEventListener("pointerup", () => { drag = null; });
      frame.addEventListener("keydown", (e) => {
        const step = e.shiftKey ? 0.05 : 0.01, m = { ArrowLeft: [-step, 0], ArrowRight: [step, 0], ArrowUp: [0, -step], ArrowDown: [0, step] }[e.key];
        if (!m) return; e.preventDefault(); st.dx = Math.max(-0.5, Math.min(0.5, st.dx + m[0])); st.dy = Math.max(-0.5, Math.min(0.5, st.dy + m[1])); redraw();
      });
      const done = (v) => { dlg.close(); dlg.remove(); URL.revokeObjectURL(pic.url); if (prev && prev.focus) prev.focus(); resolve(v); };
      use.addEventListener("click", async () => { const r = await encode(st); done(r ? r.url : null); });
      cancel.addEventListener("click", () => done(null));
      dlg.addEventListener("cancel", (e) => { e.preventDefault(); done(null); });
      dlg.showModal(); redraw(); frame.focus();
    });
  }
  window.LGLogoTool = { open, MAX_KB, OUT_W, OUT_H };
})();
