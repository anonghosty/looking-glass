/* Looking Glass · a confirmation dialog that lists exactly what an action will change ("Confirm all"), in the page's own
   style (st-modal, lg-btn). Keyboard focus, Tab trapping and focus back to the opener are dialog-focus.js's (it handles
   every aria-modal element); Escape and the backdrop cancel. Text is always set as text.
   LGConfirmList.open({title, intro, rows: [{title, sub, techs: [{id, name}]}], confirm}) -> Promise<boolean> */
(() => {
  "use strict";
  if (window.LGConfirmList) return;
  const el = (t, c, x) => { const e = document.createElement(t); if (c) e.className = c; if (x != null) e.textContent = x; return e; };
  let n = 0;

  function open({ title, intro, rows, confirm }) {
    return new Promise((resolve) => {
      const id = `lgcl${++n}`;
      const back = el("div", "st-modal-back");
      const box = el("section", "st-modal cl-modal");
      box.setAttribute("role", "dialog"); box.setAttribute("aria-modal", "true"); box.setAttribute("aria-labelledby", `${id}t`);
      const head = el("div", "st-modal-head"), h = el("h2", null, title); h.id = `${id}t`;
      const x = el("button", "icon-btn", "×"); x.type = "button"; x.setAttribute("aria-label", "Close");
      head.append(h, x);
      const list = el("ul", "cl-list");
      list.setAttribute("aria-label", `${rows.length} item${rows.length === 1 ? "" : "s"}`);
      for (const r of rows) {
        const li = el("li", "cl-row");
        li.append(el("b", "cl-title", r.title));
        if (r.sub) li.append(el("span", "cl-sub mono", r.sub));
        if (r.techs?.length) {
          const t = el("div", "cl-techs");
          for (const tt of r.techs) { const c = el("span", "cl-tech"); c.append(el("span", "cl-tid mono", tt.id), document.createTextNode(` ${tt.name}`)); t.append(c); }
          li.append(t);
        }
        list.append(li);
      }
      const foot = el("div", "cl-foot");
      const no = el("button", "lg-btn ghost", "Cancel"), yes = el("button", "lg-btn primary", confirm || "Confirm");
      no.type = yes.type = "button";
      foot.append(no, yes);
      box.append(head);
      if (intro) box.append(el("p", "st-hint cl-intro", intro));
      box.append(el("p", "cl-count", `${rows.length} in total`), list, foot);
      let done = false;
      const opener = document.activeElement;      // focus goes back here when the dialog closes
      const close = (v) => {
        if (done) return; done = true;
        document.removeEventListener("keydown", onKey, true);
        box.remove(); back.remove();
        if (opener && opener.isConnected && typeof opener.focus === "function") { try { opener.focus({ preventScroll: true }); } catch { /* gone */ } }
        resolve(v);
      };
      const onKey = (e) => { if (e.key === "Escape") { e.preventDefault(); e.stopPropagation(); close(false); } };
      document.addEventListener("keydown", onKey, true);
      x.addEventListener("click", () => close(false)); no.addEventListener("click", () => close(false));
      back.addEventListener("click", () => close(false)); yes.addEventListener("click", () => close(true));
      document.body.append(back, box);
      setTimeout(() => { if (!done) yes.focus(); }, 90);
    });
  }
  window.LGConfirmList = { open };
})();
