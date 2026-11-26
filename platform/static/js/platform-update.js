/* SPDX-License-Identifier: AGPL-3.0-only
   SPDX-FileCopyrightText: the Looking Glass contributors */
/* Looking Glass · Settings -> Update (platform_update.py, deploy/update_run.py; the user 2026-11-25).
   Shows the installed release, Check for an update, and Update to the newer one; while a run is busy, its steps one by
   one (the log the update helper writes, which survives the restart: when Looking Glass is restarting the page waits and
   asks again). Update asks for the fresh check every time (stepup.py; loader.js and lg-stepup.js show the dialog).
   Built with the DOM only: no HTML strings. */
(() => {
  "use strict";
  const pane = document.getElementById("tabUpdate"), box = document.getElementById("upBody");
  if (!pane || !box) return;
  const csrf = () => document.querySelector('meta[name="csrf-token"]')?.content || "";
  const el = (tag, cls, text) => { const e = document.createElement(tag); if (cls) e.className = cls; if (text != null) e.textContent = text; return e; };
  const btn = (label, cls, fn) => { const b = el("button", `lg-btn ${cls || ""}`.trim(), label); b.type = "button"; b.addEventListener("click", fn); return b; };
  const when = (t) => (t ? new Date(t * 1000).toISOString().slice(0, 19).replace("T", " ") + " UTC" : "");
  const STATE = { running: "Running", done: "Updated", failed: "Not updated", rolled_back: "Put back", checked: "Checked" };
  let D = null, timer = null, open = false, msg = "";

  async function api(body) {
    const r = await fetch("/api/admin/update", { method: body === undefined ? "GET" : "POST", credentials: "same-origin", cache: "no-store",
      headers: body === undefined ? {} : { "Content-Type": "application/json", "X-CSRF-Token": csrf() },
      body: body === undefined ? undefined : JSON.stringify(body) });
    const j = await r.json().catch(() => ({}));
    if (!r.ok) { const e = new Error(j.error || `Looking Glass answered ${r.status}`); e.data = j; throw e; }
    return j;
  }

  async function load() {
    try { D = await api(); msg = ""; draw(); }
    catch (e) {
      // restarting: the old process has gone and the new one is starting; the run goes on, so ask again
      if (D && D.busy) { msg = "Looking Glass is restarting; the steps continue below…"; draw(); }
      else { box.classList.remove("st-loading"); box.textContent = window.LGLoader.errorText(e); }
    }
    schedule();
  }
  function schedule() {
    clearTimeout(timer);
    if (open) timer = setTimeout(load, D && (D.busy || D.waiting) ? 2000 : 30000);
  }

  async function ask(body, button) {
    button.disabled = true; msg = "";
    try { D = await api(body); } catch (e) { msg = window.LGLoader.errorText(e); }
    button.disabled = false; draw(); schedule();
  }

  function draw() {
    box.classList.remove("st-loading", "lg-has-logo");
    box.replaceChildren();
    const s = D.status || {};
    box.append(el("p", "st-meta", `Installed: ${D.installed || "no release tag on this checkout"}`));
    if (!D.release_install) {
      box.append(el("p", "st-access", "This folder was not installed from a release (for example a developer's working copy), so it is not updated from here: its maintainer updates it."));
    } else if (!D.helper) {
      const p = el("p", "st-access", "The update helper is not installed yet. Once, on the server, in the platform folder, as the installation's user: ");
      p.append(el("code", "tm-cmd", D.command));
      p.append(document.createTextNode(` (it asks for sudo, and installs ${D.unit}.path and ${D.unit}.service, which run as that user, never as root).`));
      box.append(p);
    }
    const row = el("div", "up-actions");
    const can = D.release_install && D.helper && !D.busy;
    const check = btn("Check for an update", "", () => ask({ kind: "check" }, check)); check.disabled = !can;
    row.append(check);
    const newest = s.kind === "check" && s.state === "checked" && (s.newer || []).length ? s.newer[s.newer.length - 1] : "";
    if (newest) {
      const go = btn(`Update to ${newest}`, "primary", () => ask({ kind: "update", tag: newest }, go)); go.disabled = !can;
      row.append(go);
    }
    box.append(row);
    if (msg) box.append(el("p", "wk-msg bad", msg));
    if (s.state) {
      const head = el("p", `up-state up-${s.state}`, `${STATE[s.state] || s.state}${s.kind === "update" && s.tag ? `: ${s.tag}` : ""}` +
        `${s.step && s.state === "running" ? ` · ${s.step}` : ""}${s.result ? ` · ${s.result}` : ""}`);
      head.setAttribute("role", "status");
      box.append(head, el("p", "st-meta", `${s.by ? `Asked by ${s.by} · ` : ""}started ${when(s.started)}${s.ended ? ` · ended ${when(s.ended)}` : ""}`));
    }
    if ((D.log || []).length) {
      const list = el("ol", "up-log"); list.setAttribute("aria-label", "The update's steps");
      for (const l of D.log.slice(-200)) {
        const li = el("li", `up-l up-${l.level}`);
        li.append(el("span", "up-t", when(l.t).slice(11, 19)), el("span", "up-s", l.step), el("span", "up-m", l.msg));
        list.append(li);
      }
      box.append(list);
      if (D.busy) list.lastElementChild?.scrollIntoView({ block: "nearest" });
    }
  }

  document.addEventListener("lg:settings-tab", (e) => {
    open = e.detail === "update";
    if (open) load(); else clearTimeout(timer);
  });
})();
