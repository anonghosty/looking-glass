/* SPDX-License-Identifier: AGPL-3.0-only
   SPDX-FileCopyrightText: the Looking Glass contributors */
/* Looking Glass · Your account: the person's passkeys (stepup.py, passkeys.py; the user 2026-11-24).
   A list (name, added, last used) with Rename and Remove, and Add a passkey (the browser asks the device). Adding or
   removing one asks for the fresh check every time (loader.js shows it), except while a person on a public
   installation registers their first passkeys right after signing in. */
(() => {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const csrf = () => document.querySelector('meta[name="csrf-token"]')?.content || "";
  const minimum = Number(document.body.dataset.minimum || 0);
  const err = (t) => { $("pkError").textContent = t || ""; };
  const when = (t) => (t ? new Date(t * 1000).toISOString().slice(0, 16).replace("T", " ") + " UTC" : "not yet");

  async function call(url, body) {
    const r = await fetch(url, { method: body === undefined ? "GET" : "POST", credentials: "same-origin",
      headers: body === undefined ? {} : { "Content-Type": "application/json", "X-CSRF-Token": csrf() },
      body: body === undefined ? undefined : JSON.stringify(body) });
    const j = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(j.error || `Looking Glass answered ${r.status}`);
    return j;
  }

  let last = {};          // the last answer about the passkeys (public, minimum): a new passkey's answer is drawn with it
  function draw(d) {
    last = d;
    const box = $("pkList");
    box.classList.remove("st-loading", "lg-has-logo");
    box.replaceChildren();
    const list = d.passkeys || [];
    if (!list.length) {
      const p = document.createElement("p"); p.className = "st-hint";
      p.textContent = "No passkey is registered for this account yet."; box.append(p);
    } else {
      const wrap = document.createElement("div"); wrap.className = "table-wrap";
      const t = document.createElement("table"); t.className = "st-table";
      const head = t.createTHead().insertRow();
      for (const h of ["Passkey", "Added", "Last used", ""]) { const th = document.createElement("th"); th.textContent = h; head.append(th); }
      const body = t.createTBody();
      for (const k of list) {
        const tr = body.insertRow();
        tr.insertCell().textContent = k.name; tr.insertCell().textContent = when(k.created); tr.insertCell().textContent = when(k.last_used);
        const c = tr.insertCell();
        const ren = document.createElement("button"); ren.type = "button"; ren.className = "pill-btn"; ren.textContent = "Rename";
        ren.addEventListener("click", async () => {
          const name = prompt("A new name for this passkey", k.name);
          if (name == null) return;
          err(); try { draw({ ...d, ...(await call(`/api/passkeys/${encodeURIComponent(k.id)}/rename`, { name })) }); } catch (e) { err(window.LGLoader.errorText(e, true)); }
        });
        const rm = document.createElement("button"); rm.type = "button"; rm.className = "pill-btn"; rm.textContent = "Remove";
        rm.disabled = d.public && list.length <= minimum;
        if (rm.disabled) rm.title = `Keep at least ${minimum}: add another one first.`;
        rm.addEventListener("click", async () => {
          if (!confirm(`Remove the passkey "${k.name}"? That device can no longer sign in to Looking Glass.`)) return;
          err(); try { draw({ ...d, ...(await call(`/api/passkeys/${encodeURIComponent(k.id)}/remove`, {})) }); } catch (e) { err(window.LGLoader.errorText(e, true)); }
        });
        c.append(ren, " ", rm);
      }
      wrap.append(t); box.append(wrap);
    }
    const enrol = $("pkEnrol");
    if (enrol) enrol.hidden = !(d.public && list.length < minimum);
    if (d.public && list.length >= minimum && document.body.dataset.enrol === "1") {
      const ok = document.createElement("p"); ok.className = "st-banner";
      ok.textContent = `You have ${list.length} passkeys: Looking Glass is open. `;
      const go = document.createElement("a"); go.href = "/overview"; go.textContent = "Go to your Overview";
      ok.append(go); box.append(ok);
    }
  }

  async function load() {
    // a list that could not be read says so and stops turning (audit 2026-11-27, 9-9: the loading animation stayed)
    try { draw(await call("/api/passkeys")); } catch (e) {
      const box = $("pkList"); box.classList.remove("st-loading", "lg-has-logo"); box.textContent = window.LGLoader.errorText(e);
    }
  }

  $("pkAdd")?.addEventListener("click", async () => {
    err();
    const b = $("pkAdd"); b.disabled = true;
    try {
      if (!window.LGPasskey?.supported()) throw new Error("This browser or address cannot use passkeys here.");
      const opts = await call("/api/passkeys/options", {});
      const credential = await window.LGPasskey.create(opts);
      // the answer holds the new list; the rest (public, minimum) is the page's last answer: no extra read (audit
      // 2026-11-27, 9-15), unless the page never had one
      const added = await call("/api/passkeys", { credential, name: $("pkName").value });
      draw({ ...(last.passkeys ? last : await call("/api/passkeys")), ...added });
      $("pkName").value = "";
    } catch (e) {
      err(e && e.name && e.name !== "Error" ? window.LGPasskey.words(e) : window.LGLoader.errorText(e, true));
    } finally { b.disabled = false; }
  });

  window.LGLoader?.wait(load(), "Loading your passkeys");
})();
