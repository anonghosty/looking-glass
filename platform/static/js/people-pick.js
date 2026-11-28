/* SPDX-License-Identifier: AGPL-3.0-only
   SPDX-FileCopyrightText: the Looking Glass contributors */
/* Looking Glass · "Send to": the person a finding goes to (findings.py: a finding is a channel, like a ticket; only the
   people in it see it and its trail). window.LGPeople.picker(kind) → { el, value(), check() } with kind management,
   researcher or analyst: a list of the active accounts that do that job (/api/findings/people), names only. */
(() => {
  "use strict";
  const el = (t, c, x) => { const e = document.createElement(t); if (c) e.className = c; if (x != null) e.textContent = x; return e; };
  const WHO = { management: ["a manager", "Send to (management)"], researcher: ["a researcher", "Send to (researcher)"], analyst: ["an analyst", "Send to (analyst)"],
                advisor: ["an advisor", "Send to (advisor)"] };
  const cache = {};
  // only a list that came back is kept: a refused or failed request is not "no accounts", it is said and can be tried
  // again (audit 2026-11-27, 11-9: a failed fetch was kept as an empty list until the page was reloaded)
  const load = (kind) => (cache[kind] ||= fetch(`/api/findings/people?kind=${kind}`, { cache: "no-store" })
    .then((r) => { if (!r.ok) throw new Error(`answered ${r.status}`); return r.json(); }).then((d) => d.people || [])
    .catch((e) => { delete cache[kind]; throw e; }));

  function picker(kind) {
    const [one, label] = WHO[kind] || WHO.management;
    const wrap = el("label", "pp-pick");
    const sel = el("select", "pp-sel lg-enhance"); sel.setAttribute("aria-label", label);
    sel.append(new Option(`Choose ${one}…`, ""));
    const NOTE = "Only you and the person you choose see it and its trail (and whoever it is passed on to).";
    const note = el("small", "pp-note", NOTE);
    wrap.append(el("span", "pp-l", label), sel, note);
    const fill = () => load(kind).then((people) => {
      note.textContent = NOTE; note.classList.remove("bad"); sel.disabled = false;
      // names only: the value is the person's code (person_code.py), never a sign-in name; two people with one name
      // are told apart by the code's last characters
      const twice = (n) => people.filter((q) => q.name === n).length > 1;
      for (const p of people) sel.append(new Option(`${p.name}${twice(p.name) ? ` (${p.code.slice(-4)})` : ""}${p.role && p.role !== kind ? ` · ${p.role}` : ""}`, p.code));
      if (!people.length) { sel.disabled = true; note.textContent = `No ${one.replace(/^an? /, "")} account yet: an admin adds one in Admin.`; note.classList.add("bad"); }
    }, () => {
      sel.disabled = true; note.classList.add("bad");
      note.textContent = "The list of people could not be loaded. ";
      const again = el("button", "link-btn", "Try again"); again.type = "button";
      again.addEventListener("click", (ev) => { ev.preventDefault(); note.textContent = "Loading the list of people."; fill(); });
      note.append(again);
    });
    fill();
    return {
      el: wrap,
      value: () => sel.value,
      check() { if (sel.value) return true; sel.focus(); wrap.classList.add("need"); setTimeout(() => wrap.classList.remove("need"), 1600); return false; },
      reset() { sel.value = ""; },
    };
  }
  window.LGPeople = { picker, label: (kind) => (WHO[kind] || WHO.management)[0] };
})();
