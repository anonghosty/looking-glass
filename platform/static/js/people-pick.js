/* Looking Glass · "Send to": the person a finding goes to (findings.py: a finding is a channel, like a ticket; only the
   people in it see it and its trail). window.LGPeople.picker(kind) → { el, value(), check() } with kind management,
   researcher or analyst: a list of the active accounts that do that job (/api/findings/people), names only. */
(() => {
  "use strict";
  const el = (t, c, x) => { const e = document.createElement(t); if (c) e.className = c; if (x != null) e.textContent = x; return e; };
  const WHO = { management: ["a manager", "Send to (management)"], researcher: ["a researcher", "Send to (researcher)"], analyst: ["an analyst", "Send to (analyst)"],
                advisor: ["an advisor", "Send to (advisor)"] };
  const cache = {};
  const load = (kind) => (cache[kind] ||= fetch(`/api/findings/people?kind=${kind}`, { cache: "no-store" })
    .then((r) => (r.ok ? r.json() : { people: [] })).then((d) => d.people || []).catch(() => []));

  function picker(kind) {
    const [one, label] = WHO[kind] || WHO.management;
    const wrap = el("label", "pp-pick");
    const sel = el("select", "pp-sel"); sel.setAttribute("aria-label", label);
    sel.append(new Option(`Choose ${one}…`, ""));
    const note = el("small", "pp-note", "Only you and the person you choose see it and its trail (and whoever it is passed on to).");
    wrap.append(el("span", "pp-l", label), sel, note);
    load(kind).then((people) => {
      for (const p of people) sel.append(new Option(`${p.name}${p.name !== p.user ? ` (${p.user})` : ""}${p.role && p.role !== kind ? ` · ${p.role}` : ""}`, p.user));
      if (!people.length) { sel.disabled = true; note.textContent = `No ${one.replace(/^an? /, "")} account yet: an admin adds one in Admin.`; note.classList.add("bad"); }
    });
    return {
      el: wrap,
      value: () => sel.value,
      check() { if (sel.value) return true; sel.focus(); wrap.classList.add("need"); setTimeout(() => wrap.classList.remove("need"), 1600); return false; },
      reset() { sel.value = ""; },
    };
  }
  window.LGPeople = { picker, label: (kind) => (WHO[kind] || WHO.management)[0] };
})();
