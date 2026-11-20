#!/usr/bin/env python3
"""The map's infection list with infections ticked counts what else the matching devices carry (facets.overlap; the
user, 2026-11-20: "when i filter it doesnt reflect on the other infections", chose overlap counts), and the filters
move smoothly (rolling counts, rows sliding, arcs fading; "there is no smooth filtering animation").
Made-up records only. Run: .venv/bin/python tests/check_filter_overlap.py (LG_HELD_DIR: held .new files).
"""
import os
import sys

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if not os.path.isdir(os.path.join(HERE, "static", "js")):
    HERE = os.getcwd()
sys.path.insert(0, HERE)
S = os.environ.get("LG_HELD_DIR", "")
checks, fails = 0, []


def ok(name, cond, detail=""):
    global checks
    checks += 1
    if cond:
        print(f"  ok   {name}")
    else:
        fails.append(name)
        print(f"  FAIL {name}  {str(detail)[:300]}")


def read(path):
    n = os.path.basename(path)
    p = os.path.join(S, n + ".new") if S and os.path.exists(os.path.join(S, n + ".new")) else path
    return open(p, encoding="utf-8").read()


import facets as F  # noqa: E402

print("1. facets.overlap")
ev = lambda ip, inf, sev="critical": {"src_ip": ip, "infection": inf, "severity": sev}  # noqa: E731
# 192.0.2.x: documentation addresses (made up). .1 and .2 carry glassworm; .1 also vo1d, .2 also badbox; .3 vo1d only
evs = [ev("192.0.2.1", "glassworm"), ev("192.0.2.1", "vo1d"), ev("192.0.2.1", "vo1d"), ev("192.0.2.2", "glassworm"),
       ev("192.0.2.2", "badbox"), ev("192.0.2.3", "vo1d"), ev("192.0.2.4", "sality", "info"), ev("192.0.2.1", "badbox", "info")]
name, dev = (lambda e: e["infection"]), (lambda e: e["src_ip"])
pool = F.pools(evs, {"infection": {"glassworm"}}, lambda e, f: e[f])
rows = {r["value"]: r["count"] for r in F.overlap(pool, name, dev)}
ok("the ticked infection counts its own devices", rows["glassworm"] == 2, rows)
ok("…another counts how many of those devices also carry it (devices, not records)", rows["vo1d"] == 1 and rows["badbox"] == 2, rows)
ok("…one none of them carries is still listed, with 0", rows.get("sality") == 0, rows)
order = [r["value"] for r in F.overlap(pool, name, dev)]
ok("most first, the 0s last", order[-1] == "sality" and order.index("glassworm") < order.index("vo1d"), order)
pool2 = F.pools(evs, {"infection": {"glassworm"}, "severity": {"critical"}}, lambda e, f: e[f])
rows2 = {r["value"]: r["count"] for r in F.overlap(pool2, name, dev)}
ok("another filter narrows it too (Critical: the Info badbox record of .1 no longer counts)", rows2["badbox"] == 1 and "sality" not in rows2, rows2)
both = F.carriers(evs, name, dev, {"glassworm", "vo1d"})
ok("two ticked: only the devices carrying both (the user, 2026-11-20)", both == {"192.0.2.1"}, both)
ok("…none carrying both: no device", F.carriers(evs, name, dev, {"glassworm", "sality"}) == set())
val = lambda e, f: e["src_ip"] if f == "_carries_all" else e[f]  # noqa: E731
pool3 = F.pools(evs, {"infection": {"glassworm", "vo1d"}, "_carries_all": both}, val)
rows3 = {r["value"]: r["count"] for r in F.overlap(pool3, name, dev)}
ok("…the list then counts those devices: both ticked 1, badbox 1 (.1 carries it too), the rest 0",
   rows3["glassworm"] == 1 and rows3["vo1d"] == 1 and rows3["badbox"] == 1 and rows3.get("sality", 0) == 0, rows3)
ok("…their records of the ticked infections are what the map shows (3 of .1's, not .2's or .3's)",
   len(pool3.passed) == 3 and {e["src_ip"] for e in pool3.passed} == {"192.0.2.1"}, len(pool3.passed))
ok("no device address in the answer, only names and counts", all(set(r) == {"value", "count"} for r in F.overlap(pool, name, dev)))

import respcache as RC  # noqa: E402
k_either = RC.filters_key({"infection": {"a", "b"}})
k_both = RC.filters_key({"infection": {"a", "b"}, "_carries_all": {"192.0.2.1", "192.0.2.9"}})
ok("cached answers for 'either' and 'both' are kept apart; the device set is not in the key", k_either != k_both and "192.0.2.1" not in str(k_both))

print("2. Used by the map's filter counts")
src = read(os.path.join(HERE, "app.py"))
ok("'both' applies only when the page asks (inf_all=1): a saved analyst code or finding keeps its devices",
   'args.get("inf_all") != "1"' in src and src.count("narrow_filters(parse_filters(") == 6)
ok("…on the map's records, stream, figures, places, replay counts and analyses alike", all(
    s in src for s in ("store.get(t_to), request.args)", "day, MultiDict(pairs))")) and "_facets.pools(day.events, flt or {}, field_value)" in src)
ok("the map asks for it with two or more ticked", 'if (state.filters.infection.size > 1) p.append("inf_all", "1");' in read(os.path.join(HERE, "static", "js", "app.js")))
ok("/api/facets uses it when infections are ticked, and says the unit", '_facets.overlap(pool' in src and 'result["infection_unit"] = "devices"' in src)
js = read(os.path.join(HERE, "static", "js", "app.js"))
ok("the list says it counts devices then, with what the counts mean", "devices that also carry each" in js and 'f.infection_unit === "devices"' in js)
ok("a choice with 0 is faded but kept to tick", 'li.classList.add("f-zero")' in js)
css = read(os.path.join(HERE, "static", "css", "app.css"))
ok("…faded by colour, not opacity (contrast kept)", ".checklist li.f-zero .name { color: var(--muted); }" in css and ".checklist li.f-zero { opacity" not in css)

print("3. Smooth filtering")
ok("rows slide to their new places, new ones fade in (FLIP)", "function flipList(" in js and "translateY(${dy}px)" in js and "flipList($(\"drawer\"), buildFilters)" in js)
ok("counts roll from the last figure shown, exact at the end even in a background tab", "function countEl(" in js and "shownCounts" in js
   and js.count("countEl(") >= 4)
ok("arcs the filters leave out fade out; the others stay drawn and are not launched twice",
   "state.fading" in js and "!matchesFilters(a.ev)" in js and "!state.active.some((x) => x.ev.id === ev.id)" in js)
ok("all of it off with reduced motion", js.count("reducedMotion") >= 4 and "if (reducedMotion) state.fading = [];" in js)

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {fails}" if fails else ""))
sys.exit(1 if fails else 0)
