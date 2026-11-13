#!/usr/bin/env python3
"""The calculations behind the Executive portal's grades and the analysis's shares, offline (review 2026-11-13).
- the 7-day grade follows the published scale: a change on small numbers is Normal; "New this week" is Danger only at
  20 or more, under 20 it is Normal (it was amber); every level the grade gives is on the scale
- the 7-day memory: an item a complete day did not have counts as 0, one missing from an old short summary is unknown
- a share in the analysis is of the whole selection, events without a value included (it was of those with one)
No database needed. Run: .venv/bin/python tests/check_calc_offline.py"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("LG_QUIET", "1")
os.environ.setdefault("THREATMAP_SCHEDULE", "0")
import management as M  # noqa: E402

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info and not cond else ""))


print("The 7-day grade follows the published scale")
week0 = [0, 0, 0, 0, 0, 0, 0]
g = M.assess(5, week0)
ok("new this week, 5 today (under 20): Normal, not amber", g["level"] == "normal" and "New this week" in g["label"], str(g))
g = M.assess(19, week0)
ok("…19 today: still Normal", g["level"] == "normal", g["level"])
g = M.assess(20, week0)
ok("…20 today: Danger (red), as the scale says", g["level"] == "high" and g["label"] == "New this week", str(g))
ok("none this week and none today: Normal", M.assess(0, week0)["level"] == "normal")
ok("fewer than 3 known days: no grade", M.assess(50, [None, None, 10, None, 12, None, None]) is None)
ok("+9.9 % is Normal (cut, not rounded up to 10 %)", M.assess(1099, [1000] * 7)["level"] == "normal")
ok("+30 % on large numbers: Caution", M.assess(1300, [1000] * 7)["level"] == "watch")
ok("+60 %: Danger", M.assess(1600, [1000] * 7)["level"] == "high")
ok("-30 %: Clear drop (good)", M.assess(700, [1000] * 7)["level"] == "good")
ok("-60 %: Unusual drop (amber)", M.assess(400, [1000] * 7)["level"] == "watch")
ok("+50 % on small numbers (12 vs 8): Normal (small numbers)", M.assess(12, [8] * 7)["level"] == "normal")
ok("went quiet after 10 or more a day: amber", M.assess(0, [15] * 7)["label"] == "Went quiet")
levels = {s["level"] for s in M.SCALE}
seen = {M.assess(t, w)["level"] for t, w in ((5, week0), (25, week0), (1000, [1000] * 7), (1150, [1000] * 7), (1300, [1000] * 7),
                                             (1600, [1000] * 7), (700, [1000] * 7), (400, [1000] * 7), (0, [15] * 7))}
ok("every level the grade gives is on the published scale", seen <= levels, f"{sorted(seen - levels)}")

print("The 7-day memory")
ok("an item a complete day did not have counts as 0", M.item_count({"items": {"a": 30}, "all": True}, "b") == 0)
ok("an item missing from an old top-80 summary is unknown, not 0", M.item_count({"items": {f"x{i}": 1 for i in range(80)}}, "b") is None)
ok("a day without reports is unknown", M.item_count({"none": True, "items": {}}, "a") is None)

print("Shares in the analysis are of the whole selection")
import app as A  # noqa: E402
evs = [{"dst_port": 443}] * 10 + [{"dst_port": ""}] * 90
top = A._top(evs, "dst_port")
ok("10 of 100 events have port 443, the other 90 none: its share is 10 %, not 100 %", top and top[0]["share"] == 0.1, str(top))
ok("…an empty value is never listed", all(r["value"] for r in top))
print("An advisory's report is out of date only when the advisory changed after it")
import advisory as ADV  # noqa: E402
a = {"heading": "", "subject": "S", "tlp": "TLP:AMBER", "description": "D", "actions": "A", "history": []}
a["reports"] = [{"n": 1, "at": 100, "content": ADV.content_sig(a)}]
ok("a report with its fingerprint, nothing changed: current", ADV.report_stale(a) is False)
ok("…the TLP changed: out of date", ADV.report_stale(dict(a, tlp="TLP:CLEAR")) is True)
old = dict(a, reports=[{"n": 1, "at": 100}], history=[{"at": 90, "what": "edited"}, {"at": 100, "what": "report generated: x.pdf"}])
ok("a report from before fingerprints, not edited since: current (no needless regeneration)", ADV.report_stale(old) is False)
old2 = dict(old, history=old["history"] + [{"at": 150, "what": "edited after it was drafted: back to draft"}])
ok("…edited after it was generated: out of date", ADV.report_stale(old2) is True)
ok("no report yet: not out of date", ADV.report_stale(dict(a, reports=[])) is False)
print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
