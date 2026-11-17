#!/usr/bin/env python3
"""The spike notice on the Overview's buttons (spike_notice.py, features.py; the user, 2026-11-16). Made-up records only,
in stand-in platforms (no MongoDB needed):
1. the rule: a spike is 1.5 times the day before and 500 more; a drop the other way round; a small day never is
2. communications: the cause is the infections that grew, with their report; services: the reports that grew
3. a day is counted as the platform shows it (external review of v2026.11.17): through the platform's own day reader
   (file-name day, never a scan of the whole history), inside the constituency, from memory when the day is held there
4. never counted while a page waits: in the background, once per change, kept while nothing changed
5. the answer holds counts and names only (no address), and features.py installs it
6. who may ask: the platforms, management, researchers and admins; nobody else
Run: .venv/bin/python tests/check_spike_notice.py"""
import collections
import json
import os
import sys
import threading
import time
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from flask import Flask, g  # noqa: E402

import spike_notice as SN  # noqa: E402

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info else ""), flush=True)


DAY = datetime(2026, 11, 15, tzinfo=timezone.utc)
PREV = DAY - timedelta(days=1)


def recs(when, infection, n, asn=64500):
    return [{"_t": (when + timedelta(hours=3)).timestamp(), "infection": infection, "src_ip": f"192.0.2.{i % 250}",
             "src_asn": asn, "dst_ip": "", "dst_asn": None, "ip": f"192.0.2.{i % 250}", "asn": asn} for i in range(n)]


class Platform:
    """A stand-in for a platform's day store: rows per report per day, its day reader and its signature."""
    def __init__(self, data, sources, by_infection, held=None):
        self.data, self.srcs, self.by_inf, self.held = data, sources, by_infection, held or {}
        self.reads, self.sigs, self.version, self.restricted, self.allowed = [], 0, 1, False, set()

    def fetch(self, src, start, end):
        self.reads.append((src["name"], start))
        return [dict(e) for e in self.data.get(src["name"], {}).get(start, [])], None

    def signature(self, start):
        self.sigs += 1
        return {n: len(d.get(start, [])) for n, d in self.data.items() if d.get(start)}

    def parts(self):
        return {"sources": lambda: self.srcs, "signature": self.signature, "fetch": self.fetch,
                "loaded": lambda s: self.held.get(s), "version": lambda: self.version,
                "in_scope": lambda e: not self.restricted or (e.get("asn") or e.get("src_asn")) in self.allowed,
                "by_infection": self.by_inf}


COMMS = [{"name": "event4_sinkhole", "label": "Sinkhole"}, {"name": "event4_sinkhole_http", "label": "Sinkhole HTTP"},
         {"name": "event4_sinkhole_dns", "label": "Sinkhole DNS"}]
SVC = [{"name": "scan_rdp", "label": "Accessible RDP"}, {"name": "scan_ssh", "label": "Accessible SSH"}]
comms = Platform({
    "event4_sinkhole": {PREV: recs(PREV, "android.vo1d2", 1500), DAY: recs(DAY, "android.vo1d2", 3500) + recs(DAY, "glassworm", 40)},
    "event4_sinkhole_http": {PREV: recs(PREV, "android.badbox2", 1000), DAY: recs(DAY, "android.badbox2", 2200, asn=64999)},
    "event4_sinkhole_dns": {PREV: recs(PREV, "x.dns", 500), DAY: recs(DAY, "x.dns", 510)}}, COMMS, True)
svc = Platform({"scan_rdp": {PREV: recs(PREV, None, 300), DAY: recs(DAY, None, 2000)},
                "scan_ssh": {PREV: recs(PREV, None, 4000), DAY: recs(DAY, None, 4100)}}, SVC, False)
LBL = lambda srcs: {s["name"]: s["label"] for s in srcs}   # noqa: E731

print("1. The rule")
ok("1.5 times the day before and 500 more: a spike", SN.kind_of(3000, 2000) == "spike")
ok("the other way round: a drop", SN.kind_of(2000, 3000) == "drop")
ok("a doubling of a small day is not a spike (fewer than 500 more)", SN.kind_of(800, 400) == "")
ok("500 more but less than 1.5 times: not a spike", SN.kind_of(10600, 10000) == "")
ok("the change in per cent, none when there was nothing the day before", SN.change_of(150, 100) == 50 and SN.change_of(5, 0) is None)

print("2. What is behind it")
cp = comms.parts()
c = SN.compare(SN.count_day(cp, DAY), SN.count_day(cp, PREV), LBL(COMMS), DAY, by_infection=True)
ok("communications: today and the day before, all reports together",
   c["today"] == 3500 + 40 + 2200 + 510 and c["before"] == 1500 + 1000 + 500 and c["kind"] == "spike", str({k: c[k] for k in ("today", "before", "kind")}))
ok("the cause is the infections that grew, with their report, biggest first",
   [(x["what"], x["report"]) for x in c["causes"]] == [("android.vo1d2", "Sinkhole"), ("android.badbox2", "Sinkhole HTTP")], str(c["causes"]))
ok("a small mover is left out (under a tenth of the change)", all(x["what"] not in ("glassworm", "x.dns") for x in c["causes"]))
sp_ = svc.parts()
s = SN.compare(SN.count_day(sp_, DAY), SN.count_day(sp_, PREV), LBL(SVC), DAY)
ok("services: a steady total (+42%) does not hide a report that jumped six-fold: noticed, naming it",
   s["kind"] == "spike" and s["scope"] == "part" and [x["what"] for x in s["causes"]] == ["Accessible RDP"], str(s))
ok("... and a whole-platform spike is marked as such", c["scope"] == "all")
one = Platform({"r": {PREV: recs(PREV, "big.steady", 9000) + recs(PREV, "new.one", 10), DAY: recs(DAY, "big.steady", 9100) + recs(DAY, "new.one", 900)}},
               [{"name": "r", "label": "Sinkhole"}], True).parts()
o = SN.compare(SN.count_day(one, DAY), SN.count_day(one, PREV), {"r": "Sinkhole"}, DAY, by_infection=True)
ok("communications: one infection that jumped inside a steady report is named, with its report",
   o["scope"] == "part" and [(x["what"], x["report"]) for x in o["causes"]] == [("new.one", "Sinkhole")], str(o))
flat = Platform({"d": {PREV: recs(PREV, "x.dns", 500), DAY: recs(DAY, "x.dns", 510)}}, [{"name": "d", "label": "D"}], True).parts()
f = SN.compare(SN.count_day(flat, DAY), SN.count_day(flat, PREV), {"d": "D"}, DAY, by_infection=True)
ok("a steady day: no notice and no cause", f["kind"] == "" and f["causes"] == [])
dr = Platform({"r": {PREV: recs(PREV, "a", 3000), DAY: recs(DAY, "a", 1000)}}, [{"name": "r", "label": "R"}], True).parts()
d = SN.compare(SN.count_day(dr, DAY), SN.count_day(dr, PREV), {"r": "R"}, DAY, by_infection=True)
ok("a drop names what fell", d["kind"] == "drop" and d["causes"] and d["causes"][0]["what"] == "a", str(d))

early = Platform({"a": {PREV: recs(PREV, "x", 30000), DAY: recs(DAY, "x", 2000)}, "b": {PREV: recs(PREV, "y", 20000)},
                  "c": {PREV: recs(PREV, "z", 9000)}, "d": {PREV: recs(PREV, "w", 7000)}}, [{"name": n, "label": n} for n in "abcd"], True).parts()
e = SN.compare(SN.count_day(early, DAY), SN.count_day(early, PREV), {}, DAY, by_infection=True)
ok("a day still arriving (1 report of the 4 the day before had) gives no notice, and says why (2026-11-17)",
   e["kind"] == "" and e["causes"] == [] and e["complete"] is False and (e["reports"], e["reports_before"]) == (1, 4), str(e))
ok("... a day with its reports in is compared as before", c["complete"] is True and c["kind"] == "spike")

print("3. Counted as the platform shows the day")
src = open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "spike_notice.py"), encoding="utf-8").read()
code = "\n".join(l for l in src.split('"""')[2::2])      # the code, not the docstrings
ok("no query of its own by extracted_date (unindexed: it read every record kept)",
   "extracted_date" not in code and "count_documents" not in code and "aggregate(" not in code)
comms.reads.clear()
SN.count_day(cp, DAY)
ok("each report's day is read through the platform's own day reader (file-name day, the event time in the day)",
   sorted(n for n, _ in comms.reads) == sorted(x["name"] for x in COMMS) and all(t == DAY for _, t in comms.reads))
comms.restricted, comms.allowed = True, {64500}
c2 = SN.count_day(cp, DAY)
ok("inside the constituency when one is set: a network outside it is not counted",
   "event4_sinkhole_http" not in c2 and sum(c2["event4_sinkhole"].values()) == 3540, str({k: sum(v.values()) for k, v in c2.items()}))
comms.restricted = False
held = Platform({}, COMMS, True, held={DAY: {"event4_sinkhole": recs(DAY, "android.vo1d2", 7)}})
hp_ = held.parts()
ok("a day the platform holds in memory is counted from there, without reading anything",
   SN.count_day(hp_, DAY) == {"event4_sinkhole": collections.Counter({"android.vo1d2": 7})} and held.reads == [])

print("4. Never while a page waits")
slow = threading.Event()
lazy = Platform(comms.data, COMMS, True)
lp = lazy.parts()
real_fetch = lp["fetch"]
lp["fetch"] = lambda *a: (slow.wait(5), real_fetch(*a))[1]
sp = SN.Spikes({"platforms": {"comms": lp}, "day_of": lambda p: DAY})
t0 = time.time()
first = sp.get()
ok("the first ask answers at once, with nothing yet, and starts the work in the background",
   first == {} and time.time() - t0 < 1 and "comms" in sp.running, f"{time.time() - t0:.2f}s")
ok("... a second ask meanwhile does not start a second count", sp.get() == {} and len(sp.running) == 1)
slow.set()
for _ in range(50):
    if "comms" not in sp.running:
        break
    time.sleep(0.1)
got = sp.get()
ok("once worked out, the answer is there", got.get("comms", {}).get("today") == c["today"], str(got)[:120])
sp2 = SN.Spikes({"platforms": {"comms": comms.parts(), "services": svc.parts()}, "day_of": lambda p: DAY})
a1 = sp2.get(wait=True)
comms.reads.clear()
sp2.cache["comms"]["at"] -= SN.CACHE_S + 1
a2 = sp2.get(wait=True)
ok("when its time is up but no report changed (the cheap indexed counts), nothing is read again",
   a1 == a2 and comms.reads == [] and set(a1) == {"comms", "services"})
comms.data["event4_sinkhole"][DAY] = comms.data["event4_sinkhole"][DAY] + recs(DAY, "android.vo1d2", 900)
sp2.cache["comms"]["at"] -= SN.CACHE_S + 1
a3 = sp2.get(wait=True)
ok("... and when a report grew, it is counted again", a3["comms"]["today"] == a1["comms"]["today"] + 900 and comms.reads)
comms.reads.clear()
comms.version += 1
sp2.cache["comms"]["at"] -= SN.CACHE_S + 1
sp2.get(wait=True)
ok("... and when the constituency changed, too", bool(comms.reads))
ok("a new replay day is never answered with the old day's notice",
   SN.Spikes({"platforms": {"comms": lp}, "day_of": lambda p: DAY + timedelta(days=1)}).get() == {})

print("5. Counts and names only")
ok("no address in the answer", "192.0.2." not in json.dumps(a1))

print("6. Who may ask")
app = Flask(__name__)
import features  # noqa: E402


class Store:
    def __init__(self, p):
        self.p, self.days, self.gen, self.settings = p, {}, 0, None

    def signature(self, s):
        return self.p.signature(s)

    def _fetch_collection(self, src, s, e):
        return self.p.fetch(src, s, e)

    _fetch = _fetch_collection


PERMS = {"analyst": {"view", "unmasked"}, "researcher": {"definitions"}, "management": {"management"}, "admin": {"settings"},
         "advisor": {"advisory"}, "auditor": {"audit"}}
settings = type("S", (), {"restricted": False, "version": 1, "in_scope": staticmethod(lambda a, i: True)})()
core = {"db": None, "registry": type("R", (), {"get": staticmethod(lambda: COMMS)})(), "store": Store(comms), "settings": settings,
        "svc": {"registry": type("R", (), {"get": staticmethod(lambda: SVC)})(), "store": Store(svc)},
        "replay_now": lambda: DAY + timedelta(hours=14), "day_start": lambda dt: dt.replace(hour=0, minute=0, second=0, microsecond=0),
        "AUTH": {"has_perm": lambda p: p in g.user["perms"]}, "app_logger": None}
inst = features.install(app, core)
ok("features.py installs it (app.py only calls features.install)", "spikes" in inst
   and "spike_notice" not in open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "app.py"), encoding="utf-8").read())
inst["spikes"].get(wait=True)


def ask(role):
    with app.test_request_context("/api/overview/spikes"):
        g.user = {"user": role, "role": role, "perms": PERMS[role]}
        r = app.view_functions["api_overview_spikes"]()
        code = r[1] if isinstance(r, tuple) else 200
        return code, (r[0] if isinstance(r, tuple) else r).get_json()


got = {r: ask(r)[0] for r in PERMS}
ok("analysts, researchers, management and admins get it; advisors and auditors do not",
   got == {"analyst": 200, "researcher": 200, "management": 200, "admin": 200, "advisor": 403, "auditor": 403}, str(got))
ok("the answer is the same counts as the comparison", ask("researcher")[1]["comms"]["today"] == a3["comms"]["today"])
import auth  # noqa: E402
ok("researchers' and management's pages may reach it (auth.py's lists)",
   any("/api/overview/spikes".startswith(p) for p in auth.DEFINITIONS_PATHS)
   and any("/api/overview/spikes".startswith(p) for p in auth.MANAGEMENT_PATHS))

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {fails}" if fails else ""))
sys.exit(1 if fails else 0)
