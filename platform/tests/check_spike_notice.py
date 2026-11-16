#!/usr/bin/env python3
"""The spike notice on the Overview's buttons (spike_notice.py, features.py; the user, 2026-11-16). Made-up records only,
in a stand-in database (no MongoDB needed):
1. the rule: a spike is 1.5 times the day before and 500 more; a drop the other way round; a small day never is
2. communications: the cause is the infections that grew, with their report; services: the reports that grew
3. the answer holds counts and names only (no address), is kept per day, and features.py installs it
4. who may ask: the platforms, management, researchers and admins; nobody else
Run: .venv/bin/python tests/check_spike_notice.py"""
import json
import os
import sys
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


def _in(v, cond):
    lo, hi = cond["$gte"], cond["$lt"]
    if isinstance(lo, str):
        return isinstance(v, str) and lo <= v < hi
    return isinstance(v, datetime) and lo <= v < hi


def _match(doc, q):
    return any(_in(doc.get("extracted_date"), alt["extracted_date"]) for alt in q["$or"])


class Coll:
    def __init__(self, docs):
        self.docs = docs

    def count_documents(self, q):
        return sum(1 for d in self.docs if _match(d, q))

    def aggregate(self, pipe):
        rows = [d for d in self.docs if _match(d, pipe[0]["$match"])]
        out = {}
        for d in rows:
            out[d.get("infection")] = out.get(d.get("infection"), 0) + 1
        return [{"_id": k, "n": v} for k, v in out.items()]


DAY = datetime(2026, 11, 15, tzinfo=timezone.utc)
PREV = DAY - timedelta(days=1)


def recs(when, infection, n, as_text=False):
    t = when + timedelta(hours=3)
    return [{"extracted_date": t.strftime("%Y-%m-%dT%H:%M:%S") if as_text else t, "infection": infection,
             "src_ip": f"192.0.2.{i % 250}"} for i in range(n)]


db = {
    "event4_sinkhole": Coll(recs(PREV, "android.vo1d2", 1500) + recs(DAY, "android.vo1d2", 3500) + recs(DAY, "glassworm", 40)),
    "event4_sinkhole_http": Coll(recs(PREV, "android.badbox2", 1000) + recs(DAY, "android.badbox2", 2200, as_text=True)),
    "event4_sinkhole_dns": Coll(recs(PREV, "x.dns", 500) + recs(DAY, "x.dns", 510)),
    "scan_rdp": Coll(recs(PREV, None, 300) + recs(DAY, None, 2000)),
    "scan_ssh": Coll(recs(PREV, None, 4000) + recs(DAY, None, 4100)),
}
COMMS = [{"name": "event4_sinkhole", "label": "Sinkhole"}, {"name": "event4_sinkhole_http", "label": "Sinkhole HTTP"},
         {"name": "event4_sinkhole_dns", "label": "Sinkhole DNS"}]
SVC = [{"name": "scan_rdp", "label": "Accessible RDP"}, {"name": "scan_ssh", "label": "Accessible SSH"}]

print("1. The rule")
ok("1.5 times the day before and 500 more: a spike", SN.kind_of(3000, 2000) == "spike")
ok("the other way round: a drop", SN.kind_of(2000, 3000) == "drop")
ok("a doubling of a small day is not a spike (fewer than 500 more)", SN.kind_of(800, 400) == "")
ok("500 more but less than 1.5 times: not a spike", SN.kind_of(10600, 10000) == "")
ok("the change in per cent, none when there was nothing the day before", SN.change_of(150, 100) == 50 and SN.change_of(5, 0) is None)

print("2. What is behind it")
c = SN.compare(db, COMMS, DAY, by_infection=True)
ok("communications: today and the day before, all reports together (dates stored either way)",
   c["today"] == 3500 + 40 + 2200 + 510 and c["before"] == 1500 + 1000 + 500 and c["kind"] == "spike", str({k: c[k] for k in ("today", "before", "kind")}))
ok("the cause is the infections that grew, with their report, biggest first",
   [(x["what"], x["report"]) for x in c["causes"]] == [("android.vo1d2", "Sinkhole"), ("android.badbox2", "Sinkhole HTTP")],
   str(c["causes"]))
ok("a small mover is left out (under a tenth of the change)", all(x["what"] not in ("glassworm", "x.dns") for x in c["causes"]))
s = SN.compare(db, SVC, DAY)
ok("services: a steady total (+42%) does not hide a report that jumped six-fold: noticed, naming it",
   s["kind"] == "spike" and s["scope"] == "part" and [x["what"] for x in s["causes"]] == ["Accessible RDP"], str(s))
ok("... and a whole-platform spike is marked as such", c["scope"] == "all")
one = SN.compare({"r": Coll(recs(PREV, "big.steady", 9000) + recs(DAY, "big.steady", 9100) + recs(PREV, "new.one", 10) + recs(DAY, "new.one", 900))},
                 [{"name": "r", "label": "Sinkhole"}], DAY, by_infection=True)
ok("communications: one infection that jumped inside a steady report is named, with its report",
   one["scope"] == "part" and [(x["what"], x["report"]) for x in one["causes"]] == [("new.one", "Sinkhole")], str(one))
flat = SN.compare(db, [{"name": "event4_sinkhole_dns", "label": "Sinkhole DNS"}], DAY, by_infection=True)
ok("a steady day: no notice and no cause", flat["kind"] == "" and flat["causes"] == [])
drop = SN.compare({"r": Coll(recs(PREV, "a", 3000) + recs(DAY, "a", 1000))}, [{"name": "r", "label": "R"}], DAY, by_infection=True)
ok("a drop names what fell", drop["kind"] == "drop" and drop["causes"] and drop["causes"][0]["what"] == "a", str(drop))

print("3. Counts and names only, kept per day")
ok("no address in the answer", "192.0.2." not in json.dumps(c) + json.dumps(s))
calls = []
sp = SN.Spikes({"db": db, "comms_sources": lambda: (calls.append(1), COMMS)[1], "svc_sources": lambda: SVC,
                "day_of": lambda p: DAY})
a1, a2 = sp.get(), sp.get()
ok("worked out once per day, then kept", a1 == a2 and len(calls) == 1 and set(a1) == {"comms", "services"})

print("4. Who may ask")
app = Flask(__name__)
import features  # noqa: E402
PERMS = {"analyst": {"view", "unmasked"}, "researcher": {"definitions"}, "management": {"management"}, "admin": {"settings"},
         "advisor": {"advisory"}, "auditor": {"audit"}}
core = {"db": db, "registry": type("R", (), {"get": staticmethod(lambda: COMMS)})(),
        "svc": {"registry": type("R", (), {"get": staticmethod(lambda: SVC)})()},
        "replay_now": lambda: DAY + timedelta(hours=14), "day_start": lambda dt: dt.replace(hour=0, minute=0, second=0, microsecond=0),
        "AUTH": {"has_perm": lambda p: p in g.user["perms"]}, "app_logger": None}
inst = features.install(app, core)
ok("features.py installs it (app.py only calls features.install)", "spikes" in inst
   and "spike_notice" not in open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "app.py"), encoding="utf-8").read())


def ask(role):
    with app.test_request_context("/api/overview/spikes"):
        g.user = {"user": role, "role": role, "perms": PERMS[role]}
        r = app.view_functions["api_overview_spikes"]()
        code = r[1] if isinstance(r, tuple) else 200
        return code, (r[0] if isinstance(r, tuple) else r).get_json()


got = {r: ask(r)[0] for r in PERMS}
ok("analysts, researchers, management and admins get it; advisors and auditors do not",
   got == {"analyst": 200, "researcher": 200, "management": 200, "admin": 200, "advisor": 403, "auditor": 403}, str(got))
ok("the answer is the same counts as the comparison", ask("researcher")[1]["comms"]["today"] == c["today"])
import auth  # noqa: E402
ok("researchers' and management's pages may reach it (auth.py's lists)",
   any("/api/overview/spikes".startswith(p) for p in auth.DEFINITIONS_PATHS)
   and any("/api/overview/spikes".startswith(p) for p in auth.MANAGEMENT_PATHS))

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {fails}" if fails else ""))
sys.exit(1 if fails else 0)
