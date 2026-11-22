#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
# runs itself with the project's own Python (.venv), from wherever it is called
''''exec "$(dirname -- "$0")/../.venv/bin/python" "$0" "$@" # '''
"""Explore a match of "Looking Glass asks" (intel_match.py, 2026-11-15): every name and report of the match, each worked
out over ONLY the records that carry the indicator, side by side; only a match Looking Glass is asking about; no host.
Made-up days (documentation addresses and example domains only); no service, no database.
Usage: tests/check_intel_match.py"""
import datetime
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from flask import Flask  # noqa: E402
import intel  # noqa: E402
import intel_match  # noqa: E402

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info and not cond else ""), flush=True)


class Day:
    def __init__(self, events):
        self.start = datetime.datetime(2026, 11, 14, tzinfo=datetime.timezone.utc)
        self.serial, self.events = 1, events


class Store:
    def __init__(self, events):
        self.days = {"d": Day(events)}


SHARED = "blackfriday.example.net"
ev = []
for i in range(3):        # avalanche-generic in Sinkhole HTTP, calling the shared domain: its own tag and agent
    ev.append({"infection": "avalanche-generic", "source": "sh_http", "src_ip": f"192.0.2.{10 + i}", "http_host": SHARED,
               "http_agent": "AvaBot/1.0", "tag": ["avalanche", "banker"]})
for i in range(4):        # the same name, another domain: must NOT be in the match
    ev.append({"infection": "avalanche-generic", "source": "sh_http", "src_ip": f"192.0.2.{20 + i}", "http_host": "other.example.org",
               "http_agent": "Elsewhere/2.0", "tag": ["spam-only"]})
ev.append({"infection": "qsnatch", "source": "sh_dns", "src_ip": "198.51.100.7", "extras": {"query": SHARED}, "tag": ["qnap", "banker"]})
ev.append({"infection": "qsnatch", "source": "sh_dns", "src_ip": "198.51.100.8", "extras": {"query": "nas.example.com"}, "tag": ["qnap-other"]})

DENY = {"on": False}
ctx = {"store": Store(ev), "svc_store": Store([]), "labels": lambda: {"sh_http": "Sinkhole HTTP", "sh_dns": "Sinkhole DNS"},
       "defined": lambda: {("infections", "avalanche-generic"): "Avalanche", ("infections", "qsnatch"): "QSnatch"},
       "allowed": lambda: not DENY["on"]}
I = intel.Intel(ctx)
lead = next((x for x in I.leads()["leads"] if x["value"] == SHARED), None)
print("The match")
ok("Looking Glass asks about the shared domain (two names)", lead is not None and lead["priority"] == 3, str([(x["value"], x["priority"]) for x in I.leads()["leads"]]))

app = Flask(__name__)
mv = intel_match.install(app, I, ctx)
c = app.test_client()
r = c.get(f"/api/intel/match?kind=domain&value={SHARED}")
d = r.get_json() or {}
places = {(p["name"], p["report"]): p for p in d.get("places", [])}
ok("Explore answers with both places of the match", r.status_code == 200
   and set(places) == {("avalanche-generic", "Sinkhole HTTP"), ("qsnatch", "Sinkhole DNS")}, str(list(places)))
av, qs = places.get(("avalanche-generic", "Sinkhole HTTP"), {}), places.get(("qsnatch", "Sinkhole DNS"), {})
kinds = lambda p: {k["kind"]: [v["value"] for v in k["values"]] for k in p.get("indicators", [])}
print("Only the records that carry it")
ok("avalanche-generic: its 3 records with the domain, not its 7 in all", av.get("records") == 3 and av.get("devices") == 3, str(av.get("records")))
ok("…its own tags and agent; nothing from its records without the domain",
   set(kinds(av).get("Associated tags", [])) == {"avalanche", "banker"} and kinds(av).get("User agent") == ["AvaBot/1.0"]
   and "other.example.org" not in json.dumps(av) and "spam-only" not in json.dumps(av), json.dumps(kinds(av)))
ok("qsnatch: its 1 record with the domain looked up, its own tags", qs.get("records") == 1
   and set(kinds(qs).get("Associated tags", [])) == {"qnap", "banker"} and "qnap-other" not in json.dumps(qs), json.dumps(kinds(qs)))
ok("…the sets that travel with it on the same record are given per place",
   any(SHARED in c_["items"] for c_ in (av.get("combinations") or []) + ([av["single"]] if av.get("single") else [])))
ok("what Looking Glass stated comes with it", d.get("verdict") == "Shared by two names" and SHARED in d.get("text", ""))
print("The 5-device rule for codes, per viewer (review of 6da6a80)")
import small_codes  # noqa: E402
_sees = small_codes.viewer_sees_hosts
codes = lambda ans: [c_.get("code") for p in ans.get("places", []) for c_ in (p.get("combinations") or []) + ([p["single"]] if p.get("single") else [])]
small_codes.viewer_sees_hosts = lambda: True            # an admin (sees the devices) opens it first...
admin = c.get(f"/api/intel/match?kind=domain&value={SHARED}").get_json()
small_codes.viewer_sees_hosts = lambda: False           # ...then a researcher, within the hour, from the cache
res = c.get(f"/api/intel/match?kind=domain&value={SHARED}").get_json()
small_codes.viewer_sees_hosts = _sees
ok("the admin gets the codes of patterns on fewer than 5 devices", any(codes(admin)), str(codes(admin)))
ok("…the researcher after them does not (the cache keeps the scan, not the admin's answer)",
   codes(res) and not any(codes(res)), str(codes(res)))
print("No hosts, no free search")
body = r.get_data(as_text=True)
ok("no device address in the answer", not any(ip in body for ip in ("192.0.2.", "198.51.100.")))
r2 = c.get("/api/intel/match?kind=domain&value=other.example.org")
ok("a value Looking Glass is not asking about: 404, nothing gathered", r2.status_code == 404)
ok("kind and value are both needed", c.get("/api/intel/match?kind=domain").status_code == 400)

DENY["on"] = True
ok("only for researchers and admins (403 otherwise)", c.get(f"/api/intel/match?kind=domain&value={SHARED}").status_code == 403)

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
