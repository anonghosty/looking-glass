#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""The bell's report feed notices (system_alerts._report_feed, 2026-11-27): an installation whose daily read of the
report feed failed or stopped, and a feed builder on this computer that stopped running. Temporary folders only: no
database, no network, no live file. Run: .venv/bin/python tests/check_feed_alerts.py"""
import json
import os
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import system_alerts as SA  # noqa: E402

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    print(("  ok   " if cond else "  FAIL ") + label + ("" if cond else f"  [{info}]"))
    if not cond:
        fails.append(label)


def iso(t):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))


NOW = time.time()
tmp = tempfile.mkdtemp(prefix="lg-feed-alerts-")
base, builder = os.path.join(tmp, "platform"), os.path.join(tmp, "builder")
os.makedirs(os.path.join(base, "data")); os.makedirs(os.path.join(builder, "logs"))


def status(**kw):
    json.dump({"status": kw, "reports": {}}, open(os.path.join(base, "data", "report_map.json"), "w"))


def runs(*times):
    with open(os.path.join(builder, "logs", "feed-2026-11.log"), "w") as f:
        for t in times:
            f.write(f"== {iso(t)}\npages: 0 read of 0 due (120 in all), 0 changed, 0 failed\n")


def keys(env=None):
    a = SA.Alerts(base, env=env if env is not None else {"FEED_BUILDER_DIR": builder})
    return {x["key"].split(":")[0]: x for x in a._report_feed(NOW)}


print("1. The installation's daily read")
status(feed_checked=iso(NOW - 3600), feed_error="", feed_built=iso(NOW - 3 * 86400))
runs(NOW - 1800)
k = keys()
ok("a read an hour ago, a feed built 3 days ago (nothing changed at Shadowserver): no notice", not k, list(k))
status(feed_checked=iso(NOW - 3 * 86400), feed_error="")
ok("no read for 3 days: 'The report feed could not be read'", "report-feed-read" in keys(), list(keys()))
status(feed_checked=iso(NOW - 600), feed_error="URLError: <urlopen error timed out>")
k = keys()
ok("a read that failed: the notice, with the error", "report-feed-read" in k and "timed out" in k["report-feed-read"]["text"], list(k))
ok("...an administrator's problem, linked to the Task monitor",
   k.get("report-feed-read", {}).get("problem") is True and k["report-feed-read"]["link"] == "/settings#monitor")

print("2. The builder on this computer")
status(feed_checked=iso(NOW - 600), feed_error="")
runs(NOW - 7200, NOW - 3600)
ok("the builder ran an hour ago: no notice", "report-feed-builder" not in keys(), list(keys()))
runs(NOW - 20 * 86400, NOW - 19 * 86400)
k = keys()
ok("its last run 19 days ago (10-23 Nov): 'The report feed builder has stopped'", "report-feed-builder" in k, list(k))
ok("...naming when it last ran and what to check", k.get("report-feed-builder") and iso(NOW - 19 * 86400)[:10] in k["report-feed-builder"]["text"]
   and "run_feed.sh" in k["report-feed-builder"]["text"])
open(os.path.join(builder, "logs", "feed-2026-11.log"), "w").write("garbage\n")
ok("a log with no run in it: the notice too", "report-feed-builder" in keys(), list(keys()))
ok("no builder on this computer (an ordinary installation): no builder notice",
   "report-feed-builder" not in keys({"FEED_BUILDER_DIR": os.path.join(tmp, "nowhere")}), list(keys({"FEED_BUILDER_DIR": os.path.join(tmp, "nowhere")})))

print("3. In the bell")
runs(NOW - 20 * 86400)
cur = SA.Alerts(base, env={"FEED_BUILDER_DIR": builder}).current()
ok("the bell's list carries the builder notice", any(a["key"].startswith("report-feed-builder:") for a in cur), [a["key"] for a in cur][:8])
ok("the notices come back each day (the day is in the key)", any(a["key"].endswith(time.strftime("%Y-%m-%d", time.gmtime(time.time()))) for a in cur
                                                                    if a["key"].startswith("report-feed")))
ok("no report_map.json at all (a new installation before its first read): no error, no read notice",
   (os.remove(os.path.join(base, "data", "report_map.json")) or True) and "report-feed-read" not in keys())

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
