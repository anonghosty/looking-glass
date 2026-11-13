#!/usr/bin/env python3
"""Who views host-level data is logged (data_access.py; CIS 3.14 "Log Sensitive Data Access", review 2026-11-13): one
audit entry per view of one host's activity, the hosts behind a figure, a record's details or an analysis, and per host-list
download; who and what, hosts by reference, NEVER an address; not twice for the same view within the window; never for
a failed or non-GET request, the self-test or an unrelated page; off with DATA_ACCESS_LOG=0. No database needed.
Run: .venv/bin/python tests/check_data_access.py"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from flask import Flask, g, request  # noqa: E402

import data_access  # noqa: E402

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info and not cond else ""))


entries = []
app = Flask(__name__)


@app.before_request
def _who():
    g.user = {"user": request.headers.get("X-User", "")}


for path in list(data_access.SENSITIVE) + ["/api/clock"]:
    app.add_url_rule(path, path, (lambda **kw: ("ok", 200)), methods=["GET", "POST"])
app.add_url_rule("/api/missing", "missing", lambda: ("no", 404))

data_access.register(app, lambda event, **kw: entries.append({"event": event, **kw}),
                     lambda: (getattr(g, "user", None) or {}).get("user", ""), lambda ip: "R" + str(abs(hash(ip)) % 10_000))
c = app.test_client()
get = lambda path, user="daniel", **q: c.get(path, query_string=q, headers={"X-User": user})

print("Views of host-level data are logged")
get("/api/related", ref="h-abc123")
e = entries[-1] if entries else {}
ok("one host's activity: logged with who and what", e.get("event") == "data_viewed" and e.get("user") == "daniel"
   and e.get("target") == "one host's activity (map)" and "ref=h-abc123" in e.get("detail", ""), str(e))
n = len(entries)
get("/api/insight", kind="src_ip", value="203.0.113.5")
e = entries[-1]
ok("an analysis of an address: logged, the address replaced by its host reference",
   len(entries) == n + 1 and "203.0.113.5" not in e["detail"] and "value=host R" in e["detail"], e["detail"])
get("/api/svc/drill", metric="hosts", issue="CVE-2024-3400")
ok("the hosts behind a figure (services): logged with the selection",
   entries[-1]["target"] == "hosts behind a figure (services)" and "issue=CVE-2024-3400" in entries[-1]["detail"])
get("/api/svc/detail", id="r-42")
ok("a record's details: logged", entries[-1]["target"] == "a record's details (services)")
get("/api/svc/hosts.csv", service="Accessible RDP")
ok("the services host-list download is logged as an export (it had no audit entry before)",
   entries[-1]["event"] == "data_exported" and "service=Accessible RDP" in entries[-1]["detail"])
ok("no entry ever holds an IP address", not any("203.0.113" in str(x) for x in entries))

print("…and only those")
n = len(entries)
get("/api/related", ref="h-abc123")
ok("the same person, the same view, again within the window: not logged twice", len(entries) == n)
get("/api/related", ref="h-abc123", user="grace")
ok("…another person viewing it is logged", len(entries) == n + 1 and entries[-1]["user"] == "grace")
n = len(entries)
get("/api/related", ref="h-other")
ok("…another host is logged", len(entries) == n + 1)
n = len(entries)
c.post("/api/related", headers={"X-User": "daniel"}, query_string={"ref": "h-post"})
get("/api/missing")
get("/api/clock")
get("/api/related", user="lg-selftest-admin", ref="h-x")
get("/api/related", user="", ref="h-anon")
ok("POST, a failed answer, an unrelated page, the self-test and no user: none logged", len(entries) == n, str(entries[n:]))
os.environ["DATA_ACCESS_LOG"] = "0"
get("/api/related", ref="h-off")
ok("DATA_ACCESS_LOG=0 turns it off", len(entries) == n and not data_access.enabled())
os.environ.pop("DATA_ACCESS_LOG")

print("Every download is its own entry, the same list twice included (review 2026-11-13)")
n = len(entries)
get("/api/svc/hosts.csv", service="Accessible RDP")
get("/api/svc/hosts.csv", service="Accessible RDP")
ok("the same host list downloaded twice within the window: two entries", len(entries) == n + 2
   and all(x["event"] == "data_exported" for x in entries[n:]), str(entries[n:]))
n = len(entries)
get("/api/svc/drill", metric="hosts", issue="CVE-2024-9999")
get("/api/svc/drill", metric="hosts", issue="CVE-2024-9999")
ok("…while the same view twice is still one entry", len(entries) == n + 1, str(entries[n:]))

print("Every filter is recorded, so different hosts are different views (review 2026-11-13)")
n = len(entries)
get("/api/events", src_ip="203.0.113.7")
get("/api/events", src_ip="203.0.113.8")
ok("the map's events are logged (they were not), one entry per host filtered on", len(entries) == n + 2, str(entries[n:]))
ok("…src_ip recorded as the host's reference, never the address",
   all("src_ip=host R" in x["detail"] and "203.0.113" not in x["detail"] for x in entries[n:]), str(entries[n:]))
n = len(entries)
get("/api/svc/drill", metric="hosts", port="3389", country="GH", asn="AS64500", tag="rdp")
d = entries[-1]["detail"] if len(entries) > n else ""
ok("services filters are all in the entry (port, country, asn, tag)",
   all(f in d for f in ("port=3389", "country=GH", "asn=AS64500", "tag=rdp")), d)
n = len(entries)
c.get("/api/events", query_string=[("src_ip", "203.0.113.20"), ("src_ip", "203.0.113.21")], headers={"X-User": "daniel"})
ok("a parameter given twice: both values recorded", len(entries) == n + 1 and entries[-1]["detail"].count("src_ip=host R") == 2,
   entries[-1]["detail"] if len(entries) > n else "")
n = len(entries)
get("/api/events", at="2026-11-13T10:00:00", demo="0", limit="500")
get("/api/events", at="2026-11-13T10:05:00", demo="0", limit="200")
ok("display and time options alone do not make a new view", len(entries) == n + 1, str(entries[n:]))
n = len(entries)
get("/api/related", **{"203.0.113.9": "1"})
ok("an address typed as a parameter name is masked too", len(entries) == n + 1 and "203.0.113" not in entries[-1]["detail"],
   entries[-1]["detail"] if len(entries) > n else "")
print("A long value is cut before the address finder reads it (review 2026-11-13: the CPU could be tied up)")
import time as _t  # noqa: E402
n = len(entries)
t0 = _t.perf_counter()
get("/api/insight", kind="src_ip", value=":" * 8000 + "1")
took = _t.perf_counter() - t0
ok(f"8,000 colons in value=: logged in {took:.3f} s (under 0.2 s)", len(entries) == n + 1 and took < 0.2)
n = len(entries)
get("/api/insight", kind="x", value="a" * 115 + "203.0.113.45")
ok("an address cut in half at the limit leaves none of its digits", len(entries) == n + 1
   and not any(p in entries[-1]["detail"] for p in ("203.0", "203.", "113.4")), entries[-1]["detail"] if len(entries) > n else "")
ok("no entry ever holds an IP address (all of the above)", not any("203.0.113" in str(x) for x in entries))

print("A drill-down list saved as a CSV (download=1) is an export, every time (review 2026-11-13)")
n = len(entries)
get("/api/insight/drill", kind="infection", value="mirai", metric="hosts", all="1", download="1")
get("/api/insight/drill", kind="infection", value="mirai", metric="hosts", all="1", download="1")
get("/api/svc/drill", metric="hosts", service="Accessible RDP", all="1", download="1")
ok("map and services lists: one export entry per download, the same list twice included", len(entries) == n + 3
   and [x["event"] for x in entries[n:]] == ["data_exported"] * 3
   and entries[n]["target"] == "host list download (map CSV)" and entries[-1]["target"] == "host list download (services CSV)", str(entries[n:]))
ok("…with the selection, not the download options", "value=mirai" in entries[n]["detail"] and "download" not in entries[n]["detail"], entries[n]["detail"])

print("An advisor opening one organisation's advisory (its IP addresses) is logged (review 2026-11-13)")
n = len(entries)
get("/api/advisory/F-17/net", user="sarah", network="Example Telecom")
e = entries[-1] if len(entries) > n else {}
ok("logged by its route, with the finding and the organisation", e.get("event") == "data_viewed" and e.get("user") == "sarah"
   and e.get("target") == "an organisation's hosts (advisory)" and "fid=F-17" in e.get("detail", "")
   and "network=Example Telecom" in e.get("detail", ""), str(e))
get("/api/advisory/F-17/net", user="sarah", network="Example Telecom")
ok("…once per window, like every view", len(entries) == n + 1)
get("/api/advisory/F-18/net", user="sarah", network="Example Telecom")
ok("…another finding is another view", len(entries) == n + 2)
n = len(entries)
get("/advisory/F-17/preview", user="sarah", network="Example Telecom")
e = entries[-1] if len(entries) > n else {}
ok("the advisory's PDF preview is logged too (review 2026-11-13)", e.get("target") == "an organisation's advisory report (preview)"
   and "fid=F-17" in e.get("detail", ""), str(e))

print("CIS 3.14 follows it")
import control_map as CM  # noqa: E402
ok("LG-15 backs 3.14 while views are logged", CM.lg_reading("LG-15", "3.14", {"data_access_logged": True})["status"] == "backed")
ok("…and is only related, saying why, when they are not",
   CM.lg_reading("LG-15", "3.14", {"data_access_logged": False})["status"] == "related"
   and "DATA_ACCESS_LOG=0" in CM.lg_reading("LG-15", "3.14", {"data_access_logged": False})["note"])

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
