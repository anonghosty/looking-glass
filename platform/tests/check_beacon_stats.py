#!/usr/bin/env python3
"""Beacons on the analyst's map (beacon_stats.py; the user, 2026-11-16): the Beacon filter, the "Decoded beacons" figure
and its Details list. Made-up check-ins only (tests/beacon_samples.py, addresses from 192.0.2.0/24).
1. the module: labels, filter options, counts and the Details list; a label is worked out once per record
2. the map's filter logic (app.py matches/parse_filters/public): the beacon filter narrows, the label never reaches the
   browser
3. who sees it: analysts get the options, the figure and the list; masked viewers none of them
Part 2 and 3 need the platform (MongoDB); without it they are skipped and part 1 still runs.
Run: .venv/bin/python tests/check_beacon_stats.py"""
import json
import os
import sys
import time
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault("LG_QUIET", "1")
os.environ.setdefault("THREATMAP_SCHEDULE", "0")
import beacon_decode as B  # noqa: E402
import beacon_stats as BS  # noqa: E402
from beacon_samples import encode, line, made_up, rkey  # noqa: E402

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info else ""), flush=True)


def decodable(o):
    """A request line for a made-up check-in under a key the decoder recovers (an odd random key does not: that limit
    is check_beacon_decode's business; this test is about the counts)."""
    for _ in range(50):
        u = line(encode(o, rkey()))
        if B.first(u):
            return u
    raise SystemExit("no decodable sample: the decoder changed")


def ev(i, o=None, url=None, inf="android.badbox2"):
    return {"src_ip": f"192.0.2.{20 + i}", "infection": inf, "source": "event4_sinkhole_http", "severity": "high",
            "http_url": url if url is not None else decodable(o), "http_host": "c2.example", "_t": 1763280000 + i * 60}


win = [ev(i, made_up(i, operator="WT", version="WT:1.0.0")) for i in range(4)]
win.append(ev(1, made_up(9, operator="WT", version="WT:1.0.1")))           # a second check-in from the same device
andr = [ev(10 + i, made_up(10 + i, os_name="android", operator="HTM", version="HTM:2.0")) for i in range(2)]
plain = [ev(30, url="GET /index.html HTTP/1.1"), ev(31, url="", inf="other")]
cut = [ev(40, url=line("A" * 40))]                                        # at the format's place, does not decode
events = win + andr + plain + cut
title = B.first(win[0]["http_url"])["title"]

print("1. The module")
lw, la = BS.label(win[0]), BS.label(andr[0])
ok("a Windows check-in is labelled with its format and system", lw == f"{title}, Windows", lw)
ok("an Android one too", la == f"{title}, Android", la)
ok("a record without a beacon has no label", BS.label(plain[0]) == "" and BS.label(plain[1]) == "")
lc = BS.label(cut[0])
ok("a value at the format's place that does not decode says so, and is not counted as decoded",
   lc == f"{title} (did not decode)" and BS.state(cut[0]) == "cut" and not BS.decoded(cut[0]), lc)
with mock.patch.object(B, "field", side_effect=AssertionError("decoded again")):
    try:
        again = BS.label(win[0])
        ok("the label is kept on the record: asked again, nothing is decoded again", again == lw)
    except AssertionError:
        ok("the label is kept on the record: asked again, nothing is decoded again", False)
rows = BS.facet_rows(events)
ok("filter options: one per label, most common first, with counts",
   rows[0] == {"value": lw, "count": 5} and {"value": la, "count": 2} in rows and len(rows) == 3, rows)
c = BS.counts(events)
ok("Decoded beacons counts decoded records only (5 Windows + 2 Android)", c["decoded_beacons"] == 7, c)
ok("...and devices once each (4 Windows + 2 Android)", c["beacon_devices"] == 6, c)
d = BS.drill(events, mt=lambda s: "masked:" + s)
r0 = d["rows"][0]
ok("the Details list: one row per beacon kind, decoded first, the rest last",
   [r["value"] for r in d["rows"]] == [lw, la, lc], [r["value"] for r in d["rows"]])
ok("a row gives operators, versions, records and devices",
   r0["operators"] == ["WT"] and set(r0["versions"]) == {"WT:1.0.0", "WT:1.0.1"} and r0["events"] == 5 and r0["hosts"] == 4, r0)
ok("...the names Shadowserver filed it under and the C2 domains (through the caller's mask)",
   r0["infections"] == ["android.badbox2"] and r0["domains"] == ["masked:c2.example"], r0)
ok("rows open the Beacon filter (row_kind beacon) and every column has a heading",
   d["row_kind"] == "beacon" and all(k in r0 for k, _ in d["columns"]))
ok("its Status column says what each value is (decoded, or encoded but did not decode)",
   d["rows"][0]["status"] == "Decoded" and d["rows"][-1]["status"].startswith("Encoded in a known format")
   and ["status", "Status"] in d["columns"], str([r["status"] for r in d["rows"]]))
ok("the introduction counts the same records and devices as the figure", "7 records" in d["intro"] and "6 devices" in d["intro"], d["intro"])
ok("no device identifier from the check-in is in the list",
   not any(str(v) in json.dumps(d) for o in [made_up(0, operator="WT", version="WT:1.0.0")] for k, v in o.items()
           if k in ("cpumd5", "mac", "uuid")))
ok("nothing says what to do about it (facts only)", "recommend" not in json.dumps(d).lower())
ok("an empty selection gives an empty list and a plain message", BS.drill([])["rows"] == [] and BS.drill([])["empty"])
Day = type("Day", (), {})
day = Day()
day.events = [{k: v for k, v in e.items() if k != "_bc"} for e in events]
first_answer = BS.ready(day)
t0 = time.time()
while not BS.ready(day) and time.time() - t0 < 60:
    time.sleep(0.1)
ok("a loaded day is labelled in the background: not ready at first, ready soon after", first_answer is False and BS.ready(day))
ok("...every record then has its label", all("_bc" in e for e in day.events)
   and [BS.label(e) for e in day.events] == [BS.label(e) for e in events]
   and [BS.state(e) for e in day.events] == [BS.state(e) for e in events])

print("2. The map's filter logic")
try:
    if os.environ.get("LG_UNIT_ONLY") == "1":                # the module part only (no platform, no database)
        raise RuntimeError("LG_UNIT_ONLY")
    import app as A  # noqa: E402
    from flask import g  # noqa: E402
    from werkzeug.datastructures import MultiDict  # noqa: E402
except Exception as e:                                       # no MongoDB here (the no-database CI run)
    A = None
    print(f"  skipped: the platform did not start ({type(e).__name__})")
if A is not None:
    with A.app.test_request_context("/"):
        flt = A.parse_filters(MultiDict([("beacon", la)]))
    ok("the beacon filter is read from the address", flt == {"beacon": {la}}, flt)
    got = [e for e in events if A.matches(e, flt)]
    ok("it keeps exactly the records with that beacon", got == andr, len(got))
    both = {"beacon": {la}, "infection": {"android.badbox2"}}
    ok("...and works with the other filters", [e for e in events if A.matches(e, both)] == andr)
    with A.app.test_request_context("/"):
        g.user = {"user": "lg-check-beacon", "role": "analyst", "perms": {"view", "unmasked"}, "csrf": None, "automation": True}
        pub = A.public(dict(win[0], src_ref="r1", src_asn="", dst_asn=""))
    ok("the per-record label never reaches the browser", "_bc" not in pub and "_t" not in pub)

    print("3. Who sees it")

    def call(path, masked):
        with A.app.test_request_context(path):
            g.user = {"user": "lg-check-beacon", "role": "researcher" if masked else "analyst",
                      "perms": {"view"} | (set() if masked else {"unmasked"}), "csrf": None, "automation": True}
            ep = A.app.url_map.bind("localhost").match(path.split("?")[0])
            r = A.app.view_functions[ep[0]](**ep[1])
            code = r[1] if isinstance(r, tuple) else r.status_code
            return code, json.loads((r[0] if isinstance(r, tuple) else r).get_data(as_text=True) or "{}")

    _, fa = call("/api/facets", False)
    t0 = time.time()
    while fa.get("beacon_pending") and time.time() - t0 < 600:      # the day's labelling runs in the background
        time.sleep(2)
        _, fa = call("/api/facets", False)
    _, fm = call("/api/facets", True)
    ok("analysts get the Beacon filter's options", isinstance(fa.get("beacon"), list), type(fa.get("beacon")).__name__)
    ok("masked viewers do not", "beacon" not in fm)
    src = (fa.get("source") or [{}])[0].get("value")
    if not src:
        print("  no day loaded: the figure checks are skipped")
    else:
        _, ia = call(f"/api/insight?kind=source&value={src}", False)
        _, im = call(f"/api/insight?kind=source&value={src}", True)
        ok("analysts get the Decoded beacons figure", isinstance(ia.get("decoded_beacons"), int), ia.get("decoded_beacons"))
        ok("masked viewers do not", "decoded_beacons" not in im and "beacon_devices" not in im)
        _, da = call(f"/api/insight/drill?kind=source&value={src}&metric=beacons", False)
        _, dm = call(f"/api/insight/drill?kind=source&value={src}&metric=beacons", True)
        ok("analysts get the Details list", da.get("title") == "Decoded beacons" and da.get("row_kind") == "beacon", da.get("title"))
        ok("its records add up to the figure",
           sum(r["events"] for r in da.get("rows", []) if r["decoded"] == "Yes") == ia.get("decoded_beacons")
           or da.get("total", 0) > len(da.get("rows", [])))
        ok("masked viewers get an empty list", dm.get("rows") == [] and dm.get("total") == 0, dm.get("total"))

print(f"\n{checks - len(fails)}/{checks} passed" + (f"; FAILED: {fails}" if fails else ""))
sys.exit(1 if fails else 0)
