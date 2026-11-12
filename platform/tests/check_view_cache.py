#!/usr/bin/env python3
"""Cached answers are the same answers (external review, 2026-11-12: the services analysis took ~1.4 s on every
request and the replayed counters went through the whole day on every 2-3 s poll). On the installation's own day:
1. the replayed counters (services and map), now a binary search over a selection's records found once, give exactly
   what the old whole-day count gives, at several replay moments and for several selections;
2. the services analysis, its drill-down lists and the regions map, now kept per day and selection, agree with each
   other and with the figures, keep the per-request "as of" moment current, and are served from the cache afterwards;
   a "show all" list is worked out every time and starts with the cached list.
Exits 77 (skipped) when no day is loaded yet.
Run: .venv/bin/python tests/check_view_cache.py"""
import bisect, json, os, sys, time
from urllib.parse import quote, urlencode
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("LG_QUIET", "1")
os.environ.setdefault("THREATMAP_SCHEDULE", "0")
import app as A  # noqa: E402
from flask import g  # noqa: E402
from werkzeug.datastructures import MultiDict  # noqa: E402

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond: fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info else ""), flush=True)


def call(path, demo=False):
    with A.app.test_request_context(path):
        perms = {"view", "export"} | (set() if demo else {"unmasked"})
        g.user = {"user": "lg-check-cache", "role": "admin", "perms": perms, "csrf": None, "automation": True}
        ep = A.app.url_map.bind("localhost").match(path.split("?")[0])
        t = time.perf_counter()
        r = A.app.view_functions[ep[0]](**ep[1])
        ms = (time.perf_counter() - t) * 1000
        code = r[1] if isinstance(r, tuple) else r.status_code
        return code, json.loads((r[0] if isinstance(r, tuple) else r).get_data(as_text=True) or "{}"), ms


code, facets, _ = call("/api/svc/facets")
if code != 200 or not facets.get("total"):
    print("no services day loaded yet: skipped"); sys.exit(77)
SVC = A.svc
day = SVC["store"].get(A.replay_now())
fs = facets["facets"]
pick = lambda k: (fs.get(k) or [{}])[0].get("value")
sels = [{"service": pick("service")}, {"issue": pick("issue")}, {"service": pick("service"), "cross": "1"},
        {"severity": "critical"}, {"region": pick("region")}]
sels = [s for s in sels if all(v not in (None, "") for v in s.values())]
moments = [day.start.timestamp() + h * 3600 for h in (0, 3.5, 11, 17.25, 23.99)] + [day.keys[len(day.keys) // 2]]

print("1. Services replayed counter = the old whole-day count")
bad = []
for s in sels:
    evs = SVC["scope_events"](MultiDict(s), day)
    for t in moments:
        at = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(t)) + f".{int((t % 1) * 1000):03d}Z"
        q = urlencode(dict(s, at=at))
        _, r, _ = call(f"/api/svc/replayed?{q}")
        tt = A.parse_iso(at, None).timestamp()
        want_done = sum(1 for e in evs if e["_t"] <= tt)
        nxt = next((e for e in evs if e["_t"] > tt), None)
        want = (want_done, len(evs), len({e["ip"] for e in evs if e["ip"]}))
        got = (r.get("replayed"), r.get("total"), r.get("hosts"))
        if got != want or (r.get("next_at") is None) != (nxt is None):
            bad.append(f"{s} at {at}: {got} vs {want}")
ok(f"{len(sels)} selections x {len(moments)} moments: replayed, total, hosts and the next record agree", not bad, "; ".join(bad[:3]))
# masked and unmasked viewers never share a kept selection: a real network name matches nothing for a masked viewer
# (lg-test caught this: the masked counter reused the unmasked one)
net = pick("network")
if net:
    q = urlencode({"asn": net})
    seen = {}
    for demo in (False, True, False):
        _, rp, _ = call(f"/api/svc/replayed?{q}", demo=demo)
        _, stt, _ = call(f"/api/svc/stats?{q}", demo=demo)
        seen.setdefault(demo, []).append((rp.get("total"), stt.get("total")))
    ok("a network's counter matches the figures for unmasked and masked viewers alike, whichever asked first",
       all(a == b for v in seen.values() for a, b in v), f"network {net[:20]}…: unmasked {seen[False]}, masked {seen[True]}")
q = urlencode(dict(sels[0], at=A.iso(A.replay_now())))
call(f"/api/svc/replayed?{q}")
ms = min(call(f"/api/svc/replayed?{q}")[2] for _ in range(3))
ok("…a poll after the first is a lookup, not a pass over the day", ms < 15, f"{ms:.1f} ms")

print("2. Map replayed counter = the old whole-day count")
mday = A.store.get(A.replay_now())
st = call("/api/stats")[1]
inf = next((r["value"] for r in (st.get("infection") or []) if r.get("value")), None)
bad, n = [], 0
for flt_args in ([{"infection": inf}] if inf else []) + [{"severity": "high"}]:
    flt = A.parse_filters(MultiDict(flt_args))
    for t in moments[:4]:
        tt = mday.start.timestamp() + (t - day.start.timestamp())
        at = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(tt)) + "Z"
        _, r, _ = call(f"/api/replayed?{urlencode(dict(flt_args, at=at))}")
        rt = A.parse_iso(at, None).timestamp()
        hi = bisect.bisect_right(mday.keys, rt)
        want = (sum(1 for e in mday.events[:hi] if A.matches(e, flt)), sum(1 for e in mday.events if A.matches(e, flt)),
                next((e["extracted_date"] for e in mday.events[hi:] if A.matches(e, flt)), None),
                len({e["src_ip"] for e in mday.events if e["src_ip"] and A.matches(e, flt)}))
        got = (r.get("replayed"), r.get("total"), r.get("next_at"), r.get("hosts"))
        n += 1
        if got != want:
            bad.append(f"{flt_args} at {at}: {got} vs {want}")
ok(f"{n} map selections and moments agree with the old count", n and not bad, "; ".join(bad[:3]))

print("3. Services analysis, drill-down and regions: kept per day and selection")
for s in sels[:3]:
    q = urlencode(s)
    _, a1, t1 = call(f"/api/svc/insight?{q}&at={quote(A.iso(A.replay_now()))}")
    later = A.iso(A.replay_now())
    _, a2, t2 = call(f"/api/svc/insight?{q}&at={quote(later)}")
    _, stt, _ = call(f"/api/svc/stats?{q}")
    _, rg, _ = call(f"/api/svc/regions?{q}")
    same = {k: v for k, v in a1.items() if k != "as_of"} == {k: v for k, v in a2.items() if k != "as_of"}
    ok(f"{s}: the analysis is the same from the cache, its figures match the statistics and the regions map",
       same and a1["total"] == stt["total"] and a1["hosts"] == stt["hosts"] and rg["total"] == a1["total"],
       f"{a1['total']:,} records, {a1['hosts']:,} hosts; first {t1:.0f} ms, then {t2:.0f} ms")
    ok("…its 'as of' is the moment asked for, not the cached one", a2.get("as_of") == A.iso(A.parse_iso(later, None)), a2.get("as_of"))
    ok("…and the second time it comes from the cache", t2 < 50, f"{t2:.0f} ms")
    _, d1, _ = call(f"/api/svc/drill?{q}&metric=hosts")
    _, dall, _ = call(f"/api/svc/drill?{q}&metric=hosts&all=1")
    ok("…the drill-down list is the start of the full list, which is worked out each time", d1["total"] == dall["total"] == a1["hosts"]
       and dall["rows"][:len(d1["rows"])] == d1["rows"], f"{len(d1['rows'])} of {dall['total']}")
code, _, _ = call("/api/svc/drill?metric=nonsense")
ok("an unknown drill-down is refused, not kept", code == 400, str(code))
_, masked, _ = call(f"/api/svc/drill?{urlencode(sels[0])}&metric=hosts", demo=True)
_, plain, _ = call(f"/api/svc/drill?{urlencode(sels[0])}&metric=hosts")
ok("a masked viewer never gets the unmasked list from the cache (and the other way round)",
   masked.get("rows") and plain.get("rows") and masked["rows"][0]["ip"] != plain["rows"][0]["ip"],
   f"{masked['rows'][0]['ip']} / {plain['rows'][0]['ip'][:3]}…")
import secrets as _sec  # noqa: E402
q0 = urlencode(sels[0])
call(f"/api/svc/insight?{q0}")
_, junk, tj = call(f"/api/svc/insight?{q0}&x={_sec.token_hex(6)}&utm={_sec.token_hex(6)}")
ok("a parameter nothing reads (&x=random) does not make a new cache entry: answered from the cache",
   tj < 50 and junk.get("total") is not None, f"{tj:.0f} ms")

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
