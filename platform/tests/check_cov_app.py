#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""app.py behaviour that the other checks reach only on a live server (r91, test coverage for the OpenSSF gold badge),
offline: no database, no outside connection, made-up data only (documentation addresses, private AS numbers, example
names). The day stores, the network registry, the definitions files, the audit log and the sessions file are replaced
in memory or by files in a temporary folder: nothing of the installation is read for the checks or written.

1. Small helpers: time windows, durations, medians, request paths, rhythm, the PDF's short explanations and rows,
   file names, times from a request kept within the replay day.
2. The report database down: a clear 503 (JSON for /api/, a page otherwise), the account refusal named.
3. The day store: changes announced, a fresh copy reused, a forced or changed day reloaded, a failed load keeps the
   old copy, a constituency change during a load loads again, old days dropped, the settle rule.
4. The analysis and its drill-downs on a made-up day: every metric, time windows, filters, routes, ports, masked view;
   the PDF/ZIP report of a figure on both platforms (export permission).
5. Look-ups: issues and Malpedia batches and look-up jobs (permissions, CSRF, limits, errors, stop, two at a time).
6. Definitions and networks: who may change them, every refusal, saving into the temporary files.
7. Settings: reading, the JSON-only rule, refusals, a save; Identify networks; the public settings.
Run: .venv/bin/python tests/check_cov_app.py"""
import io
import json
import os
import sys
import tempfile
import threading
import time
import zipfile
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("LG_QUIET", "1")
os.environ.setdefault("THREATMAP_SCHEDULE", "0")
os.environ["TRUST_PROXY"] = "0"                    # the app is called in-process (proxy_guard.py)
os.environ["SLOW_REQUEST_S"] = "600"               # nothing written to the slow-request log by these checks
import app as A  # noqa: E402
import auth  # noqa: E402
import services as SV  # noqa: E402
import sources  # noqa: E402
from pymongo.errors import OperationFailure, PyMongoError  # noqa: E402

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{str(info)[:300]}]" if info and not cond else ""), flush=True)


TMP = tempfile.mkdtemp(prefix="lg-cov-app-")
AUDIT = []
users, sessions, roles = A.AUTH["users"], A.AUTH["sessions"], A.AUTH["roles"]
real_get, real_perms, real_all = users.get, roles.perms, users.all
sessions._persist = lambda force=False: None                 # no sessions file written
A.AUTH["audit"].add = lambda event, **kw: AUDIT.append((event, kw))
A.asn_registry.path = os.path.join(TMP, "asns.json")         # an empty network registry of its own
A.asn_registry.mtime, A.asn_registry.asns = None, {}
A.LOCAL_DEFS_PATH = os.path.join(TMP, "definitions.json")
A._MISSES_PATH = os.path.join(TMP, "malpedia_names.json")
A.DATA_DIR = TMP
# the names seen, their levels and kinds: the made-up names never reach the installation's records
import pdf_refs  # noqa: E402
A.SEEN.path, A.SEEN.backfill = os.path.join(TMP, "seen_names.json"), lambda *a, **k: None
pdf_refs.KNOWN["path"], pdf_refs.SEEN["path"] = os.path.join(TMP, "name_levels.json"), os.path.join(TMP, "name_kinds.json")
A._kb["mtime"] = A._ikb["mtime"] = None

P = auth.TEST_PREFIX
ROLES = {"cov-admin": {"view", "unmasked", "settings", "export", "malpedia", "definitions", "networks", "management"},
         "cov-analyst": {"view", "unmasked", "export", "malpedia"},
         "cov-plain": {"view", "unmasked"},
         "cov-researcher": {"view", "definitions", "networks", "malpedia"}}
FAKE = {P + "cov-admin": "cov-admin", P + "cov-analyst": "cov-analyst", P + "cov-plain": "cov-plain",
        P + "cov-researcher": "cov-researcher", P + "cov-analyst2": "cov-analyst"}
users.get = lambda name: ({"status": "active", "role": FAKE[name], "changed": 0} if name in FAKE else real_get(name))
roles.perms = lambda role: (ROLES[role] if role in ROLES else real_perms(role))
UA = "lg-check-cov-app"
MADE = []


def client(who):
    user = P + who
    token = sessions.create(user, "127.0.0.1", UA)
    MADE.append(token)
    csrf = max((s for s in sessions.s.values() if s["user"] == user and s.get("csrf")), key=lambda s: s["created"])["csrf"]
    c = A.app.test_client()
    c.set_cookie("lg_session", token)
    return c, {"User-Agent": UA, "X-CSRF-Token": csrf}, {"User-Agent": UA}


# ---------------------------------------------------------------------- a made-up day for both platforms
RN = A.replay_now()
START = A.day_start(RN)
SPAN = max(60.0, (RN - START).total_seconds() - 1)


def at(frac):
    return START + timedelta(seconds=min(SPAN, (RN - START).total_seconds() - 1) * frac)


SRC_A = {"name": "event4_sinkhole_http", "label": "Sinkhole HTTP", "class": "Botnet / infection", "layout": "standard",
         "filename_index": True}
SRC_B = {"name": "event4_honeypot_brute_force", "label": "Honeypot brute force", "class": "Brute force", "layout": "standard",
         "filename_index": True}
PLAN = [  # (fraction of the day so far, source, ip, infection, host, severity, port)
    (0.10, SRC_A, "192.0.2.1", "examplebot", "c2-a.example.com", "critical", 80),
    (0.20, SRC_A, "192.0.2.1", "examplebot", "c2-a.example.com", "high", 80),
    (0.30, SRC_A, "192.0.2.1", "examplebot", "c2-a.example.com", "high", 80),
    (0.40, SRC_A, "192.0.2.1", "examplebot", "c2-b.example.net", "high", 80),
    (0.45, SRC_B, "192.0.2.1", "", "", "high", 22),
    (0.12, SRC_A, "192.0.2.2", "examplebot", "c2-a.example.com", "high", 8080),
    (0.15, SRC_A, "192.0.2.2", "examplebot", "c2-a.example.com", "high", 8080),
    (0.60, SRC_A, "192.0.2.2", "samplerat", "c2-b.example.net", "medium", 8080),
    (0.50, SRC_A, "192.0.2.3", "samplerat", "c2-b.example.net", "medium", 80),
    (0.55, SRC_B, "192.0.2.4", "", "", "high", 22),
    (0.70, SRC_A, "192.0.2.5", "samplerat", "c2-a.example.com", "medium", 80),
]
EVENTS = []
for i, (fr, src, ip, inf, host, sev, port) in enumerate(sorted(PLAN, key=lambda p: p[0])):
    t = at(fr)
    doc = {"timestamp": t, "extracted_date": t, "src_ip": ip, "src_port": 50000 + i, "src_asn": "64500", "src_geo": "GH",
           "src_region": "GREATER ACCRA", "src_city": "ACCRA" if i % 2 else "KUMASI", "dst_ip": f"198.51.100.{7 + i % 2}",
           "dst_port": port, "dst_asn": "64501", "dst_geo": "US", "dst_city": "ASHBURN", "http_host": host,
           "http_url": f"GET /gate.php?id={i} HTTP/1.1" if host else "", "http_agent": "Mozilla/5.0 (made-up)" if host else "",
           "infection": inf, "tag": "ssh-brute-force" if src is SRC_B else "botnet", "severity": sev, "protocol": "tcp",
           "filename": f"{START:%Y-%m-%d}-{src['name']}-example-asn.csv", "_id": f"cov{i}"}
    n = sources.normalise(doc, src)
    n["id"], n["_t"], n["extracted_date"] = f"{src['name']}:cov{i}", t.timestamp(), A.iso(t)
    for f, v in list(n.items()):
        if hasattr(v, "isoformat"):
            n[f] = A.iso(v)
    n["src_coords"], n["dst_coords"] = [-0.19, 5.6], [-77.49, 39.04]
    n["src_ref"] = A.host_refs.ref(n["src_ip"])
    n["request"] = A._request_path(n["http_url"]) if n.get("http_url") else ""
    EVENTS.append(n)
DAY = A.Day(START, EVENTS)
DAY.per_source = {SRC_A["name"]: sum(e["source"] == SRC_A["name"] for e in EVENTS), SRC_B["name"]: 2}
DAY.arrived, DAY.sig, DAY.raw_total = {}, None, len(EVENTS)
DAY.asn_raw = {"64500": len(EVENTS), "64501": len(EVENTS)}
DAY.by_src = {}
DAY.gen, DAY.settings_version = A.store.gen, A.settings.version
SSRC = {"name": "scan_http", "label": "HTTP", "family": "Accessible", "filename_index": True}
SEV = []
for i in range(8):
    t = at(0.1 + i * 0.08)
    doc = {"timestamp": t, "extracted_date": t, "ip": f"192.0.2.{10 + i % 4}", "port": 443 if i % 2 else 80, "protocol": "tcp",
           "asn": "64500", "geo": "GH", "region": "GREATER ACCRA" if i % 2 else "ASHANTI", "city": "ACCRA", "hostname": "",
           "severity": "critical" if i == 0 else "high", "tag": "cve-2024-0001;cve-2023-0002" if i % 3 == 0 else "vulnerable",
           "server": "ExampleServer/1.0", "filename": f"{START:%Y-%m-%d}-scan_http-example-asn.csv", "_id": f"scov{i}"}
    n = SV.normalise_service(doc, SSRC)
    n["id"], n["_t"], n["extracted_date"] = f"scan_http:scov{i}", t.timestamp(), SV._s(t)
    n["ip_ref"] = A.host_refs.ref(n["ip"])
    SEV.append(n)
SDAY = SV.Day(START, SEV)
SDAY.per_source, SDAY.arrived, SDAY.sig = {"scan_http": len(SEV)}, {}, None
SDAY.by_src = {"scan_http": {"raw": len(SEV), "asn": {}, "region": {}, "blocks": {}, "rows": SEV, "last": None}}
SDAY.gen, SDAY.settings_version, SDAY.raw_total = getattr(A.svc["store"], "gen", 0), A.settings.version, len(SEV)
SDAY.asn_raw, SDAY.region_raw = {"64500": len(SEV)}, {"GREATER ACCRA": 4, "ASHANTI": 4}
A.settings.in_scope = lambda asn, ip: True
REAL_STORE_GET, REAL_SVC_GET = A.store.get, A.svc["store"].get
A.store.get = lambda dt=None: DAY
A.store.days = {START: DAY}
A.svc["store"].get = lambda dt=None: SDAY
A.svc["store"].days = {START: SDAY}
diag = {"checks": [], "compatible": True, "layout": "standard", "missing": [], "missing_fields": [], "required_ok": 5,
        "required_total": 5, "warnings": []}
ENTRIES = [dict(SRC_A, diagnostic=diag, latest=""), dict(SRC_B, diagnostic=diag, latest="")]
A.registry.get = lambda *a, **k: ENTRIES
A.registry.items, A.registry.unsupported, A.registry.names = ENTRIES, [], [e["name"] for e in ENTRIES]
SENTRY = dict(SSRC, diagnostic=dict(diag, layout="single-host"), layout="single-host", fields=[], **{"class": "Accessible"})
A.svc["registry"].get = lambda *a, **k: [SENTRY]
A.svc["registry"].items, A.svc["registry"].unsupported, A.svc["registry"].names = [SENTRY], [], ["scan_http"]

try:
    # ------------------------------------------------------------------ 1. helpers
    print("1. Small helpers")
    ok("a time window with a selection: '1080+60|infection|examplebot'",
       A._parse_time_value("1080+60|infection|examplebot") == (1080.0, 60.0, "infection", "examplebot"))
    ok("…an unreadable window is the whole day, an unknown selection kind is dropped",
       A._parse_time_value("x+y|nonsense|v") == (0.0, 1440.0, "", ""))
    ok("…a nested time selection is dropped, the start is kept within the day",
       A._parse_time_value("5000+30|time|1+2") == (1439.0, 30.0, "", ""))
    ok("clock text: 00:00, 18:30, 24:00 and seconds", (A._hm(0), A._hm(1110), A._hm(1440), A._hm(61.5)) ==
       ("00:00", "18:30", "24:00", "01:01:30"))
    ok("durations: seconds, minutes, hours, none", (A._fmt_dur(None), A._fmt_dur(30), A._fmt_dur(600), A._fmt_dur(7200)) ==
       (None, "30s", "10.0 min", "2.0 h"))
    ok("median of none, odd and even counts", (A._median([]), A._median([3, 1, 2]), A._median([4, 1, 2, 3])) == (None, 2, 2.5))
    ok("a request line becomes method and path, without the query",
       A._request_path("GET /sck/1/?m=a HTTP/1.0") == "GET /sck/1/" and A._request_path("/x?y=1") == "/x")
    ok("rhythm: under three times unknown; even gaps are regular (variation 0)",
       A._rhythm([1, 2]) == (None, None) and A._rhythm([0, 10, 20, 30]) == (10, 0.0) and A._rhythm([5, 5, 5]) == (None, None))
    cve = {"kind": "cve", "cvss": {"score": 9.8, "severity": "CRITICAL"}, "exploited": True, "epss": 0.5, "found": True,
           "kev": {"name": "Example product flaw"}}
    ok("a CVE's short text: its name, CVSS, actively exploited, EPSS",
       A._short(cve) == "Example product flaw (CVSS 9.8 CRITICAL, ACTIVELY EXPLOITED (CISA KEV), EPSS 50.0%)", A._short(cve))
    ok("…a CVE not looked up yet, and one with no public record",
       "not looked up yet" in A._short({"kind": "cve", "pending": True}) and A._short({"kind": "cve"}) == "no public record")
    ok("a threat actor, a family, a definition, a reference, no source",
       (A._short({"found": True, "kind": "actor", "name": "Group"}), A._short({"found": True, "name": "Bot", "family": "win.bot"}),
        A._short({"curated": True, "title": "T"}), A._short({"reference": True, "name": "N", "source_label": "MISP Galaxy"}),
        A._short({"nosource": True, "title": "x"}), A._short({})) ==
       ("Group (threat actor)", "Bot (win.bot)", "T (Looking Glass definition)", "N (MISP Galaxy)",
        "no source knows this name: x", "no source knows this name"))
    ok("breakdown rows: label, count, hosts and share (given or worked out)",
       A._bd_rows([{"label": "A", "count": 5, "share": 0.5}, {"value": "B", "count": 1, "hosts": 1}], 10, hosts=True) ==
       [["A", "5", "0", "50.0%"], ["B", "1", "1", "10.0%"]])
    cols, rows = A._pdf_rows([["ip", "IP"], ["infections", "Infections"], ["followup", "Follow-up"], ["events", "Events"],
                              ["first", "First"], ["city", "City"]],
                             [{"ip": "192.0.2.1", "infections": ["examplebot"], "followup": [], "events": 1200,
                               "first": "2026-11-20T10:00:00Z", "city": "ACCRA"}],
                             {"examplebot": {"found": True, "name": "ExampleBot", "family": "win.examplebot", "sources": ["Malpedia"]}})
    ok("PDF rows: what each infection is, its source, ATT&CK column; follow-up 'Monitor', numbers, times, cities",
       [k for k, _ in cols][-3:] == ["_explained", "_source", "_attack"] and rows[0]["_explained"] == "examplebot: ExampleBot (win.examplebot)"
       and rows[0]["_source"] == "examplebot: Malpedia" and rows[0]["followup"] == "Monitor" and rows[0]["events"] == "1,200"
       and rows[0]["first"] == "2026-11-20 10:00:00" and rows[0]["city"] == "Accra", rows)
    cols, rows = A._pdf_rows([["name", "Issue"]], [{"name": "CVE-2024-0001"}], {"CVE-2024-0001": {"kind": "cve", "found": True}},
                             issues=True, row_name=True)
    ok("…issues: no Source column, the issue row explained", [k for k, _ in cols] == ["name", "_explained", "_attack"]
       and rows[0]["_explained"].startswith("CVE-2024-0001:"), cols)
    ok("file names: safe characters only, empty parts left out",
       A._file_base(["2026-11-20", "a b/c", None]) == "looking-glass_2026-11-20_a-b-c" and A._file_base([]) == "looking-glass_report")
    ok("a time far in the past is kept to the day before the replay day", A.parse_iso("2001-01-01T00:00:00Z", None) == START - timedelta(days=1))
    ok("…an unreadable time gives the default", A.parse_iso("not a time", "d") == "d" and A.parse_iso("", "d") == "d")
    ok("…a time with its own offset is read in UTC",
       A.parse_iso(START.replace(tzinfo=None).isoformat() + "+01:00", None) == max(START - timedelta(hours=1), START - timedelta(days=1)))
    ok("a day starts at 00:00 UTC whatever the offset",
       A.day_start(datetime(2026, 11, 20, 0, 30, tzinfo=timezone(timedelta(hours=2)))) == datetime(2026, 11, 19, tzinfo=timezone.utc))
    with A.app.test_request_context("/"):
        ok("value labels: a time window, a report, a port, a route (left to the browser)",
           A._value_label("time", "60+30", False, {}) == "01:00 to 01:30 UTC"
           and A._value_label("source", SRC_A["name"], False, {SRC_A["name"]: "Sinkhole HTTP"}) == "Sinkhole HTTP"
           and A._value_label("dst_port", "80", False, {}) == "Port 80" and A._value_label("route", "a>b", False, {}) is None)
        ok("…masked: an address never shown as it is, text through the masker",
           A._value_label("src_ip", "192.0.2.1", True, {}) != "192.0.2.1"
           and A._value_label("http_host", "c2-a.example.com", True, {}) == A.mask_text("c2-a.example.com")
           and A._value_label("dst_ip", "198.51.100.7", False, {}) == "198.51.100.7",
           (A._value_label("src_ip", "192.0.2.1", True, {}), A._value_label("http_host", "c2-a.example.com", True, {})))
        ok("…a network not in the registry: AS number", A._value_label("src_asn", "64500", False, {}) in ("AS64500", "AS64500 (AS64500)"),
           A._value_label("src_asn", "64500", False, {}))
    ok("a country's map box: unknown codes give none", A._country_bbox("zz9") is None and A._country_bbox("") is None)

    # ------------------------------------------------------------------ 2. the database down
    print("2. The report database down")
    c, H, R = client("cov-admin")
    real_view, real_page = A.app.view_functions["api_infections"], A.app.view_functions["definitions_page"]

    def down():
        raise PyMongoError("connection refused (made up)")

    def refused():
        raise OperationFailure("Authentication failed (made up)", code=18)
    A.app.view_functions["api_infections"] = down
    A._DB_WARNED["at"] = 0.0
    r = c.get("/api/infections", headers=R)
    ok("an API call: 503 with database false and what to check", r.status_code == 503 and r.json.get("database") is False
       and "cannot be reached" in r.json.get("error", ""), r.status_code)
    A.app.view_functions["api_infections"] = refused
    r = c.get("/api/infections", headers=R)
    ok("…the account refused: it says MongoDB refuses the account in platform/.env",
       r.status_code == 503 and "refuses the account" in r.json.get("error", ""), r.get_data(as_text=True)[:200])
    A.app.view_functions["definitions_page"] = down
    r = c.get("/definitions", headers=R)
    ok("a page: 503 page, not a crash", r.status_code == 503 and b"report database" in r.data, r.status_code)
    A.app.view_functions["api_infections"], A.app.view_functions["definitions_page"] = real_view, real_page

    # ------------------------------------------------------------------ 3. the day store
    print("3. The day store")
    ds = A.DayStore()
    D0 = START - timedelta(days=1)
    loads = []
    sig = {"v": {"a": 1}}

    def fake_load(start, old=None):
        loads.append(old)
        d = A.Day(start, [])
        d.per_source, d.arrived, d.sig = {"a": len(loads)}, {}, dict(sig["v"])
        return d
    ds._load, ds.signature = fake_load, lambda start: dict(sig["v"])
    d1 = ds.get(D0)
    ok("the first get loads the day", d1 is ds.days[D0] and len(loads) == 1)
    ok("…no announcement for the first load after a start", D0 not in ds.changes)
    d1.events = [EVENTS[0]]
    ok("a copy checked a moment ago is reused", ds.get(D0) is d1 and len(loads) == 1)
    d1.checked_at = 0
    ok("a copy whose time is up, MongoDB unchanged: kept, checked again", ds.get(D0) is d1 and d1.checked_at > 0 and len(loads) == 1)
    d1.checked_at = 0
    sig["v"] = {"a": 2}
    d2 = ds.get(D0)
    ok("…MongoDB has more rows: loaded again, the growth announced", d2 is not d1 and len(loads) == 2
       and ds.changes.get(D0) and ds.changes[D0][-1]["added"] == 1 and ds.changes[D0][-1]["new"] is False, ds.changes.get(D0))
    ds.invalidate(D0)
    ok("invalidate: the next get reloads", ds.days[D0].force is True and ds.get(D0) is not d2 and len(loads) == 3)

    def boom(start, old=None):
        raise RuntimeError("made-up failure")
    ds._load = boom
    ds.days[D0].force = True
    keep = ds.days[D0]
    ok("a failed load keeps the copy in memory", ds.get(D0) is keep)
    ok("…and with no copy, an empty day", ds.get(D0 - timedelta(days=5)).events == [])

    def always_moving(start, old=None):
        ds.gen += 1
        return fake_load(start, old)
    ds._load = always_moving
    n0 = len(loads)
    got = ds.get(START + timedelta(days=7))
    ok("the constituency changing on every try: three tries, the last copy answered but not kept",
       len(loads) == n0 + 3 and START + timedelta(days=7) not in ds.days and got.start == START + timedelta(days=7))

    moved = []

    def gen_load(start, old=None):
        if not moved:                       # the constituency changes once, during the first load
            ds.gen += 1
            moved.append(1)
            loads.append("gen")
        return fake_load(start, old)
    ds._load = gen_load
    ds.days[START - timedelta(days=4)] = A.Day(START - timedelta(days=4), [])
    ds.days[D0].force = True
    got = ds.get(START)
    ok("a constituency change during the load: loaded again with it, old days dropped",
       got is ds.days[START] and START - timedelta(days=4) not in ds.days and loads.count("gen") == 1)
    ds._load = fake_load
    stale = ds.days[START]
    stale.force = True
    ev = threading.Event()
    ev.set()
    ds.loading[START] = ev
    ok("another thread is loading: the stale copy is served meanwhile", ds.get(START) is stale)
    ds.loading[START + timedelta(days=9)] = ev
    ok("…and without one, an empty day after the wait", ds.get(START + timedelta(days=9)).events == [])
    ds.loading.clear()
    ok("peek: the day's rows before the constituency, 0 when not loaded",
       ds.peek(START) == 0 and ds.peek(START - timedelta(days=30)) == 0)
    ds.days[START].raw_total = 42
    ok("…42 for a loaded day with 42 rows", ds.peek(START) == 42)
    ds.reset()
    ok("reset forgets every day and moves the generation on", not ds.days and ds.gen >= 2)
    # the check every 15 seconds
    real_stamps, real_skip, real_settled = A._STAMPS, A.load_stamps.skip_count, A.settled
    A._STAMPS = SimpleNamespace(of=lambda days: None)
    A.load_stamps.skip_count = lambda day, stamp, now: False
    A.settled = lambda day, s, now: True
    try:
        ok("check: a day not loaded is not checked", ds.check(START) is False)
        ds._load, sig["v"] = fake_load, {"a": 5}
        ds.get(START)
        ok("…same rows: nothing to do", ds.check(START) is False and ds.days[START].pending is None)
        sig["v"] = {"a": 6}
        n0 = len(loads)
        ok("…more rows, settled: reloaded", ds.check(START) is True and len(loads) == n0 + 1)
        sig["v"] = {"a": 7}
        A.settled = lambda day, s, now: False
        ok("…more rows, still arriving: waits", ds.check(START) is False)
        A.load_stamps.skip_count = lambda day, stamp, now: True
        ok("…the pipeline's marks say nothing moved: not counted", ds.check(START) is False)
        A.load_stamps.skip_count = lambda day, stamp, now: False

        def bad_sig(start):
            raise RuntimeError("made-up")
        ds.signature = bad_sig
        ok("…the count fails: no reload, no crash", ds.check(START) is False)
        ok("…a day in the future is never checked", ds.check(START + timedelta(days=3)) is False)
    finally:
        A._STAMPS, A.load_stamps.skip_count, A.settled = real_stamps, real_skip, real_settled

    # ------------------------------------------------------------------ 4. the analysis on the made-up day
    print("4. The analysis, its drill-downs and reports")
    r = c.get("/api/insight?kind=infection&value=examplebot", headers=R)
    j = r.json or {}
    ok("analysis of an infection: its events, hosts, the regular beacon and the peak hour", r.status_code == 200
       and j.get("total") == 6 and j.get("hosts") == 2 and j.get("regular_beacons", 0) >= 1 and j.get("peak_hour") is not None, j.get("total"))
    ok("…plain-language findings, the other reports of its hosts among them",
       any("also appear in other reports" in s for s in j.get("insights", [])), j.get("insights"))
    ok("an unknown kind: 400", c.get("/api/insight?kind=nope", headers=R).status_code == 400)
    for kind, value, want in (("source", SRC_A["name"], 9), ("src_ip", "192.0.2.1", 5), ("dst_port", "22", 2),
                              ("route", "KUMASI|GH>ASHBURN|US", None), ("dst_place", "ASHBURN|US", 11),
                              ("request", "GET /gate.php", 9), ("time", "0+1440|infection|samplerat", 3),
                              ("filters", "infection=samplerat&infection=examplebot&inf_all=1", 3), ("src_asn", "64500", 11)):
        r = c.get("/api/insight", query_string={"kind": kind, "value": value}, headers=R)
        tot = (r.json or {}).get("total")
        ok(f"analysis by {kind}: {want if want is not None else 'some'} events", r.status_code == 200
           and (tot == want if want is not None else (tot or 0) > 0), f"{r.status_code} {tot}")
    r = c.get("/api/insight", query_string={"kind": "time", "value": "0+1440|source|" + SRC_B["name"]}, headers=R)
    ok("…a time window within a report: the window's label and its selection", r.status_code == 200
       and r.json.get("scope", {}).get("kind") == "source" and r.json.get("value_label") == "00:00 to 24:00 UTC", r.json and r.json.get("scope"))
    r = c.get("/api/insight", query_string={"kind": "src_ip", "value": "192.0.2.1"}, headers=R)
    ok("…one host in two reports: said so", any("2 different reports" in s for s in r.json.get("insights", [])), r.json.get("insights"))
    for metric, rk in (("hosts", "src_ip"), ("cross", "src_ip"), ("multi", "src_ip"), ("interval", "src_ip"),
                       ("events", "infection"), ("reports", "source"), ("share", "source"), ("c2", "http_host"), ("dst_ips", "dst_ip")):
        r = c.get("/api/insight/drill", query_string={"kind": "infection", "value": "examplebot", "metric": metric}, headers=R)
        ok(f"drill-down '{metric}': a list of {rk}", r.status_code == 200 and r.json.get("row_kind") == rk and r.json.get("rows"),
           f"{r.status_code} {(r.json or {}).get('row_kind')}")
    r = c.get("/api/insight/drill", query_string={"kind": "source", "value": SRC_A["name"], "metric": "hosts"}, headers=R)
    top = (r.json or {}).get("rows", [{}])[0]
    ok("…hosts ranked for follow-up: the host in two kinds of activity first, with its reasons",
       top.get("ip") == "192.0.2.1" and "Several kinds of activity" in top.get("followup", []) and "Critical" in top.get("followup", []), top)
    r = c.get("/api/insight/drill", query_string={"kind": "infection", "value": "examplebot", "metric": "dst_ips", "demo": "1"}, headers=R)
    ok("…masked: destination addresses concealed but still clickable",
       r.status_code == 200 and all(row["dst"] != row["value"] and "198.51.100" not in row["value"] for row in r.json["rows"]), r.json and r.json["rows"][:1])
    r = c.get("/api/insight/drill", query_string={"kind": "infection", "value": "examplebot", "metric": "beacons", "demo": "1"}, headers=R)
    ok("…decoded beacons in the masked view: none, and why", r.status_code == 200 and r.json["rows"] == [] and "analysts" in r.json["empty"])
    r = c.get("/api/insight/drill", query_string={"kind": "infection", "value": "examplebot", "metric": "beacons"}, headers=R)
    ok("…decoded beacons not ready yet: an empty list that says so, or the list", r.status_code == 200, r.status_code)
    ok("…an unknown metric: 400", c.get("/api/insight/drill?kind=infection&value=x&metric=nope", headers=R).status_code == 400)

    def cards(name):
        if name == "examplebot":
            return {"found": True, "family": "win.examplebot", "name": "ExampleBot", "sources": ["Malpedia"]}, {}
        if name == "samplerat":
            return {"found": True, "kind": "actor", "name": "Sample Group", "sources": ["Malpedia"]}, {}
        if name == "unknown":
            return {"found": False, "curated": True, "title": "Unknown activity", "sources": ["Looking Glass"]}, {}
        raise RuntimeError("made-up: no answer")
    REAL_MP, REAL_IR = A.mp_resolve, A.issues_resolve
    A.mp_resolve = cards
    q = {"kind": "infection", "value": "examplebot", "metric": "hosts", "all": "1"}
    pa, pc, pr = client("cov-plain")
    ok("a figure's report needs the export permission", pa.get("/api/insight/report", query_string=q, headers=pr).status_code == 403)
    ok("…and all=1", c.get("/api/insight/report", query_string=dict(q, all="0"), headers=R).status_code == 400)
    r = c.get("/api/insight/report", query_string=dict(q, format="pdf", label="Made-up selection"), headers=R)
    ok("…the PDF alone: a PDF file named after the selection", r.status_code == 200 and r.data[:5] == b"%PDF-"
       and "Made-up-selection" in r.headers.get("Content-Disposition", ""), f"{r.status_code} {r.headers.get('Content-Disposition')}")
    r = c.get("/api/insight/report", query_string=dict(q, kind="source", value=SRC_A["name"], metric="interval"), headers=R)
    ok("…by default a ZIP: the PDF and the complete list as CSV", r.status_code == 200 and r.mimetype == "application/zip", r.status_code)
    if r.status_code == 200:
        names = zipfile.ZipFile(io.BytesIO(r.data)).namelist()
        csv = zipfile.ZipFile(io.BytesIO(r.data)).read([n for n in names if n.endswith(".csv")][0]).decode("utf-8-sig")
        ok("…the CSV has the listed hosts and what their infections are", "192.0.2.1" in csv and "ExampleBot" in csv, csv[:200])
    ok("…the report is in the audit log", any(e == "report_pdf" and kw.get("target") == "comms:interval" for e, kw in AUDIT))
    r = c.get("/api/insight/report", query_string={"kind": "nope", "value": "x", "metric": "hosts", "all": "1"}, headers=R)
    ok("…a selection the analysis refuses is refused here too (400)", r.status_code == 400, r.status_code)

    def issue_cards(names, budget=15.0, progress=None, stop=None):
        return {n: ({"kind": "cve", "found": True, "exploited": True, "cvss": {"score": 9.8, "severity": "CRITICAL"},
                     "kev": {"name": f"Example flaw {n}"}} if n.startswith("cve") or n.startswith("CVE") else
                    {"found": False, "curated": True, "title": "Vulnerable service"}) for n in names}
    A.issues_resolve = issue_cards
    for metric in ("hosts", "issues"):
        r = c.get("/api/svc/report", query_string={"metric": metric, "all": "1", "format": "pdf"}, headers=R)
        ok(f"services report ({metric}): a PDF with the issues explained", r.status_code == 200 and r.data[:5] == b"%PDF-",
           f"{r.status_code} {r.get_data(as_text=True)[:200] if r.status_code != 200 else ''}")
    ok("…needs export, and all=1", pa.get("/api/svc/report?all=1", headers=pr).status_code == 403
       and c.get("/api/svc/report", headers=R).status_code == 400)
    r = c.get("/api/svc/report", query_string={"metric": "nope", "all": "1"}, headers=R)
    ok("…an unknown metric: refused", r.status_code == 400)
    r = c.get("/api/infections/missing", headers=R)
    ok("infections without a definition on the replay day: listed with their counts", r.status_code == 200
       and r.json["seen"] >= 2 and all("count" in x for x in r.json["missing"] + r.json["needs_review"]), r.json)
    r = c.get("/api/asns?demo=1", headers=R)
    ok("the network registry is not offered in the masked view", r.status_code == 403)
    ok("…and offered otherwise", c.get("/api/asns", headers=R).status_code == 200)
    A._SVC_ISSUES.update(at=0.0, data={})
    st = A._svc_issue_stats()
    ok("issues of the services days: records and hosts per issue", st and all(x["records"] >= len(x["hosts"]) for x in st.values()), st)
    ok("…kept a minute", A._svc_issue_stats() is st)
    try:
        A._warm_views()
        ok("the first views worked out ahead (warm-up) run on the day without an error", True)
    except Exception as exc:  # noqa: BLE001
        ok("the first views worked out ahead (warm-up) run on the day without an error", False, repr(exc))

    # ------------------------------------------------------------------ 5. look-ups
    print("5. Look-ups")
    ac, AH, AR = client("cov-analyst")
    ok("issues batch: the 'malpedia' permission", pa.get("/api/issues/batch?values=x", headers=pr).status_code == 403)
    ok("…at most 120", ac.get("/api/issues/batch", query_string={"values": ",".join(f"i{n}" for n in range(121))}, headers=AR).status_code == 400)
    r = ac.get("/api/issues/batch?values=CVE-2024-0001,vulnerable,CVE-2024-0001", headers=AR)
    ok("…each issue once, explained", r.status_code == 200 and set(r.json["results"]) == {"CVE-2024-0001", "vulnerable"}, r.json)

    def bad_issues(names, **kw):
        raise ValueError("made-up bad value")
    A.issues_resolve = bad_issues
    ok("…a bad value: 400, not a server error", ac.get("/api/issues/batch?values=x", headers=AR).status_code == 400)
    A.issues_resolve = issue_cards

    def mp_cards(name):
        if name == "bad":
            raise ValueError("not a name")
        if name == "busy":
            raise RuntimeError("Too many requests (made up)")
        if name == "down":
            raise RuntimeError("unreachable (made up)")
        if name == "actor":
            return {"found": True, "kind": "actor", "name": "Group"}, {"matches": []}
        if name == "defined":
            return {"found": False, "curated": True, "title": "Defined"}, {}
        if name == "mpdef":
            return ({"found": True, "family": "win.x", "curated_references": ["https://example.org/r"],
                     "matched_by": "the administrator's definition"}, {})
        if name == "none":
            return {"found": False, "title": "No source knows this name"}, {}
        return {"found": True, "family": "win." + name, "name": name}, {}
    A.mp_resolve = mp_cards
    ok("Malpedia batch: the permission", pa.get("/api/malpedia/batch?values=x", headers=pr).status_code == 403)
    ok("…at most 80 names", ac.get("/api/malpedia/batch", query_string={"values": ",".join(f"n{i}" for i in range(81))}, headers=AR).status_code == 400)
    r = ac.get("/api/malpedia/batch?values=good,bad,down,Good,ref:x", headers=AR)
    res = (r.json or {}).get("results", {})
    ok("…each name once; a bad name says why; no answer is 'pending'", r.status_code == 200 and res.get("good", {}).get("found")
       and res.get("bad", {}).get("found") is False and res.get("down", {}).get("pending") and r.json["pending"] == 1
       and "Good" not in res, res)
    r = ac.get("/api/malpedia/batch?values=ref:x,good&demo=1", headers=AR)
    ok("…masked references are not names (masked view)", r.status_code == 200 and "ref:x" not in r.json["results"], r.json)
    ok("single look-up: the permission first", pa.get("/api/malpedia?field=md5&value=x", headers=pr).status_code == 403)
    real_token = A.malpedia.token
    A.malpedia.token = ""
    ok("…a hash without a Malpedia token: 503", ac.get("/api/malpedia?field=md5&value=x", headers=AR).status_code == 503)
    A.malpedia.token = "made-up-token"
    ok("…an unknown field: 400", ac.get("/api/malpedia?field=nope&value=x", headers=AR).status_code == 400)
    for v, key in (("actor", "actor_card"), ("defined", "curated"), ("none", "explain"), ("mpdef", "curated_references")):
        r = ac.get(f"/api/malpedia?field=infection&value={v}", headers=AR)
        ok(f"…'{v}': the card and its '{key}' part", r.status_code == 200 and key in r.json and "card" in r.json, r.json)
    ok("…the administrator's definition is the match", ac.get("/api/malpedia?field=tag&value=mpdef", headers=AR).json["matches"][0]["id"] == "win.x")
    ok("…a bad name: 400; Malpedia busy: 429; unreachable: 502",
       (ac.get("/api/malpedia?value=bad", headers=AR).status_code, ac.get("/api/malpedia?value=busy", headers=AR).status_code,
        ac.get("/api/malpedia?value=down", headers=AR).status_code) == (400, 429, 502))
    real_lookup = A.malpedia.lookup
    A.malpedia.lookup = lambda field, value: {"field": field, "value": value, "matches": []}
    ok("…a hash goes to Malpedia's own look-up", ac.get("/api/malpedia?field=sha256&value=abc", headers=AR).json.get("field") == "sha256")

    # look-up jobs
    def wait_job(cl, hdr, jid, secs=20):
        t0 = time.time()
        while time.time() - t0 < secs:
            j = cl.get(f"/api/lookups/{jid}?since=bad", headers=hdr).json
            if j.get("state") != "running":
                return j
            time.sleep(0.1)
        return j
    ok("look-up jobs: a role without look-ups is refused", pa.post("/api/lookups", json={"kind": "issues", "values": ["x"]}, headers=pc).status_code == 403)
    ok("…without the page's token", ac.post("/api/lookups", json={"kind": "issues", "values": ["x"]}, headers=AR).status_code == 403)
    ok("…kind and values needed", ac.post("/api/lookups", json={"kind": "other", "values": ["x"]}, headers=AH).status_code == 400)
    ok("…at most 400", ac.post("/api/lookups", json={"kind": "issues", "values": [f"v{i}" for i in range(401)]}, headers=AH).status_code == 400)

    def issues_job(names, budget=15.0, progress=None, stop=None):
        for n in names:
            progress("item", f"{n}: answered")
        progress("step", "made-up step")
        return issue_cards(names)
    A.issues_resolve = issues_job
    r = ac.post("/api/lookups", json={"kind": "issues", "values": ["CVE-2024-0001", "vulnerable"]}, headers=AH)
    j = wait_job(ac, AR, r.json["id"])
    ok("…an issues job runs to the end with its results and log", j.get("state") == "done" and set(j.get("results") or {}) ==
       {"CVE-2024-0001", "vulnerable"} and j.get("done") == 2 and any("Finished" in ln for ln in j.get("log", [])), j)
    ok("…someone else cannot see it", client("cov-analyst2")[0].get(f"/api/lookups/{r.json['id']}", headers=AR).status_code == 404)
    r = ac.post("/api/lookups", json={"kind": "malpedia", "values": ["good", "bad", "down", "actor", "defined"]}, headers=AH)
    j = wait_job(ac, AR, r.json["id"])
    res = j.get("results") or {}
    ok("…a Malpedia job: found, refused with its reason, not checked yet counted as failed",
       j.get("state") == "done" and res.get("good", {}).get("found") and res.get("bad", {}).get("reason") == "not a name"
       and res.get("down", {}).get("pending") and j.get("failed") == 1, j)

    def broken(names, **kw):
        raise KeyError("made-up internal error")
    A.issues_resolve = broken
    j = wait_job(ac, AR, ac.post("/api/lookups", json={"kind": "issues", "values": ["x"]}, headers=AH).json["id"])
    ok("…a job that fails: 'failed' with a public reason, the platform carries on", j.get("state") == "failed" and j.get("error"), j)
    gate = threading.Event()

    def slow(names, budget=15.0, progress=None, stop=None):
        gate.wait(10)
        progress("item", "x: answered")
        return {}
    A.issues_resolve = slow
    j1 = ac.post("/api/lookups", json={"kind": "issues", "values": ["a"]}, headers=AH).json["id"]
    j2 = ac.post("/api/lookups", json={"kind": "issues", "values": ["b"]}, headers=AH).json["id"]
    r = ac.post("/api/lookups", json={"kind": "issues", "values": ["c"]}, headers=AH)
    ok("…two running at a time per person: the third waits (429)", r.status_code == 429, r.status_code)
    oc, OH, _ = client("cov-analyst2")
    ok("stopping: without the page's token refused, another person's job unknown",
       ac.post(f"/api/lookups/{j1}/stop", headers=AR).status_code == 403
       and oc.post(f"/api/lookups/{j1}/stop", headers=OH).status_code == 404)
    r = ac.post(f"/api/lookups/{j1}/stop", headers=AH)
    gate.set()
    j = wait_job(ac, AR, j1)
    ok("…stopped by its owner: 'stopped' between two names", r.status_code == 200 and j.get("state") == "stopped", j)
    wait_job(ac, AR, j2)
    A.mp_resolve = lambda name: (_ for _ in ()).throw(RuntimeError("Too many requests (made up)"))
    jm = ac.post("/api/lookups", json={"kind": "malpedia", "values": ["slow1"]}, headers=AH).json["id"]
    time.sleep(0.5)
    ac.post(f"/api/lookups/{jm}/stop", headers=AH)
    j = wait_job(ac, AR, jm)
    ok("…a Malpedia job waiting for its limit stops at once when stopped", j.get("state") == "stopped"
       and any("limit reached" in ln for ln in j.get("log", [])), j)
    A.mp_resolve = mp_cards
    r = ac.post("/api/lookups?demo=1", json={"kind": "malpedia", "values": ["ref:abc", "good"]}, headers=AH)
    j = wait_job(ac, AR, r.json["id"])
    ok("…masked references are skipped in the masked view", j.get("state") == "done" and "ref:abc" not in (j.get("results") or {}), j)
    ok("unknown job: 404", ac.get("/api/lookups/nothing", headers=AR).status_code == 404)
    A.issues_resolve = issue_cards

    # Malpedia search, background check
    rc, RH, RR = client("cov-researcher")
    ok("Malpedia search: definitions people only", pa.get("/api/kb/malpedia-search?q=abc", headers=pr).status_code == 403)
    A.malpedia.token = ""
    ok("…not set up: 503", rc.get("/api/kb/malpedia-search?q=abc", headers=RR).status_code == 503)
    ok("…background check not set up: 503", rc.post("/api/kb/check", headers=RH).status_code == 503)
    A.malpedia.token = "made-up-token"
    ok("…3 to 60 characters", rc.get("/api/kb/malpedia-search?q=ab", headers=RR).status_code == 400)
    real_find, real_mpget = A.malpedia.find, A.malpedia._get
    A.malpedia.find = lambda q: [{"id": "win.examplebot", "alt_names": ["exbot"], "matched_by": "alias exbot"}]
    A.malpedia._get = lambda path: [{"name": "example_group", "synonyms": ["EG"], "common_name": "Example Group"}, {"x": 1}]
    r = rc.get("/api/kb/malpedia-search?q=exbot", headers=RR)
    ok("…families and threat actors, with their Malpedia pages", r.status_code == 200 and [x["id"] for x in r.json["results"]] ==
       ["win.examplebot", "actor:example_group"] and r.json["results"][1]["url"].endswith("/actor/example_group"), r.json)

    def busy(q):
        raise RuntimeError("Too many (made up)")
    A.malpedia.find = busy
    ok("…Malpedia busy: 429", rc.get("/api/kb/malpedia-search?q=exbot", headers=RR).status_code == 429)
    A.malpedia.find, A.malpedia._get = real_find, real_mpget
    ok("background check: a change permission and the page's token", rc.post("/api/kb/check", headers=RR).status_code == 403)
    calls = []

    def mp_lookup(field, name):
        calls.append(name)
        if name == "newname1":
            return {"family": {"id": "win.newname1"}}
        if name == "newname2":
            return {"actor": {"id": "group2"}}
        raise ValueError("unknown")
    A.malpedia.lookup = mp_lookup
    real_unchecked, real_sleep = A._unchecked_names, A.time.sleep
    A._unchecked_names = lambda: ["newname1", "newname2", "newname3"]
    A._AUTOCHECK["running"] = False
    A.time = SimpleNamespace(**{k: getattr(time, k) for k in ("time", "strftime", "gmtime", "monotonic", "perf_counter")},
                             sleep=lambda s: None)
    try:
        r = rc.post("/api/kb/check", headers=RH)
        t0 = time.time()
        while A._AUTOCHECK["running"] and time.time() - t0 < 10:
            time.sleep(0.05)
        names = A._read_names()
        ok("…started: every new name checked and recorded, family, actor or nothing", r.status_code == 200 and r.json["started"]
           and names.get("newname1", {}).get("family") == "win.newname1" and names.get("newname2", {}).get("family") == "actor:group2"
           and names.get("newname3", {}).get("family") == "" and A._AUTOCHECK["done"] == 3, (r.json, names))
        A._AUTOCHECK["running"] = True
        r = rc.post("/api/kb/check", headers=RH)
        ok("…one already running: not started again, and it says so", r.json["started"] is False and r.json["note"])
        A._AUTOCHECK["running"] = False
    finally:
        A.time = time
        A._unchecked_names = real_unchecked
        A.malpedia.lookup = real_lookup

    # ------------------------------------------------------------------ 6. definitions and networks
    print("6. Definitions and networks")
    ok("definition: reading needs the definitions permission", pa.get("/api/kb/entry?name=x", headers=pr).status_code == 403)
    ok("…changing needs it with the page's token", pa.post("/api/kb/entry", json={}, headers=pc).status_code == 403
       and rc.post("/api/kb/entry", json={}, headers=RR).status_code == 403)
    real_fresh = A.AUTH["fresh"]
    A.AUTH["fresh"] = lambda: False
    ok("…a session older than 12 hours must sign in again", rc.post("/api/kb/entry", json={}, headers=RH).status_code == 403)
    A.AUTH["fresh"] = real_fresh
    A.malpedia.token = ""
    bad = [("not json", None), ("bad name", {"name": "<b>"}), ("bad issue", {"name": "<b>", "section": "issues"}),
           ("reference not a link", {"name": "newbot", "references": ["ftp://x"]}),
           ("bad Malpedia id", {"name": "newbot", "malpedia": "nope"}),
           ("no reference", {"name": "newbot", "title": "T", "description": "D"}),
           ("no title and description", {"name": "newbot", "references": ["https://example.org/a"]}),
           ("a CVE with neither a note nor a reference", {"name": "cve-2024-0001", "section": "issues", "references": []})]
    for label, body in bad:
        r = rc.post("/api/kb/entry", data="x" if body is None else json.dumps(body), content_type="application/json", headers=RH)
        ok(f"…refused: {label} (400)", r.status_code == 400, f"{r.status_code} {r.get_data(as_text=True)[:120]}")
    # r91 fix: a CVE note alone is enough (NVD, CISA and EPSS are shown anyway); the general rule used to refuse it
    r = rc.post("/api/kb/entry", json={"name": "cve-2024-0001", "section": "issues", "description": "A made-up note.",
                                       "references": []}, headers=RH)
    ok("…a CVE note without a reference is saved (200)", r.status_code == 200, f"{r.status_code} {r.get_data(as_text=True)[:120]}")
    r = rc.post("/api/kb/entry", json={"name": "NewBot", "title": "New bot", "type": "Botnet", "description": "A made-up bot.",
                                       "references": ["https://example.org/newbot"]}, headers=RH)
    saved = json.load(open(A.LOCAL_DEFS_PATH, encoding="utf-8"))
    ok("…a definition saved: reviewed, by whom, in the site's own definitions file", r.status_code == 200
       and saved["infections"]["newbot"]["status"] == "reviewed" and saved["infections"]["newbot"]["curated_by"] == P + "cov-researcher", saved)
    ok("…in the audit log", any(e == "definition_saved" and kw.get("target") == "newbot" for e, kw in AUDIT))
    ok("…and read back", rc.get("/api/kb/entry?name=newbot", headers=RR).json.get("title") == "New bot")
    A._write_names({"newbot2": {"family": "", "count": 1}})
    r = rc.post("/api/kb/entry", json={"name": "newbot2", "malpedia": "win.newbot2", "references": []}, headers=RH)
    ok("…a Malpedia id alone is enough; the name is checked again next time", r.status_code == 200 and "newbot2" not in A._read_names())
    r = rc.post("/api/kb/entry", json={"name": "cve-2024-0001", "section": "issues", "description": "Made-up note.",
                                       "references": ["https://example.org/advisory"]}, headers=RH)
    ok("…a CVE note is stored under the CVE's own spelling", r.status_code == 200 and r.json["name"] == "CVE-2024-0001", r.json)
    ok("…issue definitions are read back", rc.get("/api/kb/entry?name=cve-2024-0001&section=issues", headers=RR).json.get("description") == "Made-up note.")
    A.malpedia.token = "made-up-token"
    real_family = A.malpedia.family
    A.malpedia.family = lambda i: None
    r = rc.post("/api/kb/entry", json={"name": "newbot3", "malpedia": "win.nothing", "references": []}, headers=RH)
    ok("…a Malpedia id Malpedia does not know: refused", r.status_code == 400 and "no family" in r.json["error"])

    def mp_down(i):
        raise RuntimeError("down")
    A.malpedia.family = mp_down
    r = rc.post("/api/kb/entry", json={"name": "newbot3", "malpedia": "win.newbot3", "references": []}, headers=RH)
    ok("…Malpedia unreachable: the researcher's id is kept", r.status_code == 200)
    A.malpedia.family = real_family
    A.malpedia.token = real_token
    r = rc.get("/api/infections", headers=RR)
    ok("the definitions list names who wrote one, never the account", r.status_code == 200 and "curated_by" not in json.dumps(r.json.get("newbot", {})))
    # people for the "send to" lists
    users.all = lambda: {"grace": {"status": "active", "role": "cov-analyst"}, "daniel": {"status": "disabled", "role": "cov-analyst"},
                         P + "x": {"status": "active", "role": "cov-analyst"}, "sarah": {"status": "active", "role": "cov-plain"}}
    ok("people who do a job: active analysts only, never test or disabled accounts",
       [p["user"] for p in A._people_of("analyst")] == ["grace"] and A._people_of("management") == [])
    users.all = real_all
    # networks
    ok("network types: researchers and admins only", pa.post("/api/networks/types", json={}, headers=pc).status_code == 403)
    A.AUTH["fresh"] = lambda: False
    ok("…fresh sign-in needed (types, entry, look-up)", rc.post("/api/networks/types", json={}, headers=RH).status_code == 403
       and rc.post("/api/networks/entry", json={}, headers=RH).status_code == 403
       and rc.post("/api/networks/lookup", json={}, headers=RH).status_code == 403)
    A.AUTH["fresh"] = real_fresh
    ok("…an empty type: refused", rc.post("/api/networks/types", json={"label": ""}, headers=RH).status_code == 400)
    r = rc.post("/api/networks/types", json={"label": "Made-up sector", "alias": "Sector"}, headers=RH)
    ok("…a new type is added and offered", r.status_code == 200 and r.json["key"] and any(t.get("key") == r.json["key"] for t in r.json["types"]
       if isinstance(t, dict)) or (r.status_code == 200 and r.json["key"] in json.dumps(r.json["types"])), r.get_data(as_text=True)[:200])
    newkey = (r.json or {}).get("key", "unknown")
    for label, body in (("not JSON", None), ("AS number", {"asn": "x"}), ("name", {"asn": "64500", "name": "<b>"}),
                        ("type", {"asn": "64500", "name": "Example Net", "type": "nope"})):
        rr = rc.post("/api/networks/entry", data="x" if body is None else json.dumps(body), content_type="application/json", headers=RH)
        ok(f"network name: refused, {label} (400)", rr.status_code == 400, rr.status_code)
    rr = rc.post("/api/networks/entry", json={"asn": "64999", "name": "Example Net", "type": "unknown"}, headers=RH)
    ok("…a network not in the reports: 404", rr.status_code == 404, rr.status_code)
    A._NETS_CACHE["key"] = None
    rr = rc.post("/api/networks/entry", json={"asn": "AS64500", "name": "Example Net", "type": newkey, "note": "made\x01up"}, headers=RH)
    reg = json.load(open(A.asn_registry.path, encoding="utf-8"))
    ok("…a network in the reports is named by hand: reviewed, edited, in the registry file", rr.status_code == 200
       and reg["asns"]["64500"]["name"] == "Example Net" and reg["asns"]["64500"]["reviewed"] is True
       and reg["asns"]["64500"]["note"] == "made up", reg)
    rr = rc.post("/api/networks/entry", json={"asn": "64500", "name": "Example Net 2", "type": "unknown"}, headers=RH)
    ok("…corrected again: the audit says what changed",
       rr.status_code == 200 and any(e == "network_edited" and "-> Example Net 2" in kw.get("detail", "") for e, kw in AUDIT))
    r = rc.get("/api/networks", headers=RR)
    ok("the network list: every network of the day, the named one reviewed", r.status_code == 200
       and {x["asn"] for x in r.json["networks"]} >= {"64500", "64501"}, r.json and [x["asn"] for x in r.json["networks"]])
    ok("…not for everyone", pa.get("/api/networks", headers=pr).status_code == 403)
    import asn_lookup
    real_identify = asn_lookup.identify
    asked = []
    asn_lookup.identify = lambda path, counts, meta: asked.append(dict(counts)) or {"added": len(counts), "failed": 0}
    try:
        ok("network look-up: a list expected", rc.post("/api/networks/lookup", json={"asns": "64500"}, headers=RH).status_code == 400)
        ok("…digits only", rc.post("/api/networks/lookup", json={"asns": ["x1"]}, headers=RH).status_code == 400)
        ok("…none in the reports: 404", rc.post("/api/networks/lookup", json={"asns": ["64999"]}, headers=RH).status_code == 404)
        r = rc.post("/api/networks/lookup", json={"asns": ["AS64501", "64501"]}, headers=RH)
        ok("…in the reports: asked once, only the AS number", r.status_code == 200 and asked[-1] == {"64501": len(EVENTS)}, (r.json, asked))
        A._LOOKUP_SEEN[P + "cov-researcher"] = [time.time()] * 12
        ok("…many in a minute: wait (429)", rc.post("/api/networks/lookup", json={"asns": ["64501"]}, headers=RH).status_code == 429)
    finally:
        asn_lookup.identify = real_identify

    # ------------------------------------------------------------------ 7. Settings
    print("7. Settings")
    r = c.get("/api/settings", headers=R)
    j = r.json or {}
    ok("Settings: the networks of the day with their records, the time zones, the totals", r.status_code == 200
       and any(n["asns"] == ["64500"] for n in j.get("networks", [])) and j.get("totals", {}).get("services") == len(SEV)
       and j.get("zones", {}).get("GH"), {k: j.get(k) for k in ("totals", "day")})
    ok("…the public settings: country, map box, time zone", c.get("/api/settings/public", headers=R).json.get("country"))

    class Job:
        status = {"running": False, "done": 0}

        def running(self):
            return False

        def start(self, fn):
            self.counts = fn()
            return True
    real_job = A._ASN_JOB
    A._ASN_JOB = Job()
    try:
        ok("Identify networks: progress for admins only", pa.get("/api/asns/identify", headers=pr).status_code == 403
           and c.get("/api/asns/identify", headers=R).json == {"running": False, "done": 0})
        ok("…starting needs the page's token", c.post("/api/asns/identify", headers=R).status_code == 403)
        A.AUTH["fresh"] = lambda: False
        ok("…and a fresh sign-in", c.post("/api/asns/identify", headers=H).status_code == 403)
        A.AUTH["fresh"] = real_fresh
        r = c.post("/api/asns/identify", headers=H)
        ok("…started (202) on the networks of the days in memory, with each one's role",
           r.status_code == 202 and A._ASN_JOB.counts[0].get("64500") and A._ASN_JOB.counts[1]["64500"]["role"] == "both"
           and A._ASN_JOB.counts[1]["64501"]["role"] == "destination", getattr(A._ASN_JOB, "counts", None))
        A._ASN_JOB.running = lambda: True
        ok("…while it runs, a hand look-up or edit waits (409)", rc.post("/api/networks/lookup", json={"asns": ["64500"]}, headers=RH).status_code == 409
           and rc.post("/api/networks/entry", json={"asn": "64500"}, headers=RH).status_code == 409)
    finally:
        A._ASN_JOB = real_job
    ok("saving settings: the Settings permission", pa.post("/api/settings", json={"country": "GH"}, headers=pc).status_code == 403)
    A.AUTH["fresh"] = lambda: False
    r = c.post("/api/settings", json={"country": "GH"}, headers=H)
    ok("…an old session must sign in again", r.status_code == 403 and r.json.get("reauth") is True)
    A.AUTH["fresh"] = real_fresh
    ok("…JSON only (415)", c.post("/api/settings", data="country=GH", content_type="application/x-www-form-urlencoded", headers=H).status_code == 415)
    ok("…an object with a country", c.post("/api/settings", json={"networks": []}, headers=H).status_code == 400)
    r = c.post("/api/settings", json={"country": "ZZ", "networks": [], "cidrs": []}, headers=H)
    ok("…an unknown country: refused with the reason", r.status_code == 400 and "ZZ" in r.json["error"], r.json)
    saved_settings = []
    real_save, real_remember = A.settings.save, A._address_blocks.remember
    A.settings.save = lambda clean: saved_settings.append(clean)

    def no_disk(*a, **k):
        raise OSError("made-up: read-only")
    A._address_blocks.remember = no_disk
    try:
        r = c.post("/api/settings", json={"country": "GH", "networks": ["AS64500"], "cidrs": ["192.0.2.0/24"]}, headers=H)
        ok("…a valid change is saved (the networks file failing only loses its hint), both platforms reload",
           r.status_code == 200 and saved_settings and saved_settings[-1]["networks"] == ["64500"]
           and any(e == "settings_changed" and "(0 kept" in kw.get("detail", "") for e, kw in AUDIT), r.get_data(as_text=True)[:200])
    finally:
        A.settings.save, A._address_blocks.remember = real_save, real_remember
    # ------------------------------------------------------------------ 8. explanations and the analyst's combination search
    print("8. Explanations for the reports")
    real_card, real_many = A.cve_intel.card, A.cve_intel.lookup_many
    A.cve_intel.card = lambda n, fetch=True: {"kind": "cve", "found": True, "id": n.upper()}
    A.cve_intel.lookup_many = lambda ids, progress=None, budget=None, stop=None: {i.upper(): {"kind": "cve", "found": True} for i in ids[:1]}
    try:
        cv = A._issue_resolve_plain("CVE-2024-0001", fetch=False)
        ok("a CVE with the researchers' note: the public record plus the note and its references",
           cv.get("found") and cv.get("note") == "Made-up note." and cv.get("curated_references") == ["https://example.org/advisory"], cv)
        steps = []
        out = A._issues_resolve_plain(["CVE-2024-0001", "CVE-2024-0002", "vulnerable", "", "vulnerable"],
                                      progress=lambda kind, text, done=None: steps.append((kind, text)))
        ok("several issues: each once; a CVE without a batch answer asked alone; other issues from their definitions",
           set(out) == {"CVE-2024-0001", "CVE-2024-0002", "vulnerable"} and out["vulnerable"].get("kind") == "issue", out)
        ok("…the progress window says what was explained and how",
           any(k == "step" and "other issue" in t for k, t in steps) and any(k == "item" and t.startswith("vulnerable:") for k, t in steps), steps)
    finally:
        A.cve_intel.card, A.cve_intel.lookup_many = real_card, real_many

    def no_card(name):
        raise RuntimeError("made-up")
    A.mp_resolve = no_card
    ok("a combination's explanation that fails is left out, not an error", A._combo_explain("infections", "x") is None)
    A.mp_resolve = mp_cards
    ok("…an issue is explained from its definition", A._combo_explain("issues", "vulnerable").get("kind") == "issue")
    real_country = A.settings.data["country"]
    A.settings.data["country"] = "Q9"
    ok("region shapes of a country without a map file: none", A._adm1_shapes() is None)
    A.settings.data["country"] = real_country
    ok("the combination PDF is the analysis report's builder", A._combo_pdf({"title": "Made-up", "sources": []})[:5] == b"%PDF-")
    real_fetch, real_sfetch = A.store._fetch_collection, A.svc["store"]._fetch
    t = at(0.2)
    A.store._fetch_collection = lambda s, start, end: ([{"src_ip": "192.0.2.1", "src_asn": "64500", "dst_ip": "198.51.100.7",
                                                         "dst_asn": "64501", "extracted_date": t}], None)
    A.svc["store"]._fetch = lambda s, start, end: ([{"ip": "192.0.2.10", "asn": "64500"}], None)
    try:
        rows = A._combo_fetch("infections", {SRC_A["name"]}, START)
        ok("a combination search's day, communications: only the asked reports, times as text",
           len(rows) == 1 and isinstance(rows[0]["extracted_date"], str), rows)
        ok("…services: the asked report's rows", A._combo_fetch("services", {"scan_http"}, START) == [{"ip": "192.0.2.10", "asn": "64500"}]
           and A._combo_fetch("services", {"other"}, START) == [])
    finally:
        A.store._fetch_collection, A.svc["store"]._fetch = real_fetch, real_sfetch
    # combination codes on the Executive portal
    ok("code filter: an unknown or malformed code matches nothing; several codes are read one by one",
       A._combo_filter("nonsense", "infections", EVENTS) == [] and A._combo_filter("LG-ZZZZ, nonsense", "infections", EVENTS) == []
       and A._combo_filter("LG-A-ZZZZZZ", "infections", EVENTS) == [])
finally:
    users.get, roles.perms, users.all = real_get, real_perms, real_all
    for t in MADE:
        sessions.end(token=t)

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
