#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""The drop-downs' counts with filters set, against a brute-force count (reviewers' findings, production release
2026-11-26), in-process on made-up records in memory (tests/madeup_days.py; no database; the session store pointed at
a temporary folder).

For the map (/api/facets) and the services page (/api/svc/facets), with single and overlapping filters (two values of
one filter, three or four filters at once, the map's "carries every ticked infection"):
1. each list's counts equal a count over the made-up records matching every OTHER filter, worked out here from the
   records' own fields (the map's ticked infections: the matching devices that also carry each infection);
2. every row, picked with the other filters (the figures' own totals: /api/stats, /api/svc/stats), gives exactly the
   records its count says, so no row offers a choice that finds a different number (or nothing).
Run: .venv/bin/python tests/check_facets_bruteforce.py"""
import collections
import os
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "tests"))
os.environ.setdefault("LG_QUIET", "1")
os.environ.setdefault("THREATMAP_SCHEDULE", "0")
os.environ["TRUST_PROXY"] = "0"
os.environ.setdefault("LG_STEPUP_TESTS_OFF", "1")
os.environ["HEAVY_PER_MINUTE"] = "100000"     # hundreds of in-process look-ups: the per-person limit is tested on its own

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{str(info)[:500]}]" if info and not cond else ""), flush=True)


import app as A  # noqa: E402
import auth  # noqa: E402
import madeup_days as M  # noqa: E402

tmp = tempfile.mkdtemp(prefix="lg-check-facets-")
AU = A.AUTH
users, roles, sessions, audit = AU["users"], AU["roles"], AU["sessions"], AU["audit"]
saved = dict(get=users.get, perms=roles.perms, spath=sessions.path, s=dict(sessions.s), add=audit.add)
sessions.path = os.path.join(tmp, "sessions.json")
sessions.s.clear()
audit.add = lambda *a, **k: None
ANA, UA = auth.TEST_PREFIX + "facets-analyst", "lg-check-facets"
users.get = lambda n: {"status": "active", "role": "lg-facets-ana", "changed": 0} if n == ANA else saved["get"](n)
roles.perms = lambda r: {"view", "unmasked", "export"} if r == "lg-facets-ana" else saved["perms"](r)
H = {"User-Agent": UA}

try:
    # ------------------------------------------------------------------ made-up records (a fixed, varied mix)
    http = M.comms_source("event4_sinkhole_http", "Sinkhole HTTP")
    dns = M.comms_source("event4_sinkhole_dns", "Sinkhole DNS")
    brute = M.comms_source("event4_honeypot_brute_force", "Honeypot Brute Force", "Brute force")
    INF = ["examplebot", "otherbot", "thirdbot", ""]
    SEV = ["high", "medium", "critical", ""]
    CITY = ["ACCRA", "TEMA", "KUMASI", ""]
    GEO = ["US", "DE", "NL", ""]
    comms = []
    for i in range(72):
        src = (http, dns, brute)[i % 3]
        dev = i % 11                                    # 11 devices, several records each, in several reports
        comms.append((src, {"src_ip": f"192.0.2.{dev + 1}", "src_port": 40000 + i, "src_asn": ("64500", "64501", "")[dev % 3],
                            "src_geo": "GH", "src_city": CITY[(i // 2) % 4], "dst_ip": f"198.51.100.{i % 5}",
                            "dst_port": (80, 443, 53, 22)[i % 4], "dst_asn": "64510", "dst_geo": GEO[(i // 3) % 4],
                            "infection": INF[(dev + i // 7) % 4], "tag": ("examplebot", "c2", "")[i % 3] if src is not brute else "",
                            "severity": SEV[(i // 5) % 4], "protocol": ("tcp", "udp")[i % 2]}))
    acc = M.svc_source("scan_http", "HTTP")
    vul = M.svc_source("scan_ssl", "SSL/TLS", "Vulnerable")
    rdp = M.svc_source("scan_rdp", "RDP")
    svc = []
    for i in range(66):
        src = (acc, vul, rdp)[i % 3]
        host = i % 13
        svc.append((src, {"ip": f"192.0.2.{host + 60}", "port": (443, 80, 3389)[i % 3], "protocol": ("tcp", "udp")[(i // 4) % 2],
                          "asn": ("64500", "64501", "")[host % 3], "geo": "GH", "region": ("GREATER ACCRA", "ASHANTI", "", "Ghana")[(i // 2) % 4],
                          "city": CITY[(i // 3) % 4], "severity": SEV[(i // 4) % 4],
                          "tag": ";".join(t for t in (("cve-2024-0001", "vulnerable", "")[i % 3], ("ssl-freak", "", "rdp")[(i // 2) % 3]) if t),
                          "device_vendor": ("ExampleCo", "", "OtherCo")[(i // 5) % 3], "device_type": ("router", "camera", "")[(i // 6) % 3],
                          "server": ("nginx", "", "Microsoft-IIS/10.0")[i % 3], "sector": ("Education", "", "Government")[(i // 7) % 3]}))
    M.install(A, comms=comms, svc=svc)
    day = A.store.get()
    sday = A.svc["store"].get()

    tok = sessions.create(ANA, "127.0.0.1", UA)
    cl = A.app.test_client()
    cl.set_cookie("lg_session", tok)

    def get(path, args):
        r = cl.get(path, query_string=list(args), headers=H)
        return r.status_code, (r.json or {})

    def flat(flt):
        return [(k, v) for k, vs in flt.items() for v in sorted(vs)]

    # ------------------------------------------------------------------ 1. the map
    print("1. The map's drop-downs (/api/facets)")
    EMPTY = A.EMPTY_LABEL
    company = lambda a: A.asn_registry.company(a, False)          # noqa: E731  (the value the network filter takes)

    def m_pass(e, flt, carriers=None):
        for f, vals in flt.items():
            if f in ("src_asn", "dst_asn"):
                if not e[f] or company(e[f]) not in vals:
                    return False
            elif (e.get(f) or "") not in {("" if v == EMPTY.get(f) else v) for v in vals}:
                return False
        return carriers is None or e["src_ip"] in carriers

    MAP_SETS = [
        {"severity": {"high"}},
        {"severity": {"high", "critical"}, "src_city": {"ACCRA"}},
        {"source": {"event4_sinkhole_http"}, "dst_port": {"80", "443"}, "protocol": {"tcp"}},
        {"tag": {"c2", "untagged"}, "dst_geo": {"US", "DE"}, "src_city": {"ACCRA", "TEMA"}, "severity": {"unrated", "medium"}},
        {"infection": {"examplebot"}},
        {"infection": {"examplebot", "unknown"}, "severity": {"high", "medium"}},
        {"infection": {"examplebot", "otherbot"}, "_inf_all": True},
    ]
    for flt in MAP_SETS:
        inf_all = flt.pop("_inf_all", False)
        args = flat(flt) + ([("inf_all", "1")] if inf_all else [])
        st, d = get("/api/facets", args)
        carriers = None
        if inf_all:
            want = set(flt["infection"])
            have = collections.defaultdict(set)
            for e in day.events:
                if e["infection"] in want:
                    have[e["src_ip"]].add(e["infection"])
            carriers = {h for h, s in have.items() if s >= want}
        wrong = []
        for field in A.FACET_FIELDS + ("src_asn", "dst_asn"):
            others = {k: v for k, v in flt.items() if k != field}
            pool = [e for e in day.events if m_pass(e, others, carriers)]
            if field == "infection" and "infection" in flt:
                # ticked infections: how many of the devices matching every filter also carry each infection
                devs = {e["src_ip"] for e in day.events if m_pass(e, flt, carriers)}
                pairs = {((e["infection"] or EMPTY["infection"]), e["src_ip"]) for e in pool if e["src_ip"] in devs}
                exp = collections.Counter(n for n, _ in pairs)
                for n in {(e["infection"] or EMPTY["infection"]) for e in pool}:
                    exp.setdefault(n, 0)
            elif field in ("src_asn", "dst_asn"):
                exp = collections.Counter(company(e[field]) for e in pool if e[field])
            else:
                exp = collections.Counter((e[field] or EMPTY.get(field, "")) for e in pool)
                exp.pop("", None)
            got = {r["value"]: r["count"] for r in d.get(field) or []}
            if got != dict(exp):
                wrong.append(f"{field}: got {got} want {dict(exp)}")
        name = ", ".join(f"{k}={'/'.join(sorted(v))}" for k, v in flt.items()) + (" (carrying both)" if inf_all else "")
        ok(f"{name}: every list counted over the records matching the other filters", st == 200 and not wrong, wrong[:2])
        # every row picked with the other filters gives what it says (the map's own total)
        off = []
        for field in ("source", "severity", "tag", "src_city", "dst_geo", "dst_port", "protocol", "src_asn", "dst_asn") + (
                () if "infection" in flt else ("infection",)):
            others = [(k, v) for k, v in args if k != field]
            for row in d.get(field) or []:
                s2, tot = get("/api/stats", others + [(field, row["value"])])
                if tot.get("total") != row["count"]:
                    off.append(f"{field}={row['value']}: {row['count']} shown, {tot.get('total')} found")
        ok(f"{name}: each row picked finds the records its count says", not off, off[:4])

    # ------------------------------------------------------------------ 2. the services page
    print("2. The services page's drop-downs (/api/svc/facets)")
    SEMPTY = {"vendor": "unknown vendor", "device_type": "unknown type", "product": "unknown product", "severity": "unrated",
              "city": "unknown city", "industry": "not given"}
    PLAIN = {"service": lambda e: [e["service"]], "family": lambda e: [e["family"]], "severity": lambda e: [e["severity"]],
             "issue": lambda e: e["issues"], "tag": lambda e: e["tags"], "port": lambda e: [e["port"]],
             "city": lambda e: [e["city"]], "protocol": lambda e: [e["protocol"]] if e["protocol"] else [],
             "vendor": lambda e: [e["vendor"]] if e["vendor"] else [], "device_type": lambda e: [e["device_type"]] if e["device_type"] else [],
             "product": lambda e: [e["product"]] if e["product"] else []}
    FKEY = {"service": "service", "family": "family", "severity": "severity", "issue": "issue", "tag": "tag", "port": "port",
            "city": "city", "protocol": "protocol", "vendor": "vendor", "device_type": "device_type", "product": "product"}

    def s_pass(e, flt):
        for f, vals in flt.items():
            vs = {("" if v == SEMPTY.get(f) else v) for v in vals}
            if not set(PLAIN[f](e) or [""]) & vs:
                return False
        return True

    SVC_SETS = [
        {"severity": {"high"}},
        {"service": {"HTTP", "RDP"}, "city": {"ACCRA"}},
        {"tag": {"vulnerable", "ssl-freak"}, "port": {"443", "80"}, "protocol": {"tcp"}},
        {"family": {"Accessible"}, "vendor": {"ExampleCo", "OtherCo"}, "severity": {"unrated", "medium"}, "city": {"TEMA", "unknown city"}},
        {"issue": {"CVE-2024-0001"}, "device_type": {"router"}},
    ]
    for flt in SVC_SETS:
        args = flat(flt)
        st, d = get("/api/svc/facets", args)
        fac = d.get("facets") or {}
        wrong = []
        for name_, val in PLAIN.items():
            others = {k: v for k, v in flt.items() if FKEY[k] != name_}
            exp = collections.Counter(v for e in sday.events if s_pass(e, others) for v in set(val(e)))
            got = {r["value"]: r["count"] for r in fac.get(name_) or []}
            if got != dict(exp):
                wrong.append(f"{name_}: got {got} want {dict(exp)}")
        nm = ", ".join(f"{k}={'/'.join(sorted(v))}" for k, v in flt.items())
        ok(f"{nm}: every list counted over the records matching the other filters", st == 200 and d.get("filtered") and not wrong, wrong[:2])
        off = []
        FILTER_OF = {"network": "asn"}
        for name_, rows in fac.items():
            f = FILTER_OF.get(name_, name_)
            others = [(k, v) for k, v in args if k != f]
            for row in rows:
                s2, tot = get("/api/svc/stats", others + [(f, str(row["value"]))])
                if tot.get("total") != row["count"]:
                    off.append(f"{name_}={row.get('label') or row['value']!r}: {row['count']} shown, {tot.get('total')} found ({s2})")
        ok(f"{nm}: each row picked finds the records its count says", not off, off[:5])
finally:
    users.get, roles.perms, audit.add = saved["get"], saved["perms"], saved["add"]
    sessions.path = saved["spath"]
    sessions.s.clear()
    sessions.s.update(saved["s"])
    shutil.rmtree(tmp, ignore_errors=True)

print(f"\n{checks - len(fails)} of {checks} checks passed" + (f"; FAILED: {'; '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
