#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""One rule for the buckets every page counts in (count audit round 2, 2026-11-26: counting_keys.py), on made-up rows,
no database written (the quarterly part uses a throwaway database when this machine has an account for one), nothing
of the installation touched:

1. Regions: one spelling per region ("MURANG'A" -> "Murang'a", "ELGEYO-MARAKWET" -> "Elgeyo-Marakwet", NAIROBI and
   Nairobi one region), the administrator's region matches applied, the country's own name "Unknown region".
2. Networks: a company is its name trimmed and case-folded ("Example Telecom " = "example telecom"), AS0 is no network,
   each AS number missing from the registry its own masked alias that a masked filter takes back.
3. The same host through the Executive portal (comms + services), the quarterly report, the services page and the
   combination (advisory) report lands in the same sector, region and network bucket; Sectors are network types,
   Shadowserver's sector column is Industry (Shadowserver); a destination-only report counts its destination host.
4. The day loaders (both platforms): a row in two files of one report day counts once and is stated; a row dated
   outside the days it can be shown on, and a row without a time, are counted and stated.
5. Totals beside the short lists of the services regions map and the combination report's regions.
6. The quarterly report's own query: a row in two files of one day counts once (throwaway database, else skipped).
Run: .venv/bin/python tests/check_count_keys.py"""
import collections
import json
import os
import re
import secrets
import shutil
import sys
import tempfile
import types
import zipfile  # noqa: F401  (the combination report's ZIP, through package())
from datetime import date, datetime, timedelta, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
PLATFORM = os.path.dirname(HERE)
sys.path.insert(0, PLATFORM)
sys.path.insert(0, HERE)
os.environ.setdefault("LG_QUIET", "1")
os.environ.setdefault("THREATMAP_SCHEDULE", "0")
os.environ["TRUST_PROXY"] = "0"
os.environ["SLOW_REQUEST_S"] = "600"
import app as A  # noqa: E402
import combos as C  # noqa: E402
import counting_keys as CK  # noqa: E402
import management as MG  # noqa: E402
import netypes  # noqa: E402
import quarterly as QY  # noqa: E402
import services as SV  # noqa: E402
from flask import Flask, g  # noqa: E402

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{str(info)[:400]}]" if info and not cond else ""), flush=True)


TMP = tempfile.mkdtemp(prefix="lg-count-keys-")
DATA = os.path.join(TMP, "data")
ADM1 = os.path.join(TMP, "adm1")
os.makedirs(DATA)
os.makedirs(ADM1)
json.dump({"asns": {"64500": {"name": "Example Telecom ", "type": "isp", "demo_alias": "Telco 1", "events_last_check": 10},
                    "64501": {"name": "example  telecom", "type": "isp", "demo_alias": "Telco 2"},
                    "64502": {"name": "Lakeside Uni", "type": "education", "demo_alias": "Institution 1"}}},
          open(os.path.join(DATA, "asns.json"), "w"))
json.dump({"iso2": "KE", "regions": {"MURANG'A": {"name": "Murang'a"},
                                     "ELGEYO-MARAKWET": {"name": "Elgeyo-Marakwet", "aliases": ["ELGEYO"]},
                                     "NAIROBI": {"name": "Nairobi City", "aliases": ["NAIROBI CITY"]}}},
          open(os.path.join(ADM1, "KE.json"), "w"))
json.dump({"KE": {"NAIROBI AREA": "NAIROBI", "THE COUNTRY": "__country__"}}, open(os.path.join(DATA, "region_matches.json"), "w"))
REAL = {"path": A.asn_registry.path, "cfg": dict(CK._CFG)}
A.asn_registry.path = os.path.join(DATA, "asns.json")
A.asn_registry.mtime, A.asn_registry.asns = None, {}
CK.configure(country=lambda: "KE", adm1_dir=ADM1, data_dir=DATA, country_names=lambda cc: ["Kenya", "KENYA"],
             registry=A.asn_registry, type_labels=lambda: netypes.labels(DATA))
REG = A.asn_registry
H, H0, HT = "192.0.2.77", "192.0.2.78", "192.0.2.79"     # the host; a host without a network or region; a target host
START = datetime(2026, 11, 19, tzinfo=timezone.utc)

try:
    # ------------------------------------------------------------------ 1. regions
    print("1. Regions: one spelling, the region matches, the country itself")
    rk = CK.region_key
    ok("MURANG'A -> Murang'a (the map's name; title() gave Murang'A)", rk("MURANG'A") == "Murang'a", rk("MURANG'A"))
    ok("ELGEYO-MARAKWET -> Elgeyo-Marakwet (capitalize() gave Elgeyo-marakwet)", rk("ELGEYO-MARAKWET") == "Elgeyo-Marakwet")
    ok("NAIROBI, Nairobi, nairobi and the matched 'Nairobi Area' are one region",
       len({rk("NAIROBI"), rk("Nairobi"), rk("nairobi"), rk("Nairobi Area")}) == 1, {rk("NAIROBI"), rk("Nairobi Area")})
    ok("the country alone (KENYA), an administrator's 'the country itself' and an empty region: Unknown region",
       {rk("KENYA"), rk("The Country"), rk(""), rk(None)} == {CK.UNKNOWN_REGION})
    ok("a name the map does not know: in title case, spaces collapsed (Upper  HILLS -> Upper Hills)", rk("UPPER  HILLS") == "Upper Hills")
    ok("another country's region is not matched to this map (a destination abroad)", rk("NAIROBI", "US") == "Nairobi")
    ok("the label is stable: region_key(region_key(x)) == region_key(x)",
       all(rk(rk(v)) == rk(v) for v in ("MURANG'A", "ELGEYO", "KENYA", "UPPER HILLS", "Nairobi")))

    # ------------------------------------------------------------------ 2. networks
    print("2. Networks: companies folded, AS0 unknown, unlisted numbers each their own alias")
    ok("'Example Telecom ' (AS64500) and 'example  telecom' (AS64501) are one company, in one spelling",
       REG.company("64500", False) == REG.company("64501", False) == "Example Telecom", (REG.company("64500", False), REG.company("64501", False)))
    ok("...and one masked alias", REG.company("64500", True) == REG.company("64501", True) == "Telco 1")
    ok("0, AS0 and '' are no network (an Executive 'AS0' network before)", REG.company("0", False) == REG.company("AS0", False) == "" == CK.network_of(0, REG))
    a1, a2 = REG.alias("64999"), REG.alias("65000")
    ok("each AS number missing from the registry its own alias (one 'Unlisted network' for all before)",
       a1.startswith("Unlisted network ") and a1 != a2 and "64999" not in a1, (a1, a2))
    REG.strict = lambda: True
    ok("...which a masked filter takes back to that number only (it matched nothing before)", REG.resolve(a1) == {"64999"}, REG.resolve(a1))
    ok("...and the Unknown network row selects the records without a network", "" in REG.resolve(CK.UNKNOWN_NET))
    ok("...a real company name still selects nothing in a masked view", REG.resolve("Example Telecom") == {"\x00unknown-alias"})
    REG.strict = lambda: False
    ok("unmasked: the company name selects both its numbers, whatever its spelling", REG.resolve("EXAMPLE TELECOM") == {"64500", "64501"})
    ok("norm_asn: AS064500 -> 64500, 0 / AS0 / x -> none", (CK.norm_asn("AS064500"), CK.norm_asn("0"), CK.norm_asn("AS0"), CK.norm_asn("x"))
       == ("64500", "", "", ""))

    # ------------------------------------------------------------------ 3. one host, every page
    print("3. The same host on every page: one sector, one region, one network")
    WANT = {"sector": "Telco / ISP", "region": "Murang'a", "network": "Example Telecom"}

    class Store:
        def __init__(self):
            self.days = {}

        def get(self, dt=None):
            return None

        def signature(self, start):
            return {}

    mctx = {"AUTH": {"has_perm": lambda p: True}, "asn_registry": REG, "type_labels": lambda: netypes.labels(DATA),
            "registry": types.SimpleNamespace(get=lambda: [{"name": "event4_sinkhole_http", "label": "Sinkhole HTTP"},
                                                           {"name": "event_target_x", "label": "Made-up target report", "layout": "target"}]),
            "replay_now": lambda: START + timedelta(hours=12), "public_demo": lambda: False, "tz": None, "store": Store(),
            "svc_store": Store(), "combo_filter": lambda *a: [], "read_names": lambda: {}, "knowledge_base": lambda: {},
            "cve_intel": types.SimpleNamespace(kev=lambda: set(), card=lambda i, fetch=False: {}), "issues_kb": lambda: {},
            "infections_of": None, "geocode": lambda *a: None, "data_dir": DATA, "scope_text": lambda: "made-up",
            "country": lambda: "KE", "issues_resolve": lambda *a: {}, "mp_resolve": lambda *a: None, "user": lambda: {"user": "made-up"},
            "sources_text": lambda: "", "build_pdf": lambda s: b""}
    mapp = Flask("count-keys-mgmt")
    mapp.secret_key = "made-up"
    internals = MG.register(mapp, mctx)["internals"]
    t = START + timedelta(hours=3)

    def ev(ip, asn, region, source="event4_sinkhole_http", **kw):
        e = {"id": f"e{secrets.token_hex(4)}", "src_ip": ip, "src_asn": asn, "infection": "examplebot", "source": source,
             "attack_class": "botnet", "severity": "medium", "src_region": region, "src_city": "", "src_geo": "KE", "dst_geo": "",
             "dst_ip": "", "dst_asn": "", "dst_region": "", "dst_city": "", "_t": t.timestamp(), "http_host": "", "src_coords": None,
             "title": "", "type": "", "timestamp": t.isoformat()}
        e.update(kw)
        return e
    cev = [ev(H, "64501", "MURANG'A"), ev(H, "64501", "Murang'a"), ev(H0, "0", "KENYA"),
           ev("", "", "", source="event_target_x", dst_ip=HT, dst_asn="64502", dst_region="ELGEYO", dst_geo="KE")]
    d = internals["comms"]({}, False, day=A.Day(START, cev))
    row = lambda lst, label: next((r for r in lst if r["label"] == label), None)       # noqa: E731
    # the same day as a PAST day (the compact records of the 7-day baseline; review 2026-11-27: a destination-only
    # report raised KeyError 0 there, so the baseline never built, and its devices had no network or region)
    try:
        dp = internals["comms"]({}, False, day=internals["compact"]("comms", A.Day(START, cev)))
        past_err = None
    except Exception as ex:  # noqa: BLE001
        dp, past_err = None, f"{type(ex).__name__}: {ex}"
    ok("as a past day (the baseline's compact records), with a destination-only report: counted, no error", past_err is None, past_err)
    ok("...the same devices, regions and networks as the same day counted in full",
       dp is not None and {k: dp["kpis"].get(k) for k in ("devices", "regions", "networks")} == {k: d["kpis"].get(k) for k in ("devices", "regions", "networks")},
       (dp or {}).get("kpis"), )
    ok("Executive comms: the host's sector is its network type (Telco / ISP), 1 device",
       (row(d["sectors"], WANT["sector"]) or {}).get("hosts") == 1, d["sectors"])
    ok("...its region is Murang'a whichever way the report spells it (1 region row for both spellings)",
       (row(d["regions"], WANT["region"]) or {}).get("count") == 2, d["regions"])
    ok("...its network is Example Telecom; AS0 is Unknown network, not a network",
       row(d["networks"], WANT["network"]) and not row(d["networks"], "AS0") and row(d["networks"], CK.UNKNOWN_NET), d["networks"])
    ok("...the KPIs: 2 networks (Example Telecom, Lakeside Uni), 2 regions; the unknown ones counted apart",
       d["kpis"]["networks"] == 2 and d["kpis"]["regions"] == 2 and d["unknowns"]["networks"]["devices"] == 1
       and d["unknowns"]["regions"]["devices"] == 1, (d["kpis"], d["unknowns"]))
    ok("...a destination-only report counts its destination host (3 devices; it was Unknown with 0 devices)",
       d["kpis"]["devices"] == 3 and (row(d["sectors"], "University / research") or {}).get("hosts") == 1
       and (row(d["regions"], "Elgeyo-Marakwet") or {}).get("hosts") == 1, (d["kpis"]["devices"], d["sectors"]))
    ok("...the region filter takes the one spelling", internals["comms"]({"region": "Murang'a"}, False, day=A.Day(START, cev))["kpis"]["events"] == 2)

    def sv(ip, asn, region, sector="Communications"):
        return {"id": f"s{secrets.token_hex(4)}", "ip": ip, "asn": asn, "region": region, "city": "", "geo": "KE",
                "service": "Accessible HTTP", "report": "scan_http", "family": "Exposed service", "issues": [], "tags": [],
                "severity": "medium", "sector": sector, "vendor": "", "device_type": "", "_t": t.timestamp(), "port": 80,
                "protocol": "tcp", "vulnerable": False, "product": "", "version": "", "hostname": "", "naics": "",
                "ip_ref": A.host_refs.ref(ip) if ip else "", "extracted_date": t.isoformat(), "timestamp": t.isoformat()}
    sev_ = [sv(H, "64501", "MURANG'A"), sv(H, "64500", "Murang'a"), sv(H0, "0", "KENYA", ""), sv("", "64502", "ELGEYO")]
    s = internals["services"]({}, False, day=SV.Day(START, sev_))
    ok("Executive services: the same sector, region and network for the host",
       (row(s["sectors"], WANT["sector"]) or {}).get("hosts") == 1 and (row(s["regions"], WANT["region"]) or {}).get("hosts") == 1
       and (row(s["networks"], WANT["network"]) or {}).get("hosts") == 1, (s["sectors"], s["regions"], s["networks"]))
    ok("...Industry (Shadowserver) is Shadowserver's own column, apart", (row(s["industries"], "Communications") or {}).get("count") == 3
       and not row(s["sectors"], "Communications"), s["industries"])
    ok("...a record without an address is no host (3 hosts, 1 record without an address)",
       s["kpis"]["hosts"] == 2 and s["kpis"]["no_address"] == 1, s["kpis"])

    # the quarterly report
    R = {"quarter": "2026Q3", "lo": date(2026, 7, 1), "hi": date(2026, 10, 1), "months": ["2026-07", "2026-08", "2026-09"],
         "today": date(2026, 10, 5), "reports": {"scan_http": {"kind": "service", "label": "Accessible HTTP", "family": "Exposed service"}},
         "other": {}, "failed": {}, "rep_recs": collections.Counter(), "rep_hosts": collections.defaultdict(dict), "rep_total": collections.Counter(),
         "rep_day": collections.defaultdict(collections.Counter), "rep_noaddr": collections.Counter(), "net_total": collections.Counter(),
         "net_month": collections.Counter(), "net_hosts": collections.defaultdict(dict), "all_hosts": {}, "last_seen": {},
         "region": collections.defaultdict(set), "region_recs": collections.Counter(), "sector": collections.defaultdict(set),
         "sector_recs": collections.Counter(), "inf_hosts": collections.defaultdict(set), "inf_recs": collections.Counter(),
         "issue_hosts": collections.defaultdict(set), "issue_recs": collections.Counter(), "kev_hosts": set(), "kev_recs": 0,
         "cve_hosts": collections.defaultdict(set), "kev_cves": set(), "rep_out": collections.Counter()}
    mi = {m: i for i, m in enumerate(R["months"])}
    e_ = R["reports"]["scan_http"]
    for k, n, reg_, sec in (({"m": "2026-07", "a": "64501", "h": H}, 1, "MURANG'A", "Communications"),
                            ({"m": "2026-08", "a": "64500", "h": H}, 1, "Murang'a", "Communications"),
                            ({"m": "2026-07", "a": "0", "h": H0}, 1, "KENYA", "")):
        QY._add(R, "scan_http", e_, k, n, k["m"] + "-05", reg_, sec, mi, {}, False, False)
    X = QY.figures(R, None, TMP, date(2026, 10, 5))
    ok("quarterly: the host's sector is its network type (Telco / ISP), as on the Executive portal",
       (row(X["sectors"], WANT["sector"]) or {}).get("unique") == 1, X["sectors"])
    ok("...Shadowserver's column is Industry (Shadowserver), never a sector",
       row(X["industries"], "Communications") and not row(X["sectors"], "Communications"), X["industries"])
    ok("...Murang'a one region (both spellings), KENYA Unknown region",
       (row(X["regions"], WANT["region"]) or {}).get("records") == 2 and row(X["regions"], CK.UNKNOWN_REGION), X["regions"])
    ok("...Example Telecom one network; the quarter counts 1 network (it counted 3 AS numbers with unknown)",
       (row(X["networks"], WANT["network"]) or {}).get("unique") == 1 and X["totals"]["quarter"]["networks"] == 1
       and X["unknown_network"]["records"] == 1, (X["networks"], X["totals"]["quarter"]))
    rows_ = QY.csv_rows(dict(R, purge=QY.purge_dates(2026, 3), purge_all={}, constituency=QY.constituency(None)), X,
                        *QY.workflow(TMP, 2026, 3, R["last_seen"]), None)
    secs = {r[0] for r in rows_["management"]}
    ok("...the management CSV says which list is which: 'Sectors (network type)' and 'Industry (Shadowserver)'",
       {CK.SECTOR_LABEL, CK.INDUSTRY_LABEL} <= secs and "Sectors" not in secs, sorted(secs))

    # the services page
    sday = SV.Day(START, sev_)
    sday.per_source, sday.arrived, sday.sig = {"scan_http": len(sev_)}, {}, None
    sday.by_src = {"scan_http": {"raw": len(sev_), "asn": {}, "region": {}, "blocks": {}, "rows": sev_, "last": None}}
    sday.gen, sday.settings_version, sday.raw_total = getattr(A.svc["store"], "gen", 0), A.settings.version, len(sev_)
    sday.asn_raw, sday.region_raw = {}, {}
    sday.load_notes = {"dups": 2, "outside": 1, "undated": 0}
    keep = (A.svc["store"].get, A.svc["store"].days)
    A.svc["store"].get = lambda dt=None: sday
    A.svc["store"].days = {START: sday}

    def view(name, **args):
        with A.app.test_request_context("/x", query_string=args):
            g.user = {"user": "made-up-analyst", "perms": {"view", "unmasked", "export"}}
            r = A.app.view_functions[name]()
            return r if isinstance(r, tuple) else r.get_json()
    try:
        st = view("svc_stats", n="50")
        B = st["breakdowns"]
        ok("services page: Sectors are network types: the host in Telco / ISP (it was Shadowserver's 'Communications')",
           (row(B["sector"], WANT["sector"]) or {}).get("hosts") == 1 and not row(B["sector"], "Communications"), B["sector"])
        ok("...Shadowserver's column is the Industry (Shadowserver) list", (row(B["industry"], "Communications") or {}).get("count") == 3, B.get("industry"))
        ok("...Murang'a one row for both spellings (two rows before), Unknown region a row (dropped before)",
           (row(B["region"], WANT["region"]) or {}).get("count") == 2 and row(B["region"], CK.UNKNOWN_REGION), B["region"])
        ok("...Example Telecom one row; Unknown network a row (dropped before), not counted as a network",
           (row(B["network"], WANT["network"]) or {}).get("count") == 2 and row(B["network"], CK.UNKNOWN_NET)
           and st["totals"]["network"] == 2 and st["unknowns"]["network"]["records"] == 1, (B["network"], st["totals"]["network"]))
        ok("...KPIs: 2 networks by company (it counted 3 AS numbers), 2 hosts (the empty address is no host)",
           st["networks"] == 2 and st["hosts"] == 2 and st["no_address"] == 1, (st["networks"], st["hosts"]))
        ok("...the load figures say what was kept once and left out", st["load_notes"]["dups"] == 2
           and "2 rows also in another file that day" in st["load_notes"]["text"] and "dated outside" in st["load_notes"]["text"],
           st.get("load_notes"))
        f1 = view("svc_stats", region=WANT["region"])
        f2 = view("svc_stats", sector=WANT["sector"])
        f3 = view("svc_stats", industry="Communications")
        f4 = view("svc_stats", asn=CK.UNKNOWN_NET)
        ok("...filters by the lists' values: region Murang'a 2, sector Telco / ISP 2, industry 3, Unknown network 1",
           (f1["total"], f2["total"], f3["total"], f4["total"]) == (2, 2, 3, 1), (f1["total"], f2["total"], f3["total"], f4["total"]))
        rg = view("svc_regions")["regions"]
        ok("services regions map: each region's lists with their full counts (totals)",
           rg.get(WANT["region"], {}).get("totals") == {"services": 1, "issues": 0, "cities": 0, "networks": 1}
           and "" in rg, rg)
    finally:
        A.svc["store"].get, A.svc["store"].days = keep

    # the combination (advisory) report: package(), as check_cut_lists_data reaches it
    class Intel:
        on_codes = None

        def index(self, scope):
            return {"by": {}}
    cctx = {"base_dir": TMP, "intel": Intel(), "labels": lambda: {"event4_sinkhole_http": "Sinkhole HTTP"},
            "network": lambda a: REG.company(a, False), "has_perm": lambda p: True, "shapes": lambda: None,
            "notes": types.SimpleNamespace(list=lambda s, n: []), "explain": lambda s, n: None, "scope_text": lambda: "made-up",
            "country": lambda: "Kenya", "audit": types.SimpleNamespace(add=lambda *a, **k: None), "build_pdf": lambda spec: b"%PDF-plain",
            "store": types.SimpleNamespace(days={}), "svc_store": types.SimpleNamespace(days={}), "fetch": lambda *a: [],
            "host_flags": lambda hosts, day=None, load=True: {}, "impact_of": lambda reps: []}
    capp = Flask("count-keys-combos")
    capp.secret_key = "made-up"
    C.install(capp, cctx)
except Exception as exc:                                  # noqa: BLE001
    import traceback
    traceback.print_exc()
    ok("sections 1-3 ran", False, f"{type(exc).__name__}: {exc}")


def find_fn(name, roots):
    """A function defined inside install(), found through the routes' closures (as tests/check_cut_lists_data.py)."""
    seen, todo = set(), list(roots)
    while todo:
        f = todo.pop()
        if id(f) in seen or not isinstance(f, types.FunctionType):
            continue
        seen.add(id(f))
        if getattr(f, "__name__", "") == name and getattr(f, "__code__", None):
            return f
        for c in getattr(f, "__closure__", None) or ():
            try:
                v = c.cell_contents
            except ValueError:
                continue
            if isinstance(v, types.FunctionType):
                todo.append(v)
    return None


try:
    package = find_fn("package", capp.view_functions.values())
    T0 = START + timedelta(hours=8)
    cev2 = [{"src_ip": H, "src_asn": "64501", "source": "event4_sinkhole_http", "infection": "examplebot", "http_host": "c2.example",
             "timestamp": T0.isoformat(), "extracted_date": "2026-11-19", "_t": T0.timestamp(), "src_region": reg_,
             "src_city": city, "src_geo": "KE", "dst_port": 80, "protocol": "tcp"}
            for reg_, city in (("MURANG'A", "Town A"), ("Murang'a", "Town B"))]
    entry = {"code": "LG-C-00000001", "section": "infections", "name": "examplebot", "kind": "r", "report": "Sinkhole HTTP",
             "items": [], "label": "x"}
    job = {"id": "review1", "user": "made.up", "log": []}
    package(job, entry, cev2, [("2026-11-19", len(cev2))], [T0], cev2, None)
    sm = job.get("summary") or {}
    rd = (sm.get("region_details") or {}).get(WANT["region"]) or {}
    ok("combination report: the host's region is Murang'a, as on every page", [r["label"] for r in sm.get("regions") or []] == [WANT["region"]],
       sm.get("regions"))
    ok("...its region details carry their full counts (totals: cities, networks)", rd.get("totals") == {"cities": 1, "networks": 1}, rd)
except Exception as exc:                                   # noqa: BLE001
    import traceback
    traceback.print_exc()
    ok("the combination report ran", False, f"{type(exc).__name__}: {exc}")

# ---------------------------------------------------------------------- 4. the day loaders
print("4. The day loaders: a row in two files of one day once, late and undated rows counted and stated")


class Coll:
    def __init__(self, docs):
        self.docs = docs

    def find(self, q=None, proj=None):
        pats = [c["filename"]["$regex"] for c in (q or {}).get("$or", [])]
        return [dict(d) for d in self.docs if not pats or any(re.match(p, d.get("filename", "")) for p in pats)]

    def count_documents(self, q):
        return len(self.find(q))


class DB(dict):
    def __getitem__(self, k):
        return dict.get(self, k) or Coll([])


def doc(fn, ts, ip, lh, **kw):
    from bson import ObjectId
    d = {"_id": ObjectId(), "filename": fn, "line_hash": lh, "ip": ip, "asn": "64500", "region": "NAIROBI", "geo": "KE",
         "extracted_date": datetime.strptime(ts, "%Y-%m-%d %H:%M:%S") if ts else None, "tag": "", "severity": "high"}
    d.update(kw)
    return d


F_GEO, F_ASN = "2026-11-20-scan_http-kenya-geo.csv", "2026-11-20-scan_http-lakeside-asn.csv"
rows = [doc(F_GEO, "2026-11-19 10:00:00", "192.0.2.1", "h1"), doc(F_ASN, "2026-11-19 10:00:00", "192.0.2.1", "h1"),   # one row, two files
        doc(F_GEO, "2026-11-19 11:00:00", "192.0.2.5", "h5"),
        doc(F_GEO, "2026-11-16 10:00:00", "192.0.2.2", "h2"),           # 3 days before its file: never on a page
        doc(F_GEO, "", "192.0.2.4", "h4")]                              # no time
src = {"name": "scan_http", "label": "Accessible HTTP", "family": "Exposed service", "filename_index": True}


class Reg:
    def get(self, force=False):
        return [src]


try:
    stv = SV.ServiceStore(DB(scan_http=Coll(rows)), Reg(), types.SimpleNamespace(ref=lambda ip: "r" + ip), None)
    day = stv._load(START)
    ok("services loader: the row of the geo file and the ASN file is kept once (2 records, it showed 3)",
       sorted(e["ip"] for e in day.events) == ["192.0.2.1", "192.0.2.5"], [e["ip"] for e in day.events])
    ok("...counted and stated: 1 kept once, 1 dated outside, 1 without a time",
       day.load_notes == {"dups": 1, "outside": 1, "undated": 1}, getattr(day, "load_notes", None))
    ok("...no file name or line hash left on a record (never sent)", not any("line_hash" in e or "line_hash" in (e.get("extras") or {})
                                                                            for e in day.events))
    note = CK.load_note(**{"dups": 1, "outside": 1, "undated": 1}, day="2026-11-19")
    ok("...the sentence the pages show", note == "1 row also in another file that day (counted once); 1 row of this day's report "
       "files is dated outside 2026-11-19 (not shown on any day); 1 row of this day's report files has no time (not shown on any day).", note)
    csrc = {"name": "event4_sinkhole_http", "label": "Sinkhole HTTP", "class": "Botnet / infection", "layout": "standard", "filename_index": True}
    crow = lambda fn, ts, ip, lh: doc(fn, ts, None, lh, src_ip=ip, src_asn="64500", src_region="NAIROBI", src_geo="KE")   # noqa: E731
    cdocs = [crow(F_GEO.replace("scan_http", "event4_sinkhole_http"), "2026-11-19 10:00:00", "192.0.2.1", "c1"),
             crow(F_ASN.replace("scan_http", "event4_sinkhole_http"), "2026-11-19 10:00:00", "192.0.2.1", "c1"),
             crow(F_GEO.replace("scan_http", "event4_sinkhole_http"), "2026-11-17 10:00:00", "192.0.2.2", "c2"),
             crow(F_GEO.replace("scan_http", "event4_sinkhole_http"), "", "192.0.2.4", "c4")]
    real_db = A.db
    A.db = DB(event4_sinkhole_http=Coll(cdocs))
    try:
        got = A.DayStore()._fetch_collection(csrc, START, START + timedelta(days=1))[0]
    finally:
        A.db = real_db
    ok("map loader: the same, one record for the row in two files, 1 dated outside, 1 without a time",
       len(got) == 1 and (got.dups, got.outside, got.undated) == (1, 1, 1), (len(got), getattr(got, "dups", None)))
except Exception as exc:                                   # noqa: BLE001
    import traceback
    traceback.print_exc()
    ok("the day loaders ran", False, f"{type(exc).__name__}: {exc}")

# ---------------------------------------------------------------------- 6. the quarterly query (throwaway database)
print("6. The quarterly report's query: a row in two files of one day counts once")
client = None
try:
    import _throwaway_mongo  # noqa: E402
    from dotenv import dotenv_values  # noqa: E402
    _env = dotenv_values(os.path.join(PLATFORM, ".env"))
    client = _throwaway_mongo.client(_env.get("MONGO_HOST") or "127.0.0.1", _env.get("MONGO_PORT") or 27017)
except Exception:                                          # noqa: BLE001
    client = None
if client is None:
    print("  skipped: no account here may create a throwaway database (tests/run_admin_db_tests.sh)")
else:
    DBN = f"lg_count_keys_test_{secrets.token_hex(4)}"
    assert DBN.startswith("lg_count_keys_test_")
    try:
        qdb = client[DBN]
        base = {"port": 80, "geo": "KE", "region": "NAIROBI", "sector": "Communications", "severity": "medium", "tag": ""}
        qdb["scan_http"].insert_many([
            dict(base, ip="192.0.2.1", asn="64500", filename="2026-11-20-scan_http-kenya-geo.csv", line_hash="q1", extracted_date="2026-11-19 10:00:00"),
            dict(base, ip="192.0.2.1", asn="64500", filename="2026-11-20-scan_http-lakeside-asn.csv", line_hash="q1", extracted_date="2026-11-19 10:00:00"),
            dict(base, ip="192.0.2.2", asn="64500", filename="2026-11-20-scan_http-kenya-geo.csv", line_hash="q2", extracted_date="2026-11-19 11:00:00"),
            dict(base, ip="192.0.2.3", asn="64500", filename="2026-11-21-scan_http-kenya-geo.csv", line_hash="q1", extracted_date="2026-11-20 10:00:00")])
        RQ = QY.collect_db(qdb, 2026, 4, date(2026, 12, 1))
        ok("quarterly: 3 records (the copy in the ASN file of the same day once; the same hash on another day is its own row)",
           RQ["rep_total"]["scan_http"] == 3 and RQ["rep_dups"]["scan_http"] == 1, (RQ["rep_total"], RQ.get("rep_dups")))
        XQ = QY.figures(RQ, None, TMP, date(2026, 12, 1))
        ok("...stated: 1 row also in another file; the events' dates", XQ["duplicates"] == 1 and XQ["event_span"] == ("2026-11-19", "2026-11-20"),
           (XQ["duplicates"], XQ["event_span"]))
    finally:
        client.drop_database(DBN)

CK._CFG.update(REAL["cfg"])
A.asn_registry.path, A.asn_registry.mtime = REAL["path"], None
shutil.rmtree(TMP, ignore_errors=True)
print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
