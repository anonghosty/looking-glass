#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""Nothing goes missing or misleads in the server's lists and shares (the production release, 2026-11-26), on a
made-up day of 43,281 events and 2,500 service records, no database, nothing of the installation written:

1. The map side panel (/api/stats): every severity (there are six), totals and others beside each top list, so the
   rows plus Other equal the total.
2. The drop-downs (/api/facets, /api/svc/facets): every city and network, past the old cuts of 300 and 400.
3. The host popup (/api/related): how many infections, domains and destination IPs there are beside the 10 listed.
4. The analysis (/api/insight): totals / others / unrecorded beside each breakdown (rows + Other + Not recorded =
   the selection), attack types and severities never cut, "Found in N reports" with every report, a share of
   1 in 43,281 kept (it was rounded to 0); drill-down shares never "0.0%" for a part with events nor "100.0%" for a
   part; a destination IP's every domain.
5. The insight PDF: "Top 8 of 31" in the table titles, an "Other (N more)" row, every report in the References,
   the KPI share "<0.1%".
6. Services: networks and issues with totals and an exact Other (a record counts once however many of its issues
   are cut), regions never cut, the findings' shares, every issue and service of a drill-down row, the services PDF's
   cut titles and Other rows, EPSS "<0.1%".
Run: .venv/bin/python tests/check_nothing_missing_api.py"""
import os
import sys
import tempfile
from datetime import timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("LG_QUIET", "1")
os.environ.setdefault("THREATMAP_SCHEDULE", "0")
os.environ["TRUST_PROXY"] = "0"
os.environ["SLOW_REQUEST_S"] = "600"
import app as A  # noqa: E402
import reports_pdf  # noqa: E402
import services as SV  # noqa: E402
import sources  # noqa: E402
from flask import g  # noqa: E402
from shares import pct  # noqa: E402

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{str(info)[:400]}]" if info and not cond else ""), flush=True)


TMP = tempfile.mkdtemp(prefix="lg-nothing-missing-")
A.asn_registry.path = os.path.join(TMP, "asns.json")         # an empty network registry of its own
A.asn_registry.mtime, A.asn_registry.asns = None, {}
REAL = {"has_perm": A.AUTH["has_perm"], "audit": A.AUTH["audit"].add, "enrich": A._enrich_names,
        "issues": A.issues_resolve, "build": reports_pdf.build, "P": reports_pdf.P}
A.AUTH["has_perm"] = lambda p: True
A.AUTH["audit"].add = lambda *a, **k: None
A._enrich_names = lambda ordered: ({}, {}, "")             # no Malpedia
SPECS, DRAWN = [], []
reports_pdf.build = lambda spec: (SPECS.append(spec), REAL["build"](spec))[1]
reports_pdf.P = lambda text, st, **kw: (DRAWN.append(str(text)), REAL["P"](text, st, **kw))[1]
USER = {"user": "made-up-analyst", "perms": {"view", "unmasked", "export", "malpedia"}}

RN = A.replay_now()
START = A.day_start(RN)
SPAN = max(60.0, (RN - START).total_seconds() - 1)

# ---------------------------------------------------------------------- the made-up day: network communications
N = 43281
SRCS = [{"name": f"event4_made_up_{i:02d}", "label": f"Made-up report {i:02d}", "class": ["Botnet / infection", "Brute force",
         "Scanning"][i % 3], "layout": "standard", "filename_index": True} for i in range(15)]
SEVS = ["critical", "high", "medium", "low", "info", ""]
BASE = []
for s in SRCS:
    t = START + timedelta(seconds=1)
    doc = {"timestamp": t, "extracted_date": t, "src_ip": "192.0.2.1", "src_port": 50000, "src_asn": "64500", "src_geo": "GH",
           "src_region": "GREATER ACCRA", "src_city": "ACCRA", "dst_ip": "198.51.100.7", "dst_port": 80, "dst_asn": "64501",
           "dst_geo": "US", "dst_city": "ASHBURN", "http_host": "c2.example.com", "http_url": "GET /gate.php HTTP/1.1",
           "http_agent": "Mozilla/5.0 (made-up)", "infection": "x", "tag": "botnet", "severity": "high", "protocol": "tcp",
           "filename": f"{START:%Y-%m-%d}-{s['name']}-example-asn.csv", "_id": "base"}
    n = sources.normalise(doc, s)
    for f, v in list(n.items()):
        if hasattr(v, "isoformat"):
            n[f] = A.iso(v)
    BASE.append(n)
H = "192.0.2.250"                       # the host of the popup: 12 infections, 14 domains, 11 destination IPs
EVENTS = []
for i in range(N):
    si = 0 if i < 30000 else 1 + i % 13                     # report 00 is the big one, report 14 has a single event
    if i == N - 1:
        si = 14
    e = dict(BASE[si])
    t = START + timedelta(seconds=SPAN * i / N)
    sev = ("low" if i == 7 else "high") if si == 0 else ("high" if si == 14 else SEVS[i % 6])
    e.update(_t=t.timestamp(), extracted_date=A.iso(t), id=f"{e['source']}:nm{i}", severity=sev,
             infection="rarebot" if i == 20 else f"inf{i % 30:02d}", src_ip=f"10.{i % 5000 // 250}.{i % 250}.1",
             src_city=f"CITY{i % 350:03d}", src_asn=str(4200000000 + i % 320), dst_ip=f"198.51.100.{i % 200}",
             http_host="" if i % 4 == 0 else f"dom{i % 40}.example", tag=f"tag{i % 9}", dst_port=1000 + i % 15)
    if i < 14:                                              # the popup's host
        e.update(src_ip=H, infection=f"hostinf{i % 12}", http_host=f"hostdom{i}.example", dst_ip=f"203.0.113.{i % 11}")
    e["src_ref"] = A.host_refs.ref(e["src_ip"])
    e["src_coords"], e["dst_coords"] = [-0.19, 5.6], [-77.49, 39.04]
    e["request"] = A._request_path(e["http_url"]) if e.get("http_url") else ""
    EVENTS.append(e)
for k in range(5):                      # one destination IP named by five domains
    EVENTS[100 + k * 4 + 1].update(dst_ip="198.51.100.250", http_host=f"five{k}.example")
DAY = A.Day(START, EVENTS)
DAY.per_source = dict(A.Counter(e["source"] for e in EVENTS))
DAY.arrived, DAY.sig, DAY.raw_total, DAY.by_src = {}, None, len(EVENTS), {}
DAY.asn_raw = {}
DAY.gen, DAY.settings_version = A.store.gen, A.settings.version

# ---------------------------------------------------------------------- the made-up day: services
M = 2500
SSRC = {"name": "scan_http", "label": "HTTP", "family": "Accessible", "filename_index": True}
t = START + timedelta(seconds=1)
sbase = SV.normalise_service({"timestamp": t, "extracted_date": t, "ip": "192.0.2.10", "port": 443, "protocol": "tcp", "asn": "64500",
                              "geo": "GH", "region": "ASHANTI", "city": "ACCRA", "hostname": "", "severity": "high",
                              "tag": "vulnerable", "server": "ExampleServer/1.0",
                              "filename": f"{START:%Y-%m-%d}-scan_http-example-asn.csv", "_id": "sbase"}, SSRC)
SEV = []
for i in range(M):
    e = dict(sbase)
    t = START + timedelta(seconds=SPAN * i / M)
    iss = sorted({f"issue-{i % 12:02d}", f"issue-{(i * 7 + 3) % 12:02d}"})
    asn = "4200009999" if i == 11 else str(4200001000 + i % 15)             # one network with a single record
    e.update(_t=t.timestamp(), extracted_date=SV._s(t), id=f"scan_http:snm{i}", ip=f"10.200.{i % 250}.{i // 250}",
             port=type(sbase["port"])(9999 if i == 13 else 443), asn=asn, region=f"REGION {i % 12:02d}", city=f"TOWN{i % 450:03d}",
             issues=iss, vulnerable=True, severity=SEVS[i % 5])
    e["ip_ref"] = A.host_refs.ref(e["ip"])
    SEV.append(e)
SDAY = SV.Day(START, SEV)
SDAY.per_source, SDAY.arrived, SDAY.sig = {"scan_http": len(SEV)}, {}, None
SDAY.by_src = {"scan_http": {"raw": len(SEV), "asn": {}, "region": {}, "blocks": {}, "rows": SEV, "last": None}}
SDAY.gen, SDAY.settings_version, SDAY.raw_total = getattr(A.svc["store"], "gen", 0), A.settings.version, len(SEV)
SDAY.asn_raw, SDAY.region_raw = {}, {}

REAL_STORE = (A.store.get, A.store.days, A.svc["store"].get, A.svc["store"].days, A.registry.get, A.registry.items,
              A.registry.unsupported, A.registry.names, A.svc["registry"].get, A.svc["registry"].items,
              A.svc["registry"].unsupported, A.svc["registry"].names, A.settings.in_scope)
A.settings.in_scope = lambda asn, ip: True
A.store.get = lambda dt=None: DAY
A.store.days = {START: DAY}
A.svc["store"].get = lambda dt=None: SDAY
A.svc["store"].days = {START: SDAY}
diag = {"checks": [], "compatible": True, "layout": "standard", "missing": [], "missing_fields": [], "required_ok": 5,
        "required_total": 5, "warnings": []}
ENTRIES = [dict(s, diagnostic=diag, latest="") for s in SRCS]
A.registry.get = lambda *a, **k: ENTRIES
A.registry.items, A.registry.unsupported, A.registry.names = ENTRIES, [], [e["name"] for e in ENTRIES]
SENTRY = dict(SSRC, diagnostic=dict(diag, layout="single-host"), layout="single-host", fields=[], **{"class": "Accessible"})
A.svc["registry"].get = lambda *a, **k: [SENTRY]
A.svc["registry"].items, A.svc["registry"].unsupported, A.svc["registry"].names = [SENTRY], [], ["scan_http"]


def view(name, **args):
    """A view's answer, called the way Flask calls it (the sign-in and step-up gates are not what is checked here)."""
    with A.app.test_request_context("/x", query_string=args):
        g.user = USER
        r = A.app.view_functions[name]()
        return r if isinstance(r, tuple) else (r.get_json() if r.mimetype == "application/json" else r.get_data())


def adds_up(rows, other, none, total):
    return sum(r["count"] for r in rows) + other + none == total


try:
    print("1. The map side panel: every severity, totals and others beside each top list")
    st = A._stats_core(DAY, {}, False)
    ok("all six severities are sent (the old cut was 5)", len(st["severity"]) == 6, [r["value"] for r in st["severity"]])
    N_INF = len({e["infection"] for e in EVENTS})              # 30 + rarebot + the popup host's 12
    ok(f"totals: {N_INF} infections, 15 reports, 320 source networks", st.get("totals", {}).get("infection") == N_INF
       and st["totals"].get("source") == 15 and st["totals"].get("src_network") == 320, st.get("totals"))
    ok("…the top 8 infections plus Other equal the total", len(st["infection"]) == 8
       and adds_up(st["infection"], st["others"]["infection"], 0, st["total"]), st.get("others"))
    ok("…the top 8 source networks plus Other plus Not recorded equal the total",
       adds_up(st["src_network"], st["others"]["src_network"], st["unrecorded"]["src_network"], st["total"]))
    ok("…attack types are never cut", len(st["attack_class"]) == len({e["attack_class"] for e in EVENTS}))
    # the one counting rule (2026-11-26): AS0, 0 and no AS number are no network (they were counted as "AS0")
    few = [dict(e) for e in EVENTS[:10]]
    for e, a in zip(few, ("0", "AS0", "", "0")):
        e["src_asn"] = a
    st0 = A._stats_core(A.Day(START, few), {}, False)
    names0 = [r["value"] for r in st0["src_network"]]
    ok("AS0, 0 and none are no network: no 'AS0' row, the 4 counted as not recorded",
       not any(n in ("AS0", "0", "") for n in names0) and st0["unrecorded"]["src_network"] == 4
       and st0["totals"]["src_network"] == len({e["src_asn"] for e in few[4:]}), (names0, st0["unrecorded"], st0["totals"]))

    print("2. The drop-downs: every value, past the old cuts")
    fc = A._facets_core(DAY, False)
    ok("all 350 cities can be chosen (the old cut was 300)", len(fc["src_city"]) == 350, len(fc["src_city"]))
    ok("all 320 source networks can be chosen (the old cut was 300)", len(fc["src_asn"]) == 320, len(fc["src_asn"]))
    sf = view("svc_facets")
    ok("services: all 450 cities can be chosen (the old cut was 400)", len(sf["facets"]["city"]) == 450, len(sf["facets"]["city"]))

    print("3. The host popup: totals beside the 10 listed")
    rl = view("api_related", src_ip=H)
    ok("12 infections, 14 domains, 11 destination IPs in all; 10 of each listed",
       rl.get("totals") == {"infections": 12, "hosts": 14, "dst_ips": 11} and len(rl["infections"]) == 10, rl.get("totals"))

    print("4. The analysis: what each breakdown leaves out")
    I = view("api_insight", kind="severity", value="high")
    sel = [e for e in EVENTS if e["severity"] == "high"]
    ok("totals, others and unrecorded beside the breakdowns", all(k in I for k in ("totals", "others", "unrecorded")))
    bad = [k for k, rows in I["breakdowns"].items() if not adds_up(rows, I["others"][k], I["unrecorded"][k], I["total"])]
    ok("every breakdown: rows + Other + Not recorded = the selection", not bad and I["total"] == len(sel), bad)
    S_INF = len({e["infection"] for e in sel})
    ok(f"…{S_INF} infections in all, 8 listed", I["totals"]["infection"] == S_INF > 8
       and len(I["breakdowns"]["infection"]) == 8, I["totals"])
    ok("…attack types never cut", len(I["breakdowns"]["attack_class"]) == len({e["attack_class"] for e in sel}))
    found = next((s for s in I["insights"] if s.startswith("Found in")), "")
    ok("'Found in 15 reports' (the old text counted the 12 listed)", found.startswith("Found in 15 reports")
       and "and 11 more reports" in found, found)
    ok("…every report of the selection is named for the PDF", len(I.get("report_names") or []) == 15)
    R1 = view("api_insight", kind="infection", value="rarebot")
    ok("a share of 1 in 43,281 is kept (rounded to 4 places it was 0, read '0%')", R1["share"] > 0
       and pct(R1["share"], 1) == "<0.1%", R1["share"])
    D = view("api_insight_drill", kind="severity", value="high", metric="share")
    by = {r["value"]: r for r in D["rows"]}
    big, tiny = by[SRCS[0]["name"]], by[SRCS[14]["name"]]
    ok("drill-down: 29,999 of report 00's 30,000 events reads '>99.9%', not '100.0%'", big["mine_share"] == ">99.9%", big)
    ok("…the report with 1 of 43,281 events reads '<0.1%', not '0.0%'", tiny["share_all"] == "<0.1%", tiny)
    ok("…the selection's part of the day in the intro is never 0.0% or 100.0%", "0.0%)" not in D["intro"] and "100.0%)" not in D["intro"])
    D = view("api_insight_drill", kind="severity", value="high", metric="reports")
    ok("drill-down 'reports': the one-event report's share is '<0.1%'",
       next(r["share"] for r in D["rows"] if r["value"] == SRCS[14]["name"]) == "<0.1%")
    E = view("api_insight_drill", kind="attack_class", value=BASE[0]["attack_class"], metric="dst_ips", all="1")
    five = next((r for r in E["rows"] if r["dst"] == "198.51.100.250"), {})
    ok("a destination IP named by five domains lists all five (the old cut was 3)", len(five.get("domains") or []) == 5, five.get("domains"))

    print("5. The insight PDF")
    SPECS.clear()
    pdf = view("api_insight_report_pdf", kind="severity", value="high", metric="hosts", all="1", format="pdf")
    sp = SPECS[-1] if SPECS else {}
    ok("the PDF renders", isinstance(pdf, bytes) and pdf[:4] == b"%PDF")
    bds = {b[0]: b[2] for b in sp.get("breakdowns", [])}
    inf = bds.get(f"Infections / categories: Top 8 of {S_INF}")
    ok(f"a cut table says so: 'Infections / categories: Top 8 of {S_INF}'", inf is not None, list(bds))
    ok(f"…and ends with 'Other ({S_INF - 8} more)'", inf and inf[-1][0] == f"Other ({S_INF - 8} more)", inf and inf[-1])
    ok("…its counts add up to the selection", inf and sum(int(r[1].replace(",", "")) for r in inf) == len(sel))
    ok("…a list given in full keeps its plain name (Attack types)", "Attack types" in bds, list(bds))
    ok("Reports: 'Top 12 of 15'", "Reports: Top 12 of 15" in bds, list(bds))
    ok("…the domains table ends with 'Not recorded' for events without a domain",
       any(r[0] == "Not recorded" for k, rows in bds.items() if k.startswith("C2 / sinkhole domains") for r in rows))
    # a part with events never "0.0%", a part of the selection never "100.0%" (a value every event has is 100%)
    zero = [(k, r) for k, rows in bds.items() for r in rows
            if r[-1] == "0.0%" or (r[-1] == "100.0%" and int(r[1].replace(",", "")) != len(sel))]
    ok("…no share reads '0.0%', nor '100.0%' for a part", not zero, zero[:4])
    ch = dict(sp.get("charts", []))
    ok("the charts carry the cut in their titles and an Other bar", any(k.startswith("Reports: Top 12 of 15") and v[-1]["label"].startswith("Other")
                                                                       for k, v in ch.items()), list(ch))
    ok("References name every report of the selection (15, not the 12 listed)", len(sp.get("glossary", [])) == 15, len(sp.get("glossary", [])))
    ok("'Found in 15 reports' in the summary", any(str(p).startswith("Found in 15 reports") for p in sp.get("summary_points", [])))
    SPECS.clear()
    view("api_insight_report_pdf", kind="infection", value="rarebot", metric="hosts", all="1", format="pdf")
    k2 = dict((lbl, v) for v, lbl in (SPECS[-1]["kpis"] if SPECS else []))
    ok("the KPI tile of 1 in 43,281 reads '<0.1%', not '0.0%'", k2.get(f"of the day's {N:,} events") == "<0.1%", k2)
    # three infections explained with the same techniques and the same researcher's note
    TECH = [{"id": "T1071.001", "name": "Web Protocols", "tactics": ["Command and Control"], "certainty": "observed",
             "certainty_label": "Observed", "status": "suggested", "url": "https://attack.mitre.org/techniques/T1071/001/"},
            {"id": "T1573", "name": "Encrypted Channel", "tactics": ["Command and Control"], "certainty": "possible",
             "certainty_label": "Possible", "status": "reviewed", "url": "https://attack.mitre.org/techniques/T1573/"}]
    NOTE = {"role": "Researcher/TI", "by": "A made-up researcher", "date": "2026-11-16",
            "text": "These devices call the same made-up sinkhole every hour; follow them up together with their provider.",
            "codes": [{"code": "LG-B-0000TEST", "text": "the made-up combination of these three names"}]}
    CARDS = {f"inf{i:02d}": {"found": True, "name": f"Examplebot {i}", "family": f"win.examplebot{i}", "sources": ["Malpedia"],
                             "description": f"Examplebot {i} is a made-up family that calls a command server over the web.",
                             "attack": {"version": "18.1", "techniques": [dict(x) for x in TECH]}, "notes": [dict(NOTE)]}
             for i in range(3)}
    A._enrich_names = lambda ordered: (CARDS, {n: "made-up" for n in CARDS}, "Made-up explanations.")
    SPECS.clear(); DRAWN.clear()
    cpdf = view("api_insight_report_pdf", kind="severity", value="high", metric="hosts", all="1", format="pdf")
    web = [d for d in DRAWN if "T1071.001 Web Protocols" in d]
    ok("each ATT&CK technique printed once, naming the three infections it is mapped for",
       len(web) == 1 and all(n in web[0] for n in CARDS), web)
    ok("…the shared note printed once, the other cards point to it",
       sum("Notes shared by" in d for d in DRAWN) == 1 and sum("the same as for inf00" in d for d in DRAWN) >= 2,
       [d[:80] for d in DRAWN if "Notes" in d or "same" in d])
    # the same note saved twice on one name, and two CVEs with one CISA action but different due dates (2026-11-27)
    ACT = "Apply mitigations per vendor instructions or discontinue use of the made-up product."
    CARDS = {"inf00": {**CARDS["inf00"], "notes": [dict(NOTE), dict(NOTE)]}}
    for i, due in ((1, "2026-01-02"), (2, "2026-03-04")):
        CARDS[f"CVE-2026-0000{i}"] = {"kind": "cve", "found": True, "description": f"Made-up flaw number {i}.",
                                     "kev": {"action": ACT, "due": due, "date_added": "2026-01-01", "vendor": "Example", "product": "Box"}}
    A._enrich_names = lambda ordered: (CARDS, {n: "made-up" for n in CARDS}, "Made-up explanations.")
    SPECS.clear(); DRAWN.clear()
    view("api_insight_report_pdf", kind="severity", value="high", metric="hosts", all="1", format="pdf")
    ok("…a note saved twice on one name printed once (and its combinations once)",
       sum("Notes shared by" in d for d in DRAWN) == 1 and sum("LG-B-0000TEST" in d for d in DRAWN) == 1,
       [d[:80] for d in DRAWN if "Notes" in d or "LG-B" in d])
    acts = [d for d in DRAWN if ACT[:40] in d]
    ok("…one CISA action under two CVEs printed once; the second points to it with its own due date",
       len(acts) == 1 and "2026-01-02" in acts[0] and any("the same as for CVE-2026-00001" in d and "2026-03-04" in d for d in DRAWN),
       [d[:120] for d in DRAWN if "required action" in d])
    A._enrich_names = lambda ordered: ({}, {}, "")

    print("6. Services")
    S = view("svc_insight")
    shown = {r["value"] for r in S["breakdowns"]["network"]}
    net = lambda e: A.asn_registry.label(e["asn"], False) if e["asn"] else ""
    ok("networks: 16 in all, 10 listed", S.get("totals", {}).get("network") == 16 and len(S["breakdowns"]["network"]) == 10, S.get("totals"))
    ok("…Other is the records outside the 10 rows", S["others"]["network"] == sum(1 for e in SEV if net(e) not in shown), S["others"])
    ok("…rows + Other + Not recorded = the selection", adds_up(S["breakdowns"]["network"], S["others"]["network"],
                                                          S["unrecorded"]["network"], M))
    ishown = {r["value"] for r in S["breakdowns"]["issue"]}
    ok("issues: 12 in all; Other counts each record once, however many of its issues are cut",
       S["totals"]["issue"] == 12 and S["others"]["issue"] == sum(1 for e in SEV if any(i not in ishown for i in e["issues"])), S["others"]["issue"])
    ok("regions are never cut (12 of 12, the old cut was 10)", len(S["breakdowns"]["region"]) == 12, len(S["breakdowns"]["region"]))
    S1 = view("svc_insight", port="9999")
    ok("finding: 1 of 2,500 records reads '<0.1% of the day's records', not '0.0%'",
       "<0.1% of the day's records" in S1["findings"][0], S1["findings"][0])
    SD = view("svc_drill", metric="networks", all="1")
    row = SD["rows"][0]
    ok("drill-down networks: every issue of a row (12, the old cut was 6)", len(row["issues"].split(", ")) == len({i for e in SEV if net(e) == row["value"] for i in e["issues"]}),
       row["issues"])
    ok("…the single-record network's share reads '<0.1%'", next(r["share"] for r in SD["rows"] if r["events"] == 1) == "<0.1%")
    SPECS.clear()
    DRAWN.clear()
    ACTION = "Apply mitigations per the made-up vendor's instructions, or stop using the product if there are none."
    A.issues_resolve = lambda order, budget=0: {name: {
        "kind": "cve", "found": True, "exploited": True, "epss": 0.0004, "cvss": {"version": "3.1", "score": 9.8 - i, "severity": "critical"}, "description": f"A made-up flaw number {i} in a made-up product.",
        "kev": {"name": f"Made-up flaw {i}", "date_added": "2026-01-05", "vendor": "Example", "product": "Product", "action": ACTION,
                "due": "2026-02-01"},
        "attack": {"version": "18.1", "techniques": [dict(TECH[0])]}} for i, name in enumerate(order[:2])}
    spdf = view("api_svc_report_pdf", metric="hosts", all="1", format="pdf")
    ok("CISA's required action shared by two CVEs printed once, the other card points to it",
       sum("<b>CISA's required action:</b>" in d for d in DRAWN) == 1 and any("CISA's required action: the same as" in d for d in DRAWN),
       [d[:90] for d in DRAWN if "required action" in d])
    sp = SPECS[-1] if SPECS else {}
    ok("the services PDF renders", isinstance(spdf, bytes) and spdf[:4] == b"%PDF")
    sb = {b[0]: b[2] for b in sp.get("breakdowns", [])}
    nets = sb.get("Networks: Top 10 of 16")
    ok("'Networks: Top 10 of 16' with an Other row", nets and nets[-1][0] == "Other (6 more)", list(sb))
    ok("…Regions given in full under their plain name", "Regions" in sb and len(sb["Regions"]) == 12, list(sb))
    ok("EPSS of 0.04% reads '<0.1%' in the PDF, not '0.0%'", any("EPSS: &lt;0.1%" in d or "EPSS: <0.1%" in d for d in DRAWN),
       [d[:120] for d in DRAWN if "EPSS:" in d][:2])
    ok("…and in the short text", "EPSS <0.1%" in A._short({"kind": "cve", "found": True, "epss": 0.0004}))

    print("7. The PDFs as a reader sees them (tests/pdf_pages_check.py: no ATT&CK or paragraph twice, no '0%' share)")
    import importlib.util
    import subprocess
    files = []
    for nm, data in (("comms_analysis.pdf", cpdf), ("services_analysis.pdf", spdf), ("comms_plain.pdf", pdf)):
        p = os.path.join(TMP, nm)
        open(p, "wb").write(data)
        files.append(p)
    # the PDF reader (pypdfium2) in the Python running this, as on GitHub's checks: that Python as it is. Otherwise the
    # screenshot tools' Python, with the platform's libraries beside it when there is a .venv (a release folder or a
    # GitHub checkout has none: listing a missing .venv/lib stopped this check there, 2026-11-27)
    if importlib.util.find_spec("pypdfium2"):
        py, env = sys.executable, dict(os.environ)
    else:
        py = os.environ.get("LG_PDF_PYTHON") or os.path.expanduser("~/lg-shots/venv/bin/python")
        lib = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".venv", "lib")
        site = next((os.path.join(lib, x) for x in (sorted(os.listdir(lib)) if os.path.isdir(lib) else []) if x.startswith("python3")), "")
        env = dict(os.environ, PYTHONPATH=os.path.join(site, "site-packages")) if site else dict(os.environ)
    if os.path.exists(py):
        r = subprocess.run([py, os.path.join(os.path.dirname(os.path.abspath(__file__)), "pdf_pages_check.py")] + files,
                           capture_output=True, text=True, env=env, timeout=600)
        ok("the three made-up PDFs pass the reader's check", r.returncode == 0, (r.stdout + r.stderr)[-1500:])
    else:
        print(f"  (skipped: no Python with pypdfium2 at {py}; set LG_PDF_PYTHON)")
finally:
    (A.store.get, A.store.days, A.svc["store"].get, A.svc["store"].days, A.registry.get, A.registry.items,
     A.registry.unsupported, A.registry.names, A.svc["registry"].get, A.svc["registry"].items,
     A.svc["registry"].unsupported, A.svc["registry"].names, A.settings.in_scope) = REAL_STORE
    A.AUTH["has_perm"], A.AUTH["audit"].add, A._enrich_names, A.issues_resolve = REAL["has_perm"], REAL["audit"], REAL["enrich"], REAL["issues"]
    reports_pdf.build, reports_pdf.P = REAL["build"], REAL["P"]

print(f"{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
