#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""External accounts (the user, 2026-11-21): exactly three things, all masked, and everything else refused on the server.

1. Who is external: permissions exactly {"view"} (external_access.is_external); the built-in role always matches.
2. Refused: every route of the app (its url_map) that is not on the allow-list (external_access.ALLOWED) refuses a
   signed-in external session at the sign-in gate (403, pages and APIs, every method), before the route runs; every
   path on the allow-list is a real route.
3. Abused or Compromised, made-up rows (no database): the masked view shows no IP address, real network or company
   name, host name, organisation, account or e-mail address; filters and the search see only the masked values; no
   export, host look-up, reveal or analyst code. Analysts keep their view.
4. The two platforms with a made-up day (documentation addresses, private AS numbers, made-up names; the day stores are
   replaced in memory, nothing is read from or written to a database for them): every API the map and the services
   pages call, as an external account, carries no address, made-up host name, network or company name, e-mail address
   or name from the network registry (data/asns.json). A finding prints where and what kind, never a registry value.
Run: .venv/bin/python tests/check_external_masking.py"""
import json
import os
import re
import sys
from datetime import timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("LG_QUIET", "1")
os.environ.setdefault("THREATMAP_SCHEDULE", "0")
os.environ["TRUST_PROXY"] = "0"                    # the app is called in-process (proxy_guard.py)

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{str(info)[:400]}]" if info and not cond else ""), flush=True)


IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
IPV6 = re.compile(r"(?<![\w:])2001:db8:[0-9a-f:]*", re.I)               # the made-up IPv6 addresses
EMAIL = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
MARK = "lakeside"          # every made-up name of a constituent: host names, domains, e-mails, organisations, networks


def leaks(text, registry_names=(), generic=True):
    """The kinds of leak in a response body (never the values of the registry)."""
    out = []
    low = text.lower()
    if MARK in low:
        i = low.index(MARK)
        out.append(f"made-up name ({text[max(0, i - 30):i + 30]!r})")
    if IPV6.search(text):
        out.append(f"IPv6 address ({IPV6.search(text).group(0)})")
    if generic:
        m = IPV4.search(text)
        if m:
            out.append(f"IPv4 address ({m.group(0)})")
        m = EMAIL.search(text)
        if m and "<email>" not in m.group(0):
            out.append(f"e-mail address ({m.group(0)})")
    for n in (registry_names if generic else ()):
        if re.search(r"(?<![\w])" + re.escape(n) + r"(?![\w])", text, re.I):
            out.append("a network or company name from data/asns.json")
            break
    return out


# ---------------------------------------------------------------------- made-up data (nothing here is real)
def intel_fixture():
    """A stand-in database of Abused or Compromised reports: documentation addresses, a private AS number, names
    containing 'lakeside'. Returns (db, report map, report days, Settings class)."""
    from datetime import datetime, timezone

    class Cur(list):
        def limit(self, n):
            return Cur(self[:n])

    class Coll:
        def __init__(self, rows):
            self.rows = rows

        def _m(self, r, q):
            for k, v in q.items():
                if k == "$or":
                    if not any(self._m(r, s) for s in v):
                        return False
                elif isinstance(v, dict) and "$regex" in v:
                    if not re.match(v["$regex"], str(r.get(k, ""))):
                        return False
                elif r.get(k) != v:
                    return False
            return True

        def find(self, q=None, proj=None):
            out = [r for r in self.rows if self._m(r, q or {})]
            if proj and any(v == 1 for v in proj.values()):
                out = [{k: r[k] for k in proj if proj[k] == 1 and k in r} for r in out]
            elif proj:
                out = [{k: v for k, v in r.items() if proj.get(k) != 0} for r in out]
            return Cur(out)

        def count_documents(self, q):
            return len(self.find(q))

        def estimated_document_count(self):
            return len(self.rows)

    class FakeDB(dict):
        def list_collection_names(self):
            return list(self)

    T = datetime.now(timezone.utc).date() - timedelta(days=1)
    D = [(T - timedelta(days=i)).isoformat() for i in range(8)]

    def row(day, n, **kw):
        return dict({"filename": f"{day}-x-lakeside-asn.csv", "timestamp": f"{day} 0{n % 9}:00:00", "line_hash": f"{day}{n}",
                     "asn": "64500", "region": "GREATER ACCRA", "city": "ACCRA"}, **kw)

    db = FakeDB({
        "compromised_website": Coll([row(D[1], n, ip=f"192.0.2.{n + 1}", hostname=f"www{n}.lakeside-tel.example",
                                         url=f"http://shop{n}.lakeside-tel.example/wp-login.php?from=192.0.2.200", tag="defacement",
                                         application="wordpress", server="nginx", sector="Education", detail="seen on 192.0.2.9",
                                         secret_note="Lakeside internal") for n in range(6)]),
        "blocklist": Coll([row(D[1], n, ip=f"192.0.2.{n + 20}", source="list-a", reason="spam from 192.0.2.5 (noc@lakeside-tel.example)")
                           for n in range(4)]),
        "compromised_account": Coll([row(D[1], 1, email="alice@lakeside-tel.example", username="alice.lakeside", service="webmail",
                                         tag="stealer", public_source="paste", asn="", region="", city="")]),
        "ransomware_victim": Coll([row(D[1], 2, entity_name="Lakeside Telecom Ltd", website="www.lakeside-tel.example",
                                       sector="Communications", ransomware="examplelocker", date_published="2026-11-19", asn="")]),
        "sandbox_dns": Coll([row(D[1], 3, request="mail.lakeside-tel.example", request_type="A", response="192.0.2.77",
                                 family="examplebot", source="sandbox", asn="")]),
        "scan_post_exploitation_framework": Coll([row(D[1], 4, ip="192.0.2.99", tag="cobaltstrike", beacon_type="http",
                                                      beacon_host="c2.lakeside-tel.example", version="4.9")]),
        "compromised_iot6": Coll([row(D[1], 5, ip="2001:db8::5", hostname="cam.lakeside-tel.example", device_vendor="Example",
                                      device_type="camera", device_model="X1", tag="implant", sector="Retail")]),
    })
    groups = {"compromised_website": "Compromised systems and victims", "blocklist": "Reputation: listed or targeted",
              "compromised_account": "Leaked accounts and credentials", "ransomware_victim": "Compromised systems and victims",
              "sandbox_dns": "Malicious content hosted in the constituency",
              "scan_post_exploitation_framework": "Attacker infrastructure found in the constituency",
              "compromised_iot6": "Compromised systems and victims"}
    no_ip = {"compromised_account", "ransomware_victim", "sandbox_dns"}
    rmap = {"reports": {n: {"section": "Intelligence", "group": gr, "title": n.replace("_", " ").title(), "has_ip": n not in no_ip}
                        for n, gr in groups.items()}}

    class Settings:
        restricted, version = False, 1

        def in_scope(self, asn, ip):
            return True
    return db, rmap, D, Settings


def platform_fixture(A):
    """A made-up replay day for both platforms, put in the day stores in memory (they are not read from a database):
    documentation addresses, private AS numbers 64500/64501 named in memory only, host names and e-mails with
    'lakeside' in them. Returns {"registry": names to look for}."""
    import sources
    import services as SV
    # the network registry: the made-up networks are added in memory (the file is left as it is)
    reg = A.asn_registry
    reg._load()
    names = sorted({str(v.get(k) or "").strip() for v in reg.asns.values() for k in ("name", "holder")
                    if len(str(v.get(k) or "").strip()) >= 6})
    # a name that is also in a report's own name or definition ("Microsoft Sinkhole HTTP") is the report, not a network
    ref = ""
    for r in (A.registry, A.svc["registry"]):
        try:
            ref += " ".join(str(s.get("label", "")) for s in (r.get() or []))
        except Exception:                                   # noqa: BLE001 (no reports database here, as on GitHub)
            pass
    p = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "service_reports.json")
    ref += open(p, encoding="utf-8").read() if os.path.exists(p) else ""
    names = [n for n in names if not re.search(r"(?<![\w])" + re.escape(n) + r"(?![\w])", ref, re.I)]
    # the replay position, after the slow parts (the replay clock runs on): the made-up records end just before it
    rn = A.replay_now()
    start = A.day_start(rn)
    span = max(1.0, min(3600.0, (rn - start).total_seconds() - 1))
    times = [rn - timedelta(seconds=span * (i + 1) / 13) for i in range(12)] + [rn - timedelta(seconds=s) for s in (6, 4, 2)]
    times.sort()
    fake = {"64500": {"name": "Lakeside Telecom Ltd", "holder": "LAKESIDE-TEL-AS", "demo_alias": "Telco 9", "events_last_check": 1},
            "64501": {"name": "Lakeside Hosting", "holder": "LAKESIDE-HOST-AS", "demo_alias": "Provider 9", "events_last_check": 1}}
    reg.asns = dict(reg.asns, **fake)
    for a, v in fake.items():
        reg.company_alias[v["name"]] = v["demo_alias"]
        reg.alias_asns[v["demo_alias"]] = {a}
    reg._load = lambda: None
    A.settings.in_scope = lambda asn, ip: True
    src = {"name": "event4_sinkhole_http", "label": "Sinkhole HTTP", "class": "Botnet / infection", "layout": "standard",
           "filename_index": True}
    events = []
    for i, t in enumerate(times):
        ip = "2001:db8::10" if i == 3 else f"192.0.2.{i % 5 + 1}"
        doc = {"timestamp": t, "extracted_date": t, "src_ip": ip, "src_port": 50000 + i, "src_asn": "64500", "src_geo": "GH",
               "src_region": "GREATER ACCRA", "src_city": "ACCRA", "src_hostname": f"pc-{i}.lakeside-tel.example",
               "dst_ip": "198.51.100.7", "dst_port": 80, "dst_asn": "64501", "dst_geo": "US", "dst_city": "ASHBURN",
               "dst_hostname": "sink.lakeside-host.example", "http_host": "sinkhole-c2.example", "http_url": f"/gate.php?id={i}&from={ip}",
               "http_agent": "Mozilla/5.0", "infection": "examplebot", "tag": "examplebot", "severity": "high", "protocol": "tcp",
               "machine_name": "LAKESIDE-PC", "filename": f"{start:%Y-%m-%d}-event4_sinkhole_http-lakeside-asn.csv",
               "sysname": "LAKESIDE-PC-01", "username": "alice.lakeside", "contact": "noc@lakeside-tel.example",
               "md5": "d41d8cd98f00b204e9800998ecf8427e", "_id": f"fake{i}"}
        n = sources.normalise(doc, src)
        n["id"] = f"{src['name']}:fake{i}"
        n["_t"] = t.timestamp()
        n["extracted_date"] = A.iso(t)
        for f, v in list(n.items()):
            if hasattr(v, "isoformat"):
                n[f] = A.iso(v)
        n["src_coords"], n["dst_coords"] = [-0.19, 5.6], [-77.49, 39.04]
        n["src_ref"] = A.host_refs.ref(n["src_ip"])
        n["request"] = A._request_path(n["http_url"]) if n.get("http_url") else ""
        events.append(n)
    day = A.Day(start, events)
    day.per_source, day.arrived, day.sig = {src["name"]: len(events)}, {}, None
    day.by_src = {src["name"]: {"raw": len(events), "asn": {}, "blocks": {}, "rows": events, "last": None}}
    day.gen, day.settings_version, day.raw_total = A.store.gen, A.settings.version, len(events)
    A.store.get = lambda dt=None: day
    A.store.days = {start: day}
    ssrc = {"name": "scan_http", "label": "HTTP", "family": "Accessible", "filename_index": True}
    sevents = []
    for i, t in enumerate(times):
        ip = "2001:db8::20" if i == 4 else f"192.0.2.{i % 6 + 10}"
        doc = {"timestamp": t, "extracted_date": t, "ip": ip, "port": 443, "protocol": "tcp", "asn": "64500", "geo": "GH",
               "region": "GREATER ACCRA", "city": "ACCRA", "hostname": f"web{i}.lakeside-tel.example", "severity": "high",
               "tag": "cve-2024-0001;vulnerable", "http_title": "Lakeside Telecom portal", "sysname": "LAKESIDE-SRV",
               "server": "nginx", "http_reason": "OK", "ssl_subject_common_name": "web.lakeside-tel.example",
               "contact": "admin@lakeside-tel.example", "filename": f"{start:%Y-%m-%d}-scan_http-lakeside-asn.csv", "_id": f"sfake{i}"}
        n = SV.normalise_service(doc, ssrc)
        n["id"] = f"{ssrc['name']}:sfake{i}"
        n["_t"] = t.timestamp()
        n["extracted_date"] = SV._s(t)
        n["ip_ref"] = A.host_refs.ref(n["ip"])
        sevents.append(n)
    sday = SV.Day(start, sevents)
    sday.per_source, sday.arrived, sday.sig = {ssrc["name"]: len(sevents)}, {}, None
    sday.by_src = {ssrc["name"]: {"raw": len(sevents), "asn": {}, "region": {}, "blocks": {}, "rows": sevents, "last": None}}
    sday.gen, sday.settings_version, sday.raw_total = getattr(A.svc["store"], "gen", 0), A.settings.version, len(sevents)
    A.svc["store"].get = lambda dt=None: sday
    A.svc["store"].days = {start: sday}
    # the two report registries: the made-up reports only (as with the day stores, nothing read from a database)
    diag = {"checks": [], "compatible": True, "layout": "standard", "missing": [], "missing_fields": [], "required_ok": 5,
            "required_total": 5, "warnings": []}
    for reg_, entry in ((A.registry, dict(src, diagnostic=diag, latest="")),
                        (A.svc["registry"], dict(ssrc, diagnostic=dict(diag, layout="single-host"), layout="single-host",
                                                 fields=[], **{"class": "Accessible"}))):
        reg_.get = lambda *a, _e=entry, **k: [_e]
        reg_.items, reg_.unsupported, reg_.names = [entry], [], [entry["name"]]
    # the stream's window: from the first made-up record to the replay position when they were made
    return {"registry": names, "window": {"from": A.iso(times[0] - timedelta(seconds=1)), "to": A.iso(rn)}}


import external_access as X  # noqa: E402
import auth  # noqa: E402

print("1. Who is external")
ok("the built-in external role is exactly 'view' and counts as external", auth.FIXED_ROLES["external"] == ["view"]
   and X.is_external(auth.DEFAULT_ROLES["external"]))
ok("no other built-in role counts as external", not any(X.is_external(p) for r, p in auth.DEFAULT_ROLES.items() if r != "external"),
   [r for r, p in auth.DEFAULT_ROLES.items() if r != "external" and X.is_external(p)])
ok("a custom role with only 'view' is the same masked viewer", X.is_external({"view"}) and X.is_external(["view"]))
ok("…one with anything more is not (it keeps what its permissions give)", not X.is_external({"view", "export"})
   and not X.is_external({"view", "unmasked"}) and not X.is_external(set()) and not X.is_external(None))
ok("an admin in Peace of mind is not external", not X.is_external(auth.PEACE_PERMS))
# a report's masked rows (not a file) and the glossary's report definitions are the two allowed names with "report"
RISKY = re.compile(r"report|export|\.csv|\.pdf|lookup|malpedia|copy|finding|admin|settings$|/host$|acode|analyst-codes|beacon|combo|kb/|intel/")
risky = sorted(p for p in X.ALLOWED if RISKY.search(p) and p not in ("/api/intelligence/report", "/api/report_glossary"))
ok("the allow-list holds no download, look-up, copy, findings or admin route", not risky, risky)

import app as A  # noqa: E402

users, roles, sessions = A.AUTH["users"], A.AUTH["roles"], A.AUTH["sessions"]
real_get, real_perms = users.get, roles.perms
EXT, ANA, UA = auth.TEST_PREFIX + "external-audit", auth.TEST_PREFIX + "analyst-audit", "lg-check-external"
ROLE = {EXT: "lg-ext-audit", ANA: "lg-ana-audit"}
PERMS = {"lg-ext-audit": {"view"}, "lg-ana-audit": {"view", "unmasked", "export", "malpedia"}}
users.get = lambda n: {"status": "active", "role": ROLE[n], "changed": 0} if n in ROLE else real_get(n)
roles.perms = lambda r: set(PERMS[r]) if r in PERMS else real_perms(r)
tokens = []


def client(user):
    t = sessions.create(user, "127.0.0.1", UA)
    tokens.append(t)
    c = A.app.test_client()
    c.set_cookie("lg_session", t)
    return c


try:
    print("2. Every route not on the allow-list refuses an external account")
    ext = client(EXT)
    adapter = A.app.url_map.bind("localhost")
    unknown = []
    for p in sorted(X.ALLOWED):
        try:
            adapter.match(p, method="POST" if p == "/api/notifications/clear" else "GET")
        except Exception:                                # noqa: BLE001
            unknown.append(p)
    ok("every path on the allow-list is a route of the app", not unknown, unknown)
    tried, wrong = 0, []
    for r in sorted(A.app.url_map.iter_rules(), key=lambda r: r.rule):
        if r.rule.startswith("/static/") or r.rule.startswith(auth.PUBLIC_PATHS):
            continue
        path = re.sub(r"<(?:[^:>]+:)?[^>]+>", "1", r.rule)
        if path in X.ALLOWED:
            continue
        for m in sorted((r.methods or set()) - {"HEAD", "OPTIONS"}):
            tried += 1
            resp = ext.open(path, method=m, json={} if m != "GET" else None, headers={"User-Agent": UA})
            body = resp.get_data(as_text=True)
            refused = resp.status_code == 403 and X.REFUSED in body
            if not refused:
                wrong.append(f"{m} {path} -> {resp.status_code}")
    ok(f"all {tried} route/method pairs outside the allow-list are refused at the gate (403, the plain message)", not wrong and tried > 50, wrong[:12])
    resp = ext.get("/admin", headers={"User-Agent": UA})
    ok("…a refused page is the no-access page (back to the overview)", resp.status_code == 403 and "/?intro=1" in resp.get_data(as_text=True))
    resp = ext.get("/api/me", headers={"User-Agent": UA})
    ok("…the account's own details still answer", resp.status_code == 200 and (resp.json or {}).get("perms") == ["view"])
    resp = ext.get("/api/svc/events?all=1", headers={"User-Agent": UA})
    ok("…a complete list (?all=1) on an allowed API is still refused (no export)", resp.status_code == 403)
    ana = client(ANA)
    resp = ana.get("/api/me", headers={"User-Agent": UA})
    ok("an analyst is not held by the external list", resp.status_code == 200 and X.REFUSED not in resp.get_data(as_text=True))

    # ------------------------------------------------------------------ 3. Abused or Compromised, made-up rows
    print("3. Abused or Compromised: the masked view (made-up rows, no database)")
    from flask import Flask, g
    import intelligence as I
    DB, MAP, D, Settings = intel_fixture()
    fapp = Flask("ext-intel", template_folder=os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "templates"))
    # the page's header asks the same two questions the full app answers (findings.py, external_access.py)
    import external_access
    import finding_rules
    fapp.jinja_env.globals["lg_findings_team"] = lambda perms: finding_rules.is_team(lambda p: p in (perms or ()))
    fapp.jinja_env.globals["lg_external"] = external_access.is_external
    audited = []
    api = I.install(fapp, {"db": DB, "report_map": type("M", (), {"get": lambda self: MAP})(), "settings": Settings(),
                           "has_perm": lambda p: p in g.user["perms"], "is_demo": lambda: "unmasked" not in g.user["perms"],
                           "audit": type("Au", (), {"add": lambda self, ev, **k: audited.append((ev, k))})(), "csrf_ok": lambda: True,
                           "svc_reports": lambda: {"compromised_website", "blocklist"},
                           "network": lambda a: "Lakeside Telecom Ltd" if str(a) == "64500" else "",
                           "alias": lambda a: "Telco 9" if str(a) == "64500" else ("Unlisted network" if a else ""),
                           "cross": lambda hosts: {"services": [], "issues": [], "infections": []}})

    def icall(path, perms, role, body=None, method=None):
        method = method or ("POST" if body is not None else "GET")
        with fapp.test_request_context(path, method=method, json=body):
            g.user = {"user": "lg-check", "role": role, "perms": set(perms)}
            ep = fapp.url_map.bind("localhost").match(path.split("?")[0], method=method)
            r = fapp.view_functions[ep[0]](**ep[1])
            code = r[1] if isinstance(r, tuple) else (200 if isinstance(r, str) else r.status_code)
            r = r[0] if isinstance(r, tuple) else r
            txt = r.get_data(as_text=True) if not isinstance(r, str) else r
            return code, txt

    EX, AN = ({"view"}, "external"), ({"view", "unmasked", "export", "malpedia"}, "analyst")
    st, txt = icall("/intelligence", *EX)
    ok("the page opens for an external account", st == 200)
    st, txt = icall("/api/intelligence", *EX)
    ok("the summary answers, with nothing of a host", st == 200 and not leaks(txt), leaks(txt))
    st, txt = icall("/api/intelligence/totals", *EX)
    ok("the Overview card's counts answer", st == 200 and not leaks(txt))
    for name in sorted(n for n in DB if n in MAP["reports"]):
        st, txt = icall("/api/intelligence/report", *EX, body={"name": name, "day": D[1], "filters": {}})
        d = json.loads(txt) if st == 200 else {}
        ok(f"{name}: masked rows, no address, name, host or e-mail", st == 200 and d.get("total") and d.get("masked_view") is True
           and not leaks(txt), leaks(txt) or st)
        ok(f"{name}: no reveal, no analyst code, no account mask notice", d.get("can_reveal") is False and d.get("code") is None and d.get("masked") is False)
    st, txt = icall("/api/intelligence/report", *EX, body={"name": "compromised_website", "day": D[1], "filters": {}})
    d = json.loads(txt)
    ok("…addresses become the platforms' host labels, the network its alias, host names 'hidden'",
       all(r.get("ip", "").startswith("Host ") for r in d["rows"]) and all(r.get("asn") == "Telco 9" for r in d["rows"])
       and all(r.get("hostname") == "hidden" for r in d["rows"] if "hostname" in r), d["rows"][0])
    ok("…the network facet offers the alias only", all(v["label"] == "Telco 9" and v["value"] == "Telco 9"
       for f in d["facets"] if f["key"] == "asn" for v in f["values"]))
    ok("…fields a report adds that are not on the list are left out", not any("secret_note" in r for r in d["rows"]) and "secret_note" not in d["extra"])
    label = d["rows"][0]["ip"]
    st, t2 = icall("/api/intelligence/report", *EX, body={"name": "compromised_website", "day": D[1], "filters": {"ip": [label]}})
    ok("…a host label filters (it is what is shown)", st == 200 and json.loads(t2)["total"] >= 1)
    st, t2 = icall("/api/intelligence/report", *EX, body={"name": "compromised_website", "day": D[1], "filters": {"ip": ["192.0.2.1"]}})
    ok("…a real address typed into the filter finds nothing", st == 200 and json.loads(t2)["total"] == 0)
    st, t2 = icall("/api/intelligence/report", *EX, body={"name": "compromised_website", "day": D[1], "q": "lakeside"})
    ok("…a real name typed into the search finds nothing", st == 200 and json.loads(t2)["total"] == 0)
    st, t2 = icall("/api/intelligence/report", *EX, body={"name": "compromised_website", "day": D[1], "filters": {"asn": ["64500"]}})
    ok("…a real AS number in the network filter finds nothing", st == 200 and json.loads(t2)["total"] == 0)
    st, t2 = icall("/api/intelligence/report", *EX, body={"name": "compromised_website", "day": D[1], "filters": {"asn": ["Telco 9"]}})
    ok("…the alias does", st == 200 and json.loads(t2)["total"] >= 1)
    st, t2 = icall("/api/intelligence/report", *EX, body={"name": "compromised_account", "day": D[1], "reveal": "1"})
    ok("leaked accounts: 'reveal' means nothing to an external account, and nothing is logged as revealed",
       st == 200 and "lakeside" not in t2.lower() and not any(a[0] == "intelligence_reveal" for a in audited))
    st, t2 = icall("/api/intelligence/export.csv", *EX, body={"name": "blocklist", "day": D[1]})
    ok("the CSV export is refused", st == 403)
    st, t2 = icall("/api/intelligence/host", *EX, body={"ip": "192.0.2.1"})
    ok("a host's cross-view is refused", st == 403)
    st, txt = icall("/api/intelligence/report", *AN, body={"name": "compromised_website", "day": D[1], "filters": {}})
    ok("an analyst still sees the records unmasked (unchanged)", st == 200 and "192.0.2." in txt and "Lakeside Telecom Ltd (AS64500)" in txt
       and json.loads(txt).get("masked_view") is False)

    # ------------------------------------------------------------------ 4. the two platforms, a made-up day
    print("4. The two platforms with a made-up day, every API the pages call, as an external account")
    names = platform_fixture(A)
    reg_names = names["registry"]
    H = {"User-Agent": UA}
    W = names["window"]
    ev = ext.get("/api/events", query_string=W, headers=H)
    evj = ev.json if ev.status_code == 200 else {}
    rows = evj.get("events") if isinstance(evj, dict) else evj
    ok("the map's events answer with the made-up day", ev.status_code == 200 and rows, ev.status_code)
    ref = next((e.get("src_ref") for e in (rows or []) if e.get("src_ref")), "")
    sv = ext.get("/api/svc/events", query_string=W, headers=H)
    svj = sv.json if sv.status_code == 200 else {}
    srows = svj.get("events") if isinstance(svj, dict) else svj
    ok("the services records answer with the made-up day", sv.status_code == 200 and srows, sv.status_code)
    sref = next((e.get("ip_ref") for e in (srows or []) if e.get("ip_ref")), "")
    sid = next((e.get("id") for e in (srows or []) if e.get("id")), "")
    at = (rows or [{}])[-1].get("extracted_date", "") if rows else ""
    q = {"at": at} if at else {}
    CALLS = [("/api/events", W), ("/api/stats", {}), ("/api/facets", {}), ("/api/geo", {}), ("/api/replayed", {}),
             ("/api/overview", {}), ("/api/clock", {}), ("/api/settings/public", {}), ("/api/overview/spikes", {}),
             ("/api/related", {"ref": ref}), ("/api/insight", {"kind": "src_ip", "value": ref}),
             ("/api/insight", {"kind": "src_asn", "value": "Telco 9"}), ("/api/insight", {"kind": "infection", "value": "examplebot"}),
             ("/api/insight", {"kind": "http_host", "value": "sinkhole-c2.example"}), ("/api/insight", {"kind": "src_city", "value": "ACCRA"})]
    CALLS += [("/api/insight/drill", {"kind": "infection", "value": "examplebot", "metric": m})
              for m in ("events", "hosts", "c2", "dst_ips", "interval", "multi", "reports", "cross", "share")]
    CALLS += [("/api/svc/events", W), ("/api/svc/stats", {}), ("/api/svc/facets", {}), ("/api/svc/regions", {}),
              ("/api/svc/clock", {}), ("/api/svc/replayed", {}), ("/api/svc/detail", {"id": sid}),
              ("/api/svc/insight", {"ip": sref}), ("/api/svc/insight", {"service": "HTTP"}), ("/api/svc/insight", {"asn": "Telco 9"})]
    CALLS += [("/api/svc/drill", {"service": "HTTP", "metric": m})
              for m in ("hosts", "events", "vulnerable", "multi", "cross", "issues", "services", "networks", "regions", "share")]
    # reference text (the knowledge base's malware write-ups, report definitions): only the made-up names are looked for
    REFERENCE = [("/api/infections", {}), ("/api/report_glossary", {}), ("/api/svc/glossary", {})]
    bad, answered = [], 0
    for path, params in CALLS + REFERENCE:
        p = dict(q, **params) if path in ("/api/insight", "/api/insight/drill", "/api/related") else params
        r = ext.get(path, query_string=p, headers=H)
        if r.status_code == 503:                       # a part that reads the reports database directly, none here
            continue
        if r.status_code != 200:
            bad.append(f"{path} {p} -> {r.status_code}")
            continue
        answered += 1
        found = leaks(r.get_data(as_text=True), reg_names, generic=(path, params) not in REFERENCE)
        if found:
            bad.append(f"{path} {p}: {', '.join(found)}")
    ok(f"{answered} answers of the map and the services APIs: no address, made-up name, registry name or e-mail", not bad and answered >= 30, bad[:12])
    r = ext.get("/api/svc/detail", query_string={"id": sid}, headers=H)
    d = r.json or {}
    rec = d.get("event") or d.get("record") or d
    ok("a services record's details: host name 'hidden', the identifying fields left out", r.status_code == 200
       and rec.get("hostname") == "hidden" and "sysname" not in json.dumps(d) and "contact" not in (rec.get("extras") or {}),
       str(rec.get("extras"))[:300])
    r = ext.get("/api/infections", headers=H)
    ok("the knowledge base sends no staff names to an external account", r.status_code == 200
       and not any("by" in v for v in (r.json or {}).values() if isinstance(v, dict)))
    r = ana.get("/api/svc/events", query_string=W, headers=H)
    ok("an analyst sees the made-up addresses (the masking is the external account's, not a broken day)",
       r.status_code == 200 and "192.0.2." in r.get_data(as_text=True))
finally:
    users.get, roles.perms = real_get, real_perms
    for t in tokens:
        sessions.end(token=t)

print(f"\n{checks - len(fails)} of {checks} external-account checks passed" + (f"; FAILED: {fails}" if fails else ""))
sys.exit(1 if fails else 0)
