#!/bin/sh
# runs itself with the project's own Python (.venv), from wherever it is called
''''exec "$(dirname -- "$0")/../.venv/bin/python" "$0" "$@" # '''
"""The Intelligence portal (intelligence.py, 2026-11-14), offline: a stand-in database with made-up rows of three
reports (Compromised Website, Block Listed IP Addresses, Compromised Account without an IP address) over the last days.
Checked: only analysts and admins open it, never in demo mode; management gets counts only; today against the 7-day
median and "still arriving"; reports never received listed with why; a report's view filters on its own fields; the
constituency leaves other hosts out; leaked accounts masked unless asked (and that is logged); the CSV export is logged
and carries the filtered rows; a host's cross-view; an analyst code only from a services report, only up to its limit.
Usage: tests/check_intelligence.py"""
import json, os, re, sys
from datetime import datetime, timedelta, timezone
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from flask import Flask, g  # noqa: E402
import intelligence as I  # noqa: E402

fails, checks = [], 0
IP_RX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond: fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info else ""), flush=True)


class Cur(list):
    def limit(self, n):
        return Cur(self[:n])


class Coll:
    def __init__(self, rows): self.rows = rows
    def _m(self, r, q):
        for k, v in q.items():
            if isinstance(v, dict) and "$regex" in v:
                if not re.match(v["$regex"], str(r.get(k, ""))): return False
            elif r.get(k) != v: return False
        return True
    def find(self, q=None, proj=None):
        out = [r for r in self.rows if self._m(r, q or {})]
        if proj and any(v == 1 for v in proj.values()):
            out = [{k: r[k] for k in proj if proj[k] == 1 and k in r} for r in out]
        elif proj:
            out = [{k: v for k, v in r.items() if proj.get(k) != 0} for r in out]
        return Cur(out)
    def count_documents(self, q): return len(self.find(q))
    def estimated_document_count(self): return len(self.rows)


T = datetime.now(timezone.utc).date()
D = [(T - timedelta(days=i)).isoformat() for i in range(8)]          # today first


def row(day, n, **kw):
    return dict({"filename": f"{day}-x-ghana-geo.csv", "timestamp": f"{day} 0{n % 9}:00:00", "line_hash": f"{day}{n}{kw}"}, **kw)


web = []
for i, d in enumerate(D[1:]):                                          # 7 days before today: 10, 11, ... rows
    for n in range(10 + i):
        web.append(row(d, n, ip=f"192.0.2.{n + 1}", asn="64500", sector="Education" if n % 2 else "Government",
                       tag="defacement" if n % 3 else "phishing", url=f"http://site{n}.example/"))
web += [row(D[0], n, ip=f"192.0.2.{n + 1}", asn="64500", sector="Education", tag="defacement", url="http://a.example/") for n in range(3)]
web.append(row(D[0], 99, ip="198.51.100.9", asn="64999", sector="Education", tag="defacement", url="http://out.example/"))  # outside
block = [row(d, n, ip=f"192.0.2.{n + 1}", asn="64500", source="list-a", reason="spam") for d in D[1:4] for n in range(5)]
block.append(row(D[1], 77, ip="192.0.2.77", asn="64500", source="list-b", reason='=HYPERLINK("http://bad.example","x")'))
acct = [row(D[1], 1, email="alice@example.org", username="alice", service="webmail", tag="stealer")]
DB = {"compromised_website": Coll(web), "blocklist": Coll(block), "compromised_account": Coll(acct)}


class FakeDB(dict):
    def list_collection_names(self): return list(self)


MAP = {"reports": {
    "compromised_website": {"section": "Intelligence", "group": "Compromised systems and victims", "title": "Compromised Website", "has_ip": True},
    "blocklist": {"section": "Intelligence", "group": "Reputation: listed or targeted", "title": "Block Listed IP Addresses", "has_ip": True},
    "compromised_account": {"section": "Intelligence", "group": "Leaked accounts and credentials", "title": "Compromised Account", "has_ip": False},
    "sandbox_dns": {"section": "Intelligence", "group": "Malicious content hosted in the constituency", "title": "Sandbox-DNS", "has_ip": False},
    "malware_url": {"section": "Intelligence", "group": "Malicious content hosted in the constituency", "title": "Malware URL", "has_ip": True},
    "scan_http": {"section": "Services", "group": "", "title": "HTTP"}}}


class Settings:
    restricted, version = True, 1
    def in_scope(self, asn, ip): return str(asn) == "64500"


audited, demo = [], [False]
app = Flask(__name__, template_folder=os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "templates"))
api = I.install(app, {"db": FakeDB(DB), "report_map": type("M", (), {"get": lambda self: MAP})(), "settings": Settings(),
                      "has_perm": lambda p: p in g.user["perms"], "is_demo": lambda: demo[0],
                      "audit": type("A", (), {"add": lambda self, ev, **k: audited.append((ev, k))})(),
                      "svc_reports": lambda: {"compromised_website", "blocklist"}, "network": lambda a: "Example Net" if str(a) == "64500" else "",
                      "cross": lambda hosts: {"services": [{"title": "HTTP"}], "issues": [{"name": "CVE-2024-0001", "hosts": 1}], "infections": []}})
AN, MG, RS = {"view", "unmasked", "export"}, {"management"}, {"definitions"}


ROLE = {"management": "management", "definitions": "researcher"}


def call(path, perms, raw=False, role=None):
    with app.test_request_context(path):
        role = role or next((ROLE[p] for p in perms if p in ROLE), "analyst")
        g.user = {"user": "lg-check", "role": role, "perms": set(perms)}
        ep = app.url_map.bind("localhost").match(path.split("?")[0])
        r = app.view_functions[ep[0]](**ep[1])
        code = r[1] if isinstance(r, tuple) else r.status_code
        r = r[0] if isinstance(r, tuple) else r
        body = r.get_data(as_text=True) if not isinstance(r, str) else r
        return code, (body if raw else (json.loads(body) if body.strip().startswith("{") else {}))


print("Who opens it")
ok("a researcher is refused (hosts are never theirs)", call("/api/intelligence", RS)[0] == 403)
ok("management is refused the portal", call("/api/intelligence", MG)[0] == 403 and call("/api/intelligence/report?name=blocklist", MG)[0] == 403)
st, tot = call("/api/intelligence/totals", MG)
ok("…and gets the counts only: totals and the 7-day trend per group, no address", st == 200 and tot["groups"] and not IP_RX.search(json.dumps(tot))
   and all(len(gr["per_day"]) == 8 for gr in tot["groups"]))
ok("a researcher gets no totals either", call("/api/intelligence/totals", RS)[0] == 403)
ok("an administrator does not open it either (analysts only), though the role sees addresses and exports",
   call("/api/intelligence", AN | {"settings", "users"}, role="admin")[0] == 403 and call("/intelligence", AN | {"settings"}, raw=True, role="admin")[0] == 403)
demo[0] = True
ok("demo mode: refused (the portal shows real records)", call("/api/intelligence", AN)[0] == 403)
demo[0] = False
ok("the page is refused to a researcher", call("/intelligence", RS, raw=True)[0] == 403)

print("The groups and reports")
st, s = call("/api/intelligence", AN)
ok("an analyst opens it", st == 200, s.get("error", ""))
grp = {x["group"]: x for x in s["groups"]}
cw = next(r for r in grp["Compromised systems and victims"]["reports"] if r["name"] == "compromised_website")
ok("only Intelligence reports, in the agreed group order", [x["group"] for x in s["groups"]] == [x for x in I.GROUP_ORDER if x in grp]
   and not any(r["name"] == "scan_http" for x in s["groups"] for r in x["reports"]))
ok("today counted inside the constituency only (the host outside left out)", cw["today"] == 3, cw["today"])
ok("…against the median of the 7 days before", cw["median"] == 13, cw["median"])
ok("…with each of the 8 days", [p["rows"] for p in cw["per_day"]] == list(range(10, 17))[::-1] + [3], [p["rows"] for p in cw["per_day"]])
ok("today's report in: 1 of the usual 1 (the median of reports a day), not still arriving", s["arriving"] == {"in": 1, "usual": 1, "still": False}, s["arriving"])
kept = list(web); web[:] = [r for r in web if not r["filename"].startswith(D[0])]; api.reset()
ok("…none in yet today: still arriving, 0 of the usual 1", call("/api/intelligence", AN)[1]["arriving"] == {"in": 0, "usual": 1, "still": True})
web[:] = kept; api.reset()
nr = {x["name"]: x for x in s["not_received"]}
ok("reports never received are listed, with why", set(nr) == {"sandbox_dns", "malware_url"} and all(x["why"] for x in nr.values()), sorted(nr))
ok("…a report without an IP address says it needs a domain filter", "domain filter" in nr["sandbox_dns"]["why"])
ok("…the others say what Shadowserver can tell", "subscription" in nr["malware_url"]["why"])
ok("the no-IP report received is a card of its own, marked so", any(r["name"] == "compromised_account" and r["no_ip"] and r["received"]
   for r in grp["Leaked accounts and credentials"]["reports"]))

print("A report's view")
st, v = call(f"/api/intelligence/report?name=compromised_website&day={D[1]}", AN)
ok("its rows, its own fields as filters, then networks (by name) as the analysis window has them", st == 200 and v["total"] == 10
   and [f["key"] for f in v["facets"]] == ["url", "tag", "sector", "asn"] and v["facets"][3]["values"][0]["label"] == "Example Net (AS64500)"
   and v["stats"]["hosts"] == 10 and v["stats"]["networks"] == 1,
   f"{v.get('total')} · {[f['key'] for f in v.get('facets', [])]}")
ok("networks by name, never a bare number", all(r["asn"] == "Example Net (AS64500)" for r in v["rows"]))
st, v2 = call(f"/api/intelligence/report?name=compromised_website&day={D[1]}&sector=Education&tag=phishing", AN)
ok("filters narrow it, each row matching", st == 200 and v2["total"] and all(r["sector"] == "Education" and r["tag"] == "phishing" for r in v2["rows"]),
   v2.get("total"))
st, v3 = call(f"/api/intelligence/report?name=compromised_website&day={D[1]}&q=site1", AN)
ok("a free text searches every field", st == 200 and v3["total"] and all("site1" in r["url"] for r in v3["rows"]), v3.get("total"))
ok("an unknown report is refused", call(f"/api/intelligence/report?name=scan_http&day={D[1]}", AN)[0] == 404)
ok("a day outside the 8 is refused", call("/api/intelligence/report?name=blocklist&day=2001-01-01", AN)[0] == 400)
ok("an analyst code can be made of the view's devices (a services report)", v2["code"] and v2["code"]["possible"]
   and v2["code"]["query"].startswith("report=compromised_website&ip=") and v2["code"]["query"].count("ip=") == v2["hosts"])
st, va = call(f"/api/intelligence/report?name=compromised_account&day={D[1]}", AN)
ok("leaked accounts: masked by default", st == 200 and va["masked"] and va["rows"][0]["email"] == "a•••@example.org" and va["rows"][0]["username"] == "a•••",
   va["rows"][0] if va.get("rows") else "")
ok("…no analyst code (no device)", not va["code"])
n0 = len(audited)
st, vr = call(f"/api/intelligence/report?name=compromised_account&day={D[1]}&reveal=1", AN)
ok("…shown when the analyst asks, and that is logged", vr["rows"][0]["email"] == "alice@example.org" and audited[n0:] and audited[-1][0] == "intelligence_reveal")
n1 = len(audited)
st, vf = call(f"/api/intelligence/report?name=compromised_account&day={D[1]}&email=nobody@example.org", AN)
st2, vq = call(f"/api/intelligence/report?name=compromised_account&day={D[1]}&q=alice", AN)
ok("masked accounts cannot be filtered or searched on the account itself (no leak confirmed without a logged reveal)",
   vf["total"] == 1 and vq["total"] == 0 and not any(f["key"] in ("email", "username") for f in vf["facets"])
   and not any(a[0] == "intelligence_reveal" for a in audited[n1:]), f"filter: {vf['total']} · search: {vq['total']}")
st, vr2 = call(f"/api/intelligence/report?name=compromised_account&day={D[1]}&q=alice&reveal=1", AN)
ok("…once revealed (and logged), the account search works", vr2["total"] == 1 and audited[-1][0] == "intelligence_reveal")
import data_access  # noqa: E402
ok("viewing a report's records is in the data-access log (host-level data)", data_access.SENSITIVE.get("/api/intelligence/report", ("",))[0] == "data_viewed")
n3 = len(audited)
st, vb = call(f"/api/intelligence/report?name=blocklist&day={D[1]}&reveal=1", AN)
ok("…reveal means nothing on another report", not any(a[0] == "intelligence_reveal" for a in audited[n3:]))

print("Export and a host")
st, body = call(f"/api/intelligence/export.csv?name=compromised_website&day={D[1]}&sector=Education", AN, raw=True)
lines = [x for x in body.lstrip("﻿").splitlines() if x]
ok("the CSV carries the filtered rows", st == 200 and len(lines) - 1 == sum(1 for r in web if r["filename"].startswith(D[1]) and r["sector"] == "Education"), len(lines) - 1)
ok("…and the export is logged with its size", audited[-1][0] == "intelligence_export" and "row(s)" in audited[-1][1]["detail"] and "filtered" in audited[-1][1]["detail"])
st, body = call(f"/api/intelligence/export.csv?name=compromised_account&day={D[1]}", AN, raw=True)
ok("…leaked accounts masked in the export too", st == 200 and "alice@" not in body and "a•••@example.org" in body)
st, body = call(f"/api/intelligence/export.csv?name=blocklist&day={D[1]}", AN, raw=True)
import csv as _csv, io as _io  # noqa: E401
cells = [c for r in _csv.reader(_io.StringIO(body.lstrip("﻿"))) for c in r]
ok("a value from a report that looks like a formula never runs as one in the export", st == 200 and any("HYPERLINK" in c for c in cells)
   and not any(c[:1] in "=+-@" and c for c in cells), next((c for c in cells if "HYPERLINK" in c), ""))
ok("an export needs the export permission", call(f"/api/intelligence/export.csv?name=blocklist&day={D[1]}", {"view", "unmasked"})[0] == 403)
st, h = call("/api/intelligence/host?ip=192.0.2.1", AN)
ok("a host's cross-view: every Intelligence report of the week it is in", st == 200 and {x["name"] for x in h["intelligence"]} == {"compromised_website", "blocklist"},
   [x["name"] for x in h.get("intelligence", [])])
ok("…with the services platform's categories, and logged", h["issues"] and audited[-1][0] == "intelligence_host")
ok("…a host outside the constituency shows nothing", call("/api/intelligence/host?ip=198.51.100.9", AN)[1]["intelligence"] == [])
ok("…not an address: refused", call("/api/intelligence/host?ip=x;drop", AN)[0] == 400)
print(f"\n{checks - len(fails)} of {checks} Intelligence portal checks passed" + (f"; FAILED: {fails}" if fails else ""))
sys.exit(1 if fails else 0)
