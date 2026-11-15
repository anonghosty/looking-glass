#!/usr/bin/env python3
"""Region matches (region_matches.py, Settings > Country): the report's region names are matched to the map by name,
ISO alias, accent-free spelling or the administrator's choice; a name the map does not know gets a suggestion; the
choices are kept per country in data/region_matches.json (0600), apply to whole-country maps, and the routes refuse
non-admins, requests from another page, stale sign-ins, unknown countries and regions not on the map. Every change is
audited. No database needed.  Run: .venv/bin/python tests/check_region_matches.py"""
import json
import os
import stat
import sys
import tempfile

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
from flask import Flask, g  # noqa: E402

import region_matches as RM  # noqa: E402

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info and not cond else ""))


FILE = {"regions": {
    "GREATER ACCRA": {"name": "Greater Accra", "aliases": ["GH-AA", "ACCRA"]},
    "ASHANTI": {"name": "Ashanti", "aliases": ["GH-AH"]},
    "BRONG AHAFO": {"name": "Brong Ahafo", "aliases": ["GH-BA"]},
    "COTE D IVOIRE LAGUNES": {"name": "Lagunes"},
}}
WHOLE = {"whole": True, "regions": {"MONACO": {"name": "Monaco"}}}

print("Matching a report's region name to the map")
f = RM.resolver(FILE, {}, ["Ghana", "GHANA"])
ok("by the map's own name", f("Ashanti") == "ASHANTI")
ok("by an ISO 3166-2 alias", f("GH-AA") == "GREATER ACCRA")
ok("letter case, accents and 'Region' do not matter", f("áshanti region") == "ASHANTI")
ok("spaces and punctuation do not matter (Brong-Ahafo)", f("Brong-Ahafo") == "BRONG AHAFO")
ok("the country's own name means region unknown", f("Ghana") == RM.COUNTRY)
ok("an empty region means region unknown", f("") == RM.COUNTRY)
ok("an unknown name is not matched", f("Bono East") is None)
f2 = RM.resolver(FILE, {"Bono East": "BRONG AHAFO", "Somewhere": RM.COUNTRY}, ["Ghana"])
ok("the administrator's choice wins (Bono East on Brong Ahafo)", f2("BONO EAST") == "BRONG AHAFO")
ok("…and 'the whole country' is a choice too", f2("somewhere") == RM.COUNTRY)
w = RM.resolver(WHOLE, {}, ["Monaco"])
ok("a whole-country map takes every name", w("Monte-Carlo") == "MONACO" and w("anything") == "MONACO")

BZ = {"regions": {"BELIZE": {"name": "Belize District"}, "CAYO": {"name": "Cayo"}}}
b = RM.resolver(BZ, {}, ["Belize", "BELIZE"])
ok("a region named like the country is that region (Belize District)", b("BELIZE") == "BELIZE")
ok("…unless the administrator said it means the country", RM.resolver(BZ, {"Belize": RM.COUNTRY}, ["Belize"])("BELIZE") == RM.COUNTRY)
ok("region_names() lists the map's names, for the 'region unknown' checks", "BELIZE" in RM.region_names(BZ) and RM.region_names(WHOLE) == set())
LV = {"regions": {"JELGAVA": {"name": "Jelgava", "aliases": ["JELGAVAS NOVADS"]}, "JELGAVAS NOVADS": {"name": "Jelgavas novads"}}}
ok("a region's own name wins over another region's alias (Jelgavas novads)", RM.resolver(LV, {}, [])("Jelgavas novads") == "JELGAVAS NOVADS")

print("The default frame: where the records are (islands far apart)")
sq = lambda x, y, d=0.1: [[[[x, y], [x + d, y], [x + d, y + d], [x, y + d], [x, y]]]]  # noqa: E731
SC = {"bbox": [46.0, -10.5, 56.5, -3.5], "regions": {"MAHE N": {"name": "Mahe North", "polys": sq(55.4, -4.65)},
      "MAHE S": {"name": "Mahe South", "polys": sq(55.45, -4.8)}, "OUTER": {"name": "Outer Islands", "polys": sq(46.2, -9.5, 0.4)}}}
box, z = RM.focus_bbox(SC, {"MAHE N": 300, "MAHE S": 200, "OUTER": 2})
ok("records on Mahé: the frame is Mahé, not the whole ocean", z and box[0] > 55 and box[2] < 56.5, str(box))
box, z = RM.focus_bbox(SC, {"MAHE N": 300, "OUTER": 300})
ok("records far apart: the whole country", not z and box == SC["bbox"])
ok("no records: the whole country", RM.focus_bbox(SC, {}) == (SC["bbox"], False))
ok("a one-area map: its own frame", RM.focus_bbox({"whole": True, "bbox": [1, 2, 3, 4], "regions": {}}, {"X": 5}) == ([1, 2, 3, 4], False))
box, z = RM.focus_bbox(SC, {"MAHE N": 5})
ok("one tiny region: framed with room around it (at least a quarter degree)", z and box[2] - box[0] >= 0.25 and box[3] - box[1] >= 0.25, str(box))

print("Suggestions for names the map does not know")
s, score = RM.suggest("Ashantii", FILE, ["Ghana"])
ok("a misspelling suggests the right region", s == "ASHANTI" and score >= RM.SUGGEST_AT, f"{s} {score}")
s, score = RM.suggest("Lagunes", FILE, [])
ok("a name inside a longer region name is suggested", s == "COTE D IVOIRE LAGUNES", f"{s} {score}")
FJ = {"regions": {"CENTRAL": {"name": "Central", "aliases": ["REWA", "NAMOSI"]},
                  "WESTERN": {"name": "Western", "aliases": ["BA", "RA"]}}}
s, score = RM.suggest("Centrax", FJ, ["Fiji"])
ok("a short code inside the name does not win ('RA' in 'Centrax' is not Western)", s == "CENTRAL", f"{s} {score}")
s, score = RM.suggest("Ghanaa", FILE, ["Ghana"])
ok("a misspelt country name suggests 'the whole country'", s == RM.COUNTRY, f"{s} {score}")
s, score = RM.suggest("Zzyzx", FILE, ["Ghana"])
ok("nothing alike: no suggestion, but the score is given", s is None and 0 <= score < RM.SUGGEST_AT, f"{s} {score}")

print("Routes")
with tempfile.TemporaryDirectory() as d:
    adm1 = os.path.join(d, "adm1")
    os.makedirs(adm1)
    json.dump(FILE, open(os.path.join(adm1, "GH.json"), "w"))
    json.dump(WHOLE, open(os.path.join(adm1, "MC.json"), "w"))
    state = {"writable": True, "csrf": True, "fresh": True}
    audit = []

    class Audit:
        def add(self, ev, **kw):
            audit.append((ev, kw))

    class S:
        data = {"country": "GH"}

    ctx = {"data_dir": d, "adm1_dir": adm1, "settings": S(), "audit": Audit(),
           "country_index": lambda: {"GH": {"country": "Ghana", "names": ["GHANA"]}, "MC": {"country": "Monaco", "names": ["MONACO"]}},
           "settings_writable": lambda: state["writable"], "csrf_ok": lambda: state["csrf"], "fresh": lambda: state["fresh"],
           "region_raw": lambda: {"Ashanti": 40, "Bono East": 12, "Ghana": 3, "Ashantii": 2}}
    app = Flask(__name__)

    @app.before_request
    def _who():
        g.user = {"user": "test.admin"}

    RM.install(app, ctx)
    c = app.test_client()
    r = c.get("/api/settings/region-matches?country=GH").get_json()
    rows = {x["name"]: x for x in r["rows"]}
    ok("rows sorted by records", [x["name"] for x in r["rows"]][0] == "Ashanti")
    ok("Ashanti: on the map", rows["Ashanti"]["status"] == "map" and rows["Ashanti"]["target"] == "ASHANTI")
    ok("Ghana: the country (region unknown)", rows["Ghana"]["status"] == "country")
    ok("Ashantii: not matched, suggests Ashanti", rows["Ashantii"]["status"] == "none" and rows["Ashantii"]["suggestion"] == "ASHANTI")
    ok("the map's regions are listed by name", [x["name"] for x in r["regions"]][:2] == ["Ashanti", "Brong Ahafo"])
    post = lambda body: c.post("/api/settings/region-matches", json=body)  # noqa: E731
    rr = post({"country": "GH", "name": "Bono East", "target": "BRONG AHAFO"})
    ok("an administrator links Bono East to Brong Ahafo", rr.status_code == 200 and rr.get_json()["chosen"] == {"BONO EAST": "BRONG AHAFO"})
    p = os.path.join(d, "region_matches.json")
    ok("kept in data/region_matches.json, readable by the service only (0600)",
       json.load(open(p)) == {"GH": {"BONO EAST": "BRONG AHAFO"}} and stat.S_IMODE(os.stat(p).st_mode) == 0o600)
    ok("audited: region_match_set, with who and what", audit[-1][0] == "region_match_set" and audit[-1][1]["user"] == "test.admin"
       and "Brong Ahafo" in audit[-1][1]["detail"], str(audit[-1:]))
    rows = {x["name"]: x for x in c.get("/api/settings/region-matches?country=GH").get_json()["rows"]}
    ok("the list now shows it as chosen", rows["Bono East"]["status"] == "chosen" and rows["Bono East"]["target"] == "BRONG AHAFO")
    ok("Matches.of() gives the choices to the maps", ctx["region_matches"].of("gh") == {"BONO EAST": "BRONG AHAFO"})
    ok("'the whole country' can be chosen", post({"country": "GH", "name": "Ashantii", "target": RM.COUNTRY}).status_code == 200)
    ok("a region not on the map is refused", post({"country": "GH", "name": "X", "target": "VOLTA"}).status_code == 400)
    ok("an unknown country is refused", post({"country": "ZZ", "name": "X", "target": ""}).status_code == 400)
    ok("an empty name is refused", post({"country": "GH", "name": " ", "target": RM.COUNTRY}).status_code == 400)
    ok("a name over 120 letters is refused", post({"country": "GH", "name": "A" * 121, "target": RM.COUNTRY}).status_code == 400)
    ok("a path in the country is refused", post({"country": "../GH", "name": "X", "target": ""}).status_code == 400)
    rr = post({"country": "GH", "name": "bono east", "target": ""})
    ok("an empty target removes the choice", rr.get_json()["chosen"] == {"ASHANTII": RM.COUNTRY})
    ok("audited: region_match_removed, with what it was", audit[-1][0] == "region_match_removed" and "BRONG AHAFO" in audit[-1][1]["detail"])
    post({"country": "GH", "name": "Ashantii", "target": ""})
    ok("the last choice removed: the country leaves the file", json.load(open(p)) == {})
    ok("a whole-country map lists its one area", c.get("/api/settings/region-matches?country=MC").get_json()["whole"] is True)
    n = len(audit)
    state["csrf"] = False
    ok("a request from another page is refused", post({"country": "GH", "name": "Bono East", "target": "ASHANTI"}).status_code == 403)
    state["csrf"], state["fresh"] = True, False
    ok("a sign-in older than 12 hours is refused", post({"country": "GH", "name": "Bono East", "target": "ASHANTI"}).status_code == 403)
    state["fresh"], state["writable"] = True, False
    ok("a non-admin may not change matches", post({"country": "GH", "name": "Bono East", "target": "ASHANTI"}).status_code == 403)
    ok("…nor list them", c.get("/api/settings/region-matches?country=GH").status_code == 403)
    ok("refused requests change nothing and audit nothing", json.load(open(p)) == {} and len(audit) == n)
    open(p, "w").write("{not json")
    ok("a damaged file reads as no choices, never an error", ctx["region_matches"].of("GH") == {})

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
