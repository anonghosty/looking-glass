#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
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
box, z = RM.focus_bbox(SC, {"MAHE N": 300, "MAHE S": 200})
ok("records on Mahé: the frame is Mahé, not the whole ocean", z and box[0] > 55 and box[2] < 56.5, str(box))
# every region with records is inside the frame, the smallest too (2026-11-26: Ghana's Upper East with 1 device was
# cut off while the map said "Zoomed to the regions with records"; the frame took the regions with 98% of them)
box, z = RM.focus_bbox(SC, {"MAHE N": 300, "MAHE S": 200, "OUTER": 2})
ok("…2 records on the Outer Islands too: they are inside the frame (here: the whole country)",
   box[0] <= 46.2 and box[2] >= 46.6, str(box))
GH = {"bbox": [-3.3, 4.7, 1.2, 11.2], "regions": {"ACCRA": {"name": "Greater Accra", "polys": sq(-0.3, 5.5, 0.6)},
      "ASHANTI": {"name": "Ashanti", "polys": sq(-2.3, 6.2, 1.2)}, "UPPER EAST": {"name": "Upper East", "polys": sq(-1.2, 10.4, 0.7)}}}
box, z = RM.focus_bbox(GH, {"ACCRA": 13996, "ASHANTI": 5405, "UPPER EAST": 1})
ok("…one device in the far north: its region is inside the frame",
   box[1] <= 10.4 and box[3] >= 11.1 and box[0] <= -2.3, str(box))
for k_ in GH["regions"]:
    w_, s_ = GH["regions"][k_]["polys"][0][0][0]
    ok(f"…{GH['regions'][k_]['name']} inside the frame", box[0] <= w_ and box[1] <= s_, str(box))
# on EVERY shipped country map (static/data/adm1): whatever has records, every one of those regions is inside the
# frame; a very small country (smaller than the frame's minimum) is never zoomed; Ghana with the records of
# 2026-11-26 (NCA CERT: Greater Accra to Upper East) shows the whole country
import json as _json0  # noqa: E402
_adm = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "static", "data", "adm1")


def _rb(f, k):
    pts = [p for poly in f["regions"][k]["polys"] for p in poly[0]]
    return min(x for x, _ in pts), min(y for _, y in pts), max(x for x, _ in pts), max(y for _, y in pts)


def _inside(box, f, keys):
    return all(box[0] <= _rb(f, k)[0] + 1e-9 and box[1] <= _rb(f, k)[1] + 1e-9 and box[2] >= _rb(f, k)[2] - 1e-9
               and box[3] >= _rb(f, k)[3] - 1e-9 for k in keys)


maps_, outside_, tiny_zoomed_ = 0, [], []
for p_ in sorted(_glob_ for _glob_ in (os.path.join(_adm, n) for n in os.listdir(_adm)) if _glob_.endswith(".json")) if os.path.isdir(_adm) else []:
    f_ = _json0.load(open(p_, encoding="utf-8"))
    if f_.get("whole") or len(f_.get("regions") or {}) < 2:
        continue
    maps_ += 1
    keys_ = sorted(f_["regions"], key=lambda k: (_rb(f_, k)[2] - _rb(f_, k)[0]) * (_rb(f_, k)[3] - _rb(f_, k)[1]))
    for counts_ in ({k: 1 for k in keys_}, {keys_[-1]: 500, keys_[0]: 1}, {keys_[0]: 3}):
        b_, z_ = RM.focus_bbox(f_, counts_)
        if not _inside(b_, f_, counts_):
            outside_.append(os.path.basename(p_))
    fw_, fh_ = f_["bbox"][2] - f_["bbox"][0], f_["bbox"][3] - f_["bbox"][1]
    if fw_ < 0.25 and fh_ < 0.25 and RM.focus_bbox(f_, {keys_[0]: 3})[1]:
        tiny_zoomed_.append(os.path.basename(p_))
if maps_:
    ok(f"on all {maps_} shipped country maps, every region with records is inside the frame (also the smallest beside "
       "the biggest)", not outside_, sorted(set(outside_))[:8])
    ok("…a very small country (smaller than the frame's minimum, e.g. Nauru, San Marino) is never zoomed", not tiny_zoomed_, tiny_zoomed_)
    gh_ = os.path.join(_adm, "GH.json")
    if os.path.isfile(gh_):
        g_ = _json0.load(open(gh_, encoding="utf-8"))
        by_ = {v["name"].lower().replace(" region", "").strip(): k for k, v in g_["regions"].items()}
        nca_ = {by_[n]: c for n, c in {"greater accra": 13996, "ashanti": 5405, "eastern": 84, "bono": 69, "western": 13,
                                       "central": 3, "oti": 2, "bono east": 1, "upper east": 1}.items() if n in by_}
        b_, z_ = RM.focus_bbox(g_, nca_)
        ok("…Ghana with its records of 26 November (Greater Accra to Upper East): the whole country, every region in it",
           len(nca_) == 9 and not z_ and _inside(b_, g_, nca_), (len(nca_), z_, b_))
else:
    print("  (no country maps here: the real-map checks skipped)")
# the pages' twin (static/js/regions.js focusBox, the held copy when there is one) gives the SAME frame: run under node
import glob as _glob, json as _json, shutil as _sh, subprocess as _sp  # noqa: E402
_node = os.environ.get("LG_NODE") or _sh.which("node") or next(iter(sorted(_glob.glob(os.path.expanduser("~/lg-node/*/bin/node")))), None)
_held = os.environ.get("LG_HELD_DIR", "")
_js = os.path.join(_held, "regions.js.new") if _held and os.path.isfile(os.path.join(_held, "regions.js.new")) \
    else os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "static", "js", "regions.js")
if _node and os.path.isfile(_js):
    cases = [(SC, {"MAHE N": 300, "MAHE S": 200}), (SC, {"MAHE N": 300, "MAHE S": 200, "OUTER": 2}),
             (GH, {"ACCRA": 13996, "ASHANTI": 5405, "UPPER EAST": 1}), (SC, {"MAHE N": 5}), (SC, {})]
    prog = ("global.window = {}; require(process.argv[1]); const cs = JSON.parse(process.argv[2]);"
            "console.log(JSON.stringify(cs.map(([f, c]) => { const r = window.LGRegions.focusBox(f, c); return [r.bbox, r.zoomed]; })));")
    r_ = _sp.run([_node, "-e", prog, _js, _json.dumps(cases)], capture_output=True, text=True, timeout=30)
    try:
        js_ = _json.loads(r_.stdout)
        py_ = [list(RM.focus_bbox(f, c)) for f, c in cases]
        same = all(a[1] == b[1] and all(abs(x - y) < 1e-9 for x, y in zip(a[0], b[0])) for a, b in zip(js_, py_))
        ok(f"the map pages' focusBox ({os.path.basename(_js)}) gives the same frame as the PDF's focus_bbox", same,
           f"js {js_} py {py_}")
    except ValueError:
        ok("the map pages' focusBox runs under node", False, (r_.stdout + r_.stderr)[:300])
else:
    print("  (node not found: the map pages' focusBox not compared with focus_bbox here; CI compares them)")
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
    rr = c.post("/api/settings/region-matches", data="country=GH&name=X&target=", content_type="application/x-www-form-urlencoded")
    ok("anything but JSON is refused (415), as the Settings save", rr.status_code == 415)
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
