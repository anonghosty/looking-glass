#!/usr/bin/env python3
"""The severity map (severity_map.py, the user 2026-11-18/19), with made-up names only, a scratch folder and a throwaway
Flask app; the installation's data/ is never read or written:
1. every name the records carry is learned with its kind, rated or not (names and kinds only, never an address);
2. the rows: not rated first, then by criticality; CVEs left out; names differing only in case are one;
3. who: researchers and administrators only ('definitions', held by no other role); the CSRF token for a change;
4. a researcher rates only a name no record rates: Shadowserver's ratings are never changed; every change audited;
5. the PDFs' References section uses the rating, flagged "Researcher's rating"; once Shadowserver rates the name, its
   rating is used and the researcher's is shown as replaced;
6. the page: the card only for researchers and administrators, its script sets text only.
Run: .venv/bin/python tests/check_severity_map.py"""
import json
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
os.environ.setdefault("LG_QUIET", "1")
import pdf_refs as R  # noqa: E402

tmp = tempfile.mkdtemp()
R.KNOWN["path"] = os.path.join(tmp, "name_levels.json")      # never the installation's own files
R.SEEN["path"] = os.path.join(tmp, "name_kinds.json")
R.DAYS.clear()
import severity_map as SM  # noqa: E402

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info else ""), flush=True)


print("1. Every name the records carry, rated or not")
recs = [{"infection": "loudbot", "severity": "critical", "ip": "192.0.2.1"},
        {"infection": "quietbot", "severity": "", "ip": "192.0.2.2"},
        {"infection": "QuietBot", "ip": "192.0.2.3"},
        {"issues": ["Open thing", "CVE-2099-0001"], "severity": None, "ip": "192.0.2.4"},
        {"tags": "cve-2099-0002", "severity": "high"}]
levels, kinds = {}, {}
R.levels_from_records(recs, levels, kinds)
ok("rated names keep their level; names with no severity are learned too", levels == {"loudbot": "critical", "CVE-2099-0002": "high"}
   and {"quietbot", "Open thing", "loudbot"} <= set(kinds), f"{levels} {kinds}")
ok("…with their kind: an infection or an issue (a CVE is an issue)", kinds["quietbot"] == "Infection" and kinds["Open thing"] == "Issue"
   and kinds["CVE-2099-0001"] == "Issue")
R.remember(levels); R.remember_kinds(kinds)
saved = json.load(open(R.SEEN["path"]))
ok("kept in name_kinds.json: names and kinds only, never an address", set(saved.values()) <= {"Infection", "Issue"}
   and "192.0.2" not in json.dumps(saved), str(saved)[:120])
R.remember_kinds({"quietbot": "Issue"})
ok("…a name's first kind stays", json.load(open(R.SEEN["path"]))["quietbot"] == "Infection")
ok("calling it without kinds is as before (other callers)", R.levels_from_records(recs) == levels)

print("2. The rows")
rows = SM.build_rows(R.all_levels(), R.all_kinds(), {})
names = [r["name"] for r in rows]
ok("CVEs are not on the map (rated by CVSS)", not any(n.upper().startswith("CVE-") for n in names), str(names))
ok("names differing only in case are one row", sum(1 for n in names if n.lower() == "quietbot") == 1, str(names))
ok("not rated first, then by criticality", [r["source"] for r in rows][:2] == ["", ""] and rows[-1]["name"] == "loudbot"
   and rows[-1]["level"] == "critical" and rows[-1]["source"] == "shadowserver", str(rows))

print("3. Who")
from flask import Flask, g  # noqa: E402
app = Flask("sev-check")
who = {"user": "grace", "perms": {"definitions", "networks"}, "csrf": True}
audit = []


class Audit:
    def add(self, kind, **kw):
        audit.append((kind, kw))


@app.before_request
def _u():
    g.user = {"user": who["user"]}


api = SM.install(app, {"base_dir": tmp, "has_perm": lambda p: p in who["perms"], "csrf_ok": lambda: who["csrf"],
                       "audit": Audit(), "people_name": lambda u: {"grace": "Grace Mensah"}.get(u, "")})
api["ratings"].path = os.path.join(tmp, "name_ratings.json")
c = app.test_client()
r = c.get("/api/kb/severity-map")
ok("a researcher reads the map", r.status_code == 200 and r.get_json()["counts"]["not_rated"] == 2, str(r.get_json())[:200])
import auth  # noqa: E402
ok("'definitions' belongs to researchers (and administrators) only", auth.EXCLUSIVE_PERMS.get("definitions") == "researcher"
   and not any("definitions" in ps for role, ps in auth.DEFAULT_ROLES.items() if role not in ("researcher", "admin")))
for role, perms in (("analyst", {"view", "unmasked", "export", "malpedia"}), ("management", {"management"}),
                    ("advisor", {"advisory"}), ("auditor", {"audit"}), ("external", {"view"})):
    who["perms"] = perms
    g1, p1 = c.get("/api/kb/severity-map"), c.post("/api/kb/severity-map/rate", json={"name": "quietbot", "level": "high"})
    ok(f"the {role} role: refused, to read and to rate", g1.status_code == 403 and p1.status_code == 403)
who["perms"] = {"definitions"}
who["csrf"] = False
ok("a rating without the page's CSRF token: refused", c.post("/api/kb/severity-map/rate", json={"name": "quietbot", "level": "high"}).status_code == 403)
who["csrf"] = True

print("4. Researchers rate only names no record rates")
r = c.post("/api/kb/severity-map/rate", json={"name": "loudbot", "level": "low"})
ok("a name Shadowserver rates: refused (409), its rating never changed", r.status_code == 409 and not os.path.exists(api["ratings"].path))
ok("a CVE: refused", c.post("/api/kb/severity-map/rate", json={"name": "CVE-2099-0001", "level": "low"}).status_code == 400)
ok("a name the reports never carried: refused", c.post("/api/kb/severity-map/rate", json={"name": "madeup", "level": "low"}).status_code == 404)
ok("a word that is no level: refused", c.post("/api/kb/severity-map/rate", json={"name": "quietbot", "level": "urgent"}).status_code == 400)
ok("markup in a name: refused", c.post("/api/kb/severity-map/rate", json={"name": "<b>x</b>", "level": "low"}).status_code == 400)
r = c.post("/api/kb/severity-map/rate", json={"name": "QUIETBOT", "level": "high"})
row = next((x for x in (r.get_json() or {}).get("rows", []) if x["name"].lower() == "quietbot"), {})
ok("a not-rated name: rated, with who (full name) and when", r.status_code == 200 and row.get("level") == "high"
   and row.get("source") == "researcher" and row.get("rated_by") == "Grace Mensah" and row.get("rated_at"), str(row))
ok("…kept under the name as the reports write it, once", list(json.load(open(api["ratings"].path))) == ["quietbot"])
ok("…audited: who, which name, from what to what", audit and audit[-1][0] == "severity_rated" and audit[-1][1]["user"] == "grace"
   and audit[-1][1]["target"] == "quietbot" and audit[-1][1]["detail"] == "not rated to high", str(audit[-1:]))
n_audit = len(audit)
c.post("/api/kb/severity-map/rate", json={"name": "quietbot", "level": "high"})
ok("the same rating again: nothing written, nothing audited", len(audit) == n_audit)

print("5. The PDFs")
card = ("quietbot", {"curated": True, "curated_references": ["https://example.org/q"]})
g_ = R.groups([card], {}, [])[0]
ok("the References section uses the rating, flagged \"Researcher's rating\"", g_["level"] == "high" and g_["flags"] == ["Researcher's rating"], str(g_))
R.remember({"quietbot": "medium"})                              # a later day: Shadowserver rates it
g_ = R.groups([card], {}, [])[0]
ok("once Shadowserver rates the name: its rating, no researcher's flag", g_["level"] == "medium" and g_["flags"] == [], str(g_))
row = next(x for x in c.get("/api/kb/severity-map").get_json()["rows"] if x["name"] == "quietbot")
ok("…and the map shows the researcher's as replaced", row["source"] == "shadowserver" and row["level"] == "medium"
   and row.get("replaced") and row.get("rated_level") == "high", str(row))
ok("…which can no longer be changed here", c.post("/api/kb/severity-map/rate", json={"name": "quietbot", "level": ""}).status_code == 409)
r = c.post("/api/kb/severity-map/rate", json={"name": "Open thing", "level": "low"})
r = c.post("/api/kb/severity-map/rate", json={"name": "Open thing", "level": ""})
ok("a rating taken back: not rated again, audited", r.status_code == 200 and "Open thing" not in json.load(open(api["ratings"].path))
   and audit[-1][1]["detail"] == "low taken back: not rated", str(audit[-1:]))
R.RATINGS["get"] = None
ok("no map installed (a tool, a check): no researcher's level, never an error", R.researcher_level("quietbot") == "")

print("6. The page")
S = os.environ.get("LG_HELD_DIR", "")
tpl_path = os.path.join(S, "definitions.html.new") if S and os.path.exists(os.path.join(S, "definitions.html.new")) else os.path.join(HERE, "templates", "definitions.html")
js_path = os.path.join(S, "severity-map.js.new") if S and os.path.exists(os.path.join(S, "severity-map.js.new")) else os.path.join(HERE, "static", "js", "severity-map.js")
tpl = open(tpl_path, encoding="utf-8").read()
js = open(js_path, encoding="utf-8").read() if os.path.exists(js_path) else ""
i = tpl.find('id="cardSev"')
ok("the card only for researchers and administrators (the 'definitions' permission)",
   i > 0 and tpl.rfind('{% if "definitions" in lg_perms %}', 0, i) > tpl.rfind("{% endif %}", 0, i) and "js/severity-map.js" in tpl)
ok("its script sets the server's text as text, never as markup", js and "innerHTML" not in js and "insertAdjacentHTML" not in js)

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {fails}" if fails else ""))
sys.exit(1 if fails else 0)
