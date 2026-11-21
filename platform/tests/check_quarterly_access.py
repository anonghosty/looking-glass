#!/usr/bin/env python3
"""Who gets which quarterly report, and how (quarterly.py's routes, the bell, the purge's record). No database: a small
app with the real routes, the insider package's seals and a made-up kept quarter in a throwaway data folder.

  * management sees and downloads only the management PDF and summary CSV; advisors only theirs; administrators all;
  * researchers, analysts and external accounts get nothing (403), signed out too;
  * every POST needs the page's CSRF token;
  * every download is sealed (insider.py), its CSV stamped with who and when, and in the audit log;
  * nothing served holds an address;
  * the bell: "ready" for management, advisors and admins (each with their own link), NOT VALID and the purge's result
    for admins only, nothing for the other roles; the pipeline's purge record is written to the audit log once;
  * the working-day calendar for every quarter of 2026 to 2029.
Run: .venv/bin/python tests/check_quarterly_access.py"""
import json
import os
import re
import shutil
import sys
import tempfile
import time
from datetime import date, datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("LG_QUIET", "1")
from flask import Flask, g, request  # noqa: E402

import auth  # noqa: E402
import insider  # noqa: E402
import quarterly as qq  # noqa: E402
import system_alerts  # noqa: E402

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info and not cond else ""))


print("The working-day calendar, 2026 to 2029 (Monday to Friday; public holidays not counted)")
WANT = {  # quarter: (15th working day, purge day, cutoff), worked out from a calendar
    "2026Q1": ("2026-04-21", "2026-04-22", "2026-03-22"), "2026Q2": ("2026-07-21", "2026-07-22", "2026-06-21"),
    "2026Q3": ("2026-10-21", "2026-10-22", "2026-09-21"), "2026Q4": ("2027-01-21", "2027-01-22", "2026-12-22"),
    "2027Q1": ("2027-04-21", "2027-04-22", "2027-03-22"), "2027Q2": ("2027-07-21", "2027-07-22", "2027-06-21"),
    "2027Q3": ("2027-10-21", "2027-10-22", "2027-09-21"), "2027Q4": ("2028-01-21", "2028-01-24", "2027-12-24"),
    "2028Q1": ("2028-04-21", "2028-04-24", "2028-03-24"), "2028Q2": ("2028-07-21", "2028-07-24", "2028-06-23"),
    "2028Q3": ("2028-10-20", "2028-10-23", "2028-09-22"), "2028Q4": ("2029-01-19", "2029-01-22", "2028-12-22"),
    "2029Q1": ("2029-04-20", "2029-04-23", "2029-03-23"), "2029Q2": ("2029-07-20", "2029-07-23", "2029-06-22"),
    "2029Q3": ("2029-10-19", "2029-10-22", "2029-09-21"), "2029Q4": ("2030-01-21", "2030-01-22", "2029-12-22")}
bad = []
for q, want in WANT.items():
    p = qq.purge_dates(*qq.parse_quarter(q))
    got = (p["working_day_15"].isoformat(), p["purge_day"].isoformat(), p["cutoff"].isoformat())
    last = p["last_day"]
    n = sum(1 for i in range(1, (p["working_day_15"] - last).days + 1) if (last + timedelta(days=i)).weekday() < 5)
    if got != want or n != 15 or p["purge_day"].weekday() > 4 or p["working_day_15"].weekday() > 4:
        bad.append(f"{q} {got}")
ok("every quarter: the 15th working day, the purge day on the next working day, the cutoff 31 days before it", not bad, "; ".join(bad))
# made automatically on the next quarter's 3rd day, when the quarter's last day's reports have arrived (the user)
d = date
ok("made automatically from the next quarter's 3rd day: not on the 1st or 2nd, then 2026Q4 on 3 January",
   [qq.make_due(x) for x in (d(2027, 1, 1), d(2027, 1, 2), d(2027, 1, 3), d(2027, 3, 31))] == [None, None, "2026Q4", "2026Q4"],
   str([qq.make_due(x) for x in (d(2027, 1, 1), d(2027, 1, 2), d(2027, 1, 3), d(2027, 3, 31))]))
ok("…for every quarter of 2026 to 2029 (the 3rd day of January, April, July and October)",
   all(qq.make_due(d(y, m, 3)) == f"{y - (m == 1)}Q{4 if m == 1 else (m - 1) // 3}" and qq.make_due(d(y, m, 2)) is None
       for y in range(2026, 2030) for m in (1, 4, 7, 10)))
ok("a purge day is never a weekend, and always keeps 31 days",
   all(qq.purge_dates(y, q)["purge_day"].weekday() < 5 and (qq.purge_dates(y, q)["purge_day"] - qq.purge_dates(y, q)["cutoff"]).days == 31
       for y in range(2026, 2030) for q in range(1, 5)))

# ------------------------------------------------------------------ a kept quarter, made up
base = tempfile.mkdtemp(prefix="lgqa_")
os.environ["PIPELINE_DIR"] = os.path.join(base, "pipeline")
os.makedirs(os.environ["PIPELINE_DIR"])
open(os.path.join(os.environ["PIPELINE_DIR"], "shadowserver_pipeline.py"), "w").write("# made-up\n")
open(os.path.join(os.environ["PIPELINE_DIR"], ".env"), "w").write(f"DATA_DIR={os.environ['PIPELINE_DIR']}\n")
Q = "2026Q4"
qd = os.path.join(base, "data", "quarterly", Q)
os.makedirs(qd)
files = {}
for kind in qq.FILES:
    name = qq.file_name(kind, Q)
    body = (b"%PDF-1.4 made-up quarterly report\n" if name.endswith(".pdf")
            else f"Report status,VALID,every accuracy check passed\r\n{kind},{Q},made by the check\r\n\r\nsection,value\r\nTotals,12\r\n".encode())
    open(os.path.join(qd, name), "wb").write(body)
    files[kind] = {"name": name, "bytes": len(body), "sha256": ""}
now = time.time()
today = datetime.now(timezone.utc).date()
STATUS = {"quarter": Q, "status": "VALID", "valid": True, "why": "every accuracy check passed", "made": "made by the check",
          "generated_at": "2027-01-01T00:20:00+00:00", "generated_ts": round(now - 60), "guards": [{"name": "1 x", "ok": True, "detail": ""}],
          "last_day": "2026-12-31", "working_day_15": (today + timedelta(days=10)).isoformat(),
          "purge_day": (today + timedelta(days=11)).isoformat(), "cutoff": (today - timedelta(days=20)).isoformat(),
          "permit": True, "no_permit_why": "", "files": files}
json.dump(STATUS, open(os.path.join(qd, "status.json"), "w"))

# ------------------------------------------------------------------ a small app with the real routes
ROLES = {r: set(auth.PERMS) if r == "admin" else set(auth.DEFAULT_ROLES[r])          # the built-in roles' permissions
         for r in ("admin", "management", "advisor", "analyst", "researcher", "external", "auditor")}
NAMES = {"admin": "ada.admin", "management": "mo.manager", "advisor": "avi.advisor", "analyst": "ann.analyst",
         "researcher": "rex.researcher", "external": "eve.external", "auditor": "aud.auditor"}
AUDIT = []


class Audit:
    def add(self, event, user="", target="", detail=""):
        AUDIT.append((event, user, target, detail))


app = Flask(__name__)
app.config["TESTING"] = True


@app.before_request
def _who():
    role = request.headers.get("X-Role", "")
    g.user = {"user": NAMES[role], "role": role, "perms": set(ROLES[role])} if role in ROLES else None


def has_perm(p):
    return bool(getattr(g, "user", None)) and p in g.user["perms"]


def csrf_ok():
    return request.headers.get("X-CSRF-Token") == "the-page-token"


ctx = {"base_dir": base, "has_perm": has_perm, "csrf_ok": csrf_ok, "audit": Audit(), "people_name": lambda u: "Ada Admin" if u == "ada.admin" else ""}
insider.install(app, dict(ctx))
api = qq.install(app, dict(ctx, db=None, serving=False))
c = app.test_client()


def get(path, role):
    return c.get(path, headers={"X-Role": role} if role else {})


LISTS = {"management": "/api/mgmt/quarterly", "advisor": "/api/advisory/quarterly", "admin": "/api/admin/quarterly"}
print("\nEach role sees only its own downloads")
seen = {}
for role in ("management", "advisor", "admin"):
    r = get(LISTS[role], role)
    seen[role] = sorted(f["kind"] for q in (r.json or {}).get("quarters", []) for f in q["files"])
ok("management: the management PDF and summary CSV only", seen["management"] == ["management", "pdf_management"], str(seen["management"]))
ok("advisors: the advisor PDF and their three CSVs only", seen["advisor"] == ["advisor", "issues", "orgs", "pdf_advisor"], str(seen["advisor"]))
ok("administrators: all seven, the purge CSV and both PDFs included", seen["admin"] == sorted(qq.FILES), str(seen["admin"]))
ok("the lists carry the dates (download before, purge day, cutoff) and VALID",
   all(q["valid"] and q["download_before"] and q["purge_day"] and q["cutoff"] for q in get(LISTS["management"], "management").json["quarters"]))
ok("only the admin's list has the accuracy checks and the purge's status",
   "guards" in get(LISTS["admin"], "admin").json["quarters"][0] and "guards" not in get(LISTS["advisor"], "advisor").json["quarters"][0])
cross = [(role, path) for role in ("management", "advisor") for path in
         [f"/api/mgmt/quarterly/{Q}/{k}" for k in qq.FILES if "management" not in qq.FILES[k][2]]
         + [f"/api/advisory/quarterly/{Q}/{k}" for k in qq.FILES if "advisor" not in qq.FILES[k][2]]]
ok("a file of another audience is not served on a role's own route (404)",
   all(get(p, role).status_code in (403, 404) for role, p in cross))
ok("management cannot use the advisors' or the admins' routes; advisors not the management's or admins'",
   get(LISTS["advisor"], "management").status_code == 403 and get(LISTS["admin"], "management").status_code == 403
   and get(LISTS["management"], "advisor").status_code == 403 and get(LISTS["admin"], "advisor").status_code == 403
   and get(f"/api/admin/quarterly/{Q}/admin", "management").status_code == 403)

print("\nResearchers, analysts, external accounts and auditors get nothing")
paths = list(LISTS.values()) + [f"{p}/{Q}/{k}" for p in LISTS.values() for k in qq.FILES]
for role in ("researcher", "analyst", "external", "auditor", None):
    codes = {get(p, role).status_code for p in paths}
    ok(f"{role or 'signed out'}: refused everywhere", codes == {403}, str(codes))
ok("odd names are refused, nothing outside the quarter's folder is read",
   all(get(p, "admin").status_code == 404 for p in ("/api/admin/quarterly/2026Q5/admin", "/api/admin/quarterly/..%2F..%2Fdata/admin",
                                                     f"/api/admin/quarterly/{Q}/status", f"/api/admin/quarterly/{Q}/summary")))

print("\nEvery POST needs the page's CSRF token")
r1 = c.post("/api/admin/quarterly/make", json={"quarter": Q}, headers={"X-Role": "admin"})
r2 = c.post("/api/admin/quarterly/make", json={"quarter": Q}, headers={"X-Role": "admin", "X-CSRF-Token": "forged"})
r3 = c.post("/api/admin/quarterly/make", json={"quarter": Q}, headers={"X-Role": "management", "X-CSRF-Token": "the-page-token"})
ok("Make it again: refused without the token, with a forged one, and for a non-admin", (r1.status_code, r2.status_code, r3.status_code) == (403, 403, 403))
r4 = c.post("/api/admin/quarterly/make", json={"quarter": "2099Q1"}, headers={"X-Role": "admin", "X-CSRF-Token": "the-page-token"})
r5 = c.post("/api/admin/quarterly/make", json={"quarter": "nonsense"}, headers={"X-Role": "admin", "X-CSRF-Token": "the-page-token"})
ok("...a quarter that has not ended, or no quarter, is refused before anything runs", r4.status_code == 409 and r5.status_code == 400)
src = open(qq.__file__, encoding="utf-8").read()
posts = re.findall(r'@app\.route\("([^"]+)", methods=\["POST"\]\)\n    def (\w+)\(\):\n(.*?)\n\n', src, re.S)
ok("every POST route of quarterly.py checks the CSRF token", posts and all("csrf_ok" in body for _p, _f, body in posts), str([p for p, _f, _b in posts]))

print("\nDownloads: sealed, stamped, in the audit log, no address")
seals_path = os.path.join(base, "data", "copy_seals.jsonl")
before = len(open(seals_path).read().splitlines()) if os.path.exists(seals_path) else 0
AUDIT.clear()
r = get(f"/api/mgmt/quarterly/{Q}/management", "management")
ok("the management CSV downloads as an attachment", r.status_code == 200 and "attachment" in r.headers.get("Content-Disposition", ""))
text = r.data.decode()
ok("...still says VALID on its first line, then who downloaded it and when (stamped)",
   text.startswith("Report status,VALID") and text.splitlines()[1].startswith("Downloaded,mo.manager,"), text.splitlines()[:2])
r = get(f"/api/admin/quarterly/{Q}/admin", "admin")
ok("an admin's stamp carries the full name", r.data.decode().splitlines()[1].startswith("Downloaded,Ada Admin (ada.admin),"))
pdf = get(f"/api/advisory/quarterly/{Q}/pdf_advisor", "advisor")
ok("the advisor PDF downloads unchanged", pdf.status_code == 200 and pdf.data.startswith(b"%PDF") and pdf.mimetype == "application/pdf")
seals = [json.loads(x) for x in open(seals_path).read().splitlines()[before:]]
ok("each download is sealed (insider.py): who, which file, its fingerprint",
   [(s["user"], s["what"]) for s in seals] == [("mo.manager", qq.file_name("management", Q)), ("ada.admin", qq.file_name("admin", Q)),
                                               ("avi.advisor", qq.file_name("pdf_advisor", Q))] and all(s.get("sha256") for s in seals),
   str([(s.get("user"), s.get("what")) for s in seals]))
ok("each download is in the audit log (quarterly_download: who, the quarter, the file)",
   [(a[0], a[1], a[2]) for a in AUDIT] == [("quarterly_download", "mo.manager", Q), ("quarterly_download", "ada.admin", Q),
                                          ("quarterly_download", "avi.advisor", Q)])
import audit_portal  # noqa: E402
ok("...shown in the Audit portal by name (Data tab; made and purge under System)",
   audit_portal.TAB_OF.get("quarterly_download") == "data" and audit_portal.TAB_OF.get("quarterly_purge") == "system"
   and audit_portal.LABEL.get("quarterly_purge") == "Quarterly purge")
served = [get(p, "admin").data for p in [f"/api/admin/quarterly/{Q}/{k}" for k in qq.FILES]] + [json.dumps(get(LISTS["admin"], "admin").json).encode()]
ok("nothing served holds an address", not any(qq.ADDR_RE.search(b.decode("utf-8", "replace")) for b in served))

print("\nThe bell")
alerts = system_alerts.Alerts(base, env={})


def bell(role):
    with app.test_request_context(headers={"X-Role": role}):
        _who()
        return [a for a in alerts.for_user(NAMES[role], has_perm=has_perm) if a["id"].startswith("sys:quarterly")]


ready = {role: bell(role) for role in ROLES}
ok("\"ready\": one alert each for management, advisors and admins", all(len(ready[r]) == 1 for r in ("management", "advisor", "admin")))
ok("...none for researchers, analysts, external accounts or auditors", all(not ready[r] for r in ("researcher", "analyst", "external", "auditor")))
a = ready["management"][0]
ok("...it names the quarter, the day to download by, the cutoff and the purge day",
   a["title"] == f"{Q} reports ready" and "download it before the end of" in a["text"] and "are deleted on" in a["text"]
   and date.fromisoformat(STATUS["purge_day"]).strftime("%d %B %Y") in a["text"])
ok("...and leads each to their own page", (ready["management"][0]["link"], ready["advisor"][0]["link"], ready["admin"][0]["link"])
   == ("/management#quarterly", "/advisory#quarterly", "/settings#quarterly"))
json.dump(dict(STATUS, valid=False, status="NOT VALID", why="3 independent recount", permit=False, generated_ts=round(now)),
          open(os.path.join(qd, "status.json"), "w"))
inv = {role: bell(role) for role in ROLES}
ok("NOT VALID: a problem alert for admins only, saying no permit was written",
   len(inv["admin"]) == 1 and inv["admin"][0]["waiting"] and "No purge permit" in inv["admin"][0]["text"]
   and not any(inv[r] for r in ROLES if r != "admin"))
json.dump(STATUS, open(os.path.join(qd, "status.json"), "w"))
json.dump({"purged_before": STATUS["cutoff"], "done": {Q: {"quarter": Q, "at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                                                         "outcome": "done", "purge_day": STATUS["purge_day"], "cutoff": STATUS["cutoff"],
                                                         "keep_days": 31, "rows_deleted": 1234567, "collections_touched": 12,
                                                         "collections": {"scan_http": {"matched": 1000, "deleted": 1000}}}}},
          open(os.path.join(os.environ["PIPELINE_DIR"], "quarterly_purge_status.json"), "w"))
AUDIT.clear()
api["take_results"]()
api["take_results"]()
ok("the pipeline's purge is written to the audit log once (rows, collections, cutoff, when)",
   len(AUDIT) == 1 and AUDIT[0][0] == "quarterly_purge" and AUDIT[0][2] == Q and "1,234,567 rows deleted from 12" in AUDIT[0][3]
   and STATUS["cutoff"] in AUDIT[0][3], str(AUDIT))
done = {role: [x for x in bell(role) if x["id"].startswith("sys:quarterly-purged")] for role in ROLES}
ok("...and its result is in the admins' bell only", len(done["admin"]) == 1 and "1,234,567" in done["admin"][0]["text"]
   and not any(done[r] for r in ROLES if r != "admin"))
adm = get(LISTS["admin"], "admin").json
ok("...and on the admin's list (the purge's result, the pipeline's last check)",
   adm["quarters"][0]["purge_result"]["rows_deleted"] == 1234567 and adm["pipeline"]["purged_before"] == STATUS["cutoff"])
ok("a quarter whose rows were purged is not offered to make again (every earlier quarter starts before the cutoff)",
   not adm["can_make"], str(adm["can_make"]))
json.dump({"last": {"quarter": Q, "outcome": "refused", "why": "the permit's dates are not the rule's"}},
          open(os.path.join(os.environ["PIPELINE_DIR"], "quarterly_purge_status.json"), "w"))
os.remove(os.path.join(qd, "purge_result.json"))
ref = {role: [x for x in bell(role) if x["id"].startswith("sys:quarterly-purge-refused")] for role in ROLES}
ok("a purge Looking Glass allowed but the pipeline refused: a problem for admins only",
   len(ref["admin"]) == 1 and "not the rule" in ref["admin"][0]["text"] and not any(ref[r] for r in ROLES if r != "admin"))
shutil.rmtree(base, ignore_errors=True)
print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
