#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""Who gets which quarterly report, and how (quarterly.py's routes, the bell, the purge's record). No database: a small
app with the real routes, the insider package's seals and a made-up kept quarter in a throwaway data folder.

  * management sees and downloads only the management PDF and summary CSV; advisors only theirs; administrators only
    the purge CSV (r89: by role, so an admin previewing a portal gets 403 on its files and a note on its card);
  * the cards' words (r89): where the quarter stands before, at and after its end and on the 3rd day; each quarter's
    purge as it stands now; the empty-quarter sentence; Make it again's list from the oldest report day;
  * the page's downloads go through the one shared helper (LGLoader.download), never a plain link with download;
  * the constituency (r89): the platforms' own Settings object and rule, the "Counted for" label;
  * researchers, analysts and external accounts get nothing (403), signed out too;
  * every POST needs the page's CSRF token;
  * every download is sealed (insider.py), its CSV stamped with who and when, and in the audit log;
  * nothing served holds an address;
  * the bell: "ready" for management, advisors and admins (each with their own link), NOT VALID and the purge's result
    for admins only, nothing for the other roles; the pipeline's purge record is written to the audit log once;
  * the purge's switch (r88): off by default; turning it on or off needs the Settings permission, CSRF, a fresh session
    and the administrator's own password (a wrong one refused and counted like a failed sign-in); each change in the
    audit log; no permit while off, the permit written on turning on for a quarter whose purge day has not passed,
    removed on turning off; the bell's "purge is off" alert and the "ready" wording while off;
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
from werkzeug.security import generate_password_hash  # noqa: E402

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


PASSWORD = "the-admins-own-password-1"
_HASH = generate_password_hash(PASSWORD)
HASHES = {n: _HASH for n in NAMES.values()}
FRESH = [True]


class Users:
    def get(self, name):
        return {"hash": HASHES[name]} if name in HASHES else None


class Throttle:                                       # the sign-in throttle: a wrong password counts as a failed sign-in
    def __init__(self):
        self.failures = []

    def locked(self, ip, name):
        return False

    def failed(self, ip, name):
        self.failures.append(name)

    def wait_minutes(self, ip, name):
        return 15


THROTTLE = Throttle()
ctx = {"base_dir": base, "has_perm": has_perm, "csrf_ok": csrf_ok, "audit": Audit(), "people_name": lambda u: "Ada Admin" if u == "ada.admin" else "",
       "users": Users(), "throttle": THROTTLE, "client": lambda: ("127.0.0.1", "check"), "fresh": lambda: FRESH[0]}
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
ok("administrators: only the purge CSV (r89: no management or advisor file)", seen["admin"] == ["admin"], str(seen["admin"]))
print("\nEach role downloads only its own files (r89): by role, not only by permission (admins hold every permission)")
MG_FILES = [k for k in qq.FILES if qq.FILES[k][2] == ("management",)]
AD_FILES = [k for k in qq.FILES if qq.FILES[k][2] == ("advisor",)]
ok("FILES: the management PDF and CSV for management only, the advisor PDF and three CSVs for advisors only, the purge CSV for admins",
   sorted(MG_FILES) == ["management", "pdf_management"] and sorted(AD_FILES) == ["advisor", "issues", "orgs", "pdf_advisor"]
   and qq.FILES["admin"][2] == ("admin",))
codes = {p: get(p, "admin").status_code for p in [f"/api/mgmt/quarterly/{Q}/{k}" for k in qq.FILES]
         + [f"/api/advisory/quarterly/{Q}/{k}" for k in qq.FILES]}
ok("an admin gets 403 on every management and advisor file route", set(codes.values()) == {403}, str(codes))
for role, mine in (("management", "/api/mgmt/quarterly"), ("advisor", "/api/advisory/quarterly")):
    other = "/api/advisory/quarterly" if role == "management" else "/api/mgmt/quarterly"
    theirs = [f"{other}/{Q}/{k}" for k in qq.FILES] + [f"/api/admin/quarterly/{Q}/{k}" for k in qq.FILES]
    foreign = [f"{mine}/{Q}/{k}" for k in qq.FILES if role not in qq.FILES[k][2]]
    c2 = {p: get(p, role).status_code for p in theirs + foreign}
    ok(f"{role}: 403 on the other portal's files, the admin CSV and another audience's kind on its own route",
       set(c2.values()) == {403}, str({p: v for p, v in c2.items() if v != 403}))
pv_m, pv_a = get(LISTS["management"], "admin").json, get(LISTS["advisor"], "admin").json
ok("an admin previewing the Executive portal: the card (quarters, where the quarter stands) without downloads, and a note",
   pv_m["quarters"] and not any(q["files"] for q in pv_m["quarters"]) and pv_m["now"]
   and pv_m["note"].startswith("Quarterly reports are for management only"), str(pv_m.get("note")))
ok("...the advisory portal likewise", pv_a["quarters"] and not any(q["files"] for q in pv_a["quarters"])
   and pv_a["note"].startswith("Quarterly reports are for advisors only"))
ok("management and advisors get no note", get(LISTS["management"], "management").json["note"] == ""
   and get(LISTS["advisor"], "advisor").json["note"] == "")
ok("the one rule (may_see) by role: management yes, an admin no for the portals; the admin audience needs Settings",
   qq.may_see("management", "management", lambda p: p == "management") and not qq.may_see("management", "admin", lambda p: True)
   and not qq.may_see("advisor", "admin", lambda p: True) and qq.may_see("admin", "admin", lambda p: p == "settings")
   and not qq.may_see("admin", "management", lambda p: p == "management")
   and not qq.may_download("pdf_advisor", "management", "management", lambda p: True))
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


print("\nThe purge's switch (Settings → Quarterly, r88): off until an administrator turns it on")
PERMIT = os.path.join(qd, "purge_permit.json")
SWITCH = "/api/admin/quarterly/purge"
OK_HDR = {"X-Role": "admin", "X-CSRF-Token": "the-page-token"}
# as a new installation has it after r88: the report VALID, but no permit, because the purge is off
NOW_ST = dict(STATUS, generated_at=(today - timedelta(days=1)).isoformat() + "T00:20:00+00:00", rows_purge_deletes=4321)   # made before its purge day
json.dump(dict(NOW_ST, permit=False, no_permit_why=qq.WHY_OFF, purge_on=False), open(os.path.join(qd, "status.json"), "w"))
ok("off by default: no purge_confirmed.json, purge_on() is False", not qq.purge_on(base) and not os.path.exists(qq.confirm_path(base)))
adm = get(LISTS["admin"], "admin").json
pv = adm["purge"]["preview"]
ok("the admin's list says it is off, with the newest VALID report's dry count, purge day and cutoff",
   adm["purge"]["enabled"] is False and pv["quarter"] == Q and pv["rows"] == 4321 and pv["purge_day"] == STATUS["purge_day"]
   and pv["cutoff"] == STATUS["cutoff"] and not pv["passed"] and not pv["permit"], str(adm["purge"]))
ok("...and each quarter: no permit (the management list too), purge_on false",
   not adm["quarters"][0]["permit"] and adm["quarters"][0]["purge_on"] is False and adm["quarters"][0]["no_permit_why"] == qq.WHY_OFF
   and not get(LISTS["management"], "management").json["quarters"][0]["permit"])
off = {role: bell(role) for role in ROLES}
offa = [x for x in off["admin"] if x["id"].startswith("sys:quarterly-purge-off")]
ok("the bell, off: one alert for admins only, once per quarter (its id names the quarter)",
   len(offa) == 1 and offa[0]["id"] == f"sys:quarterly-purge-off:{Q}"
   and offa[0]["title"] + ": " + offa[0]["text"] == "The quarterly purge is off: turn it on in Settings → Quarterly, or leave it off to keep every report row."
   and not any(x["id"].startswith("sys:quarterly-purge-off") for r in ROLES if r != "admin" for x in off[r]), str(offa))
rdy = [x for x in off["management"] if x["id"].startswith("sys:quarterly-ready")]
ok("...and \"reports ready\" says what is true: no rows are deleted (never \"are deleted on\")",
   len(rdy) == 1 and "The quarterly purge is off on this installation, so no report rows are deleted." in rdy[0]["text"]
   and "are deleted on" not in rdy[0]["text"], str(rdy))
shown = {"quarter": Q, "rows": 4321, "purge_day": STATUS["purge_day"]}


def switch(role, body, headers=None):
    h = dict(headers if headers is not None else OK_HDR)
    if role is not None:
        h["X-Role"] = role
    elif "X-Role" in h:
        del h["X-Role"]
    return c.post(SWITCH, json=body, headers=h)


on_body = {"enabled": True, "password": PASSWORD, "shown": shown}
codes = {r: switch(r, on_body).status_code for r in ("management", "advisor", "analyst", "researcher", "external", "auditor")}
ok("turning it on needs the Settings permission: every other role is refused (403), signed out too",
   set(codes.values()) == {403} and switch(None, on_body).status_code == 403 and not qq.purge_on(base), str(codes))
ok("...and the page's CSRF token: none or a forged one is refused",
   switch("admin", on_body, {"X-Role": "admin"}).status_code == 403
   and switch("admin", on_body, {"X-Role": "admin", "X-CSRF-Token": "forged"}).status_code == 403 and not qq.purge_on(base))
FRESH[0] = False
ok("...and a session younger than 12 hours (sign in again)", switch("admin", on_body).status_code == 403 and not qq.purge_on(base))
FRESH[0] = True
AUDIT.clear()
THROTTLE.failures.clear()
r = switch("admin", dict(on_body, password="not-the-password"))
ok("a wrong password is refused, counted like a failed sign-in, and in the audit log",
   r.status_code == 403 and THROTTLE.failures == ["ada.admin"] and [a[0] for a in AUDIT] == ["quarterly_purge_password_failed"]
   and not qq.purge_on(base) and not os.path.exists(PERMIT), str((r.status_code, THROTTLE.failures, AUDIT)))
r = switch("admin", {"enabled": True, "shown": shown})
ok("...no password at all is refused the same way", r.status_code == 403 and len(THROTTLE.failures) == 2 and not qq.purge_on(base))
r = switch("admin", dict(on_body, shown=dict(shown, rows=12)))
ok("figures that are not what the purge would delete now are refused (read it again), before the password is checked",
   r.status_code == 409 and len(THROTTLE.failures) == 2 and not qq.purge_on(base), str(r.status_code))
ok("\"enabled\" must be true or false", switch("admin", {"enabled": "yes", "password": PASSWORD}).status_code == 400)
ok("the one password re-check is password_policy.check_own_password (no second copy in quarterly.py)",
   "check_password_hash" not in src and "check_own_password" in src)
AUDIT.clear()
r = switch("admin", on_body)
conf = json.load(open(qq.confirm_path(base)))
ok("turned on with the right password: purge_confirmed.json says enabled, who (full name), when and what was shown; owner-only",
   r.status_code == 200 and conf["enabled"] is True and conf["by"] == "ada.admin" and conf["by_name"] == "Ada Admin"
   and conf["shown"]["rows"] == 4321 and conf["shown"]["quarter"] == Q and conf["shown"]["cutoff"] == STATUS["cutoff"]
   and oct(os.stat(qq.confirm_path(base)).st_mode & 0o777) == "0o600", str((r.status_code, r.json)))
ok("...the permit is written for the quarter whose purge day has not passed (owner-only, the report's own dates)",
   os.path.exists(PERMIT) and json.load(open(PERMIT))["purge_day"] == STATUS["purge_day"]
   and json.load(open(PERMIT))["generated_at"] == NOW_ST["generated_at"] and oct(os.stat(PERMIT).st_mode & 0o777) == "0o600"
   and json.load(open(os.path.join(qd, "status.json")))["permit"] is True)
ok("...in the audit log: turned on, by whom, the rows it would delete then, the permit written",
   [a[0] for a in AUDIT] == ["quarterly_purge_on"] and AUDIT[0][1] == "ada.admin" and AUDIT[0][2] == Q
   and "4,321 raw report rows dated before " + STATUS["cutoff"] in AUDIT[0][3] and "Ada Admin" in AUDIT[0][3]
   and "purge permit written" in AUDIT[0][3], str(AUDIT))
ok("...shown in the Audit portal by name",
   audit_portal.LABEL.get("quarterly_purge_on") == "Quarterly purge turned on" and audit_portal.LABEL.get("quarterly_purge_off") == "Quarterly purge turned off"
   and "quarterly_purge_password_failed" in audit_portal.LABEL)
p = r.json["purge"]
ok("...and the page says on since when, confirmed by whom", p["enabled"] and p["by_name"] == "Ada Admin" and p["since"] == conf["at"])
ok("turning it on twice is refused (already on)", switch("admin", on_body).status_code == 409)
nobell = [x for x in bell("admin") if x["id"].startswith("sys:quarterly-purge-off")]
ok("on: the \"purge is off\" alert is gone", not nobell)
AUDIT.clear()
off_body = {"enabled": False, "password": PASSWORD}
ok("turning it off needs the same checks: another role, no CSRF token, a wrong password are refused",
   switch("management", off_body).status_code == 403 and switch("admin", off_body, {"X-Role": "admin"}).status_code == 403
   and switch("admin", dict(off_body, password="nope")).status_code == 403 and qq.purge_on(base) and os.path.exists(PERMIT))
AUDIT.clear()
r = switch("admin", off_body)
st_off = json.load(open(os.path.join(qd, "status.json")))
ok("turned off: the waiting permit is removed (the purge that has not run yet will not), status.json says why",
   r.status_code == 200 and not qq.purge_on(base) and not os.path.exists(PERMIT) and st_off["permit"] is False
   and st_off["no_permit_why"] == qq.WHY_OFF and json.load(open(qq.confirm_path(base)))["enabled"] is False)
ok("...in the audit log: turned off, by whom, what it would have deleted, the permit removed",
   [a[0] for a in AUDIT] == ["quarterly_purge_off"] and "purge permit removed" in AUDIT[0][3] and "4,321" in AUDIT[0][3], str(AUDIT))
ok("...and the \"purge is off\" alert is back for admins", any(x["id"] == f"sys:quarterly-purge-off:{Q}" for x in bell("admin")))
# a quarter whose purge day has passed: turning it on writes no permit for it
json.dump(dict(st_off, purge_day=(today - timedelta(days=1)).isoformat(), generated_at=(today - timedelta(days=5)).isoformat() + "T00:20:00+00:00"),
          open(os.path.join(qd, "status.json"), "w"))
pv2 = get(LISTS["admin"], "admin").json["purge"]["preview"]
r = switch("admin", dict(on_body, shown={"quarter": Q, "rows": 4321, "purge_day": pv2["purge_day"]}))
st_late = json.load(open(os.path.join(qd, "status.json")))
ok("turned on after a quarter's purge day: no permit for it (its rows wait for the next quarter's purge), and it says so",
   r.status_code == 200 and pv2["passed"] and not os.path.exists(PERMIT) and st_late["permit"] is False and st_late["no_permit_why"] == qq.WHY_ON_LATE,
   str((r.status_code, st_late.get("no_permit_why"))))
r = switch("admin", off_body)
# the rule itself, for every case
D0, D1 = date(2027, 1, 3), date(2027, 1, 22)
ok("the permit's one rule: VALID, made before the purge day, turned on, the day not passed",
   qq.permit_rule(True, D0, D1, True, D0) == (True, "") and qq.permit_rule(False, D0, D1, True, D0)[1] == qq.WHY_INVALID
   and qq.permit_rule(True, D0, D1, False, D0)[1] == qq.WHY_OFF and qq.permit_rule(True, date(2027, 1, 23), D1, True, date(2027, 1, 23))[1] == qq.WHY_MADE_LATE
   and qq.permit_rule(True, D0, D1, True, date(2027, 1, 23))[1] == qq.WHY_ON_LATE)
qq._write_json(qq.confirm_path(base), {"enabled": "true"})
ok("a switch file that says anything but enabled: true is off", not qq.purge_on(base))
open(qq.confirm_path(base), "w").write("{broken")
ok("...a malformed one too", not qq.purge_on(base))
json.dump(dict(NOW_ST, permit=True), open(os.path.join(qd, "status.json"), "w"))
qq._write_json(PERMIT, qq.permit_doc(NOW_ST))           # a permit left from before r88, the purge off
api["tick"]()
ok("the background check removes a permit left while the purge is off (one from before the update)",
   not os.path.exists(PERMIT) and json.load(open(os.path.join(qd, "status.json")))["no_permit_why"] == qq.WHY_OFF)
# back to the made-up kept quarter, purge on (as an installation that turned it on), for the checks below
json.dump(NOW_ST, open(os.path.join(qd, "status.json"), "w"))
os.remove(qq.confirm_path(base))
r = switch("admin", on_body)
ok("turned on again later: the permit is written again", r.status_code == 200 and os.path.exists(PERMIT), str(r.json))

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

print("\nWhere the quarter stands (r89): before, at and after its end, and on the 3rd day")
st_dec31 = qq.stands(date(2026, 12, 31), "management", ["2026Q3"], on=True)
ok("on its last day: in progress, the day it ends, the day its reports are made, the day to download by (purge on)",
   st_dec31 == ["2026Q4 is in progress: it ends Thursday 31 December 2026; its reports are made on Sunday 3 January 2027 "
                "(download before the end of Thursday 21 January 2027)."], str(st_dec31))
ok("...with the purge off, no download-by day for management",
   qq.stands(date(2026, 11, 21), "advisor", ["2026Q3"], on=False)
   == ["2026Q4 is in progress: it ends Thursday 31 December 2026; its reports are made on Sunday 3 January 2027."])
ok("...administrators get the purge day and the cutoff",
   qq.stands(date(2026, 11, 21), "admin", ["2026Q3"], on=True)
   == ["2026Q4 is in progress: it ends Thursday 31 December 2026; its reports are made on Sunday 3 January 2027; with the "
       "quarterly purge on, the report rows dated before Tuesday 22 December 2026 are deleted on Friday 22 January 2027."])
st_jan1 = qq.stands(date(2027, 1, 1), "management", [], on=False)
ok("the day after it ends: \"has ended: its reports are made on\", then the new quarter in progress",
   st_jan1 == ["2026Q4 has ended: its reports are made on Sunday 3 January 2027.",
               "2027Q1 is in progress: it ends Wednesday 31 March 2027; its reports are made on Saturday 3 April 2027."], str(st_jan1))
ok("on the 3rd day, not made yet: \"made today\"; once kept, the line goes",
   qq.stands(date(2027, 1, 3), "management", [], on=False)[0] == "2026Q4 has ended: its reports are made today, Sunday 3 January 2027."
   and len(qq.stands(date(2027, 1, 3), "management", ["2026Q4"], on=False)) == 1)
ok("after the 3rd day with none kept (and it should have been made): \"were due\"; admins are told how to make it",
   qq.stands(date(2027, 1, 9), "admin", [], on=False, since="2026-11-20")[0]
   == "2026Q4 has ended: its reports were due on Sunday 3 January 2027, and none is kept yet. Make them with Make it again."
   and len(qq.stands(date(2027, 1, 9), "admin", [], on=False, since="2027-01-05")) == 1)

print("\nEach quarter's purge as it stands NOW (r89), not as it was when the report was made")
LIVE_Q3 = {"quarter": "2026Q3", "valid": True, "generated_at": "2026-11-20T10:00:00+00:00", "purge_day": "2026-10-22",
           "cutoff": "2026-09-21", "working_day_15": "2026-10-21", "no_permit_why": qq.WHY_MADE_LATE}
ok("made after its purge day (the live 2026Q3): no purge, said plainly, whether the purge is on or off",
   qq.purge_fact(LIVE_Q3, True, date(2026, 11, 21)) == qq.purge_fact(LIVE_Q3, False, date(2026, 11, 21))
   == "No purge for this quarter: its purge day (Thursday 22 October 2026) had passed when it was made.")
Q4 = {"quarter": "2026Q4", "valid": True, "generated_at": "2027-01-03T00:20:00+00:00", "purge_day": "2027-01-22",
      "cutoff": "2026-12-22", "working_day_15": "2027-01-21"}
ok("on, with its permit: download before ..., rows dated before ... are deleted on ...",
   qq.purge_fact(Q4, True, date(2027, 1, 5), permit=True) == "Download before the end of Thursday 21 January 2027: the report rows "
   "dated before Tuesday 22 December 2026 are deleted on Friday 22 January 2027. These reports stay here.")
ok("off now (whatever the report said when it was made): no rows deleted, and what turning it on would do",
   qq.purge_fact(dict(Q4, purge_on=True), False, date(2027, 1, 5)).startswith("No report rows are deleted while the quarterly purge is off."))
ok("NOT VALID, purged, and purge day passed each say so",
   "NOT VALID" in qq.purge_fact(dict(Q4, valid=False), True, date(2027, 1, 5))
   and qq.purge_fact(Q4, True, date(2027, 2, 1), result={"outcome": "done", "at": "2027-01-22T03:00:00", "cutoff": "2026-12-22"})
   .startswith("Purged on Friday 22 January 2027")
   and qq.purge_fact(Q4, True, date(2027, 2, 1)).startswith("No purge for this quarter: its purge day (Friday 22 January 2027) has passed"))
ok("the portals' switch line follows purge_confirmed.json now (on: since when; off: the off sentence)",
   qq.purge_state(False) == qq.OFF_TEXT and qq.purge_state(True, {"at": "2026-11-21T08:47:00+00:00"}).startswith(
       "The quarterly purge is on (turned on 21 November 2026)"))
qq._write_json(qq.confirm_path(base), {"enabled": True, "at": "2026-11-21T08:47:00+00:00"})
json.dump(dict(STATUS, rows=0), open(os.path.join(qd, "status.json"), "w"))
st_path = os.path.join(base, "data", "quarterly", "state.json")
qq._write_json(st_path, dict(json.load(open(st_path)) if os.path.exists(st_path) else {}, oldest_day="2026-09-21", oldest_checked_ts=round(now)))
lm = get(LISTS["management"], "management").json
ok("the management card says the purge is on NOW (from purge_confirmed.json)", lm["purge_state"].startswith("The quarterly purge is on"),
   lm.get("purge_state"))
print("\nAn empty quarter says so (r89)")
ok("the sentence", qq.empty_text("2026Q3", date(2026, 9, 21))
   == "No report rows were loaded for 2026Q3 (Looking Glass holds report rows from 21 September 2026 on)."
   and qq.empty_text("2026Q3") == "No report rows were loaded for 2026Q3.")
ok("...on the card, for a quarter with no report rows, with the cached oldest report day",
   lm["quarters"][0]["empty_text"] == f"No report rows were loaded for {Q} (Looking Glass holds report rows from 21 September 2026 on).",
   lm["quarters"][0].get("empty_text"))
json.dump(dict(STATUS, rows=5), open(os.path.join(qd, "status.json"), "w"))
ok("...and not for a quarter with rows", get(LISTS["management"], "management").json["quarters"][0]["empty_text"] == "")

print("\nMake it again offers only ended quarters with report rows (r89)")
T = date(2026, 11, 21)
ok("the oldest report day 21 September 2026: only 2026Q3", qq.can_make(T, "", date(2026, 9, 21), True) == ["2026Q3"])
ok("no report row at all: none, and when the first report is made",
   qq.can_make(T, "", None, True) == [] and qq.can_make_note(T, None)
   == "No ended quarter has report rows yet: the first report is made on Sunday 3 January 2027.")
ok("rows from long ago: the last four; a purge removes the quarters before its cutoff",
   qq.can_make(T, "", date(2025, 1, 1), True) == ["2026Q3", "2026Q2", "2026Q1", "2025Q4"]
   and qq.can_make(T, "2026-04-01", date(2026, 4, 5), True) == ["2026Q3", "2026Q2"])
ok("the oldest day not known (no database answer yet): the last four not purged, as before",
   qq.can_make(T, "", None, False) == ["2026Q3", "2026Q2", "2026Q1", "2025Q4"])
adm = get(LISTS["admin"], "admin").json
ok("the admin list uses the cached oldest day", adm["oldest_day"] == "2026-09-21" and "can_make_note" in adm, str(adm.get("oldest_day")))
r = c.post("/api/admin/quarterly/make", json={"quarter": "2025Q1"}, headers={"X-Role": "admin", "X-CSRF-Token": "the-page-token"})
ok("...and Make it again refuses a quarter it does not offer (409)", r.status_code == 409, str(r.status_code))

print("\nThe page's downloads: the one shared helper (r89)")
HELD = os.environ.get("LG_HELD_DIR", "")
PLAT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def page_file(name):
    p = os.path.join(HELD, name + ".new") if HELD else ""
    return open(p if p and os.path.exists(p) else os.path.join(PLAT, "static", "js", name), encoding="utf-8").read()


qjs, ljs = page_file("quarterly.js"), page_file("loader.js")
ok("quarterly.js: no download attribute on a link (setAttribute(\"download\") or .download =), no href to a file",
   'setAttribute("download"' not in qjs and not re.search(r"\.download\s*=", qjs) and ".href = f.url" not in qjs)
ok("quarterly.js: every download goes through LGLoader.download", "LGLoader.download(" in qjs)
ok("loader.js: LGLoader.download fetches, makes a blob, names the file from Content-Disposition, tries once more",
   "async download(" in ljs and "createObjectURL" in ljs and "Content-Disposition" in ljs and "attempt < 2" in ljs)
ok("quarterly.js: never shows the browser's own error text (no e.message / x.message on the page)",
   not re.search(r"\b[ex]\.message\b", qjs) and "could not be reached just now (it may be restarting)" in (qjs + ljs)
   and "Trying again…" in qjs and '"Retry"' in qjs)
# r90: with no quarter to offer, Make it again shows only the sentence (can_make_note): no empty drop-down, no greyed
# button; with quarters offered, the drop-down and the button as before
mk = qjs[qjs.find("function adminTools("):qjs.find("// ---------------- the purge's switch")]
ok("quarterly.js: no quarter to offer: neither the drop-down nor the button is shown, only the sentence",
   "const none = !(d.can_make || []).length;" in mk and "if (none) {" in mk and "} else { t.append(sel, btn, msg); w.append(t); }" in mk
   and "sel.disabled = true" not in mk and "if (none && d.can_make_note)" in mk, mk[:0])
ok("quarterly.js: the pipeline's \"nothing to purge\" is shown as its own sentence (it names the quarter waiting next)",
   'last.outcome === "nothing to purge" && last.why ? last.why' in mk)

print("\nThe constituency (r89): the platforms' own Settings object and rule")
import settings as lg_settings  # noqa: E402
sp = os.path.join(base, "data", "settings_check.json")
S = lg_settings.Settings(sp)
clean, errs = lg_settings.Settings.validate({"country": "KE", "networks": ["64501"], "cidrs": ["198.51.100.0/24"]})
S.save(clean)
ok("Counted for: the whole country without a restriction",
   qq.constituency(None) == {"label": "the whole country", "key": "all"})
ok("Counted for: 1 network and 1 address range (the constituency set in Settings)",
   qq.constituency(S)["label"] == "1 network and 1 address range (the constituency set in Settings)" and qq.constituency(S)["key"] != "all")
ok("a host in the network, or in the range, is kept; another is not",
   qq.keep_host(S, {"a": 64501, "h": "203.0.113.9"}) and qq.keep_host(S, {"a": "AS64500", "h": "198.51.100.7"})
   and not qq.keep_host(S, {"a": 64500, "h": "203.0.113.9"}) and qq.keep_host(None, {"a": 1, "h": "x"}))
ok("a communication is kept when its other side's host is in the constituency (the map's rule)",
   qq.keep_host(S, {"a": 64500, "h": "203.0.113.9", "oa": 64999, "oh": "198.51.100.250"})
   and qq.keep_host(S, {"a": 64500, "h": "203.0.113.9", "oh": "198.51.100.250"})      # no dst_asn: MongoDB leaves "oa" out
   and not qq.keep_host(S, {"a": 64500, "h": "203.0.113.9", "oa": 64999, "oh": "203.0.113.250"}))
ok("the purge's switch line and the card: the purge works on all networks (said in plain words)",
   "all networks in the database, not only the constituency" in qjs)


def refused(fn):
    try:
        fn()
        return False
    except ValueError:
        return True


top = os.path.join(base, "data", "quarterly")
ok("paths stay inside the quarterly folder: a quarter name or a kept file name can never point elsewhere",
   qq.quarter_dir(base, "2026Q4").startswith(os.path.realpath(top) + os.sep)
   and refused(lambda: qq.quarter_dir(base, "../2026Q4")) and refused(lambda: qq.quarter_dir(base, "2026Q4\n"))
   and refused(lambda: qq.inside(top, "..", "x")) and refused(lambda: qq.inside(top, "/etc/passwd"))
   and refused(lambda: qq.inside(top, "")))
shutil.rmtree(base, ignore_errors=True)
print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
