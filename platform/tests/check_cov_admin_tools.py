#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""Four administrator tools on small throwaway Flask apps, with made-up stand-ins and a temporary folder (r91 coverage):
- the organisation (organisation.py): who may read and set it, demo mode, CSRF, a stale sign-in, the name rules, logos
  that are not what they claim, too big, unreadable or removed, the advisory look and page name, the logo download
- researchers' notes (notes.py): reading and writing refused without the right, an old sign-in, an empty note, too many
  or unknown combination codes, a note tracked as a finding (a manager must be named), removing (author or admin
  only, unknown id), a broken notes file, cards without notes left as they are
- Settings → Task monitor (task_monitor.py): only with 'settings'; what it reads when /proc, ps, crontab, the load or
  the disk cannot be read; restarts; the bell's pipeline status failing; clearing the cache; a body it does not know;
  the performance sampler skipping a reading that fails and stopping when nobody looks
- Settings → Workers (pipeline_settings.py): the Shadowserver API call (https only, a redirect away from https, a
  refusal with and without its reason, unreachable), ping; with no pipeline beside the platform: said so; with a
  made-up older pipeline: its settings, nothing changed, the API key checked and refused, the held-back reports
  without readable names, no 7-day sender view, one release request per report; the unlock and its expiry
No server, no database, nothing of the installation touched. Run: .venv/bin/python tests/check_cov_admin_tools.py"""
import base64, json, logging, os, shutil, sys, tempfile, time, types, urllib.error, urllib.request
from pathlib import Path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("LG_QUIET", "1")
from flask import Flask, g  # noqa: E402
from werkzeug.security import generate_password_hash  # noqa: E402
import auth  # noqa: E402
import https_only  # noqa: E402
import notes as N  # noqa: E402
import organisation as O  # noqa: E402
import pipeline_settings as PS  # noqa: E402
import task_monitor as TM  # noqa: E402

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info and not cond else ""), flush=True)


tmp = tempfile.mkdtemp(prefix="lg-cov-admintools-")
os.makedirs(os.path.join(tmp, "data"))
ME = {"user": "cov-admin", "role": "admin", "csrf": "tok", "perms": {"settings", "users"}}
FLAGS = {"demo": False, "csrf": True, "fresh": True}
logged = []
AUDIT = types.SimpleNamespace(add=lambda ev, **k: logged.append((ev, k.get("user", ""), k.get("target", ""), k.get("detail", ""))))
PW = "Steady-Harbour-Lantern-63!"
USERS = {"cov-admin": {"hash": generate_password_hash(PW), "status": "active", "role": "admin"}}


def new_app():
    app = Flask(__name__)
    app.logger.setLevel(logging.ERROR)

    @app.before_request
    def _me():
        g.user = dict(ME)
    return app


CTX = {"base_dir": tmp, "data_dir": os.path.join(tmp, "data"), "has_perm": lambda p: p in ME["perms"], "csrf_ok": lambda: FLAGS["csrf"],
       "fresh": lambda: FLAGS["fresh"], "is_demo": lambda: FLAGS["demo"], "audit": AUDIT,
       "users": types.SimpleNamespace(get=lambda n: USERS.get(n)), "throttle": auth.Throttle(), "client": lambda: ("127.0.0.1", "ua")}
PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64
JPG = b"\xff\xd8\xff" + b"\x00" * 64
url = lambda raw, kind="png": f"data:image/{kind};base64," + base64.b64encode(raw).decode()
saved_env = os.environ.get("PIPELINE_DIR")
try:
    print("The organisation")
    app = new_app(); org = O.install(app, CTX); c = app.test_client()
    ME["perms"] = {"view"}
    ok("reading without Settings or advisory: 403", c.get("/api/organisation").status_code == 403)
    ok("…setting it: 403", c.post("/api/organisation", json={"name": "X"}).status_code == 403)
    ok("…the logo: 403", c.get("/organisation/logo").status_code == 403)
    ME["perms"] = {"advisory"}
    r = c.get("/api/organisation")
    ok("an advisor reads it, cannot edit; the defaults (designed, Looking Glass)", r.status_code == 200 and r.json["can_edit"] is False
       and r.json["pdf_look"] == "designed" and r.json["pdf_brand"] == "looking-glass")
    ok("no logo yet: 404", c.get("/organisation/logo").status_code == 404)
    ME["perms"] = {"settings"}
    post = lambda b: c.post("/api/organisation", json=b)
    FLAGS["demo"] = True
    ok("demo mode on: 403", post({"name": "Made-up CSIRT"}).status_code == 403)
    FLAGS.update(demo=False, csrf=False)
    ok("without the page's CSRF token: 403", post({"name": "Made-up CSIRT"}).status_code == 403)
    FLAGS.update(csrf=True, fresh=False)
    ok("a sign-in older than 12 hours: 403", post({"name": "Made-up CSIRT"}).status_code == 403)
    FLAGS["fresh"] = True
    ok("no name: 400", post({"name": "   "}).status_code == 400)
    ok("a name with < >: 400", post({"name": "<b>CSIRT</b>"}).status_code == 400)
    ok("a name over 120 characters: 400", post({"name": "C" * 121}).status_code == 400)
    ok("a logo that is a GIF: 400", "PNG or JPEG" in post({"name": "Made-up CSIRT", "logo": "data:image/gif;base64,R0lGOD"}).json["error"])
    ok("a 'PNG' that is a JPEG inside: 400", "not the image it claims" in post({"name": "Made-up CSIRT", "logo": url(JPG)}).json["error"])
    ok("a logo that cannot be decoded: 400", "could not be read" in post({"name": "Made-up CSIRT", "logo": "data:image/png;base64,abc"}).json["error"])
    ok("a logo over 40 KB: 400 with its size", "at most 40 KB" in post({"name": "Made-up CSIRT", "logo": url(PNG + b"\x00" * 41000)}).json["error"])
    ok("an unknown look: 400", post({"name": "Made-up CSIRT", "pdf_look": "neon"}).status_code == 400)
    ok("an unknown page name: 400", post({"name": "Made-up CSIRT", "pdf_brand": "everyone"}).status_code == 400)
    r = post({"name": "  Made-up   CSIRT ", "logo": url(JPG, "jpeg"), "pdf_look": "plain", "pdf_brand": "organisation"})
    ok("a good name, JPEG logo, plain look, the organisation's name on the pages: saved, spaces tidied",
       r.status_code == 200 and r.json["name"] == "Made-up CSIRT" and r.json["has_logo"] and r.json["pdf_look"] == "plain")
    ok("…written down with what changed", any(e == "organisation_set" and "logo set" in d and "advisory look: plain" in d and "pages: organisation" in d
                                              for e, _, _, d in logged))
    r = c.get("/organisation/logo")
    ok("the logo is served as itself, not kept", r.status_code == 200 and r.data == JPG and r.mimetype == "image/jpeg" and r.headers["Cache-Control"] == "no-store")
    ok("the page name: the organisation's", org.brand_text() == "Made-up CSIRT")
    post({"name": "Made-up CSIRT"})
    ok("saving the name only keeps the logo and the look", org.get()["logo"] == JPG and org.get()["pdf_look"] == "plain")
    post({"name": "Made-up CSIRT", "logo": "", "pdf_brand": "none"})
    ok("logo '' removes it; page name none", org.get()["logo"] is None and org.brand_text() == "")
    with open(org.path, "w") as fh:
        json.dump({"name": "X", "logo": "!!not base64!!", "pdf_look": "neon", "pdf_brand": "nobody"}, fh)
    o = org.get()
    ok("a stored logo that cannot be decoded, an unknown look and name: no logo, the defaults", o["logo"] is None and o["pdf_look"] == "designed"
       and org.brand_text() == "Looking Glass")

    print("Researchers' notes")

    class People:
        def name(self, user, saved=""):
            return {"cov-research": "Ama Owusu"}.get(user, saved or user)

        def full_name(self, user):
            return self.name(user)

    class Book:
        def resolve(self, c):
            return c == "LG-C-0000ABCD"

        def describe(self, c):
            return "made-up combination"
    nctx = {"base_dir": tmp, "people": People(), "audit": AUDIT, "allowed": lambda: FLAGS["read"], "change_allowed": lambda: FLAGS["write"],
            "fresh": lambda: FLAGS["fresh"], "logger": logging.getLogger("lg-cov-notes")}
    FLAGS.update(read=False, write=False)
    app = new_app(); notes = N.install(app, nctx); c = app.test_client()
    notes.codes = Book()
    ok("reading without the right: 403", c.get("/api/notes?name=x").status_code == 403)
    ok("writing without the right: 403", c.post("/api/notes", json={"name": "x", "text": "y"}).status_code == 403)
    ok("removing without the right: 403", c.post("/api/notes/delete", json={"id": "x"}).status_code == 403)
    FLAGS.update(read=True, write=True, fresh=False)
    ok("writing after an old sign-in: 403", c.post("/api/notes", json={"name": "x", "text": "y"}).status_code == 403)
    ok("removing after an old sign-in: 403", c.post("/api/notes/delete", json={"id": "x"}).status_code == 403)
    FLAGS["fresh"] = True
    ok("an empty note: 400", c.post("/api/notes", json={"name": "examplebot", "text": "  "}).status_code == 400)
    r = c.post("/api/notes", json={"name": "examplebot", "text": "x", "codes": [f"LG-C-{i:08X}" for i in range(11)]})
    ok("eleven combination codes: 400", r.status_code == 400 and "At most 10" in r.json["error"])
    r = c.post("/api/notes", json={"name": "examplebot", "text": "x", "codes": ["LG-C-FFFFFFFF"]})
    ok("a code not known here: 400", r.status_code == 400 and "LG-C-FFFFFFFF" in r.json["error"])

    class Track:
        def __init__(self):
            self.made = []

        def recipient(self, role, to):
            return (to, "") if to == "cov-mgmt" else (None, "Name the manager who should follow it up.")

        def create(self, note, section, name, title, user, role, to, to_role, extra=None):
            self.made.append((note["id"], name, title, to))
            return {"id": 7, "title": title or name}

        def of_note(self, nid):
            return {"id": 7, "status": "open"} if any(m[0] == nid for m in self.made) else None
    notes.findings = Track()
    r = c.post("/api/notes", json={"name": "examplebot", "text": "C2 moved", "finding": {"to": "nobody"}})
    ok("tracking as a finding without a manager named: 400", r.status_code == 400 and "manager" in r.json["error"])
    ME.update(user="cov-research", role="researcher", perms={"definitions"})
    r = c.post("/api/notes", json={"name": "ExampleBot", "section": "bogus", "text": "C2 moved to a new domain\r\n",
                                   "codes": ["lg-c-0000abcd", "LG-C-0000ABCD"], "finding": {"to": "cov-mgmt", "title": "C2 moved"}})
    n = r.json.get("note", {}) if r.status_code == 200 else {}
    ok("a note with a code (any case, once) tracked as a finding: saved, the finding made",
       r.status_code == 200 and [x["code"] for x in n.get("codes", [])] == ["LG-C-0000ABCD"] and notes.findings.made
       and notes.findings.made[0][3] == "cov-mgmt", str(r.json))
    listed = (notes.list("infections", "examplebot") or [{}])[0]
    ok("…shown with the author's full name, its role, the finding's number", n.get("by") == "Ama Owusu" and n.get("role") == "Researcher"
       and listed.get("finding", {}).get("number") == "#7", str(listed))
    ok("…an unknown section is the infections", bool(notes.list("infections", "examplebot")))
    ok("…written down twice (note, finding)", [e for e, *_ in logged][-2:] == ["note_added", "finding_created"])
    card = notes.attach({"name": "examplebot"}, "infections", "EXAMPLEBOT")
    ok("a card gets its notes, without the author's user name", card["notes"] and "user" not in card["notes"][0])
    ok("a card that is not a dict, or has no notes: as it is", notes.attach("text", "infections", "x") == "text"
       and notes.attach({"a": 1}, "issues", "nothing") == {"a": 1})
    nid = n.get("id", "")
    ME.update(user="cov-analyst2", role="analyst", perms={"view"})
    r = c.post("/api/notes/delete", json={"id": nid})
    ok("someone else removing it: 403", r.status_code == 403 and "author" in r.json["error"])
    ok("an unknown id: 404", c.post("/api/notes/delete", json={"id": "nope"}).status_code == 404)
    ME.update(user="cov-admin", role="admin", perms={"settings", "users"})
    r = c.post("/api/notes/delete", json={"id": nid})
    ok("an administrator removes it; the name's list is gone", r.status_code == 200 and notes.list("infections", "examplebot") == []
       and "examplebot" not in notes.data["infections"])
    adm = notes.add("issues", "openssl", "admin note", "cov-admin", "admin")
    ok("an administrator's note is labelled as the role it played", adm["role"] == "Administrator acting as researcher")
    with open(notes.path, "w") as fh:
        fh.write("{broken")
    os.utime(notes.path, (time.time() + 5, time.time() + 5))
    ok("a broken notes file: the notes read before are kept, no error", notes.list("issues", "openssl") != [])
    r = c.get("/api/notes?section=issues&name=openssl")
    ok("reading through the API", r.status_code == 200 and len(r.json["notes"]) == 1)
    with open(notes.path, "w") as fh:
        json.dump({"services": {"scan_ssh": [{"id": "abc123", "text": "written elsewhere", "user": "gone-user", "name": "Kofi Mensah",
                                              "role": "management", "at": 5}]}}, fh)
    os.utime(notes.path, (time.time() + 10, time.time() + 10))
    got = notes.list("services", "SCAN_SSH")
    ok("a notes file changed on disk is read again; a gone account keeps its saved name, its role label",
       len(got) == 1 and got[0]["by"] == "Kofi Mensah" and got[0]["role"] == "Management" and notes.list("issues", "openssl") == [])

    print("Settings → Task monitor")
    rc = types.SimpleNamespace(entries={"a": 1, "b": 2}, gen=1, stats={"hits": 3}, lock=__import__("threading").Lock())
    rc.bump = lambda: setattr(rc, "gen", rc.gen + 1)

    class Alerts:
        def _pipeline_status(self):
            raise RuntimeError("status file broken")

        def current(self):
            return [{"title": "Made-up alert", "problem": "only for the check", "extra": "x"}]
    tctx = {"base_dir": tmp, "has_perm": lambda p: p in ME["perms"], "csrf_ok": lambda: FLAGS["csrf"], "fresh": lambda: FLAGS["fresh"],
            "audit": AUDIT, "cache": rc, "throttle": CTX["throttle"], "alerts": Alerts()}
    app = new_app(); TM.install(app, tctx); c = app.test_client()
    with open(os.path.join(tmp, "data", "restarts.jsonl"), "w") as fh:
        fh.write("".join(json.dumps({"t": 1_700_000_000 + i * 60}) + "\n" for i in range(7)))
    ME["perms"] = {"view"}
    ok("without 'settings': 403 (reading and changing)", c.get("/api/admin/monitor").status_code == 403
       and c.post("/api/admin/monitor/cache", json={"action": "clear"}).status_code == 403)
    ME["perms"] = {"settings"}
    TM.SAMPLER.IDLE_S = 0                       # no sampler thread left running after the check
    r = c.get("/api/admin/monitor")
    j = r.json or {}
    ok("the snapshot: the service, jobs, the cache, the machine", r.status_code == 200 and j["service"]["pid"] == os.getpid()
       and len(j["jobs"]) == len(TM.JOBS) and j["cache"]["entries"] == 2 and "cpus" in j["machine"])
    ok("…the last 5 restarts, newest first", len(j["restarts"]) == 5 and j["restarts"][0] > j["restarts"][-1])
    ok("…the bell's pipeline status failing: none, no error; the alerts by title and problem only",
       j["pipeline"]["last"] is None and j["alerts"] == [{"title": "Made-up alert", "problem": "only for the check"}])
    real = {"run": TM.subprocess.run, "load": TM.os.getloadavg, "statvfs": TM.os.statvfs}

    def boom(*a, **k):
        raise OSError("not here")

    def no_open(*a, **k):
        raise OSError("no /proc")
    TM.subprocess.run, TM.os.getloadavg, TM.os.statvfs = boom, boom, boom
    TM.open = no_open
    TM._CRON["at"] = 0
    try:
        ok("ps not available: MongoDB not running (no error)", TM._mongod() == {"running": False})
        ok("crontab not runnable: the schedule unreadable", TM._cron() == ([], False))
        m = TM._machine(tmp)
        ok("no load, /proc/meminfo or disk figures: only the CPU count", set(m) == {"cpus"}, str(m))
        ok("no /proc/self: only the pid, threads and uptime", set(TM._proc_self()) == {"pid", "threads", "uptime_s"})
        ok("restarts unreadable: none", TM._restarts(os.path.join(tmp, "data")) == [])
        rd = TM.Sampler._read()
        ok("a sampler reading with /proc closed: only its time", set(rd) == {"t"})
    finally:
        TM.subprocess.run, TM.os.getloadavg, TM.os.statvfs = real["run"], real["load"], real["statvfs"]
        del TM.open
    TM._CRON["at"] = 0
    real_run = TM.subprocess.run
    TM.subprocess.run = lambda *a, **k: types.SimpleNamespace(returncode=0, stderr="", stdout=(
        "# a comment\n*/30 * * * * /srv/shadowserver/run.sh\n0 3 * * 1 fetch_offline_names.py\n5 4 * * * looking-glass backup\n"
        "1 1 * * * something else\n"))
    try:
        lines, readable = TM._cron()
    finally:
        TM.subprocess.run = real_run
    ok("crontab: only Looking Glass's lines, named", readable and [x["what"] for x in lines] == ["report pipeline", "MISP Galaxy / ATT&CK refresh", "Looking Glass job"]
       and lines[0]["when"] == "*/30 * * * *", str(lines))
    s = TM.Sampler()
    s.STEP_S, s.IDLE_S = 0.01, 0.2
    s._point = lambda a, b: (_ for _ in ()).throw(ValueError("a reading that fails"))
    s.touch()
    for _ in range(100):
        if s.thread is None:
            break
        time.sleep(0.05)
    ok("the sampler skips readings that fail and stops when nobody looks", s.thread is None and len(s.hist) == 0)
    s2 = TM.Sampler()
    a_ = {"t": 0.0, "cpu_busy": 10, "cpu_all": 100, "svc_cpu": 1.0, "disk_read": 0, "net_rx": 0}
    b_ = {"t": 2.0, "cpu_busy": 60, "cpu_all": 200, "svc_cpu": 1.5, "disk_read": 2048 * 2, "net_rx": 1024}
    p = s2._point(a_, b_)
    ok("a point: CPU 50 %, disk read 2 KB/s, network 0.5 KB/s", p["cpu"] == 50.0 and p["disk_read_kbs"] == 2.0 and p["net_rx_kbs"] == 0.5, str(p))
    hd = {"X-CSRF-Token": "tok"}
    FLAGS["csrf"] = False
    ok("changing the cache without CSRF: 403", c.post("/api/admin/monitor/cache", json={"action": "clear"}).status_code == 403)
    FLAGS.update(csrf=True, fresh=False)
    r = c.post("/api/admin/monitor/cache", json={"action": "clear"})
    ok("…after an old sign-in: 403, sign in again", r.status_code == 403 and r.json.get("reauth"))
    FLAGS["fresh"] = True
    r = c.post("/api/admin/monitor/cache", json={"action": "clear"}, headers=hd)
    ok("clearing: how many answers forgotten, the generation moved on, written down", r.json == {"ok": True, "cleared": 2} and rc.gen == 2
       and any(e == "cache_cleared" for e, *_ in logged))
    ok("a ttl that is not a whole number: 400", c.post("/api/admin/monitor/cache", json={"ttl": True}).status_code == 400)
    ok("a body it does not know: 400", c.post("/api/admin/monitor/cache", json={"nothing": 1}).status_code == 400)

    print("Settings → Workers: the Shadowserver API call")
    real_open = https_only.open

    class Resp:
        def __init__(self, body):
            self.body = body

        def read(self, n):
            return self.body

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False
    answers = []

    def fake_open(req, timeout):
        a = answers.pop(0)
        if isinstance(a, Exception):
            raise a
        return Resp(a)
    https_only.open = fake_open
    try:
        ok("an address that is not https: refused before anything is sent", PS._api("test/ping", "k", "s", url="http://api.example")[1].startswith("The report API address"))
        answers[:] = [https_only.NotHttps("redirect")]
        ok("a redirect away from https: stopped", "redirected away" in PS._api("test/ping", "k", "s")[1])
        answers[:] = [urllib.error.HTTPError("https://x", 401, "no", {}, __import__("io").BytesIO(b'{"error": "Invalid API key"}'))]
        ok("refused with Shadowserver's own reason: that reason", PS._api("test/ping", "k", "s")[1] == "Invalid API key")
        answers[:] = [urllib.error.HTTPError("https://x", 500, "no", {}, __import__("io").BytesIO(b"<html>"))]
        ok("refused without a readable reason: the HTTP code", PS._api("test/ping", "k", "s")[1] == "Shadowserver refused it (HTTP 500)")
        answers[:] = [urllib.error.URLError("unreachable")]
        ok("unreachable: said so, by the kind of error only", PS._api("test/ping", "k", "s")[1] == "Shadowserver could not be reached from this server (URLError)")
        answers[:] = [b'{"pong": false}']
        ok("ping with an unexpected answer: not accepted", PS.ping("k", "s") == (False, "unexpected answer to test/ping"))
        answers[:] = [b'{"pong": "2026"}', urllib.error.URLError("x")]
        okp, msg = PS.ping("k", "s")
        ok("the key works but cannot list reports: not accepted, why", not okp and msg.startswith("the key works, but may not list reports"))
        answers[:] = [b'{"pong": "2026"}', b'["GH", "KE"]']
        ok("accepted, with the report lists", PS.ping("k", "s") == (True, "Shadowserver accepted the key; reports for GH, KE"))
        answers[:] = [b'{"pong": "2026"}', b'{}']
        ok("accepted, no report list", PS.ping("k", "s")[1].endswith("no report list is subscribed to it"))

        print("Settings → Workers: no pipeline beside the platform")
        os.environ.pop("PIPELINE_DIR", None)
        app = new_app(); PS.install(app, CTX); c = app.test_client()
        ME.update(user="cov-admin", perms={"settings"})
        ok("the settings: not on this computer", c.get("/api/pipeline/settings").json == {"found": False, "message": PS.NOT_HERE})
        ok("the held-back reports: none; the 7-day view: not found", c.get("/api/pipeline/held").json == {"held": []}
           and c.get("/api/pipeline/sender-week").json == {"found": False})
        ok("checking a saved key with no pipeline: 404", c.post("/api/pipeline/apikey/check", json={}).status_code == 404)
        FLAGS["fresh"] = False
        ok("a change after an old sign-in: 403, sign in again", c.post("/api/pipeline/lock", json={}).json.get("reauth") is True)
        FLAGS["fresh"] = True
        ok("saving while locked: 403, locked", c.post("/api/pipeline/settings", json={"values": {}}).json.get("locked") is True)
        r = c.post("/api/pipeline/unlock", json={"password": PW})
        ok("unlocking with the admin's own password", r.status_code == 200 and r.json["unlocked_for"] == PS.UNLOCK_SECONDS)
        ok("…saving with no pipeline: 404", c.post("/api/pipeline/settings", json={"values": {}}).status_code == 404)
        ok("…a new API key with no pipeline: 404", c.post("/api/pipeline/apikey", json={"key": "k", "secret": "s"}).status_code == 404)

        print("Settings → Workers: a made-up older pipeline")
        pdir = Path(tmp) / "pipe"
        (pdir / "quarantine").mkdir(parents=True)
        (pdir / "shadowserver_pipeline.py").write_text("# made-up pipeline for the check\n")
        (pdir / ".env").write_text("MAIL_PROVIDER=imap\nSHADOWSERVER_API_KEY=made-up-key\nSHADOWSERVER_API_SECRET=made-up-secret\nREPORT_SOURCE=mail\n")
        (pdir / "worker_settings.py").write_text('''
GROUPS = [("mail", "Mail")]
FIELDS = [("REPORT_SOURCE", "mail", "Reports from", "choice", "mail", ("mail", "api"), None, "help", None),
          ("MAX_FILES", "mail", "Files", "int", "10", 1, 100, "help", None),
          ("GRAPH_ONLY", "mail", "Graph", "text", "", None, None, "help", "graph")]
SPEC = {f[0]: f for f in FIELDS}
CHOICE_LABELS = {"REPORT_SOURCE": {"mail": "E-mail"}}
MADE = []
def results(d, limit=8):
    return [{"id": "r1", "status": "applied", "kind": "settings", "changed": ["MAX_FILES 10 -> 20"], "by": "cov-admin",
             "confirmed_on_server": "op"}, {"id": "r2", "status": "refused", "kind": "release", "reason": "gone"}, {"status": "x"}]
def pending(d):                      # an older pipeline: no confirmation step (one argument only)
    return [{"kind": "release", "qid": "a" * 20, "qids": ["b" * 20]}]
def validate(values, provider):
    if not isinstance(values, dict):
        return {}, ["values: an object"]
    return {k: str(v) for k, v in values.items()}, []
def make_request(d, kind, payload, by):
    MADE.append((kind, payload))
    return "req%d" % len(MADE)
def valid_api(k, s):
    return bool(k and s)
''')
        q1, q2 = "1" * 20, "2" * 20
        (pdir / "mail_auth.py").write_text(f'''
from pathlib import Path
RELEASE_FILE = "release.request"
def held(d):
    out = []
    for q in ("{q1}", "{q2}"):
        p = Path(d) / "quarantine" / q
        p.mkdir(parents=True, exist_ok=True)
        out.append((p, {{"at": 1, "result": "fail", "reason": "no DKIM", "files": ["2026-11-20-scan_ssh-example-geo.csv"], "subject": "Made-up"}}))
    return out
def mode(env):
    return "watch"
''')
        os.environ["PIPELINE_DIR"] = str(pdir)
        app = new_app(); CTX["labels"] = lambda: (_ for _ in ()).throw(RuntimeError("report database down"))
        PS.install(app, CTX); c = app.test_client()
        r = c.get("/api/pipeline/settings")
        j = r.json or {}
        ok("the settings of an older pipeline (no confirmation step): its fields for the mail provider only, the key set",
           r.status_code == 200 and j.get("found") and [f["key"] for f in j["fields"]] == ["REPORT_SOURCE", "MAX_FILES"]
           and j["api"]["key_set"] and j["fields"][0]["choices"][0]["label"] == "E-mail", str(j)[:300])
        ok("…the pipeline's results written to the audit log once each", sum(1 for e, *_ in logged if e.startswith("pipeline_request_")) == 2)
        c.get("/api/pipeline/settings")
        ok("…and not again on the next look", sum(1 for e, *_ in logged if e.startswith("pipeline_request_")) == 2)
        r = c.get("/api/pipeline/held")
        j = r.json or {}
        ok("held-back reports with the report database down: listed by file name, release asked from the pending list",
           r.status_code == 200 and len(j["held"]) == 2 and j["mode"] == "watch" and all(x["release_asked"] is False for x in j["held"])
           and j["held"][0]["names"], str(j)[:300])
        ok("no 7-day view in this pipeline: not found", c.get("/api/pipeline/sender-week").json == {"found": False})
        c.post("/api/pipeline/unlock", json={"password": PW})
        r = c.post("/api/pipeline/settings", json={"values": {"REPORT_SOURCE": "mail"}})
        ok("saving what is already set: nothing changed, locked again", r.json.get("changed") == [] and "Locked again" in r.json.get("note", ""))
        ok("…locked: the next save is refused", c.post("/api/pipeline/settings", json={"values": {}}).json.get("locked") is True)
        c.post("/api/pipeline/unlock", json={"password": PW})
        ok("values the pipeline's rules refuse: 400 with why", c.post("/api/pipeline/settings", json={"values": "x"}).status_code == 400)
        r = c.post("/api/pipeline/settings", json={"values": {"MAX_FILES": "20"}})
        ok("a change: one request, applied at the next run (no confirmation step in this pipeline)",
           r.status_code == 200 and r.json["changed"] == ["MAX_FILES"] and r.json["confirm"] is False)
        answers[:] = [b'{"pong": false}']
        r = c.post("/api/pipeline/apikey/check", json={})
        ok("checking the saved key: refused by Shadowserver, the state saved", r.status_code == 200 and r.json["ok"] is False
           and json.load(open(os.path.join(tmp, "data", "pipeline_api.json")))["ok"] is False)
        c.post("/api/pipeline/unlock", json={"password": PW})
        ok("a new key left empty: 400", c.post("/api/pipeline/apikey", json={"key": "", "secret": ""}).status_code == 400)
        answers[:] = [urllib.error.URLError("x")]
        r = c.post("/api/pipeline/apikey", json={"key": "made-up-key-2", "secret": "made-up-secret-2"})
        ok("a new key Shadowserver cannot check: not saved (400)", r.status_code == 400 and r.json["error"].startswith("Not saved"))
        ok("a release of a report not held back: 404", c.post("/api/pipeline/release", json={"id": "f" * 20}).status_code == 404)
        ok("several, one no longer held: 404, reload", "reload" in c.post("/api/pipeline/release", json={"ids": [q1, "f" * 20]}).json["error"])
        r = c.post("/api/pipeline/release", json={"ids": [q1, q2, q1]})
        ok("two held reports (one chosen twice): one request each in an older pipeline, both written down",
           r.status_code == 200 and r.json["count"] == 2 and len(r.json["requests"]) == 2
           and sum(1 for e, *_ in logged if e == "sender_release") == 2)
        ok("lock: 200", c.post("/api/pipeline/lock", json={}).status_code == 200)
    finally:
        https_only.open = real_open
finally:
    if saved_env is None:
        os.environ.pop("PIPELINE_DIR", None)
    else:
        os.environ["PIPELINE_DIR"] = saved_env
    shutil.rmtree(tmp, ignore_errors=True)
print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
