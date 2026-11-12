#!/usr/bin/env python3
"""Settings → Workers (pipeline_settings.py) and Audit portal → Sender check (sender_audit.py), in-process, against a
throwaway pipeline folder (its own .env, mail_auth.py, mail state and quarantine): the real pipeline, its .env, the
audit log and Shadowserver are never touched (the audit log and the API call are replaced for the check).
- locked by default; the admin's own password unlocks (a wrong one is refused, counted and logged); saving locks again
- only the listed settings change, each validated; passwords can be neither read nor written; every other line of the
  .env stays exactly as it was; each change is logged old → new
- the Shadowserver API key is saved only when Shadowserver accepts it, is never sent back, and the request is signed
  as Shadowserver's API requires
- held-back reports are listed, and released only when unlocked
- the Sender check page: figures, per day, keys, standards, reports that did not pass; auditors read it, others not
Run: .venv/bin/python tests/check_pipeline_settings.py"""
import hashlib, hmac, json, os, shutil, sys, tempfile
from pathlib import Path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("LG_QUIET", "1")
os.environ.setdefault("THREATMAP_SCHEDULE", "0")
os.environ["TRUST_PROXY"] = "0"
tmp = Path(tempfile.mkdtemp(prefix="lg-workers-"))
PIPE = tmp / "database"
PIPE.mkdir()
os.environ["PIPELINE_DIR"] = str(PIPE)
import app as A  # noqa: E402
import auth  # noqa: E402
import pipeline_settings as PS  # noqa: E402
from werkzeug.security import generate_password_hash  # noqa: E402

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond: fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info else ""), flush=True)


# the throwaway pipeline: its .env (with passwords that must never come out), mail_auth.py, a held-back report, results
real_pipe = next(p for p in (Path(A.BASE_DIR).parent / "database", Path(A.BASE_DIR).parent / "shadowserver") if (p / "mail_auth.py").exists())
shutil.copy(real_pipe / "mail_auth.py", PIPE / "mail_auth.py")
shutil.copy(real_pipe / "worker_settings.py", PIPE / "worker_settings.py")
PLAT = tmp / "platform-data"                        # the platform's data folder for this check (requests go here)
PLAT.mkdir()
(PIPE / "shadowserver_pipeline.py").write_text("# stand-in\n")
ENV0 = ("# Shadowserver pipeline\nMAIL_PROVIDER=imap\nIMAP_SERVER=mail.example.org\nIMAP_USER=csirt@example.org\n"
        "IMAP_PASSWORD=Very-Secret-Mailbox-9\nIMAP_FOLDER=inbox\nIMAP_VERIFY_TLS=false\nEMAIL_DAYS=7\n"
        "MONGO_PASSWORD=Very-Secret-Mongo-7\nWORKERS=6\n# a comment that must stay\n")
(PIPE / ".env").write_text(ENV0)
os.chmod(PIPE / ".env", 0o600)
sys.path.insert(0, str(PIPE))
import mail_auth as MA  # noqa: E402
import worker_settings as WS  # noqa: E402
import logging  # noqa: E402
A.PIPELINE_SETTINGS["ctx"]["data_dir"] = str(PLAT)


def apply_now():
    """What the pipeline does at the start of its next run (shadowserver_pipeline.main)."""
    return WS.apply_requests(PLAT, PIPE / ".env", PIPE, logging.getLogger("lg-check-workers"))
log = MA.Log(PIPE / ".mail_state.sqlite")
base = {"from_domain": "shadowserver.org", "signer": "shadowserver.org", "selector": "mail", "alg": "rsa-sha256", "bits": 1024, "reason": ""}
for i in range(20):
    log.add(f"k{i}", dict(base, result="pass"), f"Report {i}", [f"r{i}.zip"])
log.add("kf", dict(base, result="fail", reason="the body was changed after it was signed (body hash differs)", alg="", bits=0), "Forged", ["f.zip"], "quarantined")
log.add("kn", dict(base, result="none", signer="", reason="no DKIM signature", alg="", bits=0), "Unsigned", ["n.zip"], "kept")
log.db.execute("CREATE TABLE IF NOT EXISTS report_types (name TEXT PRIMARY KEY, first_seen TEXT, baseline INTEGER)")
log.db.executemany("INSERT INTO report_types VALUES (?, ?, ?)", [("scan_http", "2026-11-01T06:00:00+00:00", 1),
                   ("scan_ssh", "2026-11-01T06:00:00+00:00", 1), ("scan_known_new", "2026-11-10T08:00:00+00:00", 0),
                   ("scan_brandnew", "2026-11-12T09:00:00+00:00", 0)])
log.db.commit()
log.close()
qdir = MA.quarantine_dir(PIPE, "kf")
MA.write_meta(qdir, "kf", dict(base, result="fail", reason="body changed"), "Forged report", ["f.zip"], set())
(qdir / "f.zip").write_bytes(b"PK")

users, sessions, roles = A.AUTH["users"], A.AUTH["sessions"], A.AUTH["roles"]
real_get, real_perms = users.get, roles.perms
ADMIN, AUDITOR, ANALYST, UA = "chk-workers-admin", "chk-workers-auditor", "chk-workers-analyst", "lg-check-workers"
PW = "the right pass phrase 42"
FAKE = {ADMIN: {"status": "active", "role": "lg-adm", "changed": 0, "hash": generate_password_hash(PW)},
        AUDITOR: {"status": "active", "role": auth.AUDITOR_ROLE, "changed": 0}, ANALYST: {"status": "active", "role": "lg-ana", "changed": 0}}
users.get = lambda name: FAKE.get(name) or real_get(name)
roles.perms = lambda role: ({"view", "settings", "audit", "users"} if role == "lg-adm" else {"audit"} if role == auth.AUDITOR_ROLE
                            else {"view", "unmasked"} if role == "lg-ana" else real_perms(role))
audit = A.AUTH["audit"]; real_add = audit.add; logged = []
audit.add = lambda ev, **k: logged.append((ev, k.get("detail", ""), k.get("target", "")))
real_ping = PS.ping
real_entry = A.REPORT_MAP.entry          # the report map: one new type it knows, one it does not
A.REPORT_MAP.entry = lambda n: {"title": "A Known New Report", "in_schema": True} if n in ("scan_known_new", "scan_http", "scan_ssh") else None
MADE = []


def client(user):
    token = sessions.create(user, "127.0.0.1", UA); MADE.append(token)
    csrf = next(s["csrf"] for s in sessions.s.values() if s["user"] == user and s.get("csrf"))
    c = A.app.test_client(); c.set_cookie("lg_session", token)
    return c, {"User-Agent": UA, "X-CSRF-Token": csrf}


try:
    c, H = client(ADMIN)
    print("Locked by default; nothing secret comes out")
    r = c.get("/api/pipeline/settings", headers=H); d = r.json or {}
    ok("the Workers settings open for an administrator, locked", r.status_code == 200 and d.get("found") and d.get("unlocked") is False, str(r.status_code))
    body = r.get_data(as_text=True)
    ok("no password, server or mailbox login is in the answer", not any(s in body for s in ("Very-Secret", "IMAP_PASSWORD", "MONGO_PASSWORD", "mail.example.org", "csirt@example.org")))
    vals = {f["key"]: f["value"] for f in d.get("fields", [])}
    ok("current values come from the pipeline's .env (unset ones show the pipeline's default)",
       vals.get("EMAIL_DAYS") == "7" and vals.get("IMAP_VERIFY_TLS") == "false" and vals.get("MAIL_AUTH") == "log", str(vals)[:160])
    r = c.post("/api/pipeline/settings", json={"values": {"EMAIL_DAYS": "3"}}, headers=H)
    ok("saving while locked is refused", r.status_code == 403 and (r.json or {}).get("locked"), str(r.status_code))
    r = c.post("/api/pipeline/settings", json={"values": {"EMAIL_DAYS": "3"}}, headers={"User-Agent": UA})
    ok("…and without the page's CSRF token too", r.status_code == 403)

    print("Unlock with the administrator's own password")
    A.AUTH["throttle"].clear_address("127.0.0.1")
    r = c.post("/api/pipeline/unlock", json={"password": "wrong"}, headers=H)
    ok("a wrong password is refused and logged", r.status_code == 403 and any(e == "pipeline_unlock_failed" for e, *_ in logged), str(r.status_code))
    ok("…and counted like a failed sign-in", A.AUTH["throttle"].left("127.0.0.1", ADMIN) < 5)
    r = c.post("/api/pipeline/unlock", json={"password": PW}, headers=H)
    ok("the right password unlocks it for 10 minutes, logged", r.status_code == 200 and r.json.get("unlocked_for") == 600
       and any(e == "pipeline_unlock" for e, *_ in logged), str(r.status_code))
    other, H2 = client(ADMIN)
    ok("…for this session only (another session of the same person stays locked)",
       other.get("/api/pipeline/settings", headers=H2).json.get("unlocked") is False)

    print("Saving: a request in the platform's own data folder, the pipeline's .env untouched until the pipeline applies it")
    for bad, why in (({"IMAP_PASSWORD": "x"}, "a password"), ({"MONGO_PASSWORD": "x"}, "the database password"),
                     ({"WORKERS": "0"}, "below the minimum"), ({"WORKERS": "6\nIMAP_PASSWORD=x"}, "a second line"),
                     ({"MAIL_AUTH_DOMAIN": "not a domain"}, "a bad domain"), ({"MAIL_AUTH": "maybe"}, "an unknown mode"),
                     ({"GMAIL_LABEL": "x"}, "another provider's setting")):
        r = c.post("/api/pipeline/settings", json={"values": bad}, headers=H)
        ok(f"refused: {why}", r.status_code == 400, str(r.status_code))
    ok("…no request was made by any refused save", not WS.pending(PLAT))
    r = c.post("/api/pipeline/settings", json={"values": {"EMAIL_DAYS": "3", "MAIL_AUTH": "enforce", "IMAP_VERIFY_TLS": "true",
                                                           "WORKERS": "6", "ZIP_MAX_RATIO": "500"}}, headers=H)
    ok("a valid save requests exactly what changed", r.status_code == 200 and sorted(r.json["changed"]) == ["EMAIL_DAYS", "IMAP_VERIFY_TLS", "MAIL_AUTH", "ZIP_MAX_RATIO"]
       and "next run" in r.json.get("note", ""), str(r.json))
    reqs = list((PLAT / "pipeline_requests").glob("*.json"))
    ok("…written only into the platform's data folder (mode 600), the pipeline's .env not touched by the platform",
       len(reqs) == 1 and oct(os.stat(reqs[0]).st_mode & 0o777) == "0o600" and (PIPE / ".env").read_text() == ENV0, str(reqs))
    det = next((d_ for e, d_, _ in logged if e == "pipeline_change_requested"), "")
    ok("…logged old → new, without any password", "EMAIL_DAYS: 7 → 3" in det and "MAIL_AUTH: log → enforce" in det and "Secret" not in det, det[:160])
    g_ = c.get("/api/pipeline/settings", headers=H).json
    ok("…locked again, and the page shows it waiting for the pipeline's next run", g_.get("unlocked") is False and len(g_.get("pending") or []) == 1)
    n = apply_now()
    env = (PIPE / ".env").read_text()
    ok("the pipeline's next run checks the request again and applies it to its own .env", n == 1 and "EMAIL_DAYS=3" in env and "MAIL_AUTH=enforce" in env
       and "IMAP_VERIFY_TLS=true" in env and "ZIP_MAX_RATIO=500" in env, env[-200:])
    ok("…passwords and comments exactly as before, mode 600; the request is gone",
       "IMAP_PASSWORD=Very-Secret-Mailbox-9" in env and "MONGO_PASSWORD=Very-Secret-Mongo-7" in env and "# a comment that must stay" in env
       and oct(os.stat(PIPE / ".env").st_mode & 0o777) == "0o600" and not WS.pending(PLAT))
    g_ = c.get("/api/pipeline/settings", headers=H).json
    ok("…the page shows it applied, and the result goes into the audit log", (g_.get("results") or [{}])[0].get("status") == "applied"
       and any(e == "pipeline_request_applied" and "EMAIL_DAYS: 7 → 3" in d_ for e, d_, _ in logged))
    c.get("/api/pipeline/settings", headers=H)
    ok("…once (looking again does not log it again)", sum(1 for e, *_ in logged if e == "pipeline_request_applied") == 1)

    print("A request file is never trusted as it is: the pipeline checks it again")
    WS.make_request(PLAT, "settings", {"values": {"IMAP_PASSWORD": "stolen", "IMAP_SERVER": "evil.example"}}, "someone")
    WS.make_request(PLAT, "settings", {"values": {"WORKERS": "4\nIMAP_PASSWORD=stolen"}}, "someone")
    (PLAT / "pipeline_requests" / "made-up.json").write_text(json.dumps({"id": "made-up", "kind": "settings", "values": {"WORKERS": "2"}}))
    WS.make_request(PLAT, "release", {"qid": "../../etc/passwd"}, "someone")
    before = (PIPE / ".env").read_text()
    n = apply_now()
    res = WS.results(PLAT, limit=10)
    ok("a password, a second line, a forged request file and a made-up release are all refused; the .env is unchanged",
       n == 0 and (PIPE / ".env").read_text() == before and sum(1 for r_ in res if r_.get("status") == "refused") == 4, str([r_.get("reason") for r_ in res][:4]))
    c.get("/api/pipeline/settings", headers=H)
    ok("…each refusal goes into the audit log (as an alert)", sum(1 for e, *_ in logged if e == "pipeline_request_refused") == 4)

    print("Shadowserver API key")
    sent = {}

    class Resp:
        def __init__(self, body): self.b = body
        def read(self, n=-1): return self.b
        def __enter__(self): return self
        def __exit__(self, *a): return False

    seen = []

    def fake_urlopen(req, timeout=None):
        seen.append((req.full_url, req.data, req.get_header("Hmac2")))
        ans = {"pong": "2026-11-12 10:00:00"} if req.full_url.endswith("/test/ping") else ["example"]
        return Resp(json.dumps(ans).encode())
    PS.urllib.request.urlopen = fake_urlopen
    okp, m = PS.ping("KEY12345678", "SECRET-abc-123")
    sign = lambda b: hmac.new(b"SECRET-abc-123", b, hashlib.sha256).hexdigest()
    ok("the check is test/ping then reports/subscribed on Shadowserver's API, the key in the JSON body, each body signed with the secret (HMAC2)",
       okp and [u for u, _, _ in seen] == ["https://transform.shadowserver.org/api2/test/ping", "https://transform.shadowserver.org/api2/reports/subscribed"]
       and all(json.loads(b) == {"apikey": "KEY12345678"} and s == sign(b) for _, b, s in seen), str(seen)[:200])
    ok("…and says which reports the key would fetch", "example" in m, m)
    r = c.post("/api/pipeline/apikey", json={"key": "KEY12345678", "secret": "SECRET-abc-123"}, headers=H)
    ok("entering a key while locked is refused", r.status_code == 403)
    c.post("/api/pipeline/unlock", json={"password": PW}, headers=H)
    PS.ping = lambda k, s, url=None, timeout=15: (False, "Invalid API key")
    r = c.post("/api/pipeline/apikey", json={"key": "KEY12345678", "secret": "SECRET-abc-123"}, headers=H)
    ok("a key Shadowserver refuses is not requested", r.status_code == 400 and not WS.pending(PLAT), str(r.json))
    PS.ping = lambda k, s, url=None, timeout=15: (True, "Shadowserver accepted the key and secret")
    r = c.post("/api/pipeline/apikey", json={"key": "KEY12345678", "secret": "SECRET-abc-123"}, headers=H)
    g_ = c.get("/api/pipeline/settings", headers=H)
    ok("a key Shadowserver accepts waits for the pipeline, and the page never shows it", r.status_code == 200 and g_.json["api"]["key_waiting"]
       and "KEY12345678" not in g_.get_data(as_text=True) and "SECRET-abc" not in g_.get_data(as_text=True), str(r.status_code))
    apply_now()
    env = (PIPE / ".env").read_text()
    ok("the pipeline saves it in its own .env; the request (the only copy outside it) is deleted",
       "SHADOWSERVER_API_KEY=KEY12345678" in env and "SHADOWSERVER_API_SECRET=SECRET-abc-123" in env and not WS.pending(PLAT))
    g_ = c.get("/api/pipeline/settings", headers=H)
    every_file = "".join(p.read_text() for p in PLAT.rglob("*.json"))
    ok("…afterwards the page only says it is set; no result or log holds the key or secret", g_.json["api"]["key_set"]
       and "KEY12345678" not in g_.get_data(as_text=True) and "SECRET-abc" not in every_file and "KEY12345678" not in every_file)
    ok("…and the audit log never holds them", not any("KEY12345678" in d_ or "SECRET-abc" in d_ for _, d_, _ in logged))

    print("How the reports are fetched: e-mail or the API")
    src = next(f for f in c.get("/api/pipeline/settings", headers=H).json["fields"] if f["key"] == "REPORT_SOURCE")
    ok("the choice is offered with readable labels, e-mail by default", src["value"] == "email"
       and [x["label"] for x in src["choices"]] == ["By e-mail (the mailbox)", "Shadowserver report API"], str(src["choices"]))
    c.post("/api/pipeline/unlock", json={"password": PW}, headers=H)
    r = c.post("/api/pipeline/settings", json={"values": {"REPORT_SOURCE": "api"}}, headers=H)
    apply_now()
    ok("the API can be chosen once a key is saved", r.status_code == 200 and "REPORT_SOURCE=api" in (PIPE / ".env").read_text(), str(r.json))
    keep_env = (PIPE / ".env").read_text()
    (PIPE / ".env").write_text("\n".join(l for l in keep_env.splitlines() if not l.startswith("SHADOWSERVER_API")) + "\n")
    c.post("/api/pipeline/unlock", json={"password": PW}, headers=H)
    r = c.post("/api/pipeline/settings", json={"values": {"REPORT_SOURCE": "api", "EMAIL_DAYS": "4"}}, headers=H)
    ok("…but not without a saved key (nothing requested)", r.status_code == 400 and "API key" in r.json.get("error", "") and not WS.pending(PLAT), str(r.json))
    WS.make_request(PLAT, "settings", {"values": {"REPORT_SOURCE": "api"}}, "someone")
    apply_now()
    last = WS.results(PLAT, 1)[0]
    ok("…and the pipeline itself refuses the API without a key, too", last["status"] == "refused" and "no API key" in last["reason"], str(last))
    (PIPE / ".env").write_text(keep_env)
    c.post("/api/pipeline/lock", json={}, headers=H)            # a refused save leaves it unlocked: lock it now

    print("Held-back reports")
    h = c.get("/api/pipeline/held", headers=H).json
    ok("listed for administrators, with result and reason", len(h["held"]) == 1 and h["held"][0]["result"] == "fail" and h["mode"] == "enforce", str(h)[:160])
    qid = h["held"][0]["id"]
    r = c.post("/api/pipeline/release", json={"id": qid}, headers=H)
    ok("releasing while locked is refused", r.status_code == 403 and not WS.pending(PLAT))
    c.post("/api/pipeline/unlock", json={"password": PW}, headers=H)
    r = c.post("/api/pipeline/release", json={"id": "../../etc"}, headers=H)
    ok("a made-up id is refused", r.status_code == 404)
    r = c.post("/api/pipeline/release", json={"id": qid}, headers=H)
    ok("unlocked, the release is requested (nothing written in the pipeline's folder by the platform), logged",
       r.status_code == 200 and not (qdir / MA.RELEASE_FILE).exists() and any(e == "sender_release" for e, *_ in logged)
       and c.get("/api/pipeline/held", headers=H).json["held"][0]["release_asked"], str(r.status_code))
    apply_now()
    ok("…the pipeline's next run marks it released (its fetch step then lets it through)", (qdir / MA.RELEASE_FILE).exists())

    print("Audit portal → Sender check")
    a, HA = client(AUDITOR)
    r = a.get("/api/audit/sender", headers=HA); d = r.json or {}
    ok("the auditor reads it", r.status_code == 200 and d.get("found"), str(r.status_code))
    k = d.get("kpis", {})
    ok("figures: checked, passed, failed, unsigned, held back", k.get("checked") == 22 and k.get("pass") == 20 and k.get("fail") == 1
       and k.get("none") == 1 and k.get("held_back") == 1 and d.get("mode") == "enforce", str(k))
    ok("results per day cover the period", len(d.get("per_day", [])) == 30 and sum(x["pass"] for x in d["per_day"]) == 20)
    ok("the signing keys seen, with algorithm and key size", d.get("keys") == [{"signer": "shadowserver.org", "selector": "mail", "alg": "rsa-sha256", "bits": 1024, "reports": 20}], str(d.get("keys")))
    refs = [s["ref"] for s in d.get("standards", [])]
    ok("the standards next to the evidence (RFC 6376, 8301, 8463, 7489, NIST SP 800-177, SP 800-53 SI-7)",
       all(any(x in r_ for r_ in refs) for x in ("RFC 6376", "RFC 8301", "RFC 8463", "RFC 7489", "800-177", "SI-7")), str(refs))
    ok("…evidence only, no verdict words", not any(w in json.dumps(d["standards"]).lower() for w in ("compliant", "non-compliant", "passed the control", "verdict")))
    ok("…the key size evidence says what was seen", any("1024 bits (20)" in s["shows"] for s in d["standards"]))
    ok("reports that did not pass are listed with what happened", {x["result"]: x["action_label"] for x in d.get("odd", [])} == {"fail": "held back", "none": "processed"}, str(d.get("odd"))[:200])
    ty = d.get("types") or {}
    ok("new report types: the starting point counted, the two that arrived later listed, newest first",
       ty.get("recorded") == 4 and ty.get("since") == "2026-11-01" and [x["name"] for x in ty.get("new", [])] == ["scan_brandnew", "scan_known_new"], str(ty)[:220])
    ok("…each says whether the report definitions know it yet", {x["name"]: x["known"] for x in ty.get("new", [])} == {"scan_brandnew": False, "scan_known_new": True}
       and ty.get("new_without_definition") == 1 and next(x for x in ty["new"] if x["name"] == "scan_brandnew")["note"] == "new report, no definition yet")
    n_, HN = client(ANALYST)
    ok("an account without the audit permission cannot read it", n_.get("/api/audit/sender", headers=HN).status_code == 403)
    ok("…nor open the Workers settings", n_.get("/api/pipeline/settings", headers=HN).status_code == 403)
    ok("the auditor cannot open the Workers settings either", a.get("/api/pipeline/settings", headers=HA).status_code == 403)
finally:
    users.get, roles.perms = real_get, real_perms
    audit.add = real_add
    PS.ping = real_ping
    A.REPORT_MAP.entry = real_entry
    A.PIPELINE_SETTINGS["ctx"]["data_dir"] = os.path.join(A.BASE_DIR, "data")
    for t in MADE:
        sessions.end(token=t)
    A.AUTH["throttle"].clear_address("127.0.0.1")
    shutil.rmtree(tmp, ignore_errors=True)

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
