#!/usr/bin/env python3
"""The reports from Shadowserver's report API (report_api.py) and the choice between API and e-mail
(shadowserver_pipeline.fetch_reports), against a fake Shadowserver (nothing leaves the computer):
- every call is signed as Shadowserver documents it (POST, JSON body with apikey, HMAC2 over the exact body)
- reports/list for the last N days; each new CSV downloaded once, under its own name, into attachments_backup/
  (where e-mail attachments go), recorded with its size and SHA-256; never downloaded twice
- unusable names or ids, empty or non-CSV files, files over the size limit and failed downloads are refused or retried
- the choice: REPORT_SOURCE=api uses the API; when the API cannot be used and a mailbox is set up, that run reads the
  mailbox (and the other way round); with nothing to fall back to, the run carries on with what is on disk
Run: .venv/bin/python tests/test_report_api.py"""
import hashlib, hmac, json, logging, os, sys, tempfile
from collections import Counter
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import report_api as RA  # noqa: E402
import shadowserver_pipeline as sp  # noqa: E402

fails, checks = [], 0
log = logging.getLogger("t"); log.addHandler(logging.NullHandler())


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info else ""), flush=True)


KEY, SECRET = "testkey-0123456789", "test-secret-abcdef"
CSV = b'"timestamp","ip","port"\n"2026-11-11 01:00:00","192.0.2.10",443\n'
FILES = {"id-good-0001": CSV, "id-good-0002": CSV.replace(b"443", b"80"), "id-empty-0003": b"", "id-bin-00004": b"\x00\x01PK",
         "id-huge-00005": b'"a","b"\n' + b"x" * (2 * 2**20)}
LIST = [{"id": "id-good-0001", "file": "2026-11-11-scan_http-example-geo.csv", "report": "example", "timestamp": "2026-11-11", "type": "scan_http"},
        {"id": "id-good-0002", "file": "2026-11-11-scan_ssh-example-geo.csv", "report": "example", "timestamp": "2026-11-11", "type": "scan_ssh"},
        {"id": "id-empty-0003", "file": "2026-11-11-scan_ftp-example-geo.csv"},
        {"id": "id-bin-00004", "file": "2026-11-11-scan_rdp-example-geo.csv"},
        {"id": "id-huge-00005", "file": "2026-11-11-scan_vnc-example-geo.csv"},
        {"id": "id-gone-00006", "file": "2026-11-11-scan_smb-example-geo.csv"},
        {"id": "id-evil-00007", "file": "../../etc/passwd.csv"},
        {"id": "x/../y z", "file": "2026-11-11-scan_dns-example-geo.csv"}]
calls, mode = [], {"down": False, "refuse": False}


class R:
    def __init__(self, code, body=b"", js=None):
        self.status_code, self.body, self.js = code, body, js
    def json(self):
        if self.js is None:
            raise ValueError
        return self.js
    def iter_content(self, n):
        for i in range(0, len(self.body), n):
            yield self.body[i:i + n]
    def __enter__(self): return self
    def __exit__(self, *a): return False


import requests  # noqa: E402


def post(url, data=None, headers=None, timeout=None):
    calls.append((url, data, headers.get("HMAC2")))
    if mode["down"]:
        raise requests.ConnectionError("down")
    if mode["refuse"] or headers.get("HMAC2") != hmac.new(SECRET.encode(), data, hashlib.sha256).hexdigest():
        return R(401, js={"error": "authentication failed"})
    method = url.split("/api2/", 1)[1]
    if method == "test/ping":
        return R(200, js={"pong": "2026-11-12 10:00:00"})
    if method == "reports/subscribed":
        return R(200, js=["example"])
    if method == "reports/list":
        return R(200, js=LIST)
    return R(404, js={"error": "no such method"})


def get(url, stream=True, timeout=None, headers=None):
    i = url[len(RA.DL_URL):]
    return R(200, FILES[i]) if i in FILES else R(404)


requests.post, requests.get = post, get
ENV = {"REPORT_SOURCE": "api", "SHADOWSERVER_API_KEY": KEY, "SHADOWSERVER_API_SECRET": SECRET}

print("Signed calls")
okc, msg = RA.check(KEY, SECRET)
url, body, sig = calls[0]
ok("test/ping and reports/subscribed, POST to transform.shadowserver.org/api2/, apikey in the JSON body, HMAC2 over the exact body",
   okc and url == "https://transform.shadowserver.org/api2/test/ping" and json.loads(body) == {"apikey": KEY}
   and sig == hmac.new(SECRET.encode(), body, hashlib.sha256).hexdigest() and "example" in msg, msg)
okc, msg = RA.check(KEY, "wrong-secret")
ok("a wrong secret is refused, and the message never holds the key or secret", not okc and KEY not in msg and "secret" not in msg.lower(), msg)

print("Downloading the reports")
with tempfile.TemporaryDirectory() as d:
    base = Path(d); att = base / "attachments_backup"
    st = Counter(); calls.clear()
    n = RA.pull(base, att, 3, 4, st, log, ENV, max_mb=1)
    listed = json.loads(calls[0][1])
    ok("reports/list asks for the last N days, as a date range ending today (UTC)", calls[0][0].endswith("/reports/list")
       and ":" in listed["date"] and len(listed["date"]) == 21, listed["date"])
    got = sorted(p.name for p in att.iterdir())
    ok("the two good reports are downloaded under their own names, where e-mail attachments go", got == ["2026-11-11-scan_http-example-geo.csv", "2026-11-11-scan_ssh-example-geo.csv"]
       and (att / got[0]).read_bytes() == CSV and n == 2, str(got))
    ok("an unsafe name and an unusable id are skipped, never fetched", not any("passwd" in c[0] or " " in c[0] for c in calls) and not (base.parent / "etc").exists())
    ok("empty, non-CSV, too large and missing files are refused (tried again next run)", st["api_failed"] == 4, str(dict(st)))
    ok("no half-written .part file is left behind", not any(p.name.endswith(".part") for p in att.iterdir()))
    f = RA.Files(base / ".mail_state.sqlite")
    rows = {r[0]: (r[5], r[6]) for r in f.db.execute("SELECT * FROM api_files")}; f.close()
    ok("each download recorded with its size and SHA-256", rows.get("2026-11-11-scan_http-example-geo.csv") == (len(CSV), hashlib.sha256(CSV).hexdigest()))
    for p in att.iterdir():                      # the sorting step moves them on; the record remains
        p.unlink()
    st2 = Counter()
    RA.pull(base, att, 3, 4, st2, log, ENV, max_mb=1)
    ok("the next run does not download them again", st2["api_known"] == 2 and st2["api_downloaded"] == 0 and not list(att.iterdir()), str(dict(st2)))
    RA.pull(base, att, 3, 4, Counter(), log, ENV, refetch=True, max_mb=1)
    ok("--all downloads them again", len(list(att.iterdir())) == 2)
    try:
        RA.pull(base, att, 3, 4, Counter(), log, {}, max_mb=1)
        ok("no key: the API is not used", False)
    except RA.ApiError as e:
        ok("no key: the API is not used (the run is told why)", "no Shadowserver API key" in str(e))

print("API or e-mail, and falling back")
used = []
sp.pull_emails = lambda s, stats, refetch=False: used.append("email")
real_pull = RA.pull


def settings(base):
    return sp.Settings(env_file=base / ".env", imap_server="", imap_user="", imap_password="", imap_folder="inbox",
                       imap_verify_tls=True, mongo={}, mongo_db="t", mongo_cache_gb=1.0, base_dir=base, workers=1,
                       insert_chunk=100, download_threads=2, fetch_batch=10, days=2)


MAIL = {"MAIL_PROVIDER": "imap", "IMAP_SERVER": "mail.csirt.example", "IMAP_USER": "reports@csirt.example", "IMAP_PASSWORD": "pw"}
with tempfile.TemporaryDirectory() as d:
    base = Path(d)

    def run(env, down=False):
        used.clear(); mode["down"] = down
        os.environ.clear(); os.environ.update(env)
        RA.pull = lambda *a, **k: (used.append("api"), real_pull(*a, **k))[1]
        st = Counter(); sp.fetch_reports(settings(base), st)
        return list(used), st
    keep = dict(os.environ)
    try:
        u, st = run(dict(ENV, **MAIL))
        ok("REPORT_SOURCE=api: the API is used, the mailbox is not touched", u == ["api"], str(u))
        u, st = run(dict(ENV, **MAIL), down=True)
        ok("…the API cannot be reached and a mailbox is set up: this run reads the mailbox", u == ["api", "email"] and st["fallback_used"] == 1, str(u))
        u, st = run(dict(ENV), down=True)
        ok("…no mailbox to fall back to: the run carries on with what is on disk", u == ["api"] and st["api_unusable"] == 1, str(u))
        u, st = run(dict(MAIL, REPORT_SOURCE="email", SHADOWSERVER_API_KEY=KEY, SHADOWSERVER_API_SECRET=SECRET))
        ok("REPORT_SOURCE=email: the mailbox is used, not the API", u == ["email"], str(u))

        def mail_down(s, stats, refetch=False):
            used.append("email"); raise sp.mail_sources.MailSourceError("login refused")
        sp.pull_emails = mail_down
        u, st = run(dict(MAIL, REPORT_SOURCE="email", SHADOWSERVER_API_KEY=KEY, SHADOWSERVER_API_SECRET=SECRET))
        ok("…the mailbox cannot be read and an API key is saved: this run uses the API", u == ["email", "api"] and st["fallback_used"] == 1, str(u))
        u, st = run(dict(MAIL, REPORT_SOURCE="email"))
        ok("…no API key: the run carries on with what is on disk", u == ["email"] and st["email_failed"] == 1, str(u))
        u, st = run({"REPORT_SOURCE": "email", "IMAP_SERVER": "mail.example.org", "IMAP_USER": "user@example.org", "IMAP_PASSWORD": "change-me"})
        ok("the placeholders of .env.example do not count as a mailbox", not RA.mail_configured({"IMAP_SERVER": "mail.example.org", "IMAP_USER": "user@example.org", "IMAP_PASSWORD": "change-me"}))
    finally:
        os.environ.clear(); os.environ.update(keep); RA.pull = real_pull

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
