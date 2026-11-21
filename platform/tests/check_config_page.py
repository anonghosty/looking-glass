#!/usr/bin/env python3
"""Settings → Configuration (config_page.py). A scratch folder and a throwaway Flask app; the real data/ and .env are
never read or written, and no service is restarted (the signal is caught).
1. the catalogue: every editable setting is read by the platform, with the same default; nothing in two kinds
2. what can be kept: numbers in their range only; security, audit and unknown names never, even in a hand-edited file
3. where a value comes from: .env, then the page (which takes precedence); a secret is never in an answer
4. the API: the Settings permission; changes need JSON, the CSRF token and a recent sign-in; each is audited
5. restart: only the running service, a minute apart, by a signal to its main process
6. the page: its tab and script, built as text
Run: .venv/bin/python tests/check_config_page.py"""
import json
import os
import re
import stat
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
import config_page as C  # noqa: E402

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info else ""), flush=True)


print("1. The catalogue")
src = ""
for root, dirs, files in os.walk(HERE):
    dirs[:] = [d for d in dirs if d not in (".venv", ".venvs", "tests", "node_modules", ".git", "data", "tools", "backups")]   # backups: old code moved aside (deploy/stale_files.py)
    for f in files:
        if f.endswith(".py") and f != "config_page.py":
            src += open(os.path.join(root, f), encoding="utf-8", errors="replace").read() + "\n"
missing, wrong = [], []
for key, _g, _l, kind, default, lo, hi, _h in C.TUNING:
    m = re.search(r'"' + key + r'"\s*,\s*"?(-?[0-9][0-9_.]*)', src)
    if not m:
        missing.append(key)
        continue
    code_default = float(m.group(1).replace("_", ""))
    if code_default != float(default) or not lo <= default <= hi:
        wrong.append(f"{key}: code {m.group(1)}, page {default} ({lo}..{hi})")
ok(f"every editable setting ({len(C.TUNING)}) is read by the platform", not missing, ", ".join(missing))
ok("... with the same default as the code, inside its own range", not wrong, "; ".join(wrong))
example = open(os.path.join(HERE, ".env.example"), encoding="utf-8").read() if os.path.exists(os.path.join(HERE, ".env.example")) else ""
unknown = [k for k, *_ in C.READ_ONLY + [(s, None) for s, _ in C.SECRETS] if f'"{k}"' not in src and f"{k}=" not in example]
ok("every shown setting exists (read by the platform or in .env.example)", not unknown, ", ".join(unknown))
sec_words = ("PASSWORD", "TOKEN", "SECRET", "_KEY")
ok("no password, token or key among the editable or shown values (secrets only say set / not set)",
   not [k for k in C.TUNING_KEYS | {k for k, *_ in C.READ_ONLY} if any(w in k for w in sec_words)])
security = {"ACCESS_MODE", "VIEWER_NETWORKS", "ALLOWED_HOSTS", "MFA_REQUIRED", "REGISTRATION", "SESSION_IDLE_MINUTES",
            "SESSION_MAX_HOURS", "TRUST_PROXY", "ALLOW_INSECURE_REMOTE_LOGIN", "PUBLIC_DEMO", "CSP_REPORT_ONLY", "HSTS_MAX_AGE",
            "LOGIN_ACCOUNT_FAILS", "LOGIN_ACCOUNT_LOCK_MIN", "DATA_ACCESS_LOG", "AUDIT_RETENTION_DAYS", "AUDIT_MAX_ADMINS"}
ok("the security switches, sign-in locks and audit settings are shown only (the user's decision)",
   not (security & C.TUNING_KEYS) and security <= {k for k, *_ in C.READ_ONLY})

print("2. What can be kept")
ok("a number in its range is kept", C.validate("BEACON_KEEP_MAX", "500000") == ("500000", None))
ok("a decimal for a decimal setting", C.validate("REPLAY_OFFSET_HOURS", "12.5")[0] == "12.5")
for label, key, v in (("below its range", "HEAVY_WAIT_S", 0), ("above its range", "BEACON_KEEP_MAX", 10 ** 9),
                      ("not a number", "DAY_RELOAD_SECONDS", "ten"), ("a fraction for a whole number", "HEAVY_PER_USER", "2.5"),
                      ("true/false", "SLOW_REQUEST_S", True), ("not a number (NaN)", "SPIKE_RATIO", "nan"),
                      ("a security switch", "MFA_REQUIRED", "0"), ("an audit setting", "AUDIT_RETENTION_DAYS", "1"),
                      ("a secret", "MONGO_PASSWORD", "x"), ("an unknown name", "LD_PRELOAD", "/tmp/x.so")):
    kept, why = C.validate(key, v)
    ok(f"refused: {label}", kept is None and why, why or "")
tmp = tempfile.mkdtemp(prefix="lg_cfg_")
os.makedirs(os.path.join(tmp, "data"))
with open(os.path.join(tmp, "data", C.FILE), "w") as f:      # a hand-edited file trying to switch security off
    json.dump({"values": {"MFA_REQUIRED": "0", "ACCESS_MODE": "public", "LD_PRELOAD": "/tmp/x.so",
                          "HEAVY_WAIT_S": "999", "FINDING_ACT_DAYS": "45"}}, f)
ok("a hand-edited file applies only valid tuning values (MFA, access mode, LD_PRELOAD, out of range: never)",
   C.load(tmp) == {"FINDING_ACT_DAYS": "45"}, str(C.load(tmp)))
with open(os.path.join(tmp, "data", C.FILE), "w") as f:
    f.write("{damaged")
ok("a damaged file applies nothing (no error)", C.load(tmp) == {})

print("3. Where a value comes from")
with open(os.path.join(tmp, ".env"), "w") as f:
    f.write("FINDING_ACT_DAYS=20\nHEAVY_WAIT_S=15  # a comment\nMONGO_PASSWORD=s3cret-value\nMAPBOX_TOKEN=pk.made-up\n"
            "MFA_REQUIRED=1\nREPLAY_OFFSET_HOURS=24\n")
C._save(tmp, {"FINDING_ACT_DAYS": "45", "BEACON_KEEP_MAX": "400000"}, "admin1")
ok("the kept file is readable by the service only (600)", stat.S_IMODE(os.stat(os.path.join(tmp, "data", C.FILE)).st_mode) == 0o600)
env = {"REPLAY_OFFSET_HOURS": "6"}                            # given to the service itself (systemd)
applied = C.apply(tmp, env)
ok("the page's values take precedence over .env", env["FINDING_ACT_DAYS"] == "45" and env["BEACON_KEEP_MAX"] == "400000", str(applied))
ok("... .env is read with load_dotenv's own rules (an inline comment is not part of the value)", env["HEAVY_WAIT_S"] == "15", env.get("HEAVY_WAIT_S"))
ok("... and .env never replaces what the service was given", env["REPLAY_OFFSET_HOURS"] == "6")
snap = C.snapshot(tmp, env)
by = {i["key"]: i for i in snap["items"]}
ok("in use, where from and default are told", by["FINDING_ACT_DAYS"]["value"] == "45" and by["FINDING_ACT_DAYS"]["source"] == "this page"
   and by["HEAVY_WAIT_S"]["source"] == ".env" and by["SLOW_REQUEST_S"]["source"] == "default")
ok("nothing waits for a restart right after a start", not snap["pending_restart"])
text = json.dumps(snap)
ok("a secret is never in an answer, only whether it is set", "s3cret-value" not in text and "pk.made-up" not in text
   and by["MONGO_PASSWORD"]["set"] is True and by["NVD_API_KEY"]["set"] is False)
ok("a shown setting gives the exact .env line to change", by["MFA_REQUIRED"]["env_line"] == "MFA_REQUIRED=1" and not by["MFA_REQUIRED"]["editable"])

print("4. The API")
from flask import Flask, g  # noqa: E402
app = Flask("cfg-check")
who = {"user": "admin1", "perms": {"settings"}, "csrf": True, "fresh": True}
audit = []


class Audit:
    def add(self, kind, **kw):
        audit.append((kind, kw))


@app.before_request
def _u():
    g.user = {"user": who["user"], "perms": who["perms"]}


C.install(app, {"base_dir": tmp, "has_perm": lambda p: p in who["perms"], "csrf_ok": lambda: who["csrf"],
                "fresh": lambda: who["fresh"], "audit": Audit()})
c = app.test_client()
os.environ.pop("LG_CONFIG_APPLIED", None)
r = c.get("/api/admin/config")
ok("an administrator reads it", r.status_code == 200 and r.get_json()["items"])
who["perms"] = {"view"}
ok("without the Settings permission: refused", c.get("/api/admin/config").status_code == 403
   and c.post("/api/admin/config", json={"values": {"HEAVY_WAIT_S": 30}}).status_code == 403)
who["perms"] = {"settings"}
ok("a change sent as a form (not JSON): refused", c.post("/api/admin/config", data={"values": "x"}).status_code == 403)
who["csrf"] = False
ok("without the CSRF token: refused", c.post("/api/admin/config", json={"values": {"HEAVY_WAIT_S": 30}}).status_code == 403)
who["csrf"], who["fresh"] = True, False
r = c.post("/api/admin/config", json={"values": {"HEAVY_WAIT_S": 30}})
ok("without a recent sign-in: asked to sign in again", r.status_code == 403 and r.get_json().get("reauth"))
who["fresh"] = True
for label, values in (("a security switch", {"MFA_REQUIRED": "0"}), ("out of range", {"HEAVY_WAIT_S": 500}),
                      ("an unknown name", {"PATH": "/tmp"}), ("nothing", {}), ("not a list of values", {"values": 3})):
    r = c.post("/api/admin/config", json={"values": values} if label != "not a list of values" else values)
    ok(f"refused, nothing kept: {label}", r.status_code == 400 and C.load(tmp).get("HEAVY_WAIT_S") is None, r.get_json().get("error", ""))
audit.clear()
r = c.post("/api/admin/config", json={"values": {"HEAVY_WAIT_S": 30, "FINDING_ACT_DAYS": None}})
d = r.get_json()
ok("a valid change is kept, a null goes back to .env or the default", r.status_code == 200 and C.load(tmp).get("HEAVY_WAIT_S") == "30"
   and "FINDING_ACT_DAYS" not in C.load(tmp), str(C.load(tmp)))
ok("... it says a restart is needed", d["pending_restart"] is True)
ok("... each change is in the audit log with old and new values",
   sorted(a[1]["target"] for a in audit) == ["FINDING_ACT_DAYS", "HEAVY_WAIT_S"] and all(a[0] == "config_changed" for a in audit)
   and any("-> 30" in a[1]["detail"] for a in audit), str(audit))
audit.clear()
c.post("/api/admin/config", json={"values": {"HEAVY_WAIT_S": 30}})
ok("the same value again: no change, nothing audited", not audit)

print("5. Restart")
r = c.post("/api/admin/config/restart", json={})
ok("outside the running service: refused, says how", r.status_code == 409 and "reload.sh" in r.get_json()["error"])
sent = []
_master, _kill = C._gunicorn_master, C.os.kill
C._gunicorn_master = lambda: 4242
C.os.kill = lambda pid, sig: sent.append((pid, sig))
try:
    r = c.post("/api/admin/config/restart", json={})
    time.sleep(2)
    ok("in the service: the main process is told to stop (systemd starts it again), after the answer has left",
       r.status_code == 200 and sent == [(4242, C.signal.SIGTERM)], str(sent))
    ok("... and it is in the audit log", any(a[0] == "service_restarted" for a in audit))
    r = c.post("/api/admin/config/restart", json={})
    ok("a second restart within a minute: refused", r.status_code == 429 and len(sent) == 1)
    who["fresh"] = False
    ok("a restart needs a recent sign-in too", c.post("/api/admin/config/restart", json={}).status_code == 403)
finally:
    C._gunicorn_master, C.os.kill = _master, _kill

print("6. The page")
tpl = open(os.path.join(HERE, "templates", "settings.html"), encoding="utf-8").read()
js_path = os.path.join(HERE, "static", "js", "config-page.js")
if "tabConfig" in tpl or os.path.exists(js_path):
    js = open(js_path, encoding="utf-8").read()
    ok("the Settings page has the tab, the pane and its script", 'data-st-tab="config"' in tpl and 'id="tabConfig"' in tpl
       and "js/config-page.js" in tpl)
    ok("the page is built as text, never as HTML", "innerHTML" not in js and "insertAdjacentHTML" not in js)
    ok("it sends the CSRF token and JSON", "X-CSRF-Token" in js and "application/json" in js)
else:
    print("  (the page's files are held for the release: checked on the staged copy)")

for fn in os.listdir(os.path.join(tmp, "data")):
    os.remove(os.path.join(tmp, "data", fn))
os.rmdir(os.path.join(tmp, "data")); os.remove(os.path.join(tmp, ".env")); os.rmdir(tmp)
print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {fails}" if fails else ""))
sys.exit(1 if fails else 0)
