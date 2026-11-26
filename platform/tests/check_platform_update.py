#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""Settings → Update (platform_update.py, deploy/update_run.py, deploy/update_helper.sh), on made-up repositories only.

1. The update run, against a throwaway "GitHub" (a bare repository on disk) whose release tags are signed with a
   throwaway SSH key: Check finds the newer release; Update backs up, checks the signature, moves the code (on the
   branch), installs the libraries, restarts and ends "done"; a libraries step that fails puts the previous release back;
   an unsigned tag, a tag signed by another key, an older release, a request older than 15 minutes, a changed shipped
   file and a folder that is not a release installation are all refused with the code untouched; the log keeps every step.
2. The page's API: administrators only, CSRF, a recent sign-in; refused without the helper, on a working copy, while a
   run is busy, and without a release; a good request is written owner-only and recorded in the audit log; installing
   asks for the every-time confirmation (stepup.py), looking for one does not.
3. The files: the helper's units run as the installation's user, never root, with the code writable only for the run.
Nothing outside temporary folders is touched. Needs git and ssh-keygen. Run: .venv/bin/python tests/check_platform_update.py"""
import importlib.util, json, os, shutil, stat, subprocess, sys, tempfile, time
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "deploy"))

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{str(info)[:600]}]" if info and not cond else ""), flush=True)


if not (shutil.which("git") and shutil.which("ssh-keygen")):
    print("git or ssh-keygen missing: skipped")
    sys.exit(77)

spec = importlib.util.spec_from_file_location("update_run", os.path.join(ROOT, "deploy", "update_run.py"))
UR = importlib.util.module_from_spec(spec); spec.loader.exec_module(UR)
VI = UR.VI
tmp = tempfile.mkdtemp(prefix="lg-update-check-")
ENV = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@example.invalid", GIT_COMMITTER_NAME="t",
           GIT_COMMITTER_EMAIL="t@example.invalid", GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1")


def sh(*args, cwd=None):
    r = subprocess.run(list(args), cwd=cwd, capture_output=True, text=True, env=ENV)
    if r.returncode:
        raise RuntimeError(f"{args}: {r.stderr}")
    return r.stdout.strip()


def key(name):
    p = os.path.join(tmp, name)
    sh("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", name, "-f", p)
    pub = open(p + ".pub").read().split()
    return p, (pub[0], pub[1]), VI.key_fingerprint(pub[1])


good_key, good_pub, good_fp = key("maintainer")
bad_key, _, _ = key("someone-else")

# ---- the "GitHub": one repository with platform/ (and the run's stand-ins for the backup, libraries and restart)
src = os.path.join(tmp, "src")
os.makedirs(os.path.join(src, "platform", "deploy")); os.makedirs(os.path.join(src, "platform", "manage"))
STUB = "#!/bin/sh\necho \"{0} ran\"\n[ -f \"$(dirname \"$0\")/../data/fail_{0}\" ] && {{ echo \"{0} failed\"; exit 1; }}\nexit 0\n"
for rel, name in (("manage/backup.sh", "backup"), ("deploy/update_libraries.sh", "libraries"), ("deploy/reload.sh", "reload")):
    p = os.path.join(src, "platform", rel)
    open(p, "w").write(STUB.format(name)); os.chmod(p, 0o755)
open(os.path.join(src, "platform", ".release_fingerprints"), "w").write("{}\n")
open(os.path.join(src, "platform", ".gitignore"), "w").write("data/\nbackups/\n")
open(os.path.join(src, "platform", "VERSION"), "w").write("1\n")
sh("git", "init", "-q", "-b", "main", cwd=src)
sh("git", "add", "-A", cwd=src); sh("git", "commit", "-q", "-m", "one", cwd=src)


def tag(name, keyfile=good_key):
    sh("git", "-c", "gpg.format=ssh", "-c", f"user.signingkey={keyfile}", "tag", "-s", "-m", name, name, cwd=src)


tag("v2026.11.20")
open(os.path.join(src, "platform", "VERSION"), "w").write("2\n")
sh("git", "commit", "-qam", "two", cwd=src); tag("v2026.11.25")
open(os.path.join(src, "platform", "VERSION"), "w").write("3\n")
sh("git", "commit", "-qam", "three", cwd=src); sh("git", "tag", "-a", "-m", "unsigned", "v2026.11.26", cwd=src)
open(os.path.join(src, "platform", "VERSION"), "w").write("4\n")
sh("git", "commit", "-qam", "four", cwd=src); tag("v2026.11.27", bad_key)
hub = os.path.join(tmp, "hub.git")
sh("git", "clone", "-q", "--bare", src, hub)

# ---- the installation: a clone at v2026.11.20, on main
inst = os.path.join(tmp, "looking-glass")
sh("git", "clone", "-q", hub, inst)
sh("git", "reset", "-q", "--hard", "v2026.11.20", cwd=inst)
project = os.path.join(inst, "platform")

UR.PROJECT = project
UR.STATE = os.path.join(project, "data", "update")
UR.REQUEST, UR.STATUS, UR.LOG, UR.LOCK = (os.path.join(UR.STATE, n) for n in ("request.json", "status.json", "log.jsonl", "lock"))
VI.REPO = hub
VI.KEY_FINGERPRINT = good_fp
VI.github_keys = lambda *a, **k: [good_pub]
UR.audit = lambda *a, **k: None
os.makedirs(UR.STATE, exist_ok=True)


def request(kind, tag_="", age=0):
    with open(UR.REQUEST, "w") as fh:
        json.dump({"kind": kind, "tag": tag_, "by": "Grace Mensah", "at": time.time() - age}, fh)
    rc = UR.main([])
    return rc, json.load(open(UR.STATUS)) if os.path.exists(UR.STATUS) else {}


head = lambda: sh("git", "rev-parse", "HEAD", cwd=inst)        # noqa: E731
at = lambda t: sh("git", "rev-list", "-n1", t, cwd=inst)        # noqa: E731
version = lambda: open(os.path.join(project, "VERSION")).read().strip()  # noqa: E731

print("1. The update run")
rc, st = request("check")
ok("Check: the installed release and the newer ones on GitHub", st.get("state") == "checked" and st.get("installed") == "v2026.11.20"
   and "v2026.11.25" in (st.get("newer") or []), st)
ok("…and the request is taken (it runs once)", not os.path.exists(UR.REQUEST))
rc, st = request("update", "v2026.11.25", age=20 * 60)
ok("a request older than 15 minutes is ignored", rc == 0 and st.get("kind") == "check" and version() == "1", st)
rc, st = request("update", "v2026.11.26")
ok("an unsigned release tag is refused, the code untouched", st.get("state") == "failed" and "NOT good" in st.get("result", "")
   and version() == "1", st.get("result"))
rc, st = request("update", "v2026.11.27")
ok("a tag signed by another key is refused, the code untouched", st.get("state") == "failed" and "NOT good" in st.get("result", "")
   and version() == "1", st.get("result"))
open(os.path.join(project, "data", "fail_libraries"), "w").write("x")
before = head()
rc, st = request("update", "v2026.11.25")
ok("the libraries step fails: the previous release is put back", st.get("state") == "rolled_back" and head() == before and version() == "1",
   st.get("result"))
os.remove(os.path.join(project, "data", "fail_libraries"))
open(os.path.join(project, "VERSION"), "w").write("changed here\n")
rc, st = request("update", "v2026.11.25")
ok("a changed shipped file stops the update before anything", st.get("state") == "failed" and "changed here" in st.get("result", "")
   and head() == before, st.get("result"))
sh("git", "checkout", "-q", "--", "platform/VERSION", cwd=inst)
rc, st = request("update", "v2026.11.25")
log = [json.loads(x) for x in open(UR.LOG)]
steps = [x["step"] for x in log]
ok("Update: backup, signature, code, libraries, restart, then done", st.get("state") == "done" and version() == "2"
   and all(s in steps for s in ("backup", "signature", "code", "libraries", "restart")), (st.get("result"), sorted(set(steps))))
ok("…on the branch (a fast-forward: a later git pull still works)", sh("git", "symbolic-ref", "--short", "HEAD", cwd=inst) == "main"
   and head() == at("v2026.11.25"))
ok("…the installed release is now the new one", st.get("installed") == "v2026.11.25", st.get("installed"))
ok("…every line of the steps' output is in the log (the stand-ins said they ran)",
   all(any(f"{n} ran" in x["msg"] for x in log) for n in ("backup", "libraries", "reload")))
rc, st = request("update", "v2026.11.20")
ok("an older release is refused (no way back by request)", st.get("state") == "failed" and "not newer" in st.get("result", "")
   and version() == "2", st.get("result"))
rc, st = request("update", "v2026.11.99")
ok("a release that is not on GitHub is refused", st.get("state") == "failed" and "not a release" in st.get("result", ""), st.get("result"))
os.rename(os.path.join(project, ".release_fingerprints"), os.path.join(tmp, "fp"))
rc, st = request("check")
ok("a folder not installed from a release is not updated", st.get("state") == "failed" and "not installed from a release" in st.get("result", ""))
os.rename(os.path.join(tmp, "fp"), os.path.join(project, ".release_fingerprints"))
lk = open(UR.LOCK, "w")
import fcntl  # noqa: E402
fcntl.flock(lk, fcntl.LOCK_EX)
open(UR.REQUEST, "w").write(json.dumps({"kind": "check", "at": time.time()}))
ok("one run at a time (the lock)", UR.main([]) == 2 and os.path.exists(UR.REQUEST))
lk.close(); os.remove(UR.REQUEST)

print("2. The page's API")
os.environ.setdefault("THREATMAP_SCHEDULE", "0")
import flask  # noqa: E402
import platform_update as PU  # noqa: E402
import stepup  # noqa: E402
app = flask.Flask("t")
audit = []
who = {"user": "admin1", "perms": {"settings"}}
flags = {"csrf": True, "fresh": True}
base = os.path.join(tmp, "base")
os.makedirs(os.path.join(base, "data"))
units = os.path.join(tmp, "units"); os.makedirs(units)
PU.UNIT_DIR = units
real_helper = PU.helper_installed
PU.helper_installed = lambda unit_dir=None: real_helper(units)
PU.install(app, {"base_dir": base, "has_perm": lambda p: p in who["perms"], "csrf_ok": lambda: flags["csrf"],
                 "fresh": lambda: flags["fresh"], "audit": type("A", (), {"add": lambda self, ev, **k: audit.append((ev, k))})(),
                 "people_name": lambda u: "Ama Owusu"})


@app.before_request
def _u():
    flask.g.user = dict(who)


c = app.test_client()
post = lambda b: c.post("/api/admin/update", json=b)     # noqa: E731
d = c.get("/api/admin/update").get_json()
ok("the status: no helper, not a release installation, the command to install the helper",
   d["helper"] is False and d["release_install"] is False and d["command"] == "deploy/update_helper.sh install", d)
r = post({"kind": "check"})
ok("refused on a folder not installed from a release", r.status_code == 400 and "not installed from a release" in r.get_json()["error"])
open(os.path.join(base, ".release_fingerprints"), "w").write("{}\n")
r = post({"kind": "check"})
ok("refused without the update helper, naming the command", r.status_code == 400 and PU.COMMAND in r.get_json()["error"])
open(os.path.join(units, PU.unit_name() + ".path"), "w").write("x")
r = post({"kind": "update", "tag": "not a tag"})
ok("an update without a release named is refused", r.status_code == 400)
who["perms"] = set()
ok("without the settings permission: refused", post({"kind": "check"}).status_code == 403 and c.get("/api/admin/update").status_code == 403)
who["perms"] = {"settings"}
flags["csrf"] = False
ok("without the page's form token: refused", post({"kind": "check"}).status_code == 403)
flags["csrf"], flags["fresh"] = True, False
ok("with a session older than 12 hours: refused", post({"kind": "check"}).status_code == 403)
flags["fresh"] = True
r = post({"kind": "update", "tag": "v2026.11.25"})
reqf = os.path.join(base, "data", "update", "request.json")
saved = json.load(open(reqf)) if os.path.exists(reqf) else {}
ok("a good request is written for the helper, owner-only, with the full name (never the sign-in name)",
   r.status_code == 200 and saved.get("tag") == "v2026.11.25" and saved.get("by") == "Ama Owusu"
   and stat.S_IMODE(os.stat(reqf).st_mode) == 0o600, saved)
ok("…recorded in the audit log", audit and audit[-1][0] == "update_requested" and audit[-1][1].get("target") == "v2026.11.25", audit[-1:])
r = post({"kind": "check"})
ok("while a request waits (a run is busy): refused", r.status_code == 409)
os.remove(reqf)
os.makedirs(os.path.join(base, "data", "update"), exist_ok=True)
with open(os.path.join(base, "data", "update", "log.jsonl"), "w") as fh:
    fh.write(json.dumps({"t": 1, "step": "code", "level": "info", "msg": "moving the code"}) + "\nnot json\n")
d = c.get("/api/admin/update").get_json()
ok("the log is shown (a broken line skipped)", [x["msg"] for x in d["log"]] == ["moving the code"], d["log"])
rule = next((x for x in stepup.RULES if x[1] == r"/api/admin/update"), None)
with app.test_request_context("/api/admin/update", method="POST", json={"kind": "update"}):
    asks_update = bool(rule and rule[2]() and rule[4])
with app.test_request_context("/api/admin/update", method="POST", json={"kind": "check"}):
    asks_check = bool(rule and rule[2]())
ok("installing asks for the every-time confirmation; looking for one does not", asks_update and not asks_check, rule)
ok("…in plain words", stepup.WORDS.get("update") == "update Looking Glass")

print("3. The files")
svc = open(os.path.join(ROOT, "deploy", "looking-glass-update.service.template")).read()
ok("the run is its installation's user (User=@USER@), never root, no new privileges",
   "User=@USER@" in svc and "NoNewPrivileges=true" in svc and "CapabilityBoundingSet=\n" in svc and "root" not in svc.split("[Service]")[1].split("\n")[1])
ok("only the Looking Glass folder is writable for it", "ProtectSystem=strict" in svc and "ReadWritePaths=@ROOT@" in svc)
pth = open(os.path.join(ROOT, "deploy", "looking-glass-update.path.template")).read()
ok("the path unit watches only the request file", "PathExists=@PROJECT@/data/update/request.json" in pth)
helper = open(os.path.join(ROOT, "deploy", "update_helper.sh")).read()
ok("the helper runs as the folder's owner, also under sudo, and never as root",
   'user="$(stat -c %U "$project")"' in helper and '[ "$user" != root ]' in helper)
for t in ("unusual_timer.sh", "connectors_timer.sh"):
    src_t = open(os.path.join(ROOT, "deploy", t)).read()
    ok(f"{t}: its service is the folder's owner under sudo too (it was root, as the installer runs it)",
       'user="$(stat -c %U "$project")"' in src_t and 'user="$(id -un)"' not in src_t)
for f in ("deploy/update_run.py", "deploy/update_helper.sh"):
    ok(f"{f} can be run (mode 755)", stat.S_IMODE(os.stat(os.path.join(ROOT, f)).st_mode) == 0o755)

shutil.rmtree(tmp, ignore_errors=True)
print(f"\n{checks - len(fails)} of {checks} update checks passed" + (f"; FAILED: {fails}" if fails else ""))
sys.exit(1 if fails else 0)
