#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""Code integrity, layers 2 and 3 (r91). No database, no service: throwaway folders with made-up files only.

A. The fingerprints: deploy/stale_files.write_list() writes .release_fingerprints ("<sha256>  <path>", sha256sum's
   format, a count line) beside the two lists, for exactly the files of .release_files, hashed as they are on disk;
   --write-list writes it again; a list that was cut short, has a malformed line, '..' or a path twice is refused; the
   two other lists never name it; the release builder's secret scan finds nothing in it.
B. deploy/verify_install.py: without --fetch it compares with the local list and says that this proves consistency
   only; CHANGED, NOT IN THE RELEASE and MISSING are named; files outside the code folders and this computer's own
   files are left out; no list, a list that cannot be trusted and the working copy are "not checked" (exit 2).
   With --fetch (here a temporary git repository and an SSH signing key made by this check): a good signature by the
   expected key is required (a tag signed with another key, an unsigned or lightweight tag: exit 3, nothing
   compared), the list comes from the signed tag (a local list changed to hide a file does not hide it), the installed
   commit's tag is read from a local checkout. No outside connection at any point.
C. code_integrity.py, the daily check: an unknown file is found once (one audit entry, however often it runs) and shown
   in the administrators' bell only; a changed file is found; "This is ours" needs the Settings permission, the page's
   CSRF token, a fresh session and the administrator's own password (a wrong one counts as a failed sign-in and is
   audited), is kept in data/code_approved.json and a later change flags the file again; "Not ours" is recorded,
   audited and gives the command the administrator runs on the server (verify_install.py --quarantine moves the file to
   backups/quarantine-<time>/, never deleting it; a folder it cannot change is refused with no partial copy); the
   service itself never moves, copies or deletes a code file (tested with every move failing as in the read-only
   sandbox); the next check records once that the file has gone; the
   working copy is not checked; the database pipeline's folder is checked too; nothing is reachable by other roles,
   signed out, or by external accounts.
Run: .venv/bin/python tests/check_code_integrity.py   (LG_HELD_DIR=<folder> to read held page files)"""
import importlib.util
import json
import os
import re
import shutil
import socket
import stat
import subprocess
import sys
import tempfile

PLAT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PLAT)
sys.path.insert(0, os.path.join(PLAT, "deploy"))
os.environ.setdefault("LG_QUIET", "1")
os.environ["GIT_ALLOW_PROTOCOL"] = "file"          # git may reach local repositories only
os.environ["GIT_CONFIG_NOSYSTEM"] = "1"
from flask import Flask, g, request  # noqa: E402
from werkzeug.security import generate_password_hash  # noqa: E402

import stale_files as SF  # noqa: E402
import verify_install as VI  # noqa: E402

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{str(info)[:700]}]" if info and not cond else ""), flush=True)


# no outside connection, anywhere in this check (the project's guard pattern)
OUT = []
_rc, _rcc = socket.socket.connect, socket.create_connection
_loc = lambda a: not isinstance(a, tuple) or str(a[0]).startswith(("127.", "::1", "localhost"))  # noqa: E731
socket.socket.connect = lambda s, a, *x, **k: _rc(s, a, *x, **k) if _loc(a) else (OUT.append(a), (_ for _ in ()).throw(OSError("refused")))[1]
socket.create_connection = lambda a, *x, **k: _rcc(a, *x, **k) if _loc(a) else (OUT.append(a), (_ for _ in ()).throw(OSError("refused")))[1]
KEYS_ASKED = []
VI.github_keys = lambda *a, **k: KEYS_ASKED.append(a) or []        # never the GitHub API in this check


def put(root, rel, text=None):
    p = os.path.join(root, *rel.split("/"))
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text if text is not None else f"content of {rel}\n")
    return p


def run_vi(*a, **k):
    lines = []
    code = VI.run(*a, out=lines.append, **k)
    return code, "\n".join(lines)


W = tempfile.mkdtemp(prefix="lg-codeint-")
SHIPPED = ["app.py", "auth.py", "static/js/app.js", "static/css/app.css", "templates/index.html", "tests/check_x.py",
           "tools/helper.py", "deploy/update_libraries.sh", "security_testing/security_retest.py", ".env.example",
           "data/issues.json", "requirements.lock", "docs/x.md"]
try:
    # ================================================================================== A. the fingerprints
    print("A. The fingerprints (.release_fingerprints)")
    rel_dir = os.path.join(W, "release", "platform")
    for r in SHIPPED:
        put(rel_dir, r)
    put(rel_dir, "data/crlf.txt", "a\r\nb\r\n")                         # bytes exactly as on disk
    n = SF.write_list(rel_dir, history=["old.py"])
    fp_text = open(os.path.join(rel_dir, SF.FINGERPRINTS_NAME), encoding="utf-8").read()
    fp = SF.read_fingerprints(rel_dir)
    ok(f"written with the two lists, one line per listed file and a count line ({n} files)",
       fp is not None and set(fp) == SF.read_list(rel_dir) and f"# files: {n}\n" in fp_text and len(fp) == n, fp_text[:300])
    ok("each value is the SHA-256 of the file's bytes as they are on disk (CRLF kept)",
       all(fp[r] == SF.sha256_of(os.path.join(rel_dir, *r.split("/"))) for r in fp)
       and fp["data/crlf.txt"] == __import__("hashlib").sha256(b"a\r\nb\r\n").hexdigest())
    ok("sha256sum's own format: '<64 hex>  <path>', sorted",
       [ln for ln in fp_text.splitlines() if not ln.startswith("#")] == [f"{fp[r]}  {r}" for r in sorted(fp)])
    if shutil.which("sha256sum"):
        r = subprocess.run(["sha256sum", "-c", "--quiet", SF.FINGERPRINTS_NAME], cwd=rel_dir, capture_output=True, text=True)
        ok("sha256sum -c accepts it (every file OK)", r.returncode == 0, r.stdout + r.stderr)
    ok("no list names another list (.release_files, its history, the fingerprints)",
       not ({SF.LIST_NAME, SF.HISTORY_NAME, SF.FINGERPRINTS_NAME} & (set(fp) | SF.read_list(rel_dir) | SF.read_list(rel_dir, SF.HISTORY_NAME))))
    put(rel_dir, "static/js/held.js")
    r = subprocess.run([sys.executable, os.path.join(PLAT, "deploy", "stale_files.py"), "--folder", rel_dir, "--write-list"],
                       capture_output=True, text=True)
    fp2 = SF.read_fingerprints(rel_dir)
    ok("--write-list (the staging step, after held files) writes the fingerprints again, the new file included",
       r.returncode == 0 and "static/js/held.js" in fp2 and SF.FINGERPRINTS_NAME in r.stdout and len(fp2) == n + 1, r.stdout + r.stderr)
    os.remove(os.path.join(rel_dir, "static", "js", "held.js"))
    SF.write_list(rel_dir, history=["old.py"])
    fp_text = open(os.path.join(rel_dir, SF.FINGERPRINTS_NAME), encoding="utf-8").read()

    def refused(text):
        try:
            SF.parse_fingerprints(text)
            return False
        except SF.ListRefused:
            return True
    lines = fp_text.splitlines()
    ok("a list cut short (count unchanged) is refused", refused("\n".join(lines[:-2]) + "\n"))
    ok("a malformed line is refused", refused(fp_text.replace(f"# files: {n}", f"# files: {n + 1}") + "nothex  app2.py\n"))
    ok("'..' or an absolute path is refused", refused(fp_text.replace(f"# files: {n}", f"# files: {n + 1}") + "0" * 64 + "  ../x.py\n")
       and refused(fp_text.replace(f"# files: {n}", f"# files: {n + 1}") + "0" * 64 + "  /etc/passwd\n"))
    ok("a path listed twice is refused", refused(fp_text.replace(f"# files: {n}", f"# files: {n + 1}") + lines[-1] + "\n"))
    ok("an empty list reads as none (an older release)", SF.parse_fingerprints(f"{SF.FINGERPRINTS_HEADER}\n# files: 0\n") is None)
    spec = importlib.util.spec_from_file_location("lg_make_release_ci", os.path.join(PLAT, "tools", "make_release.py"))
    if os.path.isfile(os.path.join(PLAT, "tools", "make_release.py")):   # the maintainer's copy only (not shipped)
        MR = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(MR)
        ok("the release builder's secret scan finds nothing in it (plain lines, no JSON \"hash\" key)",
           not any(rx.search(fp_text) for rx in MR.PATTERNS.values()), [k for k, rx in MR.PATTERNS.items() if rx.search(fp_text)])
        src = open(os.path.join(PLAT, "tools", "make_release.py"), encoding="utf-8").read()
        ok("the release builder writes it with the lists, checks its count and scans it (OWN_LISTS in what it copied)",
           "stale_files.write_list(" in src and "read_fingerprints" in src and "stale_files.OWN_LISTS" in src)
    ok("in_code_folders: the code folders only", SF.in_code_folders("app.py", "platform") and SF.in_code_folders("static/js/a.js", "platform")
       and not SF.in_code_folders("data/issues.json", "platform") and not SF.in_code_folders("tests/data/x.json", "platform")
       and not SF.in_code_folders("docs/x.md", "platform") and SF.in_code_folders("bin/shadowserver", "database"))

    # ================================================================================== B. verify_install.py
    print("\nB. deploy/verify_install.py")

    def install(name):
        root = os.path.join(W, name)
        shutil.rmtree(root, ignore_errors=True)
        shutil.copytree(rel_dir, root)
        put(root, "tools/__pycache__/helper.cpython-312.pyc", "cache")      # this computer's own files: left out
        put(root, "deploy/looking-glass.service", "unit")
        put(root, "app.log", "log")
        return root
    inst = install("inst")
    code, text = run_vi(inst, "platform")
    ok("a clean installation, the local list: exit 0, every code file as shipped", code == VI.OK and "exactly as the release" in text, text)
    ok("...and it says plainly that the local list proves consistency only, not authenticity (and how to check that)",
       "not that they are genuine" in text and "--fetch" in text, text)
    put(inst, "app.py", "print('changed')\n")
    put(inst, "tools/added.py", "print('added')\n")
    os.remove(os.path.join(inst, "static", "js", "app.js"))
    put(inst, "data/issues.json", "{}")                                    # not a code file: not compared
    code, text = run_vi(inst, "platform")
    ok("a changed, an added and a missing code file: exit 1, each named",
       code == VI.DIFFERENT and re.search(r"CHANGED\s+app\.py", text) and re.search(r"NOT IN THE RELEASE\s+tools/added\.py", text)
       and re.search(r"MISSING\s+static/js/app\.js", text), text)
    ok("...files outside the code folders and this computer's own files are not named",
       "data/issues.json" not in text and ".pyc" not in text and "looking-glass.service" not in text and "app.log" not in text, text)
    ok("...the changed file's line gives both SHA-256 values", SF.sha256_of(os.path.join(inst, "app.py")) in text and fp["app.py"] in text)
    import contextlib
    import io
    with contextlib.redirect_stdout(io.StringIO()) as cli_out:
        cli_code = VI.main(["--folder", inst, "--part", "platform"])
    ok("the command line: same result and exit code", cli_code == VI.DIFFERENT and "CHANGED" in cli_out.getvalue())
    os.remove(os.path.join(inst, SF.FINGERPRINTS_NAME))
    code, text = run_vi(inst, "platform")
    ok("no list (a release before r91): not checked, exit 2, and what to do", code == VI.NOT_CHECKED and "--fetch --tag" in text, text)
    shutil.copy2(os.path.join(rel_dir, SF.FINGERPRINTS_NAME), inst)
    with open(os.path.join(inst, SF.FINGERPRINTS_NAME), "a", encoding="utf-8") as fh:
        fh.write("0" * 64 + "  tools/added.py\n")                         # count unchanged: refused
    code, text = run_vi(inst, "platform")
    ok("a list that cannot be trusted: not checked, exit 2", code == VI.NOT_CHECKED and "cut short or changed" in text, text)
    wc = install("wc")
    os.makedirs(os.path.join(wc, "tools", "release_root"))
    code, text = run_vi(wc, "platform")
    ok("the maintainer's working copy: not checked, exit 2", code == VI.NOT_CHECKED and "working copy" in text, text)

    # ---- the signed release: a temporary repository, a key made here
    have_tools = shutil.which("git") and shutil.which("ssh-keygen")
    if not have_tools:
        print("  (git or ssh-keygen missing: the signed-release part is skipped)")
    else:
        keys = os.path.join(W, "keys")
        os.makedirs(keys)
        for k in ("good", "other"):
            subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", f"{k}-check", "-f", os.path.join(keys, k)],
                           check=True, capture_output=True)
        pub = open(os.path.join(keys, "good.pub")).read().split()
        fpr = VI.key_fingerprint(pub[1])
        lf = subprocess.run(["ssh-keygen", "-lf", os.path.join(keys, "good.pub")], capture_output=True, text=True).stdout
        ok("the key fingerprint is worked out exactly as ssh-keygen -l prints it", fpr in lf, (fpr, lf))
        allowed = os.path.join(keys, "allowed_signers")
        open(allowed, "w").write(f'* namespaces="git" {pub[0]} {pub[1]}\n')
        repo = os.path.join(W, "repo")
        os.makedirs(repo)
        shutil.copytree(rel_dir, os.path.join(repo, "platform"))
        G = ["git", "-C", repo, "-c", "user.name=Check", "-c", "user.email=check@example.invalid", "-c", "gpg.format=ssh",
             "-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false"]
        subprocess.run(["git", "init", "-q", "-b", "main", repo], check=True, capture_output=True)
        subprocess.run(G + ["add", "-A"], check=True, capture_output=True)
        subprocess.run(G + ["commit", "-q", "-m", "release"], check=True, capture_output=True)

        def tag(name, key=None, signed=True, annotated=True):
            args = G + (["-c", f"user.signingkey={os.path.join(keys, key)}"] if key else [])
            if not annotated:
                return subprocess.run(args + ["tag", name], capture_output=True, text=True)
            return subprocess.run(args + ["tag", "-s" if signed else "-a", name, "-m", name], capture_output=True, text=True)
        tr = tag("v2099.1.1", "good")
        ok("(the check's own signed tag was made)", tr.returncode == 0, tr.stderr)
        tag("v2099.1.2", "other")
        tag("v2099.1.3", signed=False)
        tag("v2099.1.4", annotated=False)
        url = "file://" + repo
        inst2 = install("inst2")
        code, text = run_vi(inst2, "platform", fetch=True, tag="v2099.1.1", repo=url, signers=allowed, want_fp=fpr)
        ok("--fetch: the tag fetched, its signature good with the expected key, every file as signed: exit 0",
           code == VI.OK and "signature: good" in text and fpr in text and "the signed release v2099.1.1" in text, text)
        put(inst2, "auth.py", "tampered\n")
        put(inst2, "templates/extra.html", "<p>added</p>\n")
        # someone who changed the code also rewrote the local list to match: the signed list still finds it
        SF.write_fingerprints(inst2, sorted(set(SF.read_fingerprints(inst2)) | {"templates/extra.html"}))
        code_local, _t = run_vi(inst2, "platform")
        code, text = run_vi(inst2, "platform", fetch=True, tag="v2099.1.1", repo=url, signers=allowed, want_fp=fpr)
        ok("a local list rewritten to hide a change fools the local check, not the signed one",
           code_local == VI.OK and code == VI.DIFFERENT and re.search(r"CHANGED\s+auth\.py", text)
           and re.search(r"NOT IN THE RELEASE\s+templates/extra\.html", text) and "is not the signed release's list" in text, text)
        for t_, why in (("v2099.1.2", "signed with another key"), ("v2099.1.3", "not signed"), ("v2099.1.4", "a lightweight tag")):
            code, text = run_vi(inst2, "platform", fetch=True, tag=t_, repo=url, signers=allowed, want_fp=fpr)
            ok(f"a tag {why}: SIGNATURE NOT GOOD, exit 3, nothing compared",
               code == VI.BAD_SIGNATURE and "SIGNATURE NOT GOOD" in text and "CHANGED" not in text, text)
        other_fp = VI.key_fingerprint(open(os.path.join(keys, "other.pub")).read().split()[1])
        code, text = run_vi(inst2, "platform", fetch=True, tag="v2099.1.1", repo=url, signers=allowed, want_fp=other_fp)
        ok("published keys without the expected fingerprint: exit 3", code == VI.BAD_SIGNATURE and "none of the published" in text, text)
        code, text = run_vi(inst2, "platform", fetch=True, tag="v2099.9.9", repo=url, signers=allowed, want_fp=fpr)
        ok("a tag that is not there: not checked, exit 2", code == VI.NOT_CHECKED and "could not be fetched" in text, text)
        code, text = run_vi(inst2, "platform", fetch=True, tag="main; rm -rf /", repo=url, signers=allowed, want_fp=fpr)
        ok("a tag name that is not a release tag is refused before git runs", code == VI.NOT_CHECKED and "not a release tag" in text, text)
        code, text = run_vi(inst2, "database", fetch=True, tag="v2099.1.1", repo=url, signers=allowed, want_fp=fpr)
        ok("a signed release without that part's fingerprint list: not checked, exit 2",
           code == VI.NOT_CHECKED and "has no database/.release_fingerprints" in text, text)
        # an installation that is a git checkout: the installed commit's tag is read locally
        co = os.path.join(W, "checkout")
        subprocess.run(["git", "clone", "-q", url, co], check=True, capture_output=True)
        subprocess.run(["git", "-C", co, "-c", "advice.detachedHead=false", "checkout", "-q", "v2099.1.1"], check=True, capture_output=True)
        ok("the installed commit's tag, read from the local checkout", VI.installed_tag(os.path.join(co, "platform")) in ("v2099.1.1", "v2099.1.2", "v2099.1.3", "v2099.1.4"))
        code, text = run_vi(os.path.join(co, "platform"), "platform", fetch=True, repo=url, signers=allowed, want_fp=fpr)
        ok("--fetch without --tag on a checkout: the installed tag is used (a tag on this commit)",
           code in (VI.OK, VI.BAD_SIGNATURE) and "fetching the tag v2099.1." in text, text)
        code, text = run_vi(os.path.join(co, "platform"), "platform", fetch=True, tag="v2099.1.1", repo=url, signers=allowed, want_fp=fpr)
        ok("...and the checkout is exactly the signed release: exit 0", code == VI.OK, text)
        code, text = run_vi(inst, "platform", fetch=True, repo=url, signers=allowed, want_fp=fpr)
        ok("not a checkout and no --tag: not checked, and it says to give --tag", code == VI.NOT_CHECKED and "--tag" in text, text)
    ok("the GitHub key list was never asked for (an allowed-signers file was given; no --fetch otherwise)", not KEYS_ASKED, KEYS_ASKED)

    # ================================================================================== C. the daily check
    print("\nC. code_integrity.py: the daily check, the bell and Settings → Code check")
    os.environ["PIPELINE_DIR"] = os.path.join(W, "no-pipeline")
    base = os.path.join(W, "lg", "platform")
    for r in SHIPPED:
        put(base, r)
    os.makedirs(os.path.join(base, "deploy"), exist_ok=True)
    shutil.copy2(os.path.join(PLAT, "deploy", "stale_files.py"), os.path.join(base, "deploy", "stale_files.py"))
    SF.write_list(base, history=["tools/retired.py"])
    put(base, "tools/__pycache__/x.cpython-312.pyc", "cache")
    os.makedirs(os.path.join(base, "data"), exist_ok=True)
    import auth  # noqa: E402
    import code_integrity as CI  # noqa: E402
    import system_alerts  # noqa: E402

    ROLES = {r: set(auth.PERMS) if r == "admin" else set(auth.DEFAULT_ROLES[r])
             for r in ("admin", "management", "advisor", "analyst", "researcher", "external", "auditor")}
    NAMES = {r: f"{r[:3]}.person" for r in ROLES}
    NAMES["admin"] = "ada.admin"
    AUDIT = []

    class Audit:
        def add(self, event, user="", target="", detail="", **_k):
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
    HASH = generate_password_hash(PASSWORD)
    FRESH = [True]

    class Users:
        def get(self, name):
            return {"hash": HASH} if name in NAMES.values() else None

    class Throttle:
        failures = []

        def locked(self, ip, name):
            return False

        def failed(self, ip, name):
            self.failures.append(name)

        def wait_minutes(self, ip, name):
            return 15
    TH = Throttle()
    ctx = {"base_dir": base, "has_perm": has_perm, "csrf_ok": csrf_ok, "audit": Audit(), "fresh": lambda: FRESH[0],
           "serving": False, "people_name": lambda u: "Ada Admin" if u == "ada.admin" else "", "users": Users(),
           "throttle": TH, "client": lambda: ("127.0.0.1", "check")}
    api = CI.install(app, ctx)
    c = app.test_client()
    HDR = {"X-Role": "admin", "X-CSRF-Token": "the-page-token"}
    alerts = system_alerts.Alerts(base, env={})

    def bell(role):
        with app.test_request_context(headers={"X-Role": role}):
            _who()
            return [a for a in alerts.for_user(NAMES[role], has_perm=has_perm) if a["id"].startswith("sys:code-integrity")]

    st = api["check"]()
    ok("a clean installation: checked, no finding, nothing audited, nothing in the bell",
       st["checked"] and not st["findings"] and not AUDIT and not bell("admin"), (st, AUDIT))
    evil = put(base, "tools/evil.py", "import os  # made up\n")
    st = api["check"]()
    st = api["check"]()
    st = api["check"]()
    f1 = [f for f in st["findings"] if f["key"] == "platform/tools/evil.py"]
    ok("an unknown file in a code folder: found as 'not in the release', with its SHA-256",
       len(f1) == 1 and f1[0]["kind"] == "unknown" and f1[0]["sha256"] == SF.sha256_of(evil), st["findings"])
    ok("...ONE audit entry however often the check runs (code_integrity_finding, the path, the SHA-256)",
       [a[0] for a in AUDIT] == ["code_integrity_finding"] and AUDIT[0][2] == "platform/tools/evil.py"
       and SF.sha256_of(evil) in AUDIT[0][3] and AUDIT[0][1] == "looking-glass", AUDIT)
    b = {r: bell(r) for r in ROLES}
    ok("...ONE bell item, for administrators only, naming the file and Settings → Code check",
       len(b["admin"]) == 1 and "platform/tools/evil.py" in b["admin"][0]["text"] and b["admin"][0]["link"] == "/settings#cardCode"
       and b["admin"][0]["waiting"] and not any(b[r] for r in ROLES if r != "admin"), b)
    put(base, "auth.py", "tampered = True\n")
    st = api["check"]()
    ch = [f for f in st["findings"] if f["key"] == "platform/auth.py"]
    ok("a shipped file changed: found as 'changed', with the release's SHA-256 too, audited once",
       len(ch) == 1 and ch[0]["kind"] == "changed" and ch[0]["expected"] == SF.read_fingerprints(base)["auth.py"]
       and [a[2] for a in AUDIT] == ["platform/tools/evil.py", "platform/auth.py"] and "the release lists sha256" in AUDIT[1][3], AUDIT)
    ok("...the bell item now names both (one item, a new id)", len(bell("admin")) == 1 and "platform/auth.py" in bell("admin")[0]["text"])
    put(base, "tools/retired.py", "old\n")
    st = api["check"]()
    ok("a file an earlier release shipped is flagged too, and says so", any(f["key"] == "platform/tools/retired.py" and f["former"] for f in st["findings"])
       and "an earlier release shipped" in AUDIT[-1][3])
    os.remove(os.path.join(base, "tools", "retired.py"))
    api["check"]()

    print("\n  who may see and act")
    for role in ("management", "advisor", "analyst", "researcher", "external", "auditor", None):
        codes = {c.get("/api/admin/code-check", headers={"X-Role": role} if role else {}).status_code}
        for path in ("/api/admin/code-check/approve", "/api/admin/code-check/quarantine"):
            h = dict(HDR)
            if role:
                h["X-Role"] = role
            else:
                h.pop("X-Role")
            codes.add(c.post(path, json={"key": "platform/tools/evil.py", "sha256": SF.sha256_of(evil), "password": PASSWORD}, headers=h).status_code)
        ok(f"{role or 'signed out'}: refused everywhere (403)", codes == {403}, codes)
    v = c.get("/api/admin/code-check", headers={"X-Role": "admin"})
    ok("an administrator sees the findings, the guidance (verify_install.py --fetch) and when it last ran",
       v.status_code == 200 and {f["key"] for f in v.json["findings"]} == {"platform/tools/evil.py", "platform/auth.py"}
       and "verify_install.py --fetch" in v.json["guide"] and v.json["at"], v.json)
    import external_access  # noqa: E402
    ok("external accounts cannot reach the routes (not on the sign-in gate's allow-list)",
       not any(p.startswith("/api/admin/code-check") for p in external_access.ALLOWED))
    src = open(CI.__file__, encoding="utf-8").read()
    posts = re.findall(r'@app\.route\("([^"]+)", methods=\["POST"\]\)\n    def (\w+)\(\):\n(.*?)\n\n', src, re.S)
    ok("every POST route of code_integrity.py goes through guard() (Settings permission, CSRF, fresh session)",
       src.count('methods=["POST"]') == 2 and src.count("bad = guard(change=True)") == 2 and posts
       and all("guard(change=True)" in body for _p, _f, body in posts) and 'ctx["csrf_ok"]()' in src and "fresh" in src)
    ok("the one password re-check is password_policy.check_own_password", "check_own_password" in src and "check_password_hash" not in src)

    print("\n  This is ours, keep it")
    good = {"key": "platform/tools/evil.py", "sha256": SF.sha256_of(evil), "password": PASSWORD}
    AUDIT.clear()
    r1 = c.post("/api/admin/code-check/approve", json=good, headers={"X-Role": "admin"})
    r2 = c.post("/api/admin/code-check/approve", json=good, headers={"X-Role": "admin", "X-CSRF-Token": "forged"})
    ok("without the page's CSRF token, or a forged one: refused", (r1.status_code, r2.status_code) == (403, 403))
    FRESH[0] = False
    r3 = c.post("/api/admin/code-check/approve", json=good, headers=HDR)
    FRESH[0] = True
    ok("a session older than 12 hours: refused (sign in again)", r3.status_code == 403 and r3.json.get("reauth"))
    TH.failures.clear()
    r4 = c.post("/api/admin/code-check/approve", json=dict(good, password="not-it"), headers=HDR)
    ok("a wrong password: refused, counted as a failed sign-in, audited",
       r4.status_code == 403 and TH.failures == ["ada.admin"] and [a[0] for a in AUDIT] == ["code_integrity_password_failed"]
       and not os.path.exists(os.path.join(base, "data", CI.APPROVED)), (r4.status_code, AUDIT))
    r5 = c.post("/api/admin/code-check/approve", json=dict(good, sha256="0" * 64), headers=HDR)
    ok("a SHA-256 that is not the file's now (it changed since the page was opened): refused (409)", r5.status_code == 409)
    ok("not JSON: refused", c.post("/api/admin/code-check/approve", data="key=x", headers=HDR).status_code == 403)
    AUDIT.clear()
    r = c.post("/api/admin/code-check/approve", json=good, headers=HDR)
    apr = json.load(open(os.path.join(base, "data", CI.APPROVED)))
    ok("with the right password: kept in data/code_approved.json {path: sha256}, owner-only",
       r.status_code == 200 and apr == {"platform/tools/evil.py": good["sha256"]}
       and oct(os.stat(os.path.join(base, "data", CI.APPROVED)).st_mode & 0o777) == "0o600", (r.status_code, r.json, apr))
    ok("...audited (code_integrity_approved: who, the file, its SHA-256)",
       [a[0] for a in AUDIT] == ["code_integrity_approved"] and AUDIT[0][1] == "ada.admin" and AUDIT[0][2] == good["key"]
       and good["sha256"] in AUDIT[0][3] and "Ada Admin" in AUDIT[0][3], AUDIT)
    ok("...no longer a finding, and gone from the bell's list",
       good["key"] not in {f["key"] for f in r.json["findings"]} and "tools/evil.py" not in bell("admin")[0]["text"])
    AUDIT.clear()
    put(base, "tools/evil.py", "import os  # changed after it was kept\n")
    st = api["check"]()
    ok("the kept file changes later: found again, and audited again (new SHA-256)",
       any(f["key"] == good["key"] for f in st["findings"]) and [a[0] for a in AUDIT] == ["code_integrity_finding"]
       and SF.sha256_of(evil) in AUDIT[0][3], (st["findings"], AUDIT))

    print("\n  Not ours, move to quarantine: recorded by the page, moved by the administrator on the server")
    drop = put(base, "static/js/drop.js", "alert('made up')\n")
    st = api["check"]()
    sha = SF.sha256_of(drop)
    AUDIT.clear()
    r = c.post("/api/admin/code-check/quarantine", json={"key": "platform/static/js/drop.js", "sha256": sha, "password": "nope"}, headers=HDR)
    ok("'not ours' with a wrong password: refused, nothing recorded", r.status_code == 403 and not (CI.state(base).get("decided") or {}))
    # the service's sandbox: its code folder read-only; the page must never try to move a code file
    real = (os.rename, os.unlink, os.remove, shutil.move, shutil.copy2)
    TRIED = []

    def refuse(*a, **k):
        TRIED.append(a[:1])
        raise OSError(30, "Read-only file system")
    os.rename = os.unlink = os.remove = shutil.move = shutil.copy2 = refuse
    try:
        r = c.post("/api/admin/code-check/quarantine", json={"key": "platform/static/js/drop.js", "sha256": sha, "password": PASSWORD}, headers=HDR)
    finally:
        os.rename, os.unlink, os.remove, shutil.move, shutil.copy2 = real
    ok("with the password, every move, copy or delete failing with EROFS (the sandbox): the page tries none of them, "
       "the file stays, the decision is recorded (200)",
       not TRIED and os.path.exists(drop) and r.status_code == 200, (TRIED, r.status_code))
    AUDIT.clear()
    r = c.post("/api/admin/code-check/quarantine", json={"key": "platform/static/js/drop.js", "sha256": sha, "password": PASSWORD}, headers=HDR)
    cmd = (r.json or {}).get("command", "")
    ok("recorded: 200, the file NOT touched by the service, and the command to run on the server as the administrator",
       r.status_code == 200 and os.path.exists(drop) and "verify_install.py" in cmd and "--quarantine static/js/drop.js" in cmd
       and "--part platform" in cmd and base in cmd, (r.status_code, r.json))
    fd = next((f for f in r.json["findings"] if f["key"] == "platform/static/js/drop.js"), {})
    ok("...the card shows the decision (who, when) and the command; it says the service cannot change its own code",
       (fd.get("decided") or {}).get("command") == cmd and fd["decided"]["by"] == "Ada Admin"
       and "cannot change its own code" in r.json["not_service"], fd)
    ok("...audited (code_integrity_quarantine_decided: who, the file, its SHA-256, the command)",
       [a[0] for a in AUDIT] == ["code_integrity_quarantine_decided"] and sha in AUDIT[0][3] and cmd in AUDIT[0][3], AUDIT)
    ok("...the bell says it waits to be moved on the server", "wait" in bell("admin")[0]["text"] and "Settings → Code check" in bell("admin")[0]["text"])
    # the administrator runs the command (here: the same tool, in-process)
    out_lines = []
    code_q = VI.quarantine(base, "platform", "static/js/drop.js", out=out_lines.append)
    qd = [d for d in os.listdir(os.path.join(base, "backups")) if d.startswith("quarantine-")] if os.path.isdir(os.path.join(base, "backups")) else []
    moved = os.path.join(base, "backups", qd[0], "static", "js", "drop.js") if qd else ""
    ok("verify_install.py --quarantine: moved (never deleted) to backups/quarantine-<time>/static/js/drop.js, moved.log beside it",
       code_q == VI.OK and not os.path.exists(drop) and moved and open(moved).read() == "alert('made up')\n"
       and sha in open(os.path.join(base, "backups", qd[0], "moved.log")).read(), out_lines)
    AUDIT.clear()
    st = api["check"]()
    ok("the next check: no longer a finding, the decision dropped, its leaving recorded once (code_integrity_removed)",
       not any(f["key"] == "platform/static/js/drop.js" for f in st["findings"]) and "platform/static/js/drop.js" not in st["decided"]
       and [a[0] for a in AUDIT] == ["code_integrity_removed"], (AUDIT, st.get("decided")))
    api["check"]()
    ok("...and not recorded again", [a[0] for a in AUDIT] == ["code_integrity_removed"])
    ok("--quarantine refuses a path outside the code folders, '..', a link, or a missing file (nothing moved)",
       all(VI.quarantine(base, "platform", p, out=lambda *_: None) == VI.NOT_CHECKED
           for p in ("data/issues.json", "../x.py", "tools/none.py", "/etc/passwd")))
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        ro = put(base, "templates/ro/x.html", "<p>made up</p>\n")
        os.chmod(os.path.dirname(ro), stat.S_IRUSR | stat.S_IXUSR)
        before = sorted(os.listdir(os.path.join(base, "backups")))
        lines_ro = []
        code_ro = VI.quarantine(base, "platform", "templates/ro/x.html", out=lines_ro.append)
        os.chmod(os.path.dirname(ro), 0o755)
        ok("a folder this account cannot change: refused before anything is made, no partial copy, said plainly",
           code_ro == VI.NOT_CHECKED and os.path.exists(ro) and sorted(os.listdir(os.path.join(base, "backups"))) == before
           and "Nothing was copied" in " ".join(lines_ro), lines_ro)
        os.remove(ro)
        os.rmdir(os.path.dirname(ro))
    src_ci = open(CI.__file__, encoding="utf-8").read()
    ok("code_integrity.py never moves, copies or deletes a file (no rename, unlink, remove, shutil)",
       not re.search(r"os\.(rename|unlink|remove|rmdir)\(|shutil\.", src_ci))
    link = os.path.join(base, "tools", "link.py")
    os.symlink(os.path.join(W, "outside.py"), link)
    open(os.path.join(W, "outside.py"), "w").write("outside\n")
    st = api["check"]()
    ok("a symbolic link is never followed, flagged or moved", not any("link.py" in f["key"] for f in st["findings"]) and os.path.islink(link))
    os.remove(link)

    print("\n  the database pipeline's folder, the working copy, lists that cannot be trusted")
    pdir = os.path.join(W, "lg", "database")
    for r_ in ("shadowserver_pipeline.py", "run.sh", "tests/test_x.py", "bin/shadowserver"):
        put(pdir, r_)
    SF.write_list(pdir, history=[])
    os.environ["PIPELINE_DIR"] = pdir
    put(pdir, "bin/extra", "made up\n")
    AUDIT.clear()
    st = api["check"]()
    ok("the pipeline's folder is checked too: a file added to bin/ is found as database/bin/extra",
       st["parts"].get("database", {}).get("checked") and any(f["key"] == "database/bin/extra" for f in st["findings"])
       and [a[2] for a in AUDIT] == ["database/bin/extra"], (st["parts"], AUDIT))
    os.makedirs(os.path.join(base, "tools", "release_root"))
    AUDIT.clear()
    st = api["check"]()
    ok("the maintainer's working copy (tools/release_root): 'not checked', no finding, nothing audited, no bell item",
       not st["checked"] and "working copy" in st["why"] and not st["findings"] and not AUDIT and not bell("admin"), st)
    os.rmdir(os.path.join(base, "tools", "release_root"))
    with open(os.path.join(base, SF.FINGERPRINTS_NAME), "a", encoding="utf-8") as fh:
        fh.write("0" * 64 + "  tools/evil.py\n")
    st = api["check"]()
    rb = [a for a in bell("admin") if a["id"].startswith("sys:code-integrity-refused")]
    ok("a fingerprint list that cannot be trusted: said in the state and as a bell problem",
       "cannot be trusted" in st["problem"] and len(rb) == 1 and "verify_install.py --fetch" in rb[0]["text"], (st.get("problem"), rb))
    os.remove(os.path.join(base, SF.FINGERPRINTS_NAME))
    st = api["check"]()
    ok("no fingerprint list (a release before r91): the platform part not checked, said why",
       not st["parts"]["platform"]["checked"] and "older than r91" in st["parts"]["platform"]["why"])

    print("\n  registered, labelled, on the page")
    import audit_portal  # noqa: E402
    evs = ("code_integrity_finding", "code_integrity_approved", "code_integrity_quarantine_decided", "code_integrity_removed",
           "code_integrity_password_failed")
    ok("every audit event has a readable name and a tab in the Audit portal",
       all(e in audit_portal.LABEL and e in audit_portal.TAB_OF for e in evs) and set(re.findall(r'"(code_integrity_\w+)"', src)) <= set(evs))
    fsrc = open(os.path.join(PLAT, "features.py"), encoding="utf-8").read()
    ok("installed from features.py (its own module), its bell from system_alerts.py",
       "import code_integrity" in fsrc and "code_integrity.bell(" in open(os.path.join(PLAT, "system_alerts.py"), encoding="utf-8").read())
    ok("the background check starts only in the running service (serving), once a day", "if ctx.get(\"serving\")" in src
       and CI.CHECK_EVERY == 86400)
    HELD = os.environ.get("LG_HELD_DIR", "")

    def page_file(sub, name):
        p = os.path.join(HELD, name + ".new") if HELD else ""
        q = p if p and os.path.exists(p) else os.path.join(PLAT, *sub.split("/"), name)
        return open(q, encoding="utf-8").read() if os.path.exists(q) else ""
    html, js, tour = page_file("templates", "settings.html"), page_file("static/js", "code-integrity.js"), page_file("static/js", "tour.js")
    card = html[html.find('id="cardCode"') - 200:html.find('id="cardCode"') + 1200] if 'id="cardCode"' in html else ""
    ok("settings.html: the Code check card, for the Settings permission only, with its loading line, and its script",
       card and '{% if "settings" in lg_perms %}' in card and "st-loading" in card and "js/code-integrity.js" in html)
    ok("code-integrity.js: both actions, the password asked, errors through LGLoader.errorText, no browser confirm()",
       "/api/admin/code-check/approve" in js and "/api/admin/code-check/quarantine" in js and "current-password" in js
       and "LGLoader.errorText(" in js and "confirm(" not in js and not re.search(r"\b[ex]\.message\b", js))
    ok("the Settings tutorial has a Code check step", '["#cardCode",' in tour)
    ok("no outside connection was attempted in this whole check", not OUT, OUT)
finally:
    for top, dirs, _files in os.walk(W):
        for d in dirs:
            try:
                os.chmod(os.path.join(top, d), 0o755)
            except OSError:
                pass
    shutil.rmtree(W, ignore_errors=True)
print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
