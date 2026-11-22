#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""Old code files on update (deploy/stale_files.py): code files a former release shipped and the new one no longer does
are moved aside to backups/stale-<time>/ with their relative paths, never deleted; files no release ever shipped are
never moved, only named; nothing else is touched.

A made-up installation in a temporary folder with a made-up release list and history list: a former file in static/js
and a former top-level .py are moved, listed files stay, an unknown file in every code folder (on neither list) stays
and is named, data/, .env*, .venv/.venvs, logs/, backups/, non-code folders and files this computer makes in the code
folders stay even when unlisted, symbolic links are never followed or moved; a missing, empty, cut-short or unsafe list
(.., absolute paths), and a tampered history list, move nothing; no history list (an older release) moves nothing and
names every unlisted file; LG_KEEP_STALE=1 and --dry-run move nothing; the maintainer's working copy is left alone; the
output names each file. The release builder's history (from the published repository's git history) is checked on a
small made-up repository. Also: the updater and the release builder use it, and both check lists run this check.
No database, no network. Run: .venv/bin/python tests/check_stale_files.py
"""
import glob
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(HERE, "deploy"))
import stale_files as SF  # noqa: E402

TOOL = os.path.join(HERE, "deploy", "stale_files.py")
checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{str(info)[:400]}]" if info and not cond else ""))


def put(root, rel, text="x\n"):
    p = os.path.join(root, *rel.split("/"))
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w", encoding="utf-8") as fh:
        fh.write(text)
    return p


def tool(folder, part, *extra, keep=False):
    env = {k: v for k, v in os.environ.items() if k != "LG_KEEP_STALE"}
    if keep:
        env["LG_KEEP_STALE"] = "1"
    args = [sys.executable, TOOL, "--folder", folder] + (["--part", part] if part else []) + list(extra)
    return subprocess.run(args, capture_output=True, text=True, env=env, timeout=120)


def exists(root, rel):
    return os.path.lexists(os.path.join(root, *rel.split("/")))


def stale_dirs(root):
    return sorted(glob.glob(os.path.join(root, "backups", "stale-*")))


SHIPPED = ["app.py", "auth.py", "static/js/app.js", "static/css/app.css", "templates/index.html", "tests/check_x.py",
           "tools/helper.py", "deploy/update_libraries.sh", "security_testing/security_retest.py", ".env.example",
           "data/issues.json", "requirements.lock"]
STALE = ["old_module.py", "static/js/signin-look.js"]          # former Looking Glass files: on the history list
HISTORY_ONLY = STALE + ["static/js/gone-long-ago.js", "tools/retired_tool.py"]   # shipped once; the last two not here
# on neither list: someone's own files, one in every platform code folder; never moved, always named
UNKNOWN = ["my_top.py", "static/js/mine.js", "static/css/mine.css", "templates/mine.html", "tests/check_mine.py",
           "tools/mine.py", "deploy/mine.sh", "security_testing/mine.py"]
# unlisted, but never touched: outside the code folders, or made by this computer inside them
PROTECTED = ["data/users.json", "data/tls/key.pem", ".env", ".env.before-install-1", ".venv/lib/site.py",
             ".venvs/venv-1/lib/mod.py", "logs/app.log", "backups/old/thing.py", "static/data/adm1/xx.json",
             "manage/my_own.sh", "notes.txt", "deploy/looking-glass.service", "tools/discovery.json",
             "tools/__pycache__/helper.cpython-312.pyc", "static/js/debug.log", "tools/.ruff_cache/cache.json",
             "tests/data/sample.json", "deploy/server.pem", "templates/.env.local"]

W = tempfile.mkdtemp(prefix="lg-stale-check-")
try:
    # the release: the shipped files and their list (written by the same function the release builder uses)
    rel_dir = os.path.join(W, "release")
    for r in SHIPPED:
        put(rel_dir, r)
    n = SF.write_list(rel_dir, history=HISTORY_ONLY)
    listed = open(os.path.join(rel_dir, SF.LIST_NAME), encoding="utf-8").read()
    hist_text = open(os.path.join(rel_dir, SF.HISTORY_NAME), encoding="utf-8").read()
    nh = len(set(SHIPPED) | set(HISTORY_ONLY))

    def install(name="pf"):
        root = os.path.join(W, name)
        shutil.rmtree(root, ignore_errors=True)
        for r in SHIPPED + STALE + PROTECTED + UNKNOWN:
            put(root, r, f"content of {r}\n")
        for lst in (SF.LIST_NAME, SF.HISTORY_NAME):
            shutil.copy2(os.path.join(rel_dir, lst), os.path.join(root, lst))
        outside = os.path.join(W, "outside")
        put(outside, "target.js", "outside file\n")
        put(outside, "dir/inner.py", "outside module\n")
        os.symlink(os.path.join(outside, "target.js"), os.path.join(root, "static", "js", "link.js"))
        os.symlink(os.path.join(outside, "dir"), os.path.join(root, "tools", "linked_dir"))
        os.symlink(os.path.join(outside, "dir", "inner.py"), os.path.join(root, "linked_top.py"))
        return root

    print("1. The list")
    ok(f"the list names every shipped file, with a count line ({n} files)",
       n == len(SHIPPED) and f"# files: {n}\n" in listed and all(r + "\n" in listed for r in SHIPPED), listed)
    ok("read back exactly", SF.read_list(rel_dir) == set(SHIPPED))
    ok(f"the history list: every former file plus the current ones, sorted, with a count line ({nh} files)",
       SF.read_list(rel_dir, SF.HISTORY_NAME) == set(SHIPPED) | set(HISTORY_ONLY) and f"# files: {nh}\n" in hist_text
       and [x for x in hist_text.splitlines() if not x.startswith("#")] == sorted(set(SHIPPED) | set(HISTORY_ONLY)), hist_text)
    # the staging step writes the lists again after held files are copied in (--write-list): the history kept, the
    # new current file added, so the history still holds every current file
    put(rel_dir, "static/js/held-new.js")
    r = tool(rel_dir, None, "--write-list")
    ok("--write-list again (a held file added): history keeps the former files and gains the new current file",
       r.returncode == 0 and SF.read_list(rel_dir, SF.HISTORY_NAME) == set(SHIPPED) | set(HISTORY_ONLY) | {"static/js/held-new.js"}
       and SF.read_list(rel_dir) == set(SHIPPED) | {"static/js/held-new.js"}, r.stdout + r.stderr)
    os.remove(os.path.join(rel_dir, "static", "js", "held-new.js"))
    SF.write_list(rel_dir, history=HISTORY_ONLY)

    print("\n2. Listing first, LG_KEEP_STALE=1, then moving")
    pf = install()
    r = tool(pf, "platform", "--dry-run")
    ok("--dry-run: names both old files and moves nothing",
       r.returncode == 0 and all(s in r.stdout for s in STALE) and "nothing moved" in r.stdout
       and all(exists(pf, s) for s in STALE) and not stale_dirs(pf), r.stdout + r.stderr)
    r = tool(pf, "platform", keep=True)
    ok("LG_KEEP_STALE=1: names both, keeps both, nothing moved aside",
       r.returncode == 0 and all(s in r.stdout for s in STALE) and "LG_KEEP_STALE=1" in r.stdout
       and all(exists(pf, s) for s in STALE) and not stale_dirs(pf), r.stdout + r.stderr)
    r = tool(pf, "platform")
    d = stale_dirs(pf)
    ok("the update: exit 0, one dated folder backups/stale-<date>-<time>",
       r.returncode == 0 and len(d) == 1 and len(os.path.basename(d[0])) == len("stale-20261121-153000"), (r.stdout + r.stderr, d))
    dest = d[0] if d else os.path.join(W, "none")
    ok("the unlisted static/js file and the top-level .py are moved there with their relative paths",
       all(not exists(pf, s) and os.path.isfile(os.path.join(dest, *s.split("/"))) for s in STALE)
       and open(os.path.join(dest, "static", "js", "signin-look.js")).read() == "content of static/js/signin-look.js\n")
    ok("the output names each moved file and where they went", all(f"  {s}" in r.stdout for s in STALE) and dest in r.stdout, r.stdout)
    ok("moved.log there lists them, and only them", sorted(ln.strip() for ln in open(os.path.join(dest, "moved.log")) if not ln.startswith("#")) == sorted(STALE))
    ok("a file on neither list in EVERY platform code folder (top-level .py, static/js, static/css, templates, tests, "
       "tools, deploy, security_testing): never moved, its content unchanged, each named as left in place",
       all(open(os.path.join(pf, *u.split("/"))).read() == f"content of {u}\n" for u in UNKNOWN)
       and all(f"Not part of Looking Glass, left in place: {u}" in r.stdout for u in UNKNOWN)
       and not any(os.path.lexists(os.path.join(dest, *u.split("/"))) for u in UNKNOWN), r.stdout)
    ok("…and the update says plainly that this is normal (own scripts, new work not released yet)",
       f"({len(UNKNOWN)} file(s) above: no Looking Glass release has shipped them, so they are never moved." in r.stdout
       and "normal for your own scripts and for new work not released yet" in r.stdout, r.stdout)
    ok("every listed file is untouched", all(open(os.path.join(pf, *s.split("/"))).read() == f"content of {s}\n" for s in SHIPPED))
    left = [p for p in PROTECTED if not exists(pf, p)]
    ok("data/, .env*, .venv, .venvs, logs, backups, non-code folders and this computer's files: untouched", not left, left)
    ok("symbolic links: neither moved nor followed (their targets are untouched)",
       os.path.islink(os.path.join(pf, "static", "js", "link.js")) and os.path.islink(os.path.join(pf, "linked_top.py"))
       and os.path.islink(os.path.join(pf, "tools", "linked_dir"))
       and os.path.isfile(os.path.join(W, "outside", "target.js")) and os.path.isfile(os.path.join(W, "outside", "dir", "inner.py"))
       and not glob.glob(os.path.join(dest, "**", "*inner*"), recursive=True)
       and not glob.glob(os.path.join(dest, "**", "link*"), recursive=True))
    r = tool(pf, "platform")
    ok("run again: nothing left to move, no new folder, the unknown files still named and in place",
       r.returncode == 0 and "none;" in r.stdout and len(stale_dirs(pf)) == 1
       and all(f"left in place: {u}" in r.stdout and exists(pf, u) for u in UNKNOWN), r.stdout)

    print("\n3. Lists that move nothing")

    def refused_case(label, list_text=None, expect=SF.REFUSED, word="nothing moved", setup=None, history_text=None,
                     named=()):
        root = install()
        if list_text is not None:
            with open(os.path.join(root, SF.LIST_NAME), "w", encoding="utf-8") as fh:
                fh.write(list_text)
        if history_text is not None:
            with open(os.path.join(root, SF.HISTORY_NAME), "w", encoding="utf-8") as fh:
                fh.write(history_text)
        if setup:
            setup(root)
        r = tool(root, "platform")
        ok(label, r.returncode == expect and word in r.stdout and all(exists(root, s) for s in STALE + UNKNOWN)
           and not stale_dirs(root) and all(f"left in place: {x}" in r.stdout for x in named),
           (r.returncode, r.stdout + r.stderr))

    hist_lines = [x for x in hist_text.splitlines() if not x.startswith("#")]
    refused_case("no history list (an older release): nothing moved, every unlisted code file named as left in place",
                 expect=0, word="nothing moved", named=STALE + UNKNOWN,
                 setup=lambda root: os.remove(os.path.join(root, SF.HISTORY_NAME)))
    refused_case("a tampered history list (a line added, count unchanged): refused",
                 history_text=hist_text + "my_top.py\n")
    refused_case("a history list with ../ in a path: refused",
                 history_text=hist_text.replace(f"# files: {nh}", f"# files: {nh + 1}") + "../outside/target.js\n")
    refused_case("a history list lacking a file of the current list (count adjusted): refused",
                 history_text=f"{SF.HISTORY_HEADER}\n# files: {nh - 1}\n" + "".join(x + "\n" for x in hist_lines if x != "app.py"),
                 word=SF.HISTORY_NAME)

    refused_case("no list: says so, nothing moved", expect=0, word="no release file list",
                 setup=lambda root: os.remove(os.path.join(root, SF.LIST_NAME)))
    refused_case("an empty list (header only): says so, nothing moved", f"{SF.HEADER}\n# files: 0\n", expect=0, word="lists nothing")
    refused_case("a list with ../ in a path: refused", listed.replace(f"# files: {n}", f"# files: {n + 1}") + "../outside/target.js\n")
    refused_case("a list with an absolute path: refused", listed.replace(f"# files: {n}", f"# files: {n + 1}") + "/etc/passwd\n")
    refused_case("a list cut short (count does not match): refused", "\n".join(listed.splitlines()[:-3]) + "\n")
    refused_case("a listed file missing (the release not fully in place): refused",
                 setup=lambda root: os.remove(os.path.join(root, "auth.py")))
    refused_case("the maintainer's working copy (tools/release_root): left alone", expect=0, word="maintainer",
                 setup=lambda root: os.makedirs(os.path.join(root, "tools", "release_root")))

    def refuses(lines):
        d = os.path.join(W, "direct")
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, SF.LIST_NAME), "w", encoding="utf-8") as fh:
            fh.write(f"# files: {len(lines)}\n" + "".join(x + "\n" for x in lines))
        try:
            SF.read_list(d)
            return False
        except SF.ListRefused:
            return True
    bad = [["a.py", "static/../../x.py"], ["a.py", "/abs.py"], ["a.py", "C:/x.py"], ["a.py", "static\\js\\x.js"],
           ["a.py", "static//x.js"], ["a.py", "./a.py"]]
    ok("read_list refuses '..', absolute, backslash, empty and '.' parts", all(refuses(b) for b in bad),
       [b for b in bad if not refuses(b)])

    print("\n4. The database pipeline's folder")
    db_rel = os.path.join(W, "db-release")
    for rr in ("shadowserver_pipeline.py", "deploy.sh", "tests/test_a.py", "bin/shadowserver", "requirements.lock"):
        put(db_rel, rr)
    db_former = ("mongo_added_json.py", "old_tool.sh", "tests/test_old.py", "bin/old-helper")
    db_unknown = ("my_tool.py", "my_tool.sh", "tests/test_mine.py", "bin/mine")    # every database code folder
    SF.write_list(db_rel, history=db_former)
    db = os.path.join(W, "db")
    for rr in ("shadowserver_pipeline.py", "deploy.sh", "tests/test_a.py", "bin/shadowserver", "requirements.lock",
               ".env", "secrets/gmail.json", "backups/r.zip", "logs/run.log", "attachments_backup/a.zip",
               ".pipeline_state.sqlite") + db_former + db_unknown:
        put(db, rr)
    for lst in (SF.LIST_NAME, SF.HISTORY_NAME):
        shutil.copy2(os.path.join(db_rel, lst), os.path.join(db, lst))
    r = tool(db, "database")
    d = stale_dirs(db)
    ok("former top-level .py and .sh files, a former test and a former bin/ script are moved aside",
       r.returncode == 0 and len(d) == 1 and all(os.path.isfile(os.path.join(d[0], *x.split("/"))) and not exists(db, x)
                                                 for x in db_former), r.stdout + r.stderr)
    ok("a file on neither list in every database code folder (top-level .py and .sh, tests, bin): kept and named",
       all(exists(db, x) and f"Not part of Looking Glass, left in place: {x}" in r.stdout for x in db_unknown)
       and not any(os.path.lexists(os.path.join(d[0] if d else W, *x.split("/"))) for x in db_unknown), r.stdout)
    ok(".env, secrets/, backups/, logs/, the mail folders and the state file: untouched",
       all(exists(db, x) for x in (".env", "secrets/gmail.json", "backups/r.zip", "logs/run.log", "attachments_backup/a.zip",
                                   ".pipeline_state.sqlite", "shadowserver_pipeline.py", "bin/shadowserver")))

    print("\n5. Wired in")
    up = open(os.path.join(HERE, "deploy", "update_libraries.sh"), encoding="utf-8").read()
    ok("deploy/update_libraries.sh runs it for the platform and the pipeline, after the libraries",
       'stale_files.py" --folder "$1" --part "$2"' in up and 'stale "$project" platform' in up and 'stale "$db" database' in up
       and up.find('stale "$project" platform') > up.find('update "$project" platform'))
    mr_path = os.path.join(HERE, "tools", "make_release.py")
    if os.path.isfile(mr_path) and os.path.isdir(os.path.join(HERE, "tools", "release_root")):   # the development tree only
        mr = open(mr_path, encoding="utf-8").read()
        ok("the release builder writes both lists for platform/ and database/ with the same module",
           "stale_files.write_list(" in mr and "history=hist" in mr and '("platform", "database")' in mr)
        wf = open(os.path.join(HERE, "tools", "release_root", ".github", "workflows", "checks.yml"), encoding="utf-8").read()
        ok("the GitHub checks run this check", "check_stale_files" in wf)
    ra = open(os.path.join(HERE, "tests", "run_all_checks.sh"), encoding="utf-8").read()
    ok("run_all_checks.sh runs this check", "tests/check_stale_files.py" in ra)
    gi = os.path.join(HERE, ".gitignore")
    ok("the platform's .gitignore keeps backups/ out of the repository", os.path.isfile(gi) and "\nbackups/\n" in open(gi).read())
    if os.path.isfile(mr_path) and os.path.isdir(os.path.join(HERE, "tools", "release_root")) and shutil.which("git"):
        print("\n6. The release builder's history, from a made-up published repository")
        import importlib.util
        spec = importlib.util.spec_from_file_location("make_release_under_test", mr_path)
        MR = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(MR)
        repo = os.path.join(W, "published")
        os.makedirs(repo)
        genv = {**os.environ, "HOME": W, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid",
                "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid"}

        def git(*args):
            return subprocess.run(["git", "-C", repo, *args], capture_output=True, text=True, env=genv, timeout=60)
        git("init", "-q")
        for f in ("platform/app.py", "platform/static/js/signin-look.js", "database/mongo_added_json.py", "docs/x.md"):
            put(repo, f)
        git("add", "-A")
        git("commit", "-q", "-m", "first")
        os.remove(os.path.join(repo, "platform", "static", "js", "signin-look.js"))
        put(repo, "platform/audit_page.py")
        git("add", "-A")
        c2 = git("commit", "-q", "-m", "second")
        hp, src = MR.release_history(repo, "platform")
        hd, _ = MR.release_history(repo, "database")
        ok("two commits: a file added then removed is still in the history; prefixes stripped; other folders left out",
           c2.returncode == 0 and hp == {"app.py", "static/js/signin-look.js", "audit_page.py"} and hd == {"mongo_added_json.py"}
           and "git history" in src, (c2.stderr, hp, hd, src))
        nogit = os.path.join(W, "no-repo")
        os.makedirs(os.path.join(nogit, "platform"))
        h0, src0 = MR.release_history(nogit, "platform")
        hprev, srcp = MR.release_history(nogit, "platform", previous={"old.py"})
        ok("no published repository: the previous release's history if given, else this release's files only (said so)",
           h0 == set() and "only" in src0 and hprev == {"old.py"} and "previous" in srcp, (h0, src0, hprev, srcp))
finally:
    shutil.rmtree(W, ignore_errors=True)


def first(*cands):
    return next((p for p in cands if os.path.isfile(p)), "")


# the documentation says it, where people look (the published repository, else the development tree)
inst = first(os.path.join(HERE, "..", "docs", "INSTALLATION.md"), os.path.join(HERE, "docs", "INSTALLATION.md"))
tech = first(os.path.join(HERE, "..", "docs", "TECHNICAL_REFERENCE.md"), os.path.join(HERE, "docs", "TECHNICAL_REFERENCE.md"))
chlog = first(os.path.join(HERE, "..", "CHANGELOG.md"), os.path.join(HERE, "tools", "release_root", "CHANGELOG.md"))
it = open(inst, encoding="utf-8").read() if inst else ""
ok("INSTALLATION (Updating) says old files are moved aside, never deleted, how to keep them, and what is never touched",
   "**Old files are moved aside.**" in it and "backups/stale-<date>-<time>/" in it and "LG_KEEP_STALE=1" in it
   and "Nothing is deleted" in it and "never touched" in it, inst or "INSTALLATION.md not found")
ok("TECHNICAL_REFERENCE describes .release_files and deploy/stale_files.py",
   bool(tech) and ".release_files" in open(tech, encoding="utf-8").read() and "deploy/stale_files.py" in open(tech, encoding="utf-8").read())
ok("the CHANGELOG has it (Updating tidies old files)",
   bool(chlog) and "Updating tidies old files" in open(chlog, encoding="utf-8").read())

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
