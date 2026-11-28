#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""update_run.py: Settings → Update, done on the server by Looking Glass's own user (never root).

The web service cannot change its own code (its code folders are read-only for it). Settings writes a request,
data/update/request.json, and this runs as its own service, started by a path unit when the request appears
(deploy/update_helper.sh install, once, with sudo). Every step goes to data/update/log.jsonl and data/update/status.json,
so the page shows it live and the log survives the restart.

A request is {"kind": "check"} or {"kind": "update", "tag": "vYYYY.MM.DD[.N]", "by": "<full name>", "at": <time>}.
  check    lists the release tags on GitHub (git ls-remote) and says whether a newer one is out
  update   backup (manage/backup.sh), fetch the tag, check its signature against the maintainer's published key (the
           fingerprint in deploy/verify_install.py), move the code to it (fast-forward on the branch, else the tag),
           deploy/update_libraries.sh, deploy/reload.sh, health check; any step after the code moved that fails puts
           the previous release back the same way (code, libraries, restart)
Only a signed release newer than the installed one is ever installed, whatever the request says: a request file can
ask, never choose what runs. A request older than 15 minutes is ignored. One run at a time (a lock in data/update).

Run by hand (as the installation's user): deploy/update_run.py            take a waiting request
                                          deploy/update_run.py --check    the check, without Settings
It needs Python's standard library, git and ssh-keygen (as deploy/verify_install.py)."""
import fcntl
import json
import os
import re
import signal
import subprocess
import sys
import tempfile
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
PROJECT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import verify_install as VI  # noqa: E402

STATE = os.path.join(PROJECT, "data", "update")
REQUEST, STATUS, LOG, LOCK = (os.path.join(STATE, n) for n in ("request.json", "status.json", "log.jsonl", "lock"))
MAX_AGE = 15 * 60
KEEP_LOG_LINES = 2000
TIMEOUTS = {"backup": 1800, "libraries": 2400, "reload": 300, "git": 300}


def version_key(tag):
    """v2026.11.25.2 -> (2026, 11, 25, 2); anything else sorts first."""
    m = re.fullmatch(r"v(\d{4})\.(\d{1,2})\.(\d{1,2})(?:\.(\d{1,3}))?", tag or "")
    return tuple(int(x or 0) for x in m.groups()) if m else (0, 0, 0, 0)


class Run:
    def __init__(self, kind, tag="", by=""):
        self.kind, self.tag, self.by = kind, tag, by
        self.status = {"state": "running", "kind": kind, "tag": tag, "by": by, "started": round(time.time(), 3),
                       "ended": None, "step": "", "installed": "", "result": ""}
        self.killed = False
        os.makedirs(STATE, mode=0o700, exist_ok=True)

    # ---- what the page shows
    def say(self, msg, step=None, level="info"):
        if step:
            self.status["step"] = step
        line = {"t": round(time.time(), 3), "step": self.status["step"], "level": level, "msg": str(msg)[:2000]}
        with open(LOG, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(line, ensure_ascii=False) + "\n")
        self.save()
        print(f"[{line['step']}] {line['msg']}", flush=True)

    def save(self):
        tmp = f"{STATUS}.{os.getpid()}.tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(self.status, fh)
        os.replace(tmp, STATUS)

    def finish(self, state, result):
        self.status.update(state=state, result=result, ended=round(time.time(), 3))
        self.say(result, level="ok" if state == "done" else "bad")
        audit({"done": "update_done", "failed": "update_failed", "rolled_back": "update_rolled_back",
               "checked": "update_checked"}.get(state, "update_" + state), self.by, self.tag, result)

    # ---- running commands, every line of their output in the log
    def cmd(self, args, cwd=PROJECT, timeout=300, quiet=False):
        """(exit code, output). A step that runs longer than `timeout` is stopped, with everything it started, by a
        timer, also when it prints nothing (audit 2026-11-27: a silent hung git step was only checked when a line came,
        so it was never stopped, the lock stayed held and the page said "running" for good): 124."""
        env = dict(os.environ, GIT_TERMINAL_PROMPT="0", GIT_ASKPASS="true", LC_ALL="C", PYTHONUNBUFFERED="1")
        # its own process group, so the timer stops its children too (a child holding the output open would keep the
        # read below waiting after the step itself was stopped)
        p = subprocess.Popen(args, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=env,
                             start_new_session=True)
        stopped = threading.Event()

        def stop():
            stopped.set()
            self.killed = True              # a process this run started was killed (back() may then clear its git lock)
            try:
                os.killpg(p.pid, signal.SIGKILL)
            except OSError:
                try:
                    p.kill()
                except OSError:
                    pass
        timer = threading.Timer(timeout, stop)
        timer.daemon = True
        timer.start()
        out = []
        try:
            for line in p.stdout:
                line = line.rstrip()
                out.append(line)
                if not quiet and line:
                    self.say(line)
            rc = p.wait()
        finally:
            timer.cancel()
            if p.poll() is None:            # stopped by an error here (the log could not be written): never left running
                stop()
                p.wait()
        if stopped.is_set():
            took = f"{timeout // 60} minutes" if timeout >= 60 else f"{timeout} seconds"
            self.say(f"stopped: {' '.join(args[:2])} took longer than {took}", level="bad")
            return 124, "\n".join(out)
        return rc, "\n".join(out)


def audit(event, by, tag, detail):
    """The run in the audit log (the chain the service writes), with the platform's own Python."""
    py = os.path.join(PROJECT, ".venv", "bin", "python")
    code = ("import os,sys,time;sys.path.insert(0,sys.argv[1]);import audit_chain;"
            "audit_chain.Chain(os.path.join(sys.argv[1],'data','audit.log')).append({'t':round(time.time(),3),"
            "'event':sys.argv[2],'user':'Settings → Update','target':sys.argv[3],'detail':sys.argv[4]})")
    try:
        subprocess.run([py if os.path.exists(py) else sys.executable, "-c", code, PROJECT, event, tag or "",
                        (f"{detail} (asked by {by})" if by else detail)[:500]], timeout=60, capture_output=True)
    except (OSError, subprocess.SubprocessError):
        pass


def git_top():
    r = VI.git(["-C", PROJECT, "rev-parse", "--show-toplevel"], timeout=30)
    return r.stdout.strip() if r.returncode == 0 else ""


def dirty(top):
    """True when tracked files differ from HEAD (git status, untracked files left out), or git status could not tell."""
    r = VI.git(["-C", top, "status", "--porcelain", "--untracked-files=no"], timeout=TIMEOUTS["git"])
    return bool(r.returncode or r.stdout.strip())


def remove_added_untracked(top, prev, new):
    """After a roll back: the files `new` ADDS to `prev` that lie in the tree untracked (a stopped checkout had already
    written them) are removed: only paths in both lists, inside the folder, files and links only. Returns how many."""
    r = VI.git(["-C", top, "diff", "-z", "--name-only", "--diff-filter=A", prev, new], timeout=TIMEOUTS["git"])
    u = VI.git(["-C", top, "ls-files", "-z", "--others"], timeout=TIMEOUTS["git"])
    if r.returncode or u.returncode:
        return 0
    base = os.path.realpath(top)
    n = 0
    for rel in sorted(set(r.stdout.split("\0")) & set(u.stdout.split("\0")) - {""}):
        p = os.path.join(base, rel)
        if not os.path.realpath(os.path.dirname(p)).startswith(base + os.sep) and os.path.realpath(os.path.dirname(p)) != base:
            continue
        if os.path.islink(p) or os.path.isfile(p):
            os.remove(p)
            n += 1
    return n


def preflight(run):
    """The repository folder, or None (said why). Only an installation from a release is updated here."""
    if not os.path.isfile(os.path.join(PROJECT, ".release_fingerprints")):
        run.finish("failed", "Not updated: this folder was not installed from a release (no .release_fingerprints), "
                             "for example a developer's working copy. Its maintainer updates it.")
        return None
    top = git_top()
    if not top:
        run.finish("failed", "Not updated: the Looking Glass folder is not a git checkout (docs/INSTALLATION.md, Updating).")
        return None
    return top


def remote_tags(run):
    r = VI.git(["ls-remote", "--tags", "--refs", VI.REPO], timeout=TIMEOUTS["git"])
    if r.returncode:
        raise RuntimeError(f"GitHub could not be reached: {r.stderr.strip()[:300] or 'no answer'}")
    tags = [ln.split("refs/tags/", 1)[1] for ln in r.stdout.splitlines() if "refs/tags/" in ln]
    return sorted((t for t in tags if VI.TAG_RE.match(t) and version_key(t) > (0,)), key=version_key)


def check(run):
    top = preflight(run)
    if not top:
        return 1
    installed = VI.installed_tag(PROJECT)
    run.status["installed"] = installed
    run.say(f"installed: {installed or 'no release tag on this commit'}", step="check")
    try:
        tags = remote_tags(run)
    except RuntimeError as e:
        run.finish("failed", str(e))
        return 1
    newer = [t for t in tags if version_key(t) > version_key(installed)]
    run.status["newest"], run.status["newer"] = (tags[-1] if tags else ""), newer[-10:]
    run.finish("checked", f"A newer release is out: {newer[-1]}." if newer else "This is the newest release.")
    return 0


def update(run):
    top = preflight(run)
    if not top:
        return 1
    tag = run.tag
    if not VI.TAG_RE.match(tag or ""):
        run.finish("failed", "Not updated: no release was named.")
        return 1
    installed = VI.installed_tag(PROJECT)
    run.status["installed"] = installed
    run.say(f"from {installed or 'an untagged commit'} to {tag}", step="prepare")
    try:
        tags = remote_tags(run)
    except RuntimeError as e:
        run.finish("failed", f"Not updated: {e}")
        return 1
    if tag not in tags:
        run.finish("failed", f"Not updated: {tag} is not a release on GitHub.")
        return 1
    if version_key(tag) <= version_key(installed):
        run.finish("failed", f"Not updated: {tag} is not newer than the installed {installed}.")
        return 1
    rc, out = run.cmd(["git", "-C", top, "status", "--porcelain", "--untracked-files=no"], quiet=True)
    if rc or out.strip():
        run.finish("failed", "Not updated: shipped files were changed here (git status). Settings → Code check shows "
                             "which; put them back first.")
        return 1

    run.say("a backup first (manage/backup.sh)", step="backup")
    dest = os.path.join(PROJECT, "backups", "before-update-" + time.strftime("%Y%m%d-%H%M%S"))
    os.makedirs(dest, mode=0o700, exist_ok=True)
    rc, _ = run.cmd([os.path.join(PROJECT, "manage", "backup.sh"), dest], timeout=TIMEOUTS["backup"])
    if rc:
        run.finish("failed", "Not updated: the backup did not finish (above). Nothing was changed.")
        return 1

    run.say(f"fetching {tag} and checking its signature", step="signature")
    rc, _ = run.cmd(["git", "-C", top, "fetch", "-q", "--no-tags", VI.REPO, f"refs/tags/{tag}:refs/tags/{tag}"],
                    timeout=TIMEOUTS["git"])
    if rc:
        run.finish("failed", f"Not updated: {tag} could not be fetched. Nothing was changed.")
        return 1
    with tempfile.TemporaryDirectory(prefix="lg-update-") as tmp:
        allowed = os.path.join(tmp, "allowed_signers")
        try:
            n = VI.signers_file(VI.github_keys(), VI.KEY_FINGERPRINT, allowed)
        except (OSError, ValueError) as e:
            run.finish("failed", f"Not updated: the maintainer's signing keys could not be read ({type(e).__name__}). "
                                 "Nothing was changed.")
            return 1
        if not n:
            run.finish("failed", f"Not updated: no published signing key has the fingerprint {VI.KEY_FINGERPRINT}.")
            return 1
        kind = VI.git(["-C", top, "cat-file", "-t", f"refs/tags/{tag}"]).stdout.strip()
        r = VI.git(["-C", top, "-c", f"gpg.ssh.allowedSignersFile={allowed}", "verify-tag", f"refs/tags/{tag}"])
        said = (r.stderr + r.stdout).strip()
        if kind != "tag" or r.returncode or 'Good "git" signature' not in said or VI.KEY_FINGERPRINT not in said:
            run.finish("failed", f"Not updated: the signature of {tag} is NOT good. Nothing was changed. "
                                 "Tell the maintainer (SECURITY.md).")
            return 1
    run.say(f"signature: good, made with the key {VI.KEY_FINGERPRINT}")

    # the tree checked clean again just before the code moves: the backup can take up to 30 minutes, and an edit made
    # meanwhile must never be thrown away by a roll back's reset --hard (re-review of r1-2, 2026-11-28)
    if dirty(top):
        run.finish("failed", "Not updated: shipped files were changed here while the backup ran (git status). Nothing "
                             "was changed; Settings → Code check shows which.")
        return 1
    prev = VI.git(["-C", top, "rev-parse", "HEAD"]).stdout.strip()
    branch = VI.git(["-C", top, "symbolic-ref", "-q", "--short", "HEAD"]).stdout.strip()
    def back(why, interrupted=False, killed=False):
        """The previous release back: code, libraries, restart. Each step is tried even when one before it fails or
        stops with an error, and the run always ends "rolled_back" with what happened. interrupted: moving the code was
        stopped part way (killed by its time limit, or failed with the tree changed): the tracked files are put back by
        force (the tree was checked clean just before the move; audit 2026-11-28, r1-2), and files the release ADDS
        that the stopped step already wrote, untracked now, are removed (only those: never git clean), or every later
        update would refuse to overwrite them. killed: a git step this run started was killed, so the
        .git/index.lock it left is stale (its process group is gone) and removed; a lock not ours is never touched."""
        def step(args, timeout):
            try:
                return run.cmd(args, timeout=timeout)[0]
            except Exception as e:              # noqa: BLE001 (said in the log; the next step is still tried)
                try:
                    run.say(f"{' '.join(os.path.basename(a) for a in args[:1])} stopped by an error: {type(e).__name__}",
                            level="bad")
                except Exception:               # noqa: BLE001, S110 (the log itself could not be written)
                    pass
                return 1
        try:
            run.say(f"{why}: putting {installed or prev[:12]} back", step="roll back", level="bad")
        except Exception:                       # noqa: BLE001, S110 (the roll back matters more than its log line)
            pass
        if killed:
            try:
                gd = VI.git(["-C", top, "rev-parse", "--absolute-git-dir"], timeout=30).stdout.strip() or os.path.join(top, ".git")
                lock = os.path.join(gd, "index.lock")
                if os.path.exists(lock):
                    os.remove(lock)
                    run.say("removed the lock the stopped git step left (.git/index.lock)")
            except Exception:                   # noqa: BLE001, S110 (the reset below says what it could not do)
                pass
        if branch:
            step(["git", "-C", top, "reset", "-q", "--hard" if interrupted else "--keep", prev], TIMEOUTS["git"])
            if interrupted:                     # the checkout fallback may have left HEAD detached: the branch again
                step(["git", "-C", top, "checkout", "-q", branch], TIMEOUTS["git"])
        else:
            step(["git", "-C", top, "checkout", "-q", *(["-f"] if interrupted else []), "--detach", prev], TIMEOUTS["git"])
        if interrupted:
            try:
                n = remove_added_untracked(top, prev, f"refs/tags/{tag}")
                if n:
                    run.say(f"removed {n} file(s) of {tag} the stopped step had already written")
            except Exception:                   # noqa: BLE001, S110 (the next update's git status says what is left)
                pass
        step([os.path.join(PROJECT, "deploy", "update_libraries.sh")], TIMEOUTS["libraries"])
        rc2 = step([os.path.join(PROJECT, "deploy", "reload.sh")], TIMEOUTS["reload"])
        result = (f"Not updated ({why}). The previous release is back"
                  + (" and answering." if rc2 == 0 else ": it did NOT answer, look at the log and journalctl."))
        try:
            run.finish("rolled_back", result)
        except Exception:                       # noqa: BLE001 (the page must never stay "running": audit 2026-11-28, r1-7)
            try:
                run.status.update(state="rolled_back", result=result, ended=round(time.time(), 3))
                run.save()
            except Exception:                   # noqa: BLE001, S110 (nothing more can be written)
                pass
        return 1

    # from here on the code may have moved: an error (not only a failed step) puts the previous release back too
    # (audit 2026-11-27: an exception after the checkout left the new code with the old libraries, said "failed")
    run.killed = False
    try:
        run.say(f"moving the code to {tag}", step="code")
        rc = 1
        if branch:
            rc, _ = run.cmd(["git", "-C", top, "merge", "-q", "--ff-only", f"refs/tags/{tag}"], timeout=TIMEOUTS["git"])
        if rc and rc != 124:                    # a merge stopped by its time limit: no checkout over its half-moved tree
            rc, _ = run.cmd(["git", "-C", top, "checkout", "-q", "--detach", f"refs/tags/{tag}"], timeout=TIMEOUTS["git"])
        # a step stopped by its time limit (124) leaves a half-moved tree and .git/index.lock; a failed step that moved
        # HEAD, or left tracked files changed (128, a full disk), moved the code: all put the previous release back
        # (audit 2026-11-28, r1-2: it said "failed, nothing else was changed" and never rolled back)
        moved = rc and (rc == 124 or VI.git(["-C", top, "rev-parse", "HEAD"], timeout=30).stdout.strip() != prev or dirty(top))
    except Exception as e:                      # noqa: BLE001
        return back(f"moving the code stopped with an error: {type(e).__name__}", interrupted=True, killed=run.killed)
    if moved:
        return back("moving the code was stopped before it finished" if rc == 124 else "the code moved only part of the way",
                    interrupted=True, killed=run.killed)
    if rc:
        run.finish("failed", "Not updated: the code could not be moved to the release. Nothing else was changed.")
        return 1

    try:
        run.say("the libraries from the release's locks (deploy/update_libraries.sh)", step="libraries")
        rc, _ = run.cmd([os.path.join(PROJECT, "deploy", "update_libraries.sh")], timeout=TIMEOUTS["libraries"])
        if rc:
            return back("the libraries could not be installed")
        run.say("restarting Looking Glass (deploy/reload.sh)", step="restart")
        rc, _ = run.cmd([os.path.join(PROJECT, "deploy", "reload.sh")], timeout=TIMEOUTS["reload"])
    except Exception as e:                      # noqa: BLE001
        return back(f"stopped by an error: {type(e).__name__}: {str(e)[:200]}")
    if rc:
        return back("the new release did not answer")
    now = VI.installed_tag(PROJECT)
    run.status["installed"] = now
    run.finish("done", f"Updated to {now or tag}; Looking Glass answers. The backup is in {os.path.relpath(dest, PROJECT)}.")
    return 0


def take():
    """The waiting request (removed, so it runs once), or None."""
    try:
        with open(REQUEST, encoding="utf-8") as fh:
            req = json.load(fh)
    except (OSError, ValueError):
        req = None
    try:
        os.remove(REQUEST)
    except OSError:
        pass
    if not isinstance(req, dict) or req.get("kind") not in ("check", "update"):
        return None
    if time.time() - float(req.get("at") or 0) > MAX_AGE:
        return None
    return req


def trim_log():
    try:
        with open(LOG, encoding="utf-8") as fh:
            lines = fh.readlines()
        if len(lines) > KEEP_LOG_LINES:
            with open(LOG, "w", encoding="utf-8") as fh:
                fh.writelines(lines[-KEEP_LOG_LINES:])
    except OSError:
        pass


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    os.makedirs(STATE, mode=0o700, exist_ok=True)
    with open(LOCK, "w") as lk:
        try:
            fcntl.flock(lk, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            print("another update run is busy")
            return 2
        req = {"kind": "check", "at": time.time()} if argv[:1] == ["--check"] else take()
        if not req:
            print("no request waiting")
            return 0
        trim_log()
        run = Run(req["kind"], str(req.get("tag") or "")[:40], str(req.get("by") or "")[:120])
        run.say(f"{'Checking for a newer release' if run.kind == 'check' else 'Update to ' + run.tag} "
                f"(asked by {run.by or 'the server'})", step="start")
        try:
            return check(run) if run.kind == "check" else update(run)
        except Exception as e:                  # noqa: BLE001 (said on the page, never a silent stop)
            run.finish("failed", f"Stopped by an error: {type(e).__name__}: {str(e)[:300]}")
            return 1


if __name__ == "__main__":
    sys.exit(main())
