#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""The pipeline fixes of the second code review of the report pipeline (r2, 2026-11-28). Each check fails on the code
before the fix.

  r2-1  a file quarantined after it stopped the loader (some of its rows stored) is loaded again when moved back
  r2-2  one stop of the worker when a file is loaded alone is a file error, tried again; quarantined on the second run
  r2-3  the run lock is opened read-only and readable by others (0644), also when the file cannot be written
  r2-4  the inherited run lock is found by LG_RUN_LOCK_FD (run.sh exports it), /proc/self/fd only as the fallback;
        run.sh and `shadowserver status` open the lock read-only, make it 0644 and never follow a symbolic link
  r2-5  the IMAP UID is found before or after the literal; a forged Message-ID such as "7:102" is never taken for a UID
  r2-6  a message deleted between the listing and the fetch is a warning (gone), a refused batch stays an error
  r2-7  SORTED_KEEP_DAYS also removes the sorted copies of files loaded with no row to store
  r2-8  store_mongo_admin.sh --check: a refused (plaintext, remote) stored account says how to store it again
  r2-9  SORTED_KEEP_DAYS keeps the sorted copy of a file moved back from quarantine until it is loaded whole
  r2-10 the quarantine note names the exact path (own name) to move a file back to
Made-up files in temporary folders, an in-memory stand-in for MongoDB, a fake mail server, a fake sudo: no database,
no mailbox, no network.
Run: .venv/bin/python tests/test_fix_r2.py"""
import fcntl
import os
import shutil
import subprocess
import sys
import tempfile
import time
import types
from collections import Counter
from concurrent.futures import Future, ThreadPoolExecutor
from concurrent.futures.process import BrokenProcessPool
from pathlib import Path
from unittest import mock

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
import mail_sources  # noqa: E402
import shadowserver_pipeline as sp  # noqa: E402
import zip_limits  # noqa: E402
from pymongo.errors import BulkWriteError  # noqa: E402

checks, fails = 0, []
TMP = tempfile.mkdtemp(prefix="lg-fix-r2-")


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info and not cond else ""), flush=True)


def attempt(label, fn):
    """Run one group of checks; an exception (the old code's crash) is a failed check, not the end of the test."""
    try:
        fn()
    except Exception as exc:  # noqa: BLE001
        ok(f"{label}: ran without an error", False, f"{exc.__class__.__name__}: {str(exc)[:200]}")


def tmpdir(name):
    d = os.path.join(TMP, name)
    os.makedirs(d, exist_ok=True)
    return d


HEAD = '"timestamp","ip","port","asn"\n'


def rows(n, day="20"):
    return HEAD + "".join(f'"2026-11-{day} 01:00:{i:02d}","192.0.2.{i + 1}",23,64500\n' for i in range(n))


# ------------------------------------------------------------------ an in-memory MongoDB, just what the loader uses
class Coll:
    def __init__(self, name):
        self.name, self.docs, self.keys = name, [], set()

    def create_index(self, *a, **k):
        return "ix"

    def distinct(self, field):
        return sorted({d.get(field) for d in self.docs})

    def find(self, flt=None, proj=None):
        return [dict(d) for d in self.docs]

    def count_documents(self, flt):
        ids = set(map(str, (flt.get("_id") or {}).get("$in", [])))
        return sum(1 for d in self.docs if str(d.get("_id")) in ids)

    def insert_many(self, docs, ordered=False):
        errs, n = [], 0
        ids = {str(x.get("_id")) for x in self.docs}
        for i, d in enumerate(docs):
            d.setdefault("_id", f"oid-{id(d)}")
            key = (d.get("filename"), d.get("category"), d.get("line_hash"))
            if ("line_hash" in d and key in self.keys) or str(d["_id"]) in ids:
                errs.append({"index": i, "code": 11000, "errmsg": "duplicate"})
            else:
                ids.add(str(d["_id"]))
                self.keys.add(key)
                self.docs.append(dict(d))
                n += 1
        if errs:
            raise BulkWriteError({"writeErrors": errs, "nInserted": n})
        return type("R", (), {"inserted_ids": [0] * n})()

    def update_one(self, *a, **k):
        return None

    def bulk_write(self, ops, ordered=False):
        return None


class DB(dict):
    def __missing__(self, name):
        c = self[name] = Coll(name)
        return c


class Client:
    def __init__(self, db):
        self.db = db
        self.admin = type("A", (), {"command": staticmethod(lambda *a, **k: {"ok": 1})})()

    def __getitem__(self, name):
        return self.db

    def close(self):
        pass


def settings(base, workers=1):
    return sp.Settings(env_file=Path(base) / ".env", imap_server="", imap_user="", imap_password="", imap_folder="inbox",
                       imap_verify_tls=True, mongo={}, mongo_db="x", mongo_cache_gb=0.25, base_dir=Path(base),
                       workers=workers, insert_chunk=2, download_threads=1, fetch_batch=5, days=1)


class PartCrashPool(ThreadPoolExecutor):
    """A pool whose worker 'dies' (as the kernel ends one out of memory) on a file with 'bomb' in its name while CRASH
    is on, after it stored the first 2 rows of the file. Other files load before submit returns (no thread timing)."""
    CRASH = True
    db = None

    def __init__(self, max_workers=None, initializer=None, initargs=()):
        self.initializer, self.initargs = initializer, initargs

    def submit(self, fn, *args, **kw):
        f = Future()
        category, path, name = args[0], args[1], args[2]
        if "bomb" in name and PartCrashPool.CRASH:
            docs = list(sp.iter_csv_docs(path, name, category))[:2]
            try:
                PartCrashPool.db[category].insert_many(docs, ordered=False)
            except BulkWriteError:
                pass                                   # stored on an earlier attempt already
            f.set_exception(BrokenProcessPool("A process in the process pool was terminated abruptly"))
            return f
        if self.initializer:
            self.initializer(*self.initargs)
        try:
            f.set_result(fn(*args, **kw))
        except Exception as exc:  # noqa: BLE001
            f.set_exception(exc)
        return f

    def shutdown(self, wait=True, cancel_futures=False):
        pass


def run_load(s, db):
    stats = Counter()
    PartCrashPool.db = db

    def init(*_a):
        sp._WORKER_DB = db
    with mock.patch.object(sp, "mongo_client", lambda *a, **k: Client(db)), \
            mock.patch.object(sp, "ProcessPoolExecutor", PartCrashPool), \
            mock.patch.object(sp, "_init_worker", init):
        sp.load_into_mongo(s, stats)
    return stats


BOMB = "2026-11-22-scan_x-bomb-kenya-geo.csv"


def bomb_setup(name):
    base = tmpdir(name)
    s = settings(base, workers=2)
    d = s.sorting_dir / "scan_x"
    d.mkdir(parents=True)
    (d / "2026-11-20-scan_x-kenya-geo.csv").write_text(rows(1), encoding="utf-8")
    (d / BOMB).write_text(rows(5, "22"), encoding="utf-8")
    return base, s, d


def stored(db, fn):
    return sum(1 for x in db["scan_x"].docs if x.get("filename") == fn)


# ================================================================== r2-1
def t_r2_1():
    print("r2-1: a quarantined file moved back is loaded again")
    base, s, d = bomb_setup("r2-1")
    db = DB()
    q = Path(base) / "quarantine" / "loader" / "scan_x" / BOMB
    PartCrashPool.CRASH = True
    quarantining = None
    for _ in range(3):                                # quarantined after one run (old) or two (new)
        st = run_load(s, db)
        if q.exists():
            quarantining = st
            break
    ok("(the file that stops its worker is quarantined, with 2 of its 5 rows stored before it stopped)",
       quarantining is not None and stored(db, BOMB) == 2, f"stored {stored(db, BOMB)}")
    if quarantining is None:
        return
    reason = q.with_name(q.name + ".reason.txt").read_text(encoding="utf-8")
    ok("...the note in quarantine says some rows may already be stored", "may already be stored" in reason, reason)
    errs = sp.run_problems(quarantining)[0]
    ok("...and so does the bell's text", any(e["key"] == "files_crashed" and "may already be stored" in e["text"]
                                            for e in errs), str(errs)[:300])
    shutil.move(str(q), str(d / BOMB))                # the analyst moves it back, as the note says
    PartCrashPool.CRASH = False
    st = run_load(s, db)
    ok("moved back, the next run loads it again: all 5 rows stored, the 2 already there skipped",
       stored(db, BOMB) == 5 and st["files_loaded"] == 1 and st["rows_inserted"] == 3 and st["rows_duplicates"] == 2,
       f"stored {stored(db, BOMB)}, {dict(st)}"[:300])
    st = run_load(s, db)
    ok("...and once loaded whole, the run after that does not read it again",
       st["files_loaded"] == 0 and st["files_already_loaded"] == 2, str(dict(st))[:200])


# ================================================================== r2-2
def t_r2_2():
    print("r2-2: one stop of the worker alone is not a quarantine yet")
    base, s, d = bomb_setup("r2-2a")
    db = DB()
    q = Path(base) / "quarantine" / "loader" / "scan_x" / BOMB
    PartCrashPool.CRASH = True
    st = run_load(s, db)
    j = sp.Journal(s.journal_path)
    pend = j.pending()
    j.close()
    ok("first run: a file error, tried again next run; not quarantined, kept in the journal",
       st["file_errors"] == 1 and st["files_crashed"] == 0 and (d / BOMB).exists() and not q.exists()
       and ("scan_x", BOMB) in pend, f"{dict(st)} pending={pend}"[:300])
    errs = sp.run_problems(st)[0]
    ok("...an error of the run (file_errors), the other file loaded",
       any(e["key"] == "file_errors" for e in errs) and st["files_loaded"] == 1, str(errs)[:200])
    st = run_load(s, db)
    ok("second run, it stops its worker alone again: quarantined now, and counted",
       st["files_crashed"] == 1 and q.exists() and not (d / BOMB).exists(), str(dict(st))[:300])

    base, s, d = bomb_setup("r2-2b")
    db = DB()
    PartCrashPool.CRASH = True
    run_load(s, db)
    PartCrashPool.CRASH = False                       # the memory was short only on that run
    st = run_load(s, db)
    j = sp.Journal(s.journal_path)
    left = j.crash_names() if hasattr(j, "crash_names") else None
    pend = j.pending()
    j.close()
    ok("a file that stopped its worker on one run only loads on the next: all its rows, nothing quarantined",
       stored(db, BOMB) == 5 and st["files_crashed"] == 0 and st["file_errors"] == 0 and (d / BOMB).exists()
       and ("scan_x", BOMB) not in pend, f"stored {stored(db, BOMB)} {dict(st)}"[:300])
    ok("...and its count of stops is cleared once it loaded", left == set(), str(left))


# ================================================================== r2-3
def t_r2_3():
    print("r2-3: the run lock: read-only, readable by others")
    root = tmpdir("r2-3")
    p = os.path.join(root, ".pipeline.lock")
    old = os.umask(0o077)                             # as the pipeline's main() sets it
    try:
        fd = sp.hold_run_lock(p)
    finally:
        os.umask(old)
    try:
        mode = os.stat(p).st_mode & 0o777
        acc = fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE if fd is not None else None
        ok("created 0644 (the platform, another Linux user, can open it to see a run is busy), also under umask 077",
           mode == 0o644, oct(mode))
        ok("...opened read-only (flock needs no write access)", acc == os.O_RDONLY, str(acc))
    finally:
        if fd is not None:
            os.close(fd)
    p2 = os.path.join(root, "readonly.lock")
    open(p2, "w").close()
    os.chmod(p2, 0o444)                               # a lock file this account cannot write (left by root, say)
    try:
        fd = sp.hold_run_lock(p2)
        res = fd is not None
        if fd is not None:
            os.close(fd)
    except OSError as exc:
        res = f"{exc.__class__.__name__}: {exc}"
    ok("a lock file the run cannot write no longer stops the run (it takes the lock)", res is True, str(res))
    p3 = os.path.join(root, "link.lock")
    os.symlink(os.path.join(root, "elsewhere"), p3)
    try:
        sp.hold_run_lock(p3)
        refused = False
    except OSError:
        refused = True
    ok("...a symbolic link in its place is still refused (O_NOFOLLOW kept)", refused and not os.path.exists(
        os.path.join(root, "elsewhere")))


# ================================================================== r2-4
def t_r2_4():
    print("r2-4: the inherited run lock by LG_RUN_LOCK_FD")
    root = tmpdir("r2-4")
    p = os.path.join(root, ".pipeline.lock")
    fd0 = os.open(p, os.O_RDONLY | os.O_CREAT, 0o644)
    fcntl.flock(fd0, fcntl.LOCK_EX)                   # as run.sh holds it on descriptor 9
    real_isdir = os.path.isdir
    keep = os.environ.get("LG_RUN_LOCK_FD")
    try:
        os.environ["LG_RUN_LOCK_FD"] = str(fd0)
        with mock.patch("os.path.isdir", lambda x: False if str(x) == "/proc/self/fd" else real_isdir(x)):
            got = sp.hold_run_lock(p)
        ok("without /proc/self/fd, LG_RUN_LOCK_FD names the inherited descriptor: it is used", got == fd0, str(got))
        other = os.open(os.path.join(root, "unrelated"), os.O_RDONLY | os.O_CREAT, 0o644)
        os.environ["LG_RUN_LOCK_FD"] = str(other)
        p2 = os.path.join(root, "free.lock")
        got = sp.hold_run_lock(p2)
        ok("...a descriptor of another file in LG_RUN_LOCK_FD is not taken for the lock", got not in (None, other), str(got))
        if got not in (None, other):
            os.close(got)
        os.close(other)
    finally:
        os.close(fd0)
        if keep is None:
            os.environ.pop("LG_RUN_LOCK_FD", None)
        else:
            os.environ["LG_RUN_LOCK_FD"] = keep
    # run.sh itself: it exports LG_RUN_LOCK_FD=9, holds descriptor 9 read-only, and the lock file is 0644
    for name, pre in (("r2-4-run", None), ("r2-4-run-ro", 0o444), ("r2-4-run-600", 0o600)):
        d = tmpdir(name)
        shutil.copy(os.path.join(HERE, "run.sh"), os.path.join(d, "run.sh"))
        os.makedirs(os.path.join(d, ".venv", "bin"))
        fake = os.path.join(d, ".venv", "bin", "python")
        with open(fake, "w", encoding="utf-8") as fh:
            fh.write('#!/bin/bash\necho "fd=${LG_RUN_LOCK_FD:-unset}"\necho "mode=$(stat -c %a .pipeline.lock)"\n'
                     'grep -E "^flags:" /proc/$$/fdinfo/9\n')
        os.chmod(fake, 0o755)
        if pre is not None:
            open(os.path.join(d, ".pipeline.lock"), "w").close()
            os.chmod(os.path.join(d, ".pipeline.lock"), pre)
        r = subprocess.run(["bash", os.path.join(d, "run.sh"), "--stage", "load"], capture_output=True, text=True,
                           timeout=60, cwd=d)
        out = r.stdout + r.stderr
        flags = next((ln.split()[1] for ln in out.splitlines() if ln.startswith("flags:")), None)
        rdonly = flags is not None and int(flags, 8) & 3 == os.O_RDONLY
        if pre is None:
            ok("run.sh: the pipeline is told LG_RUN_LOCK_FD=9, descriptor 9 is read-only, the lock file 0644",
               r.returncode == 0 and "fd=9" in out and "mode=644" in out and rdonly, out[-300:])
        elif pre == 0o444:
            ok("...and run.sh runs with a lock file it cannot write (left by root, say)",
               r.returncode == 0 and "fd=9" in out and rdonly, out[-300:])
        else:
            ok("...a lock file of its own left 0600 (by an older version) is made 0644 again by run.sh",
               r.returncode == 0 and "mode=644" in out, out[-300:])
    d = tmpdir("r2-4-run-link")
    shutil.copy(os.path.join(HERE, "run.sh"), os.path.join(d, "run.sh"))
    os.symlink(os.path.join(d, "elsewhere"), os.path.join(d, ".pipeline.lock"))
    r = subprocess.run(["bash", os.path.join(d, "run.sh")], capture_output=True, text=True, timeout=60, cwd=d)
    ok("...run.sh refuses a symbolic link in the lock's place (and makes nothing through it)",
       r.returncode != 0 and not os.path.exists(os.path.join(d, "elsewhere")), (r.stdout + r.stderr)[-200:])


def shadowserver_cmd():
    """bin/shadowserver: the held copy (LG_HELD_DIR/pipe_new/shadowserver) when there is one, else the tree's."""
    held = os.path.join(os.environ.get("LG_HELD_DIR", ""), "pipe_new", "shadowserver")
    return held if os.environ.get("LG_HELD_DIR") and os.path.isfile(held) else os.path.join(HERE, "bin", "shadowserver")


def t_r2_4_status():
    print("r2-4: shadowserver status reads the run lock as run.sh takes it")
    fb = tmpdir("r2-4s-bin")
    for name, body in (("systemctl", 'echo inactive\n'), ("crontab", "exit 1\n")):
        with open(os.path.join(fb, name), "w", encoding="utf-8") as fh:
            fh.write("#!/bin/sh\n" + body)
        os.chmod(os.path.join(fb, name), 0o755)
    env = dict(os.environ, PATH=fb + os.pathsep + os.environ.get("PATH", ""))

    def status(case, prepare):
        proj = tmpdir(f"r2-4s-{case}")
        os.makedirs(os.path.join(proj, "bin"))
        shutil.copy(shadowserver_cmd(), os.path.join(proj, "bin", "shadowserver"))
        open(os.path.join(proj, "shadowserver_pipeline.py"), "w").close()
        lock = os.path.join(proj, ".pipeline.lock")
        holder = prepare(lock)
        try:
            r = subprocess.run(["bash", os.path.join(proj, "bin", "shadowserver"), "status"], capture_output=True,
                               text=True, timeout=60, env=env, cwd=proj)
        finally:
            if holder is not None:
                holder.kill()
                holder.wait(10)
        running = next((ln.split(None, 1)[1] for ln in r.stdout.splitlines() if ln.startswith("Running:")), "")
        return proj, lock, running, r.stdout + r.stderr

    proj, lock, running, out = status("none", lambda lock: None)
    ok("status without a lock file: not running, the lock file made 0644",
       running == "no" and os.path.isfile(lock) and os.stat(lock).st_mode & 0o777 == 0o644,
       f"{running!r} {oct(os.stat(lock).st_mode & 0o777) if os.path.exists(lock) else 'no file'} {out[-200:]}")

    def held_readonly(lock):
        open(lock, "w").close()
        p = subprocess.Popen([sys.executable, "-c", "import fcntl, os, sys, time\n"
                              f"fd = os.open({lock!r}, os.O_RDONLY)\nfcntl.flock(fd, fcntl.LOCK_EX)\n"
                              "print('held', flush=True)\ntime.sleep(60)\n"], stdout=subprocess.PIPE, text=True)
        p.stdout.readline()
        os.chmod(lock, 0o444)                     # a lock file this account cannot write (left by root, say)
        return p
    proj, lock, running, out = status("held", held_readonly)
    ok("...a run holds a lock file status cannot write: it still says a run is in progress",
       running.startswith("YES"), f"{running!r} {out[-200:]}")
    proj, lock, running, out = status("link", lambda lock: os.symlink(os.path.join(os.path.dirname(lock), "elsewhere"),
                                                                    lock) and None)
    ok("...a symbolic link in its place is not followed (nothing made through it)",
       not os.path.exists(os.path.join(proj, "elsewhere")), f"{running!r} {out[-200:]}")


# ================================================================== r2-5
RAW101 = b"Subject: report 101\r\n\r\nbody of 101\r\n"
RAW102 = b"Subject: report 102\r\n\r\nbody of 102\r\n"
HDR = b"Message-ID: <a@shadowserver.org>\r\nSubject: x\r\n\r\n"
LIST = b"BODY[HEADER.FIELDS (MESSAGE-ID DATE SUBJECT FROM)] {50}"


class FakeImap:
    """One message, seq 1 = UID 101 (102 also exists). uid_after: the server sends the UID after the literal."""
    def __init__(self, uid_after=False, list_uid=True, hdr=HDR, raw1=RAW101, gone=(), refuse=False):
        self.uid_after, self.list_uid, self.hdr, self.raw1 = uid_after, list_uid, hdr, raw1
        self.gone, self.refuse, self.uid_calls = set(gone), refuse, []

    def search(self, *a):
        return "OK", [b"1"]

    def _answer(self, seq, uid, what, body):
        if uid is None:
            return [(b"%s (%s)" % (seq, what), body), b")"]
        if self.uid_after:
            return [(b"%s (%s" % (seq, what), body), b" UID %s)" % uid]
        return [(b"%s (UID %s %s" % (seq, uid, what), body), b")"]

    def fetch(self, ids, what):
        if "HEADER" in what:
            return "OK", self._answer(b"1", b"101" if self.list_uid else None, LIST, self.hdr)
        return "OK", self._answer(b"1", None, b"BODY[] {40}", self.raw1)

    def uid(self, cmd, ids, what):
        self.uid_calls.append(ids)
        if self.refuse:
            return "NO", [b"server busy"]
        out = []
        for u in ids.split(","):
            if u in self.gone:
                continue
            out += self._answer(b"1" if u == "101" else b"2", u.encode(), b"BODY[] {40}",
                                {"101": RAW101, "102": RAW102}.get(u, b""))
        return "OK", out

    def logout(self):
        pass


def imap_source(fake, batch="25"):
    src = mail_sources.ImapSource({"IMAP_SERVER": "mail.example.org", "IMAP_USER": "u", "IMAP_PASSWORD": "p",
                                   "IMAP_FETCH_BATCH": batch})
    src.imap, src.uidvalidity = fake, "7"
    return src


def t_r2_5():
    print("r2-5: the IMAP UID before or after the literal; a forged Message-ID")
    for after in (False, True):
        where = "after" if after else "before"
        src = imap_source(FakeImap(uid_after=after))
        items = src.list(1)
        ok(f"listing, the UID {where} the literal: the message's key is its UID key",
           [k for k, _ in items] == ["imap:7:101"], str(items))
        got = list(src.fetch(items))
        ok(f"...fetched by UID, the UID {where} the literal: its content under its key",
           got == [("imap:7:101", RAW101)] and src.failed == 0, str([k for k, _ in got]) + f" failed={src.failed}")
    # a server that sends no UID in the listing: the key is the old form, from the Message-ID the SENDER wrote
    fake = FakeImap(list_uid=False, hdr=b"Message-ID: 7:102\r\nSubject: x\r\n\r\n")
    src = imap_source(fake)
    items = src.list(1)
    ok("(a forged Message-ID '7:102' gives the old-form key imap:7:102)", [k for k, _ in items] == ["imap:7:102"],
       str(items))
    got = list(src.fetch(items))
    ok("...it is fetched by its sequence number, never as UID 102 (another message's content under its key)",
       got == [("imap:7:102", RAW101)] and not fake.uid_calls, f"{[(k, v[:20]) for k, v in got]} uid={fake.uid_calls}")


# ================================================================== r2-6
def t_r2_6():
    print("r2-6: a message deleted between the listing and the fetch")
    keep = {k: os.environ.get(k) for k in ("MAIL_AUTH",)}
    try:
        os.environ["MAIL_AUTH"] = "off"
        for case, fake, want in (("gone", FakeImap(gone={"101"}), (1, 0)), ("refused", FakeImap(refuse=True), (0, 1))):
            base = Path(tmpdir(f"r2-6-{case}"))
            s = types.SimpleNamespace(attachments_dir=base / "att", base_dir=base, days=1, download_threads=1,
                                      zip_limits=zip_limits.Limits())
            stats = Counter()
            with mock.patch.object(sp.mail_sources, "make_source", lambda env=None, f=fake: imap_source(f)):
                sp.pull_emails(s, stats)
            errs, warns = sp.run_problems(stats)
            got = (stats["emails_gone"], stats["emails_not_fetched"])
            if case == "gone":
                ok("deleted meanwhile (the UID FETCH answered OK without it): counted as gone, a warning, not an error",
                   got == want and not any(e["key"] == "emails_not_fetched" for e in errs)
                   and any(w["key"] == "emails_gone" for w in warns), f"{got} errors={errs} warnings={warns}"[:300])
            else:
                ok("...a batch the server refused stays an error of the run, tried again next run",
                   got == want and any(e["key"] == "emails_not_fetched" for e in errs), f"{got} {errs}"[:300])
    finally:
        for k, v in keep.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


# ================================================================== r2-7
def t_r2_7():
    print("r2-7: SORTED_KEEP_DAYS and files with no row to store")
    base = tmpdir("r2-7")
    s = settings(base)
    d = s.sorting_dir / "scan_x"
    d.mkdir(parents=True)
    empty, full, later = ("2026-11-20-scan_x-kenya-geo.csv", "2026-11-21-scan_x-kenya-geo.csv",
                          "2026-11-19-scan_x-kenya-geo.csv")
    (d / empty).write_text(HEAD, encoding="utf-8")
    (d / full).write_text(rows(1, "21"), encoding="utf-8")
    db = DB()
    PartCrashPool.CRASH = False
    st = run_load(s, db)
    ok("(both files loaded, one with no row to store)", st["files_loaded"] == 2 and st["rows_inserted"] == 1,
       str(dict(st))[:200])
    (d / later).write_text(rows(1, "19"), encoding="utf-8")       # never loaded
    old = time.time() - 10 * 86400
    for fn in (empty, full, later):
        os.utime(d / fn, (old, old))
    keep = os.environ.get("SORTED_KEEP_DAYS")
    try:
        os.environ["SORTED_KEEP_DAYS"] = "1"
        stats = Counter()
        with mock.patch.object(sp, "mongo_client", lambda *a, **k: Client(db)):
            sp.prune_sorted_backup(s, stats)
    finally:
        if keep is None:
            os.environ.pop("SORTED_KEEP_DAYS", None)
        else:
            os.environ["SORTED_KEEP_DAYS"] = keep
    ok("the old sorted copy of a file loaded with no row to store is removed too", not (d / empty).exists(),
       str(sorted(os.listdir(d))))
    ok("...as is the one whose rows are in MongoDB; a file never loaded is kept",
       not (d / full).exists() and (d / later).exists() and stats["retention_files"] == 2,
       f"{sorted(os.listdir(d))} {dict(stats)}")


# ================================================================== r2-8
def t_r2_8():
    print("r2-8: store_mongo_admin.sh --check with an account stored before the TLS lines")
    d = tmpdir("r2-8")
    for f in ("store_mongo_admin.sh", "db_connect.py"):
        shutil.copy(os.path.join(HERE, f), os.path.join(d, f))
    os.makedirs(os.path.join(d, ".venv", "bin"))
    with open(os.path.join(d, ".venv", "bin", "python"), "w", encoding="utf-8") as fh:
        fh.write(f'#!/bin/sh\nexec "{sys.executable}" "$@"\n')
    os.chmod(os.path.join(d, ".venv", "bin", "python"), 0o755)
    fb = tmpdir("r2-8-bin")
    stored_env = os.path.join(d, "stored.env")
    with open(stored_env, "w", encoding="utf-8") as fh:   # stored before MONGO_TLS lines were kept with the account
        fh.write("# MongoDB administrator account\nMONGO_HOST=10.0.0.5\nMONGO_USER=admin\nMONGO_PASSWORD=x\n")
    with open(os.path.join(fb, "sudo"), "w", encoding="utf-8") as fh:
        # a stand-in for sudo: only `sudo [-n] cat <the stored file>`, read from the test's own file
        fh.write('#!/bin/sh\n[ "$1" = -n ] && shift\n[ "$1" = cat ] && exec cat "$FAKE_STORED"\nexit 1\n')
    os.chmod(os.path.join(fb, "sudo"), 0o755)
    env = dict(os.environ, PATH=fb + os.pathsep + os.environ.get("PATH", ""), FAKE_STORED=stored_env)
    r = subprocess.run(["bash", os.path.join(d, "store_mongo_admin.sh"), "--check"], capture_output=True, text=True,
                       timeout=60, env=env, stdin=subprocess.DEVNULL)
    out = r.stdout + r.stderr
    ok("refused (a MongoDB on another computer without TLS), and nothing is sent", r.returncode != 0
       and "Not signed in" in out, out[-300:])
    ok("...with the way out: how to rebuild the .env from the stored file, add the MONGO_TLS lines, store it again",
       "sudo cat /etc/looking-glass/mongo-admin.env" in out and "MONGO_TLS" in out
       and "./store_mongo_admin.sh admin.env" in out, out[-400:])


# ================================================================== r2-9
def t_r2_9():
    print("r2-9: a file moved back from quarantine keeps its sorted copy until it is loaded whole")
    base, s, d = bomb_setup("r2-9")
    db = DB()
    q = Path(base) / "quarantine" / "loader" / "scan_x" / BOMB
    PartCrashPool.CRASH = True
    for _ in range(3):
        run_load(s, db)
        if q.exists():
            break
    ok("(quarantined, 2 of its rows stored)", q.exists() and stored(db, BOMB) == 2)
    if not q.exists():
        return
    shutil.move(str(q), str(d / BOMB))                # moved back; this run's scan of its report does not happen
    old = time.time() - 10 * 86400
    os.utime(d / BOMB, (old, old))
    keep = os.environ.get("SORTED_KEEP_DAYS")
    try:
        os.environ["SORTED_KEEP_DAYS"] = "1"
        with mock.patch.object(sp, "mongo_client", lambda *a, **k: Client(db)):
            sp.prune_sorted_backup(s, Counter())
    finally:
        if keep is None:
            os.environ.pop("SORTED_KEEP_DAYS", None)
        else:
            os.environ["SORTED_KEEP_DAYS"] = keep
    ok("SORTED_KEEP_DAYS keeps its sorted copy (its name is in MongoDB, but most of its rows are only in that file)",
       (d / BOMB).exists())


# ================================================================== r2-10
def t_r2_10():
    print("r2-10: the quarantine note names the exact place to move a file back to")
    base = tmpdir("r2-10")
    d = Path(base) / "sorting_backup" / "scan_x"
    d.mkdir(parents=True)
    q = Path(base) / "quarantine" / "loader" / "scan_x"
    q.mkdir(parents=True)
    (q / BOMB).write_text("quarantined before\n", encoding="utf-8")    # a file of that name is in quarantine already
    (d / BOMB).write_text(rows(1, "22"), encoding="utf-8")
    where = sp._quarantine_loader(str(d / BOMB), Path(base), "scan_x", "a test")
    kept = Path(base) / where
    note = kept.with_name(kept.name + ".reason.txt").read_text(encoding="utf-8")
    ok("(kept under another name, as one of its name is there)", kept.name != BOMB and kept.exists(), where)
    ok("...the note names the exact path to move it back to, with its own name",
       f"sorting_backup/scan_x/{BOMB}" in note and "own name" in note, note)


try:
    for name, fn in (("r2-1", t_r2_1), ("r2-2", t_r2_2), ("r2-3", t_r2_3), ("r2-4", t_r2_4), ("r2-4 status", t_r2_4_status),
                     ("r2-5", t_r2_5),
                     ("r2-6", t_r2_6), ("r2-7", t_r2_7), ("r2-8", t_r2_8), ("r2-9", t_r2_9), ("r2-10", t_r2_10)):
        attempt(name, fn)
finally:
    shutil.rmtree(TMP, ignore_errors=True)
print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
