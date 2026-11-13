#!/usr/bin/env python3
"""uninstall.sh: removes only what belongs to its own folder, keeps data unless asked, never deletes without a
confirmation. Runs against a scratch installation with stand-ins for sudo, systemctl and crontab: nothing on this
computer is touched. No database needed."""
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
CANDIDATES = [HERE / "tools" / "release_root" / "uninstall.sh", HERE.parent / "uninstall.sh"]
SCRIPT = next((p for p in CANDIDATES if p.is_file()), None)
results = []


def check(name, ok, detail=""):
    results.append(ok)
    print(f"  {'PASS' if ok else 'FAIL'}  {name}" + (f"  ({detail})" if detail and not ok else ""))


def stub(d, name, body):
    p = d / name
    p.write_text("#!/usr/bin/env bash\n" + body + "\n")
    p.chmod(p.stat().st_mode | stat.S_IXUSR)


def setup(tmp, cmd_owner="self", mongo_conf=None):
    root = tmp / "looking-glass"
    for d in ("database/bin", "platform/deploy", "sys/systemd", "sys/etc-lg", "sys/bin", "sys/man", "sys/compl", "stubs"):
        (root / d if not d.startswith(("sys", "stubs")) else tmp / d).mkdir(parents=True, exist_ok=True)
    shutil.copy(SCRIPT, root / "uninstall.sh")
    (root / "install.sh").write_text("#!/bin/sh\n")
    (root / "database/bin/shadowserver").write_text("#!/bin/sh\n")
    (root / "database/.env").write_text("MONGO_DB=shadowserver\nMONGO_USER=lookingglass_pipeline\n")
    pf = root / "platform"
    sysd = tmp / "sys/systemd"
    (sysd / "looking-glass.service").write_text(f"[Service]\nWorkingDirectory={pf}\n")
    (sysd / "other-app.service").write_text("[Service]\nWorkingDirectory=/srv/other\n")
    target = root / "database/bin/shadowserver" if cmd_owner == "self" else Path("/srv/elsewhere/database/bin/shadowserver")
    (tmp / "sys/bin/shadowserver").write_text(f'#!/bin/sh\nexec "{target}" "$@"\n')
    (tmp / "sys/man/shadowserver.1").write_text("man")
    (tmp / "sys/compl/shadowserver").write_text("compl")
    (tmp / "sys/etc-lg/mongo-admin.env").write_text("MONGO_USER=admin\n")
    conf = tmp / "sys/mongod.conf"
    if mongo_conf:
        conf.write_text(mongo_conf.replace("@DB@", str(root / "database")))
    cron = tmp / "cron.txt"
    cron.write_text(f"*/30 * * * * {root}/database/run.sh --quiet # shadowserver-pipeline\n"
                    "0 5 * * * /srv/elsewhere/database/run.sh # shadowserver-pipeline\n"
                    "15 3 * * * /usr/bin/backup-job\n")
    st = tmp / "stubs"
    log = tmp / "calls.log"
    stub(st, "sudo", f'echo "sudo $*" >> "{log}"; [ "$1" = -n ] && shift; [ "$1" = -v ] && exit 0; "$@"')
    stub(st, "systemctl", f'echo "systemctl $*" >> "{log}"')
    stub(st, "mandb", "true")
    stub(st, "apt-get", f'echo "apt-get $*" >> "{log}"')
    stub(st, "pgrep", "exit 1")
    stub(st, "crontab", f'f="{cron}"; case "$1" in -l) [ -f "$f" ] && cat "$f" || exit 1 ;; -r) rm -f "$f" ;; -) cat > "$f" ;; esac')
    if mongo_conf is not None:
        stub(st, "mongod", "true")
    env = dict(os.environ, PATH=f"{st}:/usr/bin:/bin", HOME=str(tmp),
               LG_UNINSTALL_SYSTEMD_DIR=str(sysd), LG_UNINSTALL_ETC_DIR=str(tmp / "sys/etc-lg"),
               LG_UNINSTALL_BIN=str(tmp / "sys/bin/shadowserver"), LG_UNINSTALL_MAN=str(tmp / "sys/man/shadowserver.1"),
               LG_UNINSTALL_COMPLETION=str(tmp / "sys/compl/shadowserver"), LG_UNINSTALL_MONGOD_CONF=str(conf))
    return root, env, cron, log


def run(root, env, *args):
    return subprocess.run(["bash", str(root / "uninstall.sh"), *args], env=env, cwd=root, stdin=subprocess.DEVNULL,
                          capture_output=True, text=True, timeout=120)


def real_database_case():
    """--remove-database against a throwaway mongod in a scratch folder (skipped where mongod is not installed): the
    reports database and the two Looking Glass accounts go, another database and another account stay."""
    mongod = shutil.which("mongod")
    try:
        from pymongo import MongoClient
    except ImportError:
        MongoClient = None
    if not mongod or MongoClient is None:
        print("  skip  real database deletion (no mongod or pymongo here)")
        return
    import socket
    import time
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]
    with tempfile.TemporaryDirectory() as t:
        tmp = Path(t); dbpath = tmp / "mongo"; dbpath.mkdir()
        proc = subprocess.Popen([mongod, "--dbpath", str(dbpath), "--port", str(port), "--bind_ip", "127.0.0.1",
                                 "--quiet", "--logpath", str(tmp / "mongod.log")],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            c = MongoClient(host="127.0.0.1", port=port, serverSelectionTimeoutMS=20000)
            c.admin.command("ping")
            c["lgu_reports"]["scan_x"].insert_one({"a": 1})
            c["keep_me"]["other"].insert_one({"b": 1})
            c.admin.command("createUser", "lookingglass_pipeline", pwd="x", roles=[{"role": "readWrite", "db": "lgu_reports"}])
            c["lgu_reports"].command("createUser", "lookingglass_ro", pwd="x", roles=[{"role": "read", "db": "lgu_reports"}])
            c.admin.command("createUser", "someone_else", pwd="x", roles=[{"role": "read", "db": "keep_me"}])
            root, env, cron, log = setup(tmp)
            (root / "database/.env").write_text(f"MONGO_DB=lgu_reports\nMONGO_HOST=127.0.0.1\nMONGO_PORT={port}\n"
                                                "MONGO_USER=lookingglass_pipeline\n")
            (tmp / "sys/etc-lg/mongo-admin.env").write_text(f"MONGO_HOST=127.0.0.1\nMONGO_PORT={port}\n")  # no auth here
            venv = root / "database/.venv/bin"; venv.mkdir(parents=True)
            stub(venv, "python", f'exec "{sys.executable}" "$@"')
            r = run(root, env, "--yes", "--remove-database", "--i-understand-data-loss")
            out = (r.stdout + r.stderr)[-500:]
            users = {u["user"] for u in c.admin.command("usersInfo", {"forAllDBs": True})["users"]}
            check("real database: run exits 0", r.returncode == 0, out)
            check("real database: reports database deleted", "lgu_reports" not in c.list_database_names(), out)
            check("real database: other database kept", "keep_me" in c.list_database_names())
            check("real database: both Looking Glass accounts removed",
                  not users & {"lookingglass_pipeline", "lookingglass_ro"}, str(users))
            check("real database: other account kept", "someone_else" in users, str(users))
            check("real database: administrator file removed", not (tmp / "sys/etc-lg").exists())
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=30)
            except subprocess.TimeoutExpired:
                proc.kill()
            time.sleep(0.5)


def main():
    if SCRIPT is None:
        print("uninstall.sh not found"); return 1
    if os.geteuid() == 0:
        print("SKIPPED: run as an ordinary user (the uninstaller refuses root)"); return 77
    print(f"uninstall.sh: {SCRIPT}")
    r = subprocess.run(["bash", "-n", str(SCRIPT)], capture_output=True, text=True)
    check("bash syntax", r.returncode == 0, r.stderr)

    with tempfile.TemporaryDirectory() as t:   # dry run changes nothing
        tmp = Path(t); root, env, cron, log = setup(tmp)
        before = cron.read_text()
        r = run(root, env, "--dry-run", "--all")
        check("dry run exits 0", r.returncode == 0, r.stderr[-300:])
        check("dry run names the service, schedule and command",
              all(s in r.stdout for s in ("looking-glass.service", "pipeline schedule", "'shadowserver' command")))
        check("dry run changes nothing", (tmp / "sys/systemd/looking-glass.service").exists() and cron.read_text() == before
              and (tmp / "sys/bin/shadowserver").exists() and root.exists() and not log.exists())

    with tempfile.TemporaryDirectory() as t:   # default: system parts removed, data and folder kept
        tmp = Path(t); root, env, cron, log = setup(tmp)
        r = run(root, env, "--yes")
        out = r.stdout + r.stderr
        check("default run exits 0", r.returncode == 0, out[-400:])
        calls = log.read_text() if log.exists() else ""
        check("service stopped and disabled", "systemctl disable --now looking-glass.service" in calls, calls)
        check("its unit file removed", not (tmp / "sys/systemd/looking-glass.service").exists())
        check("another program's unit kept", (tmp / "sys/systemd/other-app.service").exists())
        c = cron.read_text() if cron.exists() else ""
        check("this folder's cron line removed", str(root) not in c, c)
        check("another installation's cron line kept", "/srv/elsewhere/database/run.sh" in c, c)
        check("unrelated cron job kept", "/usr/bin/backup-job" in c, c)
        check("command, man page, completion removed", not any((tmp / p).exists() for p in
              ("sys/bin/shadowserver", "sys/man/shadowserver.1", "sys/compl/shadowserver")))
        check("folder kept", (root / "database/.env").exists())
        check("administrator account file kept (database kept)", (tmp / "sys/etc-lg/mongo-admin.env").exists())
        check("no package removed", "apt-get" not in calls)

    with tempfile.TemporaryDirectory() as t:   # a pipeline run going on (review 2026-11-13: it was never found)
        tmp = Path(t); root, env, cron, log = setup(tmp)
        lock = root / "database/.pipeline.lock"
        # as run.sh does: it holds .pipeline.lock while it runs, the script named by a relative path
        holder = subprocess.Popen(["flock", str(lock), "sleep", "8"], cwd=root / "database")
        time.sleep(0.5)
        t0 = time.time()
        r = run(root, env, "--yes")
        waited = time.time() - t0
        holder.wait(timeout=30)
        check("a run in progress (holding the pipeline's lock) is found and waited for",
              r.returncode == 0 and "a pipeline run is in progress" in r.stdout and waited >= 5, f"{waited:.1f} s; {r.stdout[-200:]}")

    with tempfile.TemporaryDirectory() as t:   # a command that runs another folder's pipeline is left alone
        tmp = Path(t); root, env, cron, log = setup(tmp, cmd_owner="other")
        r = run(root, env, "--yes")
        check("other folder's command kept", r.returncode == 0 and (tmp / "sys/bin/shadowserver").exists(), r.stdout[-300:])

    with tempfile.TemporaryDirectory() as t:   # deleting the folder needs a typed confirmation
        tmp = Path(t); root, env, cron, log = setup(tmp)
        r = run(root, env, "--yes", "--remove-files")
        check("folder not deleted without typed confirmation", r.returncode != 0 and root.exists()
              and "typed confirmation" in r.stderr, r.stderr[-300:])
        check("refused before anything was changed", (tmp / "sys/systemd/looking-glass.service").exists())

    with tempfile.TemporaryDirectory() as t:   # ...and with it, the folder goes
        tmp = Path(t); root, env, cron, log = setup(tmp)
        r = run(root, env, "--yes", "--remove-files", "--i-understand-data-loss")
        check("folder deleted when confirmed", r.returncode == 0 and not root.exists(), (r.stdout + r.stderr)[-300:])

    with tempfile.TemporaryDirectory() as t:   # a MongoDB Looking Glass did not install is never removed
        tmp = Path(t); root, env, cron, log = setup(tmp, mongo_conf="# someone else's\nnet:\n  port: 27017\n")
        r = run(root, env, "--dry-run", "--remove-mongodb")
        check("foreign MongoDB not removed", "NOT removed" in r.stdout and "apt-get purge" not in r.stdout, r.stdout[-400:])

    with tempfile.TemporaryDirectory() as t:   # ...one it did install is, when asked
        tmp = Path(t); root, env, cron, log = setup(tmp, mongo_conf="# Managed by @DB@/deploy.sh - edit .env\n")
        r = run(root, env, "--dry-run", "--remove-mongodb")
        check("Looking Glass's MongoDB removed when asked", "apt-get purge" in r.stdout, r.stdout[-400:])

    with tempfile.TemporaryDirectory() as t:   # database removal without the means to do it stops, keeps data
        tmp = Path(t); root, env, cron, log = setup(tmp)
        r = run(root, env, "--yes", "--remove-database", "--i-understand-data-loss")
        check("database removal stops cleanly without Python/pymongo", r.returncode != 0 and "NOT deleted" in r.stderr
              and (tmp / "sys/etc-lg/mongo-admin.env").exists(), (r.stdout + r.stderr)[-300:])

    real_database_case()

    with tempfile.TemporaryDirectory() as t:   # an odd database name is refused before anything happens
        tmp = Path(t); root, env, cron, log = setup(tmp)
        (root / "database/.env").write_text("MONGO_DB=x;rm -rf ~\n")
        r = run(root, env, "--yes")
        check("unsafe MONGO_DB refused", r.returncode != 0 and (tmp / "sys/systemd/looking-glass.service").exists())

    # review 2026-11-13: MongoDB's own databases, a unit installed through a symlink, a run that will not stop
    for name in ("admin", "Local", "config"):
        with tempfile.TemporaryDirectory() as t:
            tmp = Path(t); root, env, cron, log = setup(tmp)
            (root / "database/.env").write_text(f"MONGO_DB={name}\n")
            r = run(root, env, "--yes", "--remove-database", "--i-understand-data-loss")
            check(f"MONGO_DB={name} (MongoDB's own database) refused before anything is changed", r.returncode != 0
                  and "MongoDB's own databases" in r.stderr and (tmp / "sys/systemd/looking-glass.service").exists(), (r.stdout + r.stderr)[-300:])
    with tempfile.TemporaryDirectory() as t:
        tmp = Path(t); root, env, cron, log = setup(tmp)
        link = tmp / "lg-link"; link.symlink_to(root)
        (tmp / "sys/systemd/looking-glass.service").write_text(f"[Service]\nWorkingDirectory={link}/platform/\n")
        r = run(root, env, "--yes")
        check("a unit installed through a symlink (with a trailing slash) is found and removed", r.returncode == 0
              and not (tmp / "sys/systemd/looking-glass.service").exists() and (tmp / "sys/systemd/other-app.service").exists(),
              (r.stdout + r.stderr)[-300:])
    with tempfile.TemporaryDirectory() as t:
        tmp = Path(t); root, env, cron, log = setup(tmp)
        lock = root / "database/.pipeline.lock"; lock.write_text("")
        # detached: its own session and no shared output, so nothing waits on it; killed as a group afterwards
        holder = subprocess.Popen(["flock", str(lock), "sleep", "400"], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                  stderr=subprocess.DEVNULL, start_new_session=True)
        try:
            stub(tmp / "stubs", "sleep", "true")             # the 5-minute wait passes at once
            r = run(root, env, "--yes", "--remove-files", "--i-understand-data-loss")
            check("a run that still holds the lock: stopped there, the folder NOT deleted", r.returncode != 0
                  and "NOT touched" in r.stderr and (root / "install.sh").exists(), (r.stdout + r.stderr)[-300:])
        finally:
            import signal
            try:
                os.killpg(holder.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            holder.wait()

    print(f"{sum(results)}/{len(results)} checks passed")
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
