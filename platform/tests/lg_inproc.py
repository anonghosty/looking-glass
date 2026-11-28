# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""Shared set-up for the checks that call every route of the app in-process (the pattern of check_role_refusals.py
and check_api_no_secrets.py):
- accounts(): made-up accounts of the given roles in temporary account, session, counter, role and first-run stores,
  one test client per account with its own session cookie and form token, plus a signed-out client;
- guard(): while the routes run, every file write outside the temporary folder (open, io.open, os.open with a write
  flag, rename, remove, folders), every new process or signal, every network connection and every database write is
  refused and counted. A route that reaches such a step stops there with PermissionError (tagged with the check's name);
- platform_copy(): before app is imported, a temporary linked copy of the platform with its own copy of data/, so
  even a write the guards do not see lands in the copy; data_snapshot() / data_changes() prove the live data/ is
  untouched (a change while the platform's own server runs from that folder is the server's, and is a note).
Nothing here touches live data: the caller makes the temporary folder and throws it away."""
import base64
import builtins
import io
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time

from werkzeug.security import generate_password_hash

PASSWORD = "Steady-Harbour-Lantern-63!"
LIVE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))      # the platform folder these checks belong to
TAIL_OVER = 8 * 1024 * 1024       # data files bigger than this (copy_seals.jsonl) are copied as their last lines only
TAIL_BYTES = 256 * 1024


def _copy_data_file(src, dst):
    if os.path.getsize(src) <= TAIL_OVER:
        return shutil.copy2(src, dst)
    with open(src, "rb") as fi, open(dst, "wb") as fo:          # an append-only log: its newest whole lines
        fi.seek(-TAIL_BYTES, os.SEEK_END)
        fi.readline()
        fo.write(fi.read())
    shutil.copystat(src, dst)
    return dst


def platform_copy(prefix):
    """Call BEFORE importing app: a temporary copy of the platform whose code entries are links to this folder's and
    whose data/ is a real copy (big append-only logs as their newest lines), and logs/ and backups/ empty. sys.path and
    the working folder are set to it, so app.py (BASE_DIR = abspath(__file__)) and every module read and write the
    copy's data/, never the live one. A watcher removes the copy when this process ends (also after os._exit).
    Returns the copy's folder."""
    root = tempfile.mkdtemp(prefix=prefix + "-platform-")
    plat = os.path.join(root, "platform")
    os.makedirs(plat)
    for name in os.listdir(LIVE):
        src = os.path.join(LIVE, name)
        if name == "data":
            shutil.copytree(src, os.path.join(plat, "data"), symlinks=True, copy_function=_copy_data_file)
        elif name in ("logs", "backups"):
            os.makedirs(os.path.join(plat, name))
        else:
            os.symlink(src, os.path.join(plat, name))
    subprocess.Popen(["/bin/sh", "-c", f'while kill -0 {os.getpid()} 2>/dev/null; do sleep 2; done; rm -rf "{root}"'],
                     stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
    sys.path[:] = [p for p in sys.path if os.path.abspath(p or ".") != LIVE and os.path.realpath(p or ".") != os.path.realpath(LIVE)]
    sys.path.insert(0, plat)
    os.chdir(plat)
    return plat


def data_snapshot(folder=None):
    """{relative path: (mtime_ns, size)} for every file in the live data/ folder."""
    base = os.path.join(folder or LIVE, "data")
    out = {}
    for root, _dirs, files in os.walk(base):
        for n in files:
            p = os.path.join(root, n)
            try:
                st = os.lstat(p)
                out[os.path.relpath(p, folder or LIVE)] = (st.st_mtime_ns, st.st_size)
            except OSError:
                pass
    return out


def live_servers(folder=None):
    """Process ids of the platform's own server (gunicorn or app.py) running from that folder: it writes data/ too."""
    want, out = os.path.realpath(folder or LIVE), []
    for pid in os.listdir("/proc") if os.path.isdir("/proc") else []:
        try:
            if pid.isdigit() and int(pid) != os.getpid() and os.path.realpath(f"/proc/{pid}/cwd") == want:
                with io.FileIO(f"/proc/{pid}/cmdline", "r") as fh:
                    cmd = fh.read()
                if b"gunicorn" in cmd or b"app.py" in cmd:
                    out.append(pid)
        except OSError:
            pass
    return out


def data_changes(before, after, folder=None):
    """(changed files, notes): files of the live data/ that changed between two snapshots. When the platform's own
    server runs from that folder, a change is its write (this process could not write there) and goes to notes."""
    changed = sorted(k for k in set(before) | set(after) if before.get(k) != after.get(k))
    servers = live_servers(folder)
    if not servers:
        return changed, []
    return [], [f"note: {k} changed during the run while the platform's own server (pid {', '.join(servers)}) runs "
                "from that folder: its write, not this check's" for k in changed]


def builtin_roles(auth):
    return sorted(set(auth.DEFAULT_ROLES) | set(auth.FIXED_ROLES))


def accounts(A, auth, tmp, prefix, ua, roles):
    """{role: (client, csrf)} for one made-up account per role, and "signed out": (client, None)."""
    AU = A.AUTH
    users, sessions, throttle, roles_store = AU["users"], AU["sessions"], AU["throttle"], AU["roles"]
    AU["audit"].add = lambda ev, **k: None
    sessions.path, throttle.path, roles_store.path = (os.path.join(tmp, n) for n in ("sessions.json", "login_counters.json", "roles.json"))
    AU["setup"].path = os.path.join(tmp, "setup_code")
    sessions.s.clear(); throttle.fail.clear()
    h = generate_password_hash(PASSWORD)
    acc = {f"{prefix}-{r}": {"hash": h, "role": r, "status": "active", "totp": base64.b32encode(os.urandom(20)).decode().rstrip("="),
                             "changed": 0, "created": 1, "pw_set_at": int(time.time()), "profile": {"full_name": f"Check {r.title()}"}}
           for r in roles}
    with open(os.path.join(tmp, "users.json"), "w") as fh:
        json.dump({"users": acc}, fh)
    users.path, users.mtime = os.path.join(tmp, "users.json"), None
    out = {}
    for name, a in acc.items():
        tok = sessions.create(name, "127.0.0.1", ua)
        c = A.app.test_client(); c.set_cookie("lg_session", tok)
        out[a["role"]] = (c, sessions.s[auth._h(tok)]["csrf"])
    out["signed out"] = (A.app.test_client(), None)
    return out


class Guard:
    def __init__(self, tmp, tag):
        self.tmp, self.tag, self.refused = os.path.realpath(tmp), tag, []
        self.real_open, self.real_exit = builtins.open, os._exit

    def _inside(self, file):
        try:
            p = os.path.realpath(os.fsdecode(file))
        except TypeError:                               # a file descriptor: already open
            return True
        return p.startswith(self.tmp + os.sep)

    def refuse(self, what):
        def f(*a, **k):
            self.refused.append(what)
            raise PermissionError(f"{self.tag}: {what} refused")
        return f

    def install(self):
        real_open, real_os_open = builtins.open, os.open
        W = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_APPEND | os.O_TRUNC

        def g_open(file, mode="r", *a, **k):
            if any(ch in str(mode) for ch in "wax+") and isinstance(file, (str, bytes, os.PathLike)) and not self._inside(file):
                self.refused.append("write " + os.fsdecode(file))
                raise PermissionError(f"{self.tag}: write refused")
            return real_open(file, mode, *a, **k)

        def g_os_open(path, flags, *a, **k):
            if flags & W and not self._inside(path):
                self.refused.append("write " + os.fsdecode(path))
                raise PermissionError(f"{self.tag}: write refused")
            return real_os_open(path, flags, *a, **k)

        builtins.open = io.open = g_open
        os.open = g_os_open
        for fn in ("replace", "rename", "remove", "unlink", "rmdir", "mkdir", "chmod", "truncate", "symlink", "link",
                   "system", "kill", "killpg", "fork", "execv", "execve", "execvp", "posix_spawn", "posix_spawnp"):
            if hasattr(os, fn):
                real = getattr(os, fn)
                if fn in ("replace", "rename", "remove", "unlink", "rmdir", "mkdir", "chmod", "truncate"):
                    def inside_only(*a, _real=real, _fn=fn, **k):
                        if a and all(self._inside(x) for x in a[:2] if isinstance(x, (str, bytes, os.PathLike))):
                            return _real(*a, **k)
                        return self.refuse("os." + _fn)()
                    setattr(os, fn, inside_only)
                else:
                    setattr(os, fn, self.refuse("os." + fn))
        real_makedirs = os.makedirs
        os.makedirs = lambda p, *a, **k: (real_makedirs(p, *a, **k) if self._inside(p) else
                                          None if os.path.isdir(p) else self.refuse("os.makedirs")())
        shutil.rmtree, shutil.move, shutil.copy, shutil.copy2, shutil.copyfile = (self.refuse("shutil") for _ in range(5))
        subprocess.Popen = self.refuse("a new process")
        socket.socket.connect = self.refuse("a network connection")
        socket.socket.connect_ex = self.refuse("a network connection")
        tempfile.tempdir = self.tmp
        try:
            import pymongo.collection as PC
            for m in ("insert_one", "insert_many", "update_one", "update_many", "replace_one", "delete_one", "delete_many",
                      "bulk_write", "drop", "create_index", "find_one_and_update", "find_one_and_delete", "find_one_and_replace"):
                setattr(PC.Collection, m, self.refuse("a database write"))
        except ImportError:
            pass
        return self


def guard(tmp, tag):
    return Guard(tmp, tag).install()
