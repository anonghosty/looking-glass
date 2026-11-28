#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""safe_libraries.py: Looking Glass's Python libraries, installed only when every file matches the lock.

Every installation and every update installs the libraries through this one tool: the guided installer
(install.sh), deploy/install.sh, the pipeline's deploy.sh, deploy/update_libraries.sh and the checks. It needs only
Python's standard library and the pip that comes with a new virtual environment.

    safe_libraries.py check-machine [--python PY]
        Ubuntu 24.04 or later, Python 3.12, 3.13 or 3.14, an x86_64 or aarch64 processor; anything else is refused
        with the reason (exit 2).
    safe_libraries.py install --lock FILE --venv PATH [--part NAME] [--python PY] [--report-dir DIR] [--log FILE]
                              [--release TAG] [--import MODULES] [--force]
        Finds every file the lock names, checks each against the lock's sha256 values, builds a new environment
        beside the running one and switches over only when everything matched and installed. PATH (.venv) becomes a
        link to .venvs/<name>-<time>; the environment before it is kept there too (the last two are kept).
    safe_libraries.py fetch --lock FILE --dir DIR [...]
        Only finds and checks the files (into DIR), and prints them; nothing is installed.
    safe_libraries.py check-lock --lock FILE --requirements FILE
        Every line of the lock carries sha256 values, and every locked version is inside requirements.txt's caps.

Where the files come from, in this order, each file checked against THIS folder's lock (requirements.lock):
  1. PyPI (LG_PYPI_URL, default https://pypi.org/simple);
  2. the library repository: the release's bundle, looking-glass-libraries-<release>.tar.gz, attached to the
     release in github.com/anonghosty/looking-glass-libraries (LG_LIBRARIES_URL);
  3. the local copy: ~/looking-glass/libraries/<release>/<part>/ (LG_LIBRARIES_DIR), the files of the last two
     successful installations, kept read-only.
A file that does not match is refused: a warning names the library, version, source and both sha256 values, the
next source is tried, and the event is written to suspected-packages.json and .txt in the report folder (the
platform puts it in its audit log and in the administrators' bell). When no source has a matching file, the
installation stops and nothing is changed. Exit codes: 0 installed, 10 installed but a source was refused (see the
report), 2 this computer is not supported, 3 stopped (nothing changed), 4 the lock is not usable, 1 other errors.
"""
import argparse
import datetime
import hashlib
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.parse
import urllib.request

PYTHONS = ("3.12", "3.13", "3.14")
MACHINES = ("x86_64", "aarch64")
UBUNTU_MIN = (24, 4)
# the wheel tags looked for (the same as tools/build_wheelhouse.sh): glibc 2.17 and later, which every supported
# Ubuntu has; files that need nothing of the processor (py3-none-any) always qualify
PLATFORM_TAGS = ("manylinux_2_28_{m}", "manylinux2014_{m}", "manylinux_2_17_{m}")
PYPI = "https://pypi.org/simple"
LIBRARIES_URL = ("https://github.com/anonghosty/looking-glass-libraries/releases/download/{release}/"
                 "looking-glass-libraries-{release}.tar.gz")
BUNDLE_MAX = 2 * 1024 ** 3                 # a bundle is about 100 MB; anything near this is not one
KEEP_LOCAL = 2                             # releases kept in the local copy
KEEP_VENVS = 2                             # environments kept in .venvs (the one in use and the one before)
REPORT = "suspected-packages"
LOCK_STAMP = "lg-lock.sha256"              # in an environment: the sha256 of the lock it was installed from
OK, FLAGGED, REFUSED, STOPPED, BAD_LOCK, ERROR = 0, 10, 2, 3, 4, 1


class Stop(Exception):
    """Nothing was changed: the reason, and the exit code."""
    def __init__(self, text, code=STOPPED):
        super().__init__(text)
        self.code = code


LOG = {"file": None}


def say(text="", err=False):
    print(text, file=sys.stderr if err else sys.stdout, flush=True)
    if LOG["file"]:
        try:
            with open(LOG["file"], "a", encoding="utf-8") as f:
                for line in str(text).splitlines() or [""]:
                    f.write(f"{time.strftime('%H:%M:%S')} {line}\n")
        except OSError:
            pass


def norm(name):
    """A library's name as PyPI compares names (Flask, flask, python_dotenv, python-dotenv...)."""
    return re.sub(r"[-_.]+", "-", name).lower()


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# ------------------------------------------------------------------------------------------------ the machine
def os_release(path="/etc/os-release"):
    out = {}
    try:
        for line in open(path, encoding="utf-8", errors="replace"):
            k, sep, v = line.strip().partition("=")
            if sep:
                out[k] = v.strip().strip("'\"")
    except OSError:
        pass
    return out


def python_facts(python):
    """(version 'X.Y', processor) of the Python that will run Looking Glass."""
    r = subprocess.run([python, "-c", "import platform, sys; print('%d.%d' % sys.version_info[:2], platform.machine())"],
                       capture_output=True, text=True, timeout=60)
    if r.returncode or len(r.stdout.split()) != 2:
        raise Stop(f"Could not run {python} to read its version.", REFUSED)
    v, m = r.stdout.split()
    return v, m


def machine_problems(osr, py_version, machine):
    """Every reason this computer is refused ([] when it is supported)."""
    out = []
    pretty = osr.get("PRETTY_NAME") or osr.get("NAME") or "an unknown system"
    ver = re.match(r"^(\d+)\.(\d+)$", osr.get("VERSION_ID", ""))
    if osr.get("ID") != "ubuntu" or not ver or (int(ver.group(1)), int(ver.group(2))) < UBUNTU_MIN:
        out.append(f"Looking Glass installs on Ubuntu 24.04 or later only; this computer runs {pretty}.")
    if py_version not in PYTHONS:
        out.append(f"Looking Glass runs on Python 3.12, 3.13 or 3.14; this computer's Python is {py_version}.")
    if machine not in MACHINES:
        out.append(f"Looking Glass runs on x86_64 (Intel, AMD) or aarch64 (64-bit ARM) processors; this one is {machine}.")
    return out


def check_machine(python, os_release_path="/etc/os-release", py_version=None, machine=None):
    """(py_version, machine) when supported; Stop(REFUSED) with every reason otherwise. py_version and machine are given
    only by the checks (tests/check_installer_supply.py), to simulate other computers."""
    if py_version is None or machine is None:
        v, m = python_facts(python)
        py_version, machine = py_version or v, machine or m
    probs = machine_problems(os_release(os_release_path), py_version, machine)
    if probs:
        raise Stop("This computer is not supported:\n  " + "\n  ".join(probs) + "\nNothing was installed.", REFUSED)
    return py_version, machine


# ------------------------------------------------------------------------------------------------ the lock
def read_lock(path):
    """[{name, version, hashes}] of a lock written by pip-compile --generate-hashes. A line without an exact version or
    without its sha256 values, an option that adds a source, or a library listed twice: Stop(BAD_LOCK)."""
    try:
        text = open(path, encoding="utf-8").read()
    except OSError as e:
        raise Stop(f"Cannot read the lock {path}: {e.strerror}.", BAD_LOCK) from None
    joined = re.sub(r"\\\s*\n", " ", text)
    out, seen = [], set()
    for raw in joined.splitlines():
        line = raw.split(" #", 1)[0].strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("-"):
            raise Stop(f"{os.path.basename(path)}: '{line.split()[0]}' is not allowed in a lock (it could add a source "
                       "or skip the checks).", BAD_LOCK)
        m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([0-9][0-9A-Za-z.+!-]*)((?:\s+--hash=sha256:[0-9a-f]{64})*)\s*$", line)
        if not m:
            raise Stop(f"{os.path.basename(path)}: '{line[:80]}' is not an exact version with its sha256 values; "
                       "regenerate the lock with tools/lock_requirements.sh.", BAD_LOCK)
        hashes = re.findall(r"sha256:([0-9a-f]{64})", m.group(3))
        if not hashes:
            raise Stop(f"{os.path.basename(path)}: {m.group(1)}=={m.group(2)} has no sha256 value: every library in the "
                       "lock must carry them.", BAD_LOCK)
        n = norm(m.group(1))
        if n in seen:
            raise Stop(f"{os.path.basename(path)}: {m.group(1)} is listed twice.", BAD_LOCK)
        seen.add(n)
        out.append({"name": m.group(1), "key": n, "version": m.group(2), "hashes": set(hashes)})
    if not out:
        raise Stop(f"{os.path.basename(path)} lists no library.", BAD_LOCK)
    return out


def _vt(v):
    """A final release's version as a tuple of numbers, else None (a pre-release, a local version...)."""
    return tuple(int(x) for x in v.split(".")) if re.fullmatch(r"\d+(\.\d+)*", v) else None


def _cmp(a, b):
    n = max(len(a), len(b))
    a, b = a + (0,) * (n - len(a)), b + (0,) * (n - len(b))
    return (a > b) - (a < b)


def inside(version, spec):
    """Is the version allowed by a specifier list like '>=3.0,<4' (==, !=, >=, <=, >, <, ~=; X.* in == and !=)?"""
    v = _vt(version)
    if v is None:
        return False
    for part in [p.strip() for p in spec.split(",") if p.strip()]:
        m = re.match(r"^(==|!=|>=|<=|~=|>|<)\s*([0-9][0-9.]*)(\.\*)?$", part)
        if not m:
            return False
        op, w, star = m.group(1), _vt(m.group(2).rstrip(".")), m.group(3)
        if w is None:
            return False
        if star:
            same = v[:len(w)] == w
            if (op == "==" and not same) or (op == "!=" and same) or op not in ("==", "!="):
                return False
            continue
        c = _cmp(v, w)
        if op == "~=":
            if c < 0 or v[:len(w) - 1] != w[:len(w) - 1]:
                return False
        elif not {"==": c == 0, "!=": c != 0, ">=": c >= 0, "<=": c <= 0, ">": c > 0, "<": c < 0}[op]:
            return False
    return True


def read_requirements(path):
    """{key: (name, specifier)} of a requirements.txt (the human-edited caps)."""
    out = {}
    for raw in open(path, encoding="utf-8"):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?\s*(.*)$", line)
        if m:
            out[norm(m.group(1))] = (m.group(1), m.group(3).split(";", 1)[0].strip())
    return out


def lock_problems(lock_path, req_path):
    """Why a lock does not fit its requirements.txt ([] when it does)."""
    try:
        lock = read_lock(lock_path)
    except Stop as e:
        return [str(e)]
    reqs = read_requirements(req_path)
    locked = {x["key"]: x for x in lock}
    out = []
    for key, (name, spec) in sorted(reqs.items()):
        x = locked.get(key)
        if not x:
            out.append(f"{name} is in {os.path.basename(req_path)} but not in the lock: regenerate it (tools/lock_requirements.sh)")
        elif not inside(x["version"], spec):
            out.append(f"{name}=={x['version']} in the lock is outside its cap '{spec}' in {os.path.basename(req_path)}")
    return out


def lock_digest(path):
    return sha256(path)


# ------------------------------------------------------------------------------------------------ the sources
def _clean_env():
    """pip without the user's pip settings: the sources are only the ones named here (a proxy still applies)."""
    env = {k: v for k, v in os.environ.items() if not k.startswith("PIP_")}
    env.update(PIP_CONFIG_FILE=os.devnull, PIP_DISABLE_PIP_VERSION_CHECK="1", PIP_NO_INPUT="1")
    return env


def _url_ok(url):
    """https anywhere; http and file only on this computer (the checks' local package index)."""
    u = urllib.parse.urlparse(url)
    if u.scheme == "https" and u.hostname:
        return True
    if u.scheme == "http" and u.hostname in ("127.0.0.1", "localhost", "::1"):
        return True
    return u.scheme == "file"


def wheel_key(filename):
    """The library a wheel file belongs to, as norm() gives it, and its version."""
    parts = filename[:-4].split("-") if filename.endswith(".whl") else []
    return (norm(parts[0]), parts[1]) if len(parts) >= 5 else (None, None)


def target_args(py_version, machine):
    args = ["--only-binary=:all:", "--python-version", py_version, "--implementation", "cp"]
    for t in PLATFORM_TAGS:
        args += ["--platform", t.format(m=machine)]
    return args


class Sources:
    """PyPI, the library repository (downloaded once, when first needed) and the local copy."""

    def __init__(self, part, release, work, pypi=None, libraries_url=None, local_dir=None):
        self.part, self.release, self.work = part, release, work
        self.pypi = pypi or os.environ.get("LG_PYPI_URL") or PYPI
        tmpl = libraries_url or os.environ.get("LG_LIBRARIES_URL") or LIBRARIES_URL
        self.bundle_url = tmpl.format(release=release) if release else ""
        self.local_dir = os.path.expanduser(local_dir or os.environ.get("LG_LIBRARIES_DIR") or "~/looking-glass/libraries")
        self._bundle = None

    def listing(self):
        """[(label, where, pip arguments or None when unavailable, why unavailable)] in the order they are tried."""
        return [("PyPI", self.pypi, (["--index-url", self.pypi] if _url_ok(self.pypi) else None),
                 "" if _url_ok(self.pypi) else "its address must be https"),
                ("the library repository", self.bundle_url, "bundle", "" if self.bundle_url else "this installation's release is not known"),
                ("the local copy", self.local_dir, "local", "")]

    def bundle_dirs(self):
        """The release's bundle, downloaded and unpacked once: its folders of wheels ([] when it cannot be had)."""
        if self._bundle is not None:
            return self._bundle
        self._bundle = []
        if not self.bundle_url or not _url_ok(self.bundle_url):
            return self._bundle
        dest = os.path.join(self.work, "bundle")
        os.makedirs(dest, exist_ok=True)
        tgz = os.path.join(self.work, "bundle.tar.gz")
        try:
            req = urllib.request.Request(self.bundle_url, headers={"User-Agent": "looking-glass-installer"})
            with urllib.request.urlopen(req, timeout=60) as r, open(tgz, "wb") as f:   # nosec B310  (https, or this computer: _url_ok)
                got = 0
                for chunk in iter(lambda: r.read(1 << 20), b""):
                    got += len(chunk)
                    if got > BUNDLE_MAX:
                        raise OSError("the bundle is far larger than expected")
                    f.write(chunk)
            with tarfile.open(tgz, "r:gz") as tf:
                members = [m for m in tf.getmembers() if m.isfile() and m.name.endswith(".whl")]
                tf.extractall(dest, members=members, filter="data")
        except Exception as e:                  # noqa: BLE001  (not reachable, not there yet, not a bundle: the next source)
            say(f"  the library repository: not available ({type(e).__name__}: {str(e)[:120]})")
            return self._bundle
        self._bundle = sorted({os.path.dirname(os.path.join(dest, m.name)) for m in members})
        return self._bundle

    def local_dirs(self):
        """The local copy's folders for this part, newest release first."""
        if not os.path.isdir(self.local_dir):
            return []
        rels = sorted((d for d in os.listdir(self.local_dir) if os.path.isdir(os.path.join(self.local_dir, d))),
                      key=lambda d: os.path.getmtime(os.path.join(self.local_dir, d)), reverse=True)
        return [p for p in (os.path.join(self.local_dir, d, self.part) for d in rels) if os.path.isdir(p)]


def _download(pip_python, reqs, dest, source_args, target):
    cmd = [pip_python, "-m", "pip", "download", "--no-deps", "--no-cache-dir", "--disable-pip-version-check", "--no-input",
           "-d", dest, *source_args, *target, *[f"{x['name']}=={x['version']}" for x in reqs]]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, env=_clean_env(), timeout=1800)
    except subprocess.TimeoutExpired:
        return False, ["the source did not answer in time"]
    return r.returncode == 0, (r.stderr or r.stdout).strip().splitlines()[-1:] if r.returncode else []


def fetch(lock, stage, sources, pip_python, target, events, lock_name="requirements.lock"):
    """Every library of the lock into `stage`, each file checked. Refused files become events. Stop when a library has
    no matching file in any source."""
    os.makedirs(stage, exist_ok=True)
    todo = {x["key"]: x for x in lock}
    for label, where, kind, why in sources.listing():
        if not todo:
            break
        if kind is None or (kind == "bundle" and not where):
            say(f"  {label}: skipped ({why})")
            continue
        if kind == "bundle":
            dirs = sources.bundle_dirs()
            if not dirs:
                continue
            arg_sets = [sum((["--find-links", d] for d in dirs), ["--no-index"])]
        elif kind == "local":
            dirs = sources.local_dirs()
            if not dirs:
                say(f"  {label}: none yet ({where})")
                continue
            arg_sets = [["--no-index", "--find-links", d] for d in dirs]      # one release at a time, newest first
        else:
            arg_sets = [kind]
        for args in arg_sets:
            if not todo:
                break
            where_now = args[-1] if kind == "local" else where
            q = tempfile.mkdtemp(prefix="q-", dir=sources.work)
            ok_all, _ = _download(pip_python, list(todo.values()), q, args, target)
            if not ok_all:                       # one at a time, so one missing file does not hide the others
                for x in list(todo.values()):
                    _download(pip_python, [x], q, args, target)
            for f in sorted(os.listdir(q)):
                p = os.path.join(q, f)
                key, ver = wheel_key(f)
                x = todo.get(key)
                if not x or ver != x["version"]:
                    os.remove(p)                 # not asked for (pip names files itself): ignored
                    continue
                got = sha256(p)
                if got in x["hashes"]:
                    shutil.move(p, os.path.join(stage, f))
                    del todo[key]
                    continue
                ev = {"time": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
                      "library": x["name"], "version": x["version"], "file": f, "source": label, "source_url": where_now,
                      "expected": sorted(x["hashes"]), "received": got, "part": sources.part, "lock": lock_name}
                events.append(ev)
                os.remove(p)
                say("", err=True)
                say("WARNING: a library file did not match the lock (suspected tampering). It was refused.", err=True)
                say(f"  library   {x['name']} {x['version']}", err=True)
                say(f"  file      {f}", err=True)
                say(f"  source    {label} ({where_now})", err=True)
                say(f"  expected  one of the {len(x['hashes'])} sha256 values in {lock_name}:", err=True)
                for h in sorted(x["hashes"]):
                    say(f"              {h}", err=True)
                say(f"  received  {got}", err=True)
                say("  Trying the next source.", err=True)
            shutil.rmtree(q, ignore_errors=True)
        if kind != "bundle" or sources.bundle_dirs():
            say(f"  {label}: {len(lock) - len(todo)} of {len(lock)} libraries matched so far")
    if todo:
        names = ", ".join(f"{x['name']} {x['version']}" for x in todo.values())
        raise Stop(f"No source had a matching file for: {names}. Nothing was changed.")
    return sorted(os.listdir(stage))


# ------------------------------------------------------------------------------------------------ the report
def write_report(report_dir, events, outcome):
    """suspected-packages.json (every event, the last 500) and .txt (the same, readable) in the report folder."""
    if not events or not report_dir:
        return None
    os.makedirs(report_dir, exist_ok=True)
    jp = os.path.join(report_dir, REPORT + ".json")
    try:
        old = json.load(open(jp, encoding="utf-8")).get("events") or []
    except (OSError, ValueError, AttributeError):
        old = []
    for e in events:
        e["outcome"] = outcome
        # random, made once here and kept in the report: two refusals of the same file from the same source in the
        # same second are two events (2026-11-27: a hash of time, library, version, source and file gave them one id,
        # and the audit log got one of the two)
        e.setdefault("id", secrets.token_hex(8))
    allev = (old + events)[-500:]
    tmp = jp + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o640)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump({"about": "Library files Looking Glass refused because they did not match the lock (suspected tampering). "
                            "docs/INSTALLATION.md, 'When a library file does not match', says how to report them.",
                   "events": allev}, f, indent=1)
    os.replace(tmp, jp)
    lines = ["Suspected tampered library files", "================================", "",
             "Looking Glass refused these files because their sha256 value is not in the lock (requirements.lock).",
             "How to report them: docs/INSTALLATION.md, 'When a library file does not match'.", ""]
    for e in allev:
        lines += [f"{e['time']}  {e['library']} {e['version']}  ({e.get('part', '')})",
                  f"  file      {e['file']}",
                  f"  source    {e['source']}: {e['source_url']}",
                  f"  expected  one of: {', '.join(e['expected'])}",
                  f"  received  {e['received']}",
                  f"  outcome   {e.get('outcome', '')}", ""]
    tp = os.path.join(report_dir, REPORT + ".txt")
    fd = os.open(tp + ".tmp", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o640)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    os.replace(tp + ".tmp", tp)
    return jp


# ------------------------------------------------------------------------------------------------ the local copy
def _writable(path, on):
    for top, dirs, files in os.walk(path):
        os.chmod(top, 0o755 if on else 0o555)
        for f in files:
            os.chmod(os.path.join(top, f), 0o644 if on else 0o444)


def save_local(stage, local_dir, release, part):
    """The checked files into the local copy (<release>/<part>/ with SHA256SUMS), read-only; the last KEEP_LOCAL
    releases are kept."""
    os.makedirs(local_dir, exist_ok=True)
    rel = os.path.join(local_dir, release)
    if os.path.isdir(rel):
        _writable(rel, True)
    dest = os.path.join(rel, part)
    os.makedirs(dest, exist_ok=True)
    for f in os.listdir(stage):
        shutil.copy2(os.path.join(stage, f), os.path.join(dest, f))
    sums = []
    for p in sorted(x for x in os.listdir(rel) if os.path.isdir(os.path.join(rel, x))):
        for f in sorted(os.listdir(os.path.join(rel, p))):
            sums.append(f"{sha256(os.path.join(rel, p, f))}  {p}/{f}")
    with open(os.path.join(rel, "SHA256SUMS"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(sums) + "\n")
    _writable(rel, False)
    os.utime(rel)
    kept = sorted((d for d in os.listdir(local_dir) if os.path.isdir(os.path.join(local_dir, d))),
                  key=lambda d: os.path.getmtime(os.path.join(local_dir, d)), reverse=True)
    for d in kept[KEEP_LOCAL:]:
        _writable(os.path.join(local_dir, d), True)
        shutil.rmtree(os.path.join(local_dir, d), ignore_errors=True)
    return dest


# ------------------------------------------------------------------------------------------------ the environment
def release_of(folder):
    """This installation's release: LG_RELEASE, else the newest tag of its git copy; None when unknown."""
    r = os.environ.get("LG_RELEASE", "").strip()
    if not r:
        try:
            p = subprocess.run(["git", "-C", folder, "describe", "--tags", "--abbrev=0"], capture_output=True, text=True,
                               timeout=20)
            r = p.stdout.strip() if p.returncode == 0 else ""
        except (OSError, subprocess.SubprocessError):
            r = ""
    return r if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", r or "") else None


def switch(venv, new):
    """`venv` becomes a link to `new` (a folder in .venvs beside it). A real folder there is moved into .venvs first."""
    parent, name = os.path.dirname(venv), os.path.basename(venv)
    keep = os.path.dirname(new)
    if os.path.isdir(venv) and not os.path.islink(venv):
        os.rename(venv, os.path.join(keep, f"{name.lstrip('.')}-before-{time.strftime('%Y%m%d-%H%M%S')}"))
    tmp = os.path.join(parent, f".{name}.switch-{os.getpid()}")
    if os.path.lexists(tmp):
        os.remove(tmp)
    os.symlink(os.path.relpath(new, parent), tmp)
    os.replace(tmp, venv)


def prune_venvs(keep_dir, name, current):
    mine = sorted((d for d in os.listdir(keep_dir) if d.startswith(name.lstrip(".") + "-")),
                  key=lambda d: os.path.getmtime(os.path.join(keep_dir, d)), reverse=True)
    for d in [d for d in mine if os.path.join(keep_dir, d) != current][KEEP_VENVS - 1:]:
        shutil.rmtree(os.path.join(keep_dir, d), ignore_errors=True)


def install(a):
    python = a.python or shutil.which("python3") or sys.executable
    py_version, machine = check_machine(python, a.os_release, a.python_version, a.machine)
    lock = read_lock(a.lock)
    lock_name = os.path.basename(a.lock)
    digest = lock_digest(a.lock)
    venv = os.path.abspath(a.venv) if a.venv else None
    if venv and not a.force and os.path.exists(os.path.join(venv, LOCK_STAMP)):
        if open(os.path.join(venv, LOCK_STAMP), encoding="utf-8").read().strip() == digest:
            say(f"{a.part}: already installed from this {lock_name} (nothing to do; --force installs again)")
            return OK
    folder = os.path.dirname(os.path.abspath(a.lock))
    release = a.release or release_of(folder)
    events = []
    keep_dir = os.path.join(os.path.dirname(venv), ".venvs") if venv else None
    work = tempfile.mkdtemp(prefix="lg-libraries-")
    new = None
    outcome = "stopped: no matching file in any source, nothing was changed"
    try:
        say(f"{a.part}: {len(lock)} libraries from {lock_name}, for Python {py_version} on {machine}"
            + (f" (release {release})" if release else ""))
        # the new environment is made first: its pip (the one Python brings, never upgraded from outside) finds and
        # installs the files. fetch alone uses a throwaway one.
        if venv:
            os.makedirs(keep_dir, exist_ok=True)
            new = os.path.join(keep_dir, f"{os.path.basename(venv).lstrip('.')}-{time.strftime('%Y%m%d-%H%M%S')}-{os.getpid()}")
        env_dir = new or os.path.join(work, "pip-env")
        r = subprocess.run([python, "-m", "venv", env_dir], capture_output=True, text=True, timeout=600)
        if r.returncode:
            raise Stop(f"Could not make a Python environment ({(r.stderr or r.stdout).strip()[-200:]}). Nothing was changed.")
        pip_python = os.path.join(env_dir, "bin", "python")
        stage = a.dir or os.path.join(work, "files")
        sources = Sources(a.part, release, work, local_dir=a.local_dir)
        files = fetch(lock, stage, sources, pip_python, target_args(py_version, machine), events, lock_name)
        say(f"{a.part}: every file matched the lock ({len(files)} files)")
        if not venv:
            outcome = "checked only (fetch): a matching file came from another source"
            for f in files:
                say(f"  {f}")
            return FLAGGED if events else OK
        # the install itself: only the checked files, and pip checks every hash again (and refuses anything unlisted)
        r = subprocess.run([pip_python, "-m", "pip", "install", "--no-index", "--find-links", stage, "--require-hashes",
                            "--only-binary=:all:", "--no-cache-dir", "--disable-pip-version-check", "--no-input",
                            "-r", a.lock], capture_output=True, text=True, env=_clean_env(), timeout=1800)
        if r.returncode:
            raise Stop("pip refused the installation:\n  " + "\n  ".join((r.stderr or r.stdout).strip().splitlines()[-8:])
                       + "\nNothing was changed.")
        r = subprocess.run([pip_python, "-m", "pip", "check", "--disable-pip-version-check"], capture_output=True, text=True,
                           env=_clean_env(), timeout=300)
        if r.returncode:
            raise Stop(f"The new environment's libraries do not fit together ({r.stdout.strip()[-300:]}). Nothing was changed.")
        if a.imports:
            mods = [m for m in a.imports.split(",") if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.]*", m)]
            r = subprocess.run([pip_python, "-c", "import importlib, sys\nfor m in sys.argv[1:]: importlib.import_module(m)", *mods],
                               capture_output=True, text=True, timeout=300)
            if r.returncode:
                raise Stop(f"The new environment cannot load {', '.join(mods)} ({r.stderr.strip()[-200:]}). Nothing was changed.")
        with open(os.path.join(new, LOCK_STAMP), "w", encoding="utf-8") as f:
            f.write(digest + "\n")
        switch(venv, new)
        outcome = "installed with a matching file from another source"
        prune_venvs(keep_dir, os.path.basename(venv), new)
        say(f"{a.part}: installed; {os.path.basename(venv)} now uses .venvs/{os.path.basename(new)}")
        new = None                                   # in use: never removed below
        if not a.no_local_copy:
            try:
                d = save_local(stage, sources.local_dir, release or f"unreleased-{time.strftime('%Y-%m-%d')}", a.part)
                say(f"{a.part}: the checked files are kept read-only in {d}")
            except OSError as e:
                say(f"{a.part}: the local copy was not updated ({e.strerror}); the installation itself is complete")
        return FLAGGED if events else OK
    finally:
        if events:
            p = write_report(a.report_dir, events, outcome)
            if p:
                say(f"\n{len(events)} refused file(s) recorded in {p} (and .txt beside it). Please report them: "
                    "docs/INSTALLATION.md, 'When a library file does not match'.", err=True)
        if new and os.path.isdir(new):
            shutil.rmtree(new, ignore_errors=True)
        shutil.rmtree(work, ignore_errors=True)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    cm = sub.add_parser("check-machine")
    for p in (cm, sub.add_parser("install"), sub.add_parser("fetch")):
        p.add_argument("--python", help="the Python that will run Looking Glass (default: python3)")
        # simulating another computer: only the checks use these (tests/check_installer_supply.py)
        p.add_argument("--os-release", default="/etc/os-release", help=argparse.SUPPRESS)
        p.add_argument("--python-version", help=argparse.SUPPRESS)
        p.add_argument("--machine", help=argparse.SUPPRESS)
    for name in ("install", "fetch"):
        p = sub.choices[name]
        p.add_argument("--lock", required=True)
        p.add_argument("--part", default="platform", choices=("platform", "database", "docs", "checker"))
        p.add_argument("--report-dir", help="where suspected-packages.json/.txt are written (default: the lock's folder)")
        p.add_argument("--log", help="also append every line to this file")
        p.add_argument("--release", help="this installation's release (default: LG_RELEASE, else the git copy's newest tag)")
        p.add_argument("--local-dir", help="the local copy (default: LG_LIBRARIES_DIR, else ~/looking-glass/libraries)")
        p.add_argument("--force", action="store_true", help="install again even when the environment has this lock")
        p.add_argument("--no-local-copy", action="store_true", help=argparse.SUPPRESS)
    sub.choices["install"].add_argument("--venv", required=True)
    sub.choices["install"].add_argument("--import", dest="imports", help="modules the new environment must load, a,b,c")
    sub.choices["fetch"].add_argument("--dir", required=True, help="the folder the checked files go to")
    cl = sub.add_parser("check-lock")
    cl.add_argument("--lock", required=True)
    cl.add_argument("--requirements", required=True)
    a = ap.parse_args(argv)
    try:
        if a.cmd == "check-lock":
            probs = lock_problems(a.lock, a.requirements)
            for p in probs:
                say(f"  {p}", err=True)
            say(f"{a.lock}: " + ("fits its requirements" if not probs else f"{len(probs)} problem(s)"))
            return BAD_LOCK if probs else OK
        if a.cmd == "check-machine":
            v, m = check_machine(a.python or shutil.which("python3") or sys.executable, a.os_release, a.python_version, a.machine)
            say(f"This computer is supported: {os_release(a.os_release).get('PRETTY_NAME', 'Ubuntu')}, Python {v}, {m}.")
            return OK
        LOG["file"] = a.log
        a.report_dir = a.report_dir or os.path.dirname(os.path.abspath(a.lock))
        if a.cmd == "fetch":
            a.venv, a.imports = None, ""
        else:
            a.dir = None
        return install(a)
    except Stop as e:
        say(str(e), err=True)
        return e.code


if __name__ == "__main__":
    sys.exit(main())
