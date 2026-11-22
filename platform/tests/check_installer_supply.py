#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""The libraries are installed only when every file matches the lock (r86): every way of installing, checked.

1. Every install path goes through deploy/safe_libraries.py or pip --require-hashes from a lock: the guided installer,
   deploy/install.sh, deploy/update_libraries.sh, the pipeline's deploy.sh, the GitHub checks, the docs site; nothing
   runs a plain `pip install -r requirements.txt`, Debian is no longer accepted, and the rules catch a broken copy (the
   tool without --require-hashes, an installer back on requirements.txt).
2. Every lock fits its requirements.txt (each version inside its cap, every library listed, every line hashed); a lock
   entry outside its cap, an unhashed line or an added source fails.
3. This computer: Ubuntu 24.04, 25.04, 25.10 and 26.04 accepted with Python 3.12, 3.13, 3.14 on x86_64 and aarch64;
   Debian, Ubuntu 22.04, Fedora, Python 3.11 and 3.15, i686 and armv7 refused.
4. A local package index (http.server on 127.0.0.1, tiny made-up wheels; nothing leaves this computer): each Python
   and processor gets its own files; a clean install switches .venv; PyPI poisoned but the library repository or the
   local copy clean installs, flags and reports it; every source poisoned stops with nothing changed; a library the
   lock does not list is refused; the report reaches the audit log and the administrators' bell.
No database, no network beyond 127.0.0.1. Run from the platform's folder: .venv/bin/python tests/check_installer_supply.py
(LG_PIPELINE_DIR: the pipeline's folder when it is not ../database or ../shadowserver).
"""
import base64
import functools
import hashlib
import http.server
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import threading
import zipfile

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "deploy"))
import safe_libraries as S  # noqa: E402

TOOL = os.path.join(HERE, "deploy", "safe_libraries.py")
checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{str(info)[:400]}]" if info and not cond else ""))


def read(p):
    try:
        return open(p, encoding="utf-8").read()
    except OSError:
        return ""


def first(*paths):
    return next((p for p in paths if p and os.path.exists(p)), None)


TOP = os.path.dirname(HERE)
INSTALLER = first(os.path.join(TOP, "install.sh"), os.path.join(HERE, "tools", "release_root", "install.sh"))
ROOT_FILES = os.path.dirname(INSTALLER) if INSTALLER else None
PIPE = next((p for p in (os.environ.get("LG_PIPELINE_DIR"), os.path.join(TOP, "database"), os.path.join(TOP, "shadowserver"))
             if p and os.path.isfile(os.path.join(p, "shadowserver_pipeline.py"))), None)
DOCS = first(os.path.join(TOP, "docs", "requirements.txt"), os.path.join(HERE, "tools", "release_root", "docs", "requirements.txt"))


# ------------------------------------------------------------------------------------------------ 1. the rules
def code_lines(text, comment="#"):
    """The lines that run something: comments dropped, continued lines joined."""
    text = re.sub(r"\\\n", " ", text)
    return [ln.split(" " + comment, 1)[0].strip() for ln in text.splitlines()
            if ln.strip() and not ln.strip().startswith(comment)]


def unsafe_pip(text, allow_pinned_tools=False):
    """Lines that install with pip without --require-hashes (a pinned tool, name==x.y.z only, where allowed)."""
    bad = []
    for ln in code_lines(text):
        if not re.search(r"\bpip3?\b[^|;&]*\binstall\b", ln):
            continue
        if "--require-hashes" in ln:
            continue
        args = ln.split("install", 1)[1].split()
        if allow_pinned_tools and args and all(re.fullmatch(r"[A-Za-z0-9._-]+==[0-9][0-9.]*", x) or x in ("-q", "--quiet") for x in args):
            continue
        bad.append(ln[:160])
    return bad


def tool_rules(src):
    """What the tool must keep doing ([] when it does)."""
    out = []
    m = re.search(r'"pip", "install", "--no-index", "--find-links", stage,(.{0,400}?)"-r", a\.lock', src, re.S)
    if not m or '"--require-hashes"' not in m.group(1):
        out.append("its pip install of the checked files has no --require-hashes (or is not from the checked files only)")
    if '"--only-binary=:all:"' not in src:
        out.append("it may fetch source packages (no --only-binary=:all:)")
    if not re.search(r"if got in x\[\"hashes\"\]", src):
        out.append("it no longer checks each file against the lock's hashes")
    call = src.rfind("\n        switch(venv, new)\n")              # the call, not the function's own line
    if call < 0 or call < src.find('"pip", "install", "--no-index"'):
        out.append("it no longer switches only after the install")
    return out


def installer_rules(text, name):
    """An installer: no pip install without --require-hashes, nothing from requirements.txt, the libraries through
    safe_libraries.py (directly or as $SAFE_LIBS) from a requirements.lock."""
    lines = code_lines(text)
    out = [f"{name}: {x}" for x in unsafe_pip(text)]
    if any("pip" in x and "requirements.txt" in x for x in lines):
        out.append(f"{name}: installs from requirements.txt")
    if not any(re.search(r'(safe_libraries\.py"?|\$SAFE_LIBS"?)\s+install\b', x) for x in lines) \
            or not any(re.search(r'--lock\s+"?\S*requirements\.lock', x) for x in lines):
        out.append(f"{name}: does not install through safe_libraries.py from a requirements.lock")
    return out


print("1. Every way of installing goes through the lock")
tool_src = read(TOOL)
ok("the tool: installs only the checked files, with --require-hashes, wheels only, switching after", not tool_rules(tool_src), tool_rules(tool_src))
paths = {"deploy/install.sh": os.path.join(HERE, "deploy", "install.sh"),
         "deploy/update_libraries.sh": os.path.join(HERE, "deploy", "update_libraries.sh")}
if INSTALLER:
    paths["install.sh (guided installer)"] = INSTALLER
if PIPE:
    paths["the pipeline's deploy.sh"] = os.path.join(PIPE, "deploy.sh")
for name, p in paths.items():
    t = read(p)
    probs = installer_rules(t, name)
    ok(f"{name}: through safe_libraries.py from requirements.lock, no plain pip install", t and not probs, probs or "file missing")
    ok(f"{name}: checks this computer first (check-machine)", "check-machine" in t)
for name in ("tools/lock_requirements.sh", "tools/build_wheelhouse.sh"):
    t = read(os.path.join(HERE, name))
    ok(f"{name}: every pip install it runs carries --require-hashes", t and not unsafe_pip(t), unsafe_pip(t))
if INSTALLER:
    inst = read(INSTALLER)
    ok("install.sh: the checker's libraries come from the pipeline's lock (no unpinned pymongo/requests)",
       "--part checker" in inst and '"pymongo>=' not in inst)
    ok("install.sh: Debian is no longer accepted", not re.search(r"debian:\*|\*debian\*|Debian 13", inst, re.I))
    ok("install.sh: refused library files are reported in its folder", "LG_SUPPLY_REPORT_DIR" in inst and "suspected-packages" in inst)
if ROOT_FILES:
    wf = read(os.path.join(ROOT_FILES, ".github", "workflows", "checks.yml"))
    ok("GitHub checks: libraries from the locks with --require-hashes; tools pinned; pip not upgraded from outside",
       wf and not unsafe_pip(wf, allow_pinned_tools=True) and "--upgrade pip" not in wf
       and "-r platform/requirements.lock" in wf and "-r database/requirements.lock" in wf, unsafe_pip(wf, True))
    ok("GitHub checks: this check runs in the unit job", "check_installer_supply" in wf)
    rtd = read(os.path.join(ROOT_FILES, ".readthedocs.yaml"))
    ok("the docs site installs docs/requirements.lock (pip checks every hash)", "requirements: docs/requirements.lock" in rtd)
ra = read(os.path.join(HERE, "tests", "run_all_checks.sh"))
ok("run_all_checks.sh runs this check", "tests/check_installer_supply.py" in ra)
if PIPE and os.path.exists(os.path.join(PIPE, "safe_libraries.py")):
    ok("the pipeline's copy of safe_libraries.py is the platform's, unchanged",
       S.sha256(os.path.join(PIPE, "safe_libraries.py")) == S.sha256(TOOL))
mr = read(os.path.join(HERE, "tools", "make_release.py"))
if mr and os.path.isdir(os.path.join(HERE, "tools", "release_root")):   # the development tree only: releases do not ship
    # make_release.py, and an installation may still hold an old copy from an early layout (lg-test did, 2026-11-21)
    ok("make_release ships the pipeline's lock and copies the tool beside deploy.sh",
       '"requirements.lock"' in mr and '"deploy", "safe_libraries.py"' in mr)
# the rules catch a broken copy
broken_tool = tool_src.replace('"--require-hashes",\n', "").replace('"--require-hashes", ', "")
ok("the rules catch a tool whose install lost --require-hashes", tool_rules(broken_tool) != [])
broken_dep = read(paths["deploy/install.sh"]).replace("python3 deploy/safe_libraries.py install", ".venv/bin/pip install -r requirements.txt #")
ok("the rules catch deploy/install.sh going back to pip install -r requirements.txt", installer_rules(broken_dep, "x") != [])
ok("the rules catch a CI step without --require-hashes", unsafe_pip("python -m pip install -r platform/requirements.lock", True) != [])

# ------------------------------------------------------------------------------------------------ 2. the locks
print("\n2. Every lock fits its caps")
pairs = [("platform", os.path.join(HERE, "requirements.lock"), os.path.join(HERE, "requirements.txt"))]
if PIPE:
    pairs.append(("database pipeline", os.path.join(PIPE, "requirements.lock"), os.path.join(PIPE, "requirements.txt")))
if DOCS:
    pairs.append(("docs site", os.path.join(os.path.dirname(DOCS), "requirements.lock"), DOCS))
for name, lock, req in pairs:
    probs = S.lock_problems(lock, req) if os.path.exists(lock) else ["no requirements.lock"]
    ok(f"{name}: requirements.lock fits requirements.txt (exact versions, hashes, inside the caps)", not probs, probs)
ok("versions and caps compare as pip does", all([S.inside("3.1.3", ">=3.0,<4"), not S.inside("4.0", ">=3.0,<4"), S.inside("26.2.0", ">=26.2,<27"),
                                                 S.inside("2026.6", ">=2024.1,<2100"), S.inside("9.7.7", "==9.7.7"), not S.inside("9.7.8", "==9.7.7"),
                                                 S.inside("1.4.2", "~=1.4"), not S.inside("2.0", "~=1.4"), S.inside("50.0.2", ">=42"),
                                                 not S.inside("1.0rc1", ">=0.1"), S.inside("3.2", "==3.*"), not S.inside("3.2", "!=3.*")]))
W = tempfile.mkdtemp(prefix="lg-supply-check-")
try:
    def made(name, text):
        p = os.path.join(W, name)
        with open(p, "w", encoding="utf-8") as f:
            f.write(text)
        return p
    h1, h2 = "a" * 64, "b" * 64
    req = made("req.txt", "lgdemo-a>=1.0,<2\nlgdemo-b>=3\n")
    p = S.lock_problems(made("over.lock", f"lgdemo-a==2.0 --hash=sha256:{h1}\nlgdemo-b==3.1 --hash=sha256:{h2}\n"), req)
    ok("a lock entry outside its cap fails", any("outside its cap" in x for x in p), p)
    r = subprocess.run([sys.executable, TOOL, "check-lock", "--lock", os.path.join(W, "over.lock"), "--requirements", req],
                       capture_output=True, text=True)
    ok("…and check-lock says so with its exit code", r.returncode == S.BAD_LOCK and "outside its cap" in r.stderr, r.stderr)
    p = S.lock_problems(made("miss.lock", f"lgdemo-a==1.5 --hash=sha256:{h1}\n"), req)
    ok("a library of requirements.txt missing from the lock fails", any("not in the lock" in x for x in p), p)
    p = S.lock_problems(made("nohash.lock", f"lgdemo-a==1.5 --hash=sha256:{h1}\nlgdemo-b==3.1\n"), req)
    ok("a lock line without its sha256 values fails", any("no sha256" in x or "not an exact version" in x for x in p), p)
    p = S.lock_problems(made("src.lock", f"--extra-index-url https://example.invalid/simple\nlgdemo-a==1.5 --hash=sha256:{h1}\n"), req)
    ok("a lock that adds a source fails", any("not allowed in a lock" in x for x in p), p)
    p = S.lock_problems(made("loose.lock", f"lgdemo-a>=1.5 --hash=sha256:{h1}\nlgdemo-b==3.1 --hash=sha256:{h2}\n"), req)
    ok("a lock line without an exact version fails", bool(p), p)

    # -------------------------------------------------------------------------------------------- 3. the machine
    print("\n3. Which computers are accepted")
    def osr(id_, ver, pretty):
        return {"ID": id_, "VERSION_ID": ver, "PRETTY_NAME": pretty}
    good = [(u, py, m) for u in ("24.04", "25.04", "25.10", "26.04") for py in S.PYTHONS for m in S.MACHINES]
    acc = [x for x in good if S.machine_problems(osr("ubuntu", x[0], f"Ubuntu {x[0]}"), x[1], x[2])]
    ok(f"accepted: Ubuntu 24.04/25.04/25.10/26.04 x Python 3.12/3.13/3.14 x x86_64/aarch64 ({len(good)} combinations)", not acc, acc)
    refused = {"Debian 13": (osr("debian", "13", "Debian GNU/Linux 13 (trixie)"), "3.13", "x86_64"),
               "Ubuntu 22.04": (osr("ubuntu", "22.04", "Ubuntu 22.04.5 LTS"), "3.12", "x86_64"),
               "Fedora": (osr("fedora", "42", "Fedora Linux 42"), "3.13", "x86_64"),
               "Linux Mint (ID_LIKE ubuntu)": ({"ID": "linuxmint", "ID_LIKE": "ubuntu", "VERSION_ID": "22", "PRETTY_NAME": "Linux Mint 22"}, "3.12", "x86_64"),
               "Python 3.11": (osr("ubuntu", "24.04", "Ubuntu 24.04"), "3.11", "x86_64"),
               "Python 3.15": (osr("ubuntu", "26.04", "Ubuntu 26.04"), "3.15", "x86_64"),
               "i686": (osr("ubuntu", "24.04", "Ubuntu 24.04"), "3.12", "i686"),
               "armv7": (osr("ubuntu", "24.04", "Ubuntu 24.04"), "3.12", "armv7l")}
    for label, (o, py, m) in refused.items():
        why = S.machine_problems(o, py, m)
        ok(f"refused, with the reason: {label}", len(why) == 1, why)
    for label, text, py, m, code in (("Ubuntu 26.04, Python 3.13, aarch64", 'ID=ubuntu\nVERSION_ID="26.04"\nPRETTY_NAME="Ubuntu 26.04 LTS"\n', "3.13", "aarch64", 0),
                                     ("Debian 13", 'ID=debian\nVERSION_ID="13"\nPRETTY_NAME="Debian GNU/Linux 13"\n', "3.13", "x86_64", 2),
                                     ("Ubuntu 22.04", 'ID=ubuntu\nVERSION_ID="22.04"\nPRETTY_NAME="Ubuntu 22.04 LTS"\n', "3.12", "x86_64", 2)):
        r = subprocess.run([sys.executable, TOOL, "check-machine", "--os-release", made("os-release", text), "--python-version", py,
                            "--machine", m], capture_output=True, text=True)
        ok(f"check-machine from an os-release file: {label} -> exit {code}", r.returncode == code, (r.stdout + r.stderr)[-300:])

    # -------------------------------------------------------------------------------------------- 4. a local index
    print("\n4. Installing from a local package index (127.0.0.1)")

    def wheel(dest, dist, version, tag, extra=b"", requires=()):
        """A tiny wheel (a valid zip with its METADATA, WHEEL and RECORD); extra bytes make a poisoned twin."""
        mod = dist.replace("-", "_")
        name = f"{mod}-{version}-{tag}.whl"
        di = f"{mod}-{version}.dist-info"
        files = {f"{mod}/__init__.py": b"VALUE = 'genuine'\n" + extra,
                 f"{di}/METADATA": ("Metadata-Version: 2.1\nName: %s\nVersion: %s\n%s" % (
                     dist, version, "".join(f"Requires-Dist: {r}\n" for r in requires))).encode(),
                 f"{di}/WHEEL": ("Wheel-Version: 1.0\nGenerator: lg-check\nRoot-Is-Purelib: true\n"
                                 + "".join(f"Tag: {t}\n" for t in _expand(tag))).encode()}
        rec = []
        for p, b in files.items():
            d = base64.urlsafe_b64encode(hashlib.sha256(b).digest()).rstrip(b"=").decode()
            rec.append(f"{p},sha256={d},{len(b)}")
        files[f"{di}/RECORD"] = ("\n".join(rec + [f"{di}/RECORD,,"]) + "\n").encode()
        os.makedirs(dest, exist_ok=True)
        with zipfile.ZipFile(os.path.join(dest, name), "w") as z:
            for p, b in files.items():
                z.writestr(zipfile.ZipInfo(p, (2026, 1, 1, 0, 0, 0)), b)
        return name

    def _expand(tag):
        py, abi, plats = tag.split("-")
        return [f"{py}-{abi}-{p}" for p in plats.split(".")]

    PLAT = {(py, m): f"cp{py.replace('.', '')}-cp{py.replace('.', '')}-manylinux_2_17_{m}.manylinux2014_{m}"
            for py in S.PYTHONS for m in S.MACHINES}
    good_dir = os.path.join(W, "good")
    bad_dir = os.path.join(W, "poisoned")
    names = {"pure": wheel(good_dir, "lgdemo-pure", "1.0", "py3-none-any")}
    wheel(bad_dir, "lgdemo-pure", "1.0", "py3-none-any", extra=b"import os  # a changed file\n")
    for k, tag in PLAT.items():
        names[k] = wheel(good_dir, "lgdemo-plat", "1.0", tag)
        wheel(bad_dir, "lgdemo-plat", "1.0", tag, extra=b"# changed\n")
    names["needy"] = wheel(good_dir, "lgdemo-needy", "1.0", "py3-none-any", requires=("lgdemo-extra",))
    names["extra"] = wheel(good_dir, "lgdemo-extra", "1.0", "py3-none-any")
    gh = {f: S.sha256(os.path.join(good_dir, f)) for f in os.listdir(good_dir)}

    def lock(*libs):
        out = []
        for dist in libs:
            mod = dist.replace("-", "_")
            hs = sorted(h for f, h in gh.items() if f.startswith(mod + "-"))
            out.append(f"{dist}==1.0 \\\n" + " \\\n".join(f"    --hash=sha256:{h}" for h in hs))
        return made(f"lock-{'-'.join(libs)}.lock", "\n".join(out) + "\n")

    SERVE = os.path.join(W, "serve")

    def source_tree(scen, pypi_bad=(), repo_bad=(), local_bad=(), libs=("lgdemo-pure", "lgdemo-plat")):
        """PyPI (a simple index), the library repository (a bundle) and a local copy for one scenario; the *_bad
        libraries are served poisoned there."""
        root = os.path.join(SERVE, scen)
        files = os.path.join(root, "files")
        os.makedirs(files, exist_ok=True)
        links = {}
        for dist in libs:
            mod = dist.replace("-", "_")
            for f in os.listdir(good_dir):
                if f.startswith(mod + "-"):
                    src = os.path.join(bad_dir if dist in pypi_bad else good_dir, f)
                    shutil.copy2(src, os.path.join(files, f))
                    links.setdefault(dist, []).append(f)
        os.makedirs(os.path.join(root, "simple"), exist_ok=True)
        with open(os.path.join(root, "simple", "index.html"), "w") as fh:
            fh.write("".join(f'<a href="{d}/">{d}</a>\n' for d in links))
        for d, fl in links.items():
            os.makedirs(os.path.join(root, "simple", d), exist_ok=True)
            with open(os.path.join(root, "simple", d, "index.html"), "w") as fh:
                fh.write("".join(f'<a href="../../files/{f}">{f}</a>\n' for f in fl))
        rel = os.path.join(root, "releases", "v-test")
        os.makedirs(rel, exist_ok=True)
        with tarfile.open(os.path.join(rel, "looking-glass-libraries-v-test.tar.gz"), "w:gz") as tf:
            for dist, fl in links.items():
                for f in fl:
                    tf.add(os.path.join(bad_dir if dist in repo_bad else good_dir, f), arcname=f"platform/{f}")
        local = os.path.join(W, "local", scen)
        d = os.path.join(local, "v-old", "platform")
        os.makedirs(d, exist_ok=True)
        for dist, fl in links.items():
            for f in fl:
                shutil.copy2(os.path.join(bad_dir if dist in local_bad else good_dir, f), os.path.join(d, f))
        return local

    class Quiet(http.server.SimpleHTTPRequestHandler):
        def log_message(self, *a):
            pass

    os.makedirs(SERVE, exist_ok=True)
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), functools.partial(Quiet, directory=SERVE))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    PORT = httpd.server_address[1]
    UB = made("ubuntu-os-release", 'ID=ubuntu\nVERSION_ID="26.04"\nPRETTY_NAME="Ubuntu 26.04 LTS"\n')

    def tool(scen, *args, local=None):
        env = {k: v for k, v in os.environ.items()          # (the outside-connection guard, LG_NO_OUTSIDE, stays on)
               if not k.startswith("PIP_") and k not in ("LG_PYPI_URL", "LG_LIBRARIES_URL", "LG_LIBRARIES_DIR", "LG_RELEASE")}
        env.update(LG_PYPI_URL=f"http://127.0.0.1:{PORT}/{scen}/simple",
                   LG_LIBRARIES_URL=f"http://127.0.0.1:{PORT}/{scen}/releases/{{release}}/looking-glass-libraries-{{release}}.tar.gz",
                   LG_LIBRARIES_DIR=local or os.path.join(W, "local", scen))
        return subprocess.run([sys.executable, TOOL, *args], capture_output=True, text=True, env=env, timeout=900)

    both = lock("lgdemo-pure", "lgdemo-plat")
    source_tree("combos")
    for (py, m), tag in sorted(PLAT.items()):
        out = os.path.join(W, f"fetched-{py}-{m}")
        r = tool("combos", "fetch", "--lock", both, "--dir", out, "--part", "platform", "--release", "v-test",
                 "--os-release", UB, "--python-version", py, "--machine", m)
        got = sorted(os.listdir(out)) if os.path.isdir(out) else []
        ok(f"Python {py} on {m}: its own files (the pure one and {tag.split('-')[0]}/{m})",
           r.returncode == 0 and got == sorted([names["pure"], names[(py, m)]]), (got, r.stderr[-300:]))
    for label, py, m in (("Python 3.11", "3.11", "x86_64"), ("Python 3.15", "3.15", "x86_64"), ("i686", "3.12", "i686"), ("armv7", "3.12", "armv7l")):
        r = tool("combos", "fetch", "--lock", both, "--dir", os.path.join(W, "never"), "--os-release", UB, "--python-version", py, "--machine", m)
        ok(f"{label}: refused before anything is fetched", r.returncode == S.REFUSED and not os.path.exists(os.path.join(W, "never")), r.stderr[-200:])
    deb = made("debian-os-release", 'ID=debian\nVERSION_ID="13"\nPRETTY_NAME="Debian GNU/Linux 13 (trixie)"\n')
    r = tool("combos", "install", "--lock", both, "--venv", os.path.join(W, "never", ".venv"), "--os-release", deb)
    ok("Debian: install refused, nothing made", r.returncode == S.REFUSED and not os.path.exists(os.path.join(W, "never")), r.stderr[-200:])

    host = f"{sys.version_info[0]}.{sys.version_info[1]}"
    import platform as _platform
    if host not in S.PYTHONS or _platform.machine() not in S.MACHINES:
        print(f"  (the install cases need Python 3.12-3.14 on x86_64/aarch64; this is {host} on {_platform.machine()}: skipped)")
    else:
        inst = os.path.join(W, "inst")
        os.makedirs(inst)
        venv = os.path.join(inst, ".venv")
        vpy = os.path.join(venv, "bin", "python")

        def installed_value():
            r = subprocess.run([vpy, "-c", "import lgdemo_pure, lgdemo_plat; print(lgdemo_pure.VALUE, len(open(lgdemo_pure.__file__).read()))"],
                               capture_output=True, text=True)
            return r.stdout.strip()

        source_tree("clean")
        r = tool("clean", "install", "--lock", both, "--venv", venv, "--part", "platform", "--release", "v-test",
                 "--report-dir", inst, "--os-release", UB, "--import", "lgdemo_pure,lgdemo_plat")
        ok("clean install: exit 0, .venv is a link into .venvs", r.returncode == 0 and os.path.islink(venv), (r.stdout + r.stderr)[-500:])
        ok("clean install: the genuine files are what the new environment loads", installed_value().startswith("genuine"), installed_value())
        loc = os.path.join(W, "local", "clean", "v-test", "platform")
        ok("clean install: the checked files kept read-only in the local copy, with SHA256SUMS",
           os.path.isdir(loc) and len(os.listdir(loc)) == 2 and (os.geteuid() == 0 or not os.access(loc, os.W_OK))
           and os.path.exists(os.path.join(os.path.dirname(loc), "SHA256SUMS")), loc)
        ok("clean install: no report (nothing was refused)", not os.path.exists(os.path.join(inst, "suspected-packages.json")))
        r = tool("clean", "install", "--lock", both, "--venv", venv, "--part", "platform", "--release", "v-test", "--os-release", UB)
        ok("the same lock again: nothing to do", r.returncode == 0 and "nothing to do" in r.stdout, r.stdout[-200:])

        source_tree("pypi-bad", pypi_bad=("lgdemo-pure",))
        before = os.readlink(venv)
        r = tool("pypi-bad", "install", "--force", "--lock", both, "--venv", venv, "--part", "platform", "--release", "v-test",
                 "--report-dir", inst, "--os-release", UB)
        def report_events():
            try:
                with open(os.path.join(inst, "suspected-packages.json"), encoding="utf-8") as fh:
                    return json.load(fh).get("events") or []
            except (OSError, ValueError):
                return []
        ev = (report_events() or [{}])[-1]
        bad_hash = S.sha256(os.path.join(bad_dir, names["pure"]))
        ok("PyPI poisoned, the library repository clean: installed and flagged (exit 10)", r.returncode == S.FLAGGED, (r.stdout + r.stderr)[-500:])
        ok("…the warning names library, version, source, expected and received sha256",
           all(s in r.stderr for s in ("WARNING", "lgdemo-pure 1.0", "PyPI", gh[names["pure"]], bad_hash)), r.stderr[-600:])
        ok("…the report has it (library, version, source URL, expected, received, time)",
           ev.get("library") == "lgdemo-pure" and ev.get("version") == "1.0" and ev.get("source") == "PyPI"
           and str(PORT) in ev.get("source_url", "") and ev.get("received") == bad_hash and gh[names["pure"]] in ev.get("expected", [])
           and ev.get("time") and os.path.exists(os.path.join(inst, "suspected-packages.txt")), ev)
        ok("…the genuine file was installed, and .venv switched to the new environment",
           installed_value().startswith("genuine") and "import os" not in installed_value() and os.readlink(venv) != before,
           (installed_value(), before, os.readlink(venv)))
        ok("…the environment before it is kept in .venvs", os.path.isdir(os.path.join(inst, before)))

        source_tree("two-bad", pypi_bad=("lgdemo-pure",), repo_bad=("lgdemo-pure",))
        r = tool("two-bad", "install", "--force", "--lock", both, "--venv", venv, "--part", "platform", "--release", "v-test",
                 "--report-dir", inst, "--os-release", UB)
        evs = report_events()
        ok("PyPI and the library repository poisoned, the local copy clean: installed and flagged",
           r.returncode == S.FLAGGED and installed_value().startswith("genuine")
           and {e["source"] for e in evs[-2:]} == {"PyPI", "the library repository"}, (r.stderr[-400:], evs[-2:]))

        source_tree("all-bad", pypi_bad=("lgdemo-pure",), repo_bad=("lgdemo-pure",), local_bad=("lgdemo-pure",))
        before, stamp = os.readlink(venv), read(os.path.join(venv, S.LOCK_STAMP))
        kept = sorted(os.listdir(os.path.join(inst, ".venvs")))
        r = tool("all-bad", "install", "--force", "--lock", both, "--venv", venv, "--part", "platform", "--release", "v-test",
                 "--report-dir", inst, "--os-release", UB)
        evs = report_events()
        ok("every source poisoned: stopped with 'Nothing was changed' (exit 3)", r.returncode == S.STOPPED and "Nothing was changed" in r.stderr,
           r.stderr[-400:])
        ok("…the running environment is untouched (same link, same environment, nothing left over)",
           os.readlink(venv) == before and read(os.path.join(venv, S.LOCK_STAMP)) == stamp
           and sorted(os.listdir(os.path.join(inst, ".venvs"))) == kept and installed_value().startswith("genuine"))
        ok("…and the three refusals are in the report, marked stopped",
           len(evs) >= 6 and all(e["outcome"].startswith("stopped") for e in evs[-3:]), evs[-3:])

        needy = lock("lgdemo-needy")
        source_tree("unlisted", libs=("lgdemo-needy", "lgdemo-extra"))
        before = os.readlink(venv)
        r = tool("unlisted", "install", "--force", "--lock", needy, "--venv", venv, "--part", "platform", "--release", "v-test",
                 "--report-dir", inst, "--os-release", UB)
        ok("a library the lock does not list (a dependency) is refused by pip; nothing changed",
           r.returncode == S.STOPPED and "Nothing was changed" in r.stderr and os.readlink(venv) == before, r.stderr[-400:])
        unh = made("unhashed.lock", read(needy) + "lgdemo-extra==1.0\n")
        r = tool("unlisted", "install", "--lock", unh, "--venv", venv, "--os-release", UB)
        ok("a library listed without its sha256 values: refused before anything (exit 4)", r.returncode == S.BAD_LOCK and os.readlink(venv) == before,
           r.stderr[-300:])

        # the report reaches the audit log (once) and the administrators' bell
        import library_supply as L
        written = []

        class FakeAudit:
            def add(self, event, **kw):
                written.append((event, kw))
        os.makedirs(os.path.join(inst, "data"), exist_ok=True)
        n1, n2 = L.audit_new(inst, FakeAudit()), L.audit_new(inst, FakeAudit())
        ok("each refused file goes into the audit log once, as a system event",
           n1 == len(evs) and n2 == 0 and written and written[0][0] == "library_suspected"
           and written[0][1].get("user") == L.SYSTEM_USER and "lgdemo-pure 1.0" == written[0][1].get("target"), (n1, n2, written[:1]))
        import audit_portal
        ok("the Audit portal lists it under System, with a readable label",
           audit_portal.TAB_OF.get("library_suspected") == "system" and "library_suspected" in audit_portal.LABEL)
        b = L.bell(inst)
        ok("one bell alert for administrators, naming the library and how to report it",
           len(b) == 1 and b[0]["perms"] == ("settings",) and "lgdemo-pure 1.0" in b[0]["text"] and "INSTALLATION.md" in b[0]["text"], b)
        import system_alerts
        sa = system_alerts.Alerts(inst, env={})
        ok("system_alerts shows it in the bell", any(a["key"].startswith("suspected-packages:") for a in sa.current()))
    httpd.shutdown()
finally:
    for top, dirs, files in os.walk(W):
        for d in dirs:
            try:
                os.chmod(os.path.join(top, d), 0o755)
            except OSError:
                pass
    shutil.rmtree(W, ignore_errors=True)

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
