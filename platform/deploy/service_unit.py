#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""The Looking Glass service file: written from deploy/looking-glass.service.template, and kept up to date.

The service runs sandboxed: it may read its code but write only data/ (ProtectSystem=strict, ReadOnlyPaths= the
folder, ReadWritePaths= data/ only, nothing in data/ may be run: NoExecPaths). Updates run as you, outside that
sandbox, so the code stays yours to change. When a release changes the template, the installed service file is
out of date until it is copied again; this script says so and does it, with sudo only when you ask.

  deploy/service_unit.py render --user U --project DIR --bind ADDR:PORT [--out FILE]
        the service file for that user, folder and address (deploy/install.sh uses it)
  deploy/service_unit.py check [--name NAME]
        compare the installed service file with the one this release would write; never needs sudo
        (exit 0 the same, 3 out of date, 4 not installed here or not this folder's service)
  deploy/service_unit.py install [--name NAME] [--yes]
        write the new service file (same user, folder and address as the installed one), keep a copy of the old one
        in backups/, then copy it in with sudo, reload systemd and restart the service. It shows what changes and
        asks first (--yes: do not ask)

NAME is LG_SERVICE from .env, else looking-glass. Your own additions made with `sudo systemctl edit NAME` live in
/etc/systemd/system/NAME.service.d/ and are kept: only NAME.service itself is replaced.
"""
import difflib
import os
import re
import shutil
import subprocess  # nosec B404  # fixed commands only (systemd-analyze, sudo install, systemctl), no shell
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
PROJECT = os.path.dirname(HERE)
TEMPLATE = os.path.join(HERE, "looking-glass.service.template")
SYSTEMD_DIR = os.environ.get("LG_SYSTEMD_DIR") or "/etc/systemd/system"   # another folder only in the checks


def render(template_text, user, project, bind):
    """The service file for this user, folder and address. A port under 1024 (443 for a domain with its certificate)
    gets the one capability needed to listen on it, CAP_NET_BIND_SERVICE, and nothing else."""
    for name, value in (("user", user), ("project", project), ("bind", bind)):
        if not value or "\n" in value or "|" in value:
            raise ValueError(f"{name} is empty or holds a character a service file cannot carry: {value!r}")
    if not re.fullmatch(r"[A-Za-z0-9._:\[\]-]+:[0-9]{1,5}", bind):
        raise ValueError(f"the address must be HOST:PORT, not {bind!r}")
    # the template's licence lines (SPDX, r91) are for the source file only: the written service file stays as before,
    # so an installed one is not reported out of date for a comment
    template_text = re.sub(r"(?m)^# SPDX-[A-Za-z]+(?:-[A-Za-z]+)*:.*\n", "", template_text)
    text = template_text.replace("@USER@", user).replace("@PROJECT@", project).replace("@BIND@", bind)
    if int(bind.rsplit(":", 1)[1]) < 1024:
        text = re.sub(r"(?m)^CapabilityBoundingSet=$", "CapabilityBoundingSet=CAP_NET_BIND_SERVICE", text)
        text = re.sub(r"(?m)^AmbientCapabilities=$", "AmbientCapabilities=CAP_NET_BIND_SERVICE", text)
    return text


def directives(text, section="Service"):
    """{key: [values in order]} of one section of a unit file (comments and blank lines left out)."""
    out, current = {}, None
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            current = line[1:-1]
            continue
        if current == section and "=" in line:
            k, v = line.split("=", 1)
            out.setdefault(k.strip(), []).append(v.strip())
    return out


def paths_of(d, key):
    """Every path named by KEY (several lines, several paths per line; a leading '-' or '+' left out)."""
    return [p.lstrip("-+") for v in d.get(key, []) for p in v.split()]


def installed_values(unit_text):
    """(user, folder, address) of an installed service file, or None when it is not one deploy/install.sh wrote."""
    d = directives(unit_text)
    user = (d.get("User") or [""])[-1]
    project = (d.get("WorkingDirectory") or [""])[-1]
    m = re.search(r"--bind\s+(\S+)", " ".join(d.get("ExecStart") or []))
    if not (user and project and m):
        return None
    return user, project.rstrip("/"), m.group(1)


def service_name():
    """LG_SERVICE from .env (the last such line, as deploy/reload.sh reads it), else looking-glass."""
    name = "looking-glass"
    try:
        with open(os.path.join(PROJECT, ".env"), encoding="utf-8") as f:
            for line in f:
                if line.startswith("LG_SERVICE="):
                    name = line.split("=", 1)[1].strip().strip("'\"") or name
    except OSError:
        pass
    return name


def compare(name):
    """(state, installed text, new text, message): state 'same', 'old' or 'none'."""
    unit = os.path.join(SYSTEMD_DIR, f"{name}.service")
    try:
        with open(unit, encoding="utf-8") as f:
            cur = f.read()
    except FileNotFoundError:
        return "none", "", "", f"{unit} is not installed here (a developer copy, or another computer runs the service)."
    except OSError as e:
        return "none", "", "", f"{unit} could not be read ({e.strerror})."
    vals = installed_values(cur)
    if not vals:
        return "none", cur, "", f"{unit} was not written by deploy/install.sh (no User=, WorkingDirectory= or --bind): not compared."
    user, project, bind = vals
    if os.path.realpath(project) != os.path.realpath(PROJECT):
        return "none", cur, "", f"{unit} runs {project}, not this folder ({PROJECT}): not compared."
    with open(TEMPLATE, encoding="utf-8") as f:
        new = render(f.read(), user, project, bind)
    same = [ln.rstrip() for ln in cur.strip().splitlines()] == [ln.rstrip() for ln in new.strip().splitlines()]
    return ("same" if same else "old"), cur, new, unit


def cmd_check(name):
    state, cur, new, msg = compare(name)
    if state == "none":
        print(f"Service file: {msg}")
        return 4
    if state == "same":
        print(f"Service file: {msg} is up to date.")
        return 0
    print(f"Service file: {msg} is out of date. This release's protections apply only once it is copied again.")
    sys.stdout.writelines(difflib.unified_diff(cur.splitlines(True), new.splitlines(True), "installed", "this release"))
    print(f"\nTo update it (asks for your sudo password, shows the change first, keeps a copy of the old one):\n"
          f"    deploy/service_unit.py install{'' if name == 'looking-glass' else ' --name ' + name}")
    return 3


def run(cmd):
    print("  $ " + " ".join(cmd), flush=True)
    return subprocess.run(cmd, check=False).returncode  # nosec B603  # fixed argument lists


def cmd_install(name, yes):
    state, cur, new, msg = compare(name)
    if state == "none":
        print(f"Nothing installed to update: {msg}\nA first installation: deploy/install.sh (docs/INSTALLATION.md).")
        return 4
    if state == "same":
        print(f"{msg} is up to date; nothing to do.")
        return 0
    sys.stdout.writelines(difflib.unified_diff(cur.splitlines(True), new.splitlines(True), "installed", "this release"))
    out = os.path.join(HERE, f"{name}.service")
    with open(out, "w", encoding="utf-8") as f:
        f.write(new)
    os.chmod(out, 0o644)
    if shutil.which("systemd-analyze"):
        r = subprocess.run(["systemd-analyze", "verify", out], capture_output=True, text=True, check=False)  # nosec B603 B607
        problems = [ln for ln in (r.stdout + r.stderr).splitlines() if ln.strip() and "Failed to" in ln]
        if problems:
            print("systemd-analyze found a problem in the new file; nothing was changed:\n  " + "\n  ".join(problems))
            return 1
    if not yes:
        if not sys.stdin.isatty():
            print("Not asked on a terminal: run it again with --yes to go ahead. Nothing was changed.")
            return 1
        if input(f"\nReplace {msg} with this and restart {name}? Type yes: ").strip().lower() != "yes":
            print("Nothing was changed.")
            return 1
    keep = os.path.join(PROJECT, "backups", "service-" + time.strftime("%Y%m%d-%H%M%S"))
    os.makedirs(keep, mode=0o700, exist_ok=True)
    with open(os.path.join(keep, f"{name}.service"), "w", encoding="utf-8") as f:
        f.write(cur)
    print(f"The old file is kept in {keep}/{name}.service")
    for cmd in (["sudo", "install", "-m", "644", out, msg], ["sudo", "systemctl", "daemon-reload"],
                ["sudo", "systemctl", "restart", name]):
        if run(cmd) != 0:
            print(f"Stopped at that step. To go back: sudo install -m 644 {keep}/{name}.service {msg} && "
                  f"sudo systemctl daemon-reload && sudo systemctl restart {name}")
            return 1
    for _ in range(20):
        time.sleep(1)
        if subprocess.run(["systemctl", "is-active", "--quiet", name], check=False).returncode == 0:  # nosec B603 B607
            print(f"{name} runs with the new service file. Check: systemctl status {name} --no-pager")
            return 0
    print(f"{name} did not start. See: journalctl -u {name} -n 50\nTo go back: sudo install -m 644 "
          f"{keep}/{name}.service {msg} && sudo systemctl daemon-reload && sudo systemctl restart {name}")
    return 1


def main(argv):
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        return 0

    def opt(flag, default=None):
        return argv[argv.index(flag) + 1] if flag in argv and argv.index(flag) + 1 < len(argv) else default
    if argv[0] == "render":
        user, project, bind = opt("--user"), opt("--project"), opt("--bind")
        if not (user and project and bind):
            print("render needs --user, --project and --bind")
            return 2
        with open(TEMPLATE, encoding="utf-8") as f:
            text = render(f.read(), user, project.rstrip("/"), bind)
        if opt("--out"):
            with open(opt("--out"), "w", encoding="utf-8") as f:
                f.write(text)
            os.chmod(opt("--out"), 0o644)
        else:
            sys.stdout.write(text)
        return 0
    name = opt("--name") or service_name()
    if not re.fullmatch(r"[A-Za-z0-9_.@-]+", name):
        print(f"not a service name: {name!r}")
        return 2
    if argv[0] == "check":
        return cmd_check(name)
    if argv[0] == "install":
        return cmd_install(name, "--yes" in argv)
    print(f"unknown command {argv[0]} (deploy/service_unit.py --help)")
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
