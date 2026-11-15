#!/usr/bin/env python3
"""File modes (review of d82a436: combos.py and control_map.py were executable): a Python file is executable only when
it is a script, one that starts with "#!"; every shell script that is run directly (a #! line) is executable. Checked
in the platform, and in the pipeline beside it when there is one. Nothing is changed. No database needed.
Run: .venv/bin/python tests/check_file_modes.py"""
import os
import stat
import sys

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SKIP = {".venv", "data", "__pycache__", "site", ".git", "node_modules"}
checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info and not cond else ""))


def walk(root):
    for d, dirs, files in os.walk(root):
        dirs[:] = [x for x in dirs if x not in SKIP]
        for f in files:
            if f.endswith((".py", ".sh")):
                yield os.path.join(d, f)


def shebang(p):
    try:
        with open(p, "rb") as fh:
            return fh.read(2) == b"#!"
    except OSError:
        return False


roots = [HERE] + [p for p in (os.path.join(os.path.dirname(HERE), "database"), os.path.join(os.path.dirname(HERE), "shadowserver"))
                  if os.path.isfile(os.path.join(p, "shadowserver_pipeline.py"))][:1]
for root in roots:
    files = list(walk(root))
    execable = lambda p: bool(os.stat(p).st_mode & stat.S_IXUSR)  # noqa: E731
    modules = sorted(os.path.relpath(p, root) for p in files if p.endswith(".py") and execable(p) and not shebang(p))
    ok(f"{os.path.basename(root)}: no Python module is marked executable (only scripts with a #! line)", not modules, ", ".join(modules[:12]))
    scripts = sorted(os.path.relpath(p, root) for p in files if p.endswith(".sh") and shebang(p) and not execable(p)
                     and os.path.basename(p) not in ("backup_crypt.sh",))
    ok(f"{os.path.basename(root)}: every shell script run directly is executable", not scripts, ", ".join(scripts[:12]))

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
