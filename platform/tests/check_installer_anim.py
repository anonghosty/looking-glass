#!/usr/bin/env python3
"""The installer's animated logo (tools/release_root/installer_anim.py, 2026-11-14), run in a pseudo-terminal as a
person would see it: the splash draws the logo and ends by itself, the progress screen follows its status file and
gives the terminal back when told STOP, and install.sh only animates for a person at a real terminal.
Run: .venv/bin/python tests/check_installer_anim.py"""
import fcntl
import os
import pty
import re
import select
import struct
import sys
import tempfile
import termios
import time

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def _release_file(name):
    """A file of the release's top level: beside platform/ in an installation or the GitHub repository, or in
    tools/release_root/ in the development tree."""
    for p in (os.path.join(HERE, "..", name), os.path.join(HERE, "tools", "release_root", name)):
        if os.path.isfile(p):
            return os.path.abspath(p)
    return os.path.join(HERE, "..", name)

ANIM = _release_file("installer_anim.py")
INSTALL = _release_file("install.sh")
checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info and not cond else ""))


def run_in_pty(args, cols=80, rows=24, during=None, limit=8.0):
    """Run in a pseudo-terminal of the given size; returns (seconds, exit code, everything written)."""
    pid, fd = pty.fork()
    if pid == 0:
        # the size is set on the child's own terminal before it starts, so its first look already sees it
        fcntl.ioctl(0, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
        os.environ.update(COLORTERM="truecolor", TERM="xterm-256color")
        os.execv(sys.executable, [sys.executable, ANIM] + args)
    out, t0, done = b"", time.time(), None
    while time.time() - t0 < limit:
        if during and time.time() - t0 > during[0]:
            during[1](); during = None
        r, _, _ = select.select([fd], [], [], 0.05)
        if r:
            try:
                chunk = os.read(fd, 65536)
            except OSError:
                chunk = b""
            if not chunk:                       # the program ended: collect its exit code
                _, status = os.waitpid(pid, 0)
                done = os.waitstatus_to_exitcode(status)
                break
            out += chunk
        wp, status = os.waitpid(pid, os.WNOHANG)
        if wp:
            done = os.waitstatus_to_exitcode(status)
            break
    if done is None:
        os.kill(pid, 9); os.waitpid(pid, 0)
    return time.time() - t0, done, out.decode("utf-8", "replace")


print("The splash")
secs, rc, out = run_in_pty(["splash"])
ok("runs in a standard 80 x 24 terminal and ends by itself in about 2 seconds", rc == 0 and secs < 4, f"{secs:.1f}s rc={rc}")
ok("…draws the logo in half blocks, in true colour", "▀" in out and "\x1b[38;2;" in out)
ok("…with the name", "L O O K I N G" in out)
ok("…and gives the terminal back as it was (alternate screen, cursor shown again)", out.count("\x1b[?1049h") == 1 and out.rstrip().endswith("\x1b[?1049l"))
secs, rc, out = run_in_pty(["splash"], cols=30, rows=10)
ok("a terminal too small for it: nothing drawn, no error", rc == 0 and "▀" not in out)

print("The progress screen")
st = tempfile.mktemp()
open(st, "w").write("40\nFetching the reports of the last 7 days\n")
secs, rc, out = run_in_pty(["progress", st, "/tmp/install.log"], cols=100, rows=36,
                           during=(1.2, lambda: open(st, "w").write("STOP\n")))
ok("shows the step, the bar and the log, then ends when told STOP", rc == 0 and secs < 3
   and "Fetching the reports" in out and "40%" in out and "/tmp/install.log" in out, f"{secs:.1f}s rc={rc}")
ok("…and gives the terminal back", out.rstrip().endswith("\x1b[?1049l"))
ok("…the logo animates (more than one frame drawn)", len(re.findall(r"\x1b\[4;\d+H", out)) > 3)
open(st, "w").write("1\nx\n")
secs, rc, out = run_in_pty(["progress", st], cols=80, rows=24, during=(0.8, lambda: open(st, "w").write("STOP\n")))
ok("a standard 80 x 24 terminal: still the logo, smaller", rc == 0 and "▀" in out)

print("install.sh animates only for a person at a real terminal")
src = open(INSTALL, encoding="utf-8").read()
ok("--no-animation turns it off, and is in the help", "--no-animation) NO_ANIM=1" in src and "--no-animation      no animated logo" in src)
ok("never for an unattended installation, NO_COLOR or a dumb terminal",
   all(x in src for x in ('[ -z "$ANSWERS" ]', '[ "$ASSUME_YES" = 0 ]', '[ -z "${NO_COLOR:-}" ]', '[ "${TERM:-dumb}" != dumb ]')))
ok("the progress screen is stopped on every way out (gauge_close: STOP, then wait)", 'echo STOP > "$GAUGE_STATUS"' in src
   and src.count("gauge_close") >= 6)

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
