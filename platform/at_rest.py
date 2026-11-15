"""Encryption at rest: is what Looking Glass keeps on a disk volume that is encrypted? (review of d82a436; NIST SP 800-53
SC-28). MongoDB Community does not encrypt its files, so the volume does it: LUKS (dm-crypt) on Linux, BitLocker for a
Windows computer running Looking Glass in WSL. Nothing is changed here: this only looks, for the Task monitor and the
guided installer.

status(paths) -> [{"what", "path", "state", "detail"}], state one of:
  "encrypted"      the path is on a dm-crypt (LUKS) device, directly or under LVM
  "not encrypted"  it is on a plain disk or partition
  "wsl"            inside WSL the Windows drive decides: BitLocker cannot be seen from here, check it in Windows
  "unknown"        the path or its device could not be looked at (permissions, a container, missing tools)
summary(rows) -> "encrypted" | "not encrypted" | "check Windows" | "unknown" (the weakest of the rows)
mongo_dbpath() -> MongoDB's data folder from /etc/mongod.conf (default /var/lib/mongodb)
"""
import os
import re
import subprocess

_WSL = None
_exists = os.path.exists


def is_wsl():
    global _WSL
    if _WSL is None:
        try:
            with open("/proc/version", encoding="utf-8") as f:
                _WSL = "microsoft" in f.read().lower()
        except OSError:
            _WSL = False
    return _WSL


def mongo_dbpath(conf="/etc/mongod.conf"):
    try:
        with open(conf, encoding="utf-8") as f:
            m = re.search(r"^\s*dbPath:\s*(\S+)", f.read(), re.M)
            if m:
                return m.group(1).strip("'\"")
    except OSError:
        pass
    return "/var/lib/mongodb"


def _run(cmd):
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
    return r.stdout.strip() if r.returncode == 0 else ""


def one(path):
    """(state, detail) for one path."""
    p = path
    while p and p != "/" and not _exists(p):    # a folder not made yet: the volume it would be on
        p = os.path.dirname(p.rstrip("/")) or "/"
    if is_wsl():
        return "wsl", "inside WSL: the Windows drive holding WSL's disk decides; check that BitLocker is on in Windows"
    try:
        src = _run(["findmnt", "-n", "-o", "SOURCE", "--target", p])
        if not src:
            return "unknown", "its volume could not be found (findmnt)"
        src = re.sub(r"\[.*\]$", "", src)       # btrfs subvolumes: /dev/sda2[/@home]
        if not src.startswith("/dev/"):
            return "unknown", f"on {src}, not a disk device this check can follow"
        types = _run(["lsblk", "-s", "-n", "-o", "TYPE", src]).split()
        if not types:
            return "unknown", f"on {src}; its devices could not be listed (lsblk)"
        if "crypt" in types:
            return "encrypted", f"on {src}, an encrypted (LUKS) volume"
        return "not encrypted", f"on {src}, not an encrypted volume"
    except (OSError, subprocess.SubprocessError):
        return "unknown", "the check could not run (findmnt / lsblk missing)"


def status(paths):
    rows = []
    for what, path in paths.items():
        if not path:
            continue
        state, detail = one(path)
        rows.append({"what": what, "path": path, "state": state, "detail": detail})
    return rows


def summary(rows):
    states = {r["state"] for r in rows}
    if "not encrypted" in states:
        return "not encrypted"
    if "unknown" in states:
        return "unknown"
    if "wsl" in states:
        return "check Windows"
    return "encrypted" if rows else "unknown"


if __name__ == "__main__":                       # the installer: python3 at_rest.py PATH... (label=path)
    import sys
    rows = status({a.split("=", 1)[0]: a.split("=", 1)[1] for a in sys.argv[1:] if "=" in a})
    for r in rows:
        print(f"{r['state']:<14} {r['what']}: {r['path']} ({r['detail']})")
    print(f"SUMMARY {summary(rows)}")
