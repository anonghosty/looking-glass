#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""Encryption at rest, as the Task monitor and installer report it (at_rest.py): a path on a LUKS (dm-crypt) volume,
directly or under LVM, is "encrypted"; on a plain disk "not encrypted"; inside WSL "wsl" (BitLocker decides, not
visible from inside); anything it cannot look at "unknown", never a guess. The summary takes the weakest. MongoDB's
folder comes from mongod.conf. The device tools are faked. No database needed.
Run: .venv/bin/python tests/check_at_rest.py"""
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
import at_rest as A  # noqa: E402

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info and not cond else ""))


DEV = {"/data": "/dev/mapper/vg-data", "/plain": "/dev/sda2", "/btr": "/dev/sdb1[/@home]", "/net": "server:/export"}
TREE = {"/dev/mapper/vg-data": "lvm\ncrypt\npart\ndisk", "/dev/sda2": "part\ndisk", "/dev/sdb1": "part\ndisk"}


def fake_run(cmd):
    if cmd[0] == "findmnt":
        t = cmd[-1]
        return next((v for k, v in DEV.items() if t.startswith(k)), "")
    if cmd[0] == "lsblk":
        return TREE.get(cmd[-1], "")
    return ""


A._run = fake_run
A._WSL = False
A._exists = lambda p: "not/yet" not in p          # every fake path exists, except a folder not made yet
ok("LVM on LUKS: encrypted", A.one("/data/mongodb")[0] == "encrypted", A.one("/data/mongodb"))
ok("a plain partition: not encrypted", A.one("/plain/x")[0] == "not encrypted")
ok("a btrfs subvolume is followed to its device", A.one("/btr/x")[0] == "not encrypted", A.one("/btr/x"))
ok("a network share: unknown, never a guess", A.one("/net/x")[0] == "unknown")
ok("no volume found: unknown", A.one("/nowhere/x")[0] == "unknown")
ok("a folder not made yet: the volume it would be on", A.one("/data/not/yet/made")[0] == "encrypted")
rows = A.status({"data": "/data/lg", "copies": "/plain/copies", "none": None})
ok("status lists each path given (none skipped)", [r["what"] for r in rows] == ["data", "copies"])
ok("summary: the weakest (one plain disk: not encrypted)", A.summary(rows) == "not encrypted")
ok("summary: all encrypted", A.summary(A.status({"a": "/data/a", "b": "/data/b"})) == "encrypted")
ok("summary: something unknown", A.summary(A.status({"a": "/data/a", "b": "/net/b"})) == "unknown")
A._WSL = True
r = A.one("/data/x")
ok("inside WSL: 'wsl', and it says to check BitLocker in Windows", r[0] == "wsl" and "BitLocker" in r[1])
ok("summary inside WSL: check Windows", A.summary(A.status({"a": "/data/a"})) == "check Windows")
with tempfile.NamedTemporaryFile("w", delete=False, suffix=".conf") as f:
    f.write("storage:\n  dbPath: /srv/mongo\n  journal:\n    enabled: true\n")
ok("MongoDB's folder from mongod.conf", A.mongo_dbpath(f.name) == "/srv/mongo")
os.unlink(f.name)
ok("…the default when there is none", A.mongo_dbpath("/no/such.conf") == "/var/lib/mongodb")

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
