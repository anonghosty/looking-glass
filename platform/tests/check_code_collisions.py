#!/bin/sh
# runs itself with the project's own Python (.venv), from wherever it is called
''''exec "$(dirname -- "$0")/../.venv/bin/python" "$0" "$@" # '''
"""Combination codes never stand for two combinations (combos.CodeBook.assign, external review 2026-11-14), offline:
two real combinations whose 8-character codes collide are found by search, then the book must give the second its own
code, resolve each code to its own combination, keep the codes after a restart, refuse to record a mix-up, and free a
code it forgets. Every code already in the installation's book keeps the code it has (read only, never written).
Usage: tests/check_code_collisions.py"""
import json, os, sys, tempfile
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import intel as I  # noqa: E402
import combos as C  # noqa: E402

fails, checks = [], 0


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond: fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info else ""), flush=True)


# two different combinations whose plain codes are the same (a birthday search over 32 bits: about 77,000 tries)
seen, pair = {}, None
for i in range(400000):
    name = f"lg-collide-{i}"
    code = I.code_from("LG-C-", I.combo_key("infections", name, "event4_sinkhole", ["tag:x"]))
    if code in seen:
        pair = (seen[code], name, code); break
    seen[code] = name
print(f"Two combinations with the same plain code: {pair[0]} and {pair[1]} -> {pair[2]} (after {i + 1:,} tries)" if pair else "no collision found")
ok("a real collision exists to check with", bool(pair))
a, b, plain = pair

tmp = tempfile.mkdtemp(prefix="lg-codes-")
path = os.path.join(tmp, "combo_codes.json")
book = C.CodeBook(path); I.CODE_BOOK["book"] = book
book.record("infections", a, "event4_sinkhole", [["tag:x"]])
ca = I.combo_code("infections", a, "event4_sinkhole", ["tag:x"])
cb = I.combo_code("infections", b, "event4_sinkhole", ["tag:x"])
ok("the first combination keeps the plain code", ca == plain, ca)
ok("the second gets a code of its own, of the same form", cb != plain and C.CODE_RX.match(cb), cb)
book.record("infections", b, "event4_sinkhole", [["tag:x"]])
ok("each code resolves to its own combination", book.get(ca)["name"] == a and book.get(cb)["name"] == b)
ok("the same combination always gets the same code", I.combo_code("infections", b, "event4_sinkhole", ["tag:x"]) == cb
   and I.combo_code("infections", a, "event4_sinkhole", ["tag:x"]) == ca)
ok("each entry keeps what it stands for", book.get(ca)["key"] != book.get(cb)["key"])

book2 = C.CodeBook(path); I.CODE_BOOK["book"] = book2                     # a restart: the book read back from disk
ok("after a restart both keep their codes", I.combo_code("infections", b, "event4_sinkhole", ["tag:x"]) == cb
   and I.combo_code("infections", a, "event4_sinkhole", ["tag:x"]) == ca)

# the second shown before the first is ever recorded: the first still never gets the second's code
book3 = C.CodeBook(os.path.join(tmp, "empty.json")); I.CODE_BOOK["book"] = book3
c1 = I.combo_code("infections", b, "event4_sinkhole", ["tag:x"])
c2 = I.combo_code("infections", a, "event4_sinkhole", ["tag:x"])
ok("shown but not yet recorded: still two codes", c1 != c2 and plain in (c1, c2), f"{c1} / {c2}")

# a code that stands for something else is never recorded over
book4 = C.CodeBook(os.path.join(tmp, "b4.json")); I.CODE_BOOK["book"] = book4
book4.data[plain] = {"kind": "r", "section": "infections", "name": a, "report": "event4_sinkhole", "items": ["tag:x"], "first": "x", "last": "x"}
book4.loaded = True
I.CODE_BOOK["book"] = None                                               # as before the fix: the plain code for both
forced = I.combo_code("infections", b, "event4_sinkhole", ["tag:x"])
I.CODE_BOOK["book"] = book4
book4.held, book4.by_key = {}, None
real_cc = I.combo_code
I.combo_code = lambda *a_, **k: forced                                   # simulate a caller that still made the plain code
try:
    book4.record("infections", b, "event4_sinkhole", [["tag:x"]])
finally:
    I.combo_code = real_cc
ok("a mix-up is refused: the code keeps what it stood for", book4.data[plain]["name"] == a)

# forgetting old codes frees them
book5 = C.CodeBook(os.path.join(tmp, "b5.json")); I.CODE_BOOK["book"] = book5
book5.record("infections", a, "event4_sinkhole", [["tag:x"]])
keep = C.KEEP_CODES; C.KEEP_CODES = 0
try:
    with book5.lock:
        book5._save()
finally:
    C.KEEP_CODES = keep
ok("a forgotten code is free again", plain not in book5.data and I.combo_code("infections", b, "event4_sinkhole", ["tag:x"]) == plain)

# the installation's own book: every researcher code keeps exactly the code it has (read only)
real = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data", "combo_codes.json")
try:
    data = json.load(open(real, encoding="utf-8"))
except (OSError, ValueError):
    data = {}
rx = {c: e for c, e in data.items() if isinstance(e, dict) and e.get("kind") in ("r", "x")}
bad = [c for c, e in rx.items() if I.code_from(c[:5], C.CodeBook.key_of(e)) != c]
ok("every code in this installation's book keeps its code (none would change)", not bad, f"{len(rx):,} codes checked" + (f"; {bad[:3]}" if bad else ""))
I.CODE_BOOK["book"] = None
import shutil; shutil.rmtree(tmp, ignore_errors=True)
print(f"\n{checks - len(fails)} of {checks} code-collision checks passed" + (f"; FAILED: {fails}" if fails else ""))
sys.exit(1 if fails else 0)
