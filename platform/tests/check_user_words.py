#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""Error words in answers (user_words.py): an answer shows an error's words only when Looking Glass wrote them for the
reader (Said, or registered); a library's or Python's own text gets the fixed fallback. The connectors and the passkey
checks answer this way (CodeQL py/stack-trace-exposure, 2026-11-25). No network, no database, nothing written.
Run: .venv/bin/python tests/check_user_words.py"""
import os
import re
import sys

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
checks, fails = 0, []


def ok(name, cond, detail=""):
    global checks
    checks += 1
    if cond:
        print(f"  ok   {name}")
    else:
        fails.append(name)
        print(f"  FAIL {name}  {str(detail)[:200]}")


import user_words as W  # noqa: E402

print("Which words an answer may show")
try:
    raise W.Said("Choose OpenCTI or MISP.")
except ValueError as e:
    ok("a Said error: its own words", W.words(e) == "Choose OpenCTI or MISP.", W.words(e))
    ok("…and it is still a ValueError, str() unchanged (callers and the audit as before)", str(e) == "Choose OpenCTI or MISP.")
try:
    int("not a number")
except ValueError as e:
    ok("a plain ValueError (Python's own text): the fallback", W.words(e) == W.FALLBACK, W.words(e))
    ok("…or the fallback the caller gives", W.words(e, "Enter a number.") == "Enter a number.")
try:
    raise RuntimeError("internal detail /home/x/.venv/lib/site-packages/lib.py line 12")
except RuntimeError as e:
    ok("any other error: never its text", "internal" not in W.words(e))
s = W.Said("The passkey could not be checked. Try again, or use another passkey.", detail="library said: bad signature")
ok("detail is kept for the audit and the log, never in the words", s.detail == "library said: bad signature" and "library" not in W.words(s))
ok("an object that cannot be weakly referenced: the fallback, no error", W.words(None) == W.FALLBACK and W.register(1, "x") == 1)

print("\nThe connectors' refusals (connector_net.Refused) are words for the reader")
import connector_net as net  # noqa: E402
try:
    net.parse("http://misp.example")
except net.Refused as e:
    ok("an http:// address: its plain reason is shown", W.words(e).startswith("Use an https:// address"), W.words(e))

print("\nThe passkey library's own text never reaches an answer")
import passkeys as P  # noqa: E402


class _Store:
    def of(self, user):
        return [{"id": "AAAA", "pk": "AAAA", "count": 0}]


ch = P.Challenges()
ch.new("t", "auth")
try:
    P.authenticate(_Store(), ch, "t", "someone", {"id": "AAAA", "response": {}}, "localhost", "https://localhost:5000")
    ok("a broken passkey answer is refused", False)
except ValueError as e:
    ok("a broken passkey answer: fixed words for the reader", W.words(e) == "The passkey could not be checked. Try again, or use another passkey.", W.words(e))
    ok("…the library's reason kept as detail (audit only)", bool(getattr(e, "detail", "")))

print("\nNo answer passes an error's own text (the files of this rule)")
for f in ("connectors.py", "stepup.py", "passkeys.py", "connector_net.py"):
    src = open(os.path.join(HERE, f), encoding="utf-8").read()
    bad = re.findall(r"jsonify\([^)]*error=str\(e", src) + re.findall(r'"text": str\(e\)', src)
    ok(f"{f}: no error=str(e) or \"text\": str(e) in an answer", not bad, bad)
    ok(f"{f}: no bare ValueError raised for the reader (Said instead)", "raise ValueError(" not in src or f == "connector_net.py")

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {fails}" if fails else ""))
sys.exit(1 if fails else 0)
