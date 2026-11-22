#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""Add a person (invites.py): at most INVITES_OPEN_MAX sign-up links open at once, refused in fixed words; and nothing
else an error says reaches the answer (CodeQL py/stack-trace-exposure, 2026-11-20: every ValueError's text was passed
on). Made-up names only. Run: .venv/bin/python tests/check_invite_limit.py"""
import os
import sys
import tempfile

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


import invites as I  # noqa: E402

print("The open sign-up links limit")
with tempfile.TemporaryDirectory() as tmp:
    I.INVITES_OPEN_MAX, keep = 3, I.INVITES_OPEN_MAX
    try:
        inv = I.Invites(os.path.join(tmp, "invites.json"))
        made = [inv.make("analyst", f"Test Person {n}", "admin.example") for n in range(3)]
        ok("links up to the limit are made", len(made) == 3 and all(t for t, _ in made))
        try:
            inv.make("analyst", "One Too Many", "admin.example")
            ok("one more is refused", False)
        except I.TooManyOpen as e:
            ok("one more is refused with its own error (TooManyOpen)", "3 sign-up links are open" in str(e), str(e))
        ok("…which is still a ValueError for older callers", issubclass(I.TooManyOpen, ValueError))
    finally:
        I.INVITES_OPEN_MAX = keep

print("The answer says only that, in fixed words")
src = open(os.path.join(HERE, "invites.py"), encoding="utf-8").read()
ok("the Admin page's request catches that one refusal only", "except TooManyOpen:" in src and "except ValueError as exc" not in src)
ok("…and answers with fixed words, not the error's text", 'error=f"{INVITES_OPEN_MAX} sign-up links are open: revoke some first."' in src
   and "error=str(exc)" not in src)
asrc = open(os.path.join(HERE, "advisory.py"), encoding="utf-8").read()
ok("an advisory stopped by the ATT&CK guard: the advisor gets fixed words, the detail goes to the service's log",
   "current_app.logger.warning(" in asrc and 'f"The report was not made: {e}' not in asrc)

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {fails}" if fails else ""))
sys.exit(1 if fails else 0)
