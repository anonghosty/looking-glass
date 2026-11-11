#!/bin/sh
# runs itself with the project's own Python (.venv), from wherever it is called
''''exec "$(dirname -- "$0")/../.venv/bin/python" "$0" "$@" # '''
"""Researchers' notes (notes.py) end to end, on a throwaway notes file (the real data/notes.json is never touched):
a researcher adds a note, every card of that name carries it ("Notes shared by Researcher: <full name>"), the PDF
report prints it, only its author or an admin removes it, other roles cannot add or read.
Usage: tests/check_notes.py      (the app in-process)"""
import json, os, sys, tempfile
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
os.environ.setdefault("THREATMAP_SCHEDULE", "0")
import app as A  # noqa: E402
import notes as N  # noqa: E402
from flask import g  # noqa: E402

fails, checks = [], 0


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond: fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info else ""), flush=True)


tmp = tempfile.mkdtemp(prefix="lg-notes-")
real = A.NOTES
A.NOTES = N.Notes(os.path.join(tmp, "notes.json"), A.people)          # the app's look-ups now use the throwaway file
me = next((n for n, u in A.AUTH["users"].all().items() if (u.get("profile") or {}).get("full_name")), "")
full = A.people.full_name(me)


def call(path, perms, method="GET", body=None, user=me, role="researcher"):
    with A.app.test_request_context(path, method=method, json=body):
        g.user = {"user": user, "role": role, "perms": set(perms), "csrf": None, "automation": True}
        ep = A.app.url_map.bind("localhost").match(path.split("?")[0], method=method)
        r = A.app.view_functions[ep[0]](**ep[1])      # permission checks come first: nothing is written
        code = r[1] if isinstance(r, tuple) else r.status_code
        r = r[0] if isinstance(r, tuple) else r
        return code, json.loads(r.get_data(as_text=True) or "{}")


try:
    print("Researchers' notes")
    n = A.NOTES.add("infections", "android.badbox2", "Test finding: the C2 moved to example.invalid.", me, "researcher")
    ok("a note is saved with its author's username, role and date", n["by"] == full and n["role"] == "Researcher" and n["date"])
    card, _ = A.mp_resolve("android.badbox2")
    shown = (card.get("notes") or [{}])[0]
    ok("the name's card carries the note (map, services, Executive use the same look-up)", shown.get("text", "").startswith("Test finding"), str(shown)[:80])
    ok("the card names the author by full name, never the username", shown.get("by") == full and "user" not in shown)
    ok("another name's card has no notes", not A.mp_resolve("android.vo1d2")[0].get("notes"))
    A.NOTES.add("issues", "CVE-2024-21762", "Test: FortiGate units patched by two providers this week.", me, "researcher")
    ok("an issue card carries its note", (A.issue_resolve("CVE-2024-21762", fetch=False).get("notes") or [{}])[0].get("text", "").startswith("Test:"))
    ok("the batch look-up (Executive, reports) carries it too", (A.issues_resolve(["CVE-2024-21762"])["CVE-2024-21762"].get("notes") or [{}])[0].get("by") == full)
    # the PDF report: the explanation block of the name prints the note
    import reports_pdf
    from reportlab.lib.pagesizes import A4
    blocks = reports_pdf.enrichment_block("android.badbox2", card, {}, reports_pdf.styles(), A4[0] - 80)
    keep, rest = blocks                              # (the first lines kept together, the rest)
    texts = [getattr(f, "text", "") for f in list(getattr(keep, "_content", [])) + list(rest)]
    want = f"Notes shared by Researcher: {full}"
    ok("the PDF report prints 'Notes shared by Researcher: <full name> (date): text'", any(want in x and "Test finding" in x for x in texts),
       next((x[:90] for x in texts if "Notes shared" in x), "not found"))
    ex = open(os.path.join(A.BASE_DIR, "executive_pdf.py"), encoding="utf-8").read()
    ok("the Executive PDF prints the notes too", "Notes shared by" in ex)
    # removal rules
    other = A.NOTES.add("infections", "android.badbox2", "Someone else's note.", "someone-else", "researcher")
    hit, err = A.NOTES.delete(other["id"], me, False)
    ok("a researcher cannot remove someone else's note", hit is None and "author" in err)
    hit, _ = A.NOTES.delete(other["id"], me, True)
    ok("an admin can", hit is not None)
    hit, _ = A.NOTES.delete(n["id"], me, False)
    ok("the author can remove their own", hit is not None and not any(x["text"].startswith("Test finding") for x in A.NOTES.list("infections", "android.badbox2")))
    ok("notes are stored apart from the definitions, readable JSON", json.load(open(os.path.join(tmp, "notes.json"))).get("issues"))
    # who may use the API
    code, _ = call("/api/notes?section=infections&name=x", {"view"}, role="external")
    ok("external: cannot read notes", code == 403, f"HTTP {code}")
    code, _ = call("/api/notes", {"view", "unmasked", "export", "malpedia"}, "POST", {"section": "infections", "name": "x", "text": "y"}, role="analyst")
    ok("analyst: cannot add notes", code == 403, f"HTTP {code}")
finally:
    A.NOTES = real
    import shutil; shutil.rmtree(tmp, ignore_errors=True)
print(f"\n{checks - len(fails)} of {checks} notes checks passed" + (f"; FAILED: {fails}" if fails else ""))
sys.exit(1 if fails else 0)
