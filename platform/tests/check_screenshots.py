#!/usr/bin/env python3
"""The documentation screenshots show the pages as they ship (no database needed).

docs/media/screens/manifest.json keeps, for every screenshot, the SHA-256 of the image and of each page file it shows
(template, what it extends or includes, its scripts and styles), as they were when it was taken or confirmed. This
check fails when one of those page files has changed since (the screenshot is stale), when a screenshot the docs show
is not in the manifest, when a manifest entry's image is missing, or when an image was replaced without updating the
manifest. The fix is named in each message: take the screenshot again (or look and confirm it still matches), then
    python3 tools/screens_manifest.py --update <name>.png
Run from the platform's folder, in the maintainer's copy, a release or on GitHub. LG_HELD_DIR: held .new files.
"""
import copy
import os
import sys

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(HERE, "tools"))
import screens_manifest as sm  # noqa: E402

checks, fails = 0, []


def ok(name, cond, detail=""):
    global checks
    checks += 1
    if cond:
        print(f"  ok   {name}")
    else:
        fails.append(name)
        print(f"  FAIL {name}  {str(detail)[:2000]}")


print("The check itself (made-up changes to the manifest, nothing written)")
man = sm.load()
rec = man.get("screens", {})
ok("the manifest is found beside the screenshots", os.path.isfile(sm.MANIFEST), sm.MANIFEST)
ok("it lists the screenshots (at least 40)", len(rec) >= 40, len(rec))
ok("the docs show screenshots (the references are found)", len(sm.doc_references()) >= 30, len(sm.doc_references()))
ok("a page's files are its template, what it includes, and its scripts and styles",
   {"platform/templates/settings.html", "platform/static/js/settings.js", "platform/static/css/settings.css",
    "platform/static/css/app.css", "platform/static/css/notifications.css"} <= set(sm.page_files("60-settings.png")),
   sm.page_files("60-settings.png"))
ok("...but not the shared helpers whose work never stays in a screenshot (loading animation, tour)",
   not sm.NOT_SHOWN & set(sm.page_files("60-settings.png")))
if rec:
    name = sorted(rec)[0]
    f = sorted(rec[name]["files_sha256"])[0]
    m2 = copy.deepcopy(man)
    m2["screens"][name]["files_sha256"][f] = "0" * 64
    ok("a changed page file makes its screenshot stale, naming the file and the fix",
       any(n == name and f in msg and "--update" in msg for n, msg in sm.problems(m2)))
    m2 = copy.deepcopy(man)
    m2["screens"][name]["image_sha256"] = "0" * 64
    ok("a replaced image is found", any(n == name and "replaced" in msg for n, msg in sm.problems(m2)))
    m2 = copy.deepcopy(man)
    del m2["screens"][name]
    ok("a screenshot missing from the manifest is found", any(n == name and "not in the manifest" in msg for n, msg in sm.problems(m2)))
    m2 = copy.deepcopy(man)
    m2["screens"]["99-no-such-image.png"] = {"image_sha256": "0" * 64, "files_sha256": {}}
    ok("a manifest entry whose image is missing is found",
       any(n == "99-no-such-image.png" and "image is missing" in msg for n, msg in sm.problems(m2)))

print("Every documentation screenshot is current" + (f" (held files from {sm.HELD})" if sm.HELD else ""))
found = sm.problems(man)
for n in sorted({n for n, _ in found}):
    ok(n, False, "\n         " + "\n         ".join(msg for m, msg in found if m == n))
ok(f"all {len(rec)} screenshots match the page files they show", not found,
   "stale or unrecorded: " + " ".join(sorted({n for n, _ in found})))

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {len(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
