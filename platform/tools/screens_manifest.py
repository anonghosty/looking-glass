#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""The documentation screenshots and the page files each one shows (docs/media/screens/manifest.json).

For every screenshot the manifest keeps the SHA-256 of the image and of each page file it shows (the template, the
templates it extends or includes, and the page scripts and styles they load), as they were when the screenshot was
taken or a person looked and confirmed it still matches the page. When a page file changes, its screenshots are stale
until they are taken again or confirmed (tests/check_screenshots.py fails until then).

    python3 tools/screens_manifest.py --status                 # the stale screenshots and the files that changed
    python3 tools/screens_manifest.py --update 60-settings.png  # after retaking it, or after confirming it still matches
    python3 tools/screens_manifest.py --update all              # every screenshot in the folder

Run from the platform's folder. With LG_HELD_DIR set, a held copy <name>.new of a template, script or style in that
folder is read instead of the file itself (the version that will ship).
"""
import argparse
import datetime
import hashlib
import json
import os
import re
import sys

PLAT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# the top of the release: tools/release_root in the maintainer's copy, the folder above platform/ in a release or on GitHub
TOP = os.path.join(PLAT, "tools", "release_root")
if not os.path.isdir(TOP):
    TOP = os.path.dirname(PLAT)
SCREENS_DIR = os.path.join(TOP, "docs", "media", "screens")
MANIFEST = os.path.join(SCREENS_DIR, "manifest.json")
HELD = os.environ.get("LG_HELD_DIR", "")
FIX = "python3 tools/screens_manifest.py --update"

# the address each screenshot is taken on and the template that address draws
ROUTES = {
    "/login": "login.html", "/": "index.html", "/services": "services.html", "/admin": "admin.html",
    "/audit": "audit.html", "/settings": "settings.html", "/findings": "findings.html", "/overview": "overview.html",
    "/management": "management.html", "/review/": "review.html", "/definitions": "definitions.html",
    "/intel/": "acode.html", "/combinations": "combinations.html", "/intelligence": "intelligence.html",
    "/advisory/": "advisory.html", "/advisory": "advisory_portal.html",
}
# screenshot -> the address it shows; or the files it shows when it is not a page (paths from the top of the release)
SCREENS = {
    "00-login.png": "/login",
    "10-overview.png": "/", "12-overview-glossary.png": "/", "12-overview-reports.png": "/",
    "20-comms-map.png": "/", "21-comms-insight.png": "/", "22-comms-insight-drill.png": "/", "23-comms-event.png": "/",
    "26-comms-demo.png": "/", "56-peace-of-mind.png": "/", "70-mobile-map.png": "/",
    "30-services.png": "/services", "31-services-view-kenya-regions.png": "/services", "32-services-insight.png": "/services",
    "33-services-host.png": "/services", "33-services-host-analysis.png": "/services",
    "50-admin-users.png": "/admin", "53-admin-roles.png": "/admin",
    "51-admin-sessions.png": "/audit", "52-admin-audit.png": "/audit", "55-audit-sessions.png": "/audit", "57-audit-cis.png": "/audit",
    "60-settings.png": "/settings", "60b-settings-quarterly.png": "/settings",
    "66-findings.png": "/findings", "70-findings-case.png": "/findings", "92-finding-watch.png": "/findings",
    "11-overview-roles.png": "/overview",
    "40-executive-comms.png": "/management", "40-executive-comms-baseline.png": "/management",
    "41-executive-services.png": "/management", "41-executive-services-top.png": "/management",
    "42-executive-reports.png": "/management", "43-executive-quarterly.png": "/management", "67-executive-code.png": "/management",
    "93-review-drilldown.png": "/review/",
    "61-definitions.png": "/definitions", "62-definitions-leads.png": "/definitions", "63-issues-across.png": "/definitions",
    "64-intel-combinations.png": "/definitions", "65-notes-codes.png": "/definitions",
    "94-cve-tick.png": "/intel/",
    "68-combinations.png": "/combinations",
    "90-abused-compromised.png": "/intelligence", "91-abused-records.png": "/intelligence",
    "72-advisory.png": "/advisory/", "74-advisor-dashboard.png": "/advisory", "75-advisor-quarterly.png": "/advisory",
    "80-external-masked.png": "/", "81-external-event.png": "/",
    # not pages: the advisory PDF's first page, and the guided installer in a terminal
    "73-advisory-report.png": ["platform/advisory_pdf.py", "platform/executive_pdf.py"],
    "95-guided-installer.png": ["install.sh", "installer_anim.py"],
    "96-guided-installer-progress.png": ["install.sh", "installer_anim.py"],
}
# files a page script loads by itself, not named in a template
LOADED_BY = {"js/loader.js": ["js/dialog-focus.js"], "js/notifications.js": ["css/notifications.css"]}
# shared helpers whose work never stays in a screenshot, so a change to them does not make every screenshot stale: the
# loading animation and the tour (both gone before each capture), keyboard focus in dialogs, hover tips, and the wording
# of a PDF button while it works
NOT_SHOWN = {"platform/static/js/loader.js", "platform/static/js/dialog-focus.js", "platform/static/js/tour.js",
             "platform/static/js/header-tips.js", "platform/static/js/pdf.js"}
INCLUDE_RX = re.compile(r"""\{%-?\s*(?:extends|include)\s+["']([^"']+)["']""")
STATIC_RX = re.compile(r"""filename=['"]((?:js|css)/[\w.-]+\.(?:js|css))['"]""")
STATIC_LITERAL_RX = re.compile(r"""["'`]/static/((?:js|css)/[\w.-]+\.(?:js|css))["'`]""")
DOC_REF_RX = re.compile(r"media/screens/([\w.-]+\.png)")


def local_path(rel):
    """Where a file named from the top of the release is here: the held copy (LG_HELD_DIR) of a template, script or
    style when there is one, else platform/... in the platform's folder and anything else at the top."""
    if rel.startswith("platform/"):
        inner = rel[len("platform/"):]
        if HELD and inner.startswith(("templates/", "static/")):
            held = os.path.join(HELD, os.path.basename(inner) + ".new")
            if os.path.isfile(held):
                return held
        return os.path.join(PLAT, inner)
    return os.path.join(TOP, rel)


try:      # the maintainer's copy only: the release build rewrites mentions of the guides' old places in text files
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from release_docs import TEXT as _RELEASE_TEXT, TEXT_FILES as _RELEASE_TEXT_FILES
except ImportError:  # a release or GitHub: the files already are as released
    _RELEASE_TEXT, _RELEASE_TEXT_FILES = [], ()
finally:
    sys.path.pop(0)


def sha256(path):
    """The file's SHA-256 as it is released, or None when it does not exist. In the maintainer's copy a text file is
    hashed after the same rewrites the release build makes (tools/release_docs.py), so the values match on GitHub."""
    if not os.path.isfile(path):
        return None
    with open(path, "rb") as fh:
        raw = fh.read()
    name = path[:-4] if path.endswith(".new") else path
    if _RELEASE_TEXT and name.endswith(_RELEASE_TEXT_FILES):
        try:
            text = raw.decode("utf-8")
            for a, b in _RELEASE_TEXT:
                text = text.replace(a, b)
            raw = text.encode("utf-8")
        except UnicodeDecodeError:
            pass
    return hashlib.sha256(raw).hexdigest()


def _text(rel):
    p = local_path(rel)
    return open(p, encoding="utf-8", errors="replace").read() if os.path.isfile(p) else ""


def page_files(name):
    """The files a screenshot shows, from the top of the release, sorted: the template, everything it extends or
    includes, and the scripts and styles they load (and the files those scripts load themselves), less NOT_SHOWN."""
    what = SCREENS.get(name)
    if what is None:
        raise KeyError(f"{name}: not in SCREENS (tools/screens_manifest.py): add the address it is taken on")
    if isinstance(what, list):
        return sorted(what)
    files, todo, statics = set(), [ROUTES[what]], set()
    while todo:
        t = todo.pop()
        rel = f"platform/templates/{t}"
        if rel in files:
            continue
        files.add(rel)
        src = _text(rel)
        todo += INCLUDE_RX.findall(src)
        statics.update(STATIC_RX.findall(src))
    todo = list(statics)
    while todo:
        s = todo.pop()
        rel = f"platform/static/{s}"
        if rel in files:
            continue
        files.add(rel)
        if s.endswith(".js"):
            todo += LOADED_BY.get(s, []) + STATIC_LITERAL_RX.findall(_text(rel))
    return sorted(f for f in files if f not in NOT_SHOWN and os.path.isfile(local_path(f)))


def load():
    if not os.path.isfile(MANIFEST):
        return {"screens": {}}
    with open(MANIFEST, encoding="utf-8") as fh:
        return json.load(fh)


def save(man):
    man["about"] = ("The page files each documentation screenshot shows, with the SHA-256 of each file and of the image as "
                    "they were when the screenshot was taken or confirmed. Made by platform/tools/screens_manifest.py; "
                    "checked by platform/tests/check_screenshots.py.")
    man["screens"] = dict(sorted(man["screens"].items()))
    with open(MANIFEST, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(man, fh, indent=1, sort_keys=True)
        fh.write("\n")


def record(man, name):
    """Record the image's and its page files' SHA-256 values as they are now."""
    img = sha256(os.path.join(SCREENS_DIR, name))
    if img is None:
        raise FileNotFoundError(f"{name}: no such image in {os.path.relpath(SCREENS_DIR, PLAT)}")
    page = SCREENS.get(name)
    man["screens"][name] = {
        "image_sha256": img,
        "page": page if isinstance(page, str) else "(not a page)",
        "files_sha256": {f: sha256(local_path(f)) for f in page_files(name)},
        "confirmed": datetime.date.today().isoformat(),
    }


def images():
    return sorted(f for f in os.listdir(SCREENS_DIR) if f.endswith(".png")) if os.path.isdir(SCREENS_DIR) else []


def doc_references():
    """Screenshot name -> the Markdown files that show it (the top of the release, and the platform's own guides)."""
    mds = []
    for top, dirs, files in os.walk(TOP):
        dirs[:] = [d for d in dirs if d not in {"site", ".git", "platform", "database", "__pycache__", ".venv", ".venvs", "node_modules"}]
        mds += [os.path.join(top, f) for f in files if f.endswith(".md")]
    for d in (PLAT, os.path.join(PLAT, "docs")):
        if os.path.isdir(d):
            mds += [os.path.join(d, f) for f in os.listdir(d) if f.endswith(".md")]
    refs = {}
    for p in sorted(set(mds)):
        for n in DOC_REF_RX.findall(open(p, encoding="utf-8", errors="replace").read()):
            refs.setdefault(n, set()).add(os.path.relpath(p, TOP if p.startswith(TOP) else PLAT))
    return refs


def problems(man=None):
    """Everything wrong between the screenshots, the docs, the page files and the manifest, as
    (screenshot, message) pairs; empty when every screenshot is current."""
    man = man if man is not None else load()
    rec = man.get("screens", {})
    out, docs = [], doc_references()
    for name, refs in sorted(docs.items()):
        if name not in rec:
            out.append((name, f"shown in {', '.join(sorted(refs))} but not in the manifest: {FIX} {name}"))
    for name in images():
        if name not in rec and name not in docs:
            out.append((name, f"in docs/media/screens but not in the manifest: {FIX} {name}"))
    for name, e in sorted(rec.items()):
        img = sha256(os.path.join(SCREENS_DIR, name))
        if img is None:
            out.append((name, f"in the manifest but the image is missing: add it, or remove its entry from {os.path.basename(MANIFEST)}"))
            continue
        if img != e.get("image_sha256"):
            out.append((name, f"the image was replaced without updating the manifest: {FIX} {name}"))
        for f, want in sorted(e.get("files_sha256", {}).items()):
            now = sha256(local_path(f))
            if now != want:
                how = "no longer exists" if now is None else "changed since the screenshot was taken or confirmed"
                out.append((name, f"stale: {f} {how}; take it again (or look and confirm it still matches), then {FIX} {name}"))
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--update", nargs="+", metavar="NAME", help="screenshot file names (60-settings.png or 60-settings), or all")
    g.add_argument("--status", action="store_true", help="list the stale screenshots and what changed")
    a = ap.parse_args()
    if HELD:
        print(f"reading held copies from LG_HELD_DIR ({HELD}) where they exist")
    man = load()
    if a.status:
        found = problems(man)
        for name, msg in found:
            print(f"  {name}: {msg}")
        stale = sorted({n for n, _ in found})
        print(f"{len(man.get('screens', {}))} screenshots in the manifest; "
              + (f"{len(stale)} need attention: {' '.join(stale)}" if stale else "all current"))
        return 1 if found else 0
    names = images() if a.update == ["all"] else [n if n.endswith(".png") else n + ".png" for n in a.update]
    for n in names:
        try:
            record(man, n)
        except (KeyError, FileNotFoundError) as e:
            sys.exit(str(e).strip("'\""))
        print(f"  recorded {n}: {len(man['screens'][n]['files_sha256'])} page files")
    save(man)
    print(f"{os.path.relpath(MANIFEST, PLAT)}: {len(names)} updated, {len(man['screens'])} in all")
    return 0


if __name__ == "__main__":
    sys.exit(main())
