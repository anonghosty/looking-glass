#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""Every feature ships with its tutorial, its glossary terms and its documentation (the user, 2026-11-20: "dont forget to
update tutorials and glossary and update docs ... it should be a check also").

1. Every module features.py installs is listed below, in FEATURES (with what it must have) or in BEFORE_RULE (the
   modules that existed when this rule began; that list is closed: a new feature cannot be added to it).
2. For each feature in FEATURES:
   - tour: each [page, part] is a step of that page in tour.js (the Tutorial button shows it);
   - glossary: each term key is in glossary.js (the in-app glossary; check_glossary_sync keeps docs/GLOSSARY.md equal);
   - docs: each [file, words] is found in that document;
   - a feature with nothing on any page says why (no_ui) and still needs its documentation.
DB-free. Run from the platform's folder: .venv/bin/python tests/check_feature_coverage.py (LG_HELD_DIR: held .new files).
"""
import os
import re
import sys

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
S = os.environ.get("LG_HELD_DIR", "")
checks, fails = 0, []

# what each feature must have. tour: (page key in tour.js STEPS, the step's part); glossary: term keys;
# docs: (path from the platform folder, words that must be in it)
FEATURES = {
    "quarterly": {
        "tour": [("/management", "#lgQuarterly"), ("/advisory", "#lgQuarterly"), ("/settings", '[data-st-tab=\\"quarterly\\"]')],
        "glossary": ["quarterly_report", "quarterly_purge"],
        "docs": [("docs/USER_GUIDE.md", "## Quarterly reports"), ("docs/OPERATIONS.md", "The quarterly report and the purge"),
                 ("docs/TECHNICAL_REFERENCE.md", "quarterly.py")],
    },
    # not a module of its own: the Settings constituency picker (Constituent column, address blocks, other ranges)
    "constituency_picker": {
        "tour": [("/settings", "#cardScope"), ("/settings", "#cardNets"), ("/settings", "#cidrs")],
        "glossary": ["svc_constituency", "constituent", "address_block", "other_ranges"],
        "docs": [("docs/USER_GUIDE.md", "Some address blocks"), ("docs/USER_GUIDE.md", "Other address ranges"),
                 ("docs/CONFIGURATION.md", "Some address blocks"), ("docs/TECHNICAL_REFERENCE.md", "?asn=")],
    },
    # r90: external accounts open the two platforms and Abused or Compromised only, masked (the sign-in gate's allow-list)
    "external_access": {
        "tour": [("/intelligence", "#itMain .it-hero")],
        "glossary": ["role_external"],
        "docs": [("docs/ROLES.md", "Abused or Compromised"), ("docs/TECHNICAL_REFERENCE.md", "external_access.py")],
    },
    # r91: the daily code check (layer 3) and the verify command (layer 2)
    "code_integrity": {
        "tour": [("/settings", "#cardCode")],
        "glossary": ["code_check"],
        "docs": [("docs/OPERATIONS.md", "## The code check (Settings → Code check)"),
                 ("docs/INSTALLATION.md", "verify_install.py --fetch"),
                 ("docs/TECHNICAL_REFERENCE.md", "code_integrity.py")],
    },
    # 2026-11-23: Shadowserver's own ATT&CK per event; the Definitions page counts what it tagged each report's events with
    "ss_attack": {
        "tour": [("/definitions", "#cardAttack")],
        "glossary": ["ss-event-mapping"],
        "docs": [("docs/USER_GUIDE.md", "Shadowserver's mapping for this event."),
                 ("docs/USER_GUIDE.md", "Shadowserver tagged N events of this report with"),
                 ("docs/TECHNICAL_REFERENCE.md", "ss_attack.py")],
    },
    # 2026-11-24: connectors to the CSIRT's own OpenCTI and MISP (Settings -> Connectors; the sender runs as its own timer)
    "connectors": {
        "tour": [("/settings", '[data-st-tab=\\"connectors\\"]'), ("/audit", "#pane-sent")],
        "glossary": ["connector", "connector_target", "connector_paused", "opencti_misp", "connector_revoked", "data_sent_out"],
        "docs": [("docs/CONNECTORS.md", "## Setting up OpenCTI"), ("docs/CONNECTORS.md", "## Setting up MISP"),
                 ("docs/CONNECTORS.md", "## How the data stays up to date"),
                 ("docs/CONFIGURATION.md", "## Connectors (OpenCTI and MISP)")],
    },
    # 2026-11-24: passkeys (required on public installations) and the fresh check before high-value actions
    "stepup": {
        "tour": [("/account", "#pkCard"), ("/account", "#pkAdd")],
        "glossary": ["passkey", "stepup", "stepup_every_time", "passkey_reset"],
        "docs": [("docs/USER_GUIDE.md", "### Your account and passkeys"), ("docs/USER_GUIDE.md", "### Confirming it's you"),
                 ("docs/SECURITY.md", "### Passkeys and the fresh check"),
                 ("docs/TECHNICAL_REFERENCE.md", "stepup.py")],
    },
    # 2026-11-25: how sign-in is checked, a passkey or the authenticator code (Settings -> General -> Sign-in check)
    "signin_check": {
        "tour": [("/settings", "#cardSigninCheck")],
        "glossary": ["signin_check"],
        "docs": [("docs/USER_GUIDE.md", "### Sign-in check"), ("docs/SECURITY.md", "Sign-in check"),
                 ("docs/TECHNICAL_REFERENCE.md", "signin_check.py"), ("docs/CONFIGURATION.md", "SIGNIN_CHECK")],
    },
    # 2026-11-25: people codes instead of sign-in names in pages; a new key is said in the bell and the audit log
    "person_code": {
        "tour": [],
        "glossary": ["person_code"],
        "docs": [("docs/SECURITY.md", "No sign-in names in the pages"), ("docs/OPERATIONS.md", "data/person_code.key"),
                 ("docs/TECHNICAL_REFERENCE.md", "person_code.py")],
    },
    # 2026-11-25: Settings -> Update (the page asks; the update helper backs up, installs a signed release, rolls back)
    "platform_update": {
        "tour": [("/settings", '[data-st-tab=\\"update\\"]')],
        "glossary": ["platform_update", "update_helper"],
        "docs": [("docs/INSTALLATION.md", "### Updating from Settings"), ("docs/USER_GUIDE.md", "### Update"),
                 ("docs/TECHNICAL_REFERENCE.md", "platform_update.py"), ("docs/OPERATIONS.md", "update_helper.sh"),
                 ("docs/SECURITY.md", "Settings → Update")],
    },
    # 2026-11-24: unusual activity (renamed from "patterns", the researchers' word): each thread against its own normal
    "unusual": {
        "tour": [("/unusual", "#ptToday"), ("/unusual", "#ptMine"), ("/management", "#cUnusual"), ("/definitions", "#cardLeads")],
        "glossary": ["unusual", "unusual_normal", "unusual_watched", "unusual_learned"],
        "docs": [("docs/USER_GUIDE.md", "## Unusual activity (analysts)"), ("docs/USER_GUIDE.md", "### Unusual this week"),
                 ("docs/CONFIGURATION.md", "## Unusual activity"), ("docs/TECHNICAL_REFERENCE.md", "unusual_worker.py")],
    },
    "library_supply": {
        "no_ui": "an alert in the administrators' existing bell and an entry in the audit log; no page or control of its own",
        "docs": [("docs/INSTALLATION.md", "When a library file does not match"),
                 ("docs/OPERATIONS.md", "Updating the libraries on purpose"),
                 ("docs/TECHNICAL_REFERENCE.md", "library_supply.py")],
    },
}
# installed in features.py before this rule began (2026-11-20). Closed: never add to it.
BEFORE_RULE = frozenset({"spike_notice", "config_page", "findings_live", "pdf_refs", "name_levels_catchup", "severity_map",
                         "insider", "invites", "neutral", "tour_prefs", "signin_welcome", "address_blocks", "acode_warm"})
BEFORE_RULE_SIZE = 13


def ok(name, cond, detail=""):
    global checks
    checks += 1
    if cond:
        print(f"  ok   {name}")
    else:
        fails.append(name)
        print(f"  FAIL {name}  {str(detail)[:300]}")


def read(path):
    """A held .new copy of a page file when there is one (the release ships it), else the file itself."""
    n = os.path.basename(path)
    h = os.path.join(S, n + ".new") if S else ""
    p = h if h and os.path.exists(h) else path
    return open(p, encoding="utf-8").read() if os.path.exists(p) else ""


print("1. Every installed feature is listed")
src = read(os.path.join(HERE, "features.py"))
body = src.split("def install(", 1)[1] if "def install(" in src else ""
installed = sorted(set(re.findall(r"^\s+import ([a-z_]+)\s*$", body, re.M)) - {"os"})
ok("features.py installs features (read)", len(installed) >= 10, installed)
unlisted = [m for m in installed if m not in FEATURES and m not in BEFORE_RULE]
ok("every feature features.py installs has its tutorial, glossary and docs listed here (FEATURES)", not unlisted,
   f"add to FEATURES: {unlisted}")
ok("the list of features from before the rule is closed (nothing added to it)", len(BEFORE_RULE) == BEFORE_RULE_SIZE,
   len(BEFORE_RULE))

tour = read(os.path.join(HERE, "static", "js", "tour.js"))
glossary = read(os.path.join(HERE, "static", "js", "glossary.js"))


def page_steps(page):
    """The text of one page's step list in tour.js STEPS ('"/page": [ ... ],')."""
    m = re.search(r'^\s*"' + re.escape(page) + r'":\s*\[(.*?)^\s*\],', tour, re.M | re.S)
    return m.group(1) if m else ""


print("\n2. What each feature has")
for name, need in sorted(FEATURES.items()):
    for page, part in need.get("tour", []):
        steps = page_steps(page)
        ok(f"{name}: a tutorial step on {page} for {part}", bool(steps) and f'["{part}",' in steps,
           f"tour.js STEPS['{page}'] has no step for {part}")
    for key in need.get("glossary", []):
        ok(f"{name}: glossary term '{key}'", re.search(r'key:\s*"' + re.escape(key) + r'"', glossary) is not None)
    if not need.get("tour") and not need.get("glossary"):
        ok(f"{name}: nothing on any page, and it says why (no_ui)", bool(need.get("no_ui")))
    ok(f"{name}: documented", bool(need.get("docs")))
    for path, words in need.get("docs", []):
        # a release has the guides one level up (looking-glass/docs/): that copy first, as an installation may still
        # hold an old platform/docs/ from an earlier layout; the development tree keeps them in the platform folder,
        # and the docs site's own pages in tools/release_root/docs/
        text = next((read(p) for p in (os.path.join(HERE, "..", path), os.path.join(HERE, path),
                                       os.path.join(HERE, "tools", "release_root", path)) if read(p)), "")
        ok(f"{name}: {path} covers it ({words})", words in text)

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
