#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""The documentation names only what the code has. Four things a document may name, each checked against its source:

  1. statuses of a finding: an italic status name (*With the analyst* ...) must be one the code still sets
     (findings.STATUSES, whose key some code path assigns), never a retired one;
  2. code families: every LG-<letter>- prefix must be one the code makes;
  3. buttons: a bold name right after "use", "click", "press", "tick", "choose", "pick" or "then" (**Mark as sent**)
     must be a label on some page (page scripts and templates; the held copies in LG_HELD_DIR first, when given);
  4. roles: "the <Name> role" must name a role the code defines.

The documents are the release's own: README and the other top-level Markdown files and docs/*.md, found beside the
platform folder (a release, CI) or in tools/release_root/ (a development copy). CHANGELOG.md is history and is skipped.
Planted mistakes are checked first, so the check is known to catch them. Nothing is written.
Run: .venv/bin/python tests/check_docs_vs_code.py"""
import glob
import html
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PF = os.path.dirname(HERE)
HELD = os.environ.get("LG_HELD_DIR", "")
passed = failed = 0


def ok(name, cond, detail=""):
    global passed, failed
    if cond:
        passed += 1
        print(f"  ok   {name}")
    else:
        failed += 1
        print(f"  FAIL {name}" + (f": {detail}" if detail else ""))


def read(p):
    with open(p, encoding="utf-8", errors="replace") as f:
        return f.read()


def release_root():
    for rr in (os.path.join(PF, "tools", "release_root"), os.path.dirname(PF)):
        if os.path.isdir(os.path.join(rr, "docs")) and glob.glob(os.path.join(rr, "docs", "*.md")):
            return rr
    return ""


# ---- the sources of truth
src = read(os.path.join(PF, "findings.py"))
statuses = dict(re.findall(r'\("([a-z]+)", "([^"]+)"\)', src.split("STATUSES = [", 1)[1].split("]", 1)[0]))
code = "\n".join(read(p) for p in glob.glob(os.path.join(PF, "*.py")))
set_keys = set(re.findall(r'"status"\]\s*=\s*"([a-z]+)"', code)) | set(re.findall(r'"status":\s*"([a-z]+)"', code))
set_keys |= set(re.findall(r'"([a-z]+)" if accept', code))
set_keys |= {k for t in re.findall(r'\("([a-z]+)" if to else "([a-z]+)"\)', code) for k in t}
for block in re.findall(r"TO_STATUS = \{([^}]*)\}", src):
    set_keys |= set(re.findall(r':\s*"([a-z]+)"', block))
set_keys |= {"closed"}
live_labels = {v for k, v in statuses.items() if k in set_keys}
retired = {v for k, v in statuses.items() if k not in set_keys}
families = set(re.findall(r"LG-([A-Z])-", code))

pages = {}
for p in glob.glob(os.path.join(PF, "static", "js", "*.js")) + glob.glob(os.path.join(PF, "templates", "*.html")):
    pages[os.path.basename(p)] = p
if HELD:
    for p in glob.glob(os.path.join(HELD, "*.js.new")) + glob.glob(os.path.join(HELD, "*.html.new")):
        pages[os.path.basename(p)[:-4]] = p                     # the held copy is what ships
ui_low = re.sub(r"\s+", " ", html.unescape("\n".join(read(p) for p in pages.values()))).lower()

roles = set(re.findall(r'"([a-z]+)":\s*\[', read(os.path.join(PF, "auth.py")).split("DEFAULT_ROLES", 1)[1].split("}", 1)[0]))
role_names = roles | {"administrator", "external viewer", "admin", "custom"}

EXTERNAL = {"New issue", "Report a vulnerability", "Fork", "Star", "Watch", "Code", "Releases"}   # GitHub's own buttons
VERB = r"(?:use|uses|using|click|clicks|press|presses|tick|ticks|choose|chooses|pick|picks|then)"
STATUS_LIKE = (r"With management|With the (?:analyst|advisor|researcher|manager)|Back with the [a-z]+|Advisory sent"
               r"|Approved by management")


def problems_in(name, t):
    """(name, line, kind, message) for every claim in one document that the code does not back."""
    out = []

    def where(text, pos):
        return text.count("\n", 0, pos) + 1
    prose = re.sub(r"```.*?```", lambda m: "\n" * m.group(0).count("\n"), t, flags=re.S)   # code blocks are not claims
    for m in re.finditer(rf"(?<!\*)\*({STATUS_LIKE})\*(?!\*)", prose):
        s = m.group(1)
        if s in retired:
            out.append((name, where(prose, m.start()), "status", f"*{s}* is no longer set by the code"))
        elif s not in live_labels:
            out.append((name, where(prose, m.start()), "status", f"*{s}* is not a status (findings.STATUSES)"))
    if retired:
        for m in re.finditer(r"(?:moves to|becomes|is now|goes to|status)[^.\n]{0,40}?\*{1,2}("
                             + "|".join(map(re.escape, sorted(retired))) + r")\*{1,2}", prose):
            out.append((name, where(prose, m.start()), "status", f"{m.group(1)}: a finding no longer takes this status"))
    for m in re.finditer(r"(?:^|[*(]|→)\s*(New|Advisory sent)\s*→|→\s*(Advisory sent|New)\b", prose):
        s = m.group(1) or m.group(2)
        if s in retired:
            out.append((name, where(prose, m.start()), "status", f"{s} in a status list: no longer set by the code"))
    for m in re.finditer(r"LG-([A-Z])-", t):                    # diagram code too: it is shown
        if m.group(1) not in families:
            out.append((name, where(t, m.start()), "code", f"LG-{m.group(1)}- is not a code family the code makes"))
    for m in re.finditer(rf"\b{VERB}\s+\*\*([^*\n]{{3,48}})\*\*", prose):
        label = re.sub(r"\s+", " ", m.group(1)).strip().rstrip(".:,")
        if not label[:1].isupper() or label in EXTERNAL or label.lower() in ui_low:
            continue
        out.append((name, where(prose, m.start()), "button", f"**{label}** is not a label on any page"))
    for m in re.finditer(r"\bthe \**([A-Z][a-z]+(?: viewer)?)\** role\b", prose):     # a role is named with a capital
        if m.group(1).lower() not in role_names:
            out.append((name, where(prose, m.start()), "role", f"'{m.group(1)}' is not a role"))
    return out


print("The documentation names only what the code has")
ok(f"sources read: {len(live_labels)} statuses set by the code, {len(families)} code families, {len(pages)} page "
   f"files, {len(roles)} roles", live_labels and families and len(pages) > 20 and roles,
   (sorted(live_labels), sorted(families), len(pages), sorted(roles)))

# planted mistakes first: the check must catch each one, and leave a true sentence alone
some_status = sorted(live_labels)[0] if live_labels else "With management"
cases = [
    ("a status the code never sets", "It is now *With the manager* until noon.", "status"),
    ("a made-up code family", "Send the researcher LG-Q-1234ABCD.", "code"),
    ("a button no page has", "Then click **Publish to the moon** to finish.", "button"),
    ("a role the code does not define", "Only the Wizard role may do this.", "role"),
]
if retired:
    cases.insert(1, ("a retired status", f"The finding moves to **{sorted(retired)[0]}** after that.", "status"))
for what, text, kind in cases:
    found = problems_in("planted.md", text)
    ok(f"caught: {what}", any(p[2] == kind for p in found), found)
ok("left alone: a true sentence (a real status, code family, button and role)",
   not problems_in("true.md", f"It is *{some_status}*; send LG-{sorted(families)[0]}-1234ABCD; the Analyst role. "
                              "Code blocks are not claims:\n```\nclick **Nothing Like This**\n```\n"),
   problems_in("true.md", f"It is *{some_status}*"))

rr = release_root()
ok("the release's documents are found (beside the platform folder, or tools/release_root/ in a development copy)",
   bool(rr), PF)
if rr:
    # platform/docs holds the guides only in the development tree (tools/release_root beside it); on an installation the
    # release's docs are ../docs, and a platform/docs there is an older layout's leftover, never shipped (2026-11-26:
    # lg-test's stale guides were read and named two labels the shipped docs no longer have)
    dev_tree = os.path.abspath(rr) == os.path.abspath(os.path.join(PF, "tools", "release_root"))
    docs = sorted(set(glob.glob(os.path.join(rr, "*.md")) + glob.glob(os.path.join(rr, "docs", "*.md"))
                      + (glob.glob(os.path.join(PF, "docs", "*.md")) if dev_tree else [])))
    docs = [d for d in docs if os.path.basename(d) != "CHANGELOG.md"]
    ok(f"{len(docs)} documents to read (README, docs/*.md, ...)", len(docs) >= 10, len(docs))
    found = []
    for d in docs:
        found += problems_in(os.path.relpath(d, os.path.dirname(rr)), read(d))
    for n, line, kind, msg in sorted(found):
        print(f"       {kind:6} {n}:{line}  {msg}")
    ok("every status, code family, button and role the documents name is one the code has", not found,
       f"{len(found)} to fix (listed above)")

print()
print(f"{passed}/{passed + failed} checks passed" + (f"; {failed} FAILED" if failed else ""))
sys.exit(1 if failed else 0)
