#!/usr/bin/env python3
"""Regenerate the documentation glossary (docs/GLOSSARY.md) from the in-app glossary (static/js/glossary.js), so the
two never drift apart. The hand-written introduction and "Related tools" section of GLOSSARY.md are kept; the
contents, every group of terms and the A–Z index are rebuilt.

Run from the platform folder:  python3 tools/glossary_md.py
(or give the two paths: python3 tools/glossary_md.py static/js/glossary.js ../docs/GLOSSARY.md)"""
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
S = r'"((?:[^"\\]|\\.)*)"'


def slug(h):
    return re.sub(r"\s", "-", re.sub(r"[^a-z0-9 \-]", "", h.lower()))


def groups_of(js_text):
    out = []
    for m in re.finditer(r'group:\s*' + S + r',\s*items:\s*\[(.*?)\n\s*\],', js_text, re.S):
        items = [(json.loads(f'"{t}"'), json.loads(f'"{d}"'))
                 for t, d in re.findall(r'term:\s*' + S + r',\s*def:\s*' + S, m.group(2))]
        out.append((json.loads(f'"{m.group(1)}"'), items))
    return out


def build(js_text, old_md):
    groups = groups_of(js_text)
    intro = old_md.split("## Contents")[0].rstrip() + "\n"
    related = "## Related tools" + old_md.split("## Related tools", 1)[1].split("## A–Z index")[0].rstrip() + "\n"
    lines = [intro, "## Contents", ""]
    lines += [f"- [{g}](#{slug(g)}) ({len(items)} terms)" for g, items in groups]
    lines += ["- [Related tools](#related-tools)", "- [A–Z index](#az-index)", ""]
    index = []
    for g, items in groups:
        lines += [f"## {g}", ""]
        for t, d in items:
            lines += [f"**{t}**  ", d, ""]
            index.append((t, slug(g)))
        lines += ["[↑ Back to contents](#contents)", ""]
    lines += [related, "## A–Z index", ""]
    index.sort(key=lambda x: x[0].lower())
    lines.append(" · \n".join(f"[{t}](#{s})" for t, s in index))
    return "\n".join(lines) + "\n", groups


def main():
    js = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "static", "js", "glossary.js")
    md = sys.argv[2] if len(sys.argv) > 2 else next(
        (p for p in (os.path.join(HERE, "..", "docs", "GLOSSARY.md"),                      # the published repository
                     os.path.join(HERE, "tools", "release_root", "docs", "GLOSSARY.md"))   # the development tree
         if os.path.exists(p)), None)
    if not md:
        sys.exit("GLOSSARY.md not found: give its path as the second argument.")
    text, groups = build(open(js, encoding="utf-8").read(), open(md, encoding="utf-8").read())
    with open(md, "w", encoding="utf-8") as fh:
        fh.write(text)
    print(f"{md}: {len(groups)} groups, {sum(len(i) for _, i in groups)} terms")


if __name__ == "__main__":
    main()
