#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""The software bill of materials (SBOM) of a Looking Glass release, in SPDX 2.3 JSON, made only from the lock files:
every library each part installs, at its exact version, with every sha256 value the lock accepts for it. Standard
library only, no network: it reads files and writes one file.

    tools/make_sbom.py [--root DIR] [--out FILE] [--version V] [--date YYYY-MM-DD]

Parts (components) and where their locks are, in a release (the GitHub repository) / in the maintainer's folders:
    platform    platform/requirements.lock   / requirements.lock
    pipeline    database/requirements.lock   / $LG_PIPELINE_DIR (default ../shadowserver)/requirements.lock
    docs-site   docs/requirements.lock       / tools/release_root/docs/requirements.lock   (the documentation website)
plus the GitHub Actions the checks workflow uses (.github/workflows/*.yml, each pinned to a commit).

A library is "direct" when its part's requirements.txt names it (or the lock says "via -r requirements.txt"),
"indirect" otherwise; the lock's "# via" lines give which library needs it. The same files always give the same SBOM:
everything is sorted, the identifiers are made from names and versions, the namespace from the version and the locks'
SHA-256, and the creation time from the release's changelog heading (never the clock). Without --out it prints the SBOM.
"""
import argparse
import glob
import hashlib
import json
import os
import re
import sys

FILE_NAME = "looking-glass-sbom.spdx.json"      # at the top of the release, beside README.md and CHANGELOG.md
PROJECT = "looking-glass"
REPO_URL = "https://github.com/anonghosty/looking-glass"
PROJECT_LICENSE = "AGPL-3.0-only"   # the licence of the repository (LICENSE: GNU AGPL version 3, no "or later")
COMPONENTS = ("platform", "pipeline", "docs-site")
COMPONENT_TEXT = {
    "platform": "the Looking Glass web platform (platform/)",
    "pipeline": "the database pipeline that loads the reports (database/)",
    "docs-site": "the documentation website, built by Read the Docs (docs/, mkdocs.yml); not installed on a server",
}
HEAD_RX = re.compile(r"^## (.+?)\s*$", re.M)
DATED_RX = re.compile(r"^(\d{4})-(\d{2})-(\d{2})(?: \((\d+)\))?$")
REQ_RX = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?==([^\s;\\]+)")
HASH_RX = re.compile(r"--hash=sha256:([0-9a-fA-F]{64})\b")
NAME_RX = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")
USES_RX = re.compile(r"^\s*(?:-\s*)?uses:\s*([^\s#]+)\s*(?:#\s*(\S+))?", re.M)
ID_BAD = re.compile(r"[^A-Za-z0-9.-]+")


def norm(name):
    """PEP 503 name: lower case, runs of '-', '_', '.' become one '-' (the form pip and purl use)."""
    return re.sub(r"[-_.]+", "-", name).lower()


def spdx_id(*parts):
    return "SPDXRef-" + "-".join(ID_BAD.sub("-", p).strip("-") for p in parts)


def inputs(root, pipeline_dir=None):
    """{'layout', 'locks': {component: path}, 'reqs': {component: path}, 'changelog', 'workflows': [paths]}."""
    root = os.path.abspath(root)
    if os.path.isfile(os.path.join(root, "install.sh")) and os.path.isdir(os.path.join(root, "database")):
        dirs = {"platform": os.path.join(root, "platform"), "pipeline": os.path.join(root, "database"),
                "docs-site": os.path.join(root, "docs")}
        top = root
        layout = "release"
    else:   # the maintainer's folders: root is the platform
        pipe = pipeline_dir or os.environ.get("LG_PIPELINE_DIR") or os.path.join(os.path.dirname(root), "shadowserver")
        top = os.path.join(root, "tools", "release_root")
        dirs = {"platform": root, "pipeline": pipe, "docs-site": os.path.join(top, "docs")}
        layout = "development"
    return {"layout": layout, "root": root,
            "locks": {c: os.path.join(d, "requirements.lock") for c, d in dirs.items()},
            "reqs": {c: os.path.join(d, "requirements.txt") for c, d in dirs.items()},
            "changelog": os.path.join(top, "CHANGELOG.md"),
            "workflows": sorted(glob.glob(os.path.join(top, ".github", "workflows", "*.yml")))}


def parse_lock(text):
    """{normalised name: {'name', 'version', 'hashes': sorted list, 'via': sorted list, 'direct_in_lock': bool}}."""
    out, cur, in_via = {}, None, False
    for line in text.splitlines():
        s = line.strip()
        m = REQ_RX.match(line)
        if m:
            key = norm(m.group(1))
            if key in out:
                raise ValueError(f"{m.group(1)} is locked twice")
            cur = out[key] = {"name": key, "version": m.group(2), "hashes": set(), "via": set(), "direct_in_lock": False}
            in_via = False
        elif cur is None:
            continue
        if cur is not None:
            cur["hashes"].update(h.lower() for h in HASH_RX.findall(line))
        if s.startswith("# via"):
            rest = s[len("# via"):].strip()
            in_via = not rest
            if rest:
                _add_via(cur, rest)
        elif in_via and s.startswith("#   "):
            _add_via(cur, s[1:].strip())
        elif not s.startswith("--hash") and not m:
            in_via = False
    for e in out.values():
        if not e["hashes"]:
            raise ValueError(f"{e['name']}=={e['version']} has no sha256 value in the lock")
        e["hashes"], e["via"] = sorted(e["hashes"]), sorted(e["via"])
    return out


def _add_via(entry, item):
    if item.startswith("-r ") or item.startswith("-c "):
        entry["direct_in_lock"] = True
    elif item:
        entry["via"].add(norm(item))


def parse_requirements(path):
    """The library names a requirements.txt asks for (normalised); empty when there is none."""
    names = set()
    if os.path.isfile(path):
        for line in open(path, encoding="utf-8"):
            s = line.split("#", 1)[0].strip()
            if s and not s.startswith("-"):
                m = NAME_RX.match(s)
                if m:
                    names.add(norm(m.group(1)))
    return names


def parse_actions(paths):
    """{(owner/repo[/path], commit): tag from the pin's comment or None} for every remote action used."""
    found = {}
    for p in paths:
        for m in USES_RX.finditer(open(p, encoding="utf-8").read()):
            ref, comment = m.group(1).strip("'\""), m.group(2)
            if ref.startswith(("./", "docker://")) or "@" not in ref:
                continue
            what, at = ref.rsplit("@", 1)
            tag = comment if comment and re.match(r"^v?\d[\w.-]*$", comment) else None
            if found.get((what, at)) is None:
                found[(what, at)] = tag
    return found


def release_of(changelog, version=None, date=None):
    """(version, YYYY-MM-DD) from the first heading of the changelog: '2026-11-21 (3)' -> ('2026.11.21.3', '2026-11-21').
    An 'Unreleased' heading gives 'unreleased' and the date of the newest dated heading."""
    heads = HEAD_RX.findall(open(changelog, encoding="utf-8").read()) if os.path.isfile(changelog) else []
    dated = [DATED_RX.match(h.strip()) for h in heads]
    first_dated = next((m for m in dated if m), None)
    if version is None:
        if dated and dated[0]:
            y, mo, d, n = dated[0].groups()
            version = f"{y}.{mo}.{d}" + (f".{n}" if n and n != "1" else "")
        else:
            version = "unreleased"
    if date is None:
        if not first_dated:
            raise ValueError(f"no dated heading in {changelog}: give --date")
        date = "-".join(first_dated.groups()[:3])
    if not re.match(r"^\d{4}-\d{2}-\d{2}$", date):
        raise ValueError(f"date {date!r} is not YYYY-MM-DD")
    return version, date


def _package(spdxid, name, version, purpose, comment, purl=None, download="NOASSERTION", checksums=(),
             license_declared="NOASSERTION", supplier="NOASSERTION"):
    p = {"SPDXID": spdxid, "name": name, "versionInfo": version, "downloadLocation": download,
         "filesAnalyzed": False, "licenseConcluded": "NOASSERTION", "licenseDeclared": license_declared,
         "copyrightText": "NOASSERTION", "supplier": supplier, "primaryPackagePurpose": purpose, "comment": comment}
    if purl:
        p["externalRefs"] = [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": purl}]
    if checksums:
        p["checksums"] = [{"algorithm": "SHA256", "checksumValue": h} for h in checksums]
    return p


def build(inp, version=None, date=None):
    """The SBOM as a dict (deterministic for the same files and arguments)."""
    version, date = release_of(inp["changelog"], version, date)
    missing = [p for p in inp["locks"].values() if not os.path.isfile(p)]
    if missing:
        raise FileNotFoundError("lock file missing: " + ", ".join(missing))
    digest = hashlib.sha256()
    locks = {}
    for c in COMPONENTS:
        raw = open(inp["locks"][c], "rb").read()
        digest.update(c.encode() + b"\0" + raw + b"\0")
        locks[c] = parse_lock(raw.decode("utf-8"))
    for p in inp["workflows"]:
        digest.update(os.path.basename(p).encode() + b"\0" + open(p, "rb").read() + b"\0")
    root_id = spdx_id("Package", PROJECT)
    packages, rels = [], [{"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": root_id}]
    packages.append(_package(root_id, PROJECT, version, "APPLICATION",
                             "Looking Glass: the platform, the database pipeline and the documentation website.",
                             download=f"git+{REPO_URL}.git", license_declared=PROJECT_LICENSE,
                             supplier="Organization: Looking Glass project"))
    for c in COMPONENTS:
        cid = spdx_id("Component", c)
        packages.append(_package(cid, f"{PROJECT}-{c}", version, "OTHER" if c == "docs-site" else "APPLICATION",
                                 f"Part of Looking Glass: {COMPONENT_TEXT[c]}. Its libraries come from its requirements.lock "
                                 "(exact versions, installed with pip --require-hashes).",
                                 download=f"git+{REPO_URL}.git", license_declared=PROJECT_LICENSE,
                                 supplier="Organization: Looking Glass project"))
        rels.append({"spdxElementId": root_id, "relationshipType": "CONTAINS", "relatedSpdxElement": cid})
        asked = parse_requirements(inp["reqs"][c])
        lib_ids = {k: spdx_id("Package", c, e["name"], e["version"]) for k, e in locks[c].items()}
        for key in sorted(locks[c]):
            e = locks[c][key]
            direct = key in asked or e["direct_in_lock"]
            needed_by = [v for v in e["via"] if v in locks[c]]
            how = (f"direct: {c}/requirements.txt asks for it" if direct else
                   "indirect: needed by " + (", ".join(needed_by) if needed_by else "another library in the lock"))
            packages.append(_package(
                lib_ids[key], e["name"], e["version"], "LIBRARY",
                f"{how}. Locked in the {c} requirements.lock; the checksums are the sha256 of every file the lock accepts "
                "for this version (one per platform and Python version).",
                purl=f"pkg:pypi/{e['name']}@{e['version']}", checksums=e["hashes"]))
            rels.append({"spdxElementId": cid, "relationshipType": "DEPENDS_ON", "relatedSpdxElement": lib_ids[key],
                         "comment": "direct" if direct else "indirect"})
            for parent in needed_by:
                rels.append({"spdxElementId": lib_ids[parent], "relationshipType": "DEPENDS_ON",
                             "relatedSpdxElement": lib_ids[key]})
    for (what, commit), tag in sorted(parse_actions(inp["workflows"]).items()):
        parts = what.split("/")
        owner_repo, sub = "/".join(parts[:2]), "/".join(parts[2:])
        aid = spdx_id("Action", what, commit[:12])
        purl = f"pkg:githubactions/{owner_repo}@{commit}" + (f"#{sub}" if sub else "")
        packages.append(_package(aid, what, tag or commit, "OTHER",
                                 f"GitHub Action run by the checks workflow (.github/workflows), pinned to commit {commit}"
                                 + (f" (tag {tag})" if tag else "") + "; runs on GitHub, not part of an installation.",
                                 purl=purl, download=f"git+https://github.com/{owner_repo}.git@{commit}"))
        rels.append({"spdxElementId": aid, "relationshipType": "TEST_TOOL_OF", "relatedSpdxElement": root_id})
    packages.sort(key=lambda p: p["SPDXID"])
    rels.sort(key=lambda r: (r["spdxElementId"], r["relationshipType"], r["relatedSpdxElement"]))
    tag = "unreleased" if version == "unreleased" else f"v{version}"
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"{PROJECT} {version}",
        "documentNamespace": f"{REPO_URL}/sbom/{tag}-{digest.hexdigest()[:16]}",
        "creationInfo": {"created": f"{date}T00:00:00Z", "creators": ["Tool: looking-glass-make_sbom"],
                         "comment": "Made from the lock files only (tools/make_sbom.py): the date is the release's, the "
                                    "same lock files always give the same file."},
        "documentDescribes": [root_id],
        "packages": packages,
        "relationships": rels,
    }


def render(doc):
    return json.dumps(doc, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def write(root, out, version=None, date=None, pipeline_dir=None):
    """Write the SBOM of the folder `root` to `out`; returns the document."""
    doc = build(inputs(root, pipeline_dir), version, date)
    tmp = out + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(render(doc))
    os.replace(tmp, out)
    return doc


def summary(doc):
    """{component: (direct, indirect)} and the number of actions, for messages."""
    comp = {}
    for r in doc["relationships"]:
        if r["relationshipType"] == "DEPENDS_ON" and r["spdxElementId"].startswith("SPDXRef-Component-"):
            c = r["spdxElementId"][len("SPDXRef-Component-"):]
            d, i = comp.get(c, (0, 0))
            comp[c] = (d + 1, i) if r.get("comment") == "direct" else (d, i + 1)
    actions = sum(1 for p in doc["packages"] if p["SPDXID"].startswith("SPDXRef-Action-"))
    return comp, actions


def main():
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    top = os.path.dirname(here)
    default_root = top if os.path.isfile(os.path.join(top, "install.sh")) and os.path.isdir(os.path.join(top, "database")) else here
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--root", default=default_root, help="a release folder, or the platform folder (maintainer's layout)")
    ap.add_argument("--pipeline", default=None, help="the pipeline folder in the maintainer's layout")
    ap.add_argument("--out", default=None, help=f"the file to write (e.g. {FILE_NAME}); without it the SBOM is printed")
    ap.add_argument("--version", default=None)
    ap.add_argument("--date", default=None)
    a = ap.parse_args()
    try:
        if a.out:
            doc = write(a.root, a.out, a.version, a.date, a.pipeline)
            comp, actions = summary(doc)
            print(f"{a.out}: SPDX 2.3, {doc['name']}, " + ", ".join(f"{c} {d} direct + {i} indirect" for c, (d, i) in sorted(comp.items()))
                  + f", {actions} GitHub Actions")
        else:
            sys.stdout.write(render(build(inputs(a.root, a.pipeline), a.version, a.date)))
    except (OSError, ValueError) as e:
        sys.exit(f"make_sbom: {e}")


if __name__ == "__main__":
    main()
