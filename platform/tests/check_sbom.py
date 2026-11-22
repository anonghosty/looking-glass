#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""The release's software bill of materials (r91): looking-glass-sbom.spdx.json, made by tools/make_sbom.py from the lock
files, is exact and valid. Regenerated from the locks and compared with the shipped file (in a release, or in the folder
given as the first argument); every locked library is in it with its exact version, its purl and all its sha256 values,
and nothing else is; every part's requirements.txt library is marked direct; every pinned GitHub Action is listed; the
SPDX 2.3 shape holds (required fields, unique identifiers, relationships that point at existing elements); two runs give
the same file; and the checks below catch a tampered SBOM. Reads files only: no database, no network.
Run: .venv/bin/python tests/check_sbom.py [RELEASE_FOLDER]"""
import copy
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(HERE, "tools"))
import make_sbom  # noqa: E402

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info and not cond else ""))


# ---- an independent reading of the locks (not make_sbom's parser), so a parser mistake cannot hide itself
def lock_truth(path):
    """{normalised name: (version, set of sha256)} read with a plain line scan."""
    out, cur = {}, None
    for line in open(path, encoding="utf-8"):
        m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?==(\S+?)\s*(?:\\|;|$)", line)
        if m:
            cur = re.sub(r"[-_.]+", "-", m.group(1)).lower()
            out[cur] = (m.group(2), set())
        elif cur and "--hash=sha256:" in line:
            out[cur][1].update(x.lower() for x in re.findall(r"sha256:([0-9a-fA-F]{64})", line))
        elif line.strip() and not line.startswith((" ", "\t")):
            cur = None
    return out


def shape_problems(doc):
    """SPDX 2.3 JSON shape: what a validator would refuse first. Returns a list of problems (empty = valid)."""
    bad = []
    for k in ("spdxVersion", "dataLicense", "SPDXID", "name", "documentNamespace", "creationInfo"):
        if not doc.get(k):
            bad.append(f"document field {k} missing")
    if doc.get("spdxVersion") != "SPDX-2.3":
        bad.append("spdxVersion is not SPDX-2.3")
    if doc.get("dataLicense") != "CC0-1.0":
        bad.append("dataLicense is not CC0-1.0")
    if doc.get("SPDXID") != "SPDXRef-DOCUMENT":
        bad.append("document SPDXID is not SPDXRef-DOCUMENT")
    ns = doc.get("documentNamespace", "")
    if not re.match(r"^https?://[^\s#]+$", ns):
        bad.append("documentNamespace is not a URI without '#'")
    ci = doc.get("creationInfo") or {}
    if not re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$", ci.get("created", "")):
        bad.append("creationInfo.created is not YYYY-MM-DDThh:mm:ssZ")
    if not ci.get("creators") or not all(re.match(r"^(Tool|Person|Organization): \S", c) for c in ci["creators"]):
        bad.append("creationInfo.creators missing or not 'Tool:/Person:/Organization:'")
    ids = [p.get("SPDXID", "") for p in doc.get("packages", [])]
    if len(ids) != len(set(ids)):
        bad.append("duplicate SPDXIDs")
    for p in doc.get("packages", []):
        pid = p.get("SPDXID", "")
        if not re.match(r"^SPDXRef-[A-Za-z0-9.-]+$", pid):
            bad.append(f"bad SPDXID {pid!r}")
        for k in ("name", "downloadLocation"):
            if not p.get(k):
                bad.append(f"{pid}: {k} missing")
        if p.get("filesAnalyzed", True) and "packageVerificationCode" not in p:
            bad.append(f"{pid}: filesAnalyzed without packageVerificationCode")
        for c in p.get("checksums", []):
            if c.get("algorithm") != "SHA256" or not re.match(r"^[0-9a-f]{64}$", c.get("checksumValue", "")):
                bad.append(f"{pid}: bad checksum {c}")
        for r in p.get("externalRefs", []):
            if r.get("referenceType") == "purl" and not re.match(r"^pkg:[a-z]+/\S+@\S+$", r.get("referenceLocator", "")):
                bad.append(f"{pid}: bad purl {r.get('referenceLocator')}")
        sup = p.get("supplier", "NOASSERTION")
        if sup != "NOASSERTION" and not re.match(r"^(Person|Organization): \S", sup):
            bad.append(f"{pid}: bad supplier")
    known = set(ids) | {"SPDXRef-DOCUMENT"}
    types = {"DESCRIBES", "CONTAINS", "DEPENDS_ON", "TEST_TOOL_OF"}
    for r in doc.get("relationships", []):
        if r.get("spdxElementId") not in known or r.get("relatedSpdxElement") not in known:
            bad.append(f"relationship to an unknown element: {r}")
        if r.get("relationshipType") not in types:
            bad.append(f"unexpected relationship type {r.get('relationshipType')}")
    if not any(r.get("relationshipType") == "DESCRIBES" and r.get("spdxElementId") == "SPDXRef-DOCUMENT"
               for r in doc.get("relationships", [])):
        bad.append("the document DESCRIBES nothing")
    for d in doc.get("documentDescribes", []):
        if d not in known:
            bad.append(f"documentDescribes an unknown element {d}")
    return bad


def coverage_problems(doc, inp):
    """Every locked library with its exact version, purl and all hashes; nothing that is not locked; direct marks."""
    bad = []
    pk = {p["SPDXID"]: p for p in doc["packages"]}
    for c in make_sbom.COMPONENTS:
        truth = lock_truth(inp["locks"][c])
        cid = f"SPDXRef-Component-{c}"
        deps = {r["relatedSpdxElement"]: r.get("comment") for r in doc["relationships"]
                if r["spdxElementId"] == cid and r["relationshipType"] == "DEPENDS_ON"}
        listed = {}
        for sid, how in deps.items():
            p = pk.get(sid)
            if p is None:
                bad.append(f"{c}: {sid} is not a package")
                continue
            listed[p["name"]] = (p, how)
        for name, (ver, hashes) in truth.items():
            if name not in listed:
                bad.append(f"{c}: {name}=={ver} is locked but not in the SBOM")
                continue
            p, _ = listed[name]
            if p.get("versionInfo") != ver:
                bad.append(f"{c}: {name} version {p.get('versionInfo')} in the SBOM, {ver} in the lock")
            purls = [r["referenceLocator"] for r in p.get("externalRefs", []) if r.get("referenceType") == "purl"]
            if purls != [f"pkg:pypi/{name}@{ver}"]:
                bad.append(f"{c}: {name} purl {purls}")
            got = {x["checksumValue"] for x in p.get("checksums", [])}
            if got != hashes:
                bad.append(f"{c}: {name} has {len(got)} sha256 values, the lock {len(hashes)} "
                           f"({len(hashes - got)} missing, {len(got - hashes)} not in the lock)")
        for name in set(listed) - set(truth):
            bad.append(f"{c}: {name} is in the SBOM but not in the lock")
        asked = make_sbom.parse_requirements(inp["reqs"][c])
        for name in asked:
            if name in listed and listed[name][1] != "direct":
                bad.append(f"{c}: {name} is in requirements.txt but not marked direct")
    lib_ids = {sid for c in make_sbom.COMPONENTS for r in doc["relationships"]
               if r["spdxElementId"] == f"SPDXRef-Component-{c}" for sid in [r["relatedSpdxElement"]]}
    stray = [p["SPDXID"] for p in doc["packages"] if p.get("primaryPackagePurpose") == "LIBRARY" and p["SPDXID"] not in lib_ids]
    if stray:
        bad.append(f"libraries no part depends on: {stray[:5]}")
    return bad


def action_problems(doc, inp):
    bad = []
    purls = {r["referenceLocator"] for p in doc["packages"] for r in p.get("externalRefs", [])
             if r["referenceLocator"].startswith("pkg:githubactions/")}
    want = set()
    for f in inp["workflows"]:
        for m in re.finditer(r"uses:\s*([\w.-]+/[\w.-]+)(/[^@\s]*)?@([0-9a-f]{40})\b", open(f, encoding="utf-8").read()):
            want.add(f"pkg:githubactions/{m.group(1)}@{m.group(3)}" + (f"#{m.group(2)[1:]}" if m.group(2) else ""))
    for w in sorted(want - purls):
        bad.append(f"action {w} is used but not in the SBOM")
    for w in sorted(purls - want):
        bad.append(f"action {w} is in the SBOM but not used")
    return bad


# ---- where: a release (the GitHub repository: platform/ beside database/ and docs/), a release folder given as the
#      argument, or the maintainer's folders (then the pipeline is $LG_PIPELINE_DIR or ../shadowserver)
top = os.path.dirname(HERE)
root = sys.argv[1] if len(sys.argv) > 1 else (top if os.path.isfile(os.path.join(top, "install.sh")) and os.path.isdir(os.path.join(top, "database")) else HERE)
inp = make_sbom.inputs(root)
print(f"SBOM check ({inp['layout']} layout: {root})")
ok("all three lock files are there (platform, pipeline, docs site)", all(os.path.isfile(p) for p in inp["locks"].values()),
   ", ".join(p for p in inp["locks"].values() if not os.path.isfile(p)))
if not all(os.path.isfile(p) for p in inp["locks"].values()):
    print("a lock file is missing: skipped"); sys.exit(77)
ok("the checks workflow is found", bool(inp["workflows"]))

# ---- the generator uses no network and only the standard library
src = open(os.path.join(HERE, "tools", "make_sbom.py"), encoding="utf-8").read()
imports = set(re.findall(r"^\s*(?:import|from)\s+([\w.]+)", src, re.M))
ok("make_sbom.py imports only offline standard modules", imports <= {"argparse", "glob", "hashlib", "json", "os", "re", "sys"},
   ", ".join(sorted(imports)))

# ---- deterministic
a, b = make_sbom.render(make_sbom.build(inp)), make_sbom.render(make_sbom.build(inp))
ok("two runs give the same file", a == b)
doc = json.loads(a)
ok("the output is valid JSON and reads back the same", make_sbom.render(doc) == a)
ok("no wall-clock time: created is the release date at 00:00:00Z", doc["creationInfo"]["created"].endswith("T00:00:00Z"))
other = json.loads(make_sbom.render(make_sbom.build(inp, version="1.2.3", date="2001-02-03")))
ok("the namespace follows the version", other["documentNamespace"] != doc["documentNamespace"] and "/v1.2.3-" in other["documentNamespace"])

# ---- shape, coverage, actions
probs = shape_problems(doc)
ok("SPDX 2.3 shape (required fields, unique SPDXIDs, relationships point at existing elements)", not probs, "; ".join(probs[:5]))
probs = coverage_problems(doc, inp)
ok("every locked library with its exact version, purl and all its sha256 values; nothing unlocked; direct marked", not probs, "; ".join(probs[:5]))
probs = action_problems(doc, inp)
ok("every pinned GitHub Action is listed with its commit", not probs, "; ".join(probs[:5]))
proj = [p for p in doc["packages"] if p["SPDXID"] == "SPDXRef-Package-looking-glass"]
ok("the project is described, AGPL-3.0-only", bool(proj) and proj[0]["licenseDeclared"] == "AGPL-3.0-only"
   and doc["documentDescribes"] == ["SPDXRef-Package-looking-glass"])
libs = [p for p in doc["packages"] if p["primaryPackagePurpose"] == "LIBRARY"]
ok("library licences are NOASSERTION (none guessed)", all(p["licenseDeclared"] == p["licenseConcluded"] == "NOASSERTION" for p in libs))
comp, n_actions = make_sbom.summary(doc)
for c in make_sbom.COMPONENTS:
    d, i = comp.get(c, (0, 0))
    ok(f"{c}: {d} direct + {i} indirect libraries, {d} = its requirements.txt", d == len(make_sbom.parse_requirements(inp["reqs"][c])) and d > 0)

# ---- the checks catch a tampered SBOM (each one must fail on its own fault)
t = copy.deepcopy(doc)
lib = next(p for p in t["packages"] if p.get("checksums"))
lib["checksums"].pop()
ok("a missing sha256 value is caught", bool(coverage_problems(t, inp)))
t = copy.deepcopy(doc)
next(p for p in t["packages"] if p["primaryPackagePurpose"] == "LIBRARY")["versionInfo"] += ".1"
ok("a wrong version is caught", bool(coverage_problems(t, inp)))
t = copy.deepcopy(doc)
t["packages"].append(dict(libs[0], SPDXID="SPDXRef-Package-platform-evil-1.0", name="evil", versionInfo="1.0"))
t["relationships"].append({"spdxElementId": "SPDXRef-Component-platform", "relationshipType": "DEPENDS_ON",
                           "relatedSpdxElement": "SPDXRef-Package-platform-evil-1.0"})
ok("a library that no lock holds is caught", bool(coverage_problems(t, inp)))
t = copy.deepcopy(doc)
t["relationships"].pop(next(i for i, r in enumerate(t["relationships"]) if r.get("comment") == "direct"))
ok("a dropped library is caught", bool(coverage_problems(t, inp)))
t = copy.deepcopy(doc)
t["relationships"].append({"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": "SPDXRef-nothing"})
ok("a relationship to a missing element is caught", bool(shape_problems(t)))
t = copy.deepcopy(doc)
t["packages"].append(copy.deepcopy(t["packages"][0]))
ok("a duplicate SPDXID is caught", bool(shape_problems(t)))
t = copy.deepcopy(doc)
t["packages"] = [p for p in t["packages"] if not p["SPDXID"].startswith("SPDXRef-Action-")]
ok("a missing GitHub Action is caught", bool(action_problems(t, inp)))

# ---- the shipped file (a release, or the folder given): exactly what the locks give
shipped = os.path.join(inp["root"], make_sbom.FILE_NAME) if inp["layout"] == "release" else None
if shipped:
    ok(f"{make_sbom.FILE_NAME} is shipped at the top of the release", os.path.isfile(shipped))
    if os.path.isfile(shipped):
        ok(f"the shipped {make_sbom.FILE_NAME} is exactly what the locks give (run tools/make_sbom.py --out ... again)",
           open(shipped, encoding="utf-8").read() == a)
else:
    print(f"  (development layout: no shipped {make_sbom.FILE_NAME} here; tools/make_release.py writes it into the release)")

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
