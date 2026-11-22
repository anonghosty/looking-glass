#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""Licence and copyright in every source file (OpenSSF Best Practices, gold: license_per_file, copyright_per_file).
Every source file the release ships (Python, shell, JavaScript, CSS, page templates, YAML and TOML settings, the
service file template, scripts without an extension) carries, within its first 10 lines, the two REUSE-style lines

    SPDX-License-Identifier: AGPL-3.0-only
    SPDX-FileCopyrightText: the Looking Glass contributors

as a comment in the file's own syntax: "# " after the #! line, "/* ... */" at the top of scripts and styles, and
"{# ... -#}" at the very top of page templates (a Jinja comment prints nothing, and "-#}" also drops the line end
after it, so a page starts exactly as before). Third-party files are listed below with their own licence; data
(JSON), lock files, images, documentation and the lists made at release time are not source files.

Which files: in a release (platform/ beside database/, install.sh at the top) the release's own file lists
(.release_files) and the top of the release; in the maintainer's copy the files tools/make_release.py ships, from
the platform, tools/release_root and the pipeline ($LG_PIPELINE_DIR, then ../shadowserver). LG_HELD_DIR: a held
copy <name>.new of a page file (and of a pipeline file) is read instead of the installed one. No database needed.
Run: .venv/bin/python tests/check_spdx_headers.py"""
import fnmatch
import os
import re
import sys

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOP = os.path.dirname(HERE)
LICENSE_ID = "AGPL-3.0-only"
L1 = f"SPDX-License-Identifier: {LICENSE_ID}"
L2 = "SPDX-FileCopyrightText: the Looking Glass contributors"
# the files a signed-out visitor can load (auth.PUBLIC_STATIC) never name the product (anti-fingerprinting,
# tests/check_fingerprint.py): their copyright line names "the project's contributors" instead, and nothing else in
# them may name the product
L2_PUBLIC = "SPDX-FileCopyrightText: the project's contributors"
PRODUCT = "Looking Glass"


def public_static():
    """platform/static/... paths served before sign-in, read from auth.py (the one list), or None if not found."""
    try:
        src = open(os.path.join(HERE, "auth.py"), encoding="utf-8").read()
    except OSError:
        return None
    m = re.search(r'PUBLIC_STATIC\s*=\s*frozenset\("/static/"\s*\+\s*f\s+for\s+f\s+in\s*\((.*?)\)\)', src, re.S)
    return {"platform/static/" + x for x in re.findall(r'"([^"]+)"', m.group(1))} if m else None
HEAD_LINES = 10
HASH_EXT = (".py", ".sh", ".bash", ".yml", ".yaml", ".toml", ".service.template")

# third-party files the release ships, with their own licence: never given the project's lines (paths from the top of
# the release; platform/ and database/ as in a release). Each entry must still match a shipped file.
THIRD_PARTY = {
    "platform/static/data/adm1/*.json": "geoBoundaries gbOpen (CC BY 4.0) and Natural Earth (public domain); "
                                        "each file's licence in static/data/adm1/index.json",
    "platform/static/data/ghana_regions.json": "geoBoundaries gbOpen ADM1 (CC BY 4.0)",
    "platform/static/data/LICENSE-world-atlas.md": "world-atlas, ISC licence (Michael Bostock), from Natural Earth",
    "platform/tests/fixtures/attack_map/*.json": "trimmed MITRE ATT&CK (ATT&CK terms of use) and CISA KEV samples",
    "platform/tests/fixtures/offline_names/*.json": "trimmed MITRE ATT&CK and MISP galaxy samples (CC0 / BSD-2-Clause)",
}
# made at release time, never edited by hand
GENERATED = {".release_files", ".release_files_history", ".release_fingerprints", "looking-glass-sbom.spdx.json"}
# what a release puts at its top (tools/release_root): files and the folders docs, .github, overrides
TOP_SHIPPED = {"docs", ".github", "overrides", "CONTRIBUTING.md", ".readthedocs.yaml", "CODE_OF_CONDUCT.md", "install.sh",
               "README.md", ".gitignore", "mkdocs_hooks.py", "ruff.toml", "install.answers.example", "installer_anim.py",
               "uninstall.sh", "mkdocs.yml", "CHANGELOG.md", "ACCESSIBILITY.md", "LICENSE"}
SKIP_DIRS = {".git", ".venv", ".venvs", ".installer-venv", "__pycache__", "node_modules", "site", ".ruff_cache", "media", "backups", "data"}

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info and not cond else ""))


def kind(path, name):
    """'hash', 'block', 'jinja' or None (not a source file)."""
    n = name[:-4] if name.endswith(".new") else name
    if n.endswith(HASH_EXT):
        return "hash"
    if n.endswith((".js", ".css")):
        return "block"
    if n.endswith(".html"):
        return "jinja"
    if "." not in n.lstrip("."):
        try:
            with open(path, "rb") as fh:
                return "hash" if fh.read(2) == b"#!" else None
        except OSError:
            return None
    return None


HELD = os.environ.get("LG_HELD_DIR", "")
PIPE_HELD = os.environ.get("LG_PIPELINE_DIR", "")


def held_page(rel, path):
    """A page file's held copy (LG_HELD_DIR/<name>.new) when there is one."""
    if HELD and re.fullmatch(r"(static/js/[^/]+\.js|static/css/[^/]+\.css|templates/[^/]+\.html)", rel):
        h = os.path.join(HELD, os.path.basename(rel) + ".new")
        if os.path.isfile(h):
            return h
    return path


def held_pipe(rel, path):
    """A pipeline file's held copy: LG_PIPELINE_DIR/<name>, else LG_HELD_DIR/<name>.new."""
    b = os.path.basename(rel)
    for h in ((os.path.join(PIPE_HELD, b) if PIPE_HELD else ""), (os.path.join(HELD, b + ".new") if HELD else "")):
        if h and os.path.isfile(h):
            return h
    return path


def listed(folder):
    """The release's file list of a folder (.release_files), or None."""
    p = os.path.join(folder, ".release_files")
    if not os.path.isfile(p):
        return None
    return [ln.strip() for ln in open(p, encoding="utf-8") if ln.strip() and not ln.startswith("#")]


def walk(root, skip=SKIP_DIRS):
    # a Python environment is never our source: the guided installer's own (.installer-venv, at the top of an
    # installation) or any other folder holding pyvenv.cfg
    for d, dirs, files in os.walk(root):
        dirs[:] = sorted(x for x in dirs if x not in skip and not os.path.isfile(os.path.join(d, x, "pyvenv.cfg")))
        for f in sorted(files):
            yield os.path.relpath(os.path.join(d, f), root)


files = {}   # shown path (as in a release) -> path read
release = os.path.isfile(os.path.join(TOP, "install.sh")) and os.path.isdir(os.path.join(TOP, "database")) \
    and os.path.basename(HERE) == "platform"
if release:
    layout = f"release: {TOP}"
    for part in ("platform", "database"):
        folder = os.path.join(TOP, part)
        rels = listed(folder)
        if rels is None:
            rels = list(walk(folder))
        for rel in rels:
            p = os.path.join(folder, rel)
            files[f"{part}/{rel}"] = held_page(rel, p) if part == "platform" else held_pipe(rel, p)
    # the top of an installation can hold anything (the installer's environment, your own folders, a restore's leftovers):
    # only what a release ships there is read (TOP_SHIPPED; the maintainer's copy checks that it matches release_root)
    for rel in walk(TOP, SKIP_DIRS | {"platform", "database"}):
        if rel.split(os.sep)[0] in TOP_SHIPPED:
            files[rel] = os.path.join(TOP, rel)
    license_file = os.path.join(TOP, "LICENSE")
else:
    sys.path.insert(0, os.path.join(HERE, "tools"))
    try:
        import make_release as MR
    except ImportError:
        print("SKIPPED: neither a release (../install.sh, ../database) nor the maintainer's copy (tools/make_release.py)")
        sys.exit(77)
    layout = f"maintainer's copy: {HERE}"
    for top, dirs, names in os.walk(HERE):
        dirs[:] = sorted(d for d in dirs if d not in MR.PLATFORM_SKIP_DIRS and not (top == os.path.join(HERE, "data") and d == "tls"))
        for f in sorted(names):
            p = os.path.join(top, f)
            rel = os.path.relpath(p, HERE)
            if not MR.skipped(rel) and not os.path.islink(p):
                files[f"platform/{rel}"] = held_page(rel, p)
    rr = os.path.join(HERE, "tools", "release_root")
    for rel in walk(rr):
        files[rel] = os.path.join(rr, rel)
    pipe = next((p for p in (os.path.join(TOP, "database"), os.path.join(TOP, "shadowserver"))
                 if os.path.isfile(os.path.join(p, "shadowserver_pipeline.py"))), "")
    for rel in MR.DATABASE_FILES:
        live = os.path.join(pipe, rel) if pipe else ""
        p = held_pipe(rel, live)
        if p and os.path.isfile(p):
            files[f"database/{rel}"] = p
    files["database/safe_libraries.py"] = os.path.join(HERE, "deploy", "safe_libraries.py")
    license_file = os.path.join(rr, "LICENSE")

print(f"SPDX lines in every shipped source file ({layout}"
      + (f"; held copies from {HELD}" if HELD else "") + (f"; pipeline held copies from {PIPE_HELD}" if PIPE_HELD else "") + ")")

# ---- the project's licence: LICENSE, the SBOM and these lines name the same one
lic = open(license_file, encoding="utf-8", errors="replace").read() if os.path.isfile(license_file) else ""
ok("LICENSE is the GNU Affero General Public License version 3", "GNU AFFERO GENERAL PUBLIC LICENSE" in lic and "Version 3" in lic,
   license_file)
sbom_src = os.path.join(HERE, "tools", "make_sbom.py")
m = re.search(r'^PROJECT_LICENSE\s*=\s*"([^"]+)"', open(sbom_src, encoding="utf-8").read(), re.M) if os.path.isfile(sbom_src) else None
ok(f"the SBOM names the same licence ({LICENSE_ID})", bool(m) and m.group(1) == LICENSE_ID, m.group(1) if m else "PROJECT_LICENSE not found")
if not release:                                  # the list an installation's top is read with must follow release_root
    have = set(os.listdir(rr))
    ok("TOP_SHIPPED is exactly what tools/release_root ships at the top", have == TOP_SHIPPED,
       f"only in release_root: {sorted(have - TOP_SHIPPED)}; only in TOP_SHIPPED: {sorted(TOP_SHIPPED - have)}")

# ---- every source file
third = {k: [] for k in THIRD_PARTY}
missing, wrong_id, bad_top, n_by_kind = [], [], [], {}
PUBLIC = public_static()
ok("the list of files served before sign-in was found (auth.PUBLIC_STATIC)", bool(PUBLIC), "auth.py")
PUBLIC = PUBLIC or set()
public_seen, public_named = [], []
for shown, p in sorted(files.items()):
    name = os.path.basename(shown)
    if name in GENERATED or name.endswith(".pyc"):
        continue
    hit = next((pat for pat in THIRD_PARTY if fnmatch.fnmatch(shown, pat)), None)
    if hit:
        third[hit].append(shown)
        continue
    k = kind(p, name)
    if not k:
        continue
    try:
        text = open(p, encoding="utf-8-sig").read()
    except (OSError, UnicodeDecodeError) as e:
        missing.append(f"{shown} (unreadable: {e})")
        continue
    n_by_kind[k] = n_by_kind.get(k, 0) + 1
    head = text.splitlines()[:HEAD_LINES]
    if shown in PUBLIC:
        public_seen.append(shown)
        if PRODUCT in text:
            public_named.append(shown)
        if not (any(L1 in ln for ln in head) and any(L2_PUBLIC in ln for ln in head)):
            missing.append(f"{shown} (served before sign-in: needs '{L2_PUBLIC}')")
            continue
    elif not (any(L1 in ln for ln in head) and any(L2 in ln for ln in head)):
        missing.append(shown)
        continue
    ids = re.findall(r"SPDX-License-Identifier:\s*(\S+)", "\n".join(head))
    if any(i.rstrip("*/#}-") != LICENSE_ID for i in ids):
        wrong_id.append(f"{shown}: {', '.join(ids)}")
    if k == "jinja" and not text.startswith("{#"):
        bad_top.append(f"{shown}: the comment is not the first thing in the file")
    if k == "block" and not text.startswith("/*"):
        bad_top.append(f"{shown}: the comment is not at the top")

total = sum(n_by_kind.values())
print(f"  {total} source files read: " + ", ".join(f"{n} {k}-comment" for k, n in sorted(n_by_kind.items())))
ok("there are source files to check (the file list was found)", total > 100, str(total))
ok(f"every shipped source file has both SPDX lines within its first {HEAD_LINES} lines", not missing,
   f"{len(missing)}: " + ", ".join(missing[:15]))
ok(f"the licence named is {LICENSE_ID} everywhere", not wrong_id, "; ".join(wrong_id[:10]))
src_public = {p for p in PUBLIC if p.endswith((".js", ".css"))}
ok("every script and style served before sign-in was read", src_public <= set(public_seen), sorted(src_public - set(public_seen)))
ok(f"no file served before sign-in names the product (its copyright line says \"{L2_PUBLIC[24:]}\")", not public_named,
   ", ".join(public_named))
ok("page templates start with the Jinja comment, scripts and styles with the /* */ comment", not bad_top, "; ".join(bad_top[:10]))
gone = [pat for pat, got in third.items() if not got]
ok("every third-party entry still matches a shipped file (the list stays true)", not gone, ", ".join(gone))
for pat, got in third.items():
    print(f"       third-party, own licence: {pat} ({len(got)} file(s)): {THIRD_PARTY[pat]}")

# ---- the comments change nothing that runs or is shown
try:
    import jinja2
    env = jinja2.Environment(autoescape=True)
    out = env.from_string("{# " + L1 + "\n   " + L2 + " -#}\n<!doctype html>\n<p>x</p>").render()
    ok("a template's header comment prints nothing: the page starts with <!doctype html> as before",
       out == "<!doctype html>\n<p>x</p>", repr(out[:40]))
except ImportError:
    print("  (jinja2 not importable here: template rendering not tried)")
tpl = os.path.join(HERE, "deploy", "looking-glass.service.template")
if os.path.isfile(tpl):
    sys.path.insert(0, os.path.join(HERE, "deploy"))
    import service_unit
    t = open(tpl, encoding="utf-8").read()
    rendered = service_unit.render(t, "lgtest", "/opt/lg-test", "127.0.0.1:8080")
    ok("the service file written from the template carries no SPDX lines (an installed one is not reported out of date)",
       "SPDX-" not in rendered and L1 in t, "")
# scripts that print their own opening comment as help (sed -n 'A,Bp' "$0" or sed -n 'A,/pattern/p' "$0"): the printed
# lines start at the description, never at the SPDX lines, and hold none of them
helps, bad_help = 0, []
for shown, p in sorted(files.items()):
    if not shown.endswith((".sh", ".bash")) or not os.path.isfile(p):
        continue
    src = open(p, encoding="utf-8", errors="replace").read()
    lines = src.splitlines()
    for m in re.finditer(r"sed -n '(\d+),(\d+|/[^/']+/)p' \"\$0\"", src):
        helps += 1
        a = int(m.group(1))
        if m.group(2).isdigit():
            b = int(m.group(2))
        else:
            rx = re.compile(m.group(2)[1:-1])
            b = next((i + 1 for i in range(a - 1, len(lines)) if rx.search(lines[i])), len(lines))
        part = lines[a - 1:b]
        if not part or not part[0].startswith("#") or any("SPDX-" in ln for ln in part):
            bad_help.append(f"{shown} lines {a}-{b}")
ok(f"self-printed help texts start after the SPDX lines and hold none ({helps} found)", not bad_help, ", ".join(bad_help))

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
