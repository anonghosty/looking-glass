#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""stale_files.py: code files a former release shipped and the new one no longer does are moved aside on update,
never deleted. Files Looking Glass never shipped are never moved.

A release carries, in each folder (platform/ and database/), two lists written by the release builder with write_list()
below: .release_files, every file this release ships there, and .release_files_history, every file any published
release has shipped there (this one included). After an update has put the new files in place
(deploy/update_libraries.sh calls this), every file in the CODE folders that is not on the first list but IS on the
history list (a former Looking Glass file) is moved to <folder>/backups/stale-<date>-<time>/, under the same relative
path, and named in the output and in moved.log there. Put one back with mv if it was yours. A file on neither list
(your own script, say) is left where it is and named: "Not part of Looking Glass, left in place: <path>".

    stale_files.py --folder PATH --part platform|database [--dry-run]
    stale_files.py --folder PATH --write-list      (building a release: list the files in PATH now; the history list
                                                    already there, if any, is kept and the current files added to it)

Beside the two lists, write_list() writes .release_fingerprints: the SHA-256 of every file on .release_files, one
"<sha256>  <path>" line each (the format of sha256sum), with the same count line. deploy/verify_install.py (on demand,
optionally against the signed release on GitHub) and the platform's daily code check (code_integrity.py) read it with
read_fingerprints(); this tool itself does not need it.

The code folders:   platform: the *.py files at the top, static/js, static/css, templates, tests, tools, deploy,
                    security_testing;  database: the *.py and *.sh files at the top, tests, bin.
Never touched:      everything else (data/, .env and every .env*, .venv/.venvs, logs, backups, certificates and keys,
                    mail and report folders, the library copies, anything outside PATH), files this computer makes
                    in the code folders (caches, logs, the service file, the diagnostics' output), symbolic links
                    (never followed), hidden folders, and every file no Looking Glass release ever shipped.
Nothing is moved:   when either list is missing or empty (an older release without the history list: every unlisted
                    file is named and left in place), when a count line does not match, when a line is an absolute
                    path or holds "..", when the history list lacks a file of the current list, when a listed file is
                    missing (the new release is not fully in place), in the maintainer's working copy
                    (tools/release_root), with --dry-run, or with LG_KEEP_STALE=1 (former files are listed, and kept).
Exit codes: 0 done (or nothing to do), 2 a list was refused (nothing moved), 1 other errors.
It needs only Python's standard library.
"""
import argparse
import datetime
import fnmatch
import hashlib
import os
import re
import sys

LIST_NAME = ".release_files"
HISTORY_NAME = ".release_files_history"
FINGERPRINTS_NAME = ".release_fingerprints"
FINGERPRINTS_HEADER = ("# Looking Glass: the SHA-256 of every file this release ships in this folder "
                       "(deploy/verify_install.py and the daily code check read it)")
_SHA_LINE = re.compile(r"\A([0-9a-f]{64})  (.+)\Z")
HEADER = "# Looking Glass: every file this release ships in this folder (deploy/stale_files.py reads it on update)"
HISTORY_HEADER = ("# Looking Glass: every file any published release has shipped in this folder, this one included "
                  "(deploy/stale_files.py moves only these)")
CODE = {
    "platform": {"top": (".py",), "dirs": ("static/js", "static/css", "templates", "tests", "tools", "deploy", "security_testing")},
    "database": {"top": (".py", ".sh"), "dirs": ("tests", "bin")},
}
# made on this computer inside the code folders: never moved, listed or not (the platform's .gitignore keeps them out)
KEEP_NAMES = ("*.pyc", "*.log", ".env", ".env.*", "suspected-packages.*", "*.pem", "*.key", "*.crt", LIST_NAME,
              HISTORY_NAME, FINGERPRINTS_NAME)
OWN_LISTS = (LIST_NAME, HISTORY_NAME, FINGERPRINTS_NAME)
# the unit files this installation writes into deploy/ from the shipped *.template (service_unit.py, update_helper.sh:
# <name>.path for Settings -> Update, unusual_timer.sh / connectors_timer.sh: *.timer); a fresh installation's code check
# reported deploy/looking-glass-update.path as "not in the release" (2026-11-26)
KEEP_PATHS = ("deploy/*.service", "deploy/*.path", "deploy/*.timer", "tools/discovery.json", "tools/services_fields.json",
              "security_testing/SECURITY_REPORT.md")
SKIP_DIRS = {"__pycache__", "node_modules", "data", "logs", "backups", "site", ".venv", ".venvs"}
REFUSED = 2


class ListRefused(Exception):
    pass


# ------------------------------------------------------------------------------------------------ the list
def unsafe(rel):
    """Why a relative path may not be on a list ('' when it may): absolute, backslash, '..', '.' or empty parts."""
    if not rel or rel.startswith(("/", "\\")) or (len(rel) > 1 and rel[1] == ":") or "\\" in rel or "\0" in rel \
            or "\n" in rel or "\r" in rel:
        return "an absolute or unusual path"
    parts = rel.split("/")
    if ".." in parts or "." in parts or "" in parts:
        return "a path with '..' or an empty part"
    return ""


def _write(folder, name, header, rels):
    rels = sorted(set(rels))
    with open(os.path.join(folder, name), "w", encoding="utf-8", newline="\n") as fh:
        fh.write(f"{header}\n# files: {len(rels)}\n")
        fh.write("".join(r + "\n" for r in rels))
    return len(rels)


def write_list(folder, history=None):
    """Write <folder>/.release_files: every regular file under folder (relative, '/', sorted), with a count line, and
    <folder>/.release_files_history: the given history paths (every file a published release shipped in this folder)
    plus the current files. Without history, the history list already in the folder (if any) is kept and the current
    files are added to it, so the history always holds the current list. Returns the number of current files.
    Used by the release builder (tools/make_release.py) and the staging step (--write-list)."""
    rels = []
    for top, dirs, files in os.walk(folder):
        dirs[:] = sorted(d for d in dirs if not os.path.islink(os.path.join(top, d)))
        for f in files:
            p = os.path.join(top, f)
            if os.path.isfile(p) and not os.path.islink(p):
                rels.append(os.path.relpath(p, folder).replace(os.sep, "/"))
    rels = sorted(r for r in rels if r not in OWN_LISTS)
    bad = [r for r in rels if unsafe(r)]
    if bad:
        raise ListRefused(f"a file here has a name no list may hold: {bad[0][:80]}")
    if history is None:
        history = read_list(folder, HISTORY_NAME) or set()
    history = {h for h in history if not unsafe(h) and h not in OWN_LISTS}
    n = _write(folder, LIST_NAME, HEADER, rels)
    _write(folder, HISTORY_NAME, HISTORY_HEADER, history | set(rels))
    write_fingerprints(folder, rels)
    return n


def sha256_of(path):
    """The SHA-256 of a file's bytes, exactly as they are on disk (hex)."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def write_fingerprints(folder, rels):
    """<folder>/.release_fingerprints: "<sha256>  <path>" for every given file (the files of .release_files), sorted,
    with a count line. Written by write_list(), so the release builder and the staging step write it together."""
    rels = sorted(set(rels))
    with open(os.path.join(folder, FINGERPRINTS_NAME), "w", encoding="utf-8", newline="\n") as fh:
        fh.write(f"{FINGERPRINTS_HEADER}\n# files: {len(rels)}\n")
        for r in rels:
            fh.write(f"{sha256_of(os.path.join(folder, *r.split('/')))}  {r}\n")
    return len(rels)


def parse_fingerprints(text, name=FINGERPRINTS_NAME):
    """{path: sha256} from the text of a fingerprint list; None when it lists nothing. Raises ListRefused when it cannot
    be trusted (a count that does not match, a malformed line, an absolute path or '..', a path listed twice)."""
    out, count = {}, None
    for raw in text.split("\n"):
        line = raw.rstrip("\r")
        if line.startswith("# files:"):
            try:
                count = int(line.split(":", 1)[1])
            except ValueError:
                raise ListRefused(f"{name}: the count line is not a number") from None
            continue
        if not line.strip() or line.startswith("#"):
            continue
        m = _SHA_LINE.match(line)
        if not m:
            raise ListRefused(f"{name}: a line is not '<sha256>  <path>' ({line[:80]})")
        sha, rel = m.groups()
        why = unsafe(rel)
        if why:
            raise ListRefused(f"{name}: {why} is listed ({rel[:80]})")
        if rel in out:
            raise ListRefused(f"{name}: {rel[:80]} is listed twice")
        out[rel] = sha
    if not out:
        return None
    if count is None or count != len(out):
        raise ListRefused(f"{name}: it says {count} files but lists {len(out)} (cut short or changed)")
    return out


def read_fingerprints(folder):
    """{path: sha256} from <folder>/.release_fingerprints; None when there is none (a release before r91) or it lists
    nothing. Raises ListRefused when it cannot be trusted."""
    path = os.path.join(folder, FINGERPRINTS_NAME)
    if not os.path.isfile(path) or os.path.islink(path):
        return None
    with open(path, encoding="utf-8") as fh:
        return parse_fingerprints(fh.read())


def in_code_folders(rel, part):
    """True when a relative path lies where code_files() looks (the part's code folders), whether or not it exists."""
    spec = CODE[part]
    if "/" not in rel:
        return rel.endswith(spec["top"])
    parts = rel.split("/")
    if any(p in SKIP_DIRS or p.startswith(".") for p in parts[:-1]):
        return False
    return any(rel.startswith(d + "/") for d in spec["dirs"])


def read_list(folder, name=LIST_NAME):
    """The set of relative paths in <folder>/<name> (.release_files, or .release_files_history); None when there is no
    list or it lists nothing. Raises ListRefused when the list cannot be trusted (bad count, absolute path, '..')."""
    path = os.path.join(folder, name)
    if not os.path.isfile(path) or os.path.islink(path):
        return None
    rels, count = set(), None
    with open(path, encoding="utf-8") as fh:
        for raw in fh:
            line = raw.rstrip("\n").rstrip("\r")
            if line.startswith("# files:"):
                try:
                    count = int(line.split(":", 1)[1])
                except ValueError:
                    raise ListRefused(f"{name}: the count line is not a number") from None
                continue
            if not line.strip() or line.startswith("#"):
                continue
            why = unsafe(line)
            if why:
                raise ListRefused(f"{name}: {why} is listed ({line[:80]})")
            rels.add(line)
    if not rels:
        return None
    if count is None or count != len(rels):
        raise ListRefused(f"{name}: it says {count} files but lists {len(rels)} (cut short or changed)")
    return rels


# ------------------------------------------------------------------------------------------------ what is stale
def kept(rel):
    name = rel.rsplit("/", 1)[-1]
    return any(fnmatch.fnmatch(name, p) for p in KEEP_NAMES) or any(fnmatch.fnmatch(rel, p) for p in KEEP_PATHS)


def code_files(folder, part):
    """Every regular file (no symbolic links) in the part's code folders, relative to folder."""
    spec = CODE[part]
    out = []
    for f in sorted(os.listdir(folder)):
        p = os.path.join(folder, f)
        if f.endswith(spec["top"]) and os.path.isfile(p) and not os.path.islink(p):
            out.append(f)
    for d in spec["dirs"]:
        base = os.path.join(folder, *d.split("/"))
        # the folder itself and every part of its path must be real folders, not links
        parts = d.split("/")
        if any(os.path.islink(os.path.join(folder, *parts[:i + 1])) for i in range(len(parts))) or not os.path.isdir(base):
            continue
        for top, dirs, files in os.walk(base):            # os.walk never descends into a linked folder
            dirs[:] = sorted(x for x in dirs if x not in SKIP_DIRS and not x.startswith(".")
                             and not os.path.islink(os.path.join(top, x)))
            for f in sorted(files):
                p = os.path.join(top, f)
                if os.path.islink(p) or not os.path.isfile(p):
                    continue
                out.append(os.path.relpath(p, folder).replace(os.sep, "/"))
    return out


def find_stale(folder, part):
    """(former, unknown, history_present, None), or ([], [], False, reason) when nothing may be checked.
    former: unlisted code files a published release shipped (these may be moved); unknown: unlisted code files no
    release ever shipped, or every unlisted code file when there is no history list (these are never moved)."""
    folder = os.path.abspath(folder)
    if os.path.isdir(os.path.join(folder, "tools", "release_root")):
        return [], [], False, "this is the maintainer's working copy (tools/release_root is here)"
    listed = read_list(folder)
    if listed is None:
        return [], [], False, f"no release file list ({LIST_NAME}) here, or it lists nothing"
    history = read_list(folder, HISTORY_NAME)
    if history is not None and not listed <= history:
        lacking = sorted(listed - history)
        raise ListRefused(f"{HISTORY_NAME} lacks {len(lacking)} file(s) of {LIST_NAME} (changed or not from this "
                          "release): " + ", ".join(lacking[:5]))
    missing = sorted(r for r in listed if not os.path.isfile(os.path.join(folder, *r.split("/"))))
    if missing:
        raise ListRefused(f"{len(missing)} listed file(s) are missing, so the new release is not fully in place: "
                          + ", ".join(missing[:5]))
    unlisted = [r for r in code_files(folder, part) if r not in listed and not kept(r)]
    if history is None:
        return [], unlisted, False, None
    return [r for r in unlisted if r in history], [r for r in unlisted if r not in history], True, None


def move_aside(folder, rels, now=None):
    """Move each file to <folder>/backups/stale-<time>/<rel>; returns that folder."""
    stamp = (now or datetime.datetime.now()).strftime("%Y%m%d-%H%M%S")
    dest = os.path.join(folder, "backups", f"stale-{stamp}")
    n = 2
    while os.path.exists(dest):
        dest = os.path.join(folder, "backups", f"stale-{stamp}-{n}")
        n += 1
    os.makedirs(dest, mode=0o700)
    with open(os.path.join(dest, "moved.log"), "w", encoding="utf-8") as log:
        log.write(f"# {stamp}: code files the new release no longer ships, moved here from {folder}\n")
        for rel in rels:
            src = os.path.join(folder, *rel.split("/"))
            dst = os.path.join(dest, *rel.split("/"))
            os.makedirs(os.path.dirname(dst), mode=0o700, exist_ok=True)
            os.rename(src, dst)                           # same file system: the file itself, its mode kept
            log.write(rel + "\n")
    return dest


def run(folder, part, dry_run=False, keep=False, out=print):
    folder = os.path.abspath(folder)
    try:
        stale, unknown, has_history, why = find_stale(folder, part)
    except ListRefused as e:
        out(f"Old code files ({part}): NOT checked, nothing moved: {e}")
        return REFUSED
    except OSError as e:
        out(f"Old code files ({part}): could not read the release file lists, nothing moved: {e}")
        return REFUSED
    if why:
        out(f"Old code files ({part}): not checked, nothing moved: {why}.")
        return 0
    if not has_history:
        out(f"Old code files ({part}): nothing moved: there is no list of the files earlier releases shipped "
            f"({HISTORY_NAME}) here, so no file can be told to be a former Looking Glass file.")
        for rel in unknown:
            out(f"  Not on this release's list, left in place: {rel}")
        return 0
    for rel in unknown:
        out(f"Not part of Looking Glass, left in place: {rel}")
    if unknown:
        # a contributor's new file, or an installation's own script, is expected here: say so plainly
        out(f"  ({len(unknown)} file(s) above: no Looking Glass release has shipped them, so they are never moved. "
            "This is normal for your own scripts and for new work not released yet.)")
    if not stale:
        out(f"Old code files ({part}): none; "
            + ("every code file here is shipped by this release." if not unknown
               else "no file an earlier release shipped is left in the code folders."))
        return 0
    out(f"Old code files ({part}): {len(stale)} file(s) an earlier release shipped and the new one no longer does:")
    for rel in stale:
        out(f"  {rel}")
    if dry_run:
        out("  (listing only: nothing moved)")
        return 0
    if keep:
        out("  Kept, because LG_KEEP_STALE=1 is set.")
        return 0
    try:
        dest = move_aside(folder, stale)
    except OSError as e:
        out(f"  Could not move them all aside ({e}); what was moved is listed in moved.log under {folder}/backups/.")
        return 1
    out(f"  Moved aside to {dest} (same folders inside, listed in moved.log). Put one back with mv if it was yours.")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--folder", required=True, help="the platform's or the database pipeline's folder")
    ap.add_argument("--part", choices=sorted(CODE))
    ap.add_argument("--dry-run", action="store_true", help="only list the files")
    ap.add_argument("--write-list", action="store_true",
                    help="for a release folder being built: write its .release_files from the files in it now")
    a = ap.parse_args(argv)
    if not os.path.isdir(a.folder) or os.path.islink(a.folder.rstrip("/")):
        print(f"{a.folder} is not a folder; nothing done.")
        return 1
    if a.write_list:
        try:
            n = write_list(a.folder)
        except ListRefused as e:
            print(f"{LIST_NAME} not written: {e}")
            return REFUSED
        print(f"{LIST_NAME}: {n} files listed in {a.folder}; {HISTORY_NAME}: "
              f"{len(read_list(a.folder, HISTORY_NAME) or ())} files (every release so far, this one included); "
              f"{FINGERPRINTS_NAME}: the SHA-256 of the {n} files")
        return 0
    if not a.part:
        ap.error("--part is needed (platform or database)")
    return run(a.folder, a.part, dry_run=a.dry_run, keep=os.environ.get("LG_KEEP_STALE") == "1")


if __name__ == "__main__":
    sys.exit(main())
