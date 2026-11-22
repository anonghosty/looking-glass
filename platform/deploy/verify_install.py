#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""verify_install.py: are the installed code files exactly the ones the release shipped? An administrator runs it on the
server, whenever they want to know (the platform's daily code check, code_integrity.py, watches between runs).

    verify_install.py [--folder PATH] [--part platform|database]            the list on this computer only
    verify_install.py --fetch [--tag vYYYY.MM.DD] [--folder ...] [--part ...] the signed release on GitHub
    verify_install.py --folder PATH --part ... --quarantine <path>           move one code file aside (never deleted)

--quarantine is what Settings → Code check's "Not ours, move to quarantine" asks an administrator to run on the server,
as the account that owns the installation: the service cannot change its own code (its code folders are read-only for
it). The file goes to <folder>/backups/quarantine-<time>/<path>, with moved.log; nothing is ever copied or deleted.

Every release carries, in platform/ and database/, a list of the SHA-256 of every file it ships (.release_fingerprints,
written by the release builder). This compares every installed code file with it (the code folders and the exclusions
of deploy/stale_files.py: the platform's *.py at the top, static/js, static/css, templates, tests, tools, deploy,
security_testing; the pipeline's *.py and *.sh at the top, tests, bin) and names each file that is
  CHANGED              on the list, but its content is not what the release shipped
  NOT IN THE RELEASE   in a code folder, but no file of that name is on the list (added here)
  MISSING              on the list, but not here

Without --fetch it reads the list on this computer. That proves only that the files match that list: someone who can
change the code here can change the list too. It makes no outside connection.
With --fetch (the only time it connects anywhere) it fetches the release's tag from GitHub into a temporary folder,
checks the tag's signature with git against the maintainer's published SSH signing key (its fingerprint is written
below and in docs/INSTALLATION.md, "Checking a release's signature"), and takes the list from that signed tag. Which
tag: --tag, else the tag of the installed commit (git describe, read locally). For full assurance run the copy of this
tool from the signed tag itself (docs/OPERATIONS.md says how), since a changed installation could change this file too.

Exit codes: 0 every code file matches; 1 differences found (listed); 2 not checked (no list, a list that cannot be
trusted, the release or its keys could not be fetched, the maintainer's working copy); 3 the signature is NOT good:
do not trust that release's list (nothing compared). It needs Python's standard library, and git and ssh-keygen for --fetch.
"""
import argparse
import base64
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import stale_files as SF  # noqa: E402

REPO = "https://github.com/anonghosty/looking-glass.git"
KEYS_URL = "https://api.github.com/users/anonghosty/ssh_signing_keys"
# the maintainer's signing key ("Looking Glass commit signing" on GitHub; docs/INSTALLATION.md)
KEY_FINGERPRINT = "SHA256:OgsRca17219/hsf7eF8MztBJXbPMgEYzatsAqKWznlU"
TAG_RE = re.compile(r"\Av[0-9][0-9A-Za-z._-]{0,40}\Z")
KEY_TYPES = ("ssh-ed25519", "ssh-rsa", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521",
             "sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com")
OK, DIFFERENT, NOT_CHECKED, BAD_SIGNATURE = 0, 1, 2, 3


class NotChecked(Exception):
    pass


class BadSignature(Exception):
    pass


# ------------------------------------------------------------------------------------------------ comparing
def compare(folder, part, listed):
    """(changed, added, missing, checked): changed [(rel, sha now, sha listed)], added [rel], missing [rel], and how many
    code files were looked at. listed: {rel: sha256} (a fingerprint list)."""
    files = [r for r in SF.code_files(folder, part) if not SF.kept(r)]
    changed, added = [], []
    for rel in files:
        want = listed.get(rel)
        if want is None:
            added.append(rel)
            continue
        got = SF.sha256_of(os.path.join(folder, *rel.split("/")))
        if got != want:
            changed.append((rel, got, want))
    here = set(files)
    missing = sorted(r for r in listed if SF.in_code_folders(r, part) and not SF.kept(r) and r not in here
                     and not os.path.lexists(os.path.join(folder, *r.split("/"))))
    return changed, added, missing, len(files)


# ------------------------------------------------------------------------------------------------ the signed release
def key_fingerprint(b64):
    """The SHA256:... fingerprint of an SSH public key (its base64 blob), as ssh-keygen -l prints it."""
    blob = base64.b64decode(b64.encode("ascii"), validate=True)
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode("ascii").rstrip("=")


def keys_from_lines(lines):
    """[(type, base64)] from allowed-signers lines or 'type base64 comment' lines."""
    out = []
    for line in lines:
        toks = line.split()
        for i, t in enumerate(toks[:-1]):
            if t in KEY_TYPES:
                out.append((t, toks[i + 1]))
                break
    return out


def github_keys(url=KEYS_URL, timeout=20):
    """The maintainer's published SSH signing keys (GitHub's API, the documented method)."""
    req = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json", "User-Agent": "looking-glass-verify"})
    with urllib.request.urlopen(req, timeout=timeout) as r:     # nosec B310: a fixed https address (or --keys-url)
        data = json.loads(r.read(1 << 20).decode("utf-8"))
    return keys_from_lines(str(k.get("key", "")) for k in data if isinstance(k, dict))


def signers_file(keys, want_fp, path):
    """Write an allowed-signers file holding only the keys whose fingerprint is want_fp; returns how many."""
    good = []
    for kt, b64 in keys:
        try:
            if key_fingerprint(b64) == want_fp:
                good.append(f'* namespaces="git" {kt} {b64}\n')
        except (ValueError, UnicodeError):
            continue
    with open(path, "w", encoding="utf-8") as fh:
        fh.writelines(good)
    return len(good)


def git(args, cwd=None, timeout=180):
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0", GIT_ASKPASS="true", LC_ALL="C")
    return subprocess.run(["git"] + args, cwd=cwd, capture_output=True, text=True, timeout=timeout, env=env)


def installed_tag(folder):
    """The release tag of the installed commit, read from the local git checkout (no connection); '' when none."""
    if not shutil.which("git"):
        return ""
    r = git(["-C", folder, "describe", "--tags", "--exact-match", "HEAD"], timeout=30)
    tag = r.stdout.strip() if r.returncode == 0 else ""
    return tag if TAG_RE.match(tag) else ""


def signed_list(tag, part, repo, keys, want_fp, out=print):
    """Fetch the tag from repo into a temporary folder, check its signature (only want_fp is allowed), and return the
    release's fingerprint list for the part ({rel: sha256}). Raises NotChecked or BadSignature."""
    for tool in ("git", "ssh-keygen"):
        if not shutil.which(tool):
            raise NotChecked(f"{tool} is not installed here (sudo apt install {'git' if tool == 'git' else 'openssh-client'})")
    tmp = tempfile.mkdtemp(prefix="lg-verify-")
    try:
        allowed = os.path.join(tmp, "allowed_signers")
        if not signers_file(keys, want_fp, allowed):
            raise BadSignature(f"none of the published signing keys has the fingerprint {want_fp}: "
                               "compare it with docs/INSTALLATION.md, 'Checking a release's signature'")
        bare = os.path.join(tmp, "release.git")
        r = git(["init", "-q", "--bare", bare])
        if r.returncode:
            raise NotChecked("git could not make a temporary repository")
        out(f"  fetching the tag {tag} from {repo} ...")
        r = git(["-C", bare, "fetch", "-q", "--no-tags", "--depth", "1", repo, f"refs/tags/{tag}:refs/tags/{tag}"])
        if r.returncode:
            raise NotChecked(f"the tag {tag} could not be fetched from {repo}: {r.stderr.strip()[:300] or 'no answer'}")
        if git(["-C", bare, "cat-file", "-t", f"refs/tags/{tag}"]).stdout.strip() != "tag":
            raise BadSignature(f"{tag} is not a signed (annotated) tag")
        r = git(["-C", bare, "-c", f"gpg.ssh.allowedSignersFile={allowed}", "verify-tag", f"refs/tags/{tag}"])
        said = (r.stderr + r.stdout).strip()
        if r.returncode or 'Good "git" signature' not in said or want_fp not in said:
            raise BadSignature(f"the signature of {tag} is not good: {said[:300] or 'no signature'}")
        out(f"  signature: good, made with the key {want_fp}")
        r = git(["-C", bare, "show", f"refs/tags/{tag}:{part}/{SF.FINGERPRINTS_NAME}"])
        if r.returncode:
            raise NotChecked(f"the release {tag} has no {part}/{SF.FINGERPRINTS_NAME} (releases before r91 have none): "
                             "nothing to compare with")
        try:
            listed = SF.parse_fingerprints(r.stdout, f"{tag}:{part}/{SF.FINGERPRINTS_NAME}")
        except SF.ListRefused as e:
            raise NotChecked(str(e)) from None
        if not listed:
            raise NotChecked(f"the release {tag} lists no files for {part}")
        return listed
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ------------------------------------------------------------------------------------------------ quarantine
def quarantine(folder, part, rel, out=print, now=None):
    """Move one code file out of the code folders, never deleting it: <folder>/backups/quarantine-<time>/<rel>, with
    moved.log there (the file's SHA-256, when). Run by an administrator, as themselves (Settings → Code check gives the
    command: the service cannot change its own code). Only a plain file in a code folder; a folder that cannot be
    written is said before anything is made (no partial copy is ever left). Exit 0 moved, 2 refused."""
    folder = os.path.abspath(folder)
    rel = rel.strip().replace("\\", "/")
    if rel.startswith(part + "/") and not SF.in_code_folders(rel, part):
        rel = rel[len(part) + 1:]                     # "platform/tools/x.py" as the page names it
    why = SF.unsafe(rel)
    src = os.path.join(folder, *rel.split("/")) if not why else ""
    if why or not SF.in_code_folders(rel, part):
        out(f"Not moved: {rel[:120]} is not a file in {part}'s code folders ({why or 'outside them'}).")
        return NOT_CHECKED
    if os.path.islink(src) or not os.path.isfile(src) or not os.path.realpath(src).startswith(os.path.realpath(folder) + os.sep):
        out(f"Not moved: {rel} is not a plain file here (missing, or a link).")
        return NOT_CHECKED
    if not (os.access(os.path.dirname(src), os.W_OK) and os.access(folder, os.W_OK)):
        out(f"Not moved: {os.path.dirname(src)} cannot be changed by this account (run it as the account that owns the "
            "installation, for example with sudo -u <that account>). Nothing was copied or changed.")
        return NOT_CHECKED
    sha = SF.sha256_of(src)
    stamp = time.strftime("%Y%m%d-%H%M%S", time.gmtime(now or time.time()))
    dest, n = os.path.join(folder, "backups", f"quarantine-{stamp}"), 2
    while os.path.exists(os.path.join(dest, *rel.split("/"))):
        dest, n = os.path.join(folder, "backups", f"quarantine-{stamp}-{n}"), n + 1
    dst = os.path.join(dest, *rel.split("/"))
    try:
        os.makedirs(os.path.dirname(dst), mode=0o700, exist_ok=True)
        os.rename(src, dst)                           # the same folder tree: the file itself, never a copy
    except OSError as e:
        out(f"Not moved: {e.strerror or type(e).__name__} ({rel}). Nothing was copied; the file is where it was.")
        return NOT_CHECKED
    with open(os.path.join(dest, "moved.log"), "a", encoding="utf-8") as log:
        log.write(f"{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(now or time.time()))}  {sha}  {part}/{rel}\n")
    out(f"Moved to quarantine: {part}/{rel} (sha256 {sha}) is now {dst} (not deleted; moved.log there). The daily "
        "code check records that it has gone. If it was a file the release ships, put the released copy back with "
        f"git checkout <tag> -- {part}/{rel}  in the Looking Glass folder, then restart Looking Glass.")
    return OK


# ------------------------------------------------------------------------------------------------ the command
def run(folder, part, fetch=False, tag="", repo=REPO, signers=None, want_fp=KEY_FINGERPRINT, keys_url=KEYS_URL, out=print):
    folder = os.path.abspath(folder)
    out(f"Code check ({part}): {folder}")
    if os.path.isdir(os.path.join(folder, "tools", "release_root")):
        out("  Not checked: this is the maintainer's working copy (tools/release_root is here).")
        return NOT_CHECKED
    try:
        local = SF.read_fingerprints(folder)
    except (SF.ListRefused, OSError) as e:
        local, local_err = None, str(e)
    else:
        local_err = ""
    if fetch:
        tag = tag or installed_tag(folder)
        if not tag:
            out("  Not checked: which release is installed could not be told (no release tag on the installed commit). "
                "Give it with --tag, for example --tag v2026.11.21 (the tags are listed on GitHub).")
            return NOT_CHECKED
        if not TAG_RE.match(tag):
            out(f"  Not checked: '{tag[:60]}' is not a release tag (like v2026.11.21).")
            return NOT_CHECKED
        try:
            if signers:
                with open(signers, encoding="utf-8") as fh:
                    keys = keys_from_lines(fh)
            else:
                out(f"  reading the maintainer's published signing keys from {keys_url} ...")
                keys = github_keys(keys_url)
            listed = signed_list(tag, part, repo, keys, want_fp, out)
        except BadSignature as e:
            out(f"  SIGNATURE NOT GOOD: {e}. Nothing was compared: do not trust this release's list.")
            return BAD_SIGNATURE
        except NotChecked as e:
            out(f"  Not checked: {e}.")
            return NOT_CHECKED
        except (OSError, ValueError, subprocess.SubprocessError) as e:
            out(f"  Not checked: the signing keys or the release could not be read ({type(e).__name__}: {str(e)[:200]}).")
            return NOT_CHECKED
        source = f"the signed release {tag}"
        if local is not None and local != listed:
            out(f"  Note: the list on this computer ({SF.FINGERPRINTS_NAME}) is not the signed release's list.")
        elif local_err:
            out(f"  Note: the list on this computer cannot be trusted ({local_err}).")
    else:
        if local_err:
            out(f"  Not checked: {local_err}. Run it with --fetch to compare with the signed release instead.")
            return NOT_CHECKED
        if local is None:
            out(f"  Not checked: there is no {SF.FINGERPRINTS_NAME} here (installed before r91). "
                "Run it with --fetch --tag <release> to compare with a signed release that has one.")
            return NOT_CHECKED
        listed, source = local, f"the list on this computer ({SF.FINGERPRINTS_NAME})"
        out("  Compared with the list on this computer only: this shows that the files match that list, not that they "
            "are genuine (whoever can change the code here can change the list too). Run with --fetch to compare "
            "with the signed release on GitHub.")
    changed, added, missing, n = compare(folder, part, listed)
    out(f"  Compared with {source}: {n} code files here; {len(changed)} changed, {len(added)} not in the release, "
        f"{len(missing)} missing.")
    for rel, got, want in changed:
        out(f"  CHANGED             {rel}  (sha256 here {got}, the release {want})")
    for rel in added:
        out(f"  NOT IN THE RELEASE  {rel}  (sha256 {SF.sha256_of(os.path.join(folder, *rel.split('/')))})")
    for rel in missing:
        out(f"  MISSING             {rel}")
    if not (changed or added or missing):
        out("  Result: every code file is exactly as the release shipped it.")
        return OK
    out("  Result: differences found. A file you did not put there: move it out of the code folders (keep a copy for "
        "an investigation). A shipped file that changed or is missing: put the release's copy back from the Looking "
        "Glass folder with  git checkout <tag> -- <part>/<path>  then restart Looking Glass.")
    return DIFFERENT


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    ap.add_argument("--folder", default=here, help="the platform's or the database pipeline's folder (default: %(default)s)")
    ap.add_argument("--part", choices=sorted(SF.CODE), help="platform or database (default: worked out from the folder)")
    ap.add_argument("--fetch", action="store_true", help="compare with the signed release on GitHub (connects to GitHub)")
    ap.add_argument("--tag", default="", help="the release to compare with (with --fetch); default: the installed commit's tag")
    ap.add_argument("--quarantine", metavar="PATH", default="",
                    help="move this code file (relative to --folder) to backups/quarantine-<time>/, never deleting it")
    ap.add_argument("--repo", default=REPO, help=argparse.SUPPRESS)
    ap.add_argument("--allowed-signers", default=None, help=argparse.SUPPRESS)
    ap.add_argument("--key-fingerprint", default=KEY_FINGERPRINT, help=argparse.SUPPRESS)
    ap.add_argument("--keys-url", default=KEYS_URL, help=argparse.SUPPRESS)
    a = ap.parse_args(argv)
    if not os.path.isdir(a.folder) or os.path.islink(a.folder.rstrip("/")):
        print(f"{a.folder} is not a folder; nothing checked.")
        return NOT_CHECKED
    part = a.part or ("database" if os.path.isfile(os.path.join(a.folder, "shadowserver_pipeline.py")) else "platform")
    if a.quarantine:
        return quarantine(a.folder, part, a.quarantine)
    return run(a.folder, part, fetch=a.fetch, tag=a.tag, repo=a.repo, signers=a.allowed_signers,
               want_fp=a.key_fingerprint, keys_url=a.keys_url)


if __name__ == "__main__":
    sys.exit(main())
