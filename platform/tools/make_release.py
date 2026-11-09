#!/bin/sh
# runs itself with the project's own Python (.venv), from wherever it is called
''''exec "$(dirname -- "$0")/../.venv/bin/python" "$0" "$@" # '''
"""Build the clean, shareable Looking Glass folder (for GitHub): the platform and the database pipeline side by side,
without secrets, accounts, report files, logs or caches. The source folders are only read.

    tools/make_release.py [--database ~/shadowserver] [--out ~/looking-glass-release]

Result:  <out>/README.md, <out>/.gitignore, <out>/platform/..., <out>/database/...
Then every released file is scanned for the values in both live .env files and for keys and tokens; any hit stops
the release (the hit is named by setting and file, never printed).
"""
import argparse
import fnmatch
import os
import re
import shutil
import subprocess
import sys

PLATFORM = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# ---- platform: everything except what .gitignore keeps out
PLATFORM_SKIP_DIRS = {".venv", "__pycache__", ".git", "release_root"}
PLATFORM_SKIP = [".env", ".env.*", "*.pyc", "*.log", "geocache.json", "deploy/*.service", "tools/discovery.json",
                 "tools/services_fields.json"]
PLATFORM_KEEP_ALWAYS = {".env.example"}
PLATFORM_DATA_KEEP = {"infections.json", "service_reports.json", "issues.json"}     # curated reference data; the rest is run-time

# ---- database pipeline: only these (the folder also holds hundreds of MB of downloaded reports)
DATABASE_FILES = ["README.md", ".env.example", ".gitignore", "requirements.txt", "shadowserver_pipeline.py",
                  "mail_sources.py", "run.sh", "check.sh", "deploy.sh", "bin/shadowserver",
                  "bin/shadowserver-completion.bash", "docs/shadowserver.1", "docs/MAIL_SETUP.md",
                  "tests/test_equivalence.py", "tests/test_mail_sources.py", "tests/selftest_compare.py",
                  "mongo_added_json.py", "pull_emails_and_create_services.py"]

TRIVIAL = {"127.0.0.1", "localhost", "27017", "admin", "shadowserver", "inbox", "false", "true", "local", "private",
           "public", "outdated_dnssec_key"}
PATTERNS = {
    "Mapbox token": re.compile(r"\bpk\.eyJ[A-Za-z0-9._-]{20,}"),
    "private key": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "authenticator key or hash in JSON": re.compile(r'"(totp|hash|recovery)"\s*:\s*"[^"]{16,}'),
}
# figures allowed in the documentation (see the figure check in main): invented examples and fixed settings only
FIGURE_RX = re.compile(r"\b\d{1,3}(?:,\d{3})+\b|\b\d+ of \d+\b")
DOC_FIGURES_OK = {
    # invented examples in the docs
    "10,000", "7,500", "6,000", "1,700", "1,850", "1,200", "360,000", "750,000",
    # fixed settings and limits
    "2,000", "3,000", "3,000,000",
    # the pipeline's synthetic speed test, and the oversized request of the security test
    "123,000", "600,000",
}


def skipped(rel):
    name = os.path.basename(rel)
    if name in PLATFORM_KEEP_ALWAYS:
        return False
    if rel.startswith("data/"):
        return rel.count("/") != 1 or name not in PLATFORM_DATA_KEEP
    return any(fnmatch.fnmatch(rel, p) or fnmatch.fnmatch(name, p) for p in PLATFORM_SKIP)


def env_values(path):
    out = {}
    if os.path.isfile(path):
        for line in open(path, encoding="utf-8", errors="replace"):
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                v = v.strip().strip("'\"")
                if len(v) >= 6 and v.lower() not in TRIVIAL and not v.isdigit():
                    out[f"{os.path.basename(os.path.dirname(path))}/.env {k.strip()}"] = v
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--database", default=os.path.expanduser("~/shadowserver"))
    ap.add_argument("--out", default=os.path.expanduser("~/looking-glass-release"))
    a = ap.parse_args()
    out = os.path.abspath(a.out)
    if out.startswith(PLATFORM + os.sep) or out.startswith(os.path.abspath(a.database) + os.sep) or out in (PLATFORM, os.path.abspath(a.database)):
        sys.exit("--out must be outside both source folders")
    if os.path.exists(out):
        if not os.path.isfile(os.path.join(out, ".looking-glass-release")):
            sys.exit(f"{out} exists and is not a release folder made by this script: choose another --out")
        shutil.rmtree(out)
    os.makedirs(out)
    open(os.path.join(out, ".looking-glass-release"), "w").close()   # marker: safe to rebuild

    copied = []
    root_src = os.path.join(PLATFORM, "tools", "release_root")
    for f in os.listdir(root_src):
        src = os.path.join(root_src, f)
        if os.path.isdir(src):            # docs/ (glossary, comparison) and docs/media/ (screenshots, film)
            shutil.copytree(src, os.path.join(out, f))
            for top, _, files in os.walk(os.path.join(out, f)):
                copied += [os.path.join(top, x) for x in files]
        else:
            shutil.copy2(src, os.path.join(out, f))
            copied.append(os.path.join(out, f))

    for top, dirs, files in os.walk(PLATFORM):
        dirs[:] = sorted(d for d in dirs if d not in PLATFORM_SKIP_DIRS and not (top == os.path.join(PLATFORM, "data") and d == "tls"))
        for f in sorted(files):
            src = os.path.join(top, f)
            rel = os.path.relpath(src, PLATFORM)
            if skipped(rel) or os.path.islink(src):
                continue
            dst = os.path.join(out, "platform", rel)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copy2(src, dst)
            copied.append(dst)

    for rel in DATABASE_FILES:
        src = os.path.join(a.database, rel)
        if not os.path.isfile(src):
            sys.exit(f"database file missing: {src}")
        dst = os.path.join(out, "database", rel)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        shutil.copy2(src, dst)
        copied.append(dst)
    # scripts stay executable whatever the source file's mode (an editor may have rewritten it without the x bit)
    for p in copied:
        try:
            with open(p, "rb") as fh:
                if fh.read(2) == b"#!":
                    os.chmod(p, 0o755)
        except OSError:
            pass

    # ---- installer sanity: the installer must parse, and every required package needs its description
    #      (13 packages but 12 descriptions made every fresh install stop with "REQ_WHY: unbound variable")
    inst = os.path.join(out, "install.sh")
    if os.path.isfile(inst):
        r = subprocess.run(["bash", "-n", inst], capture_output=True, text=True)
        if r.returncode:
            sys.exit(f"install.sh does not parse:\n{r.stderr}")
        r = subprocess.run(["bash", "-c", 'eval "$(sed -n "/^REQ_PKGS=(/,/)$/p" "$1")"; '
                            'echo "${#REQ_PKGS[@]} ${#REQ_WHY[@]}"', "_", inst], capture_output=True, text=True)
        counts = r.stdout.split()
        if len(counts) != 2 or counts[0] != counts[1] or counts[0] == "0":
            sys.exit(f"install.sh: REQ_PKGS and REQ_WHY differ in length ({' / '.join(counts) or 'not found'})")

    # ---- secret scan
    secrets = {**env_values(os.path.join(PLATFORM, ".env")), **env_values(os.path.join(a.database, ".env"))}
    key = os.path.join(PLATFORM, "data", "automation.key")
    if os.path.isfile(key):
        secrets["platform automation key"] = open(key).read().strip()
    # operational details that must never be published (this installation's networks, operators, machine, Wi-Fi,
    # firewall rule names, user names...): one term per line in a private file that is never part of the release
    terms_file = os.environ.get("LG_PRIVATE_TERMS", os.path.expanduser("~/.config/looking-glass/private-terms.txt"))
    terms = []
    if os.path.isfile(terms_file):
        terms = [t.strip() for t in open(terms_file, encoding="utf-8") if t.strip() and not t.lstrip().startswith("#")]
    hits = []
    for p in copied:
        try:
            text = open(p, encoding="utf-8").read()
        except UnicodeDecodeError:
            continue
        rel = os.path.relpath(p, out)
        for label, v in secrets.items():
            if v and v in text:
                hits.append(f"{label} found in {rel}")
        low = text.lower()
        for t in terms:
            if t.lower() in low:
                hits.append(f"private term '{t}' found in {rel}")
        for label, rx in PATTERNS.items():
            if rx.search(text):
                hits.append(f"{label} found in {rel}")
    # figures in the documentation: every number with thousands separators and every "N of M" must be one of the
    # invented examples below, so a real figure copied from a live installation can never be published by accident
    for p in copied:
        if not p.endswith((".md", ".1")):
            continue
        rel = os.path.relpath(p, out)
        for fig in FIGURE_RX.findall(open(p, encoding="utf-8").read()):
            if fig not in DOC_FIGURES_OK:
                hits.append(f"figure '{fig}' in {rel} is not a listed invented example (DOC_FIGURES_OK in tools/make_release.py)")
    # no run logs or stray text files in a release: the only text files are the two dependency lists
    for p in copied:
        rel = os.path.relpath(p, out)
        name = os.path.basename(p).lower()
        if (name.endswith((".log", ".output", ".tmp")) or "/logs/" in f"/{rel}/"
                or (name.endswith(".txt") and name != "requirements.txt")):
            hits.append(f"log or stray text file: {rel}")
    os.remove(os.path.join(out, ".looking-glass-release")) if hits else None
    size = sum(os.path.getsize(p) for p in copied)
    print(f"{len(copied)} files, {size / 1e6:.1f} MB -> {out}")
    print(f"secret scan: {len(secrets)} live values, {len(PATTERNS)} patterns and {len(terms)} private terms"
          f"{'' if terms else ' (no ' + terms_file + ')'} checked in every file")
    if hits:
        print("RELEASE NOT CLEAN:\n  " + "\n  ".join(sorted(set(hits))))
        sys.exit(1)
    print("clean: no secret, key or token found")


if __name__ == "__main__":
    main()
