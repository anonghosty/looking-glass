#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
# lock_requirements.sh: the ONLY way Looking Glass's libraries change. It turns each human-edited requirements.txt (the
# caps) into its requirements.lock: every library, its dependencies included, at one exact version with the sha256 of
# every file published for it. Every installation and update installs from the locks with --require-hashes
# (deploy/safe_libraries.py), so a library changes only when someone runs this, on purpose, and commits the result.
#
#   tools/lock_requirements.sh              lock what changed in a requirements.txt; versions already locked stay
#   tools/lock_requirements.sh --upgrade    take the newest version of every library inside its cap
#   tools/lock_requirements.sh --tools      lock the lock tool itself again (tools/lock_tools.in -> tools/lock_tools.lock)
#
# The locks it writes: the platform's requirements.lock, the database pipeline's requirements.lock and the docs site's
# docs/requirements.lock. Then it checks each lock against its caps and that every library's dependencies are in it for
# Python 3.12, 3.13 and 3.14 on x86_64 and aarch64. It needs the internet (PyPI). After it: the full checklist
# (tests/run_all_checks.sh), pip-audit on the locks, and tools/build_wheelhouse.sh for the release's library bundle
# (docs/OPERATIONS.md, "Updating the libraries on purpose").
set -euo pipefail
PF="$(cd "$(dirname "$(readlink -f "$0")")/.." && pwd)"
TOP="$(dirname "$PF")"
if [ -f "$TOP/install.sh" ] && [ -d "$TOP/database" ]; then
  DB="$TOP/database"; DOCS="$TOP/docs"                                  # a release (the GitHub repository)
else
  DB="${LG_PIPELINE_DIR:-$TOP/shadowserver}"; DOCS="$PF/tools/release_root/docs"   # the maintainer's folders
fi
UPGRADE=(); TOOLS=0
while [ $# -gt 0 ]; do
  case "$1" in
    --upgrade) UPGRADE=(--upgrade); shift ;;
    --tools) TOOLS=1; shift ;;
    -h|--help) sed -n '4,19p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option $1 (tools/lock_requirements.sh --help)"; exit 1 ;;
  esac
done
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
python3 -m venv "$T/tools"
# the lock tool itself comes from its own lock, checked like everything else
"$T/tools/bin/python" -m pip install -q --disable-pip-version-check --require-hashes -r "$PF/tools/lock_tools.lock"
export CUSTOM_COMPILE_COMMAND="tools/lock_requirements.sh"
compile() {  # FOLDER INPUT OUTPUT
  ( cd "$1" && "$T/tools/bin/pip-compile" --quiet --generate-hashes --allow-unsafe --strip-extras --no-emit-index-url \
      --no-emit-trusted-host "${UPGRADE[@]}" --output-file "$3" "$2" )
  echo "locked: $1/$3 ($(grep -cE '^[A-Za-z0-9][A-Za-z0-9._-]*==' "$1/$3") libraries, $(grep -c -- '--hash=sha256:' "$1/$3") file hashes)"
}
if [ "$TOOLS" = 1 ]; then compile "$PF/tools" lock_tools.in lock_tools.lock; exit 0; fi
problems=0
for d in "$PF" "$DB" "$DOCS"; do
  [ -f "$d/requirements.txt" ] || { echo "no requirements.txt in $d"; problems=1; continue; }
  compile "$d" requirements.txt requirements.lock
  python3 "$PF/deploy/safe_libraries.py" check-lock --lock "$d/requirements.lock" --requirements "$d/requirements.txt" || problems=1
  # every dependency of every library is in the lock, on each supported Python and processor (a dependency some Python
  # versions need and others not would otherwise be missing there)
  for py in 3.12 3.13 3.14; do for m in x86_64 aarch64; do
    if ! "$T/tools/bin/python" -m pip install -q --disable-pip-version-check --dry-run --ignore-installed --target "$T/dry" \
         --require-hashes --only-binary=:all: --python-version "$py" --implementation cp \
         --platform "manylinux_2_28_$m" --platform "manylinux2014_$m" --platform "manylinux_2_17_$m" \
         -r "$d/requirements.lock" > "$T/dry.log" 2>&1; then
      echo "NOT COMPLETE for Python $py on $m: $d/requirements.lock"; tail -3 "$T/dry.log" | sed 's/^/    /'; problems=1
    fi
  done; done
done
[ "$problems" = 0 ] || { echo "Some locks need attention (above)."; exit 1; }
echo "All locks fit their caps and are complete for Python 3.12-3.14 on x86_64 and aarch64."
echo "Next: tests/run_all_checks.sh, pip-audit on the locks, tools/build_wheelhouse.sh (docs/OPERATIONS.md)."
