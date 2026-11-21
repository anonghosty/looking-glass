#!/usr/bin/env bash
# Update the Python libraries after `git pull`, from the locks only (deploy/safe_libraries.py): the platform's .venv
# and, when the database pipeline is beside it (../database), the pipeline's .venv. Each is built anew beside the
# running one and switched to only when every file matched its requirements.lock and installed; the running service
# keeps its libraries until it is reloaded. A lock that did not change is left alone. Then code files the release no
# longer ships are moved aside to backups/stale-<time>/ (LG_KEEP_STALE=1 keeps them).
#
#   deploy/update_libraries.sh            then: deploy/reload.sh (the platform); the pipeline uses its new libraries on
#                                         its next run
#   deploy/update_libraries.sh --force    build both again even when their lock did not change
set -euo pipefail
cd "$(dirname "$(readlink -f "$0")")/.."
project="$(pwd)"
force=()
case "${1:-}" in --force) force=(--force) ;; '') ;; -h|--help) sed -n '2,10p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
  *) echo "unknown option $1 (deploy/update_libraries.sh --help)"; exit 1 ;; esac
python3 deploy/safe_libraries.py check-machine
flagged=0
update() {  # FOLDER PART IMPORTS
  local rc=0
  python3 "$project/deploy/safe_libraries.py" install --lock "$1/requirements.lock" --venv "$1/.venv" --part "$2" \
    --report-dir "$1" --import "$3" "${force[@]}" || rc=$?
  if [ "$rc" = 10 ]; then flagged=1
  elif [ "$rc" != 0 ]; then echo "Stopped: the $2 libraries were not changed (see above)."; exit "$rc"; fi
}
update "$project" platform flask,pymongo,dotenv,gunicorn,reportlab
db="$(dirname "$project")/database"
if [ -f "$db/requirements.lock" ] && [ -f "$db/shadowserver_pipeline.py" ]; then
  update "$db" database requests,pymongo,cryptography,dns
fi
# code files the new release no longer ships: moved aside to backups/stale-<time>/ in each folder, never deleted
# (deploy/stale_files.py; LG_KEEP_STALE=1 lists and keeps them). A list it cannot trust moves nothing and does not
# stop the update
stale() {  # FOLDER PART
  python3 "$project/deploy/stale_files.py" --folder "$1" --part "$2" \
    || echo "WARNING: old code files in $1 were not checked (see above); the libraries are updated."
}
stale "$project" platform
if [ -f "$db/requirements.lock" ] && [ -f "$db/shadowserver_pipeline.py" ]; then
  stale "$db" database
fi
.venv/bin/python tests/check_libraries.py
if [ "$flagged" = 1 ]; then
  echo "WARNING: a library file from one source did not match its lock and was refused; matching copies were installed."
  echo "         See suspected-packages.txt and report it (docs/INSTALLATION.md, 'When a library file does not match')."
fi
echo "Done. Reload the platform to use the new libraries: deploy/reload.sh"
