#!/usr/bin/env bash
# Run the Shadowserver pipeline. ./run.sh --help for options, ./run.sh --man for the manual.
set -euo pipefail
cd "$(dirname "$(readlink -f "$0")")"

show_help() {
  cat <<'EOF'
Usage: shadowserver run [OPTIONS]      (or ./run.sh [OPTIONS] in the project folder)

Pull Shadowserver report e-mails, unzip and sort them by service, and load
them into MongoDB (database "shadowserver"). With no options it does all of it.

Stages:
  --stage all            e-mail + unzip/sort + load into MongoDB (default)
  --stage email          only pull e-mails/links, unzip and sort into sorting_backup/
  --stage load           only load sorting_backup/ into MongoDB (no e-mail)

E-mail:
  --days N               pull e-mails received in the last N days
                         (default: EMAIL_DAYS in .env, 1 = since yesterday)

Performance:
  --workers N            parallel loader processes (default: WORKERS in .env, 6)
                         each uses ~100-200 MB RAM

Output:
  (default)              one line per e-mail, attachment, link, zip, sorted file
                         and loaded file, plus progress lines
  -q, --quiet            summary lines only (used by the daily cron job)
  -v, --verbose          also show already-saved attachments and debug info

Other:
  --check                verify setup (MongoDB, indexes, data structure, IMAP) and exit
  --env-file PATH        use another config file instead of ./.env
  -h, --help             show this help
  --man                  open the full manual (also: man shadowserver)

Examples:
  shadowserver run                          daily run
  shadowserver run --days 8                 catch up on the last 8 days
  shadowserver run --stage load             (re)load files already on disk
  shadowserver run --stage email --days 3   only download and sort, no database
  shadowserver run --quiet                  summary only

Daily automatic run:
  shadowserver schedule 06:30       run every day at 06:30 (quiet mode, cron)
  shadowserver schedule             show the schedule
  shadowserver schedule off         remove it
  (only fires while WSL is running - see: shadowserver schedule --help)

Logs:     logs/pipeline-YYYY-MM-DD.log (appended) - shadowserver logs [-f]
Related:  shadowserver check | status | schedule | deploy --help | help | man
Only one run at a time: a second run exits while another is in progress.
EOF
}

for arg in "$@"; do
  case "$arg" in
    -h|--help) show_help; exit 0 ;;
    --man)
      if command -v man >/dev/null; then exec man -l docs/shadowserver.1; fi
      echo "'man' is not installed (sudo apt-get install man-db). Showing --help instead:"; show_help; exit 0 ;;
  esac
done

mkdir -p logs
exec 9>.pipeline.lock
flock -n 9 || { echo "Another pipeline run is in progress - exiting."; exit 1; }
.venv/bin/python -u shadowserver_pipeline.py "$@" 2>&1 | tee -a "logs/pipeline-$(date +%F).log"
