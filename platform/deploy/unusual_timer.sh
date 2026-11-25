#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
# Unusual activity's worker (unusual_worker.py) as its own sandboxed service, started every hour by a timer.
# It counts the report days (counts only, no addresses) for the Unusual activity page and the Executive card.
#
#   deploy/unusual_timer.sh install    write the two unit files for this folder and user, start the timer (sudo)
#   deploy/unusual_timer.sh status     whether the timer is installed and when it runs next
#   deploy/unusual_timer.sh remove     stop and remove the timer and its service (sudo); the counts stay in data/unusual
#   deploy/unusual_timer.sh run        count now, as the timer would (the first run counts the last weeks: it can take a while)
set -euo pipefail
project="$(cd "$(dirname "$(readlink -f "$0")")/.." && pwd)"
name="$(sed -n 's/^LG_SERVICE=//p' "$project/.env" 2>/dev/null | tail -1)"; name="${name:-looking-glass}-unusual"
unit_dir=/etc/systemd/system
case "${1:-}" in
  install)
    user="$(id -un)"
    for x in service timer; do
      sed -e "s|@USER@|$user|g" -e "s|@PROJECT@|$project|g" -e '/^# SPDX-/d' "$project/deploy/looking-glass-unusual.$x.template" \
        > "$project/deploy/$name.$x"
      chmod 644 "$project/deploy/$name.$x"
    done
    sudo install -m 644 "$project/deploy/$name.service" "$unit_dir/$name.service"
    sudo install -m 644 "$project/deploy/$name.timer" "$unit_dir/$name.timer"
    sudo systemctl daemon-reload
    sudo systemctl enable --now "$name.timer"
    echo "Installed: $name.timer runs $name.service every hour. Status: deploy/unusual_timer.sh status"
    ;;
  status)
    if [ -f "$unit_dir/$name.timer" ]; then
      systemctl list-timers "$name.timer" --no-pager 2>/dev/null | head -3 || true
      systemctl status "$name.service" --no-pager -n 5 2>/dev/null | tail -6 || true
    else
      echo "Not installed: deploy/unusual_timer.sh install"
    fi
    ;;
  remove)
    sudo systemctl disable --now "$name.timer" 2>/dev/null || true
    sudo rm -f "$unit_dir/$name.timer" "$unit_dir/$name.service"
    sudo systemctl daemon-reload
    echo "Removed. The counts in data/unusual stay; delete that folder to remove them."
    ;;
  run)
    cd "$project" && .venv/bin/python unusual_worker.py
    ;;
  *) sed -n '4,10p' "$0" | sed 's/^# \{0,1\}//'; exit 1 ;;
esac
