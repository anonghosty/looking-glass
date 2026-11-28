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
# (quotes and spaces taken off, as deploy/reload.sh and update_helper.sh read it: LG_SERVICE='lg' is the service lg)
name="$(sed -n 's/^LG_SERVICE=//p' "$project/.env" 2>/dev/null | tail -1 | tr -d '"'"'"' \r')"; name="${name:-looking-glass}-unusual"
unit_dir=/etc/systemd/system
case "${1:-}" in
  install)
    # the installation's user: the folder's owner, also when this runs with sudo (never root: 2026-11-25)
    user="$(stat -c %U "$project")"
    [ "$user" != root ] || { echo "The platform folder belongs to root: install Looking Glass as its own user first."; exit 1; }
    for x in service timer; do
      sed -e "s|@USER@|$user|g" -e "s|@PROJECT@|$project|g" -e '/^# SPDX-/d' "$project/deploy/looking-glass-unusual.$x.template" \
        > "$project/deploy/$name.$x"
      chmod 644 "$project/deploy/$name.$x"
    done
    # run with sudo, the two files were written as root into the installation's folder: they belong to its user, so its
    # updates can replace them (audit 2026-11-27; as update_helper.sh does)
    chown "$user:" "$project/deploy/$name.service" "$project/deploy/$name.timer" 2>/dev/null || true
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
