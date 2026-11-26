#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
# Settings -> Update's helper: a service that runs deploy/update_run.py as this installation's user when Settings asks
# (a path unit watches data/update/request.json). Installed once; after that, updates are a button in Settings.
#
#   deploy/update_helper.sh install    write the two unit files for this folder and user, start watching (sudo)
#   deploy/update_helper.sh status     whether it is installed, and the last run
#   deploy/update_helper.sh remove     stop and remove it (sudo); updates are then done by hand (docs/INSTALLATION.md)
#   deploy/update_helper.sh check      look for a newer release now, as Settings' Check button does
set -euo pipefail
project="$(cd "$(dirname "$(readlink -f "$0")")/.." && pwd)"
name="$(sed -n 's/^LG_SERVICE=//p' "$project/.env" 2>/dev/null | tail -1 | tr -d '"'"'"' ')"; name="${name:-looking-glass}-update"
unit_dir=/etc/systemd/system
root="$project"
if [ -f "$(dirname "$project")/database/shadowserver_pipeline.py" ]; then root="$(dirname "$project")"; fi
case "${1:-}" in
  install)
    # the installation's user: the folder's owner, also when this runs with sudo (the run is never root)
    user="$(stat -c %U "$project")"
    [ "$user" != root ] || { echo "The platform folder belongs to root: install Looking Glass as its own user first."; exit 1; }
    for x in service path; do
      sed -e "s|@USER@|$user|g" -e "s|@PROJECT@|$project|g" -e "s|@ROOT@|$root|g" -e "s|@NAME@|$name|g" -e '/^# SPDX-/d' \
        "$project/deploy/looking-glass-update.$x.template" > "$project/deploy/$name.$x"
      chmod 644 "$project/deploy/$name.$x"
    done
    mkdir -p "$project/data/update" && chmod 700 "$project/data/update" && chown "$user:" "$project/data/update" "$project/deploy/$name.service" "$project/deploy/$name.path" 2>/dev/null || true
    sudo install -m 644 "$project/deploy/$name.service" "$unit_dir/$name.service"
    sudo install -m 644 "$project/deploy/$name.path" "$unit_dir/$name.path"
    sudo systemctl daemon-reload
    sudo systemctl enable --now "$name.path"
    echo "Installed: $name.path starts $name.service (as $user) when Settings -> Update asks. Status: deploy/update_helper.sh status"
    ;;
  status)
    if [ -f "$unit_dir/$name.path" ]; then
      systemctl status "$name.path" --no-pager -n 0 2>/dev/null | head -3 || true
      systemctl status "$name.service" --no-pager -n 8 2>/dev/null | tail -9 || true
    else
      echo "Not installed: deploy/update_helper.sh install"
    fi
    ;;
  remove)
    sudo systemctl disable --now "$name.path" 2>/dev/null || true
    sudo rm -f "$unit_dir/$name.path" "$unit_dir/$name.service"
    sudo systemctl daemon-reload
    echo "Removed. Updates are done by hand now (docs/INSTALLATION.md, Updating)."
    ;;
  check)
    python3 "$project/deploy/update_run.py" --check
    ;;
  *) sed -n '4,10p' "$0" | sed 's/^# \{0,1\}//'; exit 1 ;;
esac
