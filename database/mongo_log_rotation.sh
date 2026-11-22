#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
# mongo_log_rotation.sh - keep MongoDB's own log from growing without end (2026-11-17: one installation's
# /var/log/mongodb/mongod.log had reached 412 MB; nothing rotated it).
#
# Writes /etc/logrotate.d/looking-glass-mongod: the log is rotated every day, or sooner once it passes 100 MB at the
# daily run, 14 old logs kept, compressed. "copytruncate" lets MongoDB keep writing to the same file (it appends,
# logAppend: true), so MongoDB is neither changed nor restarted.
#
# deploy.sh runs it when it installs MongoDB. An installation made before 2026-11-17 runs it once by hand:
#   sudo database/mongo_log_rotation.sh --now      (--now: rotate the current log straight away too)
# Safe to run again: it changes nothing when the rule is already there. If another rule already rotates the same log
# (a MongoDB package's own, say), it leaves that one alone and writes none: two rules for one log make logrotate fail.
set -euo pipefail

RULE=/etc/logrotate.d/looking-glass-mongod
CONF=${MONGOD_CONF:-/etc/mongod.conf}
NOW=0
for a in "$@"; do
  case "$a" in
    --now) NOW=1 ;;
    -h|--help) sed -n '4,15p' "$0"; exit 0 ;;
    *) echo "unknown option: $a (see --help)" >&2; exit 2 ;;
  esac
done
[ "$(id -u)" = 0 ] || { echo "Run it with sudo: sudo $0 $*" >&2; exit 1; }
command -v logrotate >/dev/null || { apt-get install -y logrotate >/dev/null || { echo "logrotate is not installed: sudo apt-get install logrotate" >&2; exit 1; }; }

# the log MongoDB writes: systemLog.path in its configuration, else the packages' default
LOG=$(awk '/^systemLog:/{s=1;next} /^[^[:space:]#]/{s=0} s && $1=="path:"{print $2; exit}' "$CONF" 2>/dev/null || true)
LOG=${LOG:-/var/log/mongodb/mongod.log}
if grep -q "^[[:space:]]*destination:[[:space:]]*syslog" "$CONF" 2>/dev/null; then
  echo "MongoDB logs to syslog here ($CONF): the system already rotates that. Nothing to do."; exit 0
fi
OWNER=$(stat -c '%U %G' "$(dirname "$LOG")" 2>/dev/null || echo "mongodb mongodb")

other=$(grep -lsF "$LOG" /etc/logrotate.d/* 2>/dev/null | grep -vx "$RULE" || true)
if [ -n "$other" ]; then
  echo "$LOG is already rotated by: $other. Left as it is."
else
  want="# Written by Looking Glass (database/mongo_log_rotation.sh). MongoDB's own log.
$LOG {
    daily
    maxsize 100M
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
    su $OWNER
}"
  if [ "$(cat "$RULE" 2>/dev/null)" != "$want" ]; then
    printf '%s\n' "$want" > "$RULE.new" && chmod 644 "$RULE.new"
    if logrotate -d "$RULE.new" >/dev/null 2>&1; then mv "$RULE.new" "$RULE"; echo "Written: $RULE"
    else rm -f "$RULE.new"; echo "logrotate refused the rule (logrotate -d); nothing written." >&2; exit 1; fi
  else
    echo "Already in place: $RULE"
  fi
fi
if [ $NOW = 1 ] && [ -f "$RULE" ] && [ -s "$LOG" ]; then
  before=$(du -h "$LOG" | cut -f1)
  logrotate -f "$RULE" && echo "Rotated now: $LOG was $before, now $(du -h "$LOG" | cut -f1) (the old part is kept beside it, compressed at the next run)."
fi
