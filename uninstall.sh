#!/usr/bin/env bash
# Looking Glass uninstaller: undoes what ./install.sh set up on this computer.
#
#   ./uninstall.sh                     stop and remove the services, the schedule and the global command;
#                                      the reports database and this folder are KEPT (a later ./install.sh picks them up)
#   ./uninstall.sh --remove-database   also delete the reports database and the Looking Glass database accounts
#   ./uninstall.sh --remove-mongodb    also remove MongoDB itself, with all its data (only a MongoDB that
#                                      Looking Glass installed; never one that was there before)
#   ./uninstall.sh --remove-files      also delete this folder (settings, sign-in accounts, findings, audit log)
#   ./uninstall.sh --all               all of the above
#   ./uninstall.sh --dry-run           show what would be done, change nothing
#   ./uninstall.sh --yes               do not ask (the typed confirmations for deleting data are still needed,
#                                      unless --i-understand-data-loss is given too)
#
# Run it as the ordinary user who installed Looking Glass (not root). It asks for your sudo password once.
# Deleting data cannot be undone: make a copy first (platform/tools, mongodump) if you may need it again.
set -Eeuo pipefail

ROOT="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
DB_DIR="$ROOT/database"
PF_DIR="$ROOT/platform"
# where the installer puts things (overridable only so the test can point at a scratch folder)
SYSTEMD_DIR="${LG_UNINSTALL_SYSTEMD_DIR:-/etc/systemd/system}"
ETC_LG="${LG_UNINSTALL_ETC_DIR:-/etc/looking-glass}"
BIN_LINK="${LG_UNINSTALL_BIN:-/usr/local/bin/shadowserver}"
MAN_PAGE="${LG_UNINSTALL_MAN:-/usr/local/share/man/man1/shadowserver.1}"
COMPLETION="${LG_UNINSTALL_COMPLETION:-/etc/bash_completion.d/shadowserver}"
MONGOD_CONF="${LG_UNINSTALL_MONGOD_CONF:-/etc/mongod.conf}"
CRON_MARK="# shadowserver-pipeline"

RM_DB=0; RM_MONGO=0; RM_FILES=0; DRY=0; YES=0; FORCE_DATA=0
while [ $# -gt 0 ]; do
  case "$1" in
    --remove-database) RM_DB=1 ;;
    --remove-mongodb) RM_MONGO=1 ;;
    --remove-files) RM_FILES=1 ;;
    --all) RM_DB=1; RM_MONGO=1; RM_FILES=1 ;;
    --dry-run|-n) DRY=1 ;;
    --yes|-y) YES=1 ;;
    --i-understand-data-loss) FORCE_DATA=1 ;;
    -h|--help) sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option $1 (./uninstall.sh --help)"; exit 1 ;;
  esac
  shift
done

if [ -t 1 ]; then B=$'\e[1m'; R=$'\e[0m'; RED=$'\e[31m'; GRN=$'\e[32m'; YEL=$'\e[33m'; else B=; R=; RED=; GRN=; YEL=; fi
say()  { printf '%s\n' "$*"; }
done_() { if [ "${DRY:-0}" = 1 ]; then printf '  (would be) %s\n' "$*"; else printf '  %s✔%s %s\n' "$GRN" "$R" "$*"; fi; }
skip() { printf '  %s-%s %s\n' "$YEL" "$R" "$*"; }
die()  { printf '%sStopped:%s %s\n' "$RED$B" "$R" "$*" >&2; exit 1; }
# run a command, or only show it with --dry-run
do_() { if [ $DRY = 1 ]; then printf '  would run: %s\n' "$*"; else "$@"; fi; }

[ "$(id -u)" != 0 ] || die "run ./uninstall.sh as the user who installed Looking Glass (not root, not with sudo)."
[ -d "$DB_DIR" ] || [ -d "$PF_DIR" ] || die "run it from the Looking Glass folder (database/ or platform/ next to it)."

env_get() {  # FILE KEY [DEFAULT]: the value as written (never executed)
  local v; v=$(grep -E "^[[:space:]]*$2[[:space:]]*=" "$1" 2>/dev/null | head -n1 | cut -d= -f2- || true)
  v="${v%$'\r'}"; v="${v#"${v%%[![:space:]]*}"}"; v="${v%"${v##*[![:space:]]}"}"
  if [[ ${#v} -ge 2 && ( ( $v == \'*\' ) || ( $v == \"*\" ) ) ]]; then v="${v:1:${#v}-2}"; fi
  printf '%s' "${v:-${3-}}"
}

# ------------------------------------------------------------------------------------------------ what is here
# platform services: unit files whose WorkingDirectory is this platform folder (whatever name was chosen)
UNITS=()
if [ -d "$SYSTEMD_DIR" ]; then
  # compared as real paths: a unit installed through a symlink or with a trailing slash is this folder's too (review
  # 2026-11-13: it was missed, and kept restarting against a deleted folder)
  PF_REAL=$(readlink -f "$PF_DIR" 2>/dev/null || printf '%s' "$PF_DIR")
  for f in "$SYSTEMD_DIR"/*.service; do
    [ -f "$f" ] || continue
    wd=$(sed -n 's/^WorkingDirectory=//p' "$f" 2>/dev/null | head -n1)
    [ -n "$wd" ] || continue
    [ "$(readlink -f "$wd" 2>/dev/null || printf '%s' "${wd%/}")" = "$PF_REAL" ] && UNITS+=("$(basename "$f")")
  done
fi
# the schedule: only this folder's cron line (another installation's line stays)
CRON_HERE=$(crontab -l 2>/dev/null | grep -F -- "$CRON_MARK" | grep -F -- "$DB_DIR/" || true)
# the global command: only when it runs this folder's pipeline
CMD_HERE=0
if [ -e "$BIN_LINK" ] || [ -L "$BIN_LINK" ]; then
  if [ "$(readlink -f "$BIN_LINK" 2>/dev/null)" = "$DB_DIR/bin/shadowserver" ] || grep -qF "\"$DB_DIR/bin/shadowserver\"" "$BIN_LINK" 2>/dev/null; then CMD_HERE=1; fi
fi
# MongoDB: installed by this folder's deploy.sh?
MONGO_OURS=0
grep -qF "Managed by $DB_DIR/deploy.sh" "$MONGOD_CONF" 2>/dev/null && MONGO_OURS=1
MONGO_OTHER=0
[ $MONGO_OURS = 0 ] && command -v mongod >/dev/null 2>&1 && MONGO_OTHER=1
ENVF="$DB_DIR/.env"; [ -f "$ENVF" ] || ENVF="$PF_DIR/.env"
MONGO_DB=$(env_get "$ENVF" MONGO_DB shadowserver)
MONGO_HOST=$(env_get "$ENVF" MONGO_HOST 127.0.0.1)
MONGO_PORT=$(env_get "$ENVF" MONGO_PORT 27017)
MONGO_LOCAL=$(env_get "$DB_DIR/.env" MONGO_LOCAL false); MONGO_LOCAL=${MONGO_LOCAL,,}
[[ $MONGO_DB =~ ^[A-Za-z0-9_-]{1,63}$ ]] || die "MONGO_DB in $ENVF is not a plain database name: refusing to go on."
# MongoDB's own databases are never "the reports database" (review 2026-11-13: MONGO_DB=admin would have dropped
# every MongoDB account with --remove-database)
[[ ${MONGO_DB,,} =~ ^(admin|local|config)$ ]] && die "MONGO_DB in $ENVF is '$MONGO_DB', one of MongoDB's own databases: refusing to go on."

# ------------------------------------------------------------------------------------------------ the plan
say ""
say "${B}Looking Glass uninstaller$([ $DRY = 1 ] && echo ' (dry run: nothing is changed)')${R}"
say "Folder: $ROOT"
say ""
say "${B}Will be removed${R}"
if [ ${#UNITS[@]} -gt 0 ]; then say "  • platform service(s): ${UNITS[*]} (stopped, disabled, unit file deleted)"; else say "  • platform service: none found for this folder"; fi
if [ -n "$CRON_HERE" ]; then say "  • the pipeline schedule (cron line of this folder)"; else say "  • pipeline schedule: none found for this folder"; fi
if [ $CMD_HERE = 1 ]; then say "  • the global 'shadowserver' command, its man page and tab completion"; else say "  • global 'shadowserver' command: not this folder's (left alone)"; fi
[ $RM_DB = 1 ] && say "  • ${RED}the reports database '$MONGO_DB' on $MONGO_HOST:$MONGO_PORT and the accounts lookingglass_pipeline, lookingglass_ro${R}"
[ $RM_DB = 1 ] && [ -d "$ETC_LG" ] && say "  • $ETC_LG (the MongoDB administrator account kept by the installer)"
if [ $RM_MONGO = 1 ]; then
  if [ $MONGO_OURS = 1 ]; then say "  • ${RED}MongoDB itself (packages, /etc/mongod.conf, /var/lib/mongodb: ALL its databases)${R}"
  elif [ $MONGO_OTHER = 1 ]; then say "  • MongoDB: NOT removed. It was not installed by Looking Glass (another program may use it)."; RM_MONGO=0
  else say "  • MongoDB: not installed on this computer"; RM_MONGO=0; fi
fi
[ $RM_FILES = 1 ] && say "  • ${RED}this folder: $ROOT (settings, sign-in accounts, findings, advisories, audit log, report files)${R}"
say ""
say "${B}Kept${R}"
[ $RM_DB = 0 ] && say "  • the reports database '$MONGO_DB' (add --remove-database to delete it)"
[ $RM_MONGO = 0 ] && [ $MONGO_OURS = 1 ] && say "  • MongoDB (add --remove-mongodb to remove it)"
[ $RM_FILES = 0 ] && say "  • this folder with its settings and data (add --remove-files to delete it)"
say "  • system packages (python3, cron, curl...): other programs may use them"
say "  • firewall rules you added for the platform's port: remove them yourself if you made any"
say ""

if [ $DRY = 0 ] && [ $YES = 0 ]; then
  [ -t 0 ] || die "no terminal to ask in: run with --yes (and see --help)."
  read -rp "Go ahead? [no] yes/no: " a; [[ ${a,,} == y* ]] || { say "Nothing was changed."; exit 0; }
fi
# deleting data: type it, unless explicitly waived
confirm_typed() {  # WORD WHAT
  [ $DRY = 1 ] && return 0
  [ $FORCE_DATA = 1 ] && return 0
  [ -t 0 ] || die "deleting $2 needs a typed confirmation (or --i-understand-data-loss)."
  read -rp "  This deletes $2 for good. Type ${B}$1${R} to confirm: " a
  [ "$a" = "$1" ] || die "not confirmed: $2 kept. Nothing after this point was changed."
}
[ $RM_DB = 1 ] && confirm_typed "$MONGO_DB" "the reports database '$MONGO_DB'"
[ $RM_MONGO = 1 ] && confirm_typed "remove-mongodb" "MongoDB and all its databases"
[ $RM_FILES = 1 ] && confirm_typed "$(basename "$ROOT")" "the folder $ROOT"

if [ $DRY = 0 ]; then
  sudo -n true 2>/dev/null || { say "Your sudo password is needed for the services and system files."; sudo -v || die "sudo is required."; }
fi

# ------------------------------------------------------------------------------------------------ 1. services
say "${B}1. Platform service${R}"
for u in "${UNITS[@]}"; do
  do_ sudo systemctl disable --now "$u" || true
  do_ sudo rm -f "$SYSTEMD_DIR/$u"
  done_ "$u stopped, disabled and removed"
done
[ ${#UNITS[@]} -gt 0 ] && { do_ sudo systemctl daemon-reload || true; } || skip "none for this folder"

# ------------------------------------------------------------------------------------------------ 2. schedule
say "${B}2. Pipeline schedule${R}"
if [ -n "$CRON_HERE" ]; then
  if [ $DRY = 1 ]; then say "  would remove the cron line: $CRON_HERE"
  else
    others=$(crontab -l 2>/dev/null | grep -vxF -- "$CRON_HERE" || true)
    if [ -z "$(printf '%s' "$others" | tr -d '[:space:]')" ]; then crontab -r 2>/dev/null || true
    else printf '%s\n' "$others" | crontab -; fi
  fi
  done_ "schedule removed (other cron jobs kept)"
else skip "none for this folder"; fi
# a pipeline run that is going on right now: let it finish rather than cut it off mid-load. A run holds the lock
# run.sh takes (.pipeline.lock): its command line names the script by a relative path, so matching the full path never
# found it (review 2026-11-13). Its processes are this folder's when their working folder is this folder.
pipeline_running() { [ -f "$DB_DIR/.pipeline.lock" ] && ! flock -n "$DB_DIR/.pipeline.lock" true 2>/dev/null; }
pipeline_pids() {
  local p
  for p in $(pgrep -f "shadowserver_pipeline.py" 2>/dev/null); do
    [ "$(readlink -f "/proc/$p/cwd" 2>/dev/null)" = "$(readlink -f "$DB_DIR")" ] && echo "$p"
  done
}
if [ $DRY = 0 ] && { pipeline_running || [ -n "$(pipeline_pids)" ]; }; then
  say "  a pipeline run is in progress: waiting up to 5 minutes for it to finish..."
  for _ in $(seq 1 60); do { pipeline_running || [ -n "$(pipeline_pids)" ]; } || break; sleep 5; done
  if pipeline_running || [ -n "$(pipeline_pids)" ]; then
    for p in $(pipeline_pids); do kill "$p" 2>/dev/null || true; done
    sleep 5
    # the run's wrapper (run.sh) holds the lock: while anything still holds it, nothing below is touched (review
    # 2026-11-13: the database and the folder could be deleted under a run that was still going)
    pipeline_running && die "a pipeline run still holds $DB_DIR/.pipeline.lock: the database and files were NOT touched. Stop it (or wait), then run this again."
    skip "it did not finish: stopped"
  fi
fi

# ------------------------------------------------------------------------------------------------ 3. command
say "${B}3. Global command${R}"
if [ $CMD_HERE = 1 ]; then
  do_ sudo rm -f "$BIN_LINK" "$MAN_PAGE" "$COMPLETION"
  [ $DRY = 1 ] || sudo mandb -q >/dev/null 2>&1 || true
  done_ "'shadowserver' command, man page and completion removed"
else skip "not this folder's"; fi

# ------------------------------------------------------------------------------------------------ 4. database
say "${B}4. Reports database${R}"
if [ $RM_DB = 1 ]; then
  PY=""; for p in "$DB_DIR/.venv/bin/python" "$PF_DIR/.venv/bin/python" "$ROOT/.installer-venv/bin/python"; do [ -x "$p" ] && { PY="$p"; break; }; done
  [ -n "$PY" ] || [ $DRY = 1 ] || die "no Python environment with pymongo here (database/.venv, platform/.venv): the database was NOT deleted."
  # the administrator account: where the installer keeps it (root only), else database/.env when it is not one of ours
  ADMIN_ENV=$(mktemp); chmod 600 "$ADMIN_ENV"; trap 'rm -f "$ADMIN_ENV"' EXIT
  if [ $DRY = 0 ] && sudo -n test -f "$ETC_LG/mongo-admin.env" 2>/dev/null; then sudo -n cat "$ETC_LG/mongo-admin.env" > "$ADMIN_ENV"
  elif [ -f "$DB_DIR/.env" ] && ! [[ $(env_get "$DB_DIR/.env" MONGO_USER) =~ ^(lookingglass_pipeline|lookingglass_ro)?$ ]]; then cp "$DB_DIR/.env" "$ADMIN_ENV"
  fi
  if [ $DRY = 1 ]; then say "  would delete the database '$MONGO_DB' and the accounts lookingglass_pipeline (admin) and lookingglass_ro ($MONGO_DB)"
  else
    [ -s "$ADMIN_ENV" ] || die "no MongoDB administrator account found ($ETC_LG/mongo-admin.env or database/.env): the database was NOT deleted."
    LGU_ENV="$ADMIN_ENV" LGU_DB="$MONGO_DB" LGU_HOST="$MONGO_HOST" LGU_PORT="$MONGO_PORT" "$PY" -I - <<'EOF' || die "deleting the database failed (see above); nothing else was removed after this point."
import os
from pymongo import MongoClient
from pymongo.errors import OperationFailure
env = {}
for line in open(os.environ["LGU_ENV"], encoding="utf-8"):
    line = line.strip()
    if line and not line.startswith("#") and "=" in line:
        k, v = line.split("=", 1)
        v = v.strip()
        if len(v) >= 2 and v[0] == v[-1] and v[0] in "'\"":
            v = v[1:-1]
        env[k.strip()] = v
db = os.environ["LGU_DB"]
c = MongoClient(host=env.get("MONGO_HOST") or os.environ["LGU_HOST"], port=int(env.get("MONGO_PORT") or os.environ["LGU_PORT"]),
                username=env.get("MONGO_USER") or None, password=env.get("MONGO_PASSWORD") or None,
                authSource=env.get("MONGO_AUTH_SOURCE") or "admin", serverSelectionTimeoutMS=8000)
c.admin.command("ping")
for where, user in (("admin", "lookingglass_pipeline"), (db, "lookingglass_ro"), ("admin", "lookingglass_ro")):
    try:
        c[where].command("dropUser", user)
        print(f"  account {user} removed")
    except OperationFailure as e:
        if e.code != 11:          # 11 = no such user
            raise
existed = db in c.list_database_names()
c.drop_database(db)
print(f"  database '{db}' {'deleted' if existed else 'was not there'}")
EOF
    do_ sudo rm -rf "$ETC_LG"
    done_ "reports database and Looking Glass accounts deleted; $ETC_LG removed"
  fi
else skip "kept ('$MONGO_DB')"; fi

# ------------------------------------------------------------------------------------------------ 5. MongoDB
say "${B}5. MongoDB${R}"
if [ $RM_MONGO = 1 ]; then
  do_ sudo systemctl disable --now mongod || true
  do_ sudo env DEBIAN_FRONTEND=noninteractive apt-get purge -y -qq 'mongodb-org*' 'mongodb-mongosh*' 'mongodb-database-tools'
  do_ sudo rm -rf /etc/systemd/system/mongod.service.d/shadowserver.conf /var/lib/mongodb /var/log/mongodb \
    "$MONGOD_CONF" "$MONGOD_CONF.orig"
  if [ $DRY = 1 ]; then say "  would remove /etc/apt/sources.list.d/mongodb-org-*.list and /usr/share/keyrings/mongodb-server-*.gpg"
  else sudo bash -c 'rm -f /etc/apt/sources.list.d/mongodb-org-*.list /usr/share/keyrings/mongodb-server-*.gpg'; fi
  do_ sudo systemctl daemon-reload || true
  done_ "MongoDB removed"
else skip "kept"; fi

# ------------------------------------------------------------------------------------------------ 6. files
say "${B}6. Folder${R}"
if [ $RM_FILES = 1 ]; then
  case "$ROOT" in /|/home|/root|/usr|/etc|/var|/opt|"$HOME") die "refusing to delete $ROOT." ;; esac
  [ -f "$ROOT/install.sh" ] || die "$ROOT has no install.sh: it does not look like a Looking Glass folder, not deleted."
  cd /
  # files the hardened service or a root-run step may have left owned by root are removed with sudo
  do_ sudo rm -rf --one-file-system -- "$ROOT"
  done_ "$ROOT deleted"
else skip "kept: $ROOT"; fi

say ""
if [ $DRY = 1 ]; then say "${B}Dry run finished:${R} nothing was changed."
else
  say "${GRN}${B}Looking Glass is uninstalled.${R}"
  if [ $RM_FILES = 0 ]; then say "To install again later: ./install.sh in $ROOT (it finds the kept settings and data)."; fi
fi
exit 0
