#!/usr/bin/env bash
# Deploy / re-deploy the Shadowserver pipeline on this WSL machine. Safe to run repeatedly.
#
#   ./deploy.sh                      install MongoDB (native) + deps, configure, run checks
#   ./deploy.sh --schedule 'every 30m'  ...and run the pipeline every 30 minutes (or HH:MM daily; cron)
#   ./deploy.sh --unschedule         remove the daily cron job
#                                    (same as: shadowserver schedule 06:30 | off - no sudo)
#   ./deploy.sh --remove-container   delete the old Docker MongoDB container + volume
#                                    (only after its data was migrated)
#   ./deploy.sh --uninstall-commands remove the global 'shadowserver' command, man page, completion
#
# Installs the global command 'shadowserver' (/usr/local/bin), its man page and bash
# completion, so after deploying: shadowserver run | check | status | logs | deploy | man
#
# MongoDB is installed natively from the official MongoDB apt repository
# (mongod, mongosh, mongodump/mongorestore) and runs as the systemd service 'mongod':
#   /etc/mongod.conf                 127.0.0.1 only, auth on, WiredTiger cache MONGO_CACHE_GB
#   systemd drop-in                  MemoryMax=MONGO_MEMORY_LIMIT, restart on failure
# If the earlier Docker container 'shadowserver-mongo' exists, its data is dumped,
# restored into the native server, verified, and the container is stopped.
#
# MONGO_LOCAL=false in .env: MongoDB runs on another server (MONGO_HOST). Nothing is installed or configured for
# MongoDB here; deploy only checks that the account in .env can log in.
# MONGO_BIND in .env: addresses the local mongod listens on (default 127.0.0.1; add this server's address when the
# Looking Glass platform runs on another computer, and allow only that computer in the firewall).
set -euo pipefail
cd "$(dirname "$(readlink -f "$0")")"
PROJECT_DIR=$(pwd)

info() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mWARN:\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }

# Read KEY from .env literally (no shell expansion), stripping optional quotes.
env_get() {
  local v
  v=$(grep -E "^[[:space:]]*$1[[:space:]]*=" .env 2>/dev/null | head -n1 | cut -d= -f2- || true)
  v="${v%$'\r'}"; v="${v#"${v%%[![:space:]]*}"}"; v="${v%"${v##*[![:space:]]}"}"
  if [[ ${#v} -ge 2 && ( ( $v == \'*\' ) || ( $v == \"*\" ) ) ]]; then v="${v:1:${#v}-2}"; fi
  printf '%s' "${v:-${2-}}"
}

SCHEDULE=""; UNSCHEDULE=0; REMOVE_CONTAINER=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --schedule) SCHEDULE="${2-}"; [[ -n $SCHEDULE ]] || die "--schedule needs 'every 30m' or HH:MM"; shift 2 ;;
    --unschedule) UNSCHEDULE=1; shift ;;
    --remove-container) REMOVE_CONTAINER=1; shift ;;
    --uninstall-commands)
      sudo rm -f /usr/local/bin/shadowserver /usr/local/share/man/man1/shadowserver.1 /etc/bash_completion.d/shadowserver
      sudo mandb -q >/dev/null 2>&1 || true
      info "Removed the global 'shadowserver' command, man page and completion (project files untouched)"
      exit 0 ;;
    -h|--help) sed -n '2,/^set -e/p' "$0" | grep '^#' | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown option $1 (see ./deploy.sh --help)" ;;
  esac
done

# ---------------------------------------------------------------- 1. config
if [[ ! -f .env ]]; then
  cp .env.example .env; chmod 600 .env
  die "Created .env from .env.example - fill in the credentials and re-run ./deploy.sh"
fi
chmod 600 .env
MONGO_USER=$(env_get MONGO_USER); MONGO_PASSWORD=$(env_get MONGO_PASSWORD)
_local=$(env_get MONGO_LOCAL true)
# a MongoDB used as it is (MONGO_LOCAL=false) may have no access control; the one deploy.sh installs always has
[[ ${_local,,} == false || ( -n $MONGO_USER && -n $MONGO_PASSWORD ) ]] || die "MONGO_USER / MONGO_PASSWORD must be set in .env"
# was a MongoDB installed before this script ever ran? (then it may belong to someone else: see step 4)
MONGO_PREEXISTING=0
if command -v mongod >/dev/null && ! grep -q 'Managed by .*deploy.sh' /etc/mongod.conf 2>/dev/null; then MONGO_PREEXISTING=1; fi
MONGO_DB=$(env_get MONGO_DB shadowserver)
AUTH_DB=$(env_get MONGO_AUTH_SOURCE admin)
PORT=$(env_get MONGO_PORT 27017)
SERIES=$(env_get MONGO_SERIES 8.0)
CACHE_GB=$(env_get MONGO_CACHE_GB 1.5)
MEM=$(env_get MONGO_MEMORY_LIMIT 3g); MEM=${MEM^^}          # systemd wants 3G
LOCAL=$(env_get MONGO_LOCAL true); LOCAL=${LOCAL,,}
BIND=$(env_get MONGO_BIND 127.0.0.1)
OLD_CONTAINER=$(env_get MONGO_CONTAINER shadowserver-mongo)
OLD_VOLUME=$(env_get MONGO_VOLUME shadowserver-mongo-data)
MIGRATED_MARK="$PROJECT_DIR/.migrated-from-container"
# not exported: only mongosh gets the password, in its own environment (msh_*), never every command this script runs
# (apt, curl, sudo...: external review, 2026-11-12)
MS_USER="$MONGO_USER"; MS_PW="$MONGO_PASSWORD"; MS_AUTHDB="$AUTH_DB"; MS_DB="$MONGO_DB"

# password-free sudo needs no prompt (and `sudo -v` would wait for one even then: it hangs when run without a terminal,
# e.g. from install.sh); otherwise ask once.
sudo -n true 2>/dev/null || sudo -v || die "sudo is required"

# ---------------------------------------------------------------- 2. packages
info "Checking system packages"
base_pkgs=()
python3 -c 'import ensurepip, venv' 2>/dev/null || base_pkgs+=(python3-venv)
command -v gpg   >/dev/null || base_pkgs+=(gnupg)
command -v curl  >/dev/null || base_pkgs+=(curl)
command -v flock >/dev/null || base_pkgs+=(util-linux)
command -v crontab >/dev/null || base_pkgs+=(cron)
if [[ ${#base_pkgs[@]} -gt 0 ]]; then
  sudo apt-get update -qq
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${base_pkgs[@]}"
fi

if [[ $LOCAL == false ]]; then
  info "MongoDB is on another server ($(env_get MONGO_HOST):$PORT): nothing to install for it here"
elif ! command -v mongod >/dev/null || ! command -v mongosh >/dev/null || ! command -v mongorestore >/dev/null; then
  CODENAME=$(. /etc/os-release && echo "${VERSION_CODENAME:-noble}")
  ARCH=$(dpkg --print-architecture)
  has_pkg() {  # the repo answers 200 even for missing releases, so look inside the package index
    local idx
    idx=$(curl -fsSL "https://repo.mongodb.org/apt/ubuntu/dists/$1/mongodb-org/$SERIES/multiverse/binary-$ARCH/Packages.gz" 2>/dev/null \
          | gunzip 2>/dev/null) || return 1
    grep -q '^Package: mongodb-org$' <<<"$idx"
  }
  # Per MongoDB docs: Ubuntu's own 'mongodb' package conflicts with mongodb-org.
  if dpkg -s mongodb >/dev/null 2>&1; then
    die "Ubuntu's 'mongodb' package is installed and conflicts with mongodb-org - remove it first: sudo apt-get remove mongodb"
  fi
  if ! has_pkg "$CODENAME"; then
    has_pkg noble || die "Could not find MongoDB $SERIES packages on repo.mongodb.org"
    warn "MongoDB has no $SERIES packages for Ubuntu '$CODENAME' yet - using the Ubuntu 24.04 (noble) build"
    CODENAME=noble
  fi
  info "Installing MongoDB $SERIES (mongod, mongosh, database tools) from repo.mongodb.org [$CODENAME]"
  KEYRING=/usr/share/keyrings/mongodb-server-$SERIES.gpg
  curl -fsSL "https://pgp.mongodb.com/server-$SERIES.asc" | sudo gpg --dearmor --yes -o "$KEYRING"
  echo "deb [ arch=amd64,arm64 signed-by=$KEYRING ] https://repo.mongodb.org/apt/ubuntu $CODENAME/mongodb-org/$SERIES multiverse" \
    | sudo tee "/etc/apt/sources.list.d/mongodb-org-$SERIES.list" >/dev/null
  sudo apt-get update -qq
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq mongodb-org
fi
[[ $LOCAL == false ]] || info "$(mongod --version | head -n1), mongosh $(mongosh --version)"

if [[ $LOCAL != false ]]; then   # ------------------------------------------- local MongoDB: steps 3 to 6

# mongosh helpers (password passed via environment, never on the command line)
msh_noauth() { MS_USER="$MS_USER" MS_PW="$MS_PW" MS_AUTHDB="$MS_AUTHDB" MS_DB="$MS_DB" mongosh --quiet --port "$PORT" "$@"; }
msh_auth() {
  MS_USER="$MS_USER" MS_PW="$MS_PW" MS_AUTHDB="$MS_AUTHDB" MS_DB="$MS_DB" mongosh --quiet --port "$PORT" --eval \
    'const r = db.getSiblingDB(process.env.MS_AUTHDB).auth(process.env.MS_USER, process.env.MS_PW); if (!r.ok && r !== 1) quit(9);' \
    --eval "$1"
}
total_docs_js='let t=0; const d=db.getSiblingDB(process.env.MS_DB); d.getCollectionNames().forEach(c=>{t+=d.getCollection(c).countDocuments({})}); print(t)'
tool_cfg() {  # YAML config so mongodump/mongorestore never get the password on argv
  local f; f=$(mktemp); chmod 600 "$f"
  printf 'password: "%s"\n' "${MONGO_PASSWORD//\"/\\\"}" > "$f"; printf '%s' "$f"
}

# ---------------------------------------------------------------- 3. old Docker container -> dump
DOCKER=()
if command -v docker >/dev/null; then
  if docker info >/dev/null 2>&1; then DOCKER=(docker); elif sudo docker info >/dev/null 2>&1; then DOCKER=(sudo docker); fi
fi
DUMP=""
if [[ ${#DOCKER[@]} -gt 0 ]] && "${DOCKER[@]}" container inspect "$OLD_CONTAINER" >/dev/null 2>&1; then
  if [[ ! -f $MIGRATED_MARK ]]; then
    state=$("${DOCKER[@]}" inspect -f '{{.State.Status}}' "$OLD_CONTAINER")
    if [[ $state != running ]]; then
      info "Starting old container '$OLD_CONTAINER' to export its data"
      sudo systemctl stop mongod 2>/dev/null || true
      "${DOCKER[@]}" start "$OLD_CONTAINER" >/dev/null
      for _ in $(seq 1 30); do msh_noauth --eval 'db.adminCommand({ping:1}).ok' >/dev/null 2>&1 && break; sleep 2; done
    fi
    mkdir -p backups
    DUMP="backups/mongo-from-container-$(date +%Y%m%d-%H%M%S).archive.gz"
    SRC_COUNT=$(msh_auth "$total_docs_js")
    info "Exporting '$MONGO_DB' from the container ($SRC_COUNT documents) -> $DUMP"
    cfg=$(tool_cfg)
    mongodump --quiet --host 127.0.0.1 --port "$PORT" --username "$MONGO_USER" --config "$cfg" \
      --authenticationDatabase "$AUTH_DB" --db "$MONGO_DB" --archive="$DUMP" --gzip
    rm -f "$cfg"; chmod 600 "$DUMP"
    echo "$SRC_COUNT" > "$DUMP.count"
  fi
  if [[ $("${DOCKER[@]}" inspect -f '{{.State.Status}}' "$OLD_CONTAINER") == running ]]; then
    info "Stopping old container '$OLD_CONTAINER' (and disabling its auto-restart)"
    "${DOCKER[@]}" update --restart=no "$OLD_CONTAINER" >/dev/null
    "${DOCKER[@]}" stop "$OLD_CONTAINER" >/dev/null
  fi
fi

# ---------------------------------------------------------------- 4. native mongod config
# Never take over a MongoDB that was installed and configured by someone else: its port, addresses and access control
# may be relied on by other programs. Use it as it is (MONGO_LOCAL=false, what install.sh does), or say so explicitly.
if [[ $MONGO_PREEXISTING == 1 && $(env_get MONGO_TAKE_OVER false) != true ]]; then
  die "MongoDB was already installed on this computer before Looking Glass, and its configuration (/etc/mongod.conf) was
       not made by deploy.sh. deploy.sh will not rewrite it. Either use it as it is: set MONGO_LOCAL=false, MONGO_HOST=127.0.0.1,
       MONGO_PORT (its port) and an account of it in .env (install.sh offers this); or, to let deploy.sh reconfigure it
       (127.0.0.1 only, authorization on, port MONGO_PORT, restart), set MONGO_TAKE_OVER=true in .env."
fi
info "Configuring mongod ($BIND:$PORT, auth on, cache ${CACHE_GB} GB, memory limit $MEM)"
[[ -f /etc/mongod.conf && ! -f /etc/mongod.conf.orig ]] && sudo cp /etc/mongod.conf /etc/mongod.conf.orig
conf=$(cat <<EOF
# Managed by $PROJECT_DIR/deploy.sh - edit .env and re-run deploy instead of editing here.
storage:
  dbPath: /var/lib/mongodb
  wiredTiger:
    engineConfig:
      cacheSizeGB: $CACHE_GB
systemLog:
  destination: file
  logAppend: true
  path: /var/log/mongodb/mongod.log
net:
  port: $PORT
  bindIp: $BIND
processManagement:
  timeZoneInfo: /usr/share/zoneinfo
security:
  authorization: enabled
EOF
)
dropin=$(cat <<EOF
# Managed by $PROJECT_DIR/deploy.sh
[Service]
MemoryMax=$MEM
LimitNOFILE=64000
Restart=on-failure
RestartSec=5
EOF
)
changed=0
if [[ "$(sudo cat /etc/mongod.conf 2>/dev/null)" != "$conf" ]]; then
  printf '%s\n' "$conf" | sudo tee /etc/mongod.conf >/dev/null; changed=1
fi
sudo install -d /etc/systemd/system/mongod.service.d
if [[ "$(cat /etc/systemd/system/mongod.service.d/shadowserver.conf 2>/dev/null)" != "$dropin" ]]; then
  printf '%s\n' "$dropin" | sudo tee /etc/systemd/system/mongod.service.d/shadowserver.conf >/dev/null; changed=1
fi
sudo systemctl daemon-reload
sudo systemctl enable mongod >/dev/null 2>&1
if [[ $changed -eq 1 ]] || ! systemctl is-active --quiet mongod; then
  info "(Re)starting mongod"
  sudo systemctl restart mongod
fi

info "Waiting for mongod"
for _ in $(seq 1 60); do msh_noauth --eval 'db.adminCommand({ping:1}).ok' >/dev/null 2>&1 && break; sleep 1; done
msh_noauth --eval 'db.adminCommand({ping:1}).ok' >/dev/null 2>&1 \
  || { sudo tail -n 30 /var/log/mongodb/mongod.log; die "mongod did not start"; }

# ---------------------------------------------------------------- 5. user
if msh_auth 'print(1)' >/dev/null 2>&1; then
  info "MongoDB user '$MONGO_USER' OK"
else
  info "Creating MongoDB root user '$MONGO_USER' (localhost exception)"
  msh_noauth admin --eval \
    'db.createUser({user: process.env.MS_USER, pwd: process.env.MS_PW, roles: [{role: "root", db: "admin"}]})' >/dev/null \
    || die "Could not create user - users already exist with a different password? Fix MONGO_PASSWORD in .env"
  msh_auth 'print(1)' >/dev/null || die "Login as '$MONGO_USER' failed after creating the user"
fi

# ---------------------------------------------------------------- 6. restore container data
if [[ -z $DUMP && ! -f $MIGRATED_MARK ]]; then
  DUMP=$(ls -1t backups/mongo-from-container-*.archive.gz 2>/dev/null | head -n1 || true)
fi
if [[ -n $DUMP && ! -f $MIGRATED_MARK ]]; then
  SRC_COUNT=$(cat "$DUMP.count" 2>/dev/null || echo "?")
  DST_COUNT=$(msh_auth "$total_docs_js")
  if [[ $DST_COUNT != 0 ]]; then
    warn "Native '$MONGO_DB' already has $DST_COUNT documents - not restoring $DUMP automatically"
  else
    info "Restoring $DUMP into native MongoDB"
    cfg=$(tool_cfg)
    mongorestore --quiet --host 127.0.0.1 --port "$PORT" --username "$MONGO_USER" --config "$cfg" \
      --authenticationDatabase "$AUTH_DB" --archive="$DUMP" --gzip
    rm -f "$cfg"
    DST_COUNT=$(msh_auth "$total_docs_js")
    if [[ $SRC_COUNT == "$DST_COUNT" ]]; then
      info "Migration verified: $DST_COUNT documents in container = $DST_COUNT in native MongoDB"
      date > "$MIGRATED_MARK"
    else
      die "Migration count mismatch: container $SRC_COUNT vs native $DST_COUNT (dump kept at $DUMP)"
    fi
  fi
fi

if [[ $REMOVE_CONTAINER -eq 1 && ${#DOCKER[@]} -gt 0 ]]; then
  [[ -f $MIGRATED_MARK ]] || die "Refusing to remove the container: its data has not been migrated yet"
  info "Removing old container '$OLD_CONTAINER' and volume '$OLD_VOLUME'"
  "${DOCKER[@]}" rm -f "$OLD_CONTAINER" >/dev/null 2>&1 || true
  "${DOCKER[@]}" volume rm "$OLD_VOLUME" >/dev/null 2>&1 || true
fi

fi   # ------------------------------------------------------------------------ end of local MongoDB

# ---------------------------------------------------------------- 7. python venv + folders
info "Setting up Python virtualenv (.venv)"
[[ -x .venv/bin/python ]] || python3 -m venv .venv
.venv/bin/python -m pip install -q --upgrade pip
.venv/bin/python -m pip install -q -r requirements.txt
chmod +x run.sh check.sh deploy.sh shadowserver_pipeline.py 2>/dev/null || true
mkdir -p attachments_backup unzipped_backup sorting_backup logs backups
if [[ $LOCAL == false ]]; then
  info "Checking the login to the remote MongoDB"
  .venv/bin/python - <<'EOF' || die "Cannot log in to the remote MongoDB with the account in .env (address, firewall, user, password?)"
import sys
from pathlib import Path
sys.path.insert(0, ".")
import shadowserver_pipeline as sp
s = sp.load_settings(sp.argparse.Namespace(env_file=str(Path(".env").resolve()), workers=None, days=None))
sp.mongo_client(s.mongo).admin.command("ping")
print("  remote MongoDB login OK")
EOF
fi

# ---------------------------------------------------------------- 8. global commands
info "Installing global command 'shadowserver' (+ man page, tab completion)"
chmod +x bin/shadowserver
# the report data already on disk: this account only (new files get it from the pipeline's umask)
for d in attachments_backup unzipped_backup sorting_backup quarantine logs; do
  [[ -d $d ]] && chmod -R go-rwx "$d"
done
chmod go-rwx .mail_state.sqlite .pipeline_state.sqlite 2>/dev/null || true
# Root-owned copies and a root-owned wrapper, never links into this (user-writable) folder: the tab completion is
# sourced by every login shell, root's too, so a link let whoever can write here run code in other users' shells
# (external review, 2026-11-12). Run ./deploy.sh again after updating to refresh the man page and completion.
sudo rm -f /usr/local/bin/shadowserver /usr/local/share/man/man1/shadowserver.1 /etc/bash_completion.d/shadowserver
printf '#!/bin/sh\n# installed by deploy.sh: runs the pipeline command of %s\nexec "%s/bin/shadowserver" "$@"\n' \
  "$PROJECT_DIR" "$PROJECT_DIR" | sudo tee /usr/local/bin/shadowserver >/dev/null
sudo chmod 0755 /usr/local/bin/shadowserver
chmod 0644 docs/shadowserver.1 bin/shadowserver-completion.bash
sudo install -d /usr/local/share/man/man1 /etc/bash_completion.d
sudo install -m 0644 -o root -g root docs/shadowserver.1 /usr/local/share/man/man1/shadowserver.1
sudo mandb -q >/dev/null 2>&1 || true
sudo install -m 0644 -o root -g root bin/shadowserver-completion.bash /etc/bash_completion.d/shadowserver
command -v shadowserver >/dev/null || warn "/usr/local/bin is not on PATH - open a new shell"

# ---------------------------------------------------------------- 9. schedule (optional)
# Same code as 'shadowserver schedule HH:MM | off' (which needs no sudo).
if [[ -n $SCHEDULE ]]; then
  info "Scheduling daily run"
  bin/shadowserver schedule "$SCHEDULE" || die "could not set the schedule"
elif [[ $UNSCHEDULE -eq 1 ]]; then
  bin/shadowserver schedule off
fi

# ---------------------------------------------------------------- 10. verify
info "Running checks"
./check.sh
