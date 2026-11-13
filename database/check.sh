#!/usr/bin/env bash
# Verify the Shadowserver pipeline setup: native MongoDB service + binaries, memory limits,
# MongoDB auth, indexes, document structure, data folders and the IMAP login.
# Exit code 0 = everything required is OK. Needs no sudo.
set -uo pipefail
cd "$(dirname "$(readlink -f "$0")")"

env_get() {
  local v
  v=$(grep -E "^[[:space:]]*$1[[:space:]]*=" .env 2>/dev/null | head -n1 | cut -d= -f2- || true)
  v="${v%$'\r'}"; v="${v#"${v%%[![:space:]]*}"}"; v="${v%"${v##*[![:space:]]}"}"
  if [[ ${#v} -ge 2 && ( ( $v == \'*\' ) || ( $v == \"*\" ) ) ]]; then v="${v:1:${#v}-2}"; fi
  printf '%s' "${v:-${2-}}"
}
row() { printf '[%4s] %-46s %s\n' "$1" "$2" "$3"; [[ $1 == FAIL ]] && fail=1; return 0; }

fail=0
MEM=$(env_get MONGO_MEMORY_LIMIT 3g)
OLD_CONTAINER=$(env_get MONGO_CONTAINER shadowserver-mongo)

LOCAL=$(env_get MONGO_LOCAL true); LOCAL=${LOCAL,,}
BIND=$(env_get MONGO_BIND 127.0.0.1)
if [[ $LOCAL == false ]]; then
echo "== MongoDB (on another server: $(env_get MONGO_HOST):$(env_get MONGO_PORT 27017); its login is checked below)"
else
echo "== MongoDB (native)"
if command -v mongod >/dev/null; then row OK "mongod binary" "$(mongod --version | head -n1) ($(command -v mongod))"
else row FAIL "mongod binary" "not installed (run ./deploy.sh)"; fi
if command -v mongosh >/dev/null; then row OK "mongosh binary" "mongosh $(mongosh --version) ($(command -v mongosh))"
else row FAIL "mongosh binary" "not installed (run ./deploy.sh)"; fi
if command -v mongodump >/dev/null; then row OK "database tools" "$(mongodump --version | head -n1)"
else row WARN "database tools" "mongodump/mongorestore not installed"; fi

active=$(systemctl is-active mongod 2>/dev/null); enabled=$(systemctl is-enabled mongod 2>/dev/null)
[[ $active == active ]] && row OK "service mongod" "$active" || row FAIL "service mongod" "${active:-missing} (sudo systemctl start mongod)"
[[ $enabled == enabled ]] && row OK "starts automatically" "$enabled" || row WARN "starts automatically" "${enabled:-no}"
maxb=$(systemctl show -p MemoryMax --value mongod 2>/dev/null); curb=$(systemctl show -p MemoryCurrent --value mongod 2>/dev/null)
if [[ $maxb =~ ^[0-9]+$ ]]; then row OK "memory limit (systemd)" "$((maxb / 1048576)) MB (configured $MEM)"
else row WARN "memory limit (systemd)" "${maxb:-none} (run ./deploy.sh)"; fi
[[ $curb =~ ^[0-9]+$ ]] && row OK "current memory use" "$((curb / 1048576)) MB"
if grep -qE "^\s*bindIp:\s*${BIND//./\\.}\s*$" /etc/mongod.conf 2>/dev/null && grep -qE '^\s*authorization:\s*enabled' /etc/mongod.conf 2>/dev/null; then
  [[ $BIND == 127.0.0.1 ]] && row OK "/etc/mongod.conf" "localhost only, authorization enabled" \
                           || row OK "/etc/mongod.conf" "listens on $BIND (firewall it), authorization enabled"
else
  row WARN "/etc/mongod.conf" "not the deploy.sh config (run ./deploy.sh)"
fi
if [[ -f .migrated-from-container ]]; then row OK "data from old container" "migrated $(cat .migrated-from-container)"; fi
if command -v docker >/dev/null && docker info >/dev/null 2>&1 \
   && [[ $(docker inspect -f '{{.State.Status}}' "$OLD_CONTAINER" 2>/dev/null) == running ]]; then
  row WARN "old Docker container" "'$OLD_CONTAINER' is still running (./deploy.sh stops it)"
fi
fi

echo
echo "== Pipeline"
if [[ ! -x .venv/bin/python ]]; then
  echo "[FAIL] .venv missing (run ./deploy.sh)"; exit 1
fi
.venv/bin/python shadowserver_pipeline.py --check || fail=1

if crontab -l 2>/dev/null | grep -q '# shadowserver-pipeline'; then
  echo "Schedule: $(bin/shadowserver schedule show | head -n1 | sed 's/^Scheduled: //')"
else
  echo "Schedule: none (recommended: shadowserver schedule every 30m)"
fi
exit $fail
