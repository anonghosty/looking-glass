#!/usr/bin/env bash
# Keep the MongoDB administrator (root) account where neither the pipeline nor the platform can read it.
#
# The pipeline and the platform each sign in with their own limited account (create_pipeline_db_user.py,
# platform/deploy/create_readonly_db_user.py). The administrator account is only needed for administration:
# re-installs, backups and restores, new accounts. Kept in the project folder, it would be readable by the same Linux
# user the pipeline runs as, so code run through a hostile e-mail could take it. This script moves it to
#   /etc/looking-glass/mongo-admin.env    owner root, mode 600: readable only with sudo
# checks that sudo can read it back and that it signs in, then overwrites and removes the copy it came from.
#
#   ./store_mongo_admin.sh [FILE]     FILE: an .env holding the administrator account
#                                     (default .env.before-pipeline-account, left by create_pipeline_db_user.py)
#   ./store_mongo_admin.sh --check    does the stored account still sign in?
#   Show it again (the way back):     sudo cat /etc/looking-glass/mongo-admin.env
#
# Only the MONGO_ lines are stored; the password never appears on a command line. It protects against a break-in to
# the programs, not against root: if the user running Looking Glass has passwordless sudo, it can read the file too.
set -euo pipefail
cd "$(dirname "$(readlink -f "$0")")"
DEST_DIR=/etc/looking-glass
DEST=$DEST_DIR/mongo-admin.env
PY=.venv/bin/python; [ -x "$PY" ] || PY=python3
SUDO=(sudo); [ -t 0 ] || SUDO=(sudo -n)          # never wait for a password when no one can type it

login_check() {   # reads KEY=VALUE lines on stdin; signs in with them and says which roles it has
  "$PY" -c '
import sys
from pymongo import MongoClient
e = {}
for raw in sys.stdin.read().splitlines():
    if "=" in raw and not raw.lstrip().startswith("#"):
        k, v = raw.split("=", 1); v = v.strip()
        e[k.strip()] = v[1:-1] if len(v) >= 2 and v[0] == v[-1] and v[0] in "\x27\"" else v
c = MongoClient(host=e.get("MONGO_HOST") or "127.0.0.1", port=int(e.get("MONGO_PORT") or 27017), username=e["MONGO_USER"],
                password=e["MONGO_PASSWORD"], authSource=e.get("MONGO_AUTH_SOURCE") or "admin", serverSelectionTimeoutMS=8000)
roles = sorted(r["role"] + "@" + r["db"] for r in c.admin.command("connectionStatus")["authInfo"]["authenticatedUserRoles"])
print(e["MONGO_USER"], "signs in:", ", ".join(roles) or "no roles")
'
}

if [ "${1:-}" = --check ]; then
  "${SUDO[@]}" cat "$DEST" | login_check
  exit
fi

SRC=${1:-.env.before-pipeline-account}
[ -f "$SRC" ] || { echo "No $SRC here: nothing to store."; exit 1; }
user=$(grep -E '^[[:space:]]*MONGO_USER[[:space:]]*=' "$SRC" | tail -n1 | cut -d= -f2- | tr -d '[:space:]"'"'" || true)
case "$user" in
  ""|lookingglass_pipeline|lookingglass_ro) echo "$SRC does not hold an administrator account (MONGO_USER=${user:-empty}): nothing stored."; exit 1 ;;
esac
"${SUDO[@]}" true 2>/dev/null || { echo "sudo is not available here: $SRC is kept as it is (mode 600)."; exit 1; }

tmp=$(umask 077; mktemp)
trap 'shred -u "$tmp" 2>/dev/null || rm -f "$tmp"' EXIT
{ echo "# MongoDB administrator account of Looking Glass ($(date -u +%F)). Keep it here or in a password manager."
  grep -E '^[[:space:]]*MONGO_(HOST|PORT|USER|PASSWORD|AUTH_SOURCE)[[:space:]]*=' "$SRC"; } > "$tmp"
login_check < "$tmp" >/dev/null || { echo "The account in $SRC does not sign in: nothing stored, $SRC kept."; exit 1; }

"${SUDO[@]}" install -d -m 700 -o root -g root "$DEST_DIR"
"${SUDO[@]}" install -m 600 -o root -g root "$tmp" "$DEST"
if ! "${SUDO[@]}" cat "$DEST" | cmp -s - "$tmp"; then echo "PROBLEM: $DEST does not read back as written: $SRC kept."; exit 1; fi
echo "Stored in $DEST (root, mode 600): $("${SUDO[@]}" cat "$DEST" | login_check)"
shred -u "$SRC" 2>/dev/null || rm -f "$SRC"
echo "Removed $SRC. To see the administrator account again: sudo cat $DEST"
# Older backups of .env made by the installer and the scripts (.env.before-*) can hold the same password: blank it
# there (the rest of each backup stays), here and in the platform folder next to it.
for f in ./.env.before-* ../platform/.env.before-* ../threatmap/.env.before-*; do
  [ -f "$f" ] || continue
  u=$(grep -E '^[[:space:]]*MONGO_USER[[:space:]]*=' "$f" | tail -n1 | cut -d= -f2- | tr -d '[:space:]"'"'" || true)
  [ "$u" = "$user" ] && grep -qE '^[[:space:]]*MONGO_PASSWORD[[:space:]]*=[[:space:]]*[^[:space:]]' "$f" || continue
  sed -i -E "s|^[[:space:]]*MONGO_PASSWORD[[:space:]]*=.*|# the administrator password was moved to $DEST (sudo cat it)\nMONGO_PASSWORD=|" "$f"
  echo "Blanked the administrator password in the backup $f"
done
