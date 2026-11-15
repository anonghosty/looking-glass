#!/usr/bin/env bash
# Back up Looking Glass, INCLUDING .env (credentials), accounts, sessions, settings and certificates in data/.
# The virtualenv is left out: recreate it with deploy/install.sh (or python3 -m venv .venv && .venv/bin/pip install -r requirements.txt).
# The checksum is signed with this installation's key (audit_checkpoint.py, namespace looking-glass-backup) and the
# backup is recorded in the audit log. The private signing key itself is left out: a restored installation makes a new
# one (recorded in the audit log); the public key stays in the archive and in the audit log.
# Run it as the service's own user (the owner of data/). Run manage/restore_check.sh on the archive to rehearse a restore.
# Usage: manage/backup.sh [destination folder]     (default: ~/backups)
set -euo pipefail
project="$(cd "$(dirname "$0")/.." && pwd)"
name="$(basename "$project")"
dest="${1:-$HOME/backups}"
mkdir -p "$dest"
chmod 700 "$dest"
dest="$(cd "$dest" && pwd)"
stamp="$(date -u +%Y%m%d-%H%M%S)UTC"
out="$dest/$name-$stamp.tar.gz"
py="$project/.venv/bin/python"; [ -x "$py" ] || py=python3
tar -C "$(dirname "$project")" --exclude="$name/.venv" --exclude='__pycache__' \
    --exclude="$name/data/audit_signing/signing_key" --exclude="$name/data/audit_signing/.lock" -czf "$out" "$name"
chmod 600 "$out"   # contains secrets from .env
(cd "$dest" && sha256sum "$(basename "$out")") > "$out.sha256"   # by name, so it checks wherever the two files are copied
chmod 600 "$out.sha256"
if sig="$("$py" "$project/audit_checkpoint.py" sign-file "$out.sha256" looking-glass-backup)"; then
  echo "checksum signed: $sig"
else
  echo "WARNING: the checksum is NOT signed (is openssh-client installed?); the backup itself is complete." >&2
fi
ls -l "$out" "$out.sha256" ${sig:+"$sig"}
echo "--- contents ---"
tar -tzvf "$out"
