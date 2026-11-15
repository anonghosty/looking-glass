#!/usr/bin/env bash
# Verify a backup archive: the signature of its checksum (this installation's key, or the public key you give), the
# checksum, .env identical to the live file, and the number of files. Exits non-zero if the signature or checksum fail.
# Usage: manage/verify_backup.sh [archive] [public key file]
#        (default: the newest backup of this project in ~/backups, and this installation's data/audit_signing/signing_key.pub)
set -euo pipefail
project="$(cd "$(dirname "$0")/.." && pwd)"
name="$(basename "$project")"
f="${1:-$(ls -t "$HOME/backups/$name"-*.tar.gz | head -1)}"
pub="${2:-$project/data/audit_signing/signing_key.pub}"
py="$project/.venv/bin/python"; [ -x "$py" ] || py=python3
echo "archive: $f ($(stat -c %s "$f") bytes)"
rc=0
if [ ! -f "$f.sha256.sig" ]; then
  echo "signature: NONE (made before backups were signed, or without openssh-client)"
elif [ ! -f "$pub" ]; then
  echo "signature: NOT CHECKED (no public key at $pub: give the one you keep as the second argument)"
else
  state="$("$py" "$project/audit_checkpoint.py" verify-file "$f.sha256" looking-glass-backup "$pub" || true)"
  echo "signature: $state"
  [ "$state" = "valid" ] || rc=1
fi
(cd "$(dirname "$f")" && sha256sum -c "$(basename "$f").sha256") || rc=1
if tar -xzOf "$f" "$name/.env" | cmp -s - "$project/.env"; then echo ".env: included and identical"; else echo ".env: MISSING OR DIFFERENT"; fi
echo "files: $(tar -tzf "$f" | grep -vc '/$')"
exit $rc
