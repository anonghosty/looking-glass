#!/usr/bin/env bash
# Verify a backup archive: the signature of its checksum file (this installation's key, or the public key you give),
# that the signed checksum is THIS archive's (its name and its SHA-256, computed here), .env identical to the live file,
# and the number of files. Exits non-zero if any of the first three fail. A backup without a signature, or with no
# public key to check it, fails too, unless --allow-unsigned is given (for backups made before they were signed).
# Usage: manage/verify_backup.sh [--allow-unsigned] [archive] [public key file]
#        (default: the newest backup of this project in ~/backups, and this installation's data/audit_signing/signing_key.pub)
set -euo pipefail
project="$(cd "$(dirname "$0")/.." && pwd)"
name="$(basename "$project")"
allow_unsigned=0
[ "${1:-}" = "--allow-unsigned" ] && { allow_unsigned=1; shift; }
f="${1:-$(ls -t "$HOME/backups/$name"-*.tar.gz | head -1)}"
pub="${2:-$project/data/audit_signing/signing_key.pub}"
py="$project/.venv/bin/python"; [ -x "$py" ] || py=python3
echo "archive: $f ($(stat -c %s "$f") bytes)"
rc=0
unsigned() {
  if [ "$allow_unsigned" = 1 ]; then echo "signature: $1 (accepted: --allow-unsigned)"; else echo "signature: $1: NOT VERIFIED (--allow-unsigned accepts it)"; rc=1; fi
}
if [ ! -f "$f.sha256.sig" ]; then
  unsigned "NONE (made before backups were signed, or without openssh-client)"
elif [ ! -f "$pub" ]; then
  unsigned "NOT CHECKED (no public key at $pub: give the one you keep as the second argument)"
else
  state="$("$py" "$project/audit_checkpoint.py" verify-file "$f.sha256" looking-glass-backup "$pub" || true)"
  echo "signature: $state"
  [ "$state" = "valid" ] || rc=1
fi
# the checksum file must be about THIS archive: its name, and the SHA-256 of the archive given here (sha256sum -c alone
# would check whichever file the line names; security review of edd2d57)
read -r want named < "$f.sha256" || true
named="${named#\*}"
have="$(sha256sum "$f" | cut -d' ' -f1)"
if [ "$(basename "$named")" != "$(basename "$f")" ]; then
  echo "checksum: the checksum file is for $(basename "$named"), not for this archive"; rc=1
elif [ "$have" != "$want" ]; then
  echo "checksum: DOES NOT MATCH (the archive changed or is damaged)"; rc=1
else
  echo "checksum: matches ($have)"
fi
if tar -xzOf "$f" "$name/.env" | cmp -s - "$project/.env"; then echo ".env: included and identical"; else echo ".env: MISSING OR DIFFERENT"; fi
echo "files: $(tar -tzf "$f" | grep -vc '/$')"
exit $rc
