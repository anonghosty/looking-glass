#!/usr/bin/env bash
# Verify a backup archive: the signature of its checksum file (this installation's key, or the public key you give),
# that the signed checksum is THIS archive's (its name and its SHA-256, computed here), and, for an encrypted backup
# opened with your private key (--identity) or an unencrypted one, .env identical to the live file and the number of
# files. Exits non-zero if the signature or the checksum fail. A backup without a signature, or with no public key to
# check it, fails too, unless --allow-unsigned is given (for backups made before they were signed).
# The signature and checksum are over the encrypted file: they are checked without any private key.
# Usage: manage/verify_backup.sh [--allow-unsigned] [--identity YOUR-PRIVATE-KEY] [archive] [public key file]
#        (default: the newest backup of this project in ~/backups, and this installation's data/audit_signing/signing_key.pub)
set -euo pipefail
project="$(cd "$(dirname "$0")/.." && pwd)"
name="$(basename "$project")"
. "$project/manage/backup_crypt.sh"
allow_unsigned=0; identity=""
while [ $# -gt 0 ]; do
  case "$1" in
    --allow-unsigned) allow_unsigned=1; shift ;;
    --identity) identity="${2:-}"; shift 2 ;;
    *) break ;;
  esac
done
# (ls fails when one of the three kinds has no file yet: that is not an error here)
newest() { { ls -t "$HOME/backups/$name"-*.tar.gz "$HOME/backups/$name"-*.tar.gz.age "$HOME/backups/$name"-*.tar.gz.gpg 2>/dev/null || true; } | head -1; }
f="${1:-$(newest)}"
[ -n "$f" ] && [ -f "$f" ] || { echo "No backup archive given or found in ~/backups." >&2; exit 2; }
pub="${2:-$project/data/audit_signing/signing_key.pub}"
py="$project/.venv/bin/python"; [ -x "$py" ] || py=python3
case "$f" in *.age|*.gpg) enc="encrypted (${f##*.})" ;; *) enc="NOT encrypted" ;; esac
echo "archive: $f ($(stat -c %s "$f") bytes, $enc)"
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
# the newest one? an older genuine backup still verifies, and a file date can be changed: the audit log says (a warning,
# not a failure: restoring an older backup on purpose is allowed; security review of a40f17a)
echo "freshness: $("$py" "$project/audit_checkpoint.py" backup-age "$f" "${want:-}" 2>/dev/null || echo 'not checked')"
case "$f" in
  *.age|*.gpg)
    if [ -z "$identity" ]; then
      echo "contents: not opened (encrypted; give your private key with --identity to compare .env and count the files)"
      exit $rc
    fi ;;
esac
tmp="$(mktemp)"; trap 'rm -f "$tmp"' EXIT; chmod 600 "$tmp"
if ! bc_decrypt "$f" "$identity" > "$tmp"; then echo "contents: CANNOT BE OPENED with that key"; exit 1; fi
if tar -xzOf "$tmp" "$name/.env" | cmp -s - "$project/.env"; then echo ".env: included and identical"; else echo ".env: MISSING OR DIFFERENT"; fi
echo "files: $(tar -tzf "$tmp" | grep -vc '/$')"
exit $rc
