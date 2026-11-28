#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
# Back up Looking Glass, INCLUDING .env (credentials), accounts, sessions, settings and certificates in data/.
# The backup is ENCRYPTED to your public key (manage/backup_crypt.sh: an age recipient or a GnuPG public key, in
# data/backup_public_key or BACKUP_PUBLIC_KEY in .env); the private key stays with you, off this server. The archive is
# encrypted as it is written: no readable copy is ever on disk. Without a public key the backup is refused, unless you
# ask for an unencrypted one on purpose with --unencrypted (review of d82a436).
# The Python environments (.venv, .venvs/) are left out: recreate them with deploy/update_libraries.sh (only files that
# match requirements.lock). The local copy of the library files (~/looking-glass/libraries) is not backed up either.
# The checksum of the (encrypted) archive is signed with this installation's key (audit_checkpoint.py, namespace
# looking-glass-backup) and the backup is recorded in the audit log. The private signing key itself is left out: a
# restored installation makes a new one (recorded in the audit log); the public key stays in the archive and in the log.
# Run it as the service's own user (the owner of data/). Run manage/restore_check.sh on the archive to rehearse a restore.
# Usage: manage/backup.sh [--unencrypted] [destination folder]     (default: ~/backups)
set -euo pipefail
project="$(cd "$(dirname "$0")/.." && pwd)"
name="$(basename "$project")"
. "$project/manage/backup_crypt.sh"
plain=0
[ "${1:-}" = "--unencrypted" ] && { plain=1; shift; }
dest="${1:-$HOME/backups}"
key="$(bc_pubkey "$project" || true)"
if [ "$plain" = 0 ] && [ -z "$key" ]; then
  cat >&2 <<EOF
NOT BACKED UP: no public key to encrypt the backup to.
A backup holds .env (the database passwords and API keys), the accounts, the sessions, the audit log and the TLS key,
so it is encrypted to a key whose private half you keep OFF this server. On your own computer:
  age:    age-keygen -o looking-glass-backup-key.txt       (keep this file safe: it opens the backups)
          age-keygen -y looking-glass-backup-key.txt  >  backup_public_key
  GnuPG:  gpg --export --armor you@example.org  >  backup_public_key
then copy backup_public_key to $project/data/backup_public_key (or set BACKUP_PUBLIC_KEY in .env) and run this again.
For an unencrypted backup anyway (not recommended): manage/backup.sh --unencrypted
EOF
  exit 3
fi
mkdir -p "$dest"
chmod 700 "$dest"
dest="$(cd "$dest" && pwd)"
stamp="$(date -u +%Y%m%d-%H%M%S)UTC"
# two backups in the same second: the second gets its own name (-2, -3...), never the first one's archive and checksum
# written over (2026-11-17: a check making two backups at once caught it)
n=1; base="$stamp"
while ls "$dest/$name-$stamp".tar.gz* >/dev/null 2>&1; do n=$((n + 1)); stamp="$base-$n"; done
py="$project/.venv/bin/python"; [ -x "$py" ] || py=python3
umask 077
# the archive, to FILE (or - for stdout). GNU tar's exit code 1 means "a file changed while it was read" (the running
# service appends to its audit log and sessions): the archive is complete, that file as it was at that moment. Said, and
# the backup goes on to its checksum and signature; any other failure stops it (audit 2026-11-27: exit 1 deleted the
# encrypted archive, and left the unencrypted one without its checksum and signature)
make_tar() {
  local rc=0 out="$1" errf changed
  # tar's messages are kept (only its messages, never file contents) to name the files it reported, then shown as they were
  errf="$(mktemp)"
  tar -C "$(dirname "$project")" --exclude="$name/.venv" --exclude="$name/.venvs" --exclude='__pycache__' \
      --exclude="$name/data/audit_signing/signing_key" --exclude="$name/data/audit_signing/.lock" -czf "$out" "$name" 2> "$errf" || rc=$?
  cat "$errf" >&2
  if [ "$rc" = 1 ]; then
    # GNU tar: "tar: FILE: file changed as we read it", "...: File shrank by N bytes; padding with zeros",
    # "...: File removed before we read it" (review 2026-11-28: name them, never only "a file")
    changed="$(sed -n -e 's/^tar: \(.*\): file changed as we read it$/\1/p' -e 's/^tar: \(.*\): File shrank by .*$/\1/p' \
                      -e 's/^tar: \(.*\): File removed before we read it$/\1/p' "$errf" | sort -u | paste -sd, - | sed 's/,/, /g')"
    rm -f "$errf"
    echo "note: a file changed while it was being read (the service was writing it): the backup may be incomplete for these files: ${changed:-(tar did not name them; see its messages above)}. The backup is kept." >&2
    return 0
  fi
  rm -f "$errf"
  return "$rc"
}
if [ "$plain" = 1 ]; then
  out="$dest/$name-$stamp.tar.gz"
  echo "WARNING: an UNENCRYPTED backup (--unencrypted): anyone who gets this file can read .env and the accounts." >&2
  make_tar "$out" || { rm -f "$out"; echo "NOT BACKED UP: the archive could not be made (see above)" >&2; exit 3; }
else
  kind="$(bc_kind "$key")"
  out="$dest/$name-$stamp.tar.gz$(bc_ext "$kind")"
  make_tar - | bc_encrypt "$key" > "$out" || { rm -f "$out"; echo "NOT BACKED UP: the archive or its encryption failed (see above)" >&2; exit 3; }
  echo "encrypted ($kind) to the public key in $key"
fi
chmod 600 "$out"
(cd "$dest" && sha256sum "$(basename "$out")") > "$out.sha256"   # by name, so it checks wherever the two files are copied
chmod 600 "$out.sha256"
if sig="$("$py" "$project/audit_checkpoint.py" sign-file "$out.sha256" looking-glass-backup)"; then
  echo "checksum signed: $sig"
else
  echo "WARNING: the checksum is NOT signed (is openssh-client installed?); the backup itself is complete." >&2
fi
ls -l "$out" "$out.sha256" ${sig:+"$sig"}
if [ "$plain" = 1 ]; then
  echo "--- contents ---"
  tar -tzvf "$out"
else
  echo "contents: encrypted (manage/restore_check.sh --identity YOUR-PRIVATE-KEY $out lists and checks them)"
fi
