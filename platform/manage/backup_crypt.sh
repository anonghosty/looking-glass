#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
# Encryption of backups (sourced by manage/backup.sh, verify_backup.sh and restore_check.sh; review of d82a436: a backup
# holds .env with the database passwords and API keys, the accounts, the sessions, the audit log and the TLS key).
#
# The server keeps only a PUBLIC key; the private key stays with you, off the server. A backup copied off the server, or
# the server itself if it is broken into, cannot read a backup. Two kinds of key are accepted:
#   age (https://age-encryption.org): a file with one or more recipients "age1..." (age-keygen -y your-key.txt);
#   GnuPG: an exported public key ("-----BEGIN PGP PUBLIC KEY BLOCK-----", gpg --export --armor YOU > key.asc).
# Where: BACKUP_PUBLIC_KEY in .env (a path), else data/backup_public_key.
#
# bc_pubkey PROJECT          -> the public key file, or nothing
# bc_kind FILE               -> age | gpg | unknown
# bc_encrypt KEYFILE         stdin -> stdout, encrypted to the key (refuses an unknown key)
# bc_decrypt FILE IDENTITY   -> the archive (gzip tar) on stdout: IDENTITY is your age key file, or your GnuPG secret
#                               key (exported, --armor); a key with a passphrase asks for it on the terminal
# bc_ext KIND                -> .age | .gpg
bc_pubkey() {
  local project="$1" p=""
  p="$(grep -E '^BACKUP_PUBLIC_KEY=' "$project/.env" 2>/dev/null | tail -1 | cut -d= -f2- | tr -d '"'"'" )"
  [ -n "$p" ] && [ "${p:0:1}" != "/" ] && p="$project/$p"
  [ -z "$p" ] && p="$project/data/backup_public_key"
  [ -s "$p" ] && echo "$p"
}
# bc_clean FILE -> a private temporary copy of a key file as plain UTF-8 lines: a key saved on Windows may start with a
# byte-order mark, be UTF-16 (PowerShell 5's ">" and Out-File) and end its lines with CR LF; age refuses all of that
bc_clean() {
  local out; out="$(mktemp)"; chmod 600 "$out"
  python3 - "$1" "$out" <<'EOF'
import sys
b = open(sys.argv[1], "rb").read()
t = b.decode("utf-16") if b[:2] in (b"\xff\xfe", b"\xfe\xff") else b.decode("utf-8-sig", "replace")
open(sys.argv[2], "w", encoding="utf-8").write(t.replace("\r\n", "\n").replace("\r", "\n"))
EOF
  echo "$out"
}
bc_kind() {
  local c rc; c="$(bc_clean "$1")"; bc_kind_clean "$c"; rc=$?; rm -f "$c"; return $rc
}
bc_kind_clean() {
  if grep -qE '^[[:space:]]*age1[0-9a-z]+' "$1" 2>/dev/null; then echo age
  elif grep -q 'BEGIN PGP PUBLIC KEY BLOCK' "$1" 2>/dev/null || grep -q 'BEGIN PGP PRIVATE KEY BLOCK' "$1" 2>/dev/null; then echo gpg
  elif grep -qE '^AGE-SECRET-KEY-' "$1" 2>/dev/null; then echo age
  else echo unknown; fi
}
bc_ext() { [ "$1" = age ] && echo .age || echo .gpg; }
bc_encrypt() {
  local key="$1" kind clean rc
  clean="$(bc_clean "$key")"
  kind="$(bc_kind_clean "$clean")"
  case "$kind" in
    age)
      if command -v age >/dev/null; then age -R "$clean"; rc=$?
      else echo "age is not installed (sudo apt install age), or give a GnuPG public key instead" >&2; rc=2; fi ;;
    gpg)
      if command -v gpg >/dev/null; then
        local home; home="$(mktemp -d)"; chmod 700 "$home"
        # a throwaway keyring: nothing is added to this user's own; the key given is the only recipient
        gpg --homedir "$home" --batch --quiet --no-tty --trust-model always --recipient-file "$clean" --output - --encrypt
        rc=$?; rm -rf "$home"
      else echo "gpg is not installed (sudo apt install gnupg)" >&2; rc=2; fi ;;
    *) echo "$key is neither an age recipient (age1...) nor a GnuPG public key" >&2; rc=2 ;;
  esac
  rm -f "$clean"
  return $rc
}
bc_decrypt() {
  local f="$1" id="$2"
  case "$f" in
    *.age)
      command -v age >/dev/null || { echo "age is not installed (sudo apt install age)" >&2; return 2; }
      local cid rc; cid="$(bc_clean "$id")"                 # a private key saved on Windows too
      age -d -i "$cid" "$f"; rc=$?; rm -f "$cid"; return $rc ;;
    *.gpg)
      local home; home="$(mktemp -d)"; chmod 700 "$home"
      gpg --homedir "$home" --batch --quiet --no-tty --import "$id" 2>/dev/null
      gpg --homedir "$home" --quiet --pinentry-mode loopback --output - --decrypt "$f"
      local rc=$?; rm -rf "$home"; return $rc ;;
    *) cat "$f" ;;     # an unencrypted backup (made with --unencrypted, or before backups were encrypted)
  esac
}
