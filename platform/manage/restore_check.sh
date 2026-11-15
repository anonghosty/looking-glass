#!/usr/bin/env bash
# Rehearse a restore without touching this installation: check the backup's signature and checksum, unpack it into a
# temporary folder, and check what a restore needs is there and sound: .env, the accounts and roles, the settings, the
# TLS certificate, and the audit log, whose chain and signed checkpoints are checked by the same verifier an auditor
# runs. The temporary folder is removed at the end. Exits non-zero if anything a restore needs fails; an unsigned
# backup, or one with no public key to check it, fails too unless --allow-unsigned is given. An encrypted backup
# (manage/backup_crypt.sh) is opened with your private key, --identity, straight into the temporary folder.
# Usage: manage/restore_check.sh [--allow-unsigned] [--identity YOUR-PRIVATE-KEY] [archive] [public key file]
#        (defaults as manage/verify_backup.sh)
set -uo pipefail
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
f="${1:-$(ls -t "$HOME/backups/$name"-*.tar.gz "$HOME/backups/$name"-*.tar.gz.age "$HOME/backups/$name"-*.tar.gz.gpg 2>/dev/null | head -1)}"
[ -n "$f" ] && [ -f "$f" ] || { echo "No backup archive given or found in ~/backups." >&2; exit 2; }
pub="${2:-$project/data/audit_signing/signing_key.pub}"
py="$project/.venv/bin/python"; [ -x "$py" ] || py=python3
fails=0
row() { printf '  %-5s %-22s %s\n' "$1" "$2" "$3"; [ "$1" = FAIL ] && fails=$((fails + 1)); return 0; }

echo "Restore rehearsal: $f"
unsigned_state=$([ "$allow_unsigned" = 1 ] && echo WARN || echo FAIL)
unsigned_tail=$([ "$allow_unsigned" = 1 ] && echo "(accepted: --allow-unsigned)" || echo "(--allow-unsigned accepts it)")
if [ ! -f "$f.sha256.sig" ]; then row "$unsigned_state" signature "none: an older or unsigned backup $unsigned_tail"
elif [ ! -f "$pub" ]; then row "$unsigned_state" signature "not checked: no public key at $pub $unsigned_tail"
else
  state="$("$py" "$project/audit_checkpoint.py" verify-file "$f.sha256" looking-glass-backup "$pub" 2>/dev/null || true)"
  fp="$(LG_P="$project" LG_K="$pub" "$py" -c 'import os, sys; sys.path.insert(0, os.environ["LG_P"]); import audit_checkpoint as a; print(a.fingerprint(open(os.environ["LG_K"]).read()))' 2>/dev/null || echo '?')"
  [ "$state" = valid ] && row OK signature "valid (key $fp)" || row FAIL signature "$state"
fi
# the checksum file must be about THIS archive: its name, and the SHA-256 of the archive given here (security review of edd2d57)
read -r want named < "$f.sha256" 2>/dev/null || true
named="${named#\*}"
have="$(sha256sum "$f" | cut -d' ' -f1)"
if [ "$(basename "${named:-?}")" != "$(basename "$f")" ]; then row FAIL checksum "the checksum file is for $(basename "${named:-nothing}"), not for this archive"
elif [ "$have" != "${want:-}" ]; then row FAIL checksum "does not match: the archive changed or is damaged"
else row OK checksum "matches"; fi
# the newest signed backup? (a warning: restoring an older one on purpose is allowed; security review of a40f17a)
age="$("$py" "$project/audit_checkpoint.py" backup-age "$f" "${want:-}" 2>/dev/null || echo 'not checked')"
case "$age" in "the newest"*) row OK freshness "$age" ;; *) row WARN freshness "$age" ;; esac

case "$f" in
  *.age|*.gpg)
    if [ -z "$identity" ]; then
      row FAIL encryption "encrypted (${f##*.}): give your private key with --identity to rehearse the restore"
      echo "RESULT: NOT checked (the backup is encrypted)"; exit 1
    fi
    row OK encryption "encrypted (${f##*.}), opened with the key given" ;;
  *) row WARN encryption "NOT encrypted: anyone with this file can read .env and the accounts (manage/backup.sh encrypts by default)" ;;
esac
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
chmod 700 "$tmp"
if bc_decrypt "$f" "$identity" | tar -xzf - -C "$tmp" 2>/dev/null; then row OK unpack "$(find "$tmp" -type f | wc -l) files"; else row FAIL unpack "the archive cannot be opened or unpacked (wrong key?)"; echo "RESULT: NOT restorable"; exit 1; fi
r="$tmp/$name"
[ -f "$r/.env" ] && row OK ".env" "present ($(grep -c '=' "$r/.env") settings)" || row FAIL ".env" "missing: the database and mail credentials would be lost"
cd "$project" || { echo "RESULT: cannot open $project"; exit 1; }
"$py" - "$r/data" <<'EOF' || fails=$((fails + 1))
import json, os, sys
d = sys.argv[1]
bad = 0
def row(state, what, text):
    global bad
    print(f"  {state:<5} {what:<22} {text}")
    bad += state == "FAIL"
def load(name):
    with open(os.path.join(d, name), encoding="utf-8") as f:
        return json.load(f)
try:
    users = load("users.json")
    people = {n: u for n, u in (users.get("users", users) if isinstance(users, dict) else {}).items() if not str(n).startswith("lg-selftest-")}
    admins = sum(1 for u in people.values() if isinstance(u, dict) and u.get("role") == "admin")
    row("OK" if admins else "FAIL", "accounts", f"{len(people)} accounts, {admins} administrator(s)" + ("" if admins else ": nobody could sign in to manage it"))
except (OSError, ValueError) as e:
    row("FAIL", "accounts", f"users.json cannot be read ({type(e).__name__})")
for name, what in (("roles.json", "roles"), ("settings.json", "settings"), ("organisation.json", "organisation")):
    p = os.path.join(d, name)
    if not os.path.exists(p):
        row("WARN", what, f"{name} not in the backup (defaults would be used)")
        continue
    try:
        load(name); row("OK", what, f"{name} readable")
    except ValueError:
        row("FAIL", what, f"{name} is not valid JSON")
tls = os.path.join(d, "tls", "cert.pem")
row("OK" if os.path.exists(tls) else "WARN", "TLS certificate", "present" if os.path.exists(tls) else "not in the backup (a proxy may terminate TLS, or make a new one)")
key = os.path.join(d, "audit_signing", "signing_key")
row("FAIL" if os.path.exists(key) else "OK", "private signing key", "IN THE BACKUP: it should be left out" if os.path.exists(key)
    else "left out, as it should be (the restored installation makes a new one)")
sys.path.insert(0, os.getcwd())
import audit_verifier
r = audit_verifier.check(d)
cp = r["checkpoints"]
row("OK" if r["ok"] else "FAIL", "audit log", (f"chain whole: {r['entries']:,} entries, head entry {r['head_entry']}" if r["ok"]
                                               else f"BROKEN at entry {r['break']['entry']}: {r['break']['what']}"))
if cp["count"]:
    sigs = ", ".join(f"{v} {k}" for k, v in sorted(cp["signatures"].items()))
    row("OK" if not cp["problems"] else "FAIL", "audit checkpoints", f"{cp['count']} ({cp['matched']} found at their entry; signatures: {sigs})")
sys.exit(1 if bad else 0)
EOF
echo
if [ "$fails" -eq 0 ]; then echo "RESULT: restorable. To restore: see 'Backups' in docs/OPERATIONS.md."; else echo "RESULT: NOT restorable as it is ($fails problem(s) above)"; fi
[ "$fails" -eq 0 ]
