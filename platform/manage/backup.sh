#!/usr/bin/env bash
# Back up Looking Glass, INCLUDING .env (credentials), accounts, sessions, settings and certificates in data/.
# The virtualenv is left out: recreate it with deploy/install.sh (or python3 -m venv .venv && .venv/bin/pip install -r requirements.txt).
# Usage: manage/backup.sh [destination folder]     (default: ~/backups)
set -euo pipefail
project="$(cd "$(dirname "$0")/.." && pwd)"
name="$(basename "$project")"
dest="${1:-$HOME/backups}"
mkdir -p "$dest"
chmod 700 "$dest"
stamp="$(date -u +%Y%m%d-%H%M%S)UTC"
out="$dest/$name-$stamp.tar.gz"
tar -C "$(dirname "$project")" --exclude="$name/.venv" --exclude='__pycache__' -czf "$out" "$name"
chmod 600 "$out"   # contains secrets from .env
sha256sum "$out" > "$out.sha256"
chmod 600 "$out.sha256"
ls -l "$out" "$out.sha256"
echo "--- contents ---"
tar -tzvf "$out"
