#!/usr/bin/env bash
# Verify a backup archive: checksum, .env identical to the live file, and the number of files.
# Usage: manage/verify_backup.sh [archive]   (default: the newest backup of this project in ~/backups)
set -euo pipefail
project="$(cd "$(dirname "$0")/.." && pwd)"
name="$(basename "$project")"
f="${1:-$(ls -t "$HOME/backups/$name"-*.tar.gz | head -1)}"
echo "archive: $f ($(stat -c %s "$f") bytes)"
(cd "$(dirname "$f")" && sha256sum -c "$(basename "$f").sha256")
if tar -xzOf "$f" "$name/.env" | cmp -s - "$project/.env"; then echo ".env: included and identical"; else echo ".env: MISSING OR DIFFERENT"; fi
echo "files: $(tar -tzf "$f" | grep -vc '/$')"
