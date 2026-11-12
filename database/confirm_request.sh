#!/usr/bin/env bash
# Confirm, on the server, a Looking Glass Settings -> Workers request that makes the pipeline less strict
# (sender check lowered or another signer, certificate check off, a new API key, a held-back report released).
# Run it on the pipeline's own account:
#   ./confirm_request.sh          list what waits
#   ./confirm_request.sh <id>     show one and confirm it
set -euo pipefail
cd "$(dirname "$(readlink -f "$0")")"
PY=.venv/bin/python
[ -x "$PY" ] || PY=python3
exec "$PY" -I worker_settings.py "$@"
