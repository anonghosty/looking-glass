#!/usr/bin/env bash
# Environment check: Python, venv, and whether MongoDB (MONGO_HOST / MONGO_PORT from .env) is reachable.
cd "$(dirname "$0")/.." || exit 1
python3 --version
python3 -m venv --help >/dev/null 2>&1 && echo "venv: ok" || echo "venv: missing (sudo apt install python3-venv)"
host="$(grep -E '^MONGO_HOST=' .env 2>/dev/null | cut -d= -f2-)"; host="${host:-127.0.0.1}"
port="$(grep -E '^MONGO_PORT=' .env 2>/dev/null | cut -d= -f2-)"; port="${port:-27017}"
if timeout 4 bash -c "</dev/tcp/$host/$port" 2>/dev/null; then echo "MongoDB $host:$port: reachable"; else echo "MongoDB $host:$port: NOT reachable"; fi
