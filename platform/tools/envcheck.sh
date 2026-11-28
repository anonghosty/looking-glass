#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
# Environment check: Python, venv, and whether MongoDB (MONGO_HOST / MONGO_PORT from .env) is reachable.
cd "$(dirname "$0")/.." || exit 1
python3 --version
python3 -m venv --help >/dev/null 2>&1 && echo "venv: ok" || echo "venv: missing (sudo apt install python3-venv)"
host="$(grep -E '^MONGO_HOST=' .env 2>/dev/null | head -n1 | cut -d= -f2- | tr -d "\"' \r")"; host="${host:-127.0.0.1}"
port="$(grep -E '^MONGO_PORT=' .env 2>/dev/null | head -n1 | cut -d= -f2- | tr -d "\"' \r")"; port="${port:-27017}"
# the values from .env are data: checked, then handed to bash -c as arguments, never pasted into its command (audit
# 2026-11-27: MONGO_HOST='x;cmd' ran cmd)
if ! [[ $host =~ ^[A-Za-z0-9._:-]+$ ]] || ! [[ $port =~ ^[0-9]{1,5}$ ]]; then
  echo "MongoDB: MONGO_HOST / MONGO_PORT in .env are not a host name and a port: not checked"; exit 1
fi
if timeout 4 bash -c '</dev/tcp/"$1"/"$2"' _ "$host" "$port" 2>/dev/null; then echo "MongoDB $host:$port: reachable"; else echo "MongoDB $host:$port: NOT reachable"; fi
