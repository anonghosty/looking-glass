#!/usr/bin/env bash
# Reload the Looking Glass systemd service without sudo: stop its main process (it runs as this user) and let
# systemd's Restart=always start it again with the current code. With sudo: sudo systemctl restart <service>.
# The service name is LG_SERVICE, else the first installed of: looking-glass, threatmap.
set -u
svc="${LG_SERVICE:-}"
if [ -z "$svc" ]; then
  for s in looking-glass threatmap; do
    if [ "$(systemctl show -p LoadState --value "$s" 2>/dev/null)" = "loaded" ]; then svc="$s"; break; fi
  done
fi
[ -n "$svc" ] || { echo "no Looking Glass service installed (docs/INSTALLATION.md)"; exit 1; }
pid="$(systemctl show -p MainPID --value "$svc")"
if [ -z "$pid" ] || [ "$pid" = "0" ]; then
  echo "$svc service is not running (start it: sudo systemctl start $svc)"; exit 1
fi
port="$(systemctl show -p ExecStart --value "$svc" | grep -oE -- '--bind [^ ;]+' | grep -oE '[0-9]+$')"; port="${port:-5000}"
echo "$svc: old pid $pid"
kill "$pid"
for _ in $(seq 1 30); do
  sleep 1
  new="$(systemctl show -p MainPID --value "$svc")"
  if [ -n "$new" ] && [ "$new" != "0" ] && [ "$new" != "$pid" ]; then
    echo "new pid $new"
    break
  fi
done
for _ in $(seq 1 30); do
  # plain HTTP, or HTTPS when a certificate is in data/tls (gunicorn.conf.py); -k: the local self-signed certificate
  { curl -sf "localhost:$port/healthz" >/dev/null || curl -sfk "https://localhost:$port/healthz" >/dev/null; } && { echo "healthy"; exit 0; }
  sleep 1
done
echo "service did not become healthy (journalctl -u $svc -n 50)"; exit 1
