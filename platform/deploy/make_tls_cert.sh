#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
# Create a self-signed HTTPS certificate for Looking Glass in data/tls/ and switch the service to HTTPS. The
# certificate is named after the first name given here, else this machine's name (never the product's).
# Run it as the user the service runs as (no sudo needed):
#     ./deploy/make_tls_cert.sh                      # this machine's name and all its addresses
#     ./deploy/make_tls_cert.sh lookingglass.local   # plus extra names / addresses
# gunicorn.conf.py serves HTTPS on the same port as soon as data/tls/cert.pem and key.pem exist; this script
# reloads the service for you. Browsers warn about a self-signed certificate until each screen trusts it: install
# data/tls/cert.pem as trusted there after checking its SHA-256 fingerprint (docs/INSTALLATION.md A8), or use a
# certificate from your organisation's CA (same file names).
set -euo pipefail
cd "$(dirname "$0")/.."
me="$(id -un)"
owner="$(stat -c '%U' .)"

if [ "$(id -u)" = "0" ]; then
  echo "No need for sudo: run it as $owner (the service's user):  ./deploy/make_tls_cert.sh"
fi
if [ -e data/tls ] && [ ! -w data/tls ]; then
  echo "data/tls belongs to $(stat -c '%U' data/tls), so $me cannot write it. Fix it once with:"
  echo "    sudo chown -R $owner:$owner $(pwd)/data/tls"
  exit 1
fi
command -v openssl >/dev/null || { echo "openssl is missing: sudo apt install openssl"; exit 1; }

# names and addresses the certificate covers: localhost, this machine, its addresses, and any given here
san="DNS:localhost,IP:127.0.0.1"
add() { case ",$san," in *",$1,"*) ;; *) san="$san,$1" ;; esac; }
hn="$(hostname)"; [ -n "$hn" ] && add "DNS:$hn"
fq="$(hostname -f 2>/dev/null || true)"; [ -n "$fq" ] && [ "$fq" != "$hn" ] && add "DNS:$fq"
for ip in $(hostname -I 2>/dev/null); do
  case "$ip" in 172.17.*|172.18.*) continue ;; esac            # docker bridges: not reachable by screens
  if [[ "$ip" == *:* ]]; then add "IP:$ip"; else add "IP:$ip"; fi
done
for h in "$@"; do
  if [[ "$h" =~ ^[0-9.]+$ || "$h" == *:* ]]; then add "IP:$h"; else add "DNS:$h"; fi
done

mkdir -p data/tls && chmod 700 data/tls
if [ -f data/tls/cert.pem ]; then
  keep="data/tls/previous-$(date -u +%Y%m%d-%H%M%S)"; mkdir -p "$keep"; mv data/tls/cert.pem data/tls/key.pem "$keep"/ 2>/dev/null || true
  echo "Previous certificate kept in $keep"
fi
# the certificate's name: the first name given, else this machine's, never the product's (anti-fingerprinting,
# 2026-11-19: "CN=Looking Glass" let internet scanners list installations by their certificate)
cn="${1:-${hn:-localhost}}"
cn="$(printf '%s' "$cn" | tr -cd 'A-Za-z0-9.:_-' | cut -c1-64)"; cn="${cn:-localhost}"
openssl req -x509 -newkey rsa:3072 -sha256 -days 825 -nodes \
  -keyout data/tls/key.pem -out data/tls/cert.pem \
  -subj "/CN=$cn" -addext "subjectAltName=$san" -addext "extendedKeyUsage=serverAuth" 2>/dev/null
chmod 600 data/tls/key.pem; chmod 644 data/tls/cert.pem
if [ "$(id -u)" = "0" ]; then chown -R "$owner:$owner" data/tls; fi

echo "Certificate for: ${san//,/, }"
openssl x509 -in data/tls/cert.pem -noout -enddate -fingerprint -sha256 | sed 's/^/  /'
port="$(grep -E '^LG_PORT=' .env 2>/dev/null | cut -d= -f2-)"; port="${port:-5000}"
if systemctl is-active --quiet looking-glass 2>/dev/null || systemctl is-active --quiet threatmap 2>/dev/null; then
  echo "Reloading the service on HTTPS..."
  bash deploy/reload.sh
fi
echo "Open https://localhost:$port here, or https://<one of the addresses above>:$port from other screens."
echo "Trust this certificate on every screen that opens Looking Glass (docs/INSTALLATION.md, A8), after checking that"
echo "its SHA-256 fingerprint matches the one above. Never click past a certificate warning."
