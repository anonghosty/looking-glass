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
# Exit 0: done. 1: no certificate made (nothing changed). 3: made and in use, but Caddy in front (internal) could not be
# given it (visitors get an error, 502, until sudo deploy/caddy_front.sh sync).
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
# the certificate's name: the first name given, else this machine's, never the product's (anti-fingerprinting,
# 2026-11-19: "CN=Looking Glass" let internet scanners list installations by their certificate)
cn="${1:-${hn:-localhost}}"
cn="$(printf '%s' "$cn" | tr -cd 'A-Za-z0-9.:_-' | cut -c1-64)"; cn="${cn:-localhost}"
# made beside the one in use, which is moved aside only once the new one is there: a failure leaves the service's
# certificate where it was (2026-11-26 production check: it was moved away first, so a failed openssl left none)
rm -f data/tls/new-key.pem data/tls/new-cert.pem
if ! openssl req -x509 -newkey rsa:3072 -sha256 -days 825 -nodes \
  -keyout data/tls/new-key.pem -out data/tls/new-cert.pem \
  -subj "/CN=$cn" -addext "subjectAltName=$san" -addext "extendedKeyUsage=serverAuth" 2>/dev/null \
  || [ ! -s data/tls/new-cert.pem ] || [ ! -s data/tls/new-key.pem ]; then
  rm -f data/tls/new-key.pem data/tls/new-cert.pem
  echo "The certificate could not be made (openssl failed): nothing was changed, the one in use stays."
  exit 1
fi
chmod 600 data/tls/new-key.pem; chmod 644 data/tls/new-cert.pem
if [ -f data/tls/cert.pem ]; then
  keep="data/tls/previous-$(date -u +%Y%m%d-%H%M%S)"; mkdir -p "$keep"; mv data/tls/cert.pem data/tls/key.pem "$keep"/ 2>/dev/null || true
  echo "Previous certificate kept in $keep"
fi
mv -f data/tls/new-key.pem data/tls/key.pem; mv -f data/tls/new-cert.pem data/tls/cert.pem
if [ "$(id -u)" = "0" ]; then chown -R "$owner:$owner" data/tls; fi

echo "Certificate for: ${san//,/, }"
openssl x509 -in data/tls/cert.pem -noout -enddate -fingerprint -sha256 | sed 's/^/  /'
# (|| true: without LG_PORT in .env, grep's "no match" stopped the whole script here under pipefail, before the reload)
port="$(grep -E '^LG_PORT=' .env 2>/dev/null | cut -d= -f2- || true)"; port="${port:-5000}"
# the service by the name deploy/install.sh wrote into .env (LG_SERVICE), as deploy/reload.sh finds it; else the usual
# names (2026-11-26: a service named otherwise was never reloaded, so it went on serving the old certificate)
svc="$(grep -E '^LG_SERVICE=' .env 2>/dev/null | tail -1 | cut -d= -f2- | tr -d "\"' \r" || true)"
if systemctl is-active --quiet "${svc:-looking-glass}" 2>/dev/null || { [ -z "$svc" ] && systemctl is-active --quiet threatmap 2>/dev/null; }; then
  echo "Reloading the service on HTTPS..."
  bash deploy/reload.sh
fi
if head -1 /etc/caddy/Caddyfile 2>/dev/null | grep -q 'Managed by Looking Glass' && grep -q '^# internal: ' /etc/caddy/Caddyfile 2>/dev/null; then
  # Caddy in front of this internal installation (deploy/caddy_front.sh --internal): it serves its own copy, and checks
  # Looking Glass behind it against that copy, so from the reload above until Caddy has the new one every visitor gets
  # an error (502). Given to Caddy now (audit 2026-11-27: it waited for someone to run sync by hand)
  port="$(sed -n 's#^https://:\([0-9]*\) {#\1#p' /etc/caddy/Caddyfile)"
  synced=0; why=""
  if [ ! -f deploy/caddy_front.sh ]; then why="deploy/caddy_front.sh is not in this folder"
  elif [ "$(id -u)" = 0 ] || sudo -n true 2>/dev/null || [ -t 0 ]; then
    echo "Caddy is in front: giving it the new certificate (sudo deploy/caddy_front.sh sync; sudo may ask for your password)"
    if sudo bash deploy/caddy_front.sh sync --project "$(pwd)"; then synced=1; else why="the sync failed (see above)"; fi
  else why="sudo needs a password and there is no terminal to ask in"; fi
  if [ "$synced" = 1 ]; then
    echo "Caddy has the new certificate and answers with it."
  else
    echo "Caddy is in front: give it the new certificate now:  sudo deploy/caddy_front.sh sync"
    echo "  (until then Caddy still checks Looking Glass against the old certificate, and visitors get an error, 502)"
  fi
fi
echo "Open https://localhost:$port here, or https://<one of the addresses above>:$port from other screens."
echo "Trust this certificate on every screen that opens Looking Glass (docs/INSTALLATION.md, A8), after checking that"
echo "its SHA-256 fingerprint matches the one above. Never click past a certificate warning."
# made, but Caddy in front does not have it: not a success, visitors get an error (502) until the sync (review 2026-11-28)
if [ "${synced:-1}" = 0 ]; then
  echo "NOT FINISHED: the certificate is made and Looking Glass uses it, but Caddy was not given it ($why)." >&2
  echo "  Run:  sudo deploy/caddy_front.sh sync" >&2
  exit 3
fi
