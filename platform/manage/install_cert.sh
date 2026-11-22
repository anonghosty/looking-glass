#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
# Install a renewed certificate for the domain Looking Glass serves (a certificate bought for a domain): every check of
# deploy/install_cert.py first (the key is the certificate's, it names the domain, it is valid, the chain verifies);
# nothing changes unless all pass. Then the previous pair is kept in data/tls/previous-<time>/, the renewal is recorded
# in the audit log, the service reloads, and https://DOMAIN is checked with the new certificate, as a browser would.
# Run it as the service's own user (the owner of data/). The bell warns 30, 14 and 3 days before a certificate expires.
#
#   manage/install_cert.sh DOMAIN CERTIFICATE KEY [INTERMEDIATES]
#   manage/install_cert.sh --check DOMAIN CERTIFICATE KEY [INTERMEDIATES]   (only the checks)
#   manage/install_cert.sh --status                                         (the installed one, days left)
set -euo pipefail
project="$(cd "$(dirname "$0")/.." && pwd)"
py=python3
cd "$project"
case "${1:-}" in
  --status) exec "$py" deploy/install_cert.py status ;;
  --check) shift; mode=check ;;
  ""|-h|--help) sed -n '4,14p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
  *) mode=install ;;
esac
[ $# -ge 3 ] || { echo "usage: manage/install_cert.sh [--check] DOMAIN CERTIFICATE KEY [INTERMEDIATES]"; exit 2; }
args=("$mode" --domain "$1" --cert "$2" --key "$3" --by "$(id -un)")
[ -n "${4:-}" ] && args+=(--chain "$4")
"$py" deploy/install_cert.py "${args[@]}"
[ "$mode" = check ] && exit 0
bash deploy/reload.sh
port="$(grep -E '^LG_PORT=' .env 2>/dev/null | cut -d= -f2-)"; port="${port:-443}"
cab=(); [ -n "${LG_CA_BUNDLE:-}" ] && cab=(--cacert "$LG_CA_BUNDLE")
for _ in $(seq 1 30); do
  if curl -sf --max-time 10 "${cab[@]}" --resolve "$1:$port:127.0.0.1" "https://$1:$port/healthz" >/dev/null 2>&1; then
    echo "https://$1$([ "$port" = 443 ] || echo ":$port") answers with the new certificate"; exit 0
  fi
  sleep 2
done
echo "The service did not answer over HTTPS with the new certificate. The previous one is in data/tls/previous-*/:"
echo "move its cert.pem and key.pem back into data/tls/ and run deploy/reload.sh, then look at the service's log."
exit 1
