#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
# Caddy in front of Looking Glass for a certificate bought for a domain (the installer's public HTTPS choice).
#
# Why: Looking Glass's own server (gunicorn, one process, 8 threads) can be held up by a few deliberately slow
# connections. Caddy takes the public port, reads every request in full under strict time limits (headers within
# 10 s), and only then hands it to Looking Glass, which listens on this computer only (127.0.0.1) and keeps serving
# HTTPS there with the same certificate. Caddy checks that certificate like a browser (no "skip verification").
#
# Caddy comes from its own signed apt repository; the signing key is accepted only with the fingerprint below
# (checked against the Ubuntu and keys.openpgp.org key servers, 2026-11-23). Caddy gets its own root-owned copy
# of the certificate in /etc/caddy/looking-glass/; it fetches no certificate itself (no outside connection),
# has no admin endpoint, staples no OCSP answer (no call to the certificate authority), and speaks HTTP/1.1 and HTTP/2
# over TCP only. Its service is locked down (systemd drop-in) and kept within memory and process limits; a firewall
# table of Looking Glass's own lets Caddy send only to this computer and limits each address to 100 connections at
# once (--conn-limit). No fingerprint: no answer names Caddy (no
# Server, Via or Alt-Svc header; its error answers carry no body naming it). An /etc/caddy/Caddyfile that Looking
# Glass did not write is never replaced (only the caddy package's untouched sample is, and it is kept aside).
#
# Run as root (sudo), from the platform folder or with --project:
#   deploy/caddy_front.sh setup  --domain D --public-port P --backend-port B [--ca-bundle FILE] [--project DIR]
#   deploy/caddy_front.sh sync   [--project DIR]    copy a renewed certificate to Caddy and restart it
#   deploy/caddy_front.sh render --domain D --public-port P --backend-port B [--ca-bundle FILE]   print the Caddyfile
#   deploy/caddy_front.sh update                    Caddy's newest version (key checked; ours kept; checked through it)
#   deploy/caddy_front.sh status                    where it points, installed / newest version, automatic updates
#   deploy/caddy_front.sh remove                    Looking Glass's Caddyfile and certificate copy (the package stays)
set -euo pipefail
KEY_FP="65760C51EDEA2017CEA2CA15155B6D79CA56EA34"
KEY_URL="https://dl.cloudsmith.io/public/caddy/stable/gpg.key"
REPO="https://dl.cloudsmith.io/public/caddy/stable/deb/debian"
KEYRING="/usr/share/keyrings/caddy-stable-archive-keyring.gpg"
LIST="/etc/apt/sources.list.d/caddy-stable.list"
PIN="/etc/apt/preferences.d/caddy-stable"
CONF="/etc/caddy/Caddyfile"
CERTS="/etc/caddy/looking-glass"
MARK="# Managed by Looking Glass (deploy/caddy_front.sh): changes here are replaced by the next setup or renewal."
DROPIN="/etc/systemd/system/caddy.service.d/looking-glass.conf"
# Caddy's security updates install by themselves: Ubuntu's automatic updates take only Ubuntu's own archives unless
# told otherwise, and Caddy faces the internet (its repository's Release file says Origin: cloudsmith/caddy/stable)
AUTOUPD="/etc/apt/apt.conf.d/52looking-glass-caddy"
# Ubuntu's /etc/nftables.conf begins with "flush ruleset": when the nftables service starts or reloads, Looking
# Glass's table is loaded again right after, so Caddy's limits never silently disappear
NFT_DROPIN="/etc/systemd/system/nftables.service.d/looking-glass-caddy.conf"

# The caddy package's own unit runs with CAP_NET_ADMIN, writes its whole environment to the log (--environ) and sees
# most of the system (systemd-analyze security: 8.8 EXPOSED). Caddy faces the internet, so it is locked down like
# Looking Glass's own service: only the right to listen on a low port, nothing writable but its own state folder,
# no new privileges, no devices, kernel settings or other users' homes, the usual system calls only.
hardening() {
  cat <<'EOF'
# Managed by Looking Glass (deploy/caddy_front.sh): Caddy faces the internet, so it runs locked down.
[Service]
ExecStart=
ExecStart=/usr/bin/caddy run --config /etc/caddy/Caddyfile
ExecReload=
AmbientCapabilities=
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/var/lib/caddy
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
ProtectClock=true
ProtectHostname=true
ProtectProc=invisible
ProcSubset=pid
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=true
RestrictRealtime=true
RestrictSUIDSGID=true
LockPersonality=true
MemoryDenyWriteExecute=true
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources
UMask=0077
# within bounds: a flood cannot make Caddy take the server's memory or processes from Looking Glass
MemoryMax=1G
TasksMax=512
# the firewall rules below, loaded (as root, the '+') before every start
ExecStartPre=+/usr/sbin/nft -f /etc/caddy/looking-glass/firewall.nft
EOF
}

# The firewall (nftables, a table of Looking Glass's own): Caddy may send only to this computer (Looking Glass on
# 127.0.0.1) and answer connections already open, so even a compromised Caddy cannot reach out; and one address may
# hold at most CONN_LIMIT connections to the public port at once (this computer itself is not counted).
firewall() {
  cat <<EOF
# Managed by Looking Glass (deploy/caddy_front.sh): loaded before Caddy starts.
table inet lg_caddy
delete table inet lg_caddy
table inet lg_caddy {
	set conn4 {
		type ipv4_addr
		flags dynamic
	}
	set conn6 {
		type ipv6_addr
		flags dynamic
	}
	chain inbound {
		type filter hook input priority filter; policy accept;
		ip saddr 127.0.0.0/8 accept
		ip6 saddr ::1 accept
		tcp dport $pport ct state new add @conn4 { ip saddr ct count over $limit } counter reject with tcp reset
		tcp dport $pport ct state new add @conn6 { ip6 saddr ct count over $limit } counter reject with tcp reset
	}
	chain outbound {
		type filter hook output priority filter; policy accept;
		meta skuid "caddy" ip daddr 127.0.0.0/8 accept
		meta skuid "caddy" ip6 daddr ::1 accept
		meta skuid "caddy" ct state established,related accept
		meta skuid "caddy" counter drop
	}
}
EOF
}

cmd="${1:-}"; [ $# -gt 0 ] && shift
project="$(cd "$(dirname "$0")/.." && pwd)"; domain=""; pport=""; bport=""; cab=""; limit=100
while [ $# -gt 0 ]; do
  case "$1" in
    --conn-limit) limit="$2"; shift 2 ;;
    --domain) domain="${2,,}"; shift 2 ;;
    --public-port) pport="$2"; shift 2 ;;
    --backend-port) bport="$2"; shift 2 ;;
    --ca-bundle) cab="$2"; shift 2 ;;
    --project) project="$2"; shift 2 ;;
    *) echo "unknown option: $1"; exit 2 ;;
  esac
done
die() { echo "caddy_front: $*" >&2; exit 1; }
need_root() { [ "$(id -u)" = 0 ] || die "run it with sudo"; }
valid() {
  [[ "$domain" =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$ ]] || die "not a domain name: $domain"
  [[ "$pport" =~ ^[0-9]+$ ]] && [ "$pport" -ge 1 ] && [ "$pport" -le 65535 ] || die "public port: $pport"
  [[ "$bport" =~ ^[0-9]+$ ]] && [ "$bport" -ge 1 ] && [ "$bport" -le 65535 ] || die "backend port: $bport"
  [ "$pport" != "$bport" ] || die "the public and the backend port must differ"
  [ -z "$cab" ] || [ -f "$cab" ] || die "CA bundle not found: $cab"
  [[ "$limit" =~ ^[0-9]+$ ]] && [ "$limit" -ge 10 ] && [ "$limit" -le 10000 ] || die "connection limit: 10 to 10000, not $limit"
}

render() {
  local trust=""
  [ -n "$cab" ] && trust=$'\n\t\t\ttls_trusted_ca_certs '"$CERTS/ca-bundle.pem"
  cat <<EOF
$MARK
{
	admin off
	auto_https off
	ocsp_stapling off
	servers {
		protocols h1 h2
		timeouts {
			read_header 10s
			read_body 30s
			write 120s
			idle 2m
		}
	}
}

https://$domain:$pport {
	tls $CERTS/cert.pem $CERTS/key.pem
	# no fingerprint: nothing in an answer names Caddy (anti-fingerprinting, like Looking Glass's own answers)
	header {
		-Server
		-Via
		-Alt-Svc
	}
	reverse_proxy https://127.0.0.1:$bport {
		header_up Host {host}
		transport http {
			tls_server_name $domain$trust
		}
	}
	# Caddy's own error answers (Looking Glass down or restarting) skip the rules above: the same, and a plain line
	handle_errors {
		header {
			-Server
			-Via
			-Alt-Svc
		}
		respond "{err.status_code} {err.status_text}" {err.status_code}
	}
}
EOF
}

copy_certs() {
  [ -f "$project/data/tls/cert.pem" ] && [ -f "$project/data/tls/key.pem" ] || die "no certificate in $project/data/tls (install it first: deploy/install_cert.py)"
  getent group caddy >/dev/null || die "the caddy group is missing (is Caddy installed?)"
  install -d -m 750 -o root -g caddy "$CERTS"
  install -m 640 -o root -g caddy "$project/data/tls/cert.pem" "$CERTS/cert.pem"
  install -m 640 -o root -g caddy "$project/data/tls/key.pem" "$CERTS/key.pem"
  [ -n "$cab" ] && [ "$cab" != "$CERTS/ca-bundle.pem" ] && install -m 640 -o root -g caddy "$cab" "$CERTS/ca-bundle.pem"
  return 0
}

install_caddy() {
  if command -v caddy >/dev/null && grep -qs "$REPO" "$LIST"; then echo "Caddy already installed from its repository: $(caddy version | head -1)"; return; fi
  local d; d="$(mktemp -d)"
  curl -1sLf "$KEY_URL" -o "$d/key.asc" || die "could not download Caddy's signing key"
  local fp; fp="$(gpg --show-keys --with-colons "$d/key.asc" 2>/dev/null | awk -F: '/^fpr/ {print $10; exit}')"
  [ "$fp" = "$KEY_FP" ] || { rm -rf "$d"; die "Caddy's signing key has an unexpected fingerprint ($fp, expected $KEY_FP): not installed"; }
  gpg --dearmor < "$d/key.asc" > "$d/keyring.gpg"; install -m 644 "$d/keyring.gpg" "$KEYRING"; rm -rf "$d"
  echo "deb [signed-by=$KEYRING] $REPO any-version main" > "$LIST"
  printf 'Package: caddy\nPin: origin dl.cloudsmith.io\nPin-Priority: 900\n' > "$PIN"
  DEBIAN_FRONTEND=noninteractive apt-get update -qq -o Dir::Etc::sourcelist="$LIST" -o Dir::Etc::sourceparts=- -o APT::Get::List-Cleanup=0
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq caddy
  echo "Caddy installed from its signed repository: $(caddy version | head -1)"
}

package_default() {  # the sample Caddyfile the caddy package ships, unchanged (dpkg's own checksum of it)
  local want; want="$(dpkg-query -W -f='${Conffiles}\n' caddy 2>/dev/null | awk -v f="$CONF" '$1 == f {print $2}')"
  [ -n "$want" ] && [ "$(md5sum < "$CONF" | cut -d' ' -f1)" = "$want" ]
}

write_conf() {
  if [ -s "$CONF" ] && ! head -1 "$CONF" | grep -qF "$MARK" && package_default; then
    cp -p "$CONF" "$CONF.package-sample"; echo "the caddy package's sample Caddyfile kept as $CONF.package-sample"
  elif [ -s "$CONF" ] && ! head -1 "$CONF" | grep -qF "$MARK"; then
    die "$CONF exists and was not written by Looking Glass: not replaced. Put Looking Glass in it yourself (docs/INSTALLATION.md, B5) or move it aside."
  fi
  local tmp; tmp="$(mktemp)"; render > "$tmp"
  caddy validate --config "$tmp" --adapter caddyfile >/dev/null 2>&1 || { caddy validate --config "$tmp" --adapter caddyfile; rm -f "$tmp"; die "Caddy refused the configuration"; }
  install -m 644 -o root -g root "$tmp" "$CONF"; rm -f "$tmp"
}

key_ok() {   # the repository key apt checks Caddy's packages with is still the one pinned above
  [ -f "$KEYRING" ] || die "Caddy's repository key ($KEYRING) is missing: run setup again"
  local fp; fp="$(gpg --show-keys --with-colons "$KEYRING" 2>/dev/null | awk -F: '/^fpr/ {print $10; exit}')"
  [ "$fp" = "$KEY_FP" ] || die "Caddy's repository key has an unexpected fingerprint (${fp:-none}, expected $KEY_FP): nothing updated"
}

auto_updates() {   # Ubuntu's automatic updates, which install Caddy's updates by themselves (the 52looking-glass-caddy file)
  if ! dpkg-query -W -f='${Status}' unattended-upgrades 2>/dev/null | grep -q 'install ok installed'; then
    echo "installing Ubuntu's automatic updates (unattended-upgrades), so Caddy's updates install by themselves"
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq unattended-upgrades \
      || echo "WARNING: unattended-upgrades could not be installed: update Caddy with deploy/caddy_front.sh update"
  fi
  local on; on="$(apt-config dump APT::Periodic::Unattended-Upgrade 2>/dev/null | sed -n 's/^APT::Periodic::Unattended-Upgrade "\(.*\)";$/\1/p' | tail -1)"
  # an administrator who switched them off is not overruled: said plainly, with what to do instead
  if [ -z "$on" ] || [ "$on" = 0 ]; then
    echo "WARNING: Ubuntu's automatic updates are switched off here, so Caddy's updates do not install by themselves."
    echo "         Switch them on (sudo dpkg-reconfigure -plow unattended-upgrades) or run deploy/caddy_front.sh update regularly."
    return 1
  fi
  echo "Caddy's updates install by themselves (Ubuntu's automatic updates are on)"
}

versions() {   # "installed candidate" ("none" when apt does not know one)
  local inst cand
  inst="$(dpkg-query -W -f='${Version}' caddy 2>/dev/null || true)"
  cand="$(apt-cache policy caddy 2>/dev/null | awk '/Candidate:/ {print $2; exit}')"
  [ "$cand" = "(none)" ] && cand=""
  echo "${inst:-none} ${cand:-none}"
}

check_front() {
  local ca=(); [ -n "$cab" ] && ca=(--cacert "$cab")
  for _ in $(seq 1 20); do
    curl -sf --max-time 10 "${ca[@]}" --resolve "$domain:$pport:127.0.0.1" "https://$domain:$pport/healthz" >/dev/null 2>&1 && { echo "https://$domain:$pport answers through Caddy"; return 0; }
    sleep 1
  done
  die "https://$domain:$pport does not answer through Caddy (journalctl -u caddy)"
}

case "$cmd" in
  render) valid; render ;;
  hardening) hardening ;;
  firewall) valid; firewall ;;
  setup)
    need_root; valid
    install_caddy
    command -v nft >/dev/null || DEBIAN_FRONTEND=noninteractive apt-get install -y -qq nftables
    copy_certs
    write_conf
    firewall > "$CERTS/firewall.nft"; chown root:root "$CERTS/firewall.nft"; chmod 600 "$CERTS/firewall.nft"
    nft -c -f "$CERTS/firewall.nft" || die "nftables refused the firewall rules"
    install -d -m 755 "$(dirname "$DROPIN")"; hardening > "$DROPIN"; chmod 644 "$DROPIN"
    install -d -m 755 "$(dirname "$NFT_DROPIN")"
    printf '%s\n' "# Managed by Looking Glass (deploy/caddy_front.sh): Caddy's firewall table again after nftables (re)loads." \
      "[Service]" "ExecStartPost=-/usr/sbin/nft -f $CERTS/firewall.nft" "ExecReload=-/usr/sbin/nft -f $CERTS/firewall.nft" > "$NFT_DROPIN"
    chmod 644 "$NFT_DROPIN"
    printf '%s\n' "// Managed by Looking Glass (deploy/caddy_front.sh): Caddy faces the internet, so its security updates install by themselves." \
      'Unattended-Upgrade::Origins-Pattern { "origin=cloudsmith/caddy/stable"; };' > "$AUTOUPD"
    chmod 644 "$AUTOUPD"
    systemctl daemon-reload
    systemctl enable caddy >/dev/null 2>&1 || true
    systemctl restart caddy
    check_front
    auto_updates || true ;;
  update)
    # Caddy only, from its signed repository, after checking the key; our Caddyfile, certificate copy, hardening and
    # firewall stay (--force-confold keeps the Caddyfile: Ubuntu's automatic updates skip a package whose shipped
    # configuration file changed, so this is also the way through when that happens)
    need_root
    head -1 "$CONF" 2>/dev/null | grep -qF "$MARK" || die "Caddy is not set up by Looking Glass here: nothing to update"
    command -v caddy >/dev/null || die "Caddy is not installed: run setup"
    key_ok
    before="$(dpkg-query -W -f='${Version}' caddy)"
    DEBIAN_FRONTEND=noninteractive apt-get update -qq -o Dir::Etc::sourcelist="$LIST" -o Dir::Etc::sourceparts=- -o APT::Get::List-Cleanup=0
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --only-upgrade -o Dpkg::Options::=--force-confold caddy
    after="$(dpkg-query -W -f='${Version}' caddy)"
    head -1 "$CONF" | grep -qF "$MARK" || die "$CONF was replaced during the update: run setup again"
    [ -f "$DROPIN" ] || die "the hardening drop-in $DROPIN is gone: run setup again"
    domain="$(sed -n 's#^https://\([^:]*\):\([0-9]*\) {#\1#p' "$CONF")"; pport="$(sed -n 's#^https://[^:]*:\([0-9]*\) {#\1#p' "$CONF")"
    [ -f "$CERTS/ca-bundle.pem" ] && cab="$CERTS/ca-bundle.pem"
    if [ "$before" != "$after" ]; then systemctl daemon-reload; systemctl restart caddy; fi
    check_front
    if [ "$before" = "$after" ]; then echo "Caddy $after is the newest version in its repository"; else echo "Caddy updated: $before -> $after"; fi
    auto_updates || true ;;
  sync)
    need_root
    head -1 "$CONF" 2>/dev/null | grep -qF "$MARK" || die "Caddy is not set up by Looking Glass here: nothing to copy"
    domain="$(sed -n 's#^https://\([^:]*\):\([0-9]*\) {#\1#p' "$CONF")"; pport="$(sed -n 's#^https://[^:]*:\([0-9]*\) {#\1#p' "$CONF")"
    [ -f "$CERTS/ca-bundle.pem" ] && cab="$CERTS/ca-bundle.pem"
    copy_certs
    systemctl restart caddy
    check_front ;;
  status)
    if head -1 "$CONF" 2>/dev/null | grep -qF "$MARK"; then
      echo "Caddy in front: $(sed -n 's#^\(https://[^ ]*\) {#\1#p' "$CONF") -> $(sed -n 's#.*reverse_proxy \(https://[^ ]*\) {#\1#p' "$CONF"), service $(systemctl is-active caddy 2>/dev/null || true)"
      read -r inst cand <<< "$(versions)"
      if [ "$cand" != none ] && [ "$inst" != "$cand" ] && dpkg --compare-versions "$inst" lt "$cand" 2>/dev/null; then
        echo "Caddy $inst installed, $cand available: sudo deploy/caddy_front.sh update"
      else echo "Caddy $inst installed (the newest apt knows of)"; fi
      on="$(apt-config dump APT::Periodic::Unattended-Upgrade 2>/dev/null | sed -n 's/^APT::Periodic::Unattended-Upgrade "\(.*\)";$/\1/p' | tail -1)"
      if [ -n "$on" ] && [ "$on" != 0 ] && [ -f "$AUTOUPD" ]; then echo "automatic updates: on"
      else echo "automatic updates: OFF for Caddy (sudo deploy/caddy_front.sh update, or switch them on)"; fi
    else echo "no Caddy set up by Looking Glass here"; fi ;;
  remove)
    need_root
    if head -1 "$CONF" 2>/dev/null | grep -qF "$MARK"; then
      systemctl stop caddy 2>/dev/null || true; systemctl disable caddy >/dev/null 2>&1 || true
      nft delete table inet lg_caddy 2>/dev/null || true
      rm -f "$CONF"; rm -rf "$CERTS"; rm -f "$DROPIN" "$NFT_DROPIN"; rmdir "$(dirname "$DROPIN")" "$(dirname "$NFT_DROPIN")" 2>/dev/null || true
      systemctl daemon-reload   # $AUTOUPD stays: the caddy package stays, so its security updates go on
      [ -f "$CONF.package-sample" ] && mv "$CONF.package-sample" "$CONF"
      echo "Looking Glass's Caddy configuration and certificate copy removed (the caddy package stays: sudo apt purge caddy)"
    else echo "no Caddy set up by Looking Glass here: nothing removed"; fi ;;
  *) sed -n '4,22p' "$0" | sed 's/^# \{0,1\}//'; exit 2 ;;
esac
