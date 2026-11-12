#!/usr/bin/env bash
# Looking Glass installer: the Shadowserver database pipeline and the Looking Glass platform, in one go.
#
#   ./install.sh                     guided installation (dialog windows; asks everything it needs)
#   ./install.sh --text              the same questions as plain text prompts
#   ./install.sh --answers FILE      unattended: answers from FILE (KEY=value lines, see install.answers.example);
#                                    questions it does not answer are asked, or take their default with --yes
#   ./install.sh --yes               accept the default of every question that has one
#
# Run it as the ordinary user who will own and run Looking Glass (not root). It asks for your sudo password once,
# for the system packages, MongoDB and the services. Passwords you type are written only to the two .env files
# (mode 600); they are never shown, logged or put on a command line. A log of the installation (without secrets)
# is kept in install-logs/.
set -Eeuo pipefail

ROOT="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
DB_DIR="$ROOT/database"
PF_DIR="$ROOT/platform"
VERSION="1.0"
TITLE="Looking Glass installer $VERSION"
mkdir -p "$ROOT/install-logs"; chmod 700 "$ROOT/install-logs"
LOG="$ROOT/install-logs/install-$(date +%Y%m%d-%H%M%S).log"
: > "$LOG"; chmod 600 "$LOG"

# ---------------------------------------------------------------------------------------------------------- options
UI=auto; ANSWERS=""; ASSUME_YES=0
while [ $# -gt 0 ]; do
  case "$1" in
    --text) UI=text; shift ;;
    --answers) ANSWERS="${2:?--answers needs a file}"; shift 2 ;;
    --yes|-y) ASSUME_YES=1; shift ;;
    -h|--help) sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option $1 (./install.sh --help)"; exit 1 ;;
  esac
done
UI_WANTED="$UI"; UI=text          # plain text until the requirements (whiptail among them) are in place
INTERACTIVE=1; { [ -t 0 ] && [ -t 1 ]; } || INTERACTIVE=0

# answers file: KEY=value lines, read literally (never executed)
declare -A ANS=()
if [ -n "$ANSWERS" ]; then
  [ -r "$ANSWERS" ] || { echo "cannot read $ANSWERS"; exit 1; }
  while IFS= read -r line || [ -n "$line" ]; do
    line="${line%$'\r'}"
    case "$line" in ''|'#'*) continue ;; esac
    [[ $line == *=* ]] || continue
    k="${line%%=*}"; v="${line#*=}"; k="${k//[[:space:]]/}"
    if [[ ${#v} -ge 2 && ( ( $v == \"*\" ) || ( $v == \'*\' ) ) ]]; then v="${v:1:${#v}-2}"; fi
    ANS["$k"]="$v"
  done < "$ANSWERS"
fi

# ---------------------------------------------------------------------------------------------------------- look
if [ -t 1 ]; then
  B=$'\e[1m'; D=$'\e[2m'; R=$'\e[0m'; RED=$'\e[31m'; GRN=$'\e[32m'; YEL=$'\e[33m'; CYN=$'\e[36m'; MAG=$'\e[35m'
else B=; D=; R=; RED=; GRN=; YEL=; CYN=; MAG=; fi
# whiptail colours: dark, with the platform's violet accent
export NEWT_COLORS='
root=white,black
window=white,black
border=magenta,black
shadow=black,black
title=brightmagenta,black
textbox=white,black
button=black,magenta
actbutton=black,brightmagenta
compactbutton=white,black
checkbox=white,black
actcheckbox=black,magenta
listbox=white,black
actlistbox=black,magenta
sellistbox=black,magenta
actsellistbox=black,brightmagenta
entry=white,black
disentry=gray,black
label=white,black
emptyscale=,black
fullscale=,magenta
helpline=white,black
roottext=brightmagenta,black
'
banner() {
  [ "$UI" = text ] || return 0
  printf '%s' "$MAG$B"
  cat <<'EOF'

   ╭─────────────────────────────────────────────────────────────╮
   │   ◉  L O O K I N G   G L A S S                              │
   │      Shadowserver threat replay for African CSIRTs          │
   ╰─────────────────────────────────────────────────────────────╯
EOF
  printf '%s\n' "$R"
}
log() { printf '%s %s\n' "$(date +%H:%M:%S)" "$*" >> "$LOG"; }
say() { log "$*"; [ "$UI" = text ] && printf '%s\n' "$*"; return 0; }

# ---------------------------------------------------------------------------------------------------------- dialogs
# Every question has a KEY: an answer in the answers file wins; --yes takes the default; otherwise ask.
# The answers of the last run (never passwords or tokens) are offered as the defaults of a new run.
H=20; W=76
fit_windows() {  # wider windows on wide terminals (text wraps less), never wider than the terminal
  local cols; cols=$(tput cols 2>/dev/null || echo 80)
  W=$(( cols >= 104 ? 96 : cols - 6 )); [ "$W" -lt 60 ] && W=60
  local rows; rows=$(tput lines 2>/dev/null || echo 24)
  H=$(( rows >= 30 ? 24 : rows - 4 )); [ "$H" -lt 16 ] && H=16
  return 0
}
LAST="$ROOT/install-logs/last.answers"
declare -A PREV=() MEM=()
if [ -r "$LAST" ]; then
  while IFS= read -r line || [ -n "$line" ]; do [[ $line == *=* ]] && PREV["${line%%=*}"]="${line#*=}"; done < "$LAST"
fi
remember() { case "$1" in *PASSWORD*|*TOKEN*|*SECRET*|KEEP_*) ;; *) MEM["$1"]="$2" ;; esac; }
save_answers() {
  local k; : > "$LAST"; chmod 600 "$LAST"
  for k in "${!MEM[@]}"; do printf '%s=%s\n' "$k" "${MEM[$k]}" >> "$LAST"; done
}
prev() { [ -n "${PREV[$1]+x}" ] && printf '%s' "${PREV[$1]}" || printf '%s' "${2-}"; }
_pre() {  # KEY DEFAULT -> sets REPLY and returns 0 when answered without asking
  local k="$1" def="${2-}"
  if [ -n "${ANS[$k]+x}" ]; then REPLY="${ANS[$k]}"; log "answer $k (from file)"; return 0; fi
  if [ "$ASSUME_YES" = 1 ] && [ -n "$def" ]; then REPLY="$def"; log "answer $k = default"; return 0; fi
  if [ "$INTERACTIVE" = 0 ]; then
    [ -n "$def" ] && { REPLY="$def"; return 0; }
    echo "No answer for $k (answers file) and no terminal to ask in." >&2; exit 1
  fi
  return 1
}
cancelled() { save_answers; clear 2>/dev/null || true; echo "Installation cancelled. Your answers (not passwords) are offered again next time. Nothing after this point was changed. Log: $LOG"; exit 130; }

msg() {  # TITLE TEXT
  [ "$UI" = dialog ] && fit_windows
  if [ "$INTERACTIVE" = 0 ] || [ "$ASSUME_YES" = 1 ]; then log "[$1] $2"; [ "$UI" = text ] && printf '\n%s%s%s\n%s\n' "$B" "$1" "$R" "$2"; return 0; fi
  if [ "$UI" = dialog ]; then whiptail --title " $1 " --backtitle "$TITLE" --msgbox "$2" $H $W
  else printf '\n%s── %s ──%s\n%s\n' "$MAG$B" "$1" "$R" "$2"; read -rp "${D}Press Enter to continue${R} " _; fi
}
ask_yesno() {  # KEY TITLE TEXT DEFAULT(yes|no) -> REPLY=yes|no
  [ "$UI" = dialog ] && fit_windows
  local k="$1" t="$2" x="$3" def; def="$(prev "$1" "${4:-yes}")"
  if _pre "$k" "$def"; then REPLY="${REPLY,,}"; [[ $REPLY == y* || $REPLY == true || $REPLY == 1 ]] && REPLY=yes || REPLY=no; return; fi
  if [ "$UI" = dialog ]; then
    local o=(); [ "$def" = no ] && o=(--defaultno)
    if whiptail --title " $t " --backtitle "$TITLE" "${o[@]}" --yesno "$x" $H $W; then REPLY=yes; else REPLY=no; fi
  else
    printf '\n%s%s%s\n%s\n' "$B" "$t" "$R" "$x"
    local a; read -rp "  [${def}] yes/no: " a; a="${a:-$def}"; [[ ${a,,} == y* ]] && REPLY=yes || REPLY=no
  fi
  log "answer $k = $REPLY"; remember "$k" "$REPLY"
}
ask_input() {  # KEY TITLE TEXT DEFAULT [validator]
  [ "$UI" = dialog ] && fit_windows
  local k="$1" t="$2" x="$3" def="${4-}" val="${5-}"
  [[ $k == *TOKEN* ]] || def="$(prev "$k" "$def")"
  while :; do
    if ! _pre "$k" "$def"; then
      if [ "$UI" = dialog ]; then
        REPLY=$(whiptail --title " $t " --backtitle "$TITLE" --inputbox "$x" $H $W "$def" 3>&1 1>&2 2>&3) || cancelled
      else
        printf '\n%s%s%s\n%s\n' "$B" "$t" "$R" "$x"; read -rp "  [${def}]: " REPLY; REPLY="${REPLY:-$def}"
      fi
    fi
    REPLY="${REPLY#"${REPLY%%[![:space:]]*}"}"; REPLY="${REPLY%"${REPLY##*[![:space:]]}"}"
    if [ -n "$val" ] && ! err=$("$val" "$REPLY"); then
      if [ -n "${ANS[$k]+x}" ] || [ "$INTERACTIVE" = 0 ]; then echo "Answer for $k is not valid: $err" >&2; exit 1; fi
      msg "Please check" "$err"; continue
    fi
    if [[ $k == *TOKEN* ]]; then log "answer $k ($([ -n "$REPLY" ] && echo given || echo empty))"; else log "answer $k = ${REPLY:0:60}"; remember "$k" "$REPLY"; fi
    return 0
  done
}
ask_secret() {  # KEY TITLE TEXT [allow-empty]  -> REPLY (never logged)
  [ "$UI" = dialog ] && fit_windows
  local k="$1" t="$2" x="$3" empty="${4:-no}" a b
  if [ -n "${ANS[$k]+x}" ]; then REPLY="${ANS[$k]}"; log "answer $k (secret, from file)"; return 0; fi
  if [ "$INTERACTIVE" = 0 ] || [ "$ASSUME_YES" = 1 ]; then
    [ "$empty" = yes ] && { REPLY=""; return 0; }
    echo "No answer for $k (a secret must be given in the answers file or typed)." >&2; exit 1
  fi
  while :; do
    if [ "$UI" = dialog ]; then
      a=$(whiptail --title " $t " --backtitle "$TITLE" --passwordbox "$x" $H $W 3>&1 1>&2 2>&3) || cancelled
    else
      printf '\n%s%s%s\n%s\n' "$B" "$t" "$R" "$x"; read -rsp "  (hidden): " a; echo
    fi
    if [ -z "$a" ]; then [ "$empty" = yes ] && { REPLY=""; log "answer $k (secret, empty)"; return 0; }; msg "Please check" "This cannot be empty."; continue; fi
    if [ "$UI" = dialog ]; then
      b=$(whiptail --title " $t " --backtitle "$TITLE" --passwordbox "Type it again to confirm." 9 $W 3>&1 1>&2 2>&3) || cancelled
    else read -rsp "  again: " b; echo; fi
    [ "$a" = "$b" ] && { REPLY="$a"; log "answer $k (secret, typed)"; return 0; }
    msg "Please check" "The two entries differ. Try again."
  done
}
ask_menu() {  # KEY TITLE TEXT DEFAULT tag item [tag item...]
  [ "$UI" = dialog ] && fit_windows
  local k="$1" t="$2" x="$3" def; def="$(prev "$1" "$4")"; shift 4
  if _pre "$k" "$def"; then
    local ok=0 i; for ((i = 1; i <= $#; i += 2)); do [ "${!i}" = "$REPLY" ] && ok=1; done
    [ $ok = 1 ] || { echo "Answer for $k must be one of the menu choices, not '$REPLY'." >&2; exit 1; }
    remember "$k" "$REPLY"; return 0
  fi
  if [ "$UI" = dialog ]; then
    local n=$(( $# / 2 )); [ $n -gt 12 ] && n=12
    REPLY=$(whiptail --title " $t " --backtitle "$TITLE" --default-item "$def" --menu "$x" $(( n + 11 )) $W $n "$@" 3>&1 1>&2 2>&3) || cancelled
  else
    printf '\n%s%s%s\n%s\n' "$B" "$t" "$R" "$x"
    local tags=() i=1
    while [ $# -gt 0 ]; do printf '   %s%2d)%s %s\n' "$CYN" "$i" "$R" "$2"; tags+=("$1"); shift 2; i=$((i + 1)); done
    local d=1 j; for j in "${!tags[@]}"; do [ "${tags[$j]}" = "$def" ] && d=$((j + 1)); done
    while :; do
      read -rp "  choice [$d]: " a; a="${a:-$d}"
      if [[ $a =~ ^[0-9]+$ ]] && [ "$a" -ge 1 ] && [ "$a" -le ${#tags[@]} ]; then REPLY="${tags[$((a - 1))]}"; break; fi
      for j in "${!tags[@]}"; do [ "${tags[$j],,}" = "${a,,}" ] && { REPLY="${tags[$j]}"; break 2; }; done
    done
  fi
  log "answer $k = $REPLY"; remember "$k" "$REPLY"
}

# ---------------------------------------------------------------------------------------------------------- progress
GAUGE_OPEN=0; PCT=0; GAUGE_MSG="Starting..."; GAUGE_PID=""
gauge_open() {
  if [ "$UI" = dialog ] && [ "$INTERACTIVE" = 1 ]; then
    fit_windows
    exec 3> >(exec whiptail --title " Installing " --backtitle "$TITLE" --gauge "$GAUGE_MSG" 9 $W "$PCT")
    GAUGE_PID=$!
    GAUGE_OPEN=1
  fi
}
gauge() {  # PERCENT MESSAGE
  PCT="$1"; GAUGE_MSG="$2"; log "== [$1%] $2"
  if [ $GAUGE_OPEN = 1 ]; then printf 'XXX\n%s\n%s\nXXX\n' "$1" "$2" >&3
  else printf '\n%s[%3s%%]%s %s%s%s\n' "$CYN" "$1" "$R" "$B" "$2" "$R"; fi
}
gauge_close() { if [ $GAUGE_OPEN = 1 ]; then exec 3>&-; GAUGE_OPEN=0; sleep 0.3; fi; }
# the terminal was resized: draw the progress window again at the new size, same percentage and step
gauge_redraw() {
  [ $GAUGE_OPEN = 1 ] || return 0
  exec 3>&-; GAUGE_OPEN=0
  [ -n "$GAUGE_PID" ] && { wait "$GAUGE_PID" 2>/dev/null || true; }
  clear; gauge_open
  return 0
}
trap 'gauge_redraw' WINCH
# run a command in the background and wait for it in a way a resize can interrupt (to redraw), then its exit code
bg_wait() {
  "$@" >> "$LOG" 2>&1 < /dev/null &
  local pid=$! rc
  while :; do
    wait "$pid" && rc=0 || rc=$?
    kill -0 "$pid" 2>/dev/null || return "$rc"   # finished: rc is its exit code (else a resize interrupted wait)
  done
}
run() {  # LABEL command...   output to the log; on failure show the end of the log and stop
  local label="$1"; shift
  log "\$ $label"
  if bg_wait "$@"; then [ $GAUGE_OPEN = 1 ] || printf '       %s✔%s %s\n' "$GRN" "$R" "$label"; return 0; fi
  local rc=$?
  gauge_close
  fail "$label failed (exit code $rc)."
}
fail() {
  local tailtxt; tailtxt="$(tail -n 25 "$LOG" | cut -c1-110)"
  if [ "$UI" = dialog ] && [ "$INTERACTIVE" = 1 ]; then
    whiptail --title " Installation stopped " --backtitle "$TITLE" --msgbox "$1\n\nLast lines of the log:\n\n$tailtxt\n\nFull log: $LOG" $H $W
  else printf '\n%sInstallation stopped:%s %s\n%s\n\nFull log: %s\n' "$RED$B" "$R" "$1" "$tailtxt" "$LOG"; fi
  exit 1
}
trap 'gauge_close; [ -n "${SUDO_KEEPALIVE:-}" ] && kill "$SUDO_KEEPALIVE" 2>/dev/null; [ ${#MEM[@]} -gt 0 ] && save_answers 2>/dev/null; true' EXIT
# any unexpected failure is reported (never a silent exit)
trap 'rc=$?; log "unexpected error (exit $rc) at line $LINENO: $BASH_COMMAND"; gauge_close; fail "Unexpected error at line $LINENO of install.sh (exit code $rc). Please report it with the log."' ERR

# ---------------------------------------------------------------------------------------------------------- helpers
env_set() {  # FILE KEY VALUE   (value passed through the environment, never on a command line)
  K="$2" V="$3" python3 - "$1" <<'EOF'
import os, re, sys
p, k, v = sys.argv[1], os.environ["K"], os.environ["V"]
text = open(p, encoding="utf-8").read() if os.path.exists(p) else ""
line = f"{k}={v}"
if re.search(rf"^{re.escape(k)}=.*$", text, flags=re.M):
    text = re.sub(rf"^{re.escape(k)}=.*$", lambda m: line, text, count=1, flags=re.M)
else:
    text = text.rstrip("\n") + "\n" + line + "\n"
fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(fd, "w", encoding="utf-8") as f:
    f.write(text)
os.chmod(p, 0o600)
EOF
}
env_get() { grep -E "^$2=" "$1" 2>/dev/null | tail -n1 | cut -d= -f2- || true; }
gen_password() { python3 -c 'import secrets; print(secrets.token_urlsafe(24))'; }
v_port() { [[ $1 =~ ^[0-9]+$ ]] && [ "$1" -ge 1 ] && [ "$1" -le 65535 ] || { echo "A port is a number from 1 to 65535."; return 1; }; }
v_nonempty() { [ -n "$1" ] || { echo "This cannot be empty."; return 1; }; }
in_use() { ss -Hltn "sport = :$1" 2>/dev/null | grep -q .; }
v_mongo_port() {  # free, or already our own MongoDB (a re-run)
  v_port "$1" || return 1
  in_use "$1" || return 0
  if systemctl is-active --quiet mongod 2>/dev/null && grep -qE "^[[:space:]]*port:[[:space:]]*$1[[:space:]]*$" /etc/mongod.conf 2>/dev/null; then return 0; fi
  echo "Port $1 is already used by another program$([ $IS_WSL = 1 ] && echo ' (on WSL this can be another Linux distribution or Windows)'). Choose a free port, for example 27018."
  return 1
}
v_lg_port() {  # free, or already a Looking Glass service (a re-run)
  v_port "$1" || return 1
  in_use "$1" || return 0
  local s; for s in looking-glass threatmap; do
    systemctl show -p ExecStart --value "$s" 2>/dev/null | grep -qE -- "--bind [^ ]*:$1( |;|$)" && [ "$(stat -c %U "$PF_DIR")" = "$(id -un)" ] && [ "$s" = looking-glass ] && return 0
  done
  echo "Port $1 is already used by another program$([ $IS_WSL = 1 ] && echo ' (on WSL this can be another Linux distribution or Windows)'). Choose a free port, for example 5088."
  return 1
}
v_time() { [[ $1 == off || $1 =~ ^([01][0-9]|2[0-3]):[0-5][0-9]$ ]] || { echo "Use HH:MM on the 24-hour clock (for example 06:30), or off."; return 1; }; }
v_guid() { [[ $1 =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]] || { echo "The client ID looks like 1a2b3c4d-1234-5678-9abc-0123456789ab (Overview page of the app)."; return 1; }; }
v_keyfile() {
  local p="${1/#\~/$HOME}"
  [ -r "$p" ] || { echo "Cannot read $1 (give the full path of the downloaded JSON key file)."; return 1; }
  python3 - "$p" <<'EOF' || return 1
import json, sys
try:
    d = json.load(open(sys.argv[1]))
    assert d.get("type") == "service_account" and d.get("private_key") and d.get("client_email")
except Exception:
    print("This is not a Google service account JSON key (it must contain type service_account and a private_key).")
    sys.exit(1)
EOF
}
v_days() { [[ $1 =~ ^[0-9]+$ ]] && [ "$1" -ge 1 ] && [ "$1" -le 60 ] || { echo "A number of days from 1 to 60."; return 1; }; }
v_user() { [[ $1 =~ ^[A-Za-z][A-Za-z0-9_.-]{2,63}$ ]] || { echo "3 to 64 letters, digits, dot, dash or underscore, starting with a letter."; return 1; }; }
v_host() {
  [[ $1 =~ ^[0-9]+$ ]] && { echo "$1 looks like a port number. Type the server's name (for example mail.example.org or 10.0.0.5); the port is set separately or automatically."; return 1; }
  [[ $1 == *://* || $1 == */* ]] && { echo "Type only the server's name, without https:// or a path (for example mail.example.org)."; return 1; }
  [[ $1 =~ ^[A-Za-z0-9.-]+$ || $1 =~ ^[0-9A-Fa-f:]+$ ]] || { echo "A host name or IP address, for example 10.0.0.5 or mail.example.org."; return 1; }
}
v_networks() { python3 - "$1" <<'EOF' || return 1
import ipaddress, sys
items = [x.strip() for x in sys.argv[1].split(",") if x.strip()]
if not items:
    print("Give at least one address or range, for example 10.20.0.0/24, 192.168.1.40"); sys.exit(1)
for x in items:
    try:
        ipaddress.ip_network(x, strict=False)
    except ValueError:
        print(f"'{x}' is not an address or range (like 10.20.0.0/24)."); sys.exit(1)
EOF
}

# ======================================================================================================================
# 0. Checks before anything is asked
# ======================================================================================================================
banner
[ "$(id -u)" != 0 ] || { echo "Run ./install.sh as the ordinary user who will run Looking Glass (not root, not with sudo)."; exit 1; }
[ -d "$DB_DIR" ] && [ -d "$PF_DIR" ] || { echo "Run it from the Looking Glass folder (it needs database/ and platform/ next to it)."; exit 1; }
. /etc/os-release 2>/dev/null || true
case "${ID:-}:${ID_LIKE:-}" in
  ubuntu:*|debian:*|*:*debian*|*:*ubuntu*) ;;
  *) echo "Looking Glass installs on Ubuntu 24.04+ or Debian 13+ (this is ${PRETTY_NAME:-unknown})."; exit 1 ;;
esac
IS_WSL=0; grep -qi microsoft /proc/version 2>/dev/null && IS_WSL=1
if [ ! -d /run/systemd/system ]; then
  if [ $IS_WSL = 1 ]; then
    echo "systemd is not running in this WSL distribution. Turn it on, then run ./install.sh again:"
    echo "  1. sudo tee /etc/wsl.conf <<< \$'[boot]\nsystemd=true'"
    echo "  2. in Windows PowerShell:  wsl --shutdown     then open Ubuntu again"
  else echo "Looking Glass needs systemd."; fi
  exit 1
fi
log "installer $VERSION on ${PRETTY_NAME:-?}, WSL=$IS_WSL, user $(id -un), folder $ROOT"

# ======================================================================================================================
# 0b. Requirements: checked and installed before the windows open
# ======================================================================================================================
REQ_PKGS=(python3 python3-venv python3-pip curl openssl ca-certificates gnupg cron iso-codes util-linux whiptail iproute2 fonts-dejavu-core)
REQ_WHY=("Python 3" "Python environments (venv)" "Python packages (pip)" "downloads (curl)" "certificates (OpenSSL)"
         "trusted certificates" "MongoDB's signing key (gnupg)" "scheduled runs (cron)" "country names (iso-codes)"
         "locking (util-linux)" "the installer's windows (whiptail)" "port checks (iproute2)" "report fonts (DejaVu)")
pkg_ok() { dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q 'install ok installed'; }
row() { printf '  %b  %-34s %s\n' "$1" "$2" "$3"; }
OKM="${GRN}✔${R}"; NOM="${RED}✘${R}"; WRN="${YEL}!${R}"; INF="${CYN}•${R}"
requirements() {  # prints the checklist; sets MISSING
  MISSING=()
  printf '\n%sRequirements%s\n' "$B" "$R"
  row "$OKM" "Operating system" "${PRETTY_NAME:-?}$([ $IS_WSL = 1 ] && echo ' (WSL)')"
  row "$OKM" "systemd" "running"
  local i
  for i in "${!REQ_PKGS[@]}"; do
    local why="${REQ_WHY[$i]:-${REQ_PKGS[$i]}}"     # a package added without a description still shows
    if pkg_ok "${REQ_PKGS[$i]}"; then row "$OKM" "$why" "${REQ_PKGS[$i]}"
    else row "$NOM" "$why" "${REQ_PKGS[$i]}: missing, will be installed"; MISSING+=("${REQ_PKGS[$i]}"); fi
  done
  if command -v python3 >/dev/null; then
    local pv; pv=$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')
    if python3 -c 'import sys; sys.exit(sys.version_info < (3, 12))'; then row "$OKM" "Python version" "$pv (3.12 or newer needed)"
    else row "$NOM" "Python version" "$pv: Looking Glass needs 3.12 or newer (Ubuntu 24.04+ / Debian 13+)"; PY_OLD=1; fi
  fi
  detect_mongo
  if [ "$MDB_INSTALLED" = 1 ]; then
    row "$OKM" "MongoDB" "$MDB_VERSION installed, $([ "$MDB_ACTIVE" = 1 ] && echo "running on port $MDB_PORT" || echo "NOT running (port $MDB_PORT)")$([ "$MDB_AUTH" = 1 ] && echo ', login required' || echo ', NO login required')$([ "$MDB_MANAGED" = 1 ] && echo ' (set up by Looking Glass)')"
  elif [ -n "$MDB_OTHER" ]; then
    row "$INF" "MongoDB" "not installed as a service, but port${MDB_OTHER} answers (Docker? another system?)"
  else
    row "$INF" "MongoDB" "not installed: installed later, if you choose 'MongoDB on this computer'"
  fi
  local free; free=$(df -Pk "$ROOT" | awk 'NR==2 {print int($4/1048576)}')
  if [ "$free" -ge 5 ]; then row "$OKM" "Free disk space" "${free} GB"; else row "$WRN" "Free disk space" "${free} GB (5 GB or more recommended)"; fi
  local mem; mem=$(awk '/MemTotal/ {print int($2/1048576 + 0.5)}' /proc/meminfo)
  if [ "$mem" -ge 4 ]; then row "$OKM" "Memory" "${mem} GB"; else row "$WRN" "Memory" "${mem} GB (4 GB or more recommended)"; fi
  if curl -fsS --max-time 10 -o /dev/null https://pypi.org/simple/ 2>/dev/null \
     || timeout 10 bash -c '</dev/tcp/pypi.org/443' 2>/dev/null; then row "$OKM" "Internet" "reachable"
  else row "$NOM" "Internet" "pypi.org not reachable: the installer needs internet access (proxy? DNS?)"; NO_NET=1; fi
  return 0
}
# MongoDB already here? (installed service, its port, login, who set it up; or a MongoDB answering on a usual port)
detect_mongo() {
  MDB_INSTALLED=0; MDB_ACTIVE=0; MDB_PORT=27017; MDB_AUTH=0; MDB_MANAGED=0; MDB_VERSION=""; MDB_OTHER=""
  if command -v mongod >/dev/null; then
    MDB_INSTALLED=1
    MDB_VERSION=$(mongod --version 2>/dev/null | head -n1 | sed 's/db version v\{0,1\}//')
    systemctl is-active --quiet mongod 2>/dev/null && MDB_ACTIVE=1
    local p; p=$(grep -E '^[[:space:]]*port:[[:space:]]*[0-9]+' /etc/mongod.conf 2>/dev/null | grep -oE '[0-9]+' | head -n1)
    [ -n "$p" ] && MDB_PORT=$p
    grep -qE '^[[:space:]]*authorization:[[:space:]]*enabled' /etc/mongod.conf 2>/dev/null && MDB_AUTH=1
    grep -q 'Managed by .*deploy.sh' /etc/mongod.conf 2>/dev/null && MDB_MANAGED=1
  else
    local q; for q in 27017 27018 27019; do in_use "$q" && MDB_OTHER="$MDB_OTHER $q"; done
  fi
  return 0
}
PY_OLD=0; NO_NET=0
requirements
[ "$PY_OLD" = 1 ] && { echo; echo "Upgrade to Ubuntu 24.04 or later (or Debian 13), then run ./install.sh again."; exit 1; }
[ "$NO_NET" = 1 ] && { echo; echo "Connect this computer to the internet (or set http_proxy / https_proxy), then run ./install.sh again."; exit 1; }

echo
if ! sudo -n true 2>/dev/null; then
  echo "${B}Your sudo password is needed once, for the system packages, MongoDB and the services.${R}"
  sudo -v || { echo "sudo is required."; exit 1; }
fi
( while sleep 50; do sudo -n true 2>/dev/null || exit; done ) & SUDO_KEEPALIVE=$!

if [ ${#MISSING[@]} -gt 0 ]; then
  printf '%sInstalling the missing packages:%s %s\n' "$B" "$R" "${MISSING[*]}"
  run "apt-get update" sudo DEBIAN_FRONTEND=noninteractive apt-get update -qq
  run "missing packages" sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${MISSING[@]}"
  requirements
  [ ${#MISSING[@]} -eq 0 ] || fail "These packages could not be installed: ${MISSING[*]} (see the log)."
fi

CHK="$ROOT/.installer-venv/bin/python"
printf '%sPreparing the answer checks%s (MongoDB, HTTP and signing libraries, in %s)\n' "$B" "$R" ".installer-venv"
[ -x "$CHK" ] || run "checker environment" python3 -m venv "$ROOT/.installer-venv"
run "checker libraries" "$CHK" -m pip install -q --disable-pip-version-check "pymongo>=4.15,<5" "requests>=2.32,<3" "cryptography>=42"
printf '%s✔ Ready.%s The questions open in windows now.\n' "$GRN" "$R"
sleep 1

# the windows: whiptail is installed now
UI="$UI_WANTED"
if [ "$UI" = auto ]; then
  if command -v whiptail >/dev/null && [ -t 0 ] && [ -t 1 ] && [ "${TERM:-dumb}" != dumb ]; then UI=dialog; else UI=text; fi
fi
fit_windows
log "ui $UI, window ${W}x${H}"

msg "Welcome" "This installs Looking Glass on this computer:

  • the Shadowserver database pipeline  (database/)
      fetches your Shadowserver report e-mails into MongoDB every 30 minutes
  • the Looking Glass platform  (platform/)
      replays them on the two live platforms, with sign-in and MFA

The requirements are in place. Next come the questions; each answer is checked
on the spot (mailbox login, map and Malpedia keys, database, ports). Nothing is
installed until you confirm the summary. About 15 minutes.

Folder: $ROOT"

# ---------------------------------------------------------------------------------------------------------- live checks
# Each returns 0 when valid; prints one line (the reason) otherwise. Secrets travel in the environment, never in argv.
chk_py() { "$CHK" - "$@"; }
check_mail() {  # uses the M_* variables; writes a temporary env file (mode 600) for the pipeline's own test
  local tmp rc out; tmp="$(mktemp "$ROOT/install-logs/.mailtest.XXXXXX")"; chmod 600 "$tmp"
  { echo "MAIL_PROVIDER=$M_PROVIDER"; echo "MAIL_TIMEOUT=20"
    case "$M_PROVIDER" in
      imap) printf 'IMAP_SERVER=%s\nIMAP_USER=%s\nIMAP_PASSWORD=%s\nIMAP_FOLDER=%s\nIMAP_VERIFY_TLS=%s\n' \
              "$IMAP_SERVER" "$IMAP_USER" "$IMAP_PASSWORD" "$IMAP_FOLDER" "$IMAP_VERIFY_TLS" ;;
      gmail_api) printf 'GMAIL_SERVICE_ACCOUNT_FILE=%s\nGMAIL_USER=%s\nGMAIL_LABEL=%s\n' "$GMAIL_KEY_SRC" "$GMAIL_USER" "$GMAIL_LABEL" ;;
      microsoft_graph) printf 'MS_TENANT_ID=%s\nMS_CLIENT_ID=%s\nMS_CLIENT_SECRET=%s\nMS_MAILBOX=%s\nMS_FOLDER=%s\n' \
              "$MS_TENANT_ID" "$MS_CLIENT_ID" "$MS_CLIENT_SECRET" "$MS_MAILBOX" "$MS_FOLDER" ;;
    esac; } > "$tmp"
  out="$(cd "$DB_DIR" && env -u MAIL_PROVIDER "$CHK" shadowserver_pipeline.py --env-file "$tmp" --test-mail --days 1 2>&1 | tail -n1)" || true
  rm -f "$tmp"
  log "mail check: ${out:0:200}"
  [[ $out == OK:* ]] && { echo "${out#OK: }"; return 0; }   # (runs in $(...): print, don't set variables)
  echo "${out#FAIL: }"; return 1
}
check_ssapi() {  # KEY SECRET: Shadowserver's report API accepts them (test/ping, reports/subscribed); prints the lists
  SSK="$1" SSS="$2" chk_py <<'EOF'
import hashlib, hmac, json, os, sys, urllib.error, urllib.request
k, s = os.environ["SSK"].strip(), os.environ["SSS"].strip()
def call(m):
    b = json.dumps({"apikey": k}).encode()
    r = urllib.request.Request("https://transform.shadowserver.org/api2/" + m, data=b, method="POST",
                               headers={"HMAC2": hmac.new(s.encode(), b, hashlib.sha256).hexdigest(), "Content-Type": "application/json"})
    with urllib.request.urlopen(r, timeout=20) as a:
        return json.load(a)
try:
    if not (call("test/ping") or {}).get("pong"):
        print("Shadowserver did not answer test/ping as expected."); sys.exit(1)
    subs = call("reports/subscribed")
except urllib.error.HTTPError as e:
    try: why = json.load(e).get("error")
    except Exception: why = ""
    print(f"Shadowserver refused the key or secret (HTTP {e.code}{': ' + str(why)[:120] if why else ''}). Paste both again exactly."); sys.exit(1)
except Exception as e:
    print(f"Could not reach Shadowserver's API ({e.__class__.__name__}); check the internet connection."); sys.exit(2)
names = ", ".join(str(x) for x in subs[:6]) if isinstance(subs, list) else ""
print(f"Shadowserver accepted the key; reports for {names}" if names else "Shadowserver accepted the key, but no report list is subscribed to it yet")
EOF
}
check_mapbox() {
  MB="$1" chk_py <<'EOF'
import json, os, sys, urllib.error, urllib.parse, urllib.request
t = os.environ["MB"].strip()
if not t.startswith("pk."):
    print("A Mapbox public token starts with pk. (secret sk. tokens must never be used in a web page)."); sys.exit(1)
try:
    with urllib.request.urlopen("https://api.mapbox.com/tokens/v2?access_token=" + urllib.parse.quote(t), timeout=20) as r:
        j = json.load(r)
except urllib.error.HTTPError as e:
    try: j = json.load(e)
    except Exception: print(f"Mapbox answered HTTP {e.code}."); sys.exit(1)
except Exception as e:
    print(f"Could not reach Mapbox to check the token ({e.__class__.__name__}); check the internet connection."); sys.exit(2)
if j.get("code") == "TokenValid":
    sys.exit(0)
print({"TokenInvalid": "Mapbox says this token does not exist (copy it again from account.mapbox.com/access-tokens).",
       "TokenExpired": "This token has expired: create a new one.", "TokenRevoked": "This token was revoked: create a new one.",
       "TokenMalformed": "This is not a valid Mapbox token (copy the whole token)."}.get(j.get("code"), f"Mapbox: {j.get('code')}"))
sys.exit(1)
EOF
}
check_malpedia() {
  MP="$1" chk_py <<'EOF'
import os, sys, urllib.error, urllib.request
req = urllib.request.Request("https://malpedia.caad.fkie.fraunhofer.de/api/check/apikey",
                             headers={"Authorization": "apitoken " + os.environ["MP"].strip(), "User-Agent": "looking-glass-installer"})
try:
    with urllib.request.urlopen(req, timeout=20) as r:
        sys.exit(0 if r.status == 200 else 1)
except urllib.error.HTTPError as e:
    print("Malpedia does not accept this token (copy it again from your Malpedia profile)." if e.code in (401, 403)
          else f"Malpedia answered HTTP {e.code}."); sys.exit(1)
except Exception as e:
    print(f"Could not reach Malpedia to check the token ({e.__class__.__name__})."); sys.exit(2)
EOF
}
check_mongo() {  # HOST PORT USER AUTHSOURCE DB NEED_USERADMIN(yes|no) NEED_WRITE(yes|no)   (password in MPW)
  # Prints what it found (version, login, the reports database) and returns 0; or the reason and returns 1.
  MPW="$MONGO_ADMIN_PASSWORD" chk_py "$@" <<'EOF'
import os, sys
from pymongo import MongoClient
from pymongo.errors import OperationFailure, PyMongoError
host, port, user, src, db = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4], sys.argv[5]
need_useradmin, need_write = sys.argv[6] == "yes", sys.argv[7] == "yes"
kw = dict(host=host, port=port, serverSelectionTimeoutMS=8000)
if user:
    if not os.environ.get("MPW"):
        print(f"No password was given for the MongoDB account {user} (the first installation kept it in "
              "/etc/looking-glass/mongo-admin.env: sudo cat it; or in database/.env.before-pipeline-account or database/.env)."); sys.exit(1)
    kw.update(username=user, password=os.environ["MPW"], authSource=src)
try:
    c = MongoClient(**kw)
    version = c.server_info().get("version", "?")
    roles = c.admin.command("connectionStatus")["authInfo"]["authenticatedUserRoles"]
except OperationFailure as e:
    print(f"MongoDB at {host}:{port} refused the login of {user or '(no account)'}: wrong account, password or account "
          f"database ({(e.details or {}).get('errmsg', e)})."); sys.exit(1)
except PyMongoError as e:
    print(f"Cannot reach MongoDB at {host}:{port} ({e.__class__.__name__}): is it running, on this port, and allowed "
          "through the firewall?"); sys.exit(1)
except Exception as e:  # noqa: BLE001  never a bare traceback: always a reason the installer can show
    print(f"MongoDB login of {user or '(no account)'} at {host}:{port} failed ({e.__class__.__name__}: {e})."); sys.exit(1)
# a MongoDB without access control accepts anyone: find out, and say so
open_access = False
try:
    MongoClient(host=host, port=port, serverSelectionTimeoutMS=5000).list_database_names()
    open_access = True
except PyMongoError:
    pass
if not user and not open_access:
    print(f"MongoDB at {host}:{port} requires a login: give its administrator account."); sys.exit(1)
pairs = {(r["role"], r["db"]) for r in roles}
names = {r for r, _ in pairs}
if user:
    can_write = bool(names & {"root", "readWriteAnyDatabase"}) or bool(pairs & {("readWrite", db), ("dbOwner", db)})
    can_users = bool(names & {"root", "userAdminAnyDatabase"}) or bool(pairs & {("userAdmin", db), ("dbOwner", db), ("userAdmin", "admin")})
    if need_write and not can_write:
        print(f"{user} can log in but cannot write to the database '{db}' (roles: {', '.join(sorted(r + '@' + d for r, d in pairs)) or 'none'}). "
              "The pipeline stores the reports, so it needs readWrite on that database (or root)."); sys.exit(1)
    if need_useradmin and not can_users:
        print(f"{user} can log in but cannot create accounts (roles: {', '.join(sorted(r + '@' + d for r, d in pairs)) or 'none'}). "
              "Use an administrator account, or answer No to 'is this an administrator account'."); sys.exit(1)
found = []
try:
    names_ = [n for n in c[db].list_collection_names() if not n.startswith(("files_", "discovered_fields_", "system."))]
    if names_:
        docs = sum(c[db][n].estimated_document_count() for n in names_)
        found.append(f"The database '{db}' already holds {len(names_)} report collection(s) and {docs:,} rows: new reports "
                     "are added to it, rows already there are skipped.")
    else:
        found.append(f"The database '{db}' is new (or empty): it is created on the first load.")
except PyMongoError:
    found.append(f"(Could not list the database '{db}' with this account.)")
print(f"MongoDB {version} at {host}:{port}, login {'as ' + user if user else 'not required'}.  " + "  ".join(found)
      + ("  WARNING: this MongoDB does not require a login, so anyone who can reach it can read or change it. "
         "Turn on authorization (security: authorization: enabled in /etc/mongod.conf) when you can." if open_access else ""))
EOF
}
# after a failed check: try again, continue anyway, or cancel. Returns 0 = try again, 1 = continue anyway.
after_failure() {  # KEY WHAT REASON
  [ "$UI" = dialog ] && fit_windows
  local reason="$3"
  log "check failed: $2: $reason"
  if [ -n "${ANS[$1]+x}" ] || [ "$INTERACTIVE" = 0 ] || [ "$ASSUME_YES" = 1 ]; then
    if [ "${ANS[SKIP_FAILED_CHECKS]:-no}" = yes ]; then   # continue, but say why (not only in the log)
      printf '  %s! Check failed, continuing (SKIP_FAILED_CHECKS=yes): %s%s\n    %s\n' "$YEL" "$2" "$R" "$reason"; return 1
    fi
    echo "Check failed: $2: $reason (set SKIP_FAILED_CHECKS=yes in the answers file to continue anyway)" >&2; exit 1
  fi
  if [ "$UI" = dialog ]; then
    local c; c=$(whiptail --title " Check failed: $2 " --backtitle "$TITLE" --menu "$reason" 18 $W 3 \
      retry "Change the answer and check again" continue "Continue anyway (fix it later in .env)" cancel "Cancel the installation" 3>&1 1>&2 2>&3) || cancelled
  else
    printf '\n%sCheck failed: %s%s\n%s\n' "$RED$B" "$2" "$R" "$reason"
    local c; read -rp "  [r]etry, [c]ontinue anyway, [q]uit? [r]: " c; c="${c:-r}"
    case "${c,,}" in c*) c=continue ;; q*) c=cancel ;; *) c=retry ;; esac
  fi
  case "$c" in retry) for k in "${@:4}"; do unset "ANS[$k]"; done; return 0 ;; continue) return 1 ;; *) cancelled ;; esac
}
checking() {
  if [ "$UI" = dialog ] && [ "$INTERACTIVE" = 1 ]; then fit_windows; whiptail --backtitle "$TITLE" --infobox "\n  Checking $1...\n\n  This takes a few seconds (at most about 20)." 9 $W
  else printf '  %sChecking %s (at most about 20 seconds)...%s\n' "$D" "$1" "$R"; fi
}
passed() {  # shown, not only logged: a window in dialog mode, a green line in text mode
  log "check passed: $1"
  if [ "$UI" = dialog ] && [ "$INTERACTIVE" = 1 ] && [ "$ASSUME_YES" = 0 ]; then
    fit_windows
    whiptail --title " ✔ Check passed " --backtitle "$TITLE" --msgbox "\n✔  $1" 12 $W
  else
    printf '  %s✔ Check passed:%s %b\n' "$GRN" "$R" "$1"     # %b: the line breaks in a message, not "\n"
  fi
  return 0
}

# ======================================================================================================================
# 1. Questions
# ======================================================================================================================
ask_menu COMPONENTS "What to install" "What should be installed on this computer?" both \
  both     "Both: database pipeline and platform (recommended)" \
  database "Only the database pipeline (the platform runs on another computer)" \
  platform "Only the platform (the database is already set up elsewhere)"
COMPONENTS="$REPLY"; WANT_DB=0; WANT_PF=0
[ "$COMPONENTS" != platform ] && WANT_DB=1
[ "$COMPONENTS" != database ] && WANT_PF=1

# ---- MongoDB
# local    install MongoDB here (deploy.sh installs and configures it; only when no MongoDB is installed, or when the
#          one here was set up by Looking Glass before: a re-install keeps its port)
# existing a MongoDB already on this computer (installed by someone else, or in Docker): used as it is, never reconfigured
# remote   a MongoDB on another server
MONGO_BIND=127.0.0.1; READONLY=yes
if [ $WANT_DB = 1 ]; then
  if [ "$MDB_INSTALLED" = 1 ] && [ "$MDB_MANAGED" = 1 ]; then
    ask_menu MONGO_MODE "MongoDB" "MongoDB $MDB_VERSION is installed here, set up by Looking Glass before (port $MDB_PORT).
Where should the reports be stored?" local \
      local  "Keep using this MongoDB (port $MDB_PORT; recommended for a re-install)" \
      remote "Use a MongoDB on another server instead"
  elif [ "$MDB_INSTALLED" = 1 ]; then
    ask_menu MONGO_MODE "MongoDB" "MongoDB $MDB_VERSION is already installed on this computer ($([ "$MDB_ACTIVE" = 1 ] && echo "running on port $MDB_PORT" || echo "not running; port $MDB_PORT")$([ "$MDB_AUTH" = 1 ] && echo ', login required' || echo ', no login required')).
Looking Glass can use it as it is: its configuration is not changed. Where should the reports be stored?" existing \
      existing "Use the MongoDB on this computer (recommended)" \
      remote   "Use a MongoDB on another server"
  elif [ -n "$MDB_OTHER" ]; then
    ask_menu MONGO_MODE "MongoDB" "No MongoDB service is installed here, but something answers on port(s)$MDB_OTHER
(a MongoDB in Docker, or another system). Where should the reports be stored?" existing \
      existing "Use the MongoDB answering on this computer (you give its port and account)" \
      local    "Install MongoDB on this computer (on a free port)" \
      remote   "Use a MongoDB on another server"
  else
    ask_menu MONGO_MODE "MongoDB" "Where should the reports be stored (MongoDB)?" local \
      local  "Install MongoDB on this computer (recommended)" \
      remote "Use an existing MongoDB on another server"
  fi
else
  REPLY=remote
  msg "MongoDB" "The platform will read the MongoDB filled by the database pipeline.
Next: its address and an account.

Best is an administrator account: the installer then creates a separate
read-only account for the platform and stores only that one here."
fi
MONGO_MODE="$REPLY"
if [ "$MONGO_MODE" = local ]; then
  MONGO_HOST=127.0.0.1
  if [ "$MDB_MANAGED" = 1 ]; then
    MONGO_PORT="$MDB_PORT"; passed "Re-install: MongoDB keeps port $MONGO_PORT and its data."
    # Where the first installation left the administrator account: database/.env, or, once the pipeline got its own
    # account (create_pipeline_db_user.py), database/.env.before-pipeline-account. The pipeline's own account is never
    # taken for the administrator: it cannot create the platform's read-only account.
    # First choice: /etc/looking-glass/mongo-admin.env (root only, store_mongo_admin.sh), read with sudo into a private
    # temporary file that is removed again right away.
    ADMIN_ENV="$DB_DIR/.env"; [ -f "$DB_DIR/.env.before-pipeline-account" ] && ADMIN_ENV="$DB_DIR/.env.before-pipeline-account"
    ETC_TMP=""
    if sudo -n test -f /etc/looking-glass/mongo-admin.env 2>/dev/null; then
      ETC_TMP="$(umask 077; mktemp)"; sudo -n cat /etc/looking-glass/mongo-admin.env > "$ETC_TMP" 2>/dev/null && ADMIN_ENV="$ETC_TMP"
    fi
    OLD_MUSER="$(env_get "$ADMIN_ENV" MONGO_USER)"; OLD_MPW="$(env_get "$ADMIN_ENV" MONGO_PASSWORD)"
    ADMIN_FROM="${ADMIN_ENV#"$ROOT/"}"; [ -n "$ETC_TMP" ] && [ "$ADMIN_ENV" = "$ETC_TMP" ] && ADMIN_FROM=/etc/looking-glass/mongo-admin.env
    [ -n "$ETC_TMP" ] && { shred -u "$ETC_TMP" 2>/dev/null || rm -f "$ETC_TMP"; }; unset ETC_TMP
    if [ "$OLD_MUSER" = lookingglass_pipeline ] || [ "$OLD_MUSER" = lookingglass_ro ]; then OLD_MUSER=""; OLD_MPW=""; fi
    ask_input MONGO_ADMIN_USER "MongoDB administrator" "Name of the MongoDB administrator account (as created the first time):" "${OLD_MUSER:-shadowserver_admin}" v_user; MONGO_ADMIN_USER="$REPLY"
    # use the stored password, unless another one is given (an empty answer = use it) or another account was named
    [ "$MONGO_ADMIN_USER" = "$OLD_MUSER" ] || OLD_MPW=""
    if [ -n "${ANS[MONGO_ADMIN_PASSWORD]:-}" ] || [ -z "$OLD_MPW" ]; then
      ask_secret MONGO_ADMIN_PASSWORD "MongoDB administrator password" "Password of '$MONGO_ADMIN_USER' (the first installation kept it in /etc/looking-glass/mongo-admin.env: sudo cat it; or in database/.env.before-pipeline-account or database/.env):"
      MONGO_ADMIN_PASSWORD="$REPLY"
    else
      MONGO_ADMIN_PASSWORD="$OLD_MPW"; log "MongoDB password: taken from $ADMIN_FROM"
    fi
    unset OLD_MPW OLD_MUSER ADMIN_FROM
  else
    ask_input MONGO_PORT "MongoDB port" "Port for MongoDB on this computer (27017 unless something else uses it):" "$(for q in 27017 27018 27019 27020; do in_use $q || { echo $q; break; }; done)" v_mongo_port; MONGO_PORT="$REPLY"
    passed "Port $MONGO_PORT is free for MongoDB."
    ask_input MONGO_ADMIN_USER "MongoDB administrator" "Name of the MongoDB administrator account to create:" shadowserver_admin v_user; MONGO_ADMIN_USER="$REPLY"
    ask_secret MONGO_ADMIN_PASSWORD "MongoDB administrator password" "Password for '$MONGO_ADMIN_USER'.
Leave it empty to generate a strong random one (stored in database/.env)." yes
    MONGO_ADMIN_PASSWORD="$REPLY"; [ -n "$MONGO_ADMIN_PASSWORD" ] || MONGO_ADMIN_PASSWORD="$(gen_password)"
  fi
  if [ $WANT_PF = 0 ]; then
    ask_input MONGO_BIND_ADDR "MongoDB network access" "The platform will run on another computer, so MongoDB must listen on this
server's network address too. Which address should it listen on?
(Only that computer should be allowed through the firewall to port $MONGO_PORT.)" "$(hostname -I 2>/dev/null | awk '{print $1}')" v_host
    MONGO_BIND="127.0.0.1,$REPLY"
  fi
  ask_input MONGO_AUTH_SOURCE "MongoDB account database" "Database the account is defined in (almost always admin):" admin v_nonempty; MONGO_AUTH_SOURCE="$REPLY"
  ask_input MONGO_DB "Report database" "Name of the database holding the reports:" shadowserver v_user; MONGO_DB="$REPLY"
  if [ "$MDB_MANAGED" = 1 ] && [ "$MDB_ACTIVE" = 1 ]; then   # a re-install: the account must still work
    while :; do
      checking "the MongoDB login on 127.0.0.1:$MONGO_PORT"
      if reason="$(check_mongo 127.0.0.1 "$MONGO_PORT" "$MONGO_ADMIN_USER" "$MONGO_AUTH_SOURCE" "$MONGO_DB" "$([ $WANT_PF = 1 ] && echo yes || echo no)" yes)"; then
        passed "MongoDB login succeeded.\n\n$reason"; break
      fi
      after_failure MONGO_ADMIN_USER "MongoDB" "$reason" MONGO_ADMIN_USER MONGO_ADMIN_PASSWORD MONGO_AUTH_SOURCE || break
    done
    # never go on with an empty password: it would be written into both .env files and cut them off the database
    [ -n "$MONGO_ADMIN_PASSWORD" ] || { echo "The MongoDB password of '$MONGO_ADMIN_USER' is needed for a re-install (the first installation kept it in /etc/looking-glass/mongo-admin.env: sudo cat it; or in database/.env.before-pipeline-account or database/.env)." >&2; exit 1; }
  fi
else
  if [ "$MONGO_MODE" = existing ] && [ "$MDB_INSTALLED" = 1 ] && [ "$MDB_ACTIVE" = 0 ]; then
    ask_yesno START_MONGO "MongoDB is not running" "The MongoDB installed here is not running. Start it now (and at every boot)?" yes
    if [ "$REPLY" = yes ]; then
      sudo systemctl enable --now mongod >> "$LOG" 2>&1 && sleep 3 && MDB_ACTIVE=1 && passed "MongoDB started (port $MDB_PORT)." \
        || msg "MongoDB did not start" "sudo systemctl start mongod failed. See: sudo journalctl -u mongod -n 30"
    fi
  fi
  while :; do
    if [ "$MONGO_MODE" = existing ]; then
      MONGO_HOST=127.0.0.1
      ask_input MONGO_PORT "MongoDB port" "Port of the MongoDB on this computer:" "$([ "$MDB_INSTALLED" = 1 ] && echo "$MDB_PORT" || echo "${MDB_OTHER# }" | awk '{print $1}')" v_port; MONGO_PORT="$REPLY"
      ask_input MONGO_ADMIN_USER "MongoDB account" "Administrator account of that MongoDB (empty only if it requires no login):" "" ""; MONGO_ADMIN_USER="$REPLY"
      if [ -n "$MONGO_ADMIN_USER" ]; then ask_secret MONGO_ADMIN_PASSWORD "MongoDB password" "Password of '$MONGO_ADMIN_USER':"; MONGO_ADMIN_PASSWORD="$REPLY"
      else MONGO_ADMIN_PASSWORD=""; fi
    else
      ask_input MONGO_HOST "MongoDB server" "Address of the MongoDB server (host name or IP):" "" v_host; MONGO_HOST="$REPLY"
      ask_input MONGO_PORT "MongoDB port" "MongoDB port on $MONGO_HOST:" 27017 v_port; MONGO_PORT="$REPLY"
      ask_input MONGO_ADMIN_USER "MongoDB account" "MongoDB account name on $MONGO_HOST:" "" v_nonempty; MONGO_ADMIN_USER="$REPLY"
      ask_secret MONGO_ADMIN_PASSWORD "MongoDB password" "Password of '$MONGO_ADMIN_USER':"; MONGO_ADMIN_PASSWORD="$REPLY"
    fi
    ask_input MONGO_AUTH_SOURCE "MongoDB account database" "Database the account is defined in (almost always admin):" admin v_nonempty; MONGO_AUTH_SOURCE="$REPLY"
    ask_input MONGO_DB "Report database" "Name of the database holding the reports:" shadowserver v_user; MONGO_DB="$REPLY"
    READONLY=yes
    if [ $WANT_PF = 1 ] && [ -n "$MONGO_ADMIN_USER" ]; then
      ask_yesno READONLY_DB "Database account" "Is '$MONGO_ADMIN_USER' an administrator account on $MONGO_HOST?
Yes: the installer creates a read-only account for the platform and keeps only that.
No: the platform uses '$MONGO_ADMIN_USER' as it is (it should be read-only)." yes; READONLY="$REPLY"
    fi
    [ -z "$MONGO_ADMIN_USER" ] && READONLY=no     # no access control: a read-only account would protect nothing
    checking "the MongoDB login on $MONGO_HOST:$MONGO_PORT"
    if reason="$(check_mongo "$MONGO_HOST" "$MONGO_PORT" "$MONGO_ADMIN_USER" "$MONGO_AUTH_SOURCE" "$MONGO_DB" \
                 "$([ $WANT_PF = 1 ] && echo "$READONLY" || echo no)" "$([ $WANT_DB = 1 ] && echo yes || echo no)")"; then
      passed "MongoDB login succeeded.\n\n$reason"; break
    fi
    after_failure MONGO_HOST "MongoDB" "$reason" MONGO_HOST MONGO_PORT MONGO_ADMIN_USER MONGO_ADMIN_PASSWORD MONGO_AUTH_SOURCE MONGO_DB READONLY_DB || break
  done
fi

# ---- how the reports are fetched (e-mail or Shadowserver's report API), the mailbox, and the schedule
REPORT_SOURCE=email; SS_API_KEY=""; SS_API_SECRET=""; WANT_MAIL=yes
if [ $WANT_DB = 1 ]; then
  ask_menu REPORT_SOURCE "Getting the reports" "How should the pipeline get your Shadowserver reports? Either way it runs on the
schedule you choose next, fetches only what is new, and the platform shows the same data.
(This can be changed later in Settings → Workers.)" email \
    email "By e-mail: read the mailbox Shadowserver sends the reports to" \
    api   "Through Shadowserver's report API (an API key and secret from Shadowserver)"
  REPORT_SOURCE="$REPLY"
  if [ "$REPORT_SOURCE" = api ]; then
    msg "Shadowserver report API" "Shadowserver gives organisations that receive its reports an API key and a secret
for its report API. With them, every run lists your reports of the last days and
downloads the new ones straight from Shadowserver (HTTPS), with no mailbox involved.
No key yet? Ask Shadowserver for API access for your reports."
    while :; do
      ask_input SS_API_KEY "API key" "Your Shadowserver API key:" "" v_nonempty; SS_API_KEY="$REPLY"
      ask_secret SS_API_SECRET "API secret" "Its secret:"; SS_API_SECRET="$REPLY"
      checking "the key with Shadowserver"
      if reason="$(check_ssapi "$SS_API_KEY" "$SS_API_SECRET")"; then passed "$reason"; break; fi
      after_failure SS_API_KEY "Shadowserver API" "$reason" SS_API_KEY SS_API_SECRET || break
    done
    ask_yesno MAIL_FALLBACK "Mailbox as a fallback" "Also set up the mailbox the reports are sent to?
Then a run that cannot reach Shadowserver's API reads the mailbox instead (and says so in its log)." yes
    WANT_MAIL="$REPLY"
  fi
fi
if [ $WANT_DB = 1 ]; then
  IMAP_SERVER=""; IMAP_USER=""; IMAP_PASSWORD=""; IMAP_FOLDER=inbox; IMAP_VERIFY_TLS=true; M_PROVIDER=imap
  GMAIL_KEY_SRC=""; GMAIL_USER=""; GMAIL_LABEL=INBOX
  MS_TENANT_ID=""; MS_CLIENT_ID=""; MS_CLIENT_SECRET=""; MS_MAILBOX=""; MS_FOLDER=inbox
fi
if [ $WANT_DB = 1 ] && [ "$WANT_MAIL" = yes ]; then
  msg "Shadowserver mailbox" "Shadowserver sends your reports by e-mail throughout the day. The pipeline
reads that mailbox read-only: messages stay unread and are never deleted.

No reports yet? Sign up your CSIRT for the free daily reports:
  https://www.shadowserver.org/what-we-do/network-reporting/
A dedicated mailbox (e.g. shadowserver@your-csirt.org) keeps them apart.

Next: how your mailbox is reached. Each choice shows how to create its
credentials (full guide: docs/MAIL_SETUP.md)."
  IMAP_SERVER=""; IMAP_USER=""; IMAP_PASSWORD=""; IMAP_FOLDER=inbox; IMAP_VERIFY_TLS=true
  GMAIL_KEY_SRC=""; GMAIL_USER=""; GMAIL_LABEL=INBOX
  MS_TENANT_ID=""; MS_CLIENT_ID=""; MS_CLIENT_SECRET=""; MS_MAILBOX=""; MS_FOLDER=inbox
  ask_menu MAIL_PROVIDER "Mailbox" "How should the pipeline read the mailbox that receives the reports?" imap \
    google_app "Gmail / Google Workspace, with an app password (simplest)" \
    gmail_api  "Google Workspace, Gmail API service account (admin; no password)" \
    microsoft  "Microsoft 365 / Exchange Online (Microsoft Graph app; admin)" \
    imap       "Another mail server, over IMAP (cPanel, Zimbra, Roundcube...)"
  MAIL_CHOICE="$REPLY"
  case "$MAIL_CHOICE" in
    google_app)
      M_PROVIDER=imap; IMAP_SERVER=imap.gmail.com
      msg "Gmail app password: how to create it" "Gmail needs an app password (the normal password is refused):

 1. Turn on 2-Step Verification for the account:
      https://myaccount.google.com/signinoptions/two-step-verification
 2. Create an app password named \"Looking Glass\":
      https://myaccount.google.com/apppasswords
    Google shows 16 letters once: that is the password to type next.
 3. Google Workspace: an admin may need to allow IMAP for users:
      https://admin.google.com/ac/apps/gmail/enduseraccess"
      while :; do
        ask_input IMAP_USER "Gmail address" "Gmail / Google Workspace address that receives the reports:" "" v_nonempty; IMAP_USER="$REPLY"
        ask_secret IMAP_PASSWORD "App password" "The 16-letter app password of $IMAP_USER (spaces are ignored):"; IMAP_PASSWORD="${REPLY// /}"
        ask_input IMAP_FOLDER "Gmail label" "Label (folder) holding the reports (INBOX, or e.g. Shadowserver):" INBOX v_nonempty; IMAP_FOLDER="$REPLY"
        checking "the Gmail login of $IMAP_USER"
        if reason="$(check_mail)"; then passed "Mailbox login succeeded.\n\n   $reason"; break; fi
        after_failure IMAP_USER "Gmail login" "$reason" IMAP_USER IMAP_PASSWORD IMAP_FOLDER || break
      done ;;
    gmail_api)
      M_PROVIDER=gmail_api
      msg "Gmail API service account: how to create it" "Google Workspace super admin needed. No password is stored.

 1. Project:  https://console.cloud.google.com/projectcreate
 2. Enable the Gmail API:
      https://console.cloud.google.com/apis/library/gmail.googleapis.com
 3. Service account: https://console.cloud.google.com/iam-admin/serviceaccounts
    Create it, open it, Keys > Add key > JSON (download the file).
    Note its Client ID (Details tab).
 4. Domain-wide delegation: https://admin.google.com/ac/owl/domainwidedelegation
    Add new > the Client ID > scope:
      https://www.googleapis.com/auth/gmail.readonly
 5. Copy the JSON file onto this computer; you give its path next."
      while :; do
        ask_input GMAIL_KEY_FILE "Service account key" "Path of the JSON key file on this computer:" "" v_keyfile; GMAIL_KEY_SRC="$(readlink -f "${REPLY/#\~/$HOME}")"
        ask_input GMAIL_USER "Mailbox" "Address of the Workspace mailbox that receives the reports:" "" v_nonempty; GMAIL_USER="$REPLY"
        ask_input GMAIL_LABEL "Gmail label" "Label holding the reports (INBOX, or e.g. Shadowserver):" INBOX v_nonempty; GMAIL_LABEL="$REPLY"
        checking "the Gmail API access to $GMAIL_USER"
        if reason="$(check_mail)"; then passed "Mailbox login succeeded.\n\n   $reason"; break; fi
        after_failure GMAIL_USER "Gmail API" "$reason" GMAIL_KEY_FILE GMAIL_USER GMAIL_LABEL || break
      done ;;
    microsoft)
      M_PROVIDER=microsoft_graph
      msg "Microsoft 365 app: how to create it" "Entra admin needed. Microsoft refuses passwords over IMAP, so Looking Glass
reads the mailbox through Microsoft Graph with an app registration:

 1. App registrations > New registration (single tenant, no redirect URI):
    https://entra.microsoft.com/#view/Microsoft_AAD_RegisteredApps/ApplicationsListBlade
    Note the Application (client) ID and Directory (tenant) ID.
 2. API permissions > Add > Microsoft Graph > Application permissions >
    Mail.Read > Add, then 'Grant admin consent'.
 3. Certificates & secrets > New client secret: copy its VALUE.
 4. Recommended: limit the app to this one mailbox
    (New-ApplicationAccessPolicy; docs/MAIL_SETUP.md, part C4)."
      while :; do
        ask_input MS_TENANT_ID "Tenant ID" "Directory (tenant) ID (or your domain, e.g. your-csirt.org):" "" v_nonempty; MS_TENANT_ID="$REPLY"
        ask_input MS_CLIENT_ID "Client ID" "Application (client) ID:" "" v_guid; MS_CLIENT_ID="$REPLY"
        ask_secret MS_CLIENT_SECRET "Client secret" "The client secret's Value:"; MS_CLIENT_SECRET="$REPLY"
        ask_input MS_MAILBOX "Mailbox" "Address of the mailbox that receives the reports:" "" v_nonempty; MS_MAILBOX="$REPLY"
        ask_input MS_FOLDER "Mail folder" "Folder holding the reports (inbox, or the name of a folder):" inbox v_nonempty; MS_FOLDER="$REPLY"
        checking "the Microsoft Graph access to $MS_MAILBOX"
        if reason="$(check_mail)"; then passed "Mailbox login succeeded.\n\n   $reason"; break; fi
        after_failure MS_TENANT_ID "Microsoft 365" "$reason" MS_TENANT_ID MS_CLIENT_ID MS_CLIENT_SECRET MS_MAILBOX MS_FOLDER || break
      done ;;
    imap)
      M_PROVIDER=imap
      while :; do
        ask_input IMAP_SERVER "Mail server" "IMAP server (port 993) of the mailbox that receives the reports.
Ask your mail administrator, or look in your webmail's settings:" "" v_host; IMAP_SERVER="$REPLY"
        ask_input IMAP_USER "Mailbox login" "Login (usually the e-mail address) of that mailbox:" "" v_nonempty; IMAP_USER="$REPLY"
        ask_secret IMAP_PASSWORD "Mailbox password" "Password of $IMAP_USER:"; IMAP_PASSWORD="$REPLY"
        ask_input IMAP_FOLDER "Mailbox folder" "Folder holding the reports:" inbox v_nonempty; IMAP_FOLDER="$REPLY"
        ask_yesno IMAP_VERIFY_TLS "Mail server certificate" "Check the mail server's certificate?
Choose No only if the mail server uses a self-signed certificate." yes; IMAP_VERIFY_TLS=$([ "$REPLY" = yes ] && echo true || echo false)
        checking "the login of $IMAP_USER on $IMAP_SERVER"
        if reason="$(check_mail)"; then passed "Mailbox login succeeded.\n\n   $reason"; break; fi
        after_failure IMAP_SERVER "Mailbox login" "$reason" IMAP_SERVER IMAP_USER IMAP_PASSWORD IMAP_FOLDER IMAP_VERIFY_TLS || break
      done ;;
  esac
fi
if [ $WANT_DB = 1 ]; then
  ask_menu SCHEDULE "How often" "How often should the pipeline fetch new reports? Shadowserver sends them
throughout the day; each run only fetches what is new." "every 30m" \
    "every 30m" "Every 30 minutes (recommended)" \
    "every 15m" "Every 15 minutes" \
    "every 1h"  "Every hour" \
    "every 6h"  "Every 6 hours" \
    "daily"     "Once a day, at a time you choose" \
    "off"       "Only when I run it (shadowserver run)"
  SCHEDULE="$REPLY"
  if [ "$SCHEDULE" = daily ]; then
    ask_input SCHEDULE_TIME "Daily run" "Time of the daily run (HH:MM, 24-hour clock, this computer's time):" 06:30 v_time; SCHEDULE="$REPLY"
  fi
  ask_input EMAIL_DAYS "Days per run" "How many days back should every run look for report e-mails?
E-mails already fetched are skipped, so a longer look-back costs little and lets the
pipeline catch up by itself after this computer was off or the mailbox unreachable
(1 = only since yesterday; 7 recommended)." 7 v_days; EMAIL_DAYS="$REPLY"
  MAIL_AUTH=log                    # the sender check concerns e-mail only: asked when a mailbox is used
  [ "$WANT_MAIL" = yes ] && ask_yesno MAIL_AUTH_BLOCK "Sender check" "Shadowserver signs its report e-mails (DKIM). Every report's signature is checked
and recorded either way (Audit portal → Sender check).

Block reports that do not pass? A report that is not validly signed is then held back,
and not loaded, until an administrator releases it (Settings → Workers).
Recommended: No at first. A footer or forwarding rule added on the way also breaks a
genuine signature; switch blocking on in Settings → Workers once the Sender check shows
that every genuine report passes." no && MAIL_AUTH=$([ "$REPLY" = yes ] && echo enforce || echo log)
  ask_yesno RUN_PIPELINE_NOW "First run" "Fetch the reports of the last days right after installing?
(Recommended: the platform needs at least yesterday's reports.)" yes; RUN_PIPELINE_NOW="$REPLY"
  if [ "$RUN_PIPELINE_NOW" = yes ]; then ask_input FIRST_DAYS "First run" "How many days of e-mail to fetch the first time?" 7 v_days; FIRST_DAYS="$REPLY"; fi
fi

# ---- platform
if [ $WANT_PF = 1 ]; then
  mapfile -t CTRY < <(python3 -c '
import json, sys
d = json.load(open(sys.argv[1]))["countries"]
for k, v in sorted(d.items(), key=lambda x: x[1]["country"]):
    print(k); print(v["country"])' "$PF_DIR/static/data/adm1/index.json")
  ask_menu COUNTRY "Country" "Which country does your CSIRT cover? (regions map and labels; changeable later in Settings)" GH "${CTRY[@]}"
  COUNTRY="$REPLY"
  msg "Map (Mapbox): how to get a token" "The map needs a free Mapbox public token (starts with pk.):

 1. Create a free account:  https://account.mapbox.com/auth/signup/
 2. Copy the 'Default public token', or create one, at:
      https://account.mapbox.com/access-tokens/
 3. Later, restrict it there to your site's address (URL restriction).

The free tier covers a CSIRT's use. The token is checked with Mapbox next."
  while :; do
    ask_input MAPBOX_TOKEN "Map (Mapbox)" "Mapbox public token (pk.…). Leave empty to add it later in platform/.env:" "" ""; MAPBOX_TOKEN="$REPLY"
    [ -z "$MAPBOX_TOKEN" ] && break
    checking "the Mapbox token with Mapbox"
    if reason="$(check_mapbox "$MAPBOX_TOKEN")"; then passed "Mapbox accepted the token: it is valid and public (pk.)."; break; fi
    after_failure MAPBOX_TOKEN "Mapbox token" "$reason" MAPBOX_TOKEN || break
  done
  msg "Malpedia (optional): how to get a token" "Malpedia (Fraunhofer FKIE) describes malware families; Looking Glass adds
'Look up on Malpedia' buttons with a token. Optional: skip it if you have none.

 1. Request a free account (for security professionals):
      https://malpedia.caad.fkie.fraunhofer.de/  (top right: Login > Register)
 2. Once approved, your API token is on your Malpedia profile page.

The token is checked with Malpedia next."
  while :; do
    ask_secret MALPEDIA_TOKEN "Malpedia (optional)" "Malpedia API token. Leave empty to skip:" yes; MALPEDIA_TOKEN="$REPLY"
    [ -z "$MALPEDIA_TOKEN" ] && break
    checking "the Malpedia token with Malpedia"
    if reason="$(check_malpedia "$MALPEDIA_TOKEN")"; then passed "Malpedia accepted the token."; break; fi
    after_failure MALPEDIA_TOKEN "Malpedia token" "$reason" MALPEDIA_TOKEN || break
  done
  ask_menu ACCESS_MODE "Who can open Looking Glass" "Who should be able to reach the sign-in page? (Everyone still signs in with MFA.)" local \
    local   "Only this computer" \
    private "This computer and chosen networks (allow list)" \
    public  "Anyone (internet-facing site)"
  ACCESS_MODE="$REPLY"; VIEWER_NETWORKS=""; HTTPS=none; ALLOWED_HOSTS=""; TRUST_PROXY=0; INSECURE=0
  if [ "$ACCESS_MODE" = private ]; then
    ask_input VIEWER_NETWORKS "Allowed networks" "Addresses and ranges allowed to reach Looking Glass, comma separated
(for example 10.20.0.0/24, 192.168.1.40):" "" v_networks; VIEWER_NETWORKS="$REPLY"
  fi
  if [ "$ACCESS_MODE" != local ]; then
    ask_menu HTTPS "HTTPS" "Other computers must use HTTPS to sign in. How?" selfsigned \
      selfsigned "Certificate made here (self-signed; screens warn once)" \
      proxy      "A reverse proxy here does HTTPS (Caddy / nginx; you set it up)" \
      none       "No HTTPS: closed lab only (passwords readable on the network)"
    HTTPS="$REPLY"
    [ "$HTTPS" = proxy ] && TRUST_PROXY=1
    [ "$HTTPS" = none ] && INSECURE=1
    ask_input ALLOWED_HOSTS "Host names" "Extra names people will type to reach it (comma separated), for example
lookingglass.example.org. This computer's own names and addresses always work.
Leave empty if none." "" ""; ALLOWED_HOSTS="$REPLY"
  fi
  ask_input LG_PORT "Port" "Port for Looking Glass (5000 unless something else uses it):" 5000 v_lg_port; LG_PORT="$REPLY"
  in_use "$LG_PORT" && passed "Port $LG_PORT is used by Looking Glass itself (a re-install): it will be kept." \
                    || passed "Port $LG_PORT is free for Looking Glass."
  ask_yesno REGISTRATION "Accounts" "Let people request an account on the sign-in page?
(Requests wait for an administrator's approval. No = administrators add people.)" yes
  REGISTRATION=$([ "$REPLY" = yes ] && echo 1 || echo 0)
  [ "$MONGO_MODE" = local ] && READONLY=yes   # (remote: asked with the MongoDB login above)
  ask_input SERVICE_NAME "Service name" "Name of the systemd service:" looking-glass v_user; SERVICE_NAME="$REPLY"
fi
ask_yesno RUN_CHECKS "Checks" "Run the automated checks and the security test at the end? (about 5 minutes)" yes; RUN_CHECKS="$REPLY"

# ---- existing configuration
KEEP_DB_ENV=no; KEEP_PF_ENV=no
if [ $WANT_DB = 1 ] && [ -f "$DB_DIR/.env" ]; then
  ask_yesno KEEP_DB_ENV "Existing settings" "database/.env already exists. Keep a copy and replace it with the answers you just gave?
(No = keep the existing file unchanged.)" yes
  [ "$REPLY" = no ] && KEEP_DB_ENV=yes
fi
if [ $WANT_PF = 1 ] && [ -f "$PF_DIR/.env" ]; then
  ask_yesno KEEP_PF_ENV "Existing settings" "platform/.env already exists. Keep a copy and replace it with the answers you just gave?
(No = keep the existing file unchanged.)" yes
  [ "$REPLY" = no ] && KEEP_PF_ENV=yes
fi

# ---- summary
case "${M_PROVIDER:-}" in
  imap) MAIL_DESC="IMAP $IMAP_USER on $IMAP_SERVER ($IMAP_FOLDER)$([ "$IMAP_VERIFY_TLS" = true ] || echo ', certificate not checked')" ;;
  gmail_api) MAIL_DESC="Gmail API $GMAIL_USER ($GMAIL_LABEL), service account key $(basename "$GMAIL_KEY_SRC")" ;;
  microsoft_graph) MAIL_DESC="Microsoft Graph $MS_MAILBOX ($MS_FOLDER)" ;;
  *) MAIL_DESC="-" ;;
esac
[ "${WANT_MAIL:-yes}" = yes ] || MAIL_DESC="none (API only)"
case "${REPORT_SOURCE:-email}" in
  api) SOURCE_DESC="Shadowserver report API$([ "${WANT_MAIL:-yes}" = yes ] && echo ', the mailbox as a fallback' || echo ' only')" ;;
  *)   SOURCE_DESC="e-mail (the mailbox)" ;;
esac
case "${SCHEDULE:-off}" in
  off) SCHED_DESC="only when run by hand (shadowserver run)" ;;
  every*) SCHED_DESC="${SCHEDULE/m/ minutes}"; SCHED_DESC="${SCHED_DESC/h/ hour(s)}" ;;
  *) SCHED_DESC="every day at $SCHEDULE" ;;
esac
yesno() { [ "$1" = yes ] && echo yes || echo no; }
S="Install:          $([ $WANT_DB = 1 ] && echo -n 'database pipeline ')$([ $WANT_PF = 1 ] && echo -n 'platform')
MongoDB:          $(case "$MONGO_MODE" in local) [ "$MDB_MANAGED" = 1 ] && echo "keep the one set up before, port $MONGO_PORT" || echo "install here, port $MONGO_PORT$([ "$MONGO_BIND" != 127.0.0.1 ] && echo ", also on ${MONGO_BIND#127.0.0.1,}")" ;; existing) echo "the one already on this computer, port $MONGO_PORT (not reconfigured)" ;; *) echo "existing, $MONGO_HOST:$MONGO_PORT" ;; esac) · database $MONGO_DB · account ${MONGO_ADMIN_USER:-(none)}"
if [ $WANT_DB = 1 ]; then S+="
Reports from:     $SOURCE_DESC
Mailbox:          $MAIL_DESC
Fetching:         $SCHED_DESC, each run looks back $EMAIL_DAYS day(s) · first run: $([ "$RUN_PIPELINE_NOW" = yes ] && echo "now, $FIRST_DAYS days" || echo later)
Sender check:     DKIM signature of every report checked; $([ "${MAIL_AUTH:-log}" = enforce ] && echo "reports that do not pass are HELD BACK" || echo "recorded only, nothing held back")"; fi
if [ $WANT_PF = 1 ]; then S+="
Country:          $COUNTRY · map token $([ -n "$MAPBOX_TOKEN" ] && echo given || echo 'NOT given (add later)') · Malpedia $([ -n "$MALPEDIA_TOKEN" ] && echo given || echo skipped)
Access:           $ACCESS_MODE$([ -n "$VIEWER_NETWORKS" ] && echo " ($VIEWER_NETWORKS)") · HTTPS: $HTTPS · port $LG_PORT · service $SERVICE_NAME
Accounts:         sign-up on the sign-in page: $([ "$REGISTRATION" = 1 ] && echo on || echo off) · MFA for everyone
Database account: $([ "$READONLY" = yes ] && echo "a read-only account for the platform$([ $WANT_DB = 1 ] && echo ", and the pipeline's own (its database only)")" || echo "'$MONGO_ADMIN_USER' used as it is")"; fi
S+="
Checks at the end: $(yesno "$RUN_CHECKS")"
[ "$KEEP_DB_ENV" = yes ] && S+="
database/.env:    kept unchanged"
[ "$KEEP_PF_ENV" = yes ] && S+="
platform/.env:    kept unchanged"
if [ "$INTERACTIVE" = 1 ] && [ "$ASSUME_YES" = 0 ]; then
  if [ "$UI" = dialog ]; then
    whiptail --title " Ready to install " --backtitle "$TITLE" --yes-button "Install" --no-button "Cancel" --yesno "$S

Passwords are stored only in database/.env and platform/.env (mode 600)." $H $W || cancelled
  else
    printf '\n%s── Ready to install ──%s\n%s\n' "$MAG$B" "$R" "$S"
    read -rp "  Install now? [yes/no]: " a; [[ ${a,,} == y* ]] || cancelled
  fi
else
  printf '%s\n' "$S" | sed 's/^/  /'
fi
log "summary:"; printf '%s\n' "$S" >> "$LOG"
save_answers

# ======================================================================================================================
# 2. Installation
# ======================================================================================================================
[ "$UI" = text ] || clear
sudo -n true 2>/dev/null || sudo -v || { echo "sudo is required."; exit 1; }
T0=$(date +%s)
gauge_open

gauge 3 "Starting the cron service (it runs the pipeline on schedule)..."
run "cron service" sudo systemctl enable --now cron

# ---- database pipeline
DB_WARN=""
if [ $WANT_DB = 1 ]; then
  gauge 10 "Writing database/.env..."
  if [ "$KEEP_DB_ENV" = no ]; then
    [ -f "$DB_DIR/.env" ] && cp -p "$DB_DIR/.env" "$DB_DIR/.env.before-install-$(date +%Y%m%d-%H%M%S)"
    install -m 600 "$DB_DIR/.env.example" "$DB_DIR/.env"
    GMAIL_KEY_DST=""
    if [ "$M_PROVIDER" = gmail_api ]; then   # the key goes next to the pipeline, private
      install -d -m 700 "$DB_DIR/secrets"
      install -m 600 "$GMAIL_KEY_SRC" "$DB_DIR/secrets/gmail-service-account.json"
      GMAIL_KEY_DST="secrets/gmail-service-account.json"
    fi
    for kv in "MAIL_PROVIDER=$M_PROVIDER" "IMAP_SERVER=$IMAP_SERVER" "IMAP_USER=$IMAP_USER" "IMAP_FOLDER=$IMAP_FOLDER" "IMAP_VERIFY_TLS=$IMAP_VERIFY_TLS" \
              "GMAIL_SERVICE_ACCOUNT_FILE=${GMAIL_KEY_DST:-secrets/gmail-service-account.json}" "GMAIL_USER=$GMAIL_USER" "GMAIL_LABEL=$GMAIL_LABEL" \
              "MS_TENANT_ID=$MS_TENANT_ID" "MS_CLIENT_ID=$MS_CLIENT_ID" "MS_MAILBOX=$MS_MAILBOX" "MS_FOLDER=$MS_FOLDER" "EMAIL_DAYS=$EMAIL_DAYS" \
              "MAIL_AUTH=${MAIL_AUTH:-log}" "REPORT_SOURCE=${REPORT_SOURCE:-email}" \
              "MONGO_HOST=$MONGO_HOST" "MONGO_PORT=$MONGO_PORT" "MONGO_USER=$MONGO_ADMIN_USER" "MONGO_AUTH_SOURCE=$MONGO_AUTH_SOURCE" \
              "MONGO_DB=$MONGO_DB" "MONGO_LOCAL=$([ "$MONGO_MODE" = local ] && echo true || echo false)" "MONGO_BIND=$MONGO_BIND"; do
      env_set "$DB_DIR/.env" "${kv%%=*}" "${kv#*=}"
    done
    env_set "$DB_DIR/.env" IMAP_PASSWORD "$IMAP_PASSWORD"
    env_set "$DB_DIR/.env" MS_CLIENT_SECRET "$MS_CLIENT_SECRET"
    env_set "$DB_DIR/.env" MONGO_PASSWORD "$MONGO_ADMIN_PASSWORD"
    if [ -n "$SS_API_KEY" ]; then env_set "$DB_DIR/.env" SHADOWSERVER_API_KEY "$SS_API_KEY"; env_set "$DB_DIR/.env" SHADOWSERVER_API_SECRET "$SS_API_SECRET"; fi
  else
    env_set "$DB_DIR/.env" EMAIL_DAYS "$EMAIL_DAYS"    # goes with the schedule, which is applied either way
    env_set "$DB_DIR/.env" MAIL_AUTH "${MAIL_AUTH:-log}"   # the sender check: asked either way
    env_set "$DB_DIR/.env" REPORT_SOURCE "${REPORT_SOURCE:-email}"   # e-mail or the API: asked either way
    if [ -n "$SS_API_KEY" ]; then env_set "$DB_DIR/.env" SHADOWSERVER_API_KEY "$SS_API_KEY"; env_set "$DB_DIR/.env" SHADOWSERVER_API_SECRET "$SS_API_SECRET"; fi
  fi
  gauge 14 "Installing $([ "$MONGO_MODE" = local ] && [ "$MDB_MANAGED" != 1 ] && echo "MongoDB and ")the database pipeline (several minutes)..."
  sargs=(); [ "$SCHEDULE" != off ] && sargs=(--schedule "$SCHEDULE")
  log "\$ database/deploy.sh ${sargs[*]}"
  if ! bg_wait bash -c 'cd "$1" && shift && ./deploy.sh "$@"' _ "$DB_DIR" "${sargs[@]}"; then
    grep -q 'Running checks' "$LOG" || { gauge_close; fail "Installing the database pipeline failed."; }
    DB_WARN="The pipeline is installed, but its setup check reported a problem (see the log; often the mailbox login)."
  fi
  [ "$SCHEDULE" = off ] && (cd "$DB_DIR" && bin/shadowserver schedule off >> "$LOG" 2>&1 || true)
  # the pipeline's own account: read and write on its database only, not the administrator (root). The script then
  # moves the administrator account to /etc/looking-glass/mongo-admin.env (root only; store_mongo_admin.sh), the one
  # place it is kept on this computer, out of reach of the pipeline's and the platform's own Linux user.
  if [ "$KEEP_DB_ENV" = no ] && [ "$READONLY" = yes ] && [ -x "$DB_DIR/create_pipeline_db_user.py" ]; then
    gauge 36 "Giving the pipeline its own database account..."
    if ! (cd "$DB_DIR" && ./create_pipeline_db_user.py >> "$LOG" 2>&1); then
      DB_WARN="${DB_WARN:+$DB_WARN }The pipeline still uses the administrator account (its own account could not be made; see the log)."
    fi
  fi
  if [ "${RUN_PIPELINE_NOW:-no}" = yes ]; then
    gauge 40 "Fetching the reports of the last $FIRST_DAYS days and loading them (can take several minutes)..."
    log "\$ shadowserver run --days $FIRST_DAYS"
    if ! bg_wait bash -c 'cd "$1" && ./run.sh --days "$2"' _ "$DB_DIR" "$FIRST_DAYS"; then
      DB_WARN="${DB_WARN:+$DB_WARN }The first pipeline run reported a problem (see the log). The daily run will try again."
    fi
  fi
fi

# ---- platform
PF_URL=""; PF_WARN=""
if [ $WANT_PF = 1 ]; then
  gauge 55 "Writing platform/.env..."
  if [ "$KEEP_PF_ENV" = no ]; then
    [ -f "$PF_DIR/.env" ] && cp -p "$PF_DIR/.env" "$PF_DIR/.env.before-install-$(date +%Y%m%d-%H%M%S)"
    install -m 600 "$PF_DIR/.env.example" "$PF_DIR/.env"
    for kv in "MONGO_HOST=$MONGO_HOST" "MONGO_PORT=$MONGO_PORT" "MONGO_USER=$MONGO_ADMIN_USER" "MONGO_AUTH_SOURCE=$MONGO_AUTH_SOURCE" \
              "MONGO_DB=$MONGO_DB" "COUNTRY=$COUNTRY" "ACCESS_MODE=$ACCESS_MODE" "VIEWER_NETWORKS=$VIEWER_NETWORKS" \
              "ALLOWED_HOSTS=$ALLOWED_HOSTS" "TRUST_PROXY=$TRUST_PROXY" "ALLOW_INSECURE_REMOTE_LOGIN=$INSECURE" \
              "REGISTRATION=$REGISTRATION" "LG_PORT=$LG_PORT"; do
      env_set "$PF_DIR/.env" "${kv%%=*}" "${kv#*=}"
    done
    env_set "$PF_DIR/.env" MONGO_PASSWORD "$MONGO_ADMIN_PASSWORD"
    env_set "$PF_DIR/.env" MAPBOX_TOKEN "$MAPBOX_TOKEN"
    env_set "$PF_DIR/.env" MALPEDIA_TOKEN "$MALPEDIA_TOKEN"
    env_set "$PF_DIR/.env" REF_SECRET "$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
  fi
  gauge 60 "Setting up the platform's Python environment and packages..."
  iargs=(--port "$LG_PORT" --name "$SERVICE_NAME"); [ "$ACCESS_MODE" != local ] && [ "$HTTPS" != proxy ] && iargs+=(--network)
  run "platform install (deploy/install.sh)" bash -c "cd '$PF_DIR' && deploy/install.sh ${iargs[*]}"
  if [ "$KEEP_PF_ENV" = no ] && [ "$READONLY" = yes ]; then
    gauge 70 "Creating a read-only database account for the platform..."
    run "read-only MongoDB account" bash -c "cd '$PF_DIR' && .venv/bin/python deploy/create_readonly_db_user.py"
    # the administrator password stays only in /etc/looking-glass/mongo-admin.env (root only), or in database/.env if the
    # pipeline kept it; nowhere on this computer for a remote MongoDB
    if [ -f "$PF_DIR/.env.before-readonly" ]; then shred -u "$PF_DIR/.env.before-readonly" 2>/dev/null || rm -f "$PF_DIR/.env.before-readonly"; fi
  fi
  if [ "$HTTPS" = selfsigned ]; then
    gauge 74 "Making the HTTPS certificate..."
    run "HTTPS certificate" bash -c "cd '$PF_DIR' && deploy/make_tls_cert.sh"
  fi
  gauge 78 "Installing and starting the $SERVICE_NAME service..."
  run "service file" sudo install -m 644 "$PF_DIR/deploy/$SERVICE_NAME.service" "/etc/systemd/system/$SERVICE_NAME.service"
  run "systemd reload" sudo systemctl daemon-reload
  run "enable service" sudo systemctl enable "$SERVICE_NAME"
  run "start service" sudo systemctl restart "$SERVICE_NAME"
  scheme=http; [ -f "$PF_DIR/data/tls/cert.pem" ] && scheme=https
  ok=0; for _ in $(seq 1 60); do curl -sfk "$scheme://127.0.0.1:$LG_PORT/healthz" >/dev/null 2>&1 && { ok=1; break; }; sleep 1; done
  if [ $ok = 0 ]; then
    sudo journalctl -u "$SERVICE_NAME" -n 40 --no-pager >> "$LOG" 2>&1 || true
    gauge_close; fail "The $SERVICE_NAME service did not start."
  fi
  PF_URL="$scheme://localhost:$LG_PORT"
  [ -z "$MAPBOX_TOKEN" ] && PF_WARN="No Mapbox token yet: add MAPBOX_TOKEN to platform/.env, then platform/deploy/reload.sh."
fi

# ---- checks
declare -a RESULTS=()
check() {  # LABEL command...
  local label="$1"; shift
  log "\$ check: $label"
  if bg_wait "$@"; then RESULTS+=("PASS  $label"); else RESULTS+=("FAIL  $label"); fi
}
if [ "$RUN_CHECKS" = yes ]; then
  if [ $WANT_DB = 1 ]; then gauge 84 "Checking the database pipeline..."; check "database pipeline setup (shadowserver check)" bash -c "cd '$DB_DIR' && ./check.sh"; fi
  if [ $WANT_PF = 1 ]; then
    gauge 86 "Checking the platform's libraries..."
    check "platform libraries (tests/check_libraries.py)" bash -c "cd '$PF_DIR' && .venv/bin/python tests/check_libraries.py"
    gauge 88 "Security test of the platform (about 2 minutes)..."
    check "platform security test (security_testing/security_retest.py)" bash -c "cd '$PF_DIR' && security_testing/security_retest.py"
    gauge 94 "Checking both platforms against the database (about 2 minutes)..."
    check "platform checks (tests/run_all_checks.sh)" bash -c "cd '$PF_DIR' && tests/run_all_checks.sh"
  fi
fi
gauge 100 "Done."
gauge_close
kill "$SUDO_KEEPALIVE" 2>/dev/null || true; SUDO_KEEPALIVE=""

# ======================================================================================================================
# 3. Result
# ======================================================================================================================
mins=$(( ($(date +%s) - T0 + 59) / 60 ))
OUT="Finished in about $mins minute(s).
"
[ $WANT_DB = 1 ] && OUT+="
Database pipeline   database/   ·  command: shadowserver (help, status, run, logs)
  Fetching: $SCHED_DESC   ·   settings: database/.env"
[ $WANT_PF = 1 ] && OUT+="
Platform            $PF_URL   ·   service: $SERVICE_NAME
  Settings: platform/.env   ·   restart: platform/deploy/reload.sh"
if [ ${#RESULTS[@]} -gt 0 ]; then OUT+="

Checks:"; for r in "${RESULTS[@]}"; do OUT+="
  $r"; done; fi
[ -n "$DB_WARN" ] && OUT+="

Note: $DB_WARN"
[ -n "$PF_WARN" ] && OUT+="
Note: $PF_WARN"
if printf '%s\n' "${RESULTS[@]}" | grep -q '^FAIL.*run_all_checks'; then OUT+="
Note: the platform checks need yesterday's reports in the database; they fail until the first
      reports are loaded. Run them again later: platform/tests/run_all_checks.sh"; fi
if printf '%s\n' "${RESULTS[@]}" | grep -q '^FAIL.*check_libraries'; then OUT+="
Note: a library the platform uses is missing, outside the versions it was tested with, or behaves
      differently. This does not depend on reports. See the log, or run: platform/.venv/bin/python
      platform/tests/check_libraries.py"; fi
[ $WANT_PF = 1 ] && OUT+="

Next: open $PF_URL on this computer and choose \"Let's get started\" to create the
first administrator (with an authenticator app). It asks for the one-time setup code; read it with:
  cat platform/data/setup_code
Guides: docs/USER_GUIDE.md"
[ "${ACCESS_MODE:-local}" != local ] && OUT+="
Other computers: allow port $LG_PORT in the firewall for them only (docs/INSTALLATION.md)."
OUT+="

Log of this installation: install-logs/$(basename "$LOG")"
log "result:"; printf '%s\n' "$OUT" >> "$LOG"
if [ "$UI" = dialog ] && [ "$INTERACTIVE" = 1 ] && [ "$ASSUME_YES" = 0 ]; then
  whiptail --title " Looking Glass is installed " --backtitle "$TITLE" --msgbox "$OUT" $H $W
  clear
fi
printf '\n%s✔ Looking Glass is installed%s\n%s\n' "$GRN$B" "$R" "$OUT"
printf '%s\n' "${RESULTS[@]}" | grep -q '^FAIL' && exit 2
exit 0
