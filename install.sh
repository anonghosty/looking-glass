#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
# Looking Glass installer: the Shadowserver database pipeline and the Looking Glass platform, in one go.
#
#   ./install.sh                     guided installation (dialog windows; asks everything it needs)
#   ./install.sh --text              the same questions as plain text prompts
#   ./install.sh --answers FILE      unattended: answers from FILE (KEY=value lines, see install.answers.example);
#                                    questions it does not answer are asked, or take their default with --yes
#   ./install.sh --yes               accept the default of every question that has one
#   ./install.sh --no-animation      no animated logo (the splash and the progress screen)
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
if [ -n "${LG_BACK_LOG:-}" ] && [ -f "$LG_BACK_LOG" ]; then LOG="$LG_BACK_LOG"     # Back: the same log goes on
else LOG="$ROOT/install-logs/install-$(date +%Y%m%d-%H%M%S).log"; : > "$LOG"; fi
chmod 600 "$LOG"; unset LG_BACK_LOG

# ---------------------------------------------------------------------------------------------------------- options
UI=auto; ANSWERS=""; ASSUME_YES=0; NO_ANIM=0
ORIG_ARGS=("$@")                  # Back starts the installer again with them
while [ $# -gt 0 ]; do
  case "$1" in
    --text) UI=text; shift ;;
    --answers) ANSWERS="${2:?--answers needs a file}"; shift 2 ;;
    --yes|-y) ASSUME_YES=1; shift ;;
    --no-animation) NO_ANIM=1; shift ;;
    -h|--help) sed -n '4,16p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option $1 (./install.sh --help)"; exit 1 ;;
  esac
done
UI_WANTED="$UI"; UI=text          # plain text until the requirements (whiptail among them) are in place
INTERACTIVE=1; { [ -t 0 ] && [ -t 1 ]; } || INTERACTIVE=0
# the animated logo (installer_anim.py, like the platform's loading screen): only for a person at a real terminal; never
# for an unattended installation, with NO_COLOR, on a dumb terminal, or with --no-animation
anim_ok() {
  [ "$NO_ANIM" = 0 ] && [ "$INTERACTIVE" = 1 ] && [ -z "$ANSWERS" ] && [ "$ASSUME_YES" = 0 ] && [ -z "${NO_COLOR:-}" ] \
    && [ "${TERM:-dumb}" != dumb ] && [ -f "$ROOT/installer_anim.py" ] && command -v python3 >/dev/null 2>&1
}

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
   │      Shadowserver threat replay for CSIRTs everywhere       │
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
# never saved for next time: passwords, tokens, secrets and API keys (external review, 2026-11-12: the Shadowserver API
# key went into last.answers and the install log)
remember() { case "$1" in *PASSWORD*|*TOKEN*|*SECRET*|*API_KEY*|KEEP_*) ;; *) MEM["$1"]="$2" ;; esac; }
is_private() { [[ $1 == *TOKEN* || $1 == *API_KEY* ]]; }
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
# ---------------------------------------------------------------------------------------------------------- Back
# Every question has a Back button (the user, 2026-11-19); Esc still stops the installation. Back starts the installer
# again (exec) with this run's answers IN ITS ENVIRONMENT ONLY (never written to disk: passwords are among them). The new
# run answers every question before the one to go back to silently, in the same order and with the same answers (the
# checks between them run again), then asks that question with the earlier answer offered. Answers are replayed by
# their order, not their name: a check that failed and was retried asks the same question twice. If the questions no
# longer match (something changed meanwhile), replaying stops and the questions are asked from there on.
QN=0; declare -a STEPS=() SHOWN=() REPLAY_K=() REPLAY_V=(); REPLAY_TO=0
if [ -n "${LG_BACK_TO:-}" ] && [[ $LG_BACK_TO =~ ^[0-9]+$ ]]; then
  REPLAY_TO="$LG_BACK_TO"
  for ((i = 1; i <= ${LG_BACK_N:-0}; i++)); do
    v="LG_BACK_$i"; d="$(printf '%s' "${!v:-}" | base64 -d 2>/dev/null || true)"
    REPLAY_K[i]="${d%%$'\t'*}"; REPLAY_V[i]="${d#*$'\t'}"; unset "$v"
  done
  unset d v i
fi
unset LG_BACK_TO LG_BACK_N
replaying() { [ "$QN" -lt "$REPLAY_TO" ] || { [ "$QN" = 0 ] && [ "$REPLAY_TO" -gt 0 ]; }; }
# step KEY -> 0 with REPLY set when this question is answered from the replay (nothing shown); 1 to ask it.
# STEP_DEF holds the earlier answer when this is the question gone back to.
step() {
  QN=$((QN + 1)); STEP_DEF=""
  if [ "$QN" -le "$REPLAY_TO" ]; then
    if [ "${REPLAY_K[$QN]-}" != "$1" ]; then log "back: the questions changed at $QN ($1): asked from here"; REPLAY_TO=0; return 1; fi
    if [ "$QN" -lt "$REPLAY_TO" ]; then REPLY="${REPLAY_V[$QN]}"; return 0; fi
    STEP_DEF="${REPLAY_V[$QN]}"; REPLAY_TO=0
  fi
  return 1
}
record() { STEPS[QN]="$1"$'\t'"$2"; }      # KEY VALUE: in memory only
shown() { SHOWN+=("$QN"); }
go_back() {  # back to the question before this one
  local i t=0
  for ((i = ${#SHOWN[@]} - 1; i >= 0; i--)); do [ "${SHOWN[i]}" -lt "$QN" ] && { t="${SHOWN[i]}"; break; }; done
  if [ "$t" = 0 ]; then msg "Back" "This is the first question."; return 1; fi
  log "back: from question $QN to question $t"
  export LG_BACK_TO="$t" LG_BACK_N="$t" LG_BACK_LOG="$LOG"
  for ((i = 1; i <= t; i++)); do export "LG_BACK_$i=$(printf '%s' "${STEPS[i]-}" | base64 -w0)"; done
  if [ -n "${SUDO_KEEPALIVE:-}" ]; then kill "$SUDO_KEEPALIVE" 2>/dev/null || true; fi
  clear 2>/dev/null || true; echo "Back to the previous question..."
  exec bash "$ROOT/install.sh" "${ORIG_ARGS[@]}"
}
BACK_HINT='(Back: the previous question; Esc: stop)'
cancelled() { save_answers; clear 2>/dev/null || true; echo "Installation cancelled. Your answers (not passwords) are offered again next time. Nothing after this point was changed. Log: $LOG"; exit 130; }

# the advice under every "which folder holds the reports" question (2026-11-15)
FOLDER_TIP="Best: a folder (or label) only for Shadowserver's reports, filled by a mail rule
(sender ends in @shadowserver.org). Looking Glass reads every message in it, so other
mail is then never read, and a message that does not belong stands out."

msg() {  # TITLE TEXT
  if replaying; then log "[$1] (replayed, not shown)"; return 0; fi
  [ "$UI" = dialog ] && fit_windows
  if [ "$INTERACTIVE" = 0 ] || [ "$ASSUME_YES" = 1 ]; then log "[$1] $2"; [ "$UI" = text ] && printf '\n%s%s%s\n%s\n' "$B" "$1" "$R" "$2"; return 0; fi
  if [ "$UI" = dialog ]; then whiptail --title " $1 " --backtitle "$TITLE" --msgbox "$2" $H $W
  else printf '\n%s── %s ──%s\n%s\n' "$MAG$B" "$1" "$R" "$2"; read -rp "${D}Press Enter to continue${R} " _; fi
}
ask_yesno() {  # KEY TITLE TEXT DEFAULT(yes|no) -> REPLY=yes|no
  [ "$UI" = dialog ] && fit_windows
  local k="$1" t="$2" x="$3" def; def="$(prev "$1" "${4:-yes}")"
  if step "$k"; then remember "$k" "$REPLY"; record "$k" "$REPLY"; return 0; fi
  [ -n "$STEP_DEF" ] && def="$STEP_DEF"
  if _pre "$k" "$def"; then REPLY="${REPLY,,}"; [[ $REPLY == y* || $REPLY == true || $REPLY == 1 ]] && REPLY=yes || REPLY=no; record "$k" "$REPLY"; return; fi
  shown
  local rc a
  while :; do
    if [ "$UI" = dialog ]; then
      rc=0
      REPLY=$(whiptail --title " $t " --backtitle "$TITLE" --cancel-button Back --default-item "$def" --menu "$x\n\n$BACK_HINT" $H $W 2 \
        yes "Yes" no "No" 3>&1 1>&2 2>&3) || rc=$?
      if [ "$rc" = 1 ]; then go_back || true; continue; elif [ "$rc" != 0 ]; then cancelled; fi
    else
      printf '\n%s%s%s\n%s\n' "$B" "$t" "$R" "$x"
      read -rp "  [${def}] yes/no (< back): " a; a="${a:-$def}"
      if [ "$a" = "<" ]; then go_back || true; continue; fi
      [[ ${a,,} == y* ]] && REPLY=yes || REPLY=no
    fi
    break
  done
  log "answer $k = $REPLY"; remember "$k" "$REPLY"; record "$k" "$REPLY"
}
ask_input() {  # KEY TITLE TEXT DEFAULT [validator]
  [ "$UI" = dialog ] && fit_windows
  local k="$1" t="$2" x="$3" def="${4-}" val="${5-}"
  is_private "$k" || def="$(prev "$k" "$def")"
  if step "$k"; then is_private "$k" || remember "$k" "$REPLY"; record "$k" "$REPLY"; return 0; fi
  [ -n "$STEP_DEF" ] && def="$STEP_DEF"
  local asked=0
  while :; do
    if ! _pre "$k" "$def"; then
      [ "$asked" = 1 ] || shown; asked=1
      if [ "$UI" = dialog ]; then
        local rc=0
        REPLY=$(whiptail --title " $t " --backtitle "$TITLE" --cancel-button Back --inputbox "$x\n\n$BACK_HINT" $H $W "$def" 3>&1 1>&2 2>&3) || rc=$?
        if [ "$rc" = 1 ]; then go_back || true; continue; elif [ "$rc" != 0 ]; then cancelled; fi
      else
        printf '\n%s%s%s\n%s\n' "$B" "$t" "$R" "$x"; read -rp "  [${def}] (< back): " REPLY
        if [ "$REPLY" = "<" ]; then go_back || true; continue; fi
        REPLY="${REPLY:-$def}"
      fi
    fi
    REPLY="${REPLY#"${REPLY%%[![:space:]]*}"}"; REPLY="${REPLY%"${REPLY##*[![:space:]]}"}"
    if [ -n "$val" ] && ! err=$("$val" "$REPLY"); then
      if [ -n "${ANS[$k]+x}" ] || [ "$INTERACTIVE" = 0 ]; then echo "Answer for $k is not valid: $err" >&2; exit 1; fi
      msg "Please check" "$err"; continue
    fi
    if is_private "$k"; then log "answer $k ($([ -n "$REPLY" ] && echo given || echo empty))"; else log "answer $k = ${REPLY:0:60}"; remember "$k" "$REPLY"; fi
    record "$k" "$REPLY"
    return 0
  done
}
ask_secret() {  # KEY TITLE TEXT [allow-empty]  -> REPLY (never logged)
  [ "$UI" = dialog ] && fit_windows
  local k="$1" t="$2" x="$3" empty="${4:-no}" a b
  if step "$k"; then record "$k" "$REPLY"; return 0; fi
  if [ -n "${ANS[$k]+x}" ]; then REPLY="${ANS[$k]}"; log "answer $k (secret, from file)"; record "$k" "$REPLY"; return 0; fi
  if [ "$INTERACTIVE" = 0 ] || [ "$ASSUME_YES" = 1 ]; then
    [ "$empty" = yes ] && { REPLY=""; return 0; }
    echo "No answer for $k (a secret must be given in the answers file or typed)." >&2; exit 1
  fi
  shown
  while :; do
    local rc=0
    if [ "$UI" = dialog ]; then
      a=$(whiptail --title " $t " --backtitle "$TITLE" --cancel-button Back --passwordbox "$x\n\n$BACK_HINT" $H $W 3>&1 1>&2 2>&3) || rc=$?
      if [ "$rc" = 1 ]; then go_back || true; continue; elif [ "$rc" != 0 ]; then cancelled; fi
    else
      printf '\n%s%s%s\n%s\n' "$B" "$t" "$R" "$x"; read -rsp "  (hidden; < back): " a; echo
      if [ "$a" = "<" ]; then go_back || true; continue; fi
    fi
    if [ -z "$a" ]; then [ "$empty" = yes ] && { REPLY=""; log "answer $k (secret, empty)"; record "$k" ""; return 0; }; msg "Please check" "This cannot be empty."; continue; fi
    if [ "$UI" = dialog ]; then
      rc=0
      b=$(whiptail --title " $t " --backtitle "$TITLE" --cancel-button Back --passwordbox "Type it again to confirm." 9 $W 3>&1 1>&2 2>&3) || rc=$?
      if [ "$rc" = 1 ]; then continue; elif [ "$rc" != 0 ]; then cancelled; fi
    else read -rsp "  again: " b; echo; fi
    [ "$a" = "$b" ] && { REPLY="$a"; log "answer $k (secret, typed)"; record "$k" "$REPLY"; return 0; }
    msg "Please check" "The two entries differ. Try again."
  done
}
ask_menu() {  # KEY TITLE TEXT DEFAULT tag item [tag item...]
  [ "$UI" = dialog ] && fit_windows
  local k="$1" t="$2" x="$3" def; def="$(prev "$1" "$4")"; shift 4
  if step "$k"; then remember "$k" "$REPLY"; record "$k" "$REPLY"; return 0; fi
  [ -n "$STEP_DEF" ] && def="$STEP_DEF"
  if _pre "$k" "$def"; then
    local ok=0 i; for ((i = 1; i <= $#; i += 2)); do [ "${!i}" = "$REPLY" ] && ok=1; done
    [ $ok = 1 ] || { echo "Answer for $k must be one of the menu choices, not '$REPLY'." >&2; exit 1; }
    remember "$k" "$REPLY"; record "$k" "$REPLY"; return 0
  fi
  shown
  if [ "$UI" = dialog ]; then
    local n=$(( $# / 2 )) rc=0; [ $n -gt 12 ] && n=12
    while :; do
      rc=0
      REPLY=$(whiptail --title " $t " --backtitle "$TITLE" --cancel-button Back --default-item "$def" --menu "$x\n\n$BACK_HINT" $(( n + 13 )) $W $n "$@" 3>&1 1>&2 2>&3) || rc=$?
      if [ "$rc" = 1 ]; then go_back || true; continue; elif [ "$rc" != 0 ]; then cancelled; fi
      break
    done
  else
    printf '\n%s%s%s\n%s\n' "$B" "$t" "$R" "$x"
    local tags=() i=1
    while [ $# -gt 0 ]; do printf '   %s%2d)%s %s\n' "$CYN" "$i" "$R" "$2"; tags+=("$1"); shift 2; i=$((i + 1)); done
    local d=1 j; for j in "${!tags[@]}"; do [ "${tags[$j]}" = "$def" ] && d=$((j + 1)); done
    while :; do
      read -rp "  choice [$d] (< back): " a; a="${a:-$d}"
      if [ "$a" = "<" ]; then go_back || true; continue; fi
      if [[ $a =~ ^[0-9]+$ ]] && [ "$a" -ge 1 ] && [ "$a" -le ${#tags[@]} ]; then REPLY="${tags[$((a - 1))]}"; break; fi
      for j in "${!tags[@]}"; do [ "${tags[$j],,}" = "${a,,}" ] && { REPLY="${tags[$j]}"; break 2; }; done
    done
  fi
  log "answer $k = $REPLY"; remember "$k" "$REPLY"; record "$k" "$REPLY"
}

# ---------------------------------------------------------------------------------------------------------- progress
GAUGE_OPEN=0; PCT=0; GAUGE_MSG="Starting..."; GAUGE_PID=""; GAUGE_STATUS=""
gauge_status() { printf '%s\n%s\n' "$1" "$2" > "$GAUGE_STATUS.tmp" && mv -f "$GAUGE_STATUS.tmp" "$GAUGE_STATUS"; }
gauge_open() {
  if [ "$UI" = dialog ] && [ "$INTERACTIVE" = 1 ] && anim_ok; then
    GAUGE_STATUS="$(mktemp)"; gauge_status "$PCT" "$GAUGE_MSG"
    python3 "$ROOT/installer_anim.py" progress "$GAUGE_STATUS" "$LOG" < /dev/null &
    GAUGE_PID=$!; GAUGE_OPEN=2
  elif [ "$UI" = dialog ] && [ "$INTERACTIVE" = 1 ]; then
    fit_windows
    exec 3> >(exec whiptail --title " Installing " --backtitle "$TITLE" --gauge "$GAUGE_MSG" 9 $W "$PCT")
    GAUGE_PID=$!
    GAUGE_OPEN=1
  fi
}
gauge_wait() { gauge "${PCT:-14}" "$1"; log "apt: $1"; }   # the package-manager wait, in the progress window
gauge_ask() {  # MESSAGE -> APT_CHOICE = wait | stop-update | cancel (the progress window closes for the question)
  local c="wait"
  if [ "$UI" = dialog ] && [ "$INTERACTIVE" = 1 ]; then
    gauge_close
    c=$(whiptail --title " Waiting for the package manager " --backtitle "$TITLE" --menu "$1" 16 $W 3 \
      wait "Keep waiting" stop-update "Stop the automatic update for now (it runs again later by itself)" cancel "Stop the installation" \
      3>&1 1>&2 2>&3) || c=cancel
    gauge_open
  elif [ "$INTERACTIVE" = 1 ]; then
    printf '%s\n' "$1" >&2
    read -rp "  [w]ait longer, [s]top the automatic update for now, [c]ancel? [w]: " c
    case "${c,,}" in s*) c="stop-update" ;; c*) c="cancel" ;; *) c="wait" ;; esac
  fi
  # shellcheck disable=SC2034  # read by wait_for_apt, in database/apt_wait.sh
  APT_CHOICE="$c"
}
gauge() {  # PERCENT MESSAGE
  PCT="$1"; GAUGE_MSG="$2"; log "== [$1%] $2"
  if [ $GAUGE_OPEN = 1 ]; then printf 'XXX\n%s\n%s\nXXX\n' "$1" "$2" >&3
  elif [ $GAUGE_OPEN = 2 ]; then gauge_status "$1" "$2"
  else printf '\n%s[%3s%%]%s %s%s%s\n' "$CYN" "$1" "$R" "$B" "$2" "$R"; fi
}
gauge_close() {
  if [ $GAUGE_OPEN = 1 ]; then exec 3>&-; GAUGE_OPEN=0; sleep 0.3
  elif [ $GAUGE_OPEN = 2 ]; then          # the progress screen ends and gives the terminal back as it was
    echo STOP > "$GAUGE_STATUS"; GAUGE_OPEN=0
    for _ in 1 2 3 4 5 6 7 8 9 10; do kill -0 "$GAUGE_PID" 2>/dev/null || break; sleep 0.1; done
    kill "$GAUGE_PID" 2>/dev/null || true; wait "$GAUGE_PID" 2>/dev/null || true; rm -f "$GAUGE_STATUS"
  fi
}
# the terminal was resized: draw the progress window again at the new size, same percentage and step
gauge_redraw() {
  [ $GAUGE_OPEN = 1 ] || return 0           # (the progress screen redraws itself at the new size)
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
  if bg_wait "$@"; then [ $GAUGE_OPEN != 0 ] || printf '       %s✔%s %s\n' "$GRN" "$R" "$label"; return 0; fi
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
# the first copy of the key gets the value; later copies are removed, so every reader sees the one value (review
# 2026-11-13); line by line, so another key that only ends in the same name is never touched
out, done = [], False
for ln in text.splitlines():
    if re.match(rf"^{re.escape(k)}=", ln):
        if not done:
            out.append(line); done = True
        continue
    out.append(ln)
if not done:
    out.append(line)
text = "\n".join(out).rstrip("\n") + "\n"
fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(fd, "w", encoding="utf-8") as f:
    f.write(text)
os.chmod(p, 0o600)
EOF
}
env_get() { grep -E "^$2=" "$1" 2>/dev/null | head -n1 | cut -d= -f2- || true; }
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
# ports that Chrome, Edge and Firefox refuse to open ("ERR_UNSAFE_PORT"; their shared list, 2026)
BROWSER_BLOCKED=" 1 7 9 11 13 15 17 19 20 21 22 23 25 37 42 43 53 69 77 79 87 95 101 102 103 104 109 110 111 113 115 117 119 123 135 137 139 143 161 179 389 427 465 512 513 514 515 526 530 531 532 540 548 554 556 563 587 601 636 989 990 993 995 1719 1720 1723 2049 3659 4045 4190 5060 5061 6000 6566 6665 6666 6667 6668 6669 6679 6697 10080 "
safe_free_port() { local q; for q in 8443 5000 5088 8080 8888 9443; do in_use "$q" || { echo "$q"; return; }; done; echo 8443; }
v_lg_port() {  # free, or already a Looking Glass service (a re-run); never one browsers refuse to open
  v_port "$1" || return 1
  [[ $BROWSER_BLOCKED == *" $1 "* ]] && { echo "Browsers refuse to open port $1 (Chrome, Edge and Firefox show ERR_UNSAFE_PORT). Choose another, for example $(safe_free_port)."; return 1; }
  in_use "$1" || return 0
  # Caddy in front of an earlier installation (deploy/caddy_front.sh) listens on the public port: a re-run keeps it
  head -1 /etc/caddy/Caddyfile 2>/dev/null | grep -q 'Managed by Looking Glass' && grep -qE "^https://[^ ]*:$1 \{|^https://:$1 \{" /etc/caddy/Caddyfile && return 0
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
# the reports database is internal (user, 2026-11-14): this computer or a private network address, never public
v_internal_host() {
  v_host "$1" || return 1
  local why
  why="$(PYTHONPATH="$PF_DIR:$DB_DIR" python3 -c 'import sys, db_connect as d; w = d.check_internal(sys.argv[1]); print(w or ""); sys.exit(1 if w else 0)' "$1" 2>&1)" && return 0
  echo "${why:-$1 is neither this computer nor an internal network address.} Use this computer, or a server in your own network (10.x, 172.16-31.x, 192.168.x, or a name that resolves to one)."
  return 1
}
v_ca_file() { [ -z "$1" ] || [ -f "$1" ] || { echo "No such file: $1"; return 1; }; }
v_file() { [ -n "$1" ] && [ -f "$1" ] && [ -r "$1" ] || { echo "No readable file at: ${1:-(empty)}"; return 1; }; }
v_domain() {  # a domain name people type: letters, digits, dashes, dots, a top-level name; no scheme, port or path
  [[ $1 == *://* || $1 == */* || $1 == *:* ]] && { echo "Type only the domain (for example lookingglass.example.org), without https://, a port or a path."; return 1; }
  [[ ${1,,} =~ ^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$ ]] || { echo "That is not a domain name (for example lookingglass.example.org)."; return 1; }
}
v_networks() { python3 - "$1" <<'EOF' || return 1
import ipaddress, sys
items = [x.strip() for x in sys.argv[1].split(",") if x.strip()]
if not items:
    print("Give at least one address or range, for example 10.20.0.0/24, 192.168.1.40"); sys.exit(1)
for x in items:
    if x.lower() == "internal":
        continue                     # every private range (the platform reads the word: security.py)
    try:
        n = ipaddress.ip_network(x, strict=False)
    except ValueError:
        print(f"'{x}' is not an address or range (like 10.20.0.0/24)."); sys.exit(1)
    if n.prefixlen == 0:
        print(f"'{x}' is every address in the world, the internet included: choose 'Anyone (internet-facing site)' for that, "
              "or 'Any computer on our internal network'."); sys.exit(1)
    if n.network_address.is_unspecified:
        print(f"'{x}' lets nobody in: no computer has that address. For every computer on your internal network, go back "
              "and choose 'Any computer on our internal network', or type 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16."); sys.exit(1)
EOF
}

# ======================================================================================================================
# 0. Checks before anything is asked
# ======================================================================================================================
if anim_ok && [ "$REPLAY_TO" = 0 ]; then python3 "$ROOT/installer_anim.py" splash || true; fi
banner
[ "$(id -u)" != 0 ] || { echo "Run ./install.sh as the ordinary user who will run Looking Glass (not root, not with sudo)."; exit 1; }
[ -d "$DB_DIR" ] && [ -d "$PF_DIR" ] || { echo "Run it from the Looking Glass folder (it needs database/ and platform/ next to it)."; exit 1; }
. /etc/os-release 2>/dev/null || true
# This computer: Ubuntu 24.04 or later, Python 3.12-3.14, an x86_64 or aarch64 processor, checked before anything is
# installed by platform/deploy/safe_libraries.py (the one place these rules live; it says why when it refuses). Ubuntu
# always brings python3; should it be missing, only Ubuntu goes on, to install it, and the full check follows then.
SAFE_LIBS="$PF_DIR/deploy/safe_libraries.py"
[ -f "$SAFE_LIBS" ] || { echo "platform/deploy/safe_libraries.py is missing: get the complete Looking Glass folder again (git clone)."; exit 1; }
if command -v python3 >/dev/null 2>&1; then
  python3 "$SAFE_LIBS" check-machine || exit 1
elif [ "${ID:-}" != ubuntu ]; then
  echo "Looking Glass installs on Ubuntu 24.04 or later only; this computer runs ${PRETTY_NAME:-an unknown system}."; exit 1
fi
# every library refused during this installation is reported in one place: suspected-packages.json/.txt here
export LG_SUPPLY_REPORT_DIR="$ROOT"
SUSPECT_BEFORE="$(stat -c %Y "$ROOT/suspected-packages.json" 2>/dev/null || echo 0)"
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
row() {  # MARK LABEL VALUE: a long value wraps at the terminal's width, under the value column (never a stray line)
  local w line first=1
  w=$(( $(tput cols 2>/dev/null || echo 100) - 41 )); [ "$w" -ge 30 ] || w=30
  while IFS= read -r line; do
    if [ $first = 1 ]; then printf '  %b  %-34s %s\n' "$1" "$2" "$line"; first=0; else printf '%41s%s\n' "" "$line"; fi
  done < <(printf '%s\n' "$3" | fold -s -w "$w")
}
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
    if python3 "$SAFE_LIBS" check-machine >/dev/null 2>&1; then row "$OKM" "Python and processor" "Python $pv on $(uname -m) (3.12-3.14, x86_64 or aarch64)"
    else row "$NOM" "Python and processor" "Python $pv on $(uname -m): Looking Glass needs Python 3.12, 3.13 or 3.14 on x86_64 or aarch64 (Ubuntu 24.04 or later)"; PY_OLD=1; fi
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
[ "$PY_OLD" = 1 ] && { echo; python3 "$SAFE_LIBS" check-machine || true; echo "Then run ./install.sh again."; exit 1; }
[ "$NO_NET" = 1 ] && { echo; echo "Connect this computer to the internet (or set http_proxy / https_proxy), then run ./install.sh again."; exit 1; }

echo
if ! sudo -n true 2>/dev/null; then
  echo "${B}Your sudo password is needed once, for the system packages, MongoDB and the services.${R}"
  sudo -v || { echo "sudo is required."; exit 1; }
fi
( while sleep 50; do sudo -n true 2>/dev/null || exit; done ) & SUDO_KEEPALIVE=$!

# Ubuntu's automatic updates (or another installation) hold the package manager for a while after a start: wait, and
# say what for, instead of failing (lg-try, 2026-11-19)
[ -f "$DB_DIR/apt_wait.sh" ] && . "$DB_DIR/apt_wait.sh"
if [ ${#MISSING[@]} -gt 0 ] && declare -F wait_for_apt >/dev/null; then
  wait_for_apt || { echo "Stopped while waiting for the package manager. Run ./install.sh again later."; exit 1; }
fi
if [ ${#MISSING[@]} -gt 0 ]; then
  printf '%sInstalling the missing packages:%s %s\n' "$B" "$R" "${MISSING[*]}"
  run "apt-get update" sudo DEBIAN_FRONTEND=noninteractive apt-get update -qq
  run "missing packages" sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${MISSING[@]}"
  requirements
  [ ${#MISSING[@]} -eq 0 ] || fail "These packages could not be installed: ${MISSING[*]} (see the log)."
fi

CHK="$ROOT/.installer-venv/bin/python"
printf '%sPreparing the answer checks%s (MongoDB, HTTP and signing libraries, in %s)\n' "$B" "$R" ".installer-venv"
# the database pipeline's locked libraries (database/requirements.lock), every file checked against its sha256 value
# (platform/deploy/safe_libraries.py; a lock already installed there is left alone)
safe_libs() {  # LABEL safe_libraries.py install arguments...: 10 = installed, but a source's file was refused (reported)
  local label="$1" rc=0; shift
  log "\$ $label"
  bg_wait python3 "$SAFE_LIBS" install "$@" || rc=$?      # (its lines go to the log)
  if [ "$rc" = 0 ] || [ "$rc" = 10 ]; then [ $GAUGE_OPEN != 0 ] || printf '       %s✔%s %s\n' "$GRN" "$R" "$label"; return 0; fi
  gauge_close
  fail "$label: the libraries were not installed (exit code $rc). Nothing was changed. A refused file is listed in $ROOT/suspected-packages.txt."
}
[ "$REPLAY_TO" -gt 0 ] && [ -x "$CHK" ] || safe_libs "checker libraries" --lock "$DB_DIR/requirements.lock" \
  --venv "$ROOT/.installer-venv" --part checker --report-dir "$ROOT" --no-local-copy --import pymongo,requests,cryptography
printf '%s✔ Ready.%s The questions open in windows now.\n' "$GRN" "$R"
[ "$REPLAY_TO" -gt 0 ] || sleep 1

# the windows: whiptail is installed now
UI="$UI_WANTED"
if [ "$UI" = auto ]; then
  if command -v whiptail >/dev/null && [ -t 0 ] && [ -t 1 ] && [ "${TERM:-dumb}" != dumb ]; then UI=dialog; else UI=text; fi
fi
fit_windows
log "ui $UI, window ${W}x${H}"

msg "Welcome" "This installs Looking Glass on this computer:

  • the Shadowserver database pipeline  (database/)
      fetches your Shadowserver reports (by e-mail or Shadowserver's API)
      into MongoDB, every 30 minutes
  • the Looking Glass platform  (platform/)
      replays them on the two live platforms, with sign-in and MFA

The requirements are in place. Next come the questions; each answer is checked
on the spot (mailbox or API key, map and Malpedia keys, database, ports). Nothing is
installed until you confirm the summary. About 15 minutes.

Every question has a Back button (in text mode: type <). Esc stops the installation.

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
  # exit 0: fine; 1: the reason; 3: it answers, but the database is not a Looking Glass reports database
  MPW="$MONGO_ADMIN_PASSWORD" MTLS="${MONGO_TLS:-0}" MCA="${MONGO_TLS_CA_FILE:-}" MPLAIN="${MONGO_ALLOW_PLAINTEXT:-0}" \
    MDBPATH="$PF_DIR:$DB_DIR" chk_py "$@" <<'EOF'
import os, sys
sys.path[:0] = [p for p in os.environ.get("MDBPATH", "").split(":") if p]
import db_connect
from pymongo import MongoClient
from pymongo.errors import OperationFailure, PyMongoError
host, port, user, src, db = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4], sys.argv[5]
need_useradmin, need_write = sys.argv[6] == "yes", sys.argv[7] == "yes"
env = {"MONGO_HOST": host, "MONGO_PORT": str(port), "MONGO_TLS": os.environ.get("MTLS", ""),
       "MONGO_TLS_CA_FILE": os.environ.get("MCA", ""), "MONGO_ALLOW_PLAINTEXT": os.environ.get("MPLAIN", "")}
try:
    base = db_connect.kwargs(env.get)
except db_connect.Refused as e:
    print(str(e)); sys.exit(1)
kw = dict(base, serverSelectionTimeoutMS=8000)
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
    MongoClient(**dict(base, serverSelectionTimeoutMS=5000)).list_database_names()
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
        # the Looking Glass layout (as the pipeline's own check): every report collection has the unique row index
        # (filename, category, line_hash) and rows carrying those fields, category = the collection's name
        bad = []
        for n in names_[:300]:
            idx = c[db][n].index_information().values()
            has = any(i.get("unique") and [k for k, _ in i["key"]] == ["filename", "category", "line_hash"] for i in idx)
            s = c[db][n].find_one({"line_hash": {"$exists": True}}) or c[db][n].find_one()
            if not has or (s is not None and (not all(k in s for k in ("filename", "category", "line_hash")) or s.get("category") != n)):
                bad.append(n)
        if bad:
            print(f"The database '{db}' on {host} already exists but is not a Looking Glass reports database: {len(bad)} of its "
                  f"{len(names_)} collection(s) do not have the Looking Glass layout (for example {', '.join(bad[:3])}). "
                  "Looking Glass never writes into another program's data.")
            sys.exit(3)
        docs = sum(c[db][n].estimated_document_count() for n in names_)
        found.append(f"The database '{db}' already holds {len(names_)} report collection(s) and {docs:,} rows: new reports "
                     "are added to it, rows already there are skipped.")
    else:
        found.append(f"The database '{db}' is new (or empty): it is created on the first load.")
except PyMongoError:
    found.append(f"(Could not list the database '{db}' with this account.)")
print(f"MongoDB {version} at {db_connect.describe(env.get)}, login {'as ' + user if user else 'not required'}.  " + "  ".join(found)
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
  local c
  if step "CHECK:$2"; then c="$REPLY"
  elif [ "$UI" = dialog ]; then
    shown
    local rc
    while :; do
      rc=0
      c=$(whiptail --title " Check failed: $2 " --backtitle "$TITLE" --cancel-button Back --menu "$reason\n\n$BACK_HINT" 20 $W 3 \
        retry "Change the answer and check again" continue "Continue anyway (fix it later in .env)" cancel "Cancel the installation" 3>&1 1>&2 2>&3) || rc=$?
      if [ "$rc" = 1 ]; then go_back || true; continue; elif [ "$rc" != 0 ]; then cancelled; fi
      break
    done
  else
    shown
    printf '\n%sCheck failed: %s%s\n%s\n' "$RED$B" "$2" "$R" "$reason"
    read -rp "  [r]etry, [c]ontinue anyway, [q]uit? [r]: " c; c="${c:-r}"
    case "${c,,}" in c*) c="continue" ;; q*) c="cancel" ;; *) c="retry" ;; esac
  fi
  record "CHECK:$2" "$c"
  case "$c" in retry) for k in "${@:4}"; do unset "ANS[$k]"; done; return 0 ;; continue) return 1 ;; *) cancelled ;; esac
}
checking() {
  replaying && return 0
  if [ "$UI" = dialog ] && [ "$INTERACTIVE" = 1 ]; then fit_windows; whiptail --backtitle "$TITLE" --infobox "\n  Checking $1...\n\n  This takes a few seconds (at most about 20)." 9 $W
  else printf '  %sChecking %s (at most about 20 seconds)...%s\n' "$D" "$1" "$R"; fi
}
passed() {  # shown, not only logged: a window in dialog mode, a green line in text mode
  log "check passed: $1"
  replaying && return 0
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
# remote   an internal MongoDB on another server of this network (loopback or private address only, never public)
MONGO_BIND=127.0.0.1; READONLY=yes; MONGO_TLS=0; MONGO_TLS_CA_FILE=""; MONGO_ALLOW_PLAINTEXT=0; SWITCH_LOCAL=0
if [ $WANT_DB = 1 ]; then
  if [ "$MDB_INSTALLED" = 1 ] && [ "$MDB_MANAGED" = 1 ]; then
    ask_menu MONGO_MODE "MongoDB" "MongoDB $MDB_VERSION is installed here, set up by Looking Glass before (port $MDB_PORT).
Where should the reports be stored?" local \
      local  "Keep using this MongoDB (port $MDB_PORT; recommended for a re-install)" \
      remote "Use an internal MongoDB on another server of your network instead"
  elif [ "$MDB_INSTALLED" = 1 ]; then
    ask_menu MONGO_MODE "MongoDB" "MongoDB $MDB_VERSION is already installed on this computer ($([ "$MDB_ACTIVE" = 1 ] && echo "running on port $MDB_PORT" || echo "not running; port $MDB_PORT")$([ "$MDB_AUTH" = 1 ] && echo ', login required' || echo ', no login required')).
Looking Glass can use it as it is: its configuration is not changed. Where should the reports be stored?" existing \
      existing "Use the MongoDB on this computer (recommended)" \
      remote   "Use an internal MongoDB on another server of your network"
  elif [ -n "$MDB_OTHER" ]; then
    ask_menu MONGO_MODE "MongoDB" "No MongoDB service is installed here, but something answers on port(s)$MDB_OTHER
(a MongoDB in Docker, or another system). Where should the reports be stored?" existing \
      existing "Use the MongoDB answering on this computer (you give its port and account)" \
      local    "Install MongoDB on this computer (on a free port)" \
      remote   "Use an internal MongoDB on another server of your network"
  else
    ask_menu MONGO_MODE "MongoDB" "Where should the reports be stored (MongoDB)?" local \
      local  "Install MongoDB on this computer (recommended)" \
      remote "Use an internal MongoDB on another server of your network"
  fi
else
  REPLY=remote
  msg "MongoDB" "The platform will read the internal MongoDB filled by the database pipeline
(on this computer, or on a server of your own network: never one on the internet).
Next: its address and an account.

Best is an administrator account: the installer then creates a separate
read-only account for the platform and stores only that one here."
fi
MONGO_MODE="$REPLY"
mongo_local_questions() {
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
      ETC_TMP="$(umask 077; mktemp)"
      # shellcheck disable=SC2024  # only reading needs root; the copy goes to this user's own 0600 temporary file
      sudo -n cat /etc/looking-glass/mongo-admin.env > "$ETC_TMP" 2>/dev/null && ADMIN_ENV="$ETC_TMP"
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
(Only that computer should be allowed through the firewall to port $MONGO_PORT. It must be an
internal address of this server: MongoDB is never reachable from the internet.)" "$(hostname -I 2>/dev/null | awk '{print $1}')" v_internal_host
    MONGO_BIND="127.0.0.1,$REPLY"
    msg "Keep this address fixed" "MongoDB will listen on $REPLY. If this server's address ever changes, MongoDB
cannot start (\"cannot assign requested address\") and the platform cannot reach it.

Give this server a fixed address: a DHCP reservation on your router or DHCP server, or a
static address. The installation check warns if the address and MongoDB's setting stop
matching, and says how to fix it."
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
}
if [ "$MONGO_MODE" = local ]; then
  mongo_local_questions
else
  if [ "$MONGO_MODE" = existing ] && [ "$MDB_INSTALLED" = 1 ] && [ "$MDB_ACTIVE" = 0 ]; then
    ask_yesno START_MONGO "MongoDB is not running" "The MongoDB installed here is not running. Start it now (and at every boot)?" yes
    if [ "$REPLY" = yes ]; then
      # shellcheck disable=SC2024  # the installer's log is this user's own file: only systemctl needs root
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
      ask_input MONGO_HOST "Internal MongoDB server" "Address of the internal MongoDB server: a server of your own network
(a private address such as 10.0.0.5, or a name that resolves to one). The reports database is
never on the internet: a public address is refused." "" v_internal_host; MONGO_HOST="$REPLY"
      ask_input MONGO_PORT "MongoDB port" "MongoDB port on $MONGO_HOST:" 27017 v_port; MONGO_PORT="$REPLY"
      ask_yesno MONGO_TLS_ON "Encrypted connection (TLS)" "Does the MongoDB on $MONGO_HOST accept TLS connections?
Strongly recommended: the account's password and every report cross your network.
(Its certificate and name are always checked.)" yes
      if [ "$REPLY" = yes ]; then
        MONGO_TLS=1; MONGO_ALLOW_PLAINTEXT=0
        ask_input MONGO_TLS_CA_FILE "TLS certificate authority" "Path to the CA certificate (PEM file) that signed the certificate of $MONGO_HOST.
Leave it empty when that certificate is from a CA this computer already trusts." "" v_ca_file; MONGO_TLS_CA_FILE="$REPLY"
      else
        MONGO_TLS=0; MONGO_TLS_CA_FILE=""
        ask_yesno MONGO_PLAINTEXT "Without encryption" "Without TLS the password and every report cross the network readable by
anyone on the way. Only on a link you trust (a direct cable or an isolated network between
the two servers). Continue without encryption?" no
        if [ "$REPLY" = yes ]; then MONGO_ALLOW_PLAINTEXT=1
        else msg "TLS needed" "Turn on TLS on $MONGO_HOST (net.tls in its mongod.conf), then answer Yes to the TLS question."; continue; fi
      fi
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
    # (set -e: a failed check must not end the installer, so its code is taken inside the if)
    if reason="$(check_mongo "$MONGO_HOST" "$MONGO_PORT" "$MONGO_ADMIN_USER" "$MONGO_AUTH_SOURCE" "$MONGO_DB" \
                 "$([ $WANT_PF = 1 ] && echo "$READONLY" || echo no)" "$([ $WANT_DB = 1 ] && echo yes || echo no)")"; then rc=0; else rc=$?; fi
    if [ $rc = 0 ]; then passed "MongoDB login succeeded.\n\n$reason"; break; fi
    if [ $rc = 3 ]; then
      # it answers, but '$MONGO_DB' holds something else: a database of its own for Looking Glass there, or this computer
      opts=(newdb "Create a new database for Looking Glass on $MONGO_HOST (recommended)")
      [ "$MONGO_MODE" = remote ] && opts+=(local "Install MongoDB on this computer instead (the reports stay on this server)")
      opts+=(retry "Give another server, account or database name")
      ask_menu DB_MISMATCH "Not a Looking Glass database" "$reason

What should be done?" newdb "${opts[@]}"
      case "$REPLY" in
        newdb) ask_input MONGO_DB "New database" "Name of the new database for Looking Glass on $MONGO_HOST (one that does not exist yet;
the database pipeline creates its collections on the first load):" looking_glass v_user; MONGO_DB="$REPLY"; continue ;;
        local) SWITCH_LOCAL=1; break ;;
        *) continue ;;
      esac
    fi
    after_failure MONGO_HOST "MongoDB" "$reason" MONGO_HOST MONGO_PORT MONGO_ADMIN_USER MONGO_ADMIN_PASSWORD MONGO_AUTH_SOURCE MONGO_DB READONLY_DB || break
  done
fi
if [ "$SWITCH_LOCAL" = 1 ]; then          # chosen above: MongoDB and the pipeline on this computer instead
  MONGO_MODE=local; WANT_DB=1; COMPONENTS=both; MONGO_TLS=0; MONGO_TLS_CA_FILE=""; MONGO_ALLOW_PLAINTEXT=0; READONLY=yes
  mongo_local_questions
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
        ask_input IMAP_FOLDER "Gmail label" "Label (folder) holding the reports (INBOX, or e.g. Shadowserver).
$FOLDER_TIP" INBOX v_nonempty; IMAP_FOLDER="$REPLY"
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
        ask_input GMAIL_LABEL "Gmail label" "Label holding the reports (INBOX, or e.g. Shadowserver).
$FOLDER_TIP" INBOX v_nonempty; GMAIL_LABEL="$REPLY"
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
        ask_input MS_FOLDER "Mail folder" "Folder holding the reports (inbox, or the name of a folder).
$FOLDER_TIP" inbox v_nonempty; MS_FOLDER="$REPLY"
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
        ask_input IMAP_FOLDER "Mailbox folder" "Folder holding the reports.
$FOLDER_TIP" inbox v_nonempty; IMAP_FOLDER="$REPLY"
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
  # the sender check concerns e-mail only: asked when a mailbox is used. A re-install keeps what the pipeline has now
  # (review 2026-11-13: Block, switched on later in Settings → Workers, was quietly set back to "record only"): it is
  # the default offered, and kept as it is when the question is not asked
  MAIL_AUTH_NOW="$(env_get "$DB_DIR/.env" MAIL_AUTH)"
  case "${MAIL_AUTH_NOW,,}" in enforce|block) PREV[MAIL_AUTH_BLOCK]=yes;; log) PREV[MAIL_AUTH_BLOCK]=no;; esac
  MAIL_AUTH="${MAIL_AUTH_NOW:-log}"
  [ "$WANT_MAIL" = yes ] && ask_yesno MAIL_AUTH_BLOCK "Sender check" "Shadowserver signs its report e-mails (DKIM). Every report's signature is checked
and recorded either way (Audit portal → Sender check).

Block reports that do not pass? A report that is not validly signed is then held back,
and not loaded, until an administrator releases it (Settings → Workers).
Recommended: No at first, Yes in production. A footer or forwarding rule added on the way
also breaks a genuine signature, so first let the Sender check show for a few days that
every genuine report passes; then switch blocking on in Settings → Workers. Without it, a
forged report e-mail would be loaded and only flagged. Shadowserver's report API avoids
e-mail altogether (asked earlier: report source)." no && MAIL_AUTH=$([ "$REPLY" = yes ] && echo enforce || echo log)
  ask_yesno RUN_PIPELINE_NOW "First run" "Fetch the reports of the last days right after installing?
(Recommended: the platform needs at least yesterday's reports.)" yes; RUN_PIPELINE_NOW="$REPLY"
  if [ "$RUN_PIPELINE_NOW" = yes ]; then ask_input FIRST_DAYS "First run" "How many days of e-mail to fetch the first time?" 7 v_days; FIRST_DAYS="$REPLY"; fi
fi

# ---- platform
if [ $WANT_PF = 1 ]; then
  # every country in the world (2026-11-15): the continent first, then its countries (one list of ~250 is too long)
  IDX="$PF_DIR/static/data/adm1/index.json"
  CONT_OF() { python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["countries"].get(sys.argv[2].upper(), {}).get("continent", ""))' "$IDX" "$1" 2>/dev/null; }
  mapfile -t CONTS < <(python3 -c '
import json, sys
d = json.load(open(sys.argv[1]))
for c in d.get("continents") or sorted({v.get("continent") or "Africa" for v in d["countries"].values()}):
    print(c); print(c)' "$IDX")
  if [ -n "${ANS[COUNTRY]+x}" ] && [ -z "${ANS[CONTINENT]+x}" ]; then
    ANS[CONTINENT]="$(CONT_OF "${ANS[COUNTRY]}")"    # an answers file with COUNTRY only: its continent, not asked
  fi
  CDEF="$(CONT_OF "$(prev COUNTRY GH)")"; CDEF="${CDEF:-Africa}"
  ask_menu CONTINENT "Continent" "Which continent is your CSIRT's country on? (the next question lists its countries)" "$CDEF" "${CONTS[@]}"
  CONTINENT="$REPLY"
  mapfile -t CTRY < <(python3 -c '
import json, sys
d = json.load(open(sys.argv[1]))["countries"]
for k, v in sorted(d.items(), key=lambda x: x[1]["country"]):
    if (v.get("continent") or "Africa") == sys.argv[2]:
        r = v.get("regions") or 0
        extra = "  (%d regions)" % r if r else ("  (one area)" if v.get("kind") == "whole" else "")
        print(k); print(v["country"] + extra)' "$IDX" "$CONTINENT")
  CTDEF="$(prev COUNTRY GH)"; printf '%s\n' "${CTRY[@]}" | grep -qx "$CTDEF" || CTDEF="${CTRY[0]}"
  ask_menu COUNTRY "Country" "Which country does your CSIRT cover? (regions map and labels; changeable later in Settings)" "$CTDEF" "${CTRY[@]}"
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
    # a CSIRT's operations network: every computer on it (the user, 2026-11-19), or only the ones listed
    ask_menu VIEWER_SCOPE "Which computers" "Which computers besides this one may reach the sign-in page?" internal \
      internal "Any computer on our internal network (private addresses only, never the internet)" \
      list     "Only the addresses and ranges I list"
    if [ "$REPLY" = internal ]; then
      VIEWER_NETWORKS=internal
    else
      ask_input VIEWER_NETWORKS "Allowed networks" "Addresses and ranges allowed to reach Looking Glass, comma separated
(for example 10.20.0.0/24, 192.168.1.40):" "" v_networks; VIEWER_NETWORKS="$REPLY"
    fi
  fi
  TLS_DOMAIN=""; TLS_CERT_FILE=""; TLS_KEY_FILE=""; TLS_CHAIN_FILE=""; PORT_DEFAULT=5000
  if [ "$ACCESS_MODE" = public ]; then
    # reachable from the internet: one way only (the user, 2026-11-23). A certificate for a domain with Caddy in front
    # (deploy/caddy_front.sh): Looking Glass itself never faces the internet, so slow connections cannot hold it up.
    # No "No HTTPS" (review follow-up item 5, 2026-11-15), no self-signed certificate (every visitor would see a warning
    # and learn to click through it), and no proxy of your own (Caddy could not be guaranteed in front).
    ask_menu PUBLIC_HTTPS "HTTPS" "Anyone on the internet can reach this site. It uses HTTPS with a certificate for your
domain, and Caddy in front of Looking Glass (set up here; Looking Glass itself listens on this computer only).
A free certificate (for example from Let's Encrypt) or a bought one both work." domain \
      domain     "A certificate for a domain name, with Caddy in front"
    HTTPS="$REPLY"
  elif [ "$ACCESS_MODE" != local ]; then
    # an internal network too has Caddy in front (the user, 2026-11-24): a few deliberately slow connections from inside
    # could otherwise hold Looking Glass up. So no proxy of your own and no "No HTTPS" here either.
    ask_menu HTTPS "HTTPS" "Other computers must use HTTPS to sign in, with Caddy in front of Looking Glass (set up here;
Looking Glass itself listens on this computer only). Which certificate?
(A self-signed certificate covers this computer's names and its addresses as they are now: give the
server a fixed address or a name people use, or make it again after a change: deploy/make_tls_cert.sh)" selfsigned \
      selfsigned "Certificate made here (self-signed; trust it on each screen), with Caddy in front" \
      domain     "A certificate bought for a domain name, with Caddy in front"
    HTTPS="$REPLY"
  fi
  if [ "$ACCESS_MODE" != local ]; then
    [ "$HTTPS" = proxy ] && TRUST_PROXY=1
    [ "$HTTPS" = none ] && INSECURE=1
    if [ "$HTTPS" = domain ]; then
      PORT_DEFAULT=443
      while :; do
        ask_input TLS_DOMAIN "Domain" "The domain name people will type, the one the certificate is for
(for example lookingglass.example.org):" "" v_domain; TLS_DOMAIN="${REPLY,,}"
        ask_input TLS_CERT_FILE "Certificate" "Path to the certificate file your provider sent (PEM: BEGIN CERTIFICATE).
If it already holds the intermediate certificates, leave the next question empty:" "" v_file; TLS_CERT_FILE="$REPLY"
        ask_input TLS_KEY_FILE "Private key" "Path to the certificate's private key (PEM, without a passphrase).
It is copied into Looking Glass, readable only by its user; keep the original safe:" "" v_file; TLS_KEY_FILE="$REPLY"
        ask_input TLS_CHAIN_FILE "Intermediate certificates" "Path to the intermediate (chain or CA bundle) file your provider sent.
Leave empty if the certificate file already holds them:" "" v_ca_file; TLS_CHAIN_FILE="$REPLY"
        checking "the certificate for $TLS_DOMAIN"
        cargs=(check --domain "$TLS_DOMAIN" --cert "$TLS_CERT_FILE" --key "$TLS_KEY_FILE")
        [ -n "$TLS_CHAIN_FILE" ] && cargs+=(--chain "$TLS_CHAIN_FILE")
        if reason="$(python3 "$PF_DIR/deploy/install_cert.py" "${cargs[@]}" 2>&1)"; then
          passed "The certificate passed every check:\n$(printf '%s' "$reason" | grep -vE '^RESULT' | head -9)"; break
        fi
        # never installed with a failing check: change the answers or stop (no "continue anyway" here)
        after_failure TLS_CERT_FILE "the certificate" "$(printf '%s' "$reason" | grep -E 'REFUSED|note' | head -6)" \
          TLS_DOMAIN TLS_CERT_FILE TLS_KEY_FILE TLS_CHAIN_FILE \
          || fail "A certificate that does not pass its checks is never installed. Fix it and run the installer again."
      done
    fi
    ask_input ALLOWED_HOSTS "Host names" "Extra names people will type to reach it (comma separated), for example
lookingglass.example.org. This computer's own names and addresses always work.
Leave empty if none." "" ""; ALLOWED_HOSTS="$REPLY"
    if [ -n "$TLS_DOMAIN" ] && [[ ",$ALLOWED_HOSTS," != *",$TLS_DOMAIN,"* ]]; then ALLOWED_HOSTS="$TLS_DOMAIN${ALLOWED_HOSTS:+,$ALLOWED_HOSTS}"; fi
  fi
  ask_input LG_PORT "Port" "Port for Looking Glass ($PORT_DEFAULT unless something else uses it$([ "$HTTPS" = domain ] && echo '; 443 is what browsers use for https://')):" "$PORT_DEFAULT" v_lg_port; LG_PORT="$REPLY"
  in_use "$LG_PORT" && passed "Port $LG_PORT is used by Looking Glass itself (a re-install): it will be kept." \
                    || passed "Port $LG_PORT is free for Looking Glass."
  PUBLIC_PORT=""
  if [ "$HTTPS" = domain ] || [ "$HTTPS" = selfsigned ]; then
    # Caddy takes the port people use; Looking Glass itself listens on this computer only, on a port of its own, so a
    # few deliberately slow connections can never hold it up (deploy/caddy_front.sh). Behind Caddy: TRUST_PROXY=1.
    PUBLIC_PORT="$LG_PORT"; TRUST_PROXY=1
    LG_PORT=""
    for q in $(seq 5000 5099); do
      [ "$q" = "$PUBLIC_PORT" ] && continue
      if ! in_use "$q" || systemctl show -p ExecStart --value looking-glass 2>/dev/null | grep -qE -- "--bind 127\.0\.0\.1:$q( |;|$)"; then LG_PORT="$q"; break; fi
    done
    [ -n "$LG_PORT" ] || fail "No free port between 5000 and 5099 for Looking Glass behind Caddy."
    passed "Caddy will answer on port $PUBLIC_PORT; Looking Glass listens on this computer only, port $LG_PORT."
  fi
  ask_yesno REGISTRATION "Accounts" "Let people request an account on the sign-in page?
Yes: requests wait for an administrator's approval (the administrators are told in the bell).
No:  only people an administrator invites (Admin page, Add a person: a one-time sign-up link).
Either way the first administrator signs up with the one-time setup code." yes
  REGISTRATION=$([ "$REPLY" = yes ] && echo 1 || echo 0)
  # the names of the networks in the reports (the user, 2026-11-19: asked, No by default, saying what No means)
  ask_yesno NAMES_LOOKUP "Network names" "Look up the names of the networks in your reports once they are loaded?
Only AS numbers are sent, to PeeringDB and RIPEstat (public registries); nothing else leaves.

If you choose No:
  • demo mode and masked views show every network as \"Unlisted network\";
  • one check (the demo masking check's alias test) is SKIPPED until the names are looked up.
You can do it later: platform/manage/asn_registry.py 7, or Settings > Identify networks." no
  NAMES_LOOKUP="$REPLY"
  [ "$MONGO_MODE" = local ] && READONLY=yes   # (remote: asked with the MongoDB login above)
  ask_input SERVICE_NAME "Service name" "Name of the systemd service:" looking-glass v_user; SERVICE_NAME="$REPLY"
fi
ask_yesno RUN_CHECKS "Checks" "Check the installation at the end: settings, data and every security protection? (about 5 minutes)" yes; RUN_CHECKS="$REPLY"

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
MongoDB:          $(case "$MONGO_MODE" in local) [ "$MDB_MANAGED" = 1 ] && echo "keep the one set up before, port $MONGO_PORT" || echo "install here, port $MONGO_PORT$([ "$MONGO_BIND" != 127.0.0.1 ] && echo ", also on ${MONGO_BIND#127.0.0.1,}")" ;; existing) echo "the one already on this computer, port $MONGO_PORT (not reconfigured)" ;; *) echo "internal, $MONGO_HOST:$MONGO_PORT, $([ "$MONGO_TLS" = 1 ] && echo 'TLS' || echo 'NOT encrypted (trusted link)')" ;; esac) · database $MONGO_DB · account ${MONGO_ADMIN_USER:-(none)}"
if [ $WANT_DB = 1 ]; then S+="
Reports from:     $SOURCE_DESC
Mailbox:          $MAIL_DESC
Fetching:         $SCHED_DESC, each run looks back $EMAIL_DAYS day(s) · first run: $([ "$RUN_PIPELINE_NOW" = yes ] && echo "now, $FIRST_DAYS days" || echo later)
Sender check:     DKIM signature of every report checked; $([ "${MAIL_AUTH:-log}" = enforce ] && echo "reports that do not pass are HELD BACK" || echo "recorded only, nothing held back")"; fi
if [ $WANT_PF = 1 ]; then S+="
Country:          $COUNTRY · map token $([ -n "$MAPBOX_TOKEN" ] && echo given || echo 'NOT given (add later)') · Malpedia $([ -n "$MALPEDIA_TOKEN" ] && echo given || echo skipped)
Access:           $ACCESS_MODE$([ -n "$VIEWER_NETWORKS" ] && echo " ($VIEWER_NETWORKS)") · HTTPS: $HTTPS$([ -n "$TLS_DOMAIN" ] && echo " ($TLS_DOMAIN, certificate checked)")$([ -n "${PUBLIC_PORT:-}" ] && echo " · Caddy in front on port $PUBLIC_PORT, Looking Glass on 127.0.0.1:$LG_PORT" || echo " · port $LG_PORT") · service $SERVICE_NAME
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
              "MONGO_DB=$MONGO_DB" "MONGO_LOCAL=$([ "$MONGO_MODE" = local ] && echo true || echo false)" "MONGO_BIND=$MONGO_BIND" \
              "MONGO_TLS=$MONGO_TLS" "MONGO_TLS_CA_FILE=$MONGO_TLS_CA_FILE" "MONGO_ALLOW_PLAINTEXT=$MONGO_ALLOW_PLAINTEXT"; do
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
  if declare -F wait_for_apt >/dev/null && apt_lock_holder >/dev/null; then
    # shown in the progress window; after 10 minutes without progress the person chooses (gauge_ask)
    APT_ASK=gauge_ask wait_for_apt gauge_wait || { gauge_close; fail "Stopped while waiting for the package manager (nothing was installed after that point)."; }
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
              "MONGO_TLS=$MONGO_TLS" "MONGO_TLS_CA_FILE=$MONGO_TLS_CA_FILE" "MONGO_ALLOW_PLAINTEXT=$MONGO_ALLOW_PLAINTEXT" \
              "MONGO_DB=$MONGO_DB" "COUNTRY=$COUNTRY" "ACCESS_MODE=$ACCESS_MODE" "VIEWER_NETWORKS=$VIEWER_NETWORKS" \
              "ALLOWED_HOSTS=$ALLOWED_HOSTS" "TRUST_PROXY=$TRUST_PROXY" "ALLOW_INSECURE_REMOTE_LOGIN=$INSECURE" \
              "REGISTRATION=$REGISTRATION" "LG_PORT=$LG_PORT"; do
      env_set "$PF_DIR/.env" "${kv%%=*}" "${kv#*=}"
    done
    env_set "$PF_DIR/.env" MONGO_PASSWORD "$MONGO_ADMIN_PASSWORD"
    env_set "$PF_DIR/.env" MAPBOX_TOKEN "$MAPBOX_TOKEN"
    env_set "$PF_DIR/.env" MALPEDIA_TOKEN "$MALPEDIA_TOKEN"
    env_set "$PF_DIR/.env" REF_SECRET "$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
    # the connectors' stored keys are encrypted under this (connectors.py); the service can read .env, never change it
    env_set "$PF_DIR/.env" CONNECTOR_KEY_SECRET "$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
  fi
  gauge 60 "Setting up the platform's Python environment and packages..."
  # --no-sources: the name sources are downloaded below as a step of their own, which never stops the installation
  # Looking Glass never listens on the network itself: locally it serves this computer, otherwise Caddy is in front
  iargs=(--port "$LG_PORT" --name "$SERVICE_NAME" --no-sources)
  run "platform install (deploy/install.sh)" bash -c "cd '$PF_DIR' && deploy/install.sh ${iargs[*]}"
  # MISP Galaxy and MITRE ATT&CK (public files from GitHub): what explains malware names Malpedia and the researchers do
  # not, and the ATT&CK techniques of reports, advisories and CVEs. Refreshed weekly by cron (deploy/install.sh step 5).
  gauge 66 "Downloading MISP Galaxy and MITRE ATT&CK (public lists that explain malware names; about a minute)..."
  SOURCES_WARN=""
  if bg_wait bash -c "cd '$PF_DIR' && manage/fetch_offline_names.py --by installer"; then
    log "name sources downloaded"
  else
    SOURCES_WARN="MISP Galaxy / MITRE ATT&CK not (all) downloaded (no internet?): the weekly refresh tries again, or run platform/manage/fetch_offline_names.py."
    log "$SOURCES_WARN"
  fi
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
  if [ "$HTTPS" = domain ]; then
    # checked again as it is installed (the files may have changed since the questions); recorded in the audit log
    gauge 74 "Installing the certificate for $TLS_DOMAIN..."
    iargs=(install --domain "$TLS_DOMAIN" --cert "$TLS_CERT_FILE" --key "$TLS_KEY_FILE" --by installer)
    [ -n "$TLS_CHAIN_FILE" ] && iargs+=(--chain "$TLS_CHAIN_FILE")
    run "certificate for $TLS_DOMAIN" python3 "$PF_DIR/deploy/install_cert.py" "${iargs[@]}"
  fi
  gauge 78 "Installing and starting the $SERVICE_NAME service..."
  run "service file" sudo install -m 644 "$PF_DIR/deploy/$SERVICE_NAME.service" "/etc/systemd/system/$SERVICE_NAME.service"
  run "systemd reload" sudo systemctl daemon-reload
  run "enable service" sudo systemctl enable "$SERVICE_NAME"
  run "start service" sudo systemctl restart "$SERVICE_NAME"
  scheme=http; [ -f "$PF_DIR/data/tls/cert.pem" ] && scheme=https
  ok=0; for _ in $(seq 1 60); do curl -sfk "$scheme://127.0.0.1:$LG_PORT/healthz" >/dev/null 2>&1 && { ok=1; break; }; sleep 1; done
  if [ $ok = 0 ]; then
    # shellcheck disable=SC2024  # the installer's log is this user's own file: only reading the journal needs root
    sudo journalctl -u "$SERVICE_NAME" -n 40 --no-pager >> "$LOG" 2>&1 || true
    gauge_close; fail "The $SERVICE_NAME service did not start."
  fi
  PF_URL="$scheme://localhost:$LG_PORT"
  FW_NOTE=""
  if [ -n "$PUBLIC_PORT" ]; then
    # Caddy in front (deploy/caddy_front.sh): installed from its signed repository (the key checked by fingerprint),
    # the same certificate, strict time limits for slow connections; Looking Glass stays on 127.0.0.1:$LG_PORT.
    # A domain's certificate (public, or internal with one), or an internal installation's own (--internal).
    gauge 79 "Putting Caddy in front of Looking Glass on port $PUBLIC_PORT..."
    if [ "$HTTPS" = domain ]; then
      cfargs=(setup --project "$PF_DIR" --domain "$TLS_DOMAIN" --public-port "$PUBLIC_PORT" --backend-port "$LG_PORT")
    else
      cfargs=(setup --project "$PF_DIR" --internal --public-port "$PUBLIC_PORT" --backend-port "$LG_PORT")
    fi
    [ -n "${LG_CA_BUNDLE:-}" ] && cfargs+=(--ca-bundle "$LG_CA_BUNDLE")
    run "Caddy in front (port $PUBLIC_PORT)" sudo bash "$PF_DIR/deploy/caddy_front.sh" "${cfargs[@]}"
    # the firewall: when ufw is on, the HTTPS port is opened (Caddy listens on no other port); otherwise say so
    if command -v ufw >/dev/null 2>&1 && sudo ufw status 2>/dev/null | grep -q "^Status: active"; then
      run "firewall: allow $PUBLIC_PORT/tcp" sudo ufw allow "$PUBLIC_PORT/tcp" comment "Looking Glass HTTPS"
    else
      FW_NOTE="No active ufw firewall here: make sure only port $PUBLIC_PORT (HTTPS) of this server is open$([ "$ACCESS_MODE" = public ] && echo " to the internet" || echo " on your network")."
    fi
  fi
  if [ "$HTTPS" = domain ]; then
    # SELF_CHECK_HTTPS: the site, by its domain, over HTTPS with the certificate verified the way a browser does (no -k);
    # the domain is pointed at this computer for the check only (--resolve), so it works before DNS has changed.
    # LG_CA_BUNDLE: a private certificate authority's roots (test installations), else the system's
    gauge 80 "Checking https://$TLS_DOMAIN with its certificate..."
    cab=(); [ -n "${LG_CA_BUNDLE:-}" ] && cab=(--cacert "$LG_CA_BUNDLE")
    if curl -sf --max-time 15 "${cab[@]}" --resolve "$TLS_DOMAIN:$PUBLIC_PORT:127.0.0.1" "https://$TLS_DOMAIN:$PUBLIC_PORT/healthz" >/dev/null 2>>"$LOG"; then
      log "HTTPS self-check passed for $TLS_DOMAIN:$PUBLIC_PORT (through Caddy)"
    else
      gauge_close; fail "Looking Glass runs, but https://$TLS_DOMAIN:$PUBLIC_PORT does not answer with a certificate a browser would accept. The log says why."
    fi
    PF_URL="https://$TLS_DOMAIN$([ "$PUBLIC_PORT" = 443 ] || echo ":$PUBLIC_PORT")"
  elif [ -n "$PUBLIC_PORT" ]; then
    # an internal installation through Caddy, by the name its certificate is for (caddy_front.sh checked it answers)
    iname="$(sudo sed -n 's/^# internal: //p' /etc/caddy/Caddyfile 2>/dev/null | head -1)"
    [[ "$iname" == *:* ]] && iname="[$iname]"
    PF_URL="https://${iname:-localhost}$([ "$PUBLIC_PORT" = 443 ] || echo ":$PUBLIC_PORT")"
  fi
  # unusual activity (unusual_worker.py): its own timer, every hour; counts only, the platform's read-only account
  gauge 81 "Setting up unusual activity (an hourly count of the report days)..."
  log "\$ unusual activity timer (deploy/unusual_timer.sh install)"
  if ! bg_wait sudo bash "$PF_DIR/deploy/unusual_timer.sh" install; then
    PF_WARN="${PF_WARN:+$PF_WARN }Unusual activity is not counted yet: run sudo platform/deploy/unusual_timer.sh install."
  fi
  [ -z "$MAPBOX_TOKEN" ] && PF_WARN="No Mapbox token yet: add MAPBOX_TOKEN to platform/.env, then platform/deploy/reload.sh."
  [ -n "$SOURCES_WARN" ] && PF_WARN="${PF_WARN:+$PF_WARN }$SOURCES_WARN"
fi

# ---- checks
declare -a RESULTS=()
check() {  # LABEL command...
  local label="$1"; shift
  log "\$ check: $label"
  if bg_wait "$@"; then RESULTS+=("PASS  $label"); else RESULTS+=("FAIL  $label"); fi
}
if [ $WANT_PF = 1 ] && [ "${NAMES_LOOKUP:-no}" = yes ]; then
  gauge 82 "Looking up the names of the networks in the reports (only AS numbers are sent)..."
  log "\$ platform/manage/asn_registry.py 7"
  bg_wait bash -c 'cd "$1" && .venv/bin/python manage/asn_registry.py 7' _ "$PF_DIR" \
    || PF_WARN="${PF_WARN:+$PF_WARN }The network names could not be looked up now (see the log): run platform/manage/asn_registry.py 7 later."
fi
if [ "$RUN_CHECKS" = yes ]; then
  if [ $WANT_DB = 1 ]; then gauge 84 "Checking the database pipeline..."; check "database pipeline setup (shadowserver check)" bash -c "cd '$DB_DIR' && ./check.sh"; fi
  if [ $WANT_PF = 1 ]; then
    gauge 86 "Checking the platform's libraries..."
    check "platform libraries (tests/check_libraries.py)" bash -c "cd '$PF_DIR' && .venv/bin/python tests/check_libraries.py"
    gauge 88 "Checking the platform's security protections (about 2 minutes)..."
    check "platform security protections (security_testing/security_retest.py)" bash -c "cd '$PF_DIR' && security_testing/security_retest.py"
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
if [ "$(stat -c %Y "$ROOT/suspected-packages.json" 2>/dev/null || echo 0)" != "$SUSPECT_BEFORE" ]; then OUT+="

WARNING: a library file from one source did not match the lock (suspected tampering). It was refused and a
      matching copy from another source was installed. Details: suspected-packages.txt in this folder.
      Please report it: docs/INSTALLATION.md, \"When a library file does not match\"."; fi
if printf '%s\n' "${RESULTS[@]}" | grep -q '^FAIL.*run_all_checks'; then OUT+="
Note: the platform checks need yesterday's reports in the database; they fail until the first
      reports are loaded. Run them again later: platform/tests/run_all_checks.sh"; fi
if printf '%s\n' "${RESULTS[@]}" | grep -q '^FAIL.*check_libraries'; then OUT+="
Note: a library the platform uses is missing, outside the versions it supports, or behaves
      differently. This does not depend on reports. See the log, or run: platform/.venv/bin/python
      platform/tests/check_libraries.py"; fi
[ $WANT_PF = 1 ] && [ "${NAMES_LOOKUP:-no}" != yes ] && OUT+="
Note: network names were not looked up, so demo mode shows \"Unlisted network\" and the demo masking check
      skips its alias test. Later: platform/manage/asn_registry.py 7 (only AS numbers are sent)."
[ $WANT_PF = 1 ] && OUT+="

Next: open $PF_URL on this computer and choose \"Let's get started\" to create the
first administrator (with an authenticator app). It asks for the one-time setup code; read it with:
  cat platform/data/setup_code
Guides: docs/USER_GUIDE.md"
if [ "${HTTPS:-none}" = domain ]; then OUT+="
HTTPS:   https://$TLS_DOMAIN$([ "${PUBLIC_PORT:-443}" = 443 ] || echo ":$PUBLIC_PORT") answers with its certificate (checked here), through
         Caddy in front; Looking Glass itself listens on this computer only (port $LG_PORT). Point the domain's DNS
         record at this server's public address if it does not yet. The bell warns 30, 14 and 3 days before the
         certificate expires; install the renewed one with platform/manage/install_cert.sh (it updates Caddy too).${FW_NOTE:+
         $FW_NOTE}"
elif [ "${ACCESS_MODE:-local}" != local ]; then OUT+="
Other computers: allow port $LG_PORT in the firewall for them only (docs/INSTALLATION.md)."
fi
# a self-signed certificate: each screen trusts it once, after checking its fingerprint; nobody clicks past a warning
if [ "${HTTPS:-none}" = selfsigned ] && [ -f "$PF_DIR/data/tls/cert.pem" ]; then
  TLS_FP="$(openssl x509 -in "$PF_DIR/data/tls/cert.pem" -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2)"
  OUT+="
Certificate: self-signed, SHA-256 fingerprint
         ${TLS_FP:-(read it with: openssl x509 -in platform/data/tls/cert.pem -noout -fingerprint -sha256)}
         Trust platform/data/tls/cert.pem on every screen that opens Looking Glass, after checking that its
         fingerprint matches this one (docs/INSTALLATION.md, A8). Never click past a certificate warning."
fi
# encryption at rest (platform/at_rest.py): MongoDB Community does not encrypt its files; an encrypted volume does
if [ -f "$PF_DIR/at_rest.py" ]; then
  AT_REST="$(python3 "$PF_DIR/at_rest.py" "data=$PF_DIR/data" "database=$(python3 -c 'import sys; sys.path.insert(0, sys.argv[1]); import at_rest; print(at_rest.mongo_dbpath())' "$PF_DIR" 2>/dev/null || echo /var/lib/mongodb)" \
              ${DB_DIR:+"reports=$DB_DIR"} 2>/dev/null | sed -n 's/^SUMMARY //p')"
  log "encryption at rest: ${AT_REST:-not checked}"
  case "$AT_REST" in
    encrypted) OUT+="
Encryption at rest: the database, the reports and the platform's data are on encrypted volumes." ;;
    "check Windows") OUT+="
Encryption at rest: inside WSL, turn on BitLocker for the Windows drive that holds WSL (Windows Settings, Privacy and
         security, Device encryption or BitLocker): the database and the reports are not encrypted otherwise." ;;
    *) OUT+="
Encryption at rest: ${AT_REST:-not checked}. MongoDB does not encrypt its files: put this server's disk on an encrypted
         volume (LUKS), see platform/docs/SECURITY.md, Encryption at rest. Backups: put your public key in
         platform/data/backup_public_key so platform/manage/backup.sh can encrypt them." ;;
  esac
fi
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
