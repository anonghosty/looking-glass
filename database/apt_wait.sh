# shellcheck shell=bash
# Waiting for the system's package manager (sourced by install.sh and database/deploy.sh; the user, 2026-11-19).
#
# A new Ubuntu runs its automatic updates (unattended-upgrades) soon after it starts, and while they run every other
# package installation fails with "Could not get lock /var/lib/dpkg/lock-frontend" (lg-try, 2026-11-19: the installer
# stopped at MongoDB). Instead of failing, or waiting in silence, wait_for_apt says what holds the lock, for how long,
# and its latest step, every few seconds, for as long as it makes progress. After APT_WAIT_STALL_MIN minutes (10)
# without any progress it asks: keep waiting, stop the automatic update for now (it runs again later by itself), or
# stop here.
#
#   wait_for_apt [SAY]   SAY: a function called with one line of status (default: print it); returns 0 when the
#                        package manager is free, 1 when the person chose to stop here
#   APT_ASK              a function called with the stall message; it sets APT_CHOICE to wait | stop-update | cancel
#                        (default: a text prompt; none when there is no terminal: it keeps waiting). It runs in this
#                        shell, not a sub-shell, so it may close and open the installer's progress window.

APT_LOCKS=(/var/lib/dpkg/lock-frontend /var/lib/dpkg/lock /var/lib/apt/lists/lock /var/cache/apt/archives/lock)
APT_WAIT_STALL_MIN="${APT_WAIT_STALL_MIN:-10}"

apt_lock_holder() {  # prints "PID NAME" of what holds a package lock, or nothing (returns 1)
  local f p n
  if command -v fuser >/dev/null 2>&1; then
    for f in "${APT_LOCKS[@]}"; do
      p="$(sudo -n fuser "$f" 2>/dev/null | tr -s ' ' '\n' | grep -E '^[0-9]+$' | head -n1 || true)"
      if [ -n "$p" ]; then n="$(ps -o comm= -p "$p" 2>/dev/null || true)"; printf '%s %s\n' "$p" "${n:-?}"; return 0; fi
    done
  fi
  # without fuser (or sudo): the usual holders by name
  p="$(pgrep -o -f '/usr/bin/unattended-upgrade$|^/usr/bin/unattended-upgrade |apt-get |^apt |/usr/bin/dpkg |packagekitd' 2>/dev/null || true)"
  [ -n "$p" ] || return 1
  n="$(ps -o comm= -p "$p" 2>/dev/null || true)"; printf '%s %s\n' "$p" "${n:-?}"
}

apt_holder_words() {  # NAME -> what people call it
  case "$1" in
    unattended-upgr*) echo "Ubuntu's automatic updates (unattended-upgrades)" ;;
    packagekitd) echo "the software updater (PackageKit)" ;;
    apt|apt-get|aptitude) echo "another package installation (apt)" ;;
    dpkg) echo "another package installation (dpkg)" ;;
    *) echo "another program ($1)" ;;
  esac
}

apt_latest_step() {  # PID -> its latest step, in a few words
  local pid="$1" line
  if pgrep -P "$pid" -f /usr/lib/apt/methods/http >/dev/null 2>&1; then echo "downloading packages"; return; fi
  line="$(tail -n1 /var/log/dpkg.log 2>/dev/null || true)"
  if [ -n "$line" ] && [ $(( $(date +%s) - $(stat -c %Y /var/log/dpkg.log 2>/dev/null || echo 0) )) -lt 120 ]; then
    # "2026-11-19 07:31:02 status unpacked libssl3t64:amd64 3.0.13-0ubuntu3.6": the step and the package
    set -- $line
    echo "installing: ${3:-} ${5:-} ${6:-}" | sed 's/ \+$//'; return
  fi
  line="$(tail -n1 /var/log/unattended-upgrades/unattended-upgrades.log 2>/dev/null | cut -d' ' -f4- || true)"
  echo "${line:-working}" | cut -c1-90
}

apt_progress_sign() {  # anything that changes while the holder works: the logs and the download folder
  stat -c '%Y %s' /var/log/dpkg.log /var/log/unattended-upgrades/unattended-upgrades.log /var/log/apt/term.log 2>/dev/null | tr '\n' ' '
  du -sb /var/cache/apt/archives/partial 2>/dev/null | cut -f1
}

_apt_say() { printf '  %s\n' "$*"; }
_apt_ask() {  # MESSAGE -> APT_CHOICE = wait | stop-update | cancel (set, not printed: the asker runs in this shell)
  APT_CHOICE="wait"
  [ -t 0 ] || return 0
  local a
  printf '%s\n' "$1" >&2
  read -rp "  [w]ait longer, [s]top the automatic update for now, [c]ancel? [w]: " a </dev/tty
  case "${a,,}" in s*) APT_CHOICE="stop-update" ;; c*) APT_CHOICE="cancel" ;; *) APT_CHOICE="wait" ;; esac
}

wait_for_apt() {
  local say="${1:-_apt_say}" ask="${APT_ASK:-_apt_ask}" h pid name since sign last_sign last_change now mins words
  h="$(apt_lock_holder)" || return 0
  pid="${h%% *}"; name="${h#* }"; words="$(apt_holder_words "$name")"
  last_sign=""; last_change=$(date +%s)
  while h="$(apt_lock_holder)"; do
    pid="${h%% *}"; name="${h#* }"; words="$(apt_holder_words "$name")"
    since="$(ps -o etimes= -p "$pid" 2>/dev/null | tr -d ' ' || true)"; since="${since:-0}"
    now=$(date +%s); sign="$(apt_progress_sign)"
    [ "$sign" != "$last_sign" ] && { last_sign="$sign"; last_change=$now; }
    "$say" "Waiting for $words to finish: running $(( since / 60 )) min, now $(apt_latest_step "$pid"). The installation goes on by itself as soon as it is done."
    mins=$(( (now - last_change) / 60 ))
    if [ "$mins" -ge "$APT_WAIT_STALL_MIN" ]; then
      APT_CHOICE="wait"; "$ask" "$words has shown no progress for $mins minutes (process $pid)."
      case "$APT_CHOICE" in
        stop-update)
          # never "systemctl stop unattended-upgrades": the service waits for the running update to finish, so with a
          # stalled download it waits for ever (lg-try, 2026-11-19). The process itself is ended: politely, then, only
          # while it is downloading (nothing half-installed), for good. The update runs again later by itself.
          "$say" "Stopping $words for now (it runs again later by itself)..."
          sudo kill -TERM "$pid" 2>/dev/null || true
          local _
          for _ in 1 2 3 4 5 6; do kill -0 "$pid" 2>/dev/null || break; sleep 2; done
          if kill -0 "$pid" 2>/dev/null && pgrep -P "$pid" -f /usr/lib/apt/methods/http >/dev/null 2>&1 \
             && ! pgrep -x dpkg >/dev/null 2>&1; then
            sudo kill -KILL "$pid" 2>/dev/null || true; sleep 2
          fi
          kill -0 "$pid" 2>/dev/null || sudo dpkg --configure -a >/dev/null 2>&1 || true ;;
        cancel) return 1 ;;
        *) last_change=$(date +%s) ;;
      esac
    fi
    sleep 5
  done
  "$say" "The package manager is free: going on."
  return 0
}
