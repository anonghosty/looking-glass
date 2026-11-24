# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""Caddy kept up to date (the user, 2026-11-23): the administrators' bell says when the Caddy that Looking Glass put in
front (deploy/caddy_front.sh) is behind the newest version its signed repository offers, or when Ubuntu's automatic
updates, which install Caddy's updates by themselves, are not on. Only where Looking Glass set Caddy up (the
Caddyfile's first line is its mark); nothing is changed here, the alert says what to run.

state() asks dpkg and apt (local files only, nothing goes out) at most once an hour: {installed, candidate, behind,
auto_updates, reasons}. bell(base, now) -> system_alerts items, administrators only.
"""
import os
import subprocess
import threading
import time

CONF = "/etc/caddy/Caddyfile"
MARK = "# Managed by Looking Glass (deploy/caddy_front.sh)"
AUTOUPD = "/etc/apt/apt.conf.d/52looking-glass-caddy"
CHECK_EVERY = 3600
_lock = threading.Lock()
_cache = {"at": 0.0, "state": None}


def _run(args):
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=20, check=False)  # noqa: S603  (fixed commands)
        return p.returncode, p.stdout
    except (OSError, subprocess.SubprocessError):
        return 1, ""


def managed(conf=CONF):
    try:
        with open(conf, encoding="utf-8") as f:
            return f.readline().startswith(MARK)
    except OSError:
        return False


def state(conf=CONF, autoupd=AUTOUPD, run=_run):
    """{installed, candidate, behind, auto_updates, reasons} for a Caddy set up by Looking Glass, else None."""
    if not managed(conf):
        return None
    _, installed = run(["dpkg-query", "-W", "-f=${Version}", "caddy"])
    installed = installed.strip()
    _, pol = run(["apt-cache", "policy", "caddy"])
    candidate = next((ln.split(":", 1)[1].strip() for ln in pol.splitlines() if ln.strip().startswith("Candidate:")), "")
    candidate = "" if candidate == "(none)" else candidate
    behind = False
    if installed and candidate and candidate != installed:
        rc, _ = run(["dpkg", "--compare-versions", installed, "lt", candidate])
        behind = rc == 0
    reasons = []
    _, uu = run(["dpkg-query", "-W", "-f=${Status}", "unattended-upgrades"])
    if "install ok installed" not in uu:
        reasons.append("Ubuntu's automatic updates (the unattended-upgrades package) are not installed")
    _, per = run(["apt-config", "dump", "APT::Periodic::Unattended-Upgrade"])
    vals = [ln.split(None, 1)[1].strip('";') for ln in per.splitlines() if ln.startswith("APT::Periodic::Unattended-Upgrade ")]
    if not vals or vals[-1] in ("0", ""):
        reasons.append("Ubuntu's automatic updates are switched off (APT::Periodic::Unattended-Upgrade)")
    if not os.path.exists(autoupd):
        reasons.append(f"Caddy's repository is not among the automatic updates ({autoupd} is missing)")
    return {"installed": installed, "candidate": candidate, "behind": behind, "auto_updates": not reasons, "reasons": reasons}


def cached_state(now=None, **kw):
    now = now or time.time()
    with _lock:
        if _cache["state"] is not None and now - _cache["at"] < CHECK_EVERY and not kw:
            return _cache["state"]
    st = state(**kw)
    with _lock:
        _cache.update(at=now, state=st or {})
    return st or {}


def bell(base=None, now=None, **kw):
    """Administrators' alerts: Caddy behind the newest version, and automatic updates not running for it."""
    now = now or time.time()
    st = cached_state(now, **kw)
    out = []
    if st.get("behind"):
        out.append({"key": f"caddy-behind:{st['candidate']}", "problem": True,
                    "title": f"Caddy {st['candidate']} is available (this server runs {st['installed']})",
                    "text": ("Caddy, in front of Looking Glass on the internet, has a newer version in its signed repository. "
                             "Update it on the server: sudo deploy/caddy_front.sh update (it checks the repository's key, "
                             "updates Caddy only and checks the site through it)."),
                    "at": now, "link": "/settings#monitor", "perms": ("settings",)})
    if st and not st.get("auto_updates", True):
        out.append({"key": "caddy-autoupdates:" + "|".join(st.get("reasons") or []), "problem": True,
                    "title": "Caddy's updates do not install by themselves",
                    "text": ("; ".join(st.get("reasons") or []) + ". Run sudo deploy/caddy_front.sh update now, and switch "
                             "automatic updates on: sudo dpkg-reconfigure -plow unattended-upgrades (docs/INSTALLATION.md)."),
                    "at": now, "link": "/settings#monitor", "perms": ("settings",)})
    return out
