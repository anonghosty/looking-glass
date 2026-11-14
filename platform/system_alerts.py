"""System alerts in the bell, for administrators: a restart, a failing pipeline run or a filling disk was only in log
files, so nobody was told.

Shown to accounts with the 'settings' permission, next to their findings notifications (notifications.py), shaped
like them so the bell shows them as they are:
  - Looking Glass restarted (each start in the last 24 hours, from data/restarts.jsonl, written at start)
  - the pipeline's last run failed, or no run finished for PIPELINE_STALE_HOURS (default 26), or its disk is low
    (the pipeline's pipeline_status.json, retention.py in the pipeline's folder; read only)
  - the weekly MISP Galaxy / ATT&CK refresh failed (data/names_refresh.json)
Each alert has an id that changes when something new happens; clearing one hides that alert for that person only
(data/system_alerts_seen.json). Nothing here holds an address or a report's content.
"""
import calendar
import json
import os
import threading
import time

import pipeline_link

RESTART_SHOW_S = 24 * 3600


def _read_json(path):
    try:
        with open(path, encoding="utf-8") as f:
            d = json.load(f)
        return d if isinstance(d, dict) else None
    except (OSError, ValueError):
        return None


def _when(t):
    return time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(t)) if t else ""


def note_start(data_dir, now=None):
    """Called once at start: one line per start, the last 50 kept."""
    path = os.path.join(data_dir, "restarts.jsonl")
    now = now or time.time()
    try:
        old = open(path, encoding="utf-8").read().splitlines()[-49:]
    except OSError:
        old = []
    try:
        fd = os.open(path + ".tmp", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write("\n".join(old + [json.dumps({"t": round(now), "pid": os.getpid()})]) + "\n")
        os.replace(path + ".tmp", path)
    except OSError:
        pass


class Alerts:
    def __init__(self, base_dir, env=os.environ):
        self.base_dir, self.data = base_dir, os.path.join(base_dir, "data")
        self.env = env
        self.seen_path = os.path.join(self.data, "system_alerts_seen.json")
        self.lock = threading.Lock()

    def _pipeline_status(self):
        pdir = pipeline_link.find_dir(self.base_dir)
        if not pdir:
            return None
        penv = pipeline_link.read_env(os.path.join(pdir, ".env"))
        base = penv.get("DATA_DIR") or str(pdir)
        return _read_json(os.path.join(os.path.expanduser(base), "pipeline_status.json"))

    def current(self, now=None):
        """Every alert that applies now: [{key, problem, title, text, at, link}]."""
        now = now or time.time()
        out = []
        try:
            starts = [json.loads(x) for x in open(os.path.join(self.data, "restarts.jsonl"), encoding="utf-8") if x.strip()]
        except (OSError, ValueError):
            starts = []
        recent = sorted(t for t in ((s.get("t") or 0) for s in starts if isinstance(s, dict)) if now - t < RESTART_SHOW_S)
        if recent:                                   # one alert for every start of the last day: the latest, and how many
            t = recent[-1]
            more = f" It started {len(recent)} times in the last 24 hours." if len(recent) > 1 else ""
            out.append({"key": f"restart:{t}", "problem": False,
                        "title": "Looking Glass restarted" + (f" ({len(recent)} times today)" if len(recent) > 1 else ""),
                        "text": f"the service started again at {_when(t)} (an update, a reload or the computer restarting).{more}",
                        "at": t, "link": "/settings#monitor"})
        st = self._pipeline_status()
        try:
            stale_h = max(1.0, float(self.env.get("PIPELINE_STALE_HOURS", "26") or 26))
        except ValueError:
            stale_h = 26.0
        if st:
            t = st.get("finished") or 0
            if not st.get("ok"):
                bits = [f"{st.get('file_errors', 0)} file error(s)" if st.get("file_errors") else "",
                        "the mailbox could not be read" if st.get("email_failed") else ""]
                out.append({"key": f"pipeline-failed:{t}", "problem": True, "title": "The last report run had problems",
                            "text": f"the pipeline's run of {_when(t)} did not go well" + (": " + ", ".join(b for b in bits if b) if any(bits) else "")
                            + ". Its log says more (Settings → Workers).", "at": t, "link": "/settings#workers"})
            if t and now - t > stale_h * 3600:
                out.append({"key": f"pipeline-stale:{t}", "problem": True, "title": "No report run lately",
                            "text": f"the pipeline last finished a run at {_when(t)}, more than {stale_h:g} hours ago. Check its schedule.",
                            "at": t, "link": "/settings#workers"})
            if st.get("disk_low"):
                out.append({"key": f"disk-low:{t}", "problem": True, "title": "The disk is filling up",
                            "text": f"{st.get('free_gb')} GB free where the reports are kept (warning below {st.get('min_free_gb')} GB). "
                                    "Free space, or set SORTED_KEEP_DAYS in the pipeline's .env.", "at": t, "link": "/settings#workers"})
        ns = _read_json(os.path.join(self.data, "names_refresh.json"))
        if ns and ns.get("ok") is False:
            at = ns.get("at") or ""
            try:
                t = calendar.timegm(time.strptime(at[:19], "%Y-%m-%dT%H:%M:%S"))     # written in UTC
            except ValueError:
                t = now
            out.append({"key": f"names-failed:{at}", "problem": True, "title": "The MISP Galaxy / ATT&CK refresh failed",
                        "text": "the old copies stay in use. The Definitions page says why.", "at": t, "link": "/definitions"})
        return out

    def _seen(self):
        return _read_json(self.seen_path) or {}

    def for_user(self, user, now=None):
        """This person's alerts not cleared yet, as bell items (notifications.js)."""
        mine = set(self._seen().get(user) or [])
        out = []
        for a in self.current(now):
            if a["key"] in mine:
                continue
            out.append({"id": "sys:" + a["key"], "number": "System", "case": False, "network": "", "title": a["title"],
                        "status": "system", "status_label": "Needs a look" if a["problem"] else "For your information",
                        "by": "Looking Glass", "text": a["text"], "updates": 1, "at": float(a["at"] or 0),
                        "when": _when(a["at"]), "waiting": a["problem"], "link": a["link"]})
        return out

    def clear(self, user, ids):
        """Hide these alerts (ids 'sys:<key>') for this person; keys that no longer apply are dropped."""
        keys = {i[4:] for i in ids if isinstance(i, str) and i.startswith("sys:")}
        if not keys:
            return 0
        live = {a["key"] for a in self.current()}
        with self.lock:
            d = self._seen()
            mine = (set(d.get(user) or []) | keys) & live
            d[user] = sorted(mine)
            tmp = f"{self.seen_path}.{os.getpid()}.tmp"
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(d, f)
            os.replace(tmp, self.seen_path)
        return len(keys & live)
