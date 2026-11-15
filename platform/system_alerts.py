"""System alerts in the bell, for administrators: a restart, a failing pipeline run or a filling disk was only in log
files, so nobody was told.

Shown to accounts with the 'settings' permission, next to their findings notifications (notifications.py), shaped
like them so the bell shows them as they are:
  - Looking Glass restarted (each start in the last 24 hours, from data/restarts.jsonl, written at start)
  - the pipeline's last run failed, or no run finished for PIPELINE_STALE_HOURS (default 26), or its disk is low
    (the pipeline's pipeline_status.json, retention.py in the pipeline's folder; read only)
  - the weekly MISP Galaxy / ATT&CK refresh failed (data/names_refresh.json)
  - the HTTPS certificate (data/tls) expires within 30 days: again at 14 and at 3 days, and once it has expired
  - the audit log cannot be written (a full disk...), and for 7 days after, that entries were lost (auth.Audit)
  - the sender check has stopped checking (DNS does not answer for the key), or, once, that blocking can be switched on
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
GAP_SHOW_S = 7 * 24 * 3600

# The audit log's write failures (auth.Audit, review 2026-11-15), kept in memory: the disk may be what is failing.
_AUDIT = {"failing": None, "recovered": None, "at": 0}
_AUDIT_LOCK = threading.Lock()


def note_audit_write(failing, recovered=None, now=None):
    """auth.Audit tells: failing = {since, last, count, error} while entries cannot be written; None with `recovered`
    (the same shape) once they can again and the gap has been written into the log."""
    with _AUDIT_LOCK:
        _AUDIT["failing"] = failing
        if recovered:
            _AUDIT["recovered"], _AUDIT["at"] = dict(recovered), now or time.time()


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
                        (f"{st.get('rows_failed', 0):,} row(s) not written in {st.get('files_rows_failed', 0)} file(s), tried again next run"
                         if st.get("files_rows_failed") else ""),
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
        with _AUDIT_LOCK:
            fa, rec, rec_at = _AUDIT["failing"], _AUDIT["recovered"], _AUDIT["at"]
        if fa:
            out.append({"key": f"audit-write:{round(fa['since'])}", "problem": True,
                        "title": "The audit log cannot be written",
                        "text": (f"since {_when(fa['since'])}, {fa['count']} audit entr{'y' if fa['count'] == 1 else 'ies'} could not "
                                 f"be written ({fa['error']}). Free disk space or fix the data folder's permissions; once it "
                                 "works again, the gap is written into the log."),
                        "at": fa["last"], "link": "/audit"})
        elif rec and now - rec_at < GAP_SHOW_S:
            out.append({"key": f"audit-gap:{round(rec['since'])}", "problem": True,
                        "title": "Audit entries were lost",
                        "text": (f"{rec['count']} audit entr{'y' if rec['count'] == 1 else 'ies'} could not be written between "
                                 f"{_when(rec['since'])} and {_when(rec['last'])} ({rec['error']}). The gap is recorded in the "
                                 "audit log; tell your auditor."),
                        "at": rec_at, "link": "/audit"})
        out += self._sender_check(now)
        cert = self._certificate()
        if cert and cert["days_left"] <= 30:
            days = cert["days_left"]
            step = 0 if days < 0 else 3 if days <= 3 else 14 if days <= 14 else 30     # a new alert at each step
            when = time.strftime("%Y-%m-%d", time.gmtime(cert["not_after"]))
            out.append({"key": f"tls-expiry:{cert['fingerprint'][:23]}:{step}", "problem": True,
                        "title": ("The HTTPS certificate has EXPIRED" if days < 0 else f"The HTTPS certificate expires in {days} day(s)"),
                        "text": (f"the certificate for {cert['domain'] or 'this site'} {'expired' if days < 0 else 'expires'} on {when}. "
                                 "Install the renewed one with manage/install_cert.sh (docs/OPERATIONS.md)."),
                        "at": now, "link": "/settings#monitor"})
        return out

    def _sender_check(self, now):
        """The sender check over the last 7 days (the pipeline's mail_auth.readiness, 2026-11-15): a problem when it has
        stopped checking (DNS does not answer for the key); once, a note that blocking can be switched on safely."""
        try:
            pdir = pipeline_link.find_dir(self.base_dir)
            ma = pipeline_link.mail_auth(pdir) if pdir else None
            if not (ma and hasattr(ma, "readiness")):
                return []
            mode = ma.mode(pipeline_link.read_env(pdir / ".env"))
            if mode == "off":
                return []
            week = ma.readiness(pipeline_link.data_dir(pdir) / ".mail_state.sqlite") or {}
        except Exception:  # noqa: BLE001  (an unreadable mail state never breaks the bell)
            return []
        if week.get("not_checking"):
            day = next((d["day"] for d in reversed(week["per_day"]) if d["total"]), week.get("to", ""))
            return [{"key": f"sender-not-checking:{day}:{mode}", "problem": True,
                     "title": "The sender check is not working" + (": reports are being held" if mode == "enforce" else ""),
                     "text": ("the latest report e-mails could not be checked: this server's DNS does not answer the look-up of "
                              "Shadowserver's signing key. " + ("With blocking on, those reports wait at every run and are not loaded. "
                                                                 if mode == "enforce" else "Reports are loaded, but none is verified. ")
                              + "Settings → Workers says more."), "at": now, "link": "/settings#workers"}]
        if mode == "log" and week.get("ready"):
            return [{"key": "sender-ready", "problem": False, "title": "Blocking can be switched on",
                     "text": f"every report e-mail passed the sender check on each of the last {week['days']} days. Settings → "
                             "Workers can switch blocking on, so unsigned or changed reports are held back.",
                     "at": now, "link": "/settings#workers"}]
        return []

    def _certificate(self):
        """The installed HTTPS certificate (data/tls), read with deploy/install_cert.py: domain, expiry, days left."""
        paths = [os.path.join(self.data, "tls", n) for n in ("cert.pem", "meta.json")]
        if not os.path.exists(paths[0]):
            return None
        stamp = tuple(os.path.getmtime(p) if os.path.exists(p) else 0 for p in paths)
        cached = getattr(self, "_cert_cache", None)
        if cached and cached[0] == stamp:            # read again only when the certificate files change
            c = cached[1]
            return dict(c, days_left=int((c["not_after"] - time.time()) // 86400)) if c else None
        try:
            import importlib.util
            spec = importlib.util.spec_from_file_location("lg_install_cert", os.path.join(self.base_dir, "deploy", "install_cert.py"))
            mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
            c = mod.status(self.base_dir)
        except Exception:                            # noqa: BLE001  never break the bell over the certificate
            c = None
        self._cert_cache = (stamp, c)
        return c

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
