# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
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
  - people who signed up and wait for approval (one alert for all; it comes back when someone new signs up)
  - this computer's addresses no longer match the HTTPS certificate or MongoDB's listening address (network changes)
  - one person ran many small Trace a leak searches within 24 hours (insider.py: testing guesses one address at a time)
  - the quarterly report (quarterly.py): ready, for management, advisors and administrators alike (the one alert that is
    not for administrators only: an alert's "perms" says who sees it); NOT VALID, and the quarterly purge's result, for
    administrators
  - a library file refused at installation because it did not match its lock, suspected tampering (library_supply.py)
  - code files that are not as the release shipped them (changed, or added), found by the daily code check
    (code_integrity.py)
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


COUNT_TITLES = {"intel": "Intel gathered", "services-intel": "The services patterns"}


def count_alerts(now=None):
    """A drill-down count (index_refresh.py) whose last try failed and has not succeeded since: the earlier counts are
    shown meanwhile. On the administrators' bell and in Settings → Task monitor (the user, 2026-11-17)."""
    import index_refresh
    now = now or time.time()
    out = []
    for s in index_refresh.status():
        e = s["last_error"]
        if not e:
            continue
        name = COUNT_TITLES.get(s["name"], s["name"])
        out.append({"key": f"counts-failed:{s['name']}:{round(e['at'])}", "problem": True,
                    "title": f"{name}: the counts could not be updated",
                    "text": (f"counting again failed at {_when(e['at'])} ({e['error']}). The earlier counts are shown meanwhile, "
                             f"and it is tried again at the next visit after {index_refresh.RETRY_SECONDS} s; this alert goes "
                             "once it works. Details in the service log: journalctl -u looking-glass."),
                    "at": e["at"], "link": "/settings#monitor"})
    return out


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
        out += self._decoding_asks()
        out += self._signups()
        out += self._small_traces(now)
        out += self._addresses(now)
        out += count_alerts(now)
        out += self._quarterly(now)
        out += self._suspected_packages(now)
        out += self._code_check(now)
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

    def _decoding_asks(self):
        """A family of undecoded requests an analyst asked to send to the Looking Glass creator: an administrator approves
        it first (beacon_unknown.py; the user, 2026-11-16). One alert per ask, until it is decided."""
        fams = (_read_json(os.path.join(self.data, "beacon_unknown.json")) or {}).get("families") or {}
        out = []
        for fid, s in fams.items():
            if not isinstance(s, dict) or s.get("state") != "asked":
                continue
            why = " ".join(str(s.get("asked_why") or "").split())[:160]
            out.append({"key": f"decode-ask:{fid}:{round(float(s.get('asked_at') or 0))}", "problem": True,
                        "title": "A decoding request waits for your approval",
                        "text": ("an analyst asked to send a family of requests Looking Glass could not decode to the Looking "
                                 "Glass creator" + (f": {why}" if why else "") + ". Check its request lines on the Findings "
                                 "page, then approve or not."),
                        "at": float(s.get("asked_at") or 0), "link": "/findings#beaconUnknown"})
        return out

    def _signups(self):
        """People who signed up and wait for an administrator's approval (the user, 2026-11-19: the administrators were not
        told). One alert for all of them; its key changes when someone new signs up, so clearing it hides it until then."""
        users = (_read_json(os.path.join(self.data, "users.json")) or {}).get("users") or {}
        waiting = []
        for name, u in users.items():
            if isinstance(u, dict) and u.get("status") == "pending" and not str(name).startswith("lg-selftest"):
                at = float((u.get("registered") or {}).get("at") or u.get("created") or 0)
                full = str(((u.get("profile") or {}).get("full_name") or "")).strip()
                waiting.append((at, f"{full} ({name})" if full and full.lower() != str(name).lower() else str(name)))
        if not waiting:
            return []
        waiting.sort()
        newest = waiting[-1][0]
        who = ", ".join(w for _, w in waiting[-3:]) + (f" and {len(waiting) - 3} more" if len(waiting) > 3 else "")
        title = (f"{waiting[0][1]} asks for an account" if len(waiting) == 1
                 else f"{len(waiting)} people are waiting for your approval")
        return [{"key": f"signup:{round(newest)}", "problem": True, "title": title,
                 "text": (f"waiting for your approval: {who}. On the Admin page, approve each with a role, or refuse."),
                 "at": newest, "link": "/admin"}]

    def _small_traces(self, now):
        """Someone ran many small Trace a leak searches (at most 3 lines or addresses each) within 24 hours: one or two addresses at a
        time can test guesses (external review of 1a7b016; the user, 2026-11-20). One alert per person, again at every
        further SMALL_TRACE_ALERT. Only counts and the person: never what was traced (insider.note_small_trace)."""
        try:
            import insider
            limit = insider.SMALL_TRACE_ALERT
        except Exception:                                # noqa: BLE001  never break the bell over this
            return []
        d = _read_json(os.path.join(self.data, "trace_watch.json")) or {}
        users = (_read_json(os.path.join(self.data, "users.json")) or {}).get("users") or {}
        out = []
        for name, ts in d.items():
            recent = sorted(t for t in ts if isinstance(t, (int, float)) and now - t < 86400) if isinstance(ts, list) else []
            if len(recent) < limit:
                continue
            step = len(recent) // limit                    # a new alert at each further `limit` traces
            full = str((((users.get(name) or {}).get("profile") or {}).get("full_name") or "")).strip()
            who = f"{full} ({name})" if full and full.lower() != str(name).lower() else str(name)
            out.append({"key": f"small-traces:{name}:{step}:{round(recent[step * limit - 1])}", "problem": True,
                        "title": f"{who} ran {len(recent)} small traces in 24 hours",
                        "text": (f"{len(recent)} Trace a leak searches of at most {insider.SMALL_TRACE_ITEMS} lines or addresses each since "
                                 f"{_when(recent[0])}. One or two addresses at a time can be used to test guesses at what was "
                                 "copied or downloaded. The audit log (Trace a leak entries) shows each one."),
                        "at": recent[-1], "link": "/audit"})
        return out

    def _quarterly(self, now):
        """The quarterly report (quarterly.py, r85): ready (management, advisors and admins: each sees it once), NOT VALID
        (admins), the purge done or not run (admins). Each alert says who sees it (perms) and where it leads (links)."""
        try:
            import quarterly
            return quarterly.bell(self.base_dir, now)
        except Exception:                                # noqa: BLE001  never break the bell over this
            return []

    def _suspected_packages(self, now):
        """A library file refused at installation because it did not match its lock (library_supply.py, r86): one alert
        for the events of the last 30 days, administrators only."""
        try:
            import library_supply
            return library_supply.bell(self.base_dir, now)
        except Exception:                                # noqa: BLE001  never break the bell over this
            return []

    def _code_check(self, now):
        """Code files that are not as the release shipped them, found by the daily code check (code_integrity.py, r91):
        one alert while any stand, administrators only."""
        try:
            import code_integrity
            return code_integrity.bell(self.base_dir, now)
        except Exception:                                # noqa: BLE001  never break the bell over this
            return []

    def _addresses(self, now):
        """This computer's address changed and the certificate or MongoDB's listening address no longer match
        (net_drift.py, the user 2026-11-19). Worked out at most every 5 minutes (the bell asks often)."""
        cached = getattr(self, "_drift_cache", None)
        if not cached or now - cached[0] > 300:
            try:
                import net_drift
                found = net_drift.drift(self.base_dir, env=self.env)
            except Exception:                            # noqa: BLE001  never break the bell over this
                found = []
            cached = self._drift_cache = (now, found)
        return [{"key": d["key"], "problem": True, "title": d["title"], "text": d["text"], "at": cached[0], "link": "/settings"}
                for d in cached[1]]

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

    def for_user(self, user, now=None, has_perm=None):
        """This person's alerts not cleared yet, as bell items (notifications.js). has_perm(p): only the alerts meant for
        a permission they hold (an alert's "perms"; administrators' 'settings' when it names none); its "links" pick
        where it leads for them."""
        mine = set(self._seen().get(user) or [])
        out = []
        for a in self.current(now):
            if a["key"] in mine:
                continue
            perms = a.get("perms") or ("settings",)
            if has_perm is not None and not any(has_perm(p) for p in perms):
                continue
            link = a["link"]
            if has_perm is not None and a.get("links"):
                link = next((a["links"][p] for p in perms if p in a["links"] and has_perm(p)), link)
            out.append({"id": "sys:" + a["key"], "number": "System", "case": False, "network": "", "title": a["title"],
                        "status": "system", "status_label": "Needs a look" if a["problem"] else "For your information",
                        "by": "Looking Glass", "text": a["text"], "updates": 1, "at": float(a["at"] or 0),
                        "when": _when(a["at"]), "waiting": a["problem"], "link": link})
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
