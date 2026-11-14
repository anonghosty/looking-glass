"""Settings → Task monitor, for administrators: how the service and what it depends on are doing right now, like a
task manager, to watch and troubleshoot without a terminal.

  GET  /api/admin/monitor          the web service (uptime, memory, CPU, threads, requests running and per minute), its
                                   background jobs (alive or not), the slowest requests of the last day (slow_log.py),
                                   the cache (response_cache.py), MongoDB's memory, the machine (load, memory, swap,
                                   disk), the pipeline's last run and schedule, recent restarts, sign-in locks, alerts
  POST /api/admin/monitor/cache    {action: "clear"}: forget every kept answer now;
                                   {ttl: seconds}: how long heavy answers are kept (0..3600; 0 = off)

Everything is read from this computer only; nothing names a host from the reports. Reading needs the 'settings'
permission; the two actions also the CSRF token and a fresh sign-in, and each is written to the audit log.
"""
import json
import os
import subprocess
import threading
import time
from collections import deque

from flask import abort, g, jsonify, make_response, request

import pipeline_link
import request_tracker
import response_cache
import slow_log

JOBS = {"replay-schedule": "Replay schedule (the day replayed at the same time of day)",
        "malpedia-new-names": "Malpedia check of new names",
        "cve-lookups": "CVE look-ups (NVD, KEV, EPSS)",
        "report-map": "Shadowserver report map",
        "mgmt-baseline-prewarm": "Executive baseline (runs once at start, then ends)"}
_STARTED = time.time()
_CPU = {"t": None, "cpu": None}
_CRON = {"at": 0, "lines": [], "readable": True}


def _proc_self():
    out = {"pid": os.getpid(), "threads": threading.active_count(), "uptime_s": round(time.time() - _STARTED)}
    try:
        with open("/proc/self/status", encoding="utf-8") as f:
            for ln in f:
                if ln.startswith("VmRSS:"):
                    out["memory_mb"] = round(int(ln.split()[1]) / 1024)
        with open("/proc/self/stat", encoding="utf-8") as f:
            parts = f.read().rsplit(")", 1)[1].split()
        cpu = (int(parts[11]) + int(parts[12])) / os.sysconf("SC_CLK_TCK")
        now = time.monotonic()
        if _CPU["t"] is not None and now > _CPU["t"]:
            out["cpu_percent"] = round(100 * (cpu - _CPU["cpu"]) / (now - _CPU["t"]), 1)
        _CPU.update(t=now, cpu=cpu)
    except (OSError, ValueError, IndexError):
        pass
    return out


def _mongod():
    try:
        r = subprocess.run(["ps", "-C", "mongod", "-o", "rss=,etimes="], capture_output=True, text=True, timeout=5)
        rows = [ln.split() for ln in r.stdout.splitlines() if ln.strip()]
        if rows:
            return {"running": True, "memory_mb": round(sum(int(x[0]) for x in rows) / 1024), "uptime_s": int(rows[0][1])}
    except (OSError, subprocess.SubprocessError, ValueError):
        pass
    return {"running": False}


def _machine(path):
    out = {"cpus": os.cpu_count()}
    try:
        out["load"] = [round(x, 2) for x in os.getloadavg()]
    except OSError:
        pass
    try:
        mem = {}
        with open("/proc/meminfo", encoding="utf-8") as f:
            for ln in f:
                k, v = ln.split(":", 1)
                mem[k] = int(v.split()[0]) // 1024
        out.update(memory_total_mb=mem.get("MemTotal"), memory_available_mb=mem.get("MemAvailable"),
                   swap_total_mb=mem.get("SwapTotal"), swap_used_mb=(mem.get("SwapTotal", 0) - mem.get("SwapFree", 0)))
    except (OSError, ValueError):
        pass
    try:
        st = os.statvfs(path)
        out.update(disk_free_gb=round(st.f_bavail * st.f_frsize / 1024 ** 3, 1), disk_total_gb=round(st.f_blocks * st.f_frsize / 1024 ** 3, 1))
    except OSError:
        pass
    return out


def _cron():
    """The schedules of this account (pipeline, name refresh), read at most once a minute; only Looking Glass's lines.
    readable False: the service's sandbox does not let it run crontab (NoNewPrivileges), which says nothing about
    whether there is a schedule; the last run's time shows that."""
    if time.time() - _CRON["at"] > 60:
        lines, readable = [], True
        try:
            r = subprocess.run(["crontab", "-l"], capture_output=True, text=True, timeout=5)
            # "no crontab for <user>" is a real empty schedule; any other failure means it could not be read
            readable = r.returncode == 0 or "no crontab" in (r.stderr or "").lower()
            for ln in r.stdout.splitlines():
                s = ln.strip()
                if s and not s.startswith("#") and any(k in s for k in ("shadowserver", "fetch_offline_names", "looking-glass")):
                    when = " ".join(s.split()[:5])
                    what = ("report pipeline" if "shadowserver" in s or "run.sh" in s else
                            "MISP Galaxy / ATT&CK refresh" if "fetch_offline_names" in s else "Looking Glass job")
                    lines.append({"when": when, "what": what})
        except (OSError, subprocess.SubprocessError):
            readable = False
        _CRON.update(at=time.time(), lines=lines, readable=readable)
    return _CRON["lines"], _CRON["readable"]


def _restarts(data_dir, n=5):
    try:
        with open(os.path.join(data_dir, "restarts.jsonl"), encoding="utf-8") as f:
            rows = [json.loads(x) for x in f if x.strip()]
        return [time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(r["t"])) for r in rows[-n:]][::-1]
    except (OSError, ValueError, KeyError, TypeError):
        return []


class Sampler:
    """Performance history, like Task Manager's graphs: a reading every STEP_S seconds, the last KEEP kept. Runs only
    while someone looks: it starts with the first monitor request and stops IDLE_S after the last."""
    STEP_S, KEEP, IDLE_S = 2.0, 60, 120

    def __init__(self):
        self.hist = deque(maxlen=self.KEEP)
        self.lock = threading.Lock()
        self.seen = 0.0
        self.thread = None
        self.prev = None

    @staticmethod
    def _read():
        r = {"t": time.time()}
        try:
            with open("/proc/stat", encoding="utf-8") as f:
                v = [int(x) for x in f.readline().split()[1:]]
            r["cpu_busy"], r["cpu_all"] = sum(v) - v[3] - (v[4] if len(v) > 4 else 0), sum(v)
        except (OSError, ValueError):
            pass
        try:
            rd = wr = 0
            with open("/proc/diskstats", encoding="utf-8") as f:
                for ln in f:
                    p = ln.split()
                    name = p[2]
                    whole = (name.startswith(("sd", "vd", "xvd", "hd")) and not name[-1].isdigit()) or \
                            (name.startswith("nvme") and "p" not in name.split("n", 1)[-1])
                    if whole:
                        rd += int(p[5]) * 512; wr += int(p[9]) * 512
            r["disk_read"], r["disk_write"] = rd, wr
        except (OSError, ValueError, IndexError):
            pass
        try:
            rx = tx = 0
            with open("/proc/net/dev", encoding="utf-8") as f:
                for ln in list(f)[2:]:
                    name, data = ln.split(":", 1)
                    if name.strip() == "lo":
                        continue
                    p = data.split(); rx += int(p[0]); tx += int(p[8])
            r["net_rx"], r["net_tx"] = rx, tx
        except (OSError, ValueError, IndexError):
            pass
        try:
            with open("/proc/self/stat", encoding="utf-8") as f:
                parts = f.read().rsplit(")", 1)[1].split()
            r["svc_cpu"] = (int(parts[11]) + int(parts[12])) / os.sysconf("SC_CLK_TCK")
        except (OSError, ValueError, IndexError):
            pass
        return r

    def _point(self, a, b):
        dt = max(1e-6, b["t"] - a["t"])
        mc = _machine("/")
        p = {"t": round(b["t"]), "memory_used_mb": (mc.get("memory_total_mb") or 0) - (mc.get("memory_available_mb") or 0),
             "memory_total_mb": mc.get("memory_total_mb"), "swap_used_mb": mc.get("swap_used_mb")}
        if "cpu_all" in a and "cpu_all" in b and b["cpu_all"] > a["cpu_all"]:
            p["cpu"] = round(100 * (b["cpu_busy"] - a["cpu_busy"]) / (b["cpu_all"] - a["cpu_all"]), 1)
        if "svc_cpu" in a and "svc_cpu" in b:
            p["service_cpu"] = round(100 * (b["svc_cpu"] - a["svc_cpu"]) / dt / (os.cpu_count() or 1), 1)
        for k in ("disk_read", "disk_write", "net_rx", "net_tx"):
            if k in a and k in b:
                p[k + "_kbs"] = round(max(0, b[k] - a[k]) / dt / 1024, 1)
        p["service_mb"] = _proc_self().get("memory_mb")
        p["mongodb_mb"] = _mongod().get("memory_mb")
        return p

    def _run(self):
        a = self._read()
        while time.time() - self.seen < self.IDLE_S:
            time.sleep(self.STEP_S)
            b = self._read()
            try:
                pt = self._point(a, b)
                with self.lock:
                    self.hist.append(pt)
            except Exception:  # noqa: BLE001  (a reading that fails is skipped)
                pass
            a = b
        with self.lock:
            self.thread = None

    def touch(self):
        """Someone is looking: keep sampling (start if needed). Returns the history so far."""
        with self.lock:
            self.seen = time.time()
            if self.thread is None:
                self.thread = threading.Thread(target=self._run, daemon=True, name="task-monitor-sampler")
                self.thread.start()
            return list(self.hist)


SAMPLER = Sampler()


def snapshot(ctx):
    data_dir = os.path.join(ctx["base_dir"], "data")
    alive = {t.name for t in threading.enumerate() if t.is_alive()}
    rc = ctx.get("cache")
    pstat = None
    if ctx.get("alerts"):
        try:
            pstat = ctx["alerts"]._pipeline_status()
        except Exception:  # noqa: BLE001
            pstat = None
    pdir = pipeline_link.find_dir(ctx["base_dir"])
    sched, sched_ok = _cron()
    return {
        "at": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        "service": _proc_self(),
        "requests": slow_log.counts(),
        "jobs": [{"name": label, "running": key in alive, "once": key == "mgmt-baseline-prewarm"} for key, label in JOBS.items()],
        "slow": slow_log.summary(os.path.join(data_dir, "slow_requests.jsonl"), 1)[:10],
        "slow_limit_s": slow_log.threshold(),
        "cache": ({"ttl_s": response_cache.ttl(), "ttl_env_s": response_cache.env_ttl(), "ttl_from_settings": response_cache._override() is not None,
                   "entries": len(rc.entries), "generation": rc.gen, **rc.stats} if rc else None),
        "mongodb": _mongod(),
        "machine": _machine(data_dir),
        "pipeline": {"found": bool(pdir), "last": pstat, "schedule": sched, "schedule_readable": sched_ok},
        "restarts": _restarts(data_dir),
        "locks": len(ctx["throttle"].lockouts()) if ctx.get("throttle") else 0,
        "processes": request_tracker.processes(),
        "users": request_tracker.users(),
        "users_window_min": request_tracker.WINDOW_S // 60,
        "performance": SAMPLER.touch(),
        "sample_s": Sampler.STEP_S,
        "alerts": [{"title": a["title"], "problem": a["problem"]} for a in (ctx["alerts"].current() if ctx.get("alerts") else [])],
    }


def install(app, ctx):
    """ctx: base_dir, has_perm, csrf_ok, fresh, audit, cache (response_cache.ResponseCache), throttle, alerts."""
    hp = ctx["has_perm"]

    @app.route("/api/admin/monitor")
    def api_admin_monitor():
        if not hp("settings"):
            return jsonify(error="The task monitor is for administrators (the 'settings' permission)."), 403
        return jsonify(snapshot(ctx))

    @app.route("/api/admin/monitor/cache", methods=["POST"])
    def api_admin_monitor_cache():
        if not hp("settings"):
            return jsonify(error="Changing the cache is for administrators (the 'settings' permission)."), 403
        if request.mimetype != "application/json" or not ctx["csrf_ok"]():
            abort(403)
        if not ctx["fresh"]():
            abort(make_response(jsonify(error="For your security, sign out and sign in again to make changes.", reauth=True), 403))
        d = request.get_json(silent=True) or {}
        who = (getattr(g, "user", None) or {}).get("user", "")
        rc = ctx.get("cache")
        if d.get("action") == "clear":
            n = len(rc.entries) if rc else 0
            if rc:
                with rc.lock:
                    rc.entries.clear()
                rc.bump()
            ctx["audit"].add("cache_cleared", user=who, target="task monitor", detail=f"{n} kept answer(s) forgotten")
            return jsonify(ok=True, cleared=n)
        if "ttl" in d:
            v = d["ttl"]
            if isinstance(v, bool) or not isinstance(v, int) or not 0 <= v <= response_cache.TTL_MAX:
                return jsonify(error=f"A whole number of seconds from 0 to {response_cache.TTL_MAX}."), 400
            old = response_cache.ttl()
            kept = response_cache.save_ttl(v)
            ctx["audit"].add("cache_time_changed", user=who, target="task monitor",
                             detail=f"heavy answers kept {old} s -> {kept} s" + (" (cache off)" if kept == 0 else ""))
            return jsonify(ok=True, ttl_s=kept)
        return jsonify(error='Send {"action": "clear"} or {"ttl": seconds}.'), 400
