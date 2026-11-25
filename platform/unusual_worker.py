#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""Unusual activity's worker (the user, 2026-11-24, decision 2a): a separate process run by its own systemd timer
(deploy/looking-glass-unusual.*), never inside the web service, so counting a month of reports never slows a page.

Each run:
1. every report day of the last WINDOW + 1 days that is new or changed (its records, the constituency or this file's
   FORMAT) is counted again into a day summary: per report, per network and report, and per report pair, how many of
   the constituency's devices; counts only, never an address (data/unusual/days/<day>.json);
2. the latest day, and each of the 7 before it, is compared with its threads' normal (unusual_detect.py): the
   suggestions go to data/unusual/suggestions.json, which the Unusual activity page and the Executive card read.
Reads MongoDB with the platform's read-only account. Limits (.env, generous defaults, decision 7a): UNUSUAL_MAX_SECONDS
and UNUSUAL_MAX_DEVICES stop a day's count early; that day is then marked partial and counted again next run.
Run by hand: .venv/bin/python unusual_worker.py
"""
import datetime as dt
import hashlib
import json
import os
import re
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
FORMAT = "1"                          # raised when a summary's shape changes: every day is counted again


def env_int(name, default, lo, hi):
    try:
        return max(lo, min(hi, int(os.environ.get(name, default))))
    except (TypeError, ValueError):
        return default


def env_float(name, default, lo, hi):
    try:
        return max(lo, min(hi, float(os.environ.get(name, default))))
    except (TypeError, ValueError):
        return default


def config():
    return {"window": env_int("UNUSUAL_WINDOW_DAYS", 28, 7, 90),
            "min_devices": env_int("UNUSUAL_MIN_DEVICES", 10, 2, 100000),
            "ratio": env_float("UNUSUAL_RATIO", 2.0, 1.2, 100.0),
            "z": env_float("UNUSUAL_Z", 4.0, 2.0, 50.0),
            "min_history": env_int("UNUSUAL_MIN_HISTORY_DAYS", 7, 3, 60),
            "min_lift": env_float("UNUSUAL_MIN_LIFT", 2.0, 1.0, 1000.0),
            "max_seconds": env_int("UNUSUAL_MAX_SECONDS", 1800, 60, 6 * 3600),
            "max_devices": env_int("UNUSUAL_MAX_DEVICES", 3000000, 10000, 50000000)}


def write_json(path, data):
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    tmp = f"{path}.{os.getpid()}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(data, f, separators=(",", ":"))
    os.replace(tmp, path)


def read_json(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def excluded():
    return {x.strip() for x in (os.environ.get("EXCLUDE_COLLECTIONS", "outdated_dnssec_key") or "").split(",") if x.strip()}


def count_day(db, cols, day, settings, cap_devices, deadline):
    """One report day into a summary: the constituency's device on each record (the source when it is in the
    constituency, else the destination; services: the host), counted per report, network and report pair.
    Returns (summary, partial)."""
    import unusual_detect as pd
    d = pd.Day(day)
    for c in cols:
        for r in db[c].find({"filename": {"$regex": "^" + re.escape(day)}}, pd.FIELDS):
            dev = pd.device_of(r, settings)
            if dev is None:
                continue
            d.add(c, dev[2], dev[0], dev[1])
            if len(d.device_reports) >= cap_devices or time.time() > deadline:
                return d.summary(), True
    return d.summary(), False


def run(base_dir=HERE, now=None, log=print):
    from dotenv import dotenv_values
    for k, v in dotenv_values(os.path.join(base_dir, ".env")).items():
        if v is not None:
            os.environ.setdefault(k, v)
    import connectors_worker as cw                       # report_collections and day_signature: one shared version
    import db_connect
    import unusual_detect as pd
    from pymongo import MongoClient
    from settings import Settings
    cfg = config()
    data = os.path.join(base_dir, "data", "unusual")
    settings = Settings(os.path.join(base_dir, "data", "settings.json"))
    scope = hashlib.sha256(json.dumps(settings.data, sort_keys=True, default=str).encode()).hexdigest()[:16]
    db = MongoClient(**db_connect.kwargs(os.environ.get), username=os.environ.get("MONGO_USER") or None,
                     password=os.environ.get("MONGO_PASSWORD") or None, authSource=os.environ.get("MONGO_AUTH_SOURCE", "admin"),
                     serverSelectionTimeoutMS=8000)[os.environ.get("MONGO_DB", "shadowserver")]
    skip = excluded()
    cols = [c for c in cw.report_collections(db) if c not in skip]
    today = (now or dt.datetime.now(dt.timezone.utc)).date()
    started = time.time()
    deadline = started + cfg["max_seconds"]
    counted, partial_days, summaries = 0, [], []
    for i in range(cfg["window"] + 8, 0, -1):            # oldest first; today itself is never complete
        day = (today - dt.timedelta(days=i)).isoformat()
        path = os.path.join(data, "days", f"{day}.json")
        sig = cw.day_signature(db, cols, day)
        if not sig:
            continue
        full = hashlib.sha256(json.dumps([sig, scope, FORMAT], sort_keys=True).encode()).hexdigest()[:16]
        old = read_json(path)
        if old and old.get("sig") == full and not old.get("partial"):
            summaries.append(old)
            continue
        if time.time() > deadline:
            partial_days.append(day)
            if old:
                summaries.append(old)
            continue
        s, partial = count_day(db, cols, day, settings, cfg["max_devices"], deadline)
        s.update(sig=full, partial=partial, made=int(time.time()))
        write_json(path, s)
        summaries.append(s)
        counted += 1
        if partial:
            partial_days.append(day)
    # days older than the window are not needed any more
    keep = {(today - dt.timedelta(days=i)).isoformat() for i in range(cfg["window"] + 9)}
    try:
        for f in os.listdir(os.path.join(data, "days")):
            if f.endswith(".json") and f[:-5] not in keep:
                os.remove(os.path.join(data, "days", f))
    except OSError:
        pass
    summaries.sort(key=lambda s: s["day"])
    latest = summaries[-1]["day"] if summaries else None
    # the team's decisions per report: each report's bar, learned (decision 2a; unusual.py keeps them)
    learned = (read_json(os.path.join(data, "decisions.json")) or {}).get("learned") or {}
    week = {}
    for s in summaries[-8:]:
        for x in pd.detect(s, summaries, cfg, learned):
            if s["day"] != latest:
                x.pop("history", None)           # the chart is drawn for the latest day's cards only
            week.setdefault(s["day"], []).append(x)
    write_json(os.path.join(data, "suggestions.json"), {
        "made": int(time.time()), "day": latest, "seconds": round(time.time() - started, 1), "counted_days": counted,
        "partial_days": partial_days, "config": {k: cfg[k] for k in ("window", "min_devices", "ratio", "z", "min_history", "min_lift")},
        "suggestions": week.get(latest, []) if latest else [],
        "week": {d: v for d, v in week.items()}})
    log(f"unusual activity: {counted} day(s) counted, {len(week.get(latest, []) if latest else [])} suggestion(s) for {latest}"
        + (f"; partial: {', '.join(partial_days)}" if partial_days else ""))
    return counted


if __name__ == "__main__":
    run()
