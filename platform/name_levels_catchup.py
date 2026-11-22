# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""Every name's criticality learned once from all the reports' records (the user, 2026-11-18: "can't we fix that").

The PDFs' References section flags each infection and issue with the highest severity Shadowserver gave the records
that carry it (pdf_refs.py). Day loads teach those levels as days come into memory, and pdf_refs remembers them in
data/name_levels.json; a name seen only on days loaded before that (a review kept on an earlier day: m0yv on lg-test,
records of 12-15 November, days in memory 16-18) read "not rated". So, once, NAME_LEVELS_DELAY_S seconds after a start
(default 120, after the days in memory and the warm-ups; 0 = never), one background thread reads every report
collection once: only each record's infection, issues, tags and severity (never an address), in batches, pausing
between them so the pages are not held up. It learns every name's highest level, keeps it in data/name_levels.json
after each collection, and writes data/name_levels.done when every collection is read: then it never runs again
(the day loads keep the file current). Only in the running service (index_refresh.SERVING).
Installed from features.py: name_levels_catchup.install(app, {"db", "collections": () -> names, "base_dir", "logger"})."""
import json
import os
import threading
import time

import index_refresh
import pdf_refs

BATCH = 5000                 # records read between two pauses
PAUSE = 0.05                 # seconds between batches: the database and the pages keep their pace
FIELDS = {"infection": 1, "issues": 1, "tags": 1, "severity": 1, "_id": 0}     # never an address
VERSION = 2                  # 2 (2026-11-19): also every name carried, rated or not, for the severity map: read once more


def delay():
    try:
        return max(0, min(3600, int(os.environ.get("NAME_LEVELS_DELAY_S", "120"))))
    except ValueError:
        return 120


def done_path(base_dir):
    return os.path.join(base_dir, "data", "name_levels.done")


def is_done(base_dir):
    try:
        with open(done_path(base_dir), encoding="utf-8") as fh:
            return (json.load(fh) or {}).get("version") == VERSION
    except (OSError, ValueError):
        return False


def catch_up(db, names, base_dir, stop=None, pause=PAUSE):
    """Read every collection once and remember every name's highest level. {"collections", "records", "names", "seconds"}."""
    t, records, learned = time.time(), 0, {}
    cols = [n for n in names if n]
    for n in cols:
        levels, kinds = {}, {}
        batch = []
        for e in db[n].find({}, FIELDS).batch_size(2000):
            batch.append(e)
            if len(batch) >= BATCH:
                pdf_refs.levels_from_records(batch, levels, kinds); records += len(batch); batch = []
                if stop is not None and stop.is_set():
                    pdf_refs.remember(levels); pdf_refs.remember_kinds(kinds)
                    return {"collections": cols, "records": records, "names": len(learned), "seconds": round(time.time() - t, 1), "stopped": True}
                time.sleep(pause)
        pdf_refs.levels_from_records(batch, levels, kinds); records += len(batch)
        pdf_refs.remember(levels)                         # kept after each collection: an interrupted run keeps its part
        pdf_refs.remember_kinds(kinds)                    # …and every name it carried, rated or not (the severity map)
        for k, v in levels.items():
            pdf_refs.lift(learned, k, v)
    os.makedirs(os.path.join(base_dir, "data"), exist_ok=True)
    with open(done_path(base_dir), "w", encoding="utf-8") as fh:
        json.dump({"version": VERSION, "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "records": records,
                   "names": len(learned)}, fh)
    return {"collections": cols, "records": records, "names": len(learned), "seconds": round(time.time() - t, 1)}


def install(app, ctx):
    db, log, base = ctx["db"], ctx.get("logger"), ctx["base_dir"]
    state = {"started": False, "result": None}

    def run():
        try:
            state["result"] = catch_up(db, ctx["collections"](), base)
            if log:
                r = state["result"]
                log.warning("Name levels learned from every report: %s names from %s records in %ss",
                            r["names"], f"{r['records']:,}", r["seconds"])
        except Exception:                                  # noqa: BLE001  (the day loads still teach the levels)
            if log:
                log.exception("Name levels: not learned from every report")

    d = delay()
    if index_refresh.SERVING and d > 0 and not is_done(base):
        state["started"] = True
        threading.Timer(d, run).start()
    return state
