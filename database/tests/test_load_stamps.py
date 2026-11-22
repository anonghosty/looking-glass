# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""Load stamps and the address index (review of d82a436): when rows of a report are inserted, the pipeline marks the
report and the day its file is named after (collection lg_load_stamps: rows added, when), so Looking Glass reads one
small collection every 15 seconds instead of counting every report's rows; a file name without a date is not marked;
a mark that cannot be written never stops the load. Each report collection gets the address index
{ip, filename} (only rows with an address), for the host look-up. No MongoDB needed (a fake one).
Run: python3 tests/test_load_stamps.py"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import shadowserver_pipeline as sp  # noqa: E402

fails, n = [], 0


def ok(label, cond, info=""):
    global n
    n += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info and not cond else ""))


class Coll:
    def __init__(self):
        self.docs = {}
        self.fail = False

    def update_one(self, q, upd, upsert=False):
        if self.fail:
            raise RuntimeError("no write access")
        d = self.docs.setdefault(q["_id"], {"_id": q["_id"]}) if upsert else self.docs[q["_id"]]
        d.update(upd.get("$set", {}))
        for k, v in upd.get("$inc", {}).items():
            d[k] = d.get(k, 0) + v


class DB(dict):
    def __missing__(self, k):
        self[k] = Coll()
        return self[k]


sp._WORKER_DB = DB()
st = sp._WORKER_DB[sp.STAMPS]
sp.stamp_loaded("scan_http", "2026-11-14-scan_http-ghana-geo.csv", 120)
sp.stamp_loaded("scan_http", "2026-11-14-scan_http-ghana-geo_2.csv", 30)
d = st.docs.get("scan_http|2026-11-14", {})
ok("a mark per report and file-name day, rows added up", d.get("rows") == 150 and d.get("coll") == "scan_http" and d.get("day") == "2026-11-14", d)
ok("…with when it was written", d.get("at") is not None)
sp.stamp_loaded("event4_sinkhole", "2026-11-15-event4_sinkhole-ghana-geo.csv", 5)
ok("another report or day: its own mark", "event4_sinkhole|2026-11-15" in st.docs and len(st.docs) == 2)
sp.stamp_loaded("scan_http", "notes.json", 1)
ok("a file name without a date is not marked", len(st.docs) == 2)
st.fail = True
try:
    sp.stamp_loaded("scan_http", "2026-11-14-scan_http-ghana-geo_3.csv", 1)
    ok("a mark that cannot be written never stops the load", True)
except Exception as e:  # noqa: BLE001
    ok("a mark that cannot be written never stops the load", False, repr(e))
ok("the address index: ip then filename", sp.HOST_INDEX == [("ip", 1), ("filename", 1)])
src = open(sp.__file__, encoding="utf-8").read()
ok("…created with every report collection, for rows that have an address",
   'create_index(HOST_INDEX, name="ip_filename", partialFilterExpression={"ip": {"$exists": True}})' in src)
ok("…and the marks written as rows are inserted", "stamp_loaded(category, filename, ins)" in src)

print(f"\n{n - len(fails)}/{n} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
