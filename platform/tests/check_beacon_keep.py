#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""The beacon decoder's public answers kept across restarts (beacon_keep.py). Made-up request lines only, in a scratch
folder; no database, nothing of the real data/ folder is read or written.
1. kept answers come back after a "restart" (a new store on the same file), and the decoder is then not run again
2. the file holds hashes and public fields only: no request line, no host, mode 600
3. a different decoder (another fingerprint) does not use the old answers
4. a damaged file, or a folder that cannot be written, only means decoding again: never an error
5. at most MAX_ENTRIES answers, the oldest dropped first
Run: .venv/bin/python tests/check_beacon_keep.py"""
import json
import logging
import os
import stat
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import beacon_decode as BD  # noqa: E402
import beacon_keep as BK  # noqa: E402

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info else ""), flush=True)


tmp = tempfile.mkdtemp(prefix="lg_bkeep_")
path = os.path.join(tmp, "beacon_summaries.json")
V = BK.fingerprint(BD.__file__)
import base64  # noqa: E402
import random  # noqa: E402
_rnd = random.Random(7)
# shaped like a CLogin check-in (so the decoder works on them), made of random made-up bytes
URLS = [f"GET /CLogin?key={base64.b64encode(bytes(_rnd.randrange(256) for _ in range(120))).decode()} HTTP/1.1"
        for i in range(30)]
HOST = "c2.example.invalid"

decodes = {"n": 0}
_real = BD._decode_once


def counting(url):
    decodes["n"] += 1
    return _real(url)


BD._decode_once = counting

print("0. Only in the running service")
from flask import Flask  # noqa: E402
BD.install(Flask("keep-check"), {"csrf_ok": lambda: True, "sees_hosts": lambda: False})
ok("installing the API outside the service keeps nothing (a check never reads or writes data/beacon_summaries.json)",
   BD.KEEP is None)

print("1. Kept across a restart")
BD.KEEP = BK.SummaryStore(path, V)
first = [BD.field({"http_url": u, "http_host": HOST}, "format") for u in URLS]
n_first = decodes["n"]
BD.KEEP.flush()
BD._summary.cache_clear(); BD._decode_cached.cache_clear()          # the restart: nothing in memory
decodes["n"] = 0
BD.KEEP = BK.SummaryStore(path, V)
again = [BD.field({"http_url": u, "http_host": HOST}, "format") for u in URLS]
ok(f"the same answers after the restart ({len(URLS)} request lines)", again == first)
ok("... without decoding again", decodes["n"] == 0 and n_first > 0, f"{n_first} decodes first, {decodes['n']} after")
ok("... read from the kept file", BD.KEEP.hits == len(URLS), f"{BD.KEEP.hits} kept answers used")

print("2. What the file holds")
raw = open(path, encoding="utf-8").read()
ok("no request line, query value or host in it", not any(u.split("=", 1)[1][:20] in raw for u in URLS) and HOST not in raw and "CLogin?" not in raw)
body = json.loads(raw)
fields = {p[0] for v in body["entries"].values() for p in v}
ok("only the public summary fields", fields <= {"format", "id", "operator", "version", "os_family", "state"}, str(sorted(fields)))
ok("readable by the service only (mode 600)", stat.S_IMODE(os.stat(path).st_mode) == 0o600, oct(stat.S_IMODE(os.stat(path).st_mode)))

print("3. Another decoder")
ok("a different fingerprint starts empty", len(BK.SummaryStore(path, "another-decoder").data) == 0)
ok("... and the same one reads them", len(BK.SummaryStore(path, V).data) == len(URLS))

print("4. Problems only mean decoding again")
with open(path, "w", encoding="utf-8") as f:
    f.write("{not json")
ok("a damaged file: an empty store, no error", len(BK.SummaryStore(path, V).data) == 0)
logging.getLogger("looking-glass").disabled = True
bad = BK.SummaryStore(os.path.join(tmp, "no-such-folder", "x.json"), V)
bad.put("GET /a?b=c HTTP/1.1", None, (("format", "x"),))
try:
    bad.flush()
    flushed = True
except Exception:                                  # noqa: BLE001
    flushed = False
logging.getLogger("looking-glass").disabled = False
ok("a folder that cannot be written: no error, the answer still kept in memory", flushed and bad.get("GET /a?b=c HTTP/1.1", None))

print("5. A limit")
_max = BK.MAX_ENTRIES
BK.MAX_ENTRIES = 10
s = BK.SummaryStore(os.path.join(tmp, "small.json"), V)
for i in range(25):
    s.put(f"GET /x?i={i} HTTP/1.1", None, (("format", ""),))
ok("at most MAX_ENTRIES, the newest kept", len(s.data) == 10 and s.get("GET /x?i=24 HTTP/1.1", None) and not s.get("GET /x?i=0 HTTP/1.1", None))
BK.MAX_ENTRIES = _max

print("6. A country with many more check-ins (200,000 kept answers)")
import time  # noqa: E402
import tracemalloc  # noqa: E402
kinds = [(("format", f"Format {i % 3}"), ("operator", f"op{i % 5}"), ("state", "decoded")) for i in range(15)]
big_path = os.path.join(tmp, "big.json")
tracemalloc.start()
big = BK.SummaryStore(big_path, V)
for i in range(200_000):
    big.put(f"GET /CLogin?key=made-up-{i} HTTP/1.1", "c2.example.invalid", kinds[i % 15])
mem = tracemalloc.get_traced_memory()[1]
tracemalloc.stop()
ok("held in memory once per different summary", len(big.shared) == 15, f"{len(big.shared)} different summaries")
ok("memory for 200,000 answers stays modest (< 80 MB)", mem < 80e6, f"{mem / 1e6:.0f} MB")
ok("... and the file is not rewritten on every new answer (at most once a minute)", big.dirty > 100_000, f"{big.dirty} waiting")
t = time.perf_counter(); big.flush(); dt = time.perf_counter() - t
size = os.path.getsize(big_path)
ok("one write of all of them is quick (< 5 s)", dt < 5, f"{dt:.1f} s, {size / 1e6:.0f} MB")
t = time.perf_counter(); again = BK.SummaryStore(big_path, V); dt = time.perf_counter() - t
ok("read back after a restart quickly (< 5 s), all of them", len(again.data) == 200_000 and dt < 5, f"{dt:.1f} s")
for st in (big, again, s, bad):                   # nothing left to write at exit: the scratch folder goes now
    st.dirty = 0

BD._decode_once = _real
BD.KEEP = None
for fn in os.listdir(tmp):
    os.remove(os.path.join(tmp, fn))
os.rmdir(tmp)
print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {fails}" if fails else ""))
sys.exit(1 if fails else 0)
