# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""Check that both platforms show exactly the constituency set in Settings (AS numbers only; address ranges are
not counted here): every count is compared with MongoDB directly. Read-only.

Usage: .venv/bin/python tests/verify_constituency.py [YYYY-MM-DD]   (default: the day the service replays)
The service asked: LG_BASE (for example http://127.0.0.1:5088) when set, else this installation's own address
(tests/lgauth.py: LG_PORT from the environment or .env, https when data/tls/cert.pem is there).
Exit code: 0 both platforms match MongoDB, 1 either differs (so tests/run_all_checks.sh reports it), 77 skipped (no
constituency networks set, or no data for the day yet). Before 2026-11-11 it always exited 0.

On a TEST system with made-up data (LG_TEST_SYSTEM=1, and the installation's MONGO_DB is LG_TEST_SYSTEM_DB, default
lg_demo; refused otherwise) the check is never skipped (2026-11-26: "we do not skip"): it backs up data/settings.json,
sets a temporary constituency of 3 to 5 AS numbers found in that day's data (read-only), restarts the service
(deploy/reload.sh: settings.json is read at start) and waits until it reads them, checks, and then ALWAYS puts the
original file back byte for byte (also on a failure or a stop), restarts again, waits until the service answers with
the original scope, and proves the file's sha256 equals the backup's. Exit 1 when anything is missing or differs.
Never on a production installation: the service is restarted twice and its scope changes for a few minutes.
"""
import os as _os, sys as _sys; _sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
import lgauth  # noqa: E402,F401  local API login (automation key)
TEST_SYSTEM = _os.environ.get("LG_TEST_SYSTEM") == "1"
BASE = (_os.environ.get("LG_BASE") or lgauth.BASE).rstrip("/")
try:
    lgauth.urlopen(BASE + "/healthz", timeout=4).read()
except Exception as _exc:  # noqa: BLE001  any reason is "not running" here; the name says which
    if TEST_SYSTEM:
        print(f"FAILED: the test system's service at {BASE} did not answer ({_exc.__class__.__name__})")
        _sys.exit(1)
    print(f"SKIPPED: needs the running Looking Glass service at {BASE}, which did not answer ({_exc.__class__.__name__})")
    _sys.exit(77)
import hashlib
import json
import os
import re
import signal
import stat
import subprocess
import sys
import tempfile
import time
import urllib.request
from collections import Counter
from datetime import datetime, timedelta, timezone

from dotenv import dotenv_values, load_dotenv
from pymongo import MongoClient

import mongo_derive  # the one rule's row key (counting_keys.row_key)

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
load_dotenv(os.path.join(ROOT, ".env"))
SETTINGS = os.path.join(ROOT, "data", "settings.json")
# the day both platforms replay (lgauth.replay_day; the events clock, the services clock is the same day)
day = sys.argv[1] if len(sys.argv) > 1 else lgauth.replay_day(BASE, "/api/clock")
start = datetime.fromisoformat(day).replace(tzinfo=timezone.utc); end = start + timedelta(days=1)
at = (start + timedelta(hours=12)).isoformat().replace("+00:00", "Z")
get = lambda p: json.load(urllib.request.urlopen(BASE + p, timeout=300))
client = MongoClient(host=os.environ["MONGO_HOST"], port=int(os.environ.get("MONGO_PORT", 27017)), username=os.environ.get("MONGO_USER"),
                     password=os.environ.get("MONGO_PASSWORD"), authSource=os.environ.get("MONGO_AUTH_SOURCE", "admin"), serverSelectionTimeoutMS=8000)
db = client[os.environ["MONGO_DB"]]


def in_day(d):
    ed = d.get("extracted_date")
    if isinstance(ed, str):
        try:
            ed = datetime.fromisoformat(ed.replace("Z", "+00:00"))
        except ValueError:
            return False
    if not isinstance(ed, datetime):
        return False
    if ed.tzinfo is None:
        ed = ed.replace(tzinfo=timezone.utc)
    return start <= ed < end


q = lambda: {"$or": [{"filename": {"$regex": "^" + re.escape(p)}} for p in (day, end.strftime("%Y-%m-%d"))]}
ROW = {"filename": 1, "line_hash": 1}


def check(asns):
    """Both platforms against MongoDB for these networks: the number of platforms that differ, or None (no records).
    asns None: no constituency is set, so every record of the day counts (and both platforms must show all of them)."""
    # a row sent in two files of one report day is counted once (counting_keys.row_key), as the platform counts it
    once = mongo_derive.Once()
    # communications: source or destination network in the constituency
    comms_expected = 0
    for s in get(f"/api/sources?at={at}")["sources"]:
        for d in db[s["name"]].find(q(), {"extracted_date": 1, "src_asn": 1, "dst_asn": 1, **ROW}):
            if in_day(d) and once.first(s["name"], d) and (asns is None or str(d.get("src_asn") or "") in asns
                                                           or str(d.get("dst_asn") or "") in asns):
                comms_expected += 1
    comms = get(f"/api/stats?at={at}")["total"]
    print(f"communications: MongoDB {comms_expected:,} · platform {comms:,} · {'match' if comms == comms_expected else 'DIFFERENT'}")
    # services: the host's network in the constituency
    svc_expected = 0
    for r in get(f"/api/svc/facets?at={at}")["reports"]:
        for d in db[r["name"]].find(q(), {"extracted_date": 1, "asn": 1, **ROW}):
            if in_day(d) and once.first(r["name"], d) and (asns is None or str(d.get("asn") or "") in asns):
                svc_expected += 1
    svc = get(f"/api/svc/stats?at={at}&n=200")
    print(f"services: MongoDB {svc_expected:,} · platform {svc['total']:,} · {'match' if svc['total'] == svc_expected else 'DIFFERENT'}")
    print("services networks shown:", len(svc["breakdowns"]["network"]))
    if not comms_expected and not comms and not svc_expected and not svc["total"]:
        return None
    return (comms != comms_expected) + (svc["total"] != svc_expected)


def report(problems):
    print("ALL MATCH" if not problems else f"{problems} PLATFORM(S) DIFFERENT")
    return 1 if problems else 0


if not TEST_SYSTEM:
    st = json.load(open(SETTINGS))
    asns = {str(a) for a in st["networks"]}
    if not asns and not st.get("cidrs"):
        # no constituency set (a new installation): both platforms show every network, and that is what is compared,
        # record for record with MongoDB, never skipped (2026-11-26: "we do not skip")
        print("constituency: none set in Settings, so every network counts: both platforms must show every record of the day")
        problems = check(None)
    elif not asns:
        # address ranges only: this check compares AS numbers (tests/check_address_blocks.py covers the ranges)
        print("SKIPPED: the constituency is address ranges only; this check compares AS numbers")
        sys.exit(77)
    else:
        print(f"constituency: {len(asns)} network(s), {len(st['cidrs'])} range(s)")
        problems = check(asns)
    if problems is None:
        print(f"SKIPPED: no records for {day} yet")
        sys.exit(77)
    sys.exit(report(problems))


# ---------------------------------------------------------------- a test system: a temporary constituency, restored
WANT_DB = os.environ.get("LG_TEST_SYSTEM_DB") or "lg_demo"
if dotenv_values(os.path.join(ROOT, ".env")).get("MONGO_DB") != WANT_DB:
    print(f"REFUSED: LG_TEST_SYSTEM=1, but this installation does not read the made-up database {WANT_DB} (its .env)")
    sys.exit(1)
REAL = os.path.dirname(os.path.realpath(os.path.join(ROOT, "data")))       # the installation (also from a copy beside it)
F = os.path.realpath(SETTINGS)
KEEP = os.path.expanduser("~/.lg_constituency_check")
BK = os.path.join(KEEP, "settings.json.orig")
if os.path.exists(BK):
    print(f"REFUSED: {BK} is left from an earlier run; put it back as {F} (cp -p) and remove it first")
    sys.exit(1)
if not os.path.isfile(F):
    print(f"REFUSED: no {F} to restore later")
    sys.exit(1)


def scope():
    """The networks the service reads now (sorted strings), or None when it does not answer."""
    try:
        s = json.load(urllib.request.urlopen(BASE + "/api/settings", timeout=60))["settings"]
        return sorted(str(a) for a in s.get("networks") or [])
    except Exception:  # noqa: BLE001  restarting, or not up yet
        return None


def restart():
    r = subprocess.run([os.path.join(REAL, "deploy", "reload.sh")], cwd=REAL, capture_output=True, text=True, timeout=180)
    print(f"  restart: {(r.stdout.strip().splitlines() or [''])[-1]} (exit {r.returncode})")
    return r.returncode == 0


def wait_scope(want, limit=240):
    now = None
    t0 = time.time()
    while time.time() - t0 < limit:
        now = scope()
        if now == want:
            print(f"  the service reads {want or 'every network (no constituency)'}")
            return True
        time.sleep(3)
    print(f"  the service did not read {want} within {limit} s (last answer: {now})")
    return False


def sha(path):
    return hashlib.sha256(open(path, "rb").read()).hexdigest()


def pick():
    """3 to 5 AS numbers in the day's made-up data (read-only), seen on both platforms when there are such."""
    comm, svc = Counter(), Counter()
    for name in db.list_collection_names():
        if name.startswith("system."):
            continue
        for d in db[name].find(q(), {"extracted_date": 1, "src_asn": 1, "dst_asn": 1, "asn": 1}).limit(200000):
            if not in_day(d):
                continue
            for k in ("src_asn", "dst_asn"):
                if d.get(k):
                    comm[str(d[k])] += 1
            if d.get("asn"):
                svc[str(d["asn"])] += 1
    both = [a for a, _ in (comm + svc).most_common() if a in comm and a in svc and a.isdigit()]
    out = both[:4]
    if len(out) < 3:
        out += [a for a, _ in (comm + svc).most_common() if a.isdigit() and a not in out][:4 - len(out)]
    return sorted(out)


def _stop(signum, _frame):
    raise SystemExit(128 + signum)          # the restore below still runs (finally)


for _sig in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
    signal.signal(_sig, _stop)

orig_bytes = open(F, "rb").read()
orig_mode = stat.S_IMODE(os.stat(F).st_mode)
orig_sha = hashlib.sha256(orig_bytes).hexdigest()
orig_scope = scope()
if orig_scope is None:
    print("FAILED: the service does not answer /api/settings: nothing changed")
    sys.exit(1)
os.makedirs(KEEP, mode=0o700, exist_ok=True)
fd = os.open(BK, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, "wb") as f:
    f.write(orig_bytes)
print(f"before: {F} sha256 {orig_sha}; the service reads {orig_scope or 'every network (no constituency)'}")
rc = 1
try:
    nets = pick()
    if not 3 <= len(nets) <= 5:
        print(f"FAILED: not 3 to 5 networks in the made-up data for {day} ({nets})")
    else:
        print(f"a temporary constituency of {nets} (found in the data for {day})")
        d = json.loads(orig_bytes.decode("utf-8"))
        d.update(networks=nets, cidrs=[], updated_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
        tmp = tempfile.NamedTemporaryFile("w", dir=os.path.dirname(F), prefix=".settings.", suffix=".tmp", delete=False,
                                          encoding="utf-8")
        with tmp:
            json.dump(d, tmp, indent=2)
        os.chmod(tmp.name, orig_mode)
        os.replace(tmp.name, F)
        if restart() and wait_scope(nets):
            print(f"constituency: {len(nets)} network(s), 0 range(s)")
            problems = check(set(nets))
            if problems is None:
                print(f"FAILED: no records for {day} on either platform, though the networks came from that day's data")
            else:
                rc = report(problems)
finally:
    for _sig in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
        signal.signal(_sig, signal.SIG_IGN)     # a stop now must not cut the restore short
    print("restore the original settings.json")
    ok = True
    with open(F, "wb") as f:                # in place: the same file, its exact bytes and mode
        f.write(open(BK, "rb").read())
    os.chmod(F, orig_mode)
    ok = restart() and ok
    ok = wait_scope(orig_scope) and ok
    now_sha = sha(F)
    if now_sha == orig_sha == sha(BK) and stat.S_IMODE(os.stat(F).st_mode) == orig_mode:
        print(f"  settings.json equals the backup byte for byte (sha256 {now_sha}), mode {oct(orig_mode)}")
    else:
        print(f"  RESTORE FAILED: sha256 {now_sha}, the backup {orig_sha}")
        ok = False
    if ok:
        os.remove(BK)
        try:
            os.rmdir(KEEP)
        except OSError:
            pass
        print("RESTORED: the test system's settings and scope are the original again")
    else:
        print(f"RESTORE NOT PROVEN: the backup is kept at {BK}")
        rc = 1
sys.exit(rc)
