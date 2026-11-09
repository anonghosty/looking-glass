"""End-to-end self test: old loader vs new pipeline on generated data, compared in MongoDB.

  .venv/bin/python tests/selftest_compare.py [--rows 5000] [--files 30] [--keep]

Uses databases shadowserver_selftest_new / shadowserver_selftest_old (dropped afterwards)
and a temp folder; never touches the real 'shadowserver' database or data folders.
Needs aiofiles + async_lru in the venv to run the original script.
"""
import argparse
import asyncio
import importlib.util
import os
import random
import shutil
import sys
import tempfile
import time
import zipfile
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import shadowserver_pipeline as sp  # noqa: E402

SERVICES = ["scan_http", "scan_ssl", "event4_honeypot_brute_force", "blocklist"]


def make_csv(rows, rnd):
    out = ["timestamp,ip,port,asn,geo,region,city,hostname,tag,naics"]
    for i in range(rows):
        ts = f"2025-08-{rnd.randint(1, 28):02d} {rnd.randint(0, 23):02d}:{rnd.randint(0, 59):02d}:{rnd.randint(0, 59):02d}"
        if i % 997 == 0:
            ts = "not-a-date"
        line = f"{ts},198.18.{rnd.randint(0,255)}.{rnd.randint(0,255)},{rnd.choice([80,443,22,8080])}," \
               f"{rnd.randint(1000,40000)},XX,EXAMPLE REGION,EXAMPLE CITY,host{i}.example,\"tag;{i % 7}\",{rnd.randint(0,9)}"
        out.append(line)
        if i % 500 == 0:
            out.append(line)  # duplicate row
    return "\n".join(out) + "\n"


def build_dataset(base: Path, files: int, rows: int):
    rnd = random.Random(42)
    att = base / "attachments_backup"
    att.mkdir(parents=True)
    n = 0
    for svc in SERVICES:
        for f in range(files):
            day = f"2025-07-{(f % 28) + 1:02d}"
            name = f"{day}-{svc}-{f:03d}-ghana-geo.csv"
            with zipfile.ZipFile(att / f"{svc}-{f}.zip", "w", zipfile.ZIP_DEFLATED) as zf:
                zf.writestr(name, make_csv(rows, rnd))
                zf.writestr("README.txt", "not a report")
            n += 1
    (att / "2025-07-01-loose_attach-ghana-geo.csv").write_text(make_csv(50, rnd))
    (att / "broken.zip").write_bytes(b"this is not a zip")
    return n


def run_old_loader(sorting_dir: Path, db_name: str, mongo_kwargs: dict):
    # The original loader reads its settings from .env; point it at the test folder and database instead.
    spec = importlib.util.spec_from_file_location("old_loader", ROOT / "mongo_added_json.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.root_directory = str(sorting_dir)
    mod.mongo_db_name = db_name
    mod.mongo_username = mongo_kwargs["username"]
    mod.mongo_password = mongo_kwargs["password"]
    loop = asyncio.new_event_loop()
    mod.loop = loop
    loop.run_until_complete(mod.main())
    loop.close()


def norm(doc):
    doc.pop("_id", None)
    return tuple(sorted((k, repr(v)) for k, v in doc.items()))


def compare(db_old, db_new):
    problems = []
    names_old, names_new = set(db_old.list_collection_names()), set(db_new.list_collection_names())
    if names_old != names_new:
        problems.append(f"collection sets differ: old-only {names_old - names_new}, new-only {names_new - names_old}")
    for name in sorted(names_old & names_new):
        a = Counter(norm(d) for d in db_old[name].find())
        b = Counter(norm(d) for d in db_new[name].find())
        if name.startswith("files_"):  # old inserts a duplicate per run; compare distinct entries
            a, b = Counter(set(a)), Counter(set(b))
        if a != b:
            problems.append(f"{name}: {sum((a - b).values())} doc(s) only in old, {sum((b - a).values())} only in new")
        if not name.startswith(("files_", "discovered_fields_")):
            ia = {k: v.get("unique") for k, v in db_old[name].index_information().items()}
            ib = {k: v.get("unique") for k, v in db_new[name].index_information().items()}
            if ia != ib:
                problems.append(f"{name}: indexes differ {ia} vs {ib}")
    return problems


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rows", type=int, default=5000)
    ap.add_argument("--files", type=int, default=30)
    ap.add_argument("--keep", action="store_true")
    args = ap.parse_args()

    sp.logging.basicConfig(level=sp.logging.INFO, format="%(asctime)s %(levelname)-7s %(message)s")
    base = Path(tempfile.mkdtemp(prefix="sstest-"))
    os.environ["DATA_DIR"] = str(base)
    os.environ["MONGO_DB"] = "shadowserver_selftest_new"
    s = sp.load_settings(sp.argparse.Namespace(env_file=str(ROOT / ".env"), workers=None, days=None))
    client = sp.mongo_client(s.mongo)
    for d in ("shadowserver_selftest_new", "shadowserver_selftest_old"):
        client.drop_database(d)

    nzip = build_dataset(base, args.files, args.rows)
    print(f"\nDataset: {nzip} zips x {args.rows} rows in {base}\n")

    stats = Counter()
    t = time.monotonic()
    sp.unzip_and_sort(s, stats)
    t_unzip = time.monotonic() - t
    t = time.monotonic()
    sp.load_into_mongo(s, stats)
    t_new = time.monotonic() - t
    rows_new = stats["rows_inserted"]

    stats2 = Counter()
    t = time.monotonic()
    sp.load_into_mongo(s, stats2)
    t_rerun = time.monotonic() - t

    print("\n--- running ORIGINAL mongo_added_json.py on the same sorting_backup ---")
    t = time.monotonic()
    run_old_loader(s.sorting_dir, "shadowserver_selftest_old", s.mongo)
    t_old = time.monotonic() - t

    problems = compare(client["shadowserver_selftest_old"], client["shadowserver_selftest_new"])
    print("\n================ RESULT ================")
    print(f"unzip+sort (new):           {t_unzip:6.1f}s  bad zip deleted={stats['zips_bad_deleted']}, loose csv moved={stats['csv_moved']}")
    print(f"load, original script:      {t_old:6.1f}s")
    print(f"load, new pipeline:         {t_new:6.1f}s  ({rows_new:,} rows, {rows_new / max(t_new, 1e-9):,.0f} rows/s)")
    print(f"speed-up:                   {t_old / max(t_new, 1e-9):6.1f}x")
    print(f"re-run (nothing new):       {t_rerun:6.1f}s  files loaded={stats2['files_loaded']}")
    print("identical data in MongoDB: " + ("YES" if not problems else "NO"))
    for p in problems:
        print("  - " + p)

    if not args.keep:
        for d in ("shadowserver_selftest_new", "shadowserver_selftest_old"):
            client.drop_database(d)
        shutil.rmtree(base, ignore_errors=True)
    return 1 if problems or stats2["files_loaded"] else 0


if __name__ == "__main__":
    sys.exit(main())
