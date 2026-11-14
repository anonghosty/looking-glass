#!/usr/bin/env python3
"""How much this installation uses, against budgets (2026-11-14: measured by hand before a release; now one command,
run by the release so a change that doubles memory or disk is seen before it reaches users).

  disk: the platform's code, its Python libraries, its data/; the pipeline's folder and its report copies;
        the report database (MongoDB dbStats, with the platform's own read-only account); free disk
  memory: the web service (every gunicorn process) and MongoDB, as the system reports them (RSS)

Budgets (.env): RESOURCE_WEB_MB (4096), RESOURCE_MONGO_MB (4096), RESOURCE_MIN_FREE_GB (5). Over a budget: a warning
line and exit code 1. Nothing is changed. Run on the server: ./tools/resource_check.py [--json]
"""
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(HERE))


def du(path):
    """Bytes under a folder (symlinks not followed), 0 when missing."""
    total = 0
    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if not os.path.islink(os.path.join(root, d))]
        for f in files:
            try:
                total += os.lstat(os.path.join(root, f)).st_size
            except OSError:
                pass
    return total


def rss_mb(pattern):
    try:
        out = subprocess.run(["ps", "-eo", "rss=,args="], capture_output=True, text=True, timeout=10).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    return round(sum(int(ln.split(None, 1)[0]) for ln in out.splitlines()
                     if pattern in ln and "resource_check" not in ln and ln.strip()) / 1024)


def db_stats():
    try:
        from pymongo import MongoClient
        env = os.environ
        kw = dict(host=env.get("MONGO_HOST", "127.0.0.1"), port=int(env.get("MONGO_PORT") or 27017), serverSelectionTimeoutMS=5000)
        if env.get("MONGO_USER"):
            kw.update(username=env["MONGO_USER"], password=env.get("MONGO_PASSWORD"),
                      authSource=env.get("MONGO_AUTH_SOURCE") or env.get("MONGO_DB") or "admin")
        s = MongoClient(**kw)[env.get("MONGO_DB") or "shadowserver"].command("dbStats", scale=1048576)
        return {"collections": s["collections"], "records": s["objects"], "data_mb": round(s["dataSize"]),
                "on_disk_mb": round(s["storageSize"] + s["indexSize"])}
    except Exception as e:  # noqa: BLE001
        return {"error": e.__class__.__name__}


def main():
    try:
        from dotenv import load_dotenv
        load_dotenv(HERE / ".env")
    except ImportError:
        pass
    import pipeline_link
    mb = lambda b: round(b / 1048576)  # noqa: E731
    r = {"platform_code_mb": mb(du(HERE) - du(HERE / ".venv") - du(HERE / "data")), "platform_libraries_mb": mb(du(HERE / ".venv")),
         "platform_data_mb": mb(du(HERE / "data"))}
    pdir = pipeline_link.find_dir(str(HERE))
    if pdir:
        penv = pipeline_link.read_env(pdir / ".env")
        base = Path(os.path.expanduser(penv.get("DATA_DIR") or str(pdir)))
        r.update(pipeline_folder_mb=mb(du(pdir)), pipeline_report_copies_mb=mb(du(base / "sorting_backup")))
    r["database"] = db_stats()
    r["free_disk_gb"] = round(shutil.disk_usage(HERE).free / 1024 ** 3, 1)
    r["web_mb"], r["mongodb_mb"] = rss_mb("gunicorn"), rss_mb("mongod ")
    budget = {"web": int(os.environ.get("RESOURCE_WEB_MB") or 4096), "mongo": int(os.environ.get("RESOURCE_MONGO_MB") or 4096),
              "free": float(os.environ.get("RESOURCE_MIN_FREE_GB") or 5)}
    over = []
    if r["web_mb"] and r["web_mb"] > budget["web"]:
        over.append(f"the web service uses {r['web_mb']} MB (budget {budget['web']}, RESOURCE_WEB_MB)")
    if r["mongodb_mb"] and r["mongodb_mb"] > budget["mongo"]:
        over.append(f"MongoDB uses {r['mongodb_mb']} MB (budget {budget['mongo']}, RESOURCE_MONGO_MB)")
    if r["free_disk_gb"] < budget["free"]:
        over.append(f"only {r['free_disk_gb']} GB free (budget {budget['free']}, RESOURCE_MIN_FREE_GB)")
    r["over_budget"] = over
    if "--json" in sys.argv:
        print(json.dumps(r, indent=2))
    else:
        d = r["database"]
        print(f"disk: platform code {r['platform_code_mb']} MB, libraries {r['platform_libraries_mb']} MB, data {r['platform_data_mb']} MB"
              + (f"; pipeline {r['pipeline_folder_mb']} MB (report copies {r['pipeline_report_copies_mb']} MB)" if pdir else "")
              + (f"; database {d['on_disk_mb']} MB on disk for {d['records']:,} records" if "records" in d else f"; database: not read ({d.get('error')})")
              + f"; {r['free_disk_gb']} GB free")
        print(f"memory: web service {r['web_mb']} MB, MongoDB {r['mongodb_mb']} MB")
        for o in over:
            print("OVER BUDGET: " + o)
        if not over:
            print("within budget")
    return 1 if over else 0


if __name__ == "__main__":
    sys.exit(main())
