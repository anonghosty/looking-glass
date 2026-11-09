"""When did each report for a day arrive in MongoDB? (insert time from the ObjectId of its records)

Usage: .venv/bin/python tools/report_arrivals.py [YYYY-MM-DD]   (default: yesterday UTC)
"""
import os
import re
import sys
from datetime import datetime, timedelta, timezone

from dotenv import load_dotenv
from pymongo import MongoClient

load_dotenv(os.path.join(os.path.dirname(__file__), "..", ".env"))
day = sys.argv[1] if len(sys.argv) > 1 else (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%d")
nxt = (datetime.fromisoformat(day) + timedelta(days=1)).strftime("%Y-%m-%d")

client = MongoClient(host=os.environ["MONGO_HOST"], port=int(os.environ.get("MONGO_PORT", 27017)),
                     username=os.environ.get("MONGO_USER"), password=os.environ.get("MONGO_PASSWORD"),
                     authSource=os.environ.get("MONGO_AUTH_SOURCE", "admin"), serverSelectionTimeoutMS=8000)
db = client[os.environ["MONGO_DB"]]

print(f"Reports with files for {day} / {nxt} (filename prefix)")
for name in sorted(db.list_collection_names()):
    c = db[name]
    for p in (day, nxt):
        q = {"filename": {"$regex": "^" + re.escape(p)}}
        n = c.count_documents(q)
        if not n:
            continue
        first = c.find(q, {"_id": 1}).sort("_id", 1).limit(1)[0]["_id"].generation_time
        last = c.find(q, {"_id": 1}).sort("_id", -1).limit(1)[0]["_id"].generation_time
        files = c.distinct("filename", q)
        print(f"  {name:40s} file {p}  {n:7d} rows  inserted {first:%m-%d %H:%M:%S} .. {last:%m-%d %H:%M:%S}  {files[:3]}")
