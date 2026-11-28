# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""Survey every collection in the Shadowserver DB: which ones carry source/destination fields?

Read-only. For each collection: estimated size, indexes, field names (union of the latest 3 docs),
fields whose name contains 'src' or 'dst', the latest document's date/filename, and how many rows the
previous day's report file(s) hold (using the filename index when present).
Writes data/discovery.json (owner-only, beside the platform's other data; never into the code folder) and prints a
summary. Every value taken from a record is masked first (hostmask.py: no address, host name or e-mail): the survey
is about the reports' layout, not about anyone in them (audit 2026-11-27, 8-10: it wrote raw records to
tools/discovery.json, inside the code tree).

Usage: .venv/bin/python tools/discover.py [--out PATH]
"""
import json
import os
import re
import sys
from datetime import datetime, timedelta, timezone

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)
import hostmask  # noqa: E402  (masks addresses, host names and e-mails in the values shown)


def short(v):
    """A value as the survey shows it: masked, and at most 80 characters, a cut said in words."""
    s = v.isoformat() if isinstance(v, datetime) else hostmask.mask(str(v))
    return s if len(s) <= 80 else f"{s[:70]} [cut, {len(s):,} characters]"


def survey(db, yesterday, say=print):
    report = []
    for name in sorted(db.list_collection_names()):
        c = db[name]
        entry = {"name": name}
        try:
            entry["estimated"] = c.estimated_document_count()
            idx = [list(ix["key"].keys()) for ix in c.list_indexes()]
            entry["indexes"] = idx
            docs = list(c.find().sort("_id", -1).limit(3))
            fields = []
            for d in docs:
                for k in d:
                    if k not in fields:
                        fields.append(k)
            entry["fields"] = fields
            entry["srcdst"] = [f for f in fields if re.search(r"src|dst", f, re.I)]
            latest = docs[0] if docs else {}
            entry["latest"] = {k: short(v) for k, v in latest.items() if k != "_id"}
            entry["has_extracted_date"] = "extracted_date" in fields
            entry["has_filename"] = "filename" in fields
            if idx and any(i and i[0] == "filename" for i in idx) and "filename" in fields:
                q = {"filename": {"$regex": "^" + re.escape(yesterday)}}
                entry["yesterday_rows"] = c.count_documents(q)
                entry["yesterday_files"] = [short(x) for x in c.distinct("filename", q)[:5]]
            else:
                entry["yesterday_rows"] = None
        except Exception as exc:  # noqa: BLE001  keep going
            entry["error"] = short(exc)
        report.append(entry)
        flag = "SRC/DST" if entry.get("srcdst") else "       "
        say(f"{flag} {name:42s} est={entry.get('estimated', '?'):>10}  yday={entry.get('yesterday_rows')!s:>7}  "
            f"{','.join(entry.get('srcdst', []))}")
    return report


def write(path, data):
    """Owner-only (0600), written whole and then moved into place."""
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    tmp = f"{path}.{os.getpid()}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=1, default=str)
    os.replace(tmp, path)


def main(argv=None, db=None):
    argv = sys.argv[1:] if argv is None else argv
    out = os.path.join(BASE, "data", "discovery.json")
    if "--out" in argv and argv.index("--out") + 1 < len(argv):
        out = argv[argv.index("--out") + 1]
    if db is None:
        from dotenv import load_dotenv
        from pymongo import MongoClient
        import db_connect  # (where the database is; TLS for one on another computer)
        load_dotenv(os.path.join(BASE, ".env"))
        client = MongoClient(
            **db_connect.kwargs(os.environ.get),
            username=os.environ.get("MONGO_USER"), password=os.environ.get("MONGO_PASSWORD"),
            authSource=os.environ.get("MONGO_AUTH_SOURCE", "admin"), serverSelectionTimeoutMS=5000, tz_aware=True,
        )
        db = client[os.environ.get("MONGO_DB", "shadowserver")]
    yesterday = (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%d")
    report = survey(db, yesterday, say=lambda s: print(s, flush=True))
    write(out, {"yesterday": yesterday, "collections": report})
    print("\nwith src/dst fields:", sum(1 for e in report if e.get("srcdst")), "of", len(report))
    print("written to", out)
    return out


if __name__ == "__main__":
    main()
