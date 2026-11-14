"""Find infections in the data that are not yet defined in data/infections.json.

Usage:  .venv/bin/python manage/infections_missing.py [days]      (default: the last 7 days)

Read-only against Mongo. Prints the undefined and needs-review infections with counts, reports, tags,
families and sample C2 domains, and writes data/infections_missing.json with ready-to-fill stub entries.
Research and write the new entries from that file (or this output), then merge them into data/infections.json. The server picks up changes to that file without a restart.
"""
import json
import os
import sys
from collections import Counter, defaultdict
from datetime import timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import app as tm  # noqa: E402

days = int(sys.argv[1]) if len(sys.argv) > 1 else 7
kb = tm.knowledge_base()
today = tm.day_start(tm.utcnow())
info = defaultdict(lambda: {"count": 0, "days": set(), "reports": Counter(), "tags": Counter(), "families": Counter(),
                            "c2": Counter(), "ports": Counter()})
for back in range(days, 0, -1):
    day = today - timedelta(days=back)
    d = tm.store._load(day)
    for e in d.events:
        k = (e["infection"] or "unknown").lower()
        i = info[k]
        i["count"] += 1
        i["days"].add(day.date().isoformat())
        i["reports"][e["source"]] += 1
        if e["tag"]: i["tags"][e["tag"]] += 1
        if e["family"]: i["families"][e["family"]] += 1
        host = e["http_host"] or e["extras"].get("query", "")
        if host: i["c2"][host] += 1
        if e["dst_port"]: i["ports"][e["dst_port"]] += 1

missing = {k: v for k, v in info.items() if k not in kb}
review = {k: v for k, v in info.items() if k in kb and kb[k].get("status") != "reviewed"}


def summary(k, v):
    top = lambda c, n=3: [x for x, _ in c.most_common(n)]
    return {"infection": k, "count": v["count"], "days_seen": sorted(v["days"]), "reports": top(v["reports"]),
            "tags": top(v["tags"]), "families": top(v["families"]), "sample_c2": top(v["c2"], 5), "ports": top(v["ports"])}


out = {
    "checked_days": days, "until": (today - timedelta(days=1)).date().isoformat(),
    "seen": len(info), "defined": len(info) - len(missing),
    "missing": [summary(k, v) for k, v in sorted(missing.items(), key=lambda kv: -kv[1]["count"])],
    "needs_review": [summary(k, v) for k, v in sorted(review.items(), key=lambda kv: -kv[1]["count"])],
    "stubs": {k: {"title": "", "type": "", "description": "", "action": "", "confidence": "low",
                  "status": "needs-review", "aliases": [], "updated": ""} for k in missing},
}
path = os.path.join(tm.BASE_DIR, "data", "infections_missing.json")
with open(path, "w", encoding="utf-8") as f:
    json.dump(out, f, indent=2)

print(f"Checked {days} days up to {out['until']}: {out['seen']} infections seen, {out['defined']} defined, "
      f"{len(missing)} missing, {len(review)} need review.")
for title, rows in (("MISSING", out["missing"]), ("NEEDS REVIEW", out["needs_review"])):
    if rows:
        print(f"\n{title}:")
        for r in rows:
            print(f"  {r['infection']:32s} {r['count']:>7,}  reports={','.join(r['reports'])}  tags={','.join(r['tags'])}  c2={','.join(r['sample_c2'][:3])}")
print(f"\nWrote {path}")
