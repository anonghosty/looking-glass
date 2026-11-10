"""List every infection seen on a replay day, with counts, reports, tags, families and sample C2 hosts."""
import os
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import app as tm  # noqa: E402

day_arg = sys.argv[1] if len(sys.argv) > 1 else None
# not tm.parse_iso: that clamps to the replay day and the day before it (for web requests), so any other day was ignored
try:
    start = (datetime.strptime(day_arg, "%Y-%m-%d").replace(tzinfo=timezone.utc) if day_arg
             else tm.day_start(tm.utcnow() - timedelta(days=1)))
except ValueError:
    sys.exit("usage: tools/list_infections.py [YYYY-MM-DD]")
d = tm.store._load(start)
info = defaultdict(lambda: {"n": 0, "src": Counter(), "tag": Counter(), "fam": Counter(), "host": Counter(), "port": Counter(), "app": Counter()})
for e in d.events:
    i = info[e["infection"] or "unknown"]
    i["n"] += 1
    i["src"][e["source"]] += 1
    i["tag"][e["tag"]] += 1
    i["fam"][e["family"]] += 1
    i["host"][e["http_host"] or e["extras"].get("query", "")] += 1
    i["port"][e["dst_port"]] += 1
    i["app"][e["application"]] += 1
print(f"{start.date()}: {len(info)} infections")
for name, i in sorted(info.items(), key=lambda kv: -kv[1]["n"]):
    top = lambda c, k=3: ", ".join(f"{v}" for v, _ in c.most_common(k) if v)
    print(f"{name} | {i['n']} | src: {top(i['src'])} | tag: {top(i['tag'])} | fam: {top(i['fam'])} | app: {top(i['app'])} | port: {top(i['port'])} | host/query: {top(i['host'])}")
