"""Print compact details of the src/dst collections found by discover.py."""
import json
import os
import sys

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
data = json.load(open(os.path.join(BASE, "tools", "discovery.json"), encoding="utf-8"))
only = set(sys.argv[1:])
for e in data["collections"]:
    if not e.get("srcdst") or (only and e["name"] not in only):
        continue
    print("=" * 100)
    print(e["name"], "| est", e.get("estimated"), "| yday", e.get("yesterday_rows"), e.get("yesterday_files"), "| idx", e.get("indexes"))
    lat = e.get("latest", {})
    keep = {k: v for k, v in lat.items() if v not in ("", None, "None")}
    print("  non-empty:", json.dumps(keep, ensure_ascii=False)[:1400])
    print("  empty   :", ",".join(k for k, v in lat.items() if v in ("", None, "None")))
