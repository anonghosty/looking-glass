# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""Print compact details of the src/dst collections found by discover.py."""
import json
import os
import sys

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# discover.py writes data/discovery.json (masked, owner-only), no longer tools/discovery.json in the code folder
PATH = os.path.join(BASE, "data", "discovery.json")
try:
    with open(PATH, encoding="utf-8") as fh:
        data = json.load(fh)
except OSError:
    sys.exit(f"{PATH} is not there: run tools/discover.py first.")
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
