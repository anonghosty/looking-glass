"""Look up every infection seen in the replay day on Malpedia (through the running app) and show what matched.

Usage: .venv/bin/python tools/malpedia_check.py
Useful when reviewing the knowledge base: low-score or missing matches need a person to check them.
"""
import os as _os, sys as _sys; _sys.path.insert(0, _os.path.join(_os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))), "tests"))
import lgauth  # noqa: E402,F401  local API login (automation key)
import json
import urllib.parse
import urllib.request

get = lambda p: json.load(urllib.request.urlopen("http://127.0.0.1:5000" + p, timeout=120))
facets = get("/api/facets")
names = [r["value"] for r in facets["infection"]]
print(f"{len(names)} infections on {facets['day']}\n")
print(f"{'infection':30} {'events':>7}  {'Malpedia family':28} matched by")
counts = {r["value"]: r["count"] for r in facets["infection"]}
found = 0
for n in names:
    r = get("/api/malpedia?field=infection&value=" + urllib.parse.quote(n))
    f = r.get("family")
    m = (r.get("matches") or [{}])[0]
    found += bool(f)
    print(f"{n[:30]:30} {counts[n]:7,}  {(f['id'] if f else '-')[:28]:28} {m.get('matched_by', 'no match') if f else 'no match'}")
print(f"\n{found} of {len(names)} infections matched a Malpedia family.")
