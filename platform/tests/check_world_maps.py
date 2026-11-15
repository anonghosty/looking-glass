#!/usr/bin/env python3
"""World maps (static/data/adm1, manage/fetch_world_boundaries.py): every ISO 3166-1 country and Kosovo is listed
under one of the seven continents with a map that loads (regions, or one area), a frame, a source with its licence,
its names, and a size the browser can take; regions have names, polygons with at least a triangle, and land in the
frame; countries across the 180th meridian are drawn in one piece. No network or database needed.
Run: .venv/bin/python tests/check_world_maps.py [DIR]"""
import json
import os
import sys

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
D = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "static", "data", "adm1")
ISO_1 = "/usr/share/iso-codes/json/iso_3166-1.json"
checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{str(info)[:300]}]" if info and not cond else ""))


index = json.load(open(os.path.join(D, "index.json"), encoding="utf-8"))
cs = index["countries"]
CONT = ("Africa", "Asia", "Europe", "North America", "South America", "Oceania", "Antarctica")

print("The index")
ok("the seven continents, in order", tuple(index.get("continents") or ()) == CONT, index.get("continents"))
if os.path.exists(ISO_1):
    iso = {r["alpha_2"] for r in json.load(open(ISO_1, encoding="utf-8"))["3166-1"]} | {"XK"}
    ok(f"every ISO 3166-1 country and Kosovo is listed ({len(iso)})", iso <= set(cs), sorted(iso - set(cs)))
else:
    ok("at least 249 countries listed", len(cs) >= 249, len(cs))
ok("every country is on a continent", all(v.get("continent") in CONT for v in cs.values()),
   [k for k, v in cs.items() if v.get("continent") not in CONT])
by = {c: sum(v["continent"] == c for v in cs.values()) for c in CONT}
ok("the 54 African countries are in Africa", by["Africa"] >= 54, by)
for cc, cont in (("GH", "Africa"), ("KE", "Africa"), ("EG", "Africa"), ("BR", "South America"), ("MX", "North America"),
                 ("JM", "North America"), ("DE", "Europe"), ("RU", "Europe"), ("XK", "Europe"), ("IN", "Asia"),
                 ("TR", "Asia"), ("AU", "Oceania"), ("FJ", "Oceania"), ("AQ", "Antarctica"), ("SJ", "Europe"), ("CX", "Oceania")):
    ok(f"{cc} is in {cont}", cs.get(cc, {}).get("continent") == cont, cs.get(cc, {}).get("continent"))
nomap = [k for k, v in cs.items() if v.get("kind") not in ("regions", "whole")]
ok("every country has a map (regions or one area)", not nomap, nomap)
ok("at least 190 countries have their regions", sum(v.get("kind") == "regions" for v in cs.values()) >= 190)
ok("every map names its licence", all(v.get("licence") for v in cs.values()), [k for k, v in cs.items() if not v.get("licence")])
ok("every country has its names (for 'region unknown')", all(v.get("names") for v in cs.values()))

print("The map files")
bad, big, frame, tri, names, whole = [], [], [], [], [], []
for cc, v in sorted(cs.items()):
    p = os.path.join(D, f"{cc}.json")
    try:
        f = json.load(open(p, encoding="utf-8"))
    except (OSError, ValueError) as e:
        bad.append(f"{cc}: {e}")
        continue
    if os.path.getsize(p) > 650_000:
        big.append(f"{cc} {os.path.getsize(p) // 1024} KB")
    regs = f.get("regions") or {}
    if v["kind"] == "whole" and not (f.get("whole") and len(regs) == 1):
        whole.append(cc)
    if v["kind"] == "regions" and len(regs) != v["regions"]:
        whole.append(f"{cc} count")
    w, s, e, n = f.get("bbox") or (0, 0, 0, 0)
    if not (-180 <= w < e <= 360 and -90 <= s < n <= 90 and e - w <= 360):
        frame.append(cc)
    for k, r in regs.items():
        if not r.get("name"):
            names.append(f"{cc}/{k}")
        for poly in r.get("polys") or [[]]:
            for ring in poly or [[]]:
                if len(ring) < 4 or any(not (w - 0.01 <= x <= e + 0.01 and s - 0.01 <= y <= n + 0.01) for x, y in ring):
                    tri.append(f"{cc}/{k}")
                    break
ok("every map file loads", not bad, bad)
ok("no map file over 650 KB (simplified for the browser)", not big, big)
ok("whole-country maps have one area; region counts agree with the index", not whole, whole)
ok("every frame is sensible", not frame, frame)
ok("every region has a name", not names, names)
ok("every ring is at least a triangle, inside the frame", not tri, tri[:20])

print("Across the 180th meridian")
for cc in ("FJ", "RU", "NZ", "KI"):
    b = cs.get(cc, {}).get("bbox") or [0, 0, 0, 0]
    ok(f"{cc} is drawn in one piece (frame {b[2] - b[0]:.0f} degrees wide)", b[2] - b[0] < 200, b)

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
