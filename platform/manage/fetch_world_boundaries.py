#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""Region maps for every country and territory in the world (ISO 3166-1, plus Kosovo), for Settings and the maps.

For each country, static/data/adm1/<ISO2>.json and an entry in static/data/adm1/index.json:
  * first-level regions (provinces, states, counties...) from geoBoundaries gbOpen ADM1 where it has them;
  * otherwise the country's outline as one area ("the whole country") from geoBoundaries gbOpen ADM0;
  * otherwise the outline from Natural Earth (public domain), so no country is left out.
The index carries each country's continent (Africa, Asia, Europe, North America, South America, Oceania, Antarctica)
for the two-step choice in Settings and the installer, its region count, its frame (bbox; countries that cross the
180th meridian get longitudes past 180 so they draw in one piece) and where its boundaries come from, with the licence.
Region names are then matched to ISO 3166-2 and their aliases (manage/region_aliases.py).

Usage: python3 manage/fetch_world_boundaries.py [--out DIR] [ISO2 ...]     (default: every country, into
       static/data/adm1). Standard library only; downloads from geoboundaries.org, github.com (geoBoundaries,
       Natural Earth) at build time. Nothing is fetched while Looking Glass runs.
"""
import json
import os
import sys
import unicodedata
import urllib.request
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "..", "static", "data", "adm1")
GB_API = "https://www.geoboundaries.org/api/current/gbOpen/ALL/{level}/"
NE_URL = ("https://raw.githubusercontent.com/nvkelso/natural-earth-vector/v5.1.2/geojson/"
          "ne_10m_admin_0_countries.geojson")
ISO_1 = "/usr/share/iso-codes/json/iso_3166-1.json"
SUFFIXES = (" REGION", " PROVINCE", " STATE", " GOVERNORATE", " COUNTY", " DISTRICT", " PREFECTURE", " DEPARTMENT",
            " WILAYA", " ATOLL")
CONTINENTS = ("Africa", "Asia", "Europe", "North America", "South America", "Oceania", "Antarctica")
# Natural Earth's continent names, and a few places neither source places well
NE_CONT = {"Seven seas (open ocean)": "Africa", "Antarctica": "Antarctica"}
FIXED_CONT = {"AQ": "Antarctica", "BV": "Antarctica", "HM": "Antarctica", "GS": "Antarctica", "TF": "Africa",
              "IO": "Asia", "UM": "Oceania", "SH": "Africa", "XK": "Europe", "RU": "Europe", "TR": "Asia",
              "CY": "Asia", "GE": "Asia", "AM": "Asia", "AZ": "Asia", "KZ": "Asia", "EG": "Africa",
              "SJ": "Europe", "CX": "Oceania", "CC": "Oceania"}
# Territories that Natural Earth draws inside another country's outline: their islands are taken from it by frame
# (west, south, east, north), so they are not left out
ISLANDS = {"SJ": [(10.0, 74.0, 35.0, 81.0), (-9.5, 70.7, -7.5, 71.3)],     # Svalbard, Jan Mayen
           "CX": [(105.4, -10.7, 105.9, -10.3)], "CC": [(96.7, -12.3, 97.0, -11.7)], "BV": [(3.2, -54.6, 3.6, -54.3)]}
BUDGET = 600_000      # bytes per country file; larger maps are simplified further so the browser stays quick


def get_json(url, timeout=180):
    with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "LookingGlass/1.0 (region maps)"}),  # nosec B310  # fixed https sources
                                timeout=timeout) as r:
        return json.load(r)


def norm(name):
    n = unicodedata.normalize("NFKD", name or "").encode("ascii", "ignore").decode().upper().strip()
    for s in SUFFIXES:
        if n.endswith(s):
            n = n[: -len(s)].strip()
    return n


def ascii_name(name):
    return unicodedata.normalize("NFKD", name or "").encode("ascii", "ignore").decode()


def continent_of(gb, iso2):
    if iso2 in FIXED_CONT:
        return FIXED_CONT[iso2]
    c, sub = (gb or {}).get("Continent") or "", (gb or {}).get("UNSDG-subregion") or ""
    if c == "Latin America and the Caribbean":
        return "South America" if sub == "South America" else "North America"
    if c == "Northern America":
        return "North America"
    return c if c in CONTINENTS else ""


def compact(geom, step):
    if not geom:
        return []
    polys = geom["coordinates"] if geom["type"] == "MultiPolygon" else [geom["coordinates"]] if geom["type"] == "Polygon" else []
    out = []
    for poly in polys:
        rings = []
        for ring in poly:
            pts = [[round(x, 3), round(y, 3)] for x, y in ring]
            if len(pts) > 400:                       # thin very detailed rings (coastlines) for the browser
                pts = pts[::step] + [pts[-1]]
            keep = [p for i, p in enumerate(pts) if i == 0 or p != pts[i - 1]]
            if len(keep) >= 4:
                rings.append(keep)
        if rings:
            out.append(rings)
    return out


def unwrap(regions):
    """A country across the 180th meridian (Fiji, Kiribati, Russia, the United States, New Zealand...): its western
    longitudes are moved past 180 so it draws in one piece. Returns the bbox [west, south, east, north]."""
    xs = [p[0] for r in regions.values() for poly in r["polys"] for ring in poly for p in ring]
    ys = [p[1] for r in regions.values() for poly in r["polys"] for ring in poly for p in ring]
    if not xs:
        return None
    if max(xs) - min(xs) > 180 and min(xs) < -150 and max(xs) > 150:
        for r in regions.values():
            for poly in r["polys"]:
                for ring in poly:
                    for p in ring:
                        if p[0] < 0:
                            p[0] = round(p[0] + 360, 3)
        xs = [p[0] for r in regions.values() for poly in r["polys"] for ring in poly for p in ring]
    return [min(xs), min(ys), max(xs), max(ys)]


def _dp(pts, tol):
    """Douglas-Peucker line simplification (standard library), keeps the first and last point."""
    if len(pts) < 3:
        return pts
    keep = [False] * len(pts)
    keep[0] = keep[-1] = True
    stack = [(0, len(pts) - 1)]
    while stack:
        a, b = stack.pop()
        (x1, y1), (x2, y2) = pts[a], pts[b]
        dx, dy = x2 - x1, y2 - y1
        n = (dx * dx + dy * dy) ** 0.5
        best, at = -1.0, -1
        for i in range(a + 1, b):
            x, y = pts[i]
            d = abs(dy * x - dx * y + x2 * y1 - y2 * x1) / n if n else ((x - x1) ** 2 + (y - y1) ** 2) ** 0.5
            if d > best:
                best, at = d, i
        if at > 0 and best > tol:
            keep[at] = True
            stack += [(a, at), (at, b)]
    return [p for p, k in zip(pts, keep) if k]


def shrink(path, budget=BUDGET):
    """Simplifies a map file in place until it fits the budget. Islets too small to see at that detail are dropped,
    but every region keeps its largest piece (at least a triangle), so no region disappears. Returns the new size."""
    size = os.path.getsize(path)
    if size <= budget:
        return size
    data = json.load(open(path, encoding="utf-8"))
    orig = {k: [[[list(p) for p in ring] for ring in poly] for poly in r["polys"]] for k, r in data["regions"].items()}
    def area(ring):
        return abs(sum(x1 * y2 - x2 * y1 for (x1, y1), (x2, y2) in zip(ring, ring[1:]))) / 2

    tol = 0.005
    while size > budget and tol < 1:
        for k, r in data["regions"].items():
            new = []
            biggest = max(orig[k], key=lambda poly: area(poly[0]))
            for poly in orig[k]:
                if poly is not biggest and area(poly[0]) < 4 * tol * tol:
                    continue                          # an islet too small to see at this detail

                rings = []
                for ring in poly:
                    s = _dp(ring, tol)
                    if len(s) < 4:                    # tiny island: keep a triangle of it
                        s = [ring[0], ring[len(ring) // 3], ring[2 * len(ring) // 3], ring[0]]
                    rings.append([[round(x, 3), round(y, 3)] for x, y in s])
                new.append(rings)
            r["polys"] = new
        blob = json.dumps(data, separators=(",", ":"), ensure_ascii=False)
        size = len(blob.encode("utf-8"))
        tol *= 1.6
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(blob)
    return size


def island_feature(ne_all, boxes):
    """The polygons of any Natural Earth country that lie inside the given frames, as one MultiPolygon feature."""
    inside = lambda poly: any(all(w <= x <= e and s <= y <= n for x, y in poly[0]) for w, s, e, n in boxes)  # noqa: E731
    polys = []
    for f in ne_all:
        g = f.get("geometry") or {}
        parts = g.get("coordinates", []) if g.get("type") == "MultiPolygon" else [g.get("coordinates")] if g.get("type") == "Polygon" else []
        polys += [p for p in parts if p and inside(p)]
    return {"type": "Feature", "properties": {}, "geometry": {"type": "MultiPolygon", "coordinates": polys}} if polys else None


def regions_from(features, name_keys, step):
    regions = {}
    for f in features:
        props = f.get("properties") or {}
        nm = next((props.get(k) for k in name_keys if props.get(k)), None) or "?"
        polys = compact(f.get("geometry"), step)
        if polys:
            regions.setdefault(norm(nm), {"name": nm, "polys": []})["polys"] += polys
    return regions


def build(task):
    iso2, iso3, name, gb1, gb0, ne_feat = task
    kind, src, lic, regions = None, "", "", {}
    try:
        if gb1:
            g = get_json(gb1["simplifiedGeometryGeoJSON"])
            regions = regions_from(g.get("features", []), ("shapeName", "shapeISO"), 2)
            kind, lic = "regions", gb1.get("boundaryLicense", "")
            src = f"geoBoundaries gbOpen ADM1 (simplified), {lic or 'open licence'}, https://www.geoboundaries.org"
        if not regions and gb0:
            g = get_json(gb0["simplifiedGeometryGeoJSON"])
            regions = {norm(name): {"name": name, "polys": [p for f in g.get("features", []) for p in compact(f.get("geometry"), 2)]}}
            kind, lic = "whole", gb0.get("boundaryLicense", "")
            src = f"geoBoundaries gbOpen ADM0 (simplified), {lic or 'open licence'}, https://www.geoboundaries.org"
        if not (regions and any(r["polys"] for r in regions.values())) and ne_feat:
            regions = {norm(name): {"name": name, "polys": compact(ne_feat.get("geometry"), 3 if iso2 not in ISLANDS else 1)}}
            kind, lic = "whole", "Public domain"
            src = "Natural Earth 1:10m admin 0 (public domain), https://www.naturalearthdata.com"
    except Exception as e:  # noqa: BLE001  (one country's download fails: listed without a map, reported)
        return iso2, None, f"download failed: {type(e).__name__}: {e}"[:200]
    regions = {k: v for k, v in regions.items() if v["polys"]}
    if not regions:
        return iso2, None, "no boundaries in any source"
    bbox = unwrap(regions)
    data = {"iso2": iso2, "iso3": iso3, "country": name, "bbox": bbox, "kind": kind, "source": src, "regions": regions}
    if kind == "whole":
        data["whole"] = True                   # one area: every record of the country lands on it
    p = os.path.join(OUT, f"{iso2}.json")
    with open(p, "w", encoding="utf-8") as fh:
        json.dump(data, fh, separators=(",", ":"), ensure_ascii=False)
    return iso2, {"iso2": iso2, "iso3": iso3, "country": name, "regions": len(regions) if kind == "regions" else 0,
                  "kind": kind, "bbox": bbox, "bytes": os.path.getsize(p), "licence": lic}, None


def main(argv):
    global OUT
    if "--out" in argv:
        i = argv.index("--out"); OUT = argv[i + 1]; argv = argv[:i] + argv[i + 2:]
    if "--shrink-only" in argv:                 # simplify the maps already in OUT, nothing downloaded
        idx_path = os.path.join(OUT, "index.json")
        index = json.load(open(idx_path, encoding="utf-8"))
        shrink_all(sorted(index["countries"]), index)
        json.dump(index, open(idx_path, "w", encoding="utf-8"), indent=1, ensure_ascii=False)
        return 0
    want = {a.upper() for a in argv}
    os.makedirs(OUT, exist_ok=True)
    iso = json.load(open(ISO_1, encoding="utf-8"))["3166-1"]
    countries = [(r["alpha_2"], r["alpha_3"], r.get("common_name") or r["name"]) for r in iso]
    countries.append(("XK", "XKX", "Kosovo"))
    gb1 = {x["boundaryISO"]: x for x in get_json(GB_API.format(level="ADM1"))}
    gb0 = {x["boundaryISO"]: x for x in get_json(GB_API.format(level="ADM0"))}
    ne = {}
    need_ne = [c for c in countries if c[1] not in gb1 and c[1] not in gb0 and (not want or c[0] in want)]
    if need_ne:
        ne_all = get_json(NE_URL, timeout=600).get("features", [])
        for f in ne_all:
            p = f.get("properties") or {}
            for k in ("ISO_A3", "ADM0_A3", "ISO_A3_EH", "SOV_A3"):
                v = p.get(k)
                if v and v != "-99":
                    ne.setdefault(v, f)
        for i2, i3, _nm in countries:          # islands drawn inside another country's outline
            if i2 in ISLANDS and i3 not in gb1 and i3 not in gb0:
                feat = island_feature(ne_all, ISLANDS[i2])
                if feat:
                    ne[i3] = feat
    tasks = [(i2, i3, nm, gb1.get(i3), gb0.get(i3), ne.get(i3)) for i2, i3, nm in countries if not want or i2 in want]
    idx_path = os.path.join(OUT, "index.json")
    index = json.load(open(idx_path)) if os.path.exists(idx_path) and want else {"countries": {}}
    failed = []
    with ThreadPoolExecutor(max_workers=8) as pool:
        for iso2, info, err in pool.map(build, tasks):
            if info:
                index["countries"][iso2] = info
            else:
                failed.append((iso2, err))
    for i2, i3, nm in countries:             # every country is listed, with its continent, even without a map
        gb = gb1.get(i3) or gb0.get(i3)
        neprops = (ne.get(i3) or {}).get("properties") or {}
        e = index["countries"].setdefault(i2, {"iso2": i2, "iso3": i3, "country": nm, "regions": 0, "kind": None,
                                               "bbox": None, "bytes": 0, "licence": ""})
        e["continent"] = continent_of(gb, i2) or NE_CONT.get(neprops.get("CONTINENT"), neprops.get("CONTINENT") or "")
        if e["continent"] not in CONTINENTS:
            e["continent"] = FIXED_CONT.get(i2, "Oceania" if neprops.get("REGION_UN") == "Oceania" else "Africa")
        e["names"] = sorted({nm.upper(), ascii_name(nm).upper()} - {""})   # the spellings that mean "the whole country"
    index["source"] = ("geoBoundaries gbOpen (ADM1 regions, or the ADM0 outline), https://www.geoboundaries.org, each "
                       "country under its own open licence (listed per country); Natural Earth (public domain) where "
                       "geoBoundaries has nothing")
    index["continents"] = list(CONTINENTS)
    json.dump(index, open(idx_path, "w", encoding="utf-8"), indent=1, ensure_ascii=False)
    have = [c for c in index["countries"].values() if c.get("kind")]
    print(f"{len(index['countries'])} countries listed: {sum(c['kind'] == 'regions' for c in have)} with regions, "
          f"{sum(c['kind'] == 'whole' for c in have)} as one area, {len(index['countries']) - len(have)} without a map")
    for iso2, err in failed:
        print(f"  {iso2}: {err}")
    total = sum(c.get("bytes", 0) for c in have)
    print(f"total {total / 1e6:.1f} MB")
    # names, ISO codes, aliases and label points so the reports' region names land on the right regions
    sys.path.insert(0, HERE)
    import region_aliases
    region_aliases.D = OUT
    all_iso = json.load(open(region_aliases.ISO_FILE, encoding="utf-8"))["3166-2"]
    for iso2, *_ in tasks:
        p = os.path.join(OUT, f"{iso2}.json")
        if os.path.exists(p) and index["countries"].get(iso2, {}).get("kind") == "regions":
            try:
                region_aliases.process(p, all_iso)
            except Exception as e:  # noqa: BLE001
                print(f"  {iso2}: aliases not added ({type(e).__name__}: {e})")
    shrink_all([iso2 for iso2, *_ in tasks], index)
    json.dump(index, open(idx_path, "w", encoding="utf-8"), indent=1, ensure_ascii=False)
    return 0 if not failed else 1


def merge_duplicates(path):
    """Two regions of one map with the same name (geoBoundaries lists some Latvian counties twice) become one region,
    so a report's region name lands on all of it. Returns the merged names."""
    data = json.load(open(path, encoding="utf-8"))
    if data.get("whole"):
        return []
    by, merged = {}, []
    for key, reg in list(data["regions"].items()):
        n = norm(reg.get("name"))
        if n in by:
            keep = data["regions"][by[n]]
            keep["polys"] += reg.get("polys") or []
            for f in ("iso", "aliases"):
                if reg.get(f):
                    keep[f] = sorted(set(keep.get(f) or []) | set(reg[f]))
            del data["regions"][key]
            merged.append(reg.get("name"))
        else:
            by[n] = key
    if merged:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, separators=(",", ":"), ensure_ascii=False)
    return merged


def shrink_all(codes, index):
    """Same-named regions merged; large maps simplified to the budget; the index keeps the new sizes and counts."""
    for iso2 in codes:
        p = os.path.join(OUT, f"{iso2}.json")
        if os.path.exists(p):
            m = merge_duplicates(p)
            if m:
                print(f"  {iso2}: merged regions listed twice: {', '.join(m)}")
                if iso2 in index["countries"]:
                    index["countries"][iso2]["regions"] = len(json.load(open(p, encoding="utf-8"))["regions"])
            before = os.path.getsize(p)
            after = shrink(p)
            if iso2 in index["countries"]:
                index["countries"][iso2]["bytes"] = after
            if after < before:
                print(f"  {iso2}: simplified {before // 1024} KB to {after // 1024} KB")
    have = [c for c in index["countries"].values() if c.get("kind")]
    print(f"total after simplifying {sum(c.get('bytes', 0) for c in have) / 1e6:.1f} MB")


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
