"""Download first-level administrative regions (provinces / regions / states) for all 54 African countries from
geoBoundaries (gbOpen ADM1, simplified, CC BY 4.0, https://www.geoboundaries.org) and store compact copies in
static/data/adm1/<ISO2>.json plus an index (static/data/adm1/index.json).

The services platform draws its regions heatmap from the country chosen in Settings.
Usage: .venv/bin/python manage/fetch_africa_boundaries.py [ISO2 ...]   (default: all 54)
"""
import json
import os
import sys
import urllib.request
from concurrent.futures import ThreadPoolExecutor

AFRICA = [  # ISO2, ISO3, name
    ("DZ", "DZA", "Algeria"), ("AO", "AGO", "Angola"), ("BJ", "BEN", "Benin"), ("BW", "BWA", "Botswana"), ("BF", "BFA", "Burkina Faso"),
    ("BI", "BDI", "Burundi"), ("CV", "CPV", "Cabo Verde"), ("CM", "CMR", "Cameroon"), ("CF", "CAF", "Central African Republic"),
    ("TD", "TCD", "Chad"), ("KM", "COM", "Comoros"), ("CG", "COG", "Congo"), ("CD", "COD", "Democratic Republic of the Congo"),
    ("CI", "CIV", "Côte d'Ivoire"), ("DJ", "DJI", "Djibouti"), ("EG", "EGY", "Egypt"), ("GQ", "GNQ", "Equatorial Guinea"),
    ("ER", "ERI", "Eritrea"), ("SZ", "SWZ", "Eswatini"), ("ET", "ETH", "Ethiopia"), ("GA", "GAB", "Gabon"), ("GM", "GMB", "Gambia"),
    ("GH", "GHA", "Ghana"), ("GN", "GIN", "Guinea"), ("GW", "GNB", "Guinea-Bissau"), ("KE", "KEN", "Kenya"), ("LS", "LSO", "Lesotho"),
    ("LR", "LBR", "Liberia"), ("LY", "LBY", "Libya"), ("MG", "MDG", "Madagascar"), ("MW", "MWI", "Malawi"), ("ML", "MLI", "Mali"),
    ("MR", "MRT", "Mauritania"), ("MU", "MUS", "Mauritius"), ("MA", "MAR", "Morocco"), ("MZ", "MOZ", "Mozambique"), ("NA", "NAM", "Namibia"),
    ("NE", "NER", "Niger"), ("NG", "NGA", "Nigeria"), ("RW", "RWA", "Rwanda"), ("ST", "STP", "São Tomé and Príncipe"),
    ("SN", "SEN", "Senegal"), ("SC", "SYC", "Seychelles"), ("SL", "SLE", "Sierra Leone"), ("SO", "SOM", "Somalia"),
    ("ZA", "ZAF", "South Africa"), ("SS", "SSD", "South Sudan"), ("SD", "SDN", "Sudan"), ("TZ", "TZA", "Tanzania"), ("TG", "TGO", "Togo"),
    ("TN", "TUN", "Tunisia"), ("UG", "UGA", "Uganda"), ("ZM", "ZMB", "Zambia"), ("ZW", "ZWE", "Zimbabwe"),
]
OUT = os.path.join(os.path.dirname(__file__), "..", "static", "data", "adm1")
URL = "https://github.com/wmgeolab/geoBoundaries/raw/main/releaseData/gbOpen/{iso3}/ADM1/geoBoundaries-{iso3}-ADM1_simplified.geojson"
SUFFIXES = (" REGION", " PROVINCE", " STATE", " GOVERNORATE", " COUNTY", " DISTRICT", " PREFECTURE", " DEPARTMENT", " WILAYA", " ATOLL")


def norm(name):
    import unicodedata
    n = unicodedata.normalize("NFKD", name).encode("ascii", "ignore").decode().upper().strip()
    for s in SUFFIXES:
        if n.endswith(s):
            n = n[: -len(s)].strip()
    return n


def compact(geom, step):
    polys = geom["coordinates"] if geom["type"] == "MultiPolygon" else [geom["coordinates"]]
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


def fetch(entry):
    iso2, iso3, name = entry
    try:
        with urllib.request.urlopen(URL.format(iso3=iso3), timeout=120) as r:
            g = json.load(r)
    except Exception as e:
        return iso2, None, f"download failed: {e}"
    regions, xs, ys = {}, [], []
    for f in g.get("features", []):
        nm = f["properties"].get("shapeName") or f["properties"].get("shapeISO") or "?"
        polys = compact(f["geometry"], 2)
        if not polys:
            continue
        key = norm(nm)
        regions.setdefault(key, {"name": nm, "polys": []})["polys"] += polys
        for poly in polys:
            for ring in poly:
                xs += [p[0] for p in ring]; ys += [p[1] for p in ring]
    if not regions:
        return iso2, None, "no regions in file"
    data = {"iso2": iso2, "iso3": iso3, "country": name, "bbox": [min(xs), min(ys), max(xs), max(ys)],
            "source": "geoBoundaries gbOpen ADM1 (simplified), CC BY 4.0, https://www.geoboundaries.org", "regions": regions}
    with open(os.path.join(OUT, f"{iso2}.json"), "w", encoding="utf-8") as fh:
        json.dump(data, fh, separators=(",", ":"), ensure_ascii=False)
    return iso2, {"iso2": iso2, "iso3": iso3, "country": name, "regions": len(regions), "bbox": data["bbox"],
                  "bytes": os.path.getsize(os.path.join(OUT, f"{iso2}.json"))}, None


if __name__ == "__main__":
    os.makedirs(OUT, exist_ok=True)
    want = {a.upper() for a in sys.argv[1:]}
    todo = [e for e in AFRICA if not want or e[0] in want]
    idx_path = os.path.join(OUT, "index.json")
    index = json.load(open(idx_path)) if os.path.exists(idx_path) else {"countries": {}}
    with ThreadPoolExecutor(max_workers=6) as pool:
        for iso2, info, err in pool.map(fetch, todo):
            if info:
                index["countries"][iso2] = info
                print(f"  {iso2} {info['country']:34s} {info['regions']:3d} regions {info['bytes'] // 1024:6d} KB")
            else:
                print(f"  {iso2} FAILED: {err}")
    for iso2, iso3, name in AFRICA:      # every country is listed, even if its boundaries could not be fetched
        index["countries"].setdefault(iso2, {"iso2": iso2, "iso3": iso3, "country": name, "regions": 0, "bbox": None, "bytes": 0})
    index["source"] = "geoBoundaries gbOpen ADM1 (simplified), CC BY 4.0, https://www.geoboundaries.org"
    json.dump(index, open(idx_path, "w", encoding="utf-8"), indent=1, ensure_ascii=False)
    print(f"{sum(1 for c in index['countries'].values() if c['regions'])} of {len(AFRICA)} countries have region boundaries")
    # names, ISO codes, aliases and label points so the reports' region names land on the right regions
    sys.path.insert(0, os.path.dirname(__file__))
    import region_aliases
    all_iso = json.load(open(region_aliases.ISO_FILE, encoding="utf-8"))["3166-2"]
    for iso2, _, _ in todo:
        p = os.path.join(OUT, f"{iso2}.json")
        if os.path.exists(p):
            cc, n, ntop, missing, _ = region_aliases.process(p, all_iso)
            print(f"  {cc}: aliases added; ISO subdivisions not covered: {', '.join(missing) or '-'}")
