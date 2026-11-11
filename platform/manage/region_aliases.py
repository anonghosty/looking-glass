"""Make the 54 African region maps (static/data/adm1/<ISO2>.json) match the region names found in the reports.

The reports' "region" field comes from IP geolocation, which names first-level subdivisions after ISO 3166-2
(often in the local language: "Alger", "Al Qāhirah") or in English ("Algiers", "Cairo Governorate"), and sometimes
uses newer subdivisions than the map (Algeria's 58 provinces vs 48 on the map, Kavango East / West in Namibia).
The map files come from geoBoundaries, whose names are mostly English and whose ISO codes are not always right.

For every region on every map this script adds:
  name     display name (repaired: truncated or garbled names are replaced by the ISO name)
  iso      the ISO 3166-2 codes it covers
  aliases  normalised names that count as this region: the map name, the ISO name, sub-units whose ISO parent is
           this region (e.g. Burkina Faso's provinces), newer subdivisions carved out of it (EXTRA below), and
           common English / local alternatives (EXTRA)
  label    [lon, lat] of a point well inside the region's largest part, for its label

Needs the iso-codes package (/usr/share/iso-codes/json/iso_3166-2.json). Re-run after fetch_africa_boundaries.py.
Usage: python3 manage/region_aliases.py [ISO2 ...]   prints, per country, ISO subdivisions that matched no region.
"""
import difflib
import json
import os
import re
import sys
import unicodedata

D = os.path.join(os.path.dirname(__file__), "..", "static", "data", "adm1")
ISO_FILE = "/usr/share/iso-codes/json/iso_3166-2.json"
# the same list as normRegion() in the browser (static/js/services.js, static/js/settings.js)
SUFFIXES = (" REGION", " PROVINCE", " STATE", " GOVERNORATE", " COUNTY", " DISTRICT", " PREFECTURE", " DEPARTMENT", " WILAYA", " ATOLL")

# alternatives the ISO list does not have: newer subdivisions -> the map region they were carved out of,
# and English / local names used by geolocation databases.  {ISO2: {map region name (any spelling): [aliases]}}
EXTRA = {
    "DZ": {  # 2019/2021: ten southern provinces split off (ISO has 58, the map 48)
        "Adrar": ["Timimoun", "Bordj Badji Mokhtar"], "Tamanrasset": ["In Salah", "In Guezzam", "Ain Salah", "Ain Guezzam", "Tamanghasset"],
        "Ouargla": ["Touggourt"], "Illizi": ["Djanet"], "El Oued": ["El M'Ghair", "El Meghaier"], "Ghardaia": ["El Meniaa", "El Menia"],
        "Biskra": ["Ouled Djellal"], "Béchar": ["Beni Abbes", "Béni Abbès"], "Algiers": ["Alger", "Al Jazair"], "Oran": ["Wahran"],
    },
    # English map names <-> ISO (local) names
    "EG": {"North Sinai": ["Shamal Sina'", "Shamal Sina"], "South Sinai": ["Janub Sina'", "Janub Sina"], "Red Sea": ["Al Bahr al Ahmar"],
           "New Valley": ["Al Wadi al Jadid"], "Alexandria": ["Al Iskandariyah"], "Ismailia": ["Al Isma'iliyah"], "Suez": ["As Suways"],
           "Gharbiyya": ["Al Gharbiyah", "Gharbia"], "Faiyum": ["Al Fayyum", "Fayoum"], "Beni Suef": ["Bani Suwayf"], "Minya Governate": ["Al Minya", "Minya"],
           "Sohag": ["Suhaj"], "Qena": ["Qina"], "Luxor Governate": ["Al Uqsur", "Luxor"], "Giza": ["Al Jizah"], "Monufia": ["Al Minufiyah", "Menofia"],
           "Beheira": ["Al Buhayrah"], "Cairo": ["Al Qahirah"], "Qalyubia": ["Al Qalyubiyah"], "Dakahlia": ["Ad Daqahliyah"], "Damietta": ["Dumyat"],
           "Kafr el-Sheikh": ["Kafr ash Shaykh"], "Port Said": ["Bur Sa'id", "Bur Said"], "Al Sharqia": ["Ash Sharqiyah", "Sharqia"], "Aswan": ["Aswan"],
           "Matrouh": ["Matruh"], "Asyut": ["Asyut"]},
    "ER": {"Anseba": ["Ansaba"], "Debub": ["Al Janubi", "Southern"], "Maekel": ["Al Awsat", "Central"], "Northen Red Sea": ["Shimali al Bahri al Ahmar", "Northern Red Sea"],
           "Southern Red Sea": ["Janubi al Bahri al Ahmar"], "Gash-Barka": ["Gash Barka"]},
    "LY": {"Ghadamis": ["Nalut"], "Ash Shati'": ["Wadi ash Shati'", "Wadi ash Shati"], "Tajura' wa an Nawahi al Arba": ["Tarabulus", "Tripoli"],
           "Al Qubbah": ["Darnah", "Derna"], "Mizdah": ["Al Jabal al Gharbi", "Nafusa Mountains"], "Ajdabiya": ["Al Wahat"], "Benghazi": ["Banghazi"]},
    "SO": {"Middle Shebelle": ["Shabeellaha Dhexe"], "Lower Shebelle": ["Shabeellaha Hoose"], "Middle Juba": ["Jubbada Dhexe"], "Lower Juba": ["Jubbada Hoose"],
           "Banadir": ["Mogadishu"]},
    "BJ": {"Kouffo": ["Couffo"], "Atlantique": ["Atlantique"], "Oueme": ["Ouémé"]},
    "CD": {"Kinshasa": ["Kinshasa City"], "Upper Uele": ["Haut-Uele", "Haut-Uélé"], "Lower Uele": ["Bas-Uele", "Bas-Uélé"], "North Kivu": ["Nord-Kivu"],
           "South Kivu": ["Sud-Kivu"], "Central Kasai": ["Kasai-Central", "Kasaï Central"]},
    "CF": {"Sangha-Mbaéré": ["Sangha"], "Mambéré-Kadéï": ["Haute-Sangha / Mambéré-Kadéï", "Haute-Sangha"], "Nana-Grébizi": ["Gribingui"], "Kémo": ["Kémo-Gribingui"]},
    "ET": {"Addis Ababa": ["Adis Abeba"], "SNNPR": ["Southern Nations, Nationalities and Peoples", "Southern Nations", "Sidama", "Southwest Ethiopia Peoples",
           "South West Ethiopia Peoples", "Central Ethiopia", "South Ethiopia"], "Hareri": ["Harari People", "Harari"], "Tigray": ["Tigrai"],
           "Beneshangul Gumu": ["Benishangul-Gumuz", "Benshangul-Gumaz"], "Oromia": ["Oromiya"], "Somali": ["Sumale"], "Gambela Peoples": ["Gambela", "Gambella"]},
    "LS": {"Butha-Buthe": ["Botha-Bothe"]},
    "ML": {"Tombouctou": ["Taoudénit", "Taoudenni", "Timbuktu"], "Gao": ["Ménaka", "Menaka"], "Koulikouro": ["Koulikoro"], "Segou": ["Ségou"]},
    "MR": {"Nouakchott Sud": ["Nouakchott Ouest", "Nouakchott Nord", "Nouakchott"]},
    "SC": {"Outer Islands": ["Outer Islands"], "La Digue and Inner Islands": ["La Digue", "Inner Islands"], "La Rivière Anglaise": ["English River", "La Riviere"],
           "Roche Caiman": ["Ile Perseverance I", "Ile Perseverance II", "Perseverance"]},
    "SL": {"Northern": ["North Western", "North West"], "Western Area": ["Western Area Urban", "Western Area Rural", "Freetown"]},
    "TD": {"N'Djamena": ["Ville de Ndjamena", "Ndjamena", "N'Djamena"]},
    "TN": {"El Kef": ["Le Kef", "Kef"]},
    "TZ": {"Pwani": ["Coast"], "Zanzibar South & Central": ["Zanzibar South", "Zanzibar Central/South"], "North Pemba": ["Pemba North"],
           "South Pemba": ["Pemba South"], "Zanzibar Urban/West": ["Zanzibar West", "Zanzibar Urban"], "Zanzibar North": ["Zanzibar North"],
           "Mbeya": ["Songwe"], "Dar es Salaam": ["Dar-es-Salaam"]},
    "BW": {"North-East": ["Francistown"], "South-East": ["Gaborone", "Lobatse"], "Southern": ["Jwaneng"], "Central": ["Selibe Phikwe", "Sowa Town", "Sowa"]},
    "GM": {"Mansakonko": ["Lower River"], "Janjanbureh": ["Central River"], "Kuntaur": [], "Kerewan": ["North Bank"], "Basse": ["Upper River"],
           "Brikama": ["Western"], "Kanifing": ["Kanifing"]},
    "ST": {"São Tomé": ["Água Grande", "Cantagalo", "Caué", "Lembá", "Lobata", "Mé-Zóchi"], "Príncipe": ["Pagué", "Autonomous Region of Principe"]},
    # older provinces above the map's regions: the region of the provincial capital
    "MG": {"Analamanga": ["Antananarivo"], "Atsinanana": ["Toamasina"], "Matsiatra Ambony": ["Fianarantsoa", "Haute Matsiatra"], "Boeny": ["Mahajanga"],
           "Atsimo-Andrefana": ["Toliara", "Toliary"], "Diana": ["Antsiranana"]},
    "GW": {"Bafatá": ["Leste"], "Cacheu": ["Norte"], "Tombali": ["Sul"]},
    "NA": {"Kavango": ["Kavango East", "Kavango West"], "Caprivi": ["Zambezi"], "Karas": ["//Karas", "Kharas"]},
    "MA": {"Casablanca-Settat": ["Grand Casablanca", "Chaouia-Ouardigha", "Doukkala-Abda"], "Rabat-Salé-Kénitra": ["Rabat-Sale-Zemmour-Zaer", "Gharb-Chrarda-Beni Hssen"],
           "Fès-Meknès": ["Fes-Boulemane", "Meknes-Tafilalet", "Taza-Al Hoceima-Taounate"], "Marrakesh-Safi": ["Marrakech-Tensift-Al Haouz", "Marrakech-Safi"],
           "Tangier-Tetouan-Al Hoceima": ["Tanger-Tetouan", "Tanger-Tetouan-Al Hoceima"], "Souss-Massa": ["Souss-Massa-Draa"],
           "Béni Mellal-Khénifra": ["Tadla-Azilal"], "Oriental": ["L'Oriental"]},
    "CM": {"Far North": ["Extreme-Nord", "Extreme North"], "North": ["Nord"], "North-West": ["Nord-Ouest"], "South": ["Sud"], "South-West": ["Sud-Ouest"],
           "East": ["Est"], "West": ["Ouest"], "Littoral": ["Littoral"], "Centre": ["Centre"]},
    "NE": {"Tahoua/Agadez": ["Tahoua", "Agadez"], "Zinder/Diffa": ["Zinder", "Diffa"], "Dossa": ["Dosso"], "Tillaberi": ["Tillabéri"]},
    "CI": {"District Autonome D'Abidjan": ["Abidjan"], "District Autonome De Yamoussoukro": ["Yamoussoukro"]},
    "SN": {"Dakar": ["Dakar"]},
    "KE": {"Nairobi": ["Nairobi City", "Nairobi Province"]},
    "NG": {"Abuja Federal Capital Territory": ["Federal Capital Territory", "FCT", "Abuja"]},
    "ZA": {"KwaZulu-Natal": ["KwaZulu Natal", "Natal"], "Gauteng": ["Gauteng"]},
    "SD": {"Khartoum": ["Al Khartum"]},
    "SS": {"Central Equatoria": ["Central Equatoria"]},
    "UG": {"Central Region": ["Central", "Kampala"], "Eastern Region": ["Eastern"], "Northern Region": ["Northern"], "Western Region": ["Western"]},
    "GH": {"Bono Region": ["Brong-Ahafo"], "Northern Region": ["Northern"], "Volta Region": ["Volta"], "Western Region": ["Western"]},
}


# display names repaired (truncated, misspelt or garbled in the boundary files)
RENAME = {
    "SC": {"Outer Isla": "Outer Islands", "La Digue a": "La Digue and Inner Islands", "La RiviÃ¨re": "La Rivière Anglaise",
           "La Rivière": "La Rivière Anglaise", "Roche CaÃ¯m": "Roche Caïman", "Roche Caiman": "Roche Caïman"},
    "ER": {"Northen Red Sea Region": "Northern Red Sea Region"},
    "BJ": {"Atlanique": "Atlantique", "Oueme": "Ouémé"},
    "ML": {"Koulikouro": "Koulikoro", "Segou": "Ségou"},
    "NE": {"Dossa": "Dosso", "Tillaberi": "Tillabéri"},
    "EG": {"Minya Governate": "Minya Governorate", "Luxor Governate": "Luxor Governorate"},
    "ET": {"SNNPR": "Southern Nations, Nationalities and Peoples (SNNPR)", "Hareri": "Harari"},
    "DZ": {"Ghardaia": "Ghardaïa", "Bejaia": "Béjaïa"},
}
INVISIBLE = re.compile(r"[​-‏‪-‮⁠﻿]")   # zero-width, direction marks, word joiner, BOM


def norm(name):
    """Same as normRegion() in the browser: no accents, upper case, common suffixes removed."""
    n = unicodedata.normalize("NFKD", str(name)).encode("ascii", "ignore").decode().upper().strip()
    for s in SUFFIXES:
        if n.endswith(s):
            n = n[: -len(s)].strip()
    return n


def flat(name):
    return re.sub(r"[^A-Z]", "", norm(name))


def unmangle(s):
    """'La RiviÃ¨re' (UTF-8 read as Latin-1) -> 'La Rivière'."""
    if "Ã" in s or "Â" in s:
        try:
            return s.encode("latin-1").decode("utf-8")
        except (UnicodeEncodeError, UnicodeDecodeError):
            return s
    return s


# ---- a label point well inside a polygon (simplified "pole of inaccessibility": grid search, then refine)
def _inside(x, y, rings):
    c = False
    for ring in rings:
        n = len(ring)
        for i in range(n):
            x1, y1 = ring[i]; x2, y2 = ring[i - 1]
            if (y1 > y) != (y2 > y) and x < (x2 - x1) * (y - y1) / (y2 - y1) + x1:
                c = not c
    return c


def _edge_dist(x, y, rings, kx):
    best = float("inf")
    for ring in rings:
        n = len(ring)
        for i in range(n):
            ax, ay = ring[i - 1]; bx, by = ring[i]
            ax, bx, px = ax * kx, bx * kx, x * kx
            dx, dy = bx - ax, by - ay
            t = 0 if dx == dy == 0 else max(0, min(1, ((px - ax) * dx + (y - ay) * dy) / (dx * dx + dy * dy)))
            d = (px - ax - t * dx) ** 2 + (y - ay - t * dy) ** 2
            best = min(best, d)
    return best ** 0.5


def label_point(polys):
    def area(ring):
        return abs(sum(ring[i - 1][0] * ring[i][1] - ring[i][0] * ring[i - 1][1] for i in range(len(ring)))) / 2
    rings = max(polys, key=lambda p: area(p[0]))
    outer = rings[0]
    xs = [p[0] for p in outer]; ys = [p[1] for p in outer]
    x0, x1, y0, y1 = min(xs), max(xs), min(ys), max(ys)
    kx = __import__("math").cos(__import__("math").radians((y0 + y1) / 2))
    best, bd = ((x0 + x1) / 2, (y0 + y1) / 2), -1
    span_x, span_y = x1 - x0, y1 - y0
    cx, cy = best
    for step in range(3):
        n = 24
        sx, sy = span_x / n, span_y / n
        for i in range(n + 1):
            for j in range(n + 1):
                x, y = cx - span_x / 2 + i * sx, cy - span_y / 2 + j * sy
                if _inside(x, y, rings):
                    d = _edge_dist(x, y, rings, kx)
                    if d > bd:
                        best, bd = (x, y), d
        cx, cy = best
        span_x, span_y = span_x / 4, span_y / 4
    return [round(best[0], 3), round(best[1], 3)]


def iso_entries(cc, all_iso):
    return [r for r in all_iso if r["code"].split("-")[0] == cc]


def match_iso(name, cands):
    """The ISO entry for a map region name (exact, split 'A/B', truncated prefix, close spelling)."""
    f = flat(name)
    by_flat = {}
    for r in cands:
        by_flat.setdefault(flat(r["name"]), []).append(r)
    out = list(by_flat.get(f, []))
    if not out and "/" in name:
        for part in name.split("/"):
            out += by_flat.get(flat(part), [])
    if not out and len(f) >= 6:   # truncated names (Seychelles: 'Anse Aux P')
        pre = [r for k, rs in by_flat.items() if k.startswith(f) for r in rs]
        if len(pre) == 1:
            out = pre
    if not out:
        close = difflib.get_close_matches(f, list(by_flat), n=1, cutoff=0.84)
        if close:
            out = by_flat[close[0]]
    return out


def process(path, all_iso):
    d = json.load(open(path, encoding="utf-8"))
    cc = d["iso2"]
    iso = iso_entries(cc, all_iso)
    top = [r for r in iso if not r.get("parent")]
    by_code = {r["code"]: r for r in iso}
    extra = {flat(k): v for k, v in EXTRA.get(cc, {}).items()}
    code_to_key = {}
    renames = RENAME.get(cc, {})
    for key, reg in d["regions"].items():
        if "label" not in reg:
            reg["label"] = label_point(reg["polys"])
        nm = INVISIBLE.sub("", reg["name"]).strip()
        nm = renames.get(nm, nm)
        nm = unmangle(nm)
        nm = renames.get(nm, nm)
        if cc == "SC" and flat(nm) == "GRANDANSE":   # two districts of this name: one on Mahé, one on Praslin (north of 4.5° S)
            nm = "Grand Anse Praslin" if reg["label"][1] > -4.5 else "Grand Anse Mahé"
        hits = match_iso(nm, top) or match_iso(nm, iso)
        # repair truncated / garbled names with the ISO name
        if hits and len(hits) == 1 and (len(nm) <= 10 and flat(hits[0]["name"]).startswith(flat(nm)) and flat(hits[0]["name"]) != flat(nm)):
            nm = hits[0]["name"]
        reg["name"] = nm
        al = {norm(nm), norm(reg.get("name", ""))}
        for part in nm.split("/"):
            al.add(norm(part))
        for h in hits:
            al.add(norm(h["name"])); code_to_key[h["code"]] = key
            for alt in re.split(r"\s*[/(),]\s*", h["name"]):
                if len(alt) > 2:
                    al.add(norm(alt))
        for a in extra.get(flat(nm), []) + extra.get(flat(key), []):
            al.add(norm(a))
        reg["iso"] = sorted({h["code"] for h in hits})
        reg["aliases"] = sorted(a for a in al if a and a != key)
    # sub-units (ISO entries with a parent) count as their parent's region
    for r in iso:
        p = r.get("parent")
        if not p:
            continue
        pk = code_to_key.get(f"{cc}-{p}") or code_to_key.get(p)
        if pk:
            reg = d["regions"][pk]
            a = norm(r["name"])
            if a != pk and a not in reg["aliases"]:
                reg["aliases"].append(a)
            code_to_key.setdefault(r["code"], pk)
    # report: ISO top-level subdivisions that no map region covers (by code or alias)
    covered = set()
    for key, reg in d["regions"].items():
        covered |= {key, *reg["aliases"]}
    missing = [r["name"] for r in top if r["code"] not in code_to_key and norm(r["name"]) not in covered]
    # the same alias must not point to two regions
    seen, clash = {}, []
    for key, reg in d["regions"].items():
        for a in [key, *reg["aliases"]]:
            if a in seen and seen[a] != key:
                clash.append(a)
            seen.setdefault(a, key)
    for key, reg in d["regions"].items():   # drop clashing aliases (keep each region's own key)
        reg["aliases"] = sorted(a for a in reg["aliases"] if a not in clash)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(d, fh, separators=(",", ":"), ensure_ascii=False)
    return cc, len(d["regions"]), len(top), missing, sorted(set(clash))


if __name__ == "__main__":
    all_iso = json.load(open(ISO_FILE, encoding="utf-8"))["3166-2"]
    want = {a.upper() for a in sys.argv[1:]}
    for f in sorted(os.listdir(D)):
        if not f.endswith(".json") or f == "index.json" or (want and f[:2] not in want):
            continue
        cc, n, ntop, missing, clash = process(os.path.join(D, f), all_iso)
        print(f"{cc}: {n} regions on the map, {ntop} ISO top-level; not covered: {', '.join(missing) or '-'}"
              + (f"; ambiguous aliases dropped: {', '.join(clash)}" if clash else ""))
