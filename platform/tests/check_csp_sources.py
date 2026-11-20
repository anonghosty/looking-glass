#!/usr/bin/env python3
"""The content security policy names outside sources by their exact files, never a whole site (review 2026-11-13 for
scripts; 2026-11-15 for fetches: connect-src allowed all of cdn.jsdelivr.net for one map file). The sign-in page's globe
reads its land map from Looking Glass itself, and the file is the one its integrity hash pins. No service needed.
Run: .venv/bin/python tests/check_csp_sources.py"""
import base64, hashlib, os, re, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import security  # noqa: E402

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond: fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info else ""), flush=True)


# hosts that serve anyone's files: allowed only with a path to one file or one folder of a named version
OPEN_CDNS = ("cdn.jsdelivr.net", "unpkg.com", "cdnjs.cloudflare.com", "esm.sh", "raw.githubusercontent.com")
policy = {d.split()[0]: d.split()[1:] for d in (x.strip() for x in security.CSP.split(";")) if d}
print("Outside sources")
for directive in ("script-src", "connect-src", "img-src", "style-src", "font-src"):
    whole = [s for s in policy.get(directive, []) if any(re.fullmatch(rf"https://{re.escape(c)}/?", s) for c in OPEN_CDNS)]
    ok(f"{directive}: no whole public CDN", not whole, " ".join(whole))
ok("connect-src: jsdelivr is gone", not any("jsdelivr" in s for s in policy.get("connect-src", [])))

print("The sign-in globe's land map")
js = open(os.path.join(ROOT, "static", "js", "auth-bg.js"), encoding="utf-8").read()
url = re.search(r'LAND_URL\s*=\s*"([^"]+)"', js)
sri = re.search(r'LAND_SRI\s*=\s*"sha384-([^"]+)"', js)
ok("auth-bg.js reads it from Looking Glass itself", url and url.group(1).startswith("/static/"), url and url.group(1))
path = os.path.join(ROOT, url.group(1).lstrip("/")) if url else ""
ok("the file is there", path and os.path.isfile(path))
if path and os.path.isfile(path) and sri:
    got = base64.b64encode(hashlib.sha384(open(path, "rb").read()).digest()).decode()
    ok("it is the file the integrity hash pins", got == sri.group(1))

print("The sign-in globe marks countries all over the world (the user, 2026-11-20: a global tool, not one country)")
ok("no single fixed country to aim at", "const HUB =" not in js and "ll(7.9, -1.0)" not in js)
ok("three countries marked at a time, picked at random", bool(re.search(r"const HUB_COUNT = 3\b", js)) and "pickHub" in js)
cities = [(float(a), float(b)) for a, b in re.findall(r"\[(-?\d+(?:\.\d+)?), (-?\d+(?:\.\d+)?)\]", js.split("const SOURCES", 1)[1].split(".map(", 1)[0])]
regions = {"the Americas": any(lon < -30 for _lat, lon in cities), "Europe": any(lat > 35 and -30 < lon < 45 for lat, lon in cities),
           "Africa": any(-35 < lat < 35 and -20 < lon < 52 for lat, lon in cities), "Asia": any(lat > 0 and lon > 60 for lat, lon in cities),
           "Oceania": any(lat < -10 and lon > 110 for lat, lon in cities)}
ok("the marked cities come from every inhabited continent", len(cities) >= 15 and all(regions.values()),
   f"{len(cities)} cities; missing: {[k for k, v in regions.items() if not v]}")
ok("…never the installation's own country (the page says nothing about the installation before sign-in)",
   not re.search(r"COUNTRY|data-country|dataset\.country", js))

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
