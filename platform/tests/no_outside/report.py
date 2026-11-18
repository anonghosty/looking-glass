"""What the checks tried to reach outside this computer (tests/no_outside/sitecustomize.py wrote it down, and refused
every one): the places Looking Glass reaches by design are listed, anything else fails the run (exit 1).
Usage: python tests/no_outside/report.py <the LG_NO_OUTSIDE file>"""
import collections
import json
import sys

# where Looking Glass goes by design (verified 2026-11-18), each with what it sends; a check reaching one is refused
# like any other, and only listed here
BY_DESIGN = {
    "api.mapbox.com": "map geocoder (place names)",
    "www.cisa.gov": "CISA KEV catalogue (a public file)",
    "api.first.org": "EPSS (CVE numbers)",
    "services.nvd.nist.gov": "NVD (CVE numbers)",
    "raw.githubusercontent.com": "public files: CVE.org records, MISP Galaxy, ATT&CK, report map, feed",
    "api.github.com": "report map (the schema's latest commit)",
    "malpedia.caad.fkie.fraunhofer.de": "Malpedia (malware names)",
    "stat.ripe.net": "RIPEstat (AS numbers)",
    "www.peeringdb.com": "PeeringDB (AS numbers)",
    "www.shadowserver.org": "Shadowserver's report pages and site map",
    "dl.shadowserver.org": "Shadowserver report downloads",
    "transform.shadowserver.org": "Shadowserver report API",
}


def host_of(dest):
    d = str(dest)
    return d.rsplit(":", 1)[0] if d.count(":") == 1 else d


def main(path):
    try:
        rows = [json.loads(x) for x in open(path, encoding="utf-8") if x.strip()]
    except OSError:
        rows = []
    seen = collections.defaultdict(lambda: {"n": 0, "checks": set()})
    for r in rows:
        h = host_of(r.get("dest", "")).lower()
        seen[h]["n"] += 1
        seen[h]["checks"].add(r.get("check", "?"))
    bad = {h: v for h, v in seen.items() if h not in BY_DESIGN}
    ok = {h: v for h, v in seen.items() if h in BY_DESIGN}
    print(f"Outside connections the checks tried: {len(rows)} (all refused, nothing left this computer)")
    for h, v in sorted(ok.items()):
        print(f"  by design, refused: {h} x{v['n']} ({BY_DESIGN[h]}) from {', '.join(sorted(v['checks'])[:6])}")
    for h, v in sorted(bad.items()):
        print(f"  NOT BY DESIGN: {h} x{v['n']} from {', '.join(sorted(v['checks'])[:6])}")
    if bad:
        print("FAILED: a check tried to reach a place Looking Glass has no reason to reach")
        return 1
    print("passed: nothing tried to reach a place outside the list")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else ""))
