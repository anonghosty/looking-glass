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

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
