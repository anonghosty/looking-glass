#!/bin/sh
# runs itself with the project's own Python (.venv), from wherever it is called
''''exec "$(dirname -- "$0")/../.venv/bin/python" "$0" "$@" # '''
"""Spreadsheet formula injection: no CSV the platform hands out may hold a cell that a spreadsheet would run as a
formula (= + - @ tab CR LF, or their full-width forms), unless the cell is a plain number or the "-" placeholder.

1. csvsafe.py itself, with planted values such as =HYPERLINK(...).
2. The code: every server CSV export writes through csvsafe, and the two browser downloads (static/js/app.js and
   services.js) carry the same rule; their rule is run here against the same planted values.
3. The real downloads: the services host list, analysis reports of both platforms, both Executive reports; every
   cell of every CSV is checked. Usage: tests/check_csv_safety.py"""
import os as _os, sys as _sys; _sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
import lgauth  # noqa: E402,F401  local API login (automation key)
lgauth.require_server()   # no running service (a fresh clone, CI): skipped, not crashed
import os, sys, io, csv, json, re, zipfile, urllib.request, urllib.parse  # noqa: E402
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)
import csvsafe  # noqa: E402

fails, checks = [], 0


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond: fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info else ""), flush=True)


PLANTED = ['=HYPERLINK("http://example.invalid","x")', "+cmd|' /C calc'!A0", "-2+3+cmd|' /C calc'!A0", "@SUM(1+1)*cmd|' /C calc'!A0",
           "\t=1+1", "\r=1+1", "\n=1+1", "＝1+1", "＋1", "－1", "＠1", "-1+1", "-x", "=", "+", "@"]
HARMLESS = ["", "-", "--", "MikroTik", "RouterOS 6.49", "a=b", "x+1", "-3", "+1.5", "12%", "1,234", "-0.5", "203.0.113.7", "CVE-2024-1234"]
NUMBER = re.compile(r"[+-]?\d+(?:[.,]\d+)*%?|-+")


def risky(s):
    return isinstance(s, str) and s[:1] in csvsafe.TRIGGERS and not NUMBER.fullmatch(s)


print("1. csvsafe.py")
for v in PLANTED:
    ok(f"planted {v[:30]!r} made safe", csvsafe.cell(v) == "'" + v)
for v in HARMLESS:
    ok(f"harmless {v!r} left as it is", csvsafe.cell(v) == v)
for v in (None, 0, -5, 3.25, True):
    ok(f"non-text {v!r} left as it is", csvsafe.cell(v) is v)
buf = io.StringIO(); w = csvsafe.writer(buf); w.writerow(PLANTED + HARMLESS); w.writerows([PLANTED])
back = list(csv.reader(io.StringIO(buf.getvalue(), newline="")))
ok("writer: every planted cell comes back starting with an apostrophe, harmless ones unchanged",
   back[0] == ["'" + v for v in PLANTED] + HARMLESS and back[1] == ["'" + v for v in PLANTED])

print("\n2. The code")
SRC = {}
for root, dirs, files in os.walk(BASE_DIR):
    dirs[:] = [d for d in dirs if d not in (".venv", "tests", "security_testing", "tools", "__pycache__", "data", ".git")]
    for f in files:
        if f.endswith(".py") and f != "csvsafe.py":
            p = os.path.join(root, f)
            SRC[os.path.relpath(p, BASE_DIR)] = open(p, encoding="utf-8").read()
bare = [n for n, t in SRC.items() if re.search(r"(?<![\w.])csv\.writer\(|DictWriter\(", t)]
ok("no server code writes CSV without csvsafe (bare csv.writer / DictWriter)", not bare, ", ".join(bare))
users = sorted(n for n, t in SRC.items() if "csvsafe" in t)
ok("the exports use csvsafe: app.py, management.py, services_api.py", {"app.py", "management.py", "services_api.py"} <= set(users), ", ".join(users))
for js in ("static/js/app.js", "static/js/services.js"):
    t = open(os.path.join(BASE_DIR, js), encoding="utf-8").read()
    m = re.search(r"const q = \(s\) => \{ s = String\(s\); if \(/(.+?)/\.test\(s\) && !/(.+?)/\.test\(s\)\) s = \"'\" \+ s;", t)
    blobs = t.count('type: "text/csv')
    if not m:
        ok(f"{js}: the CSV download has the guard", False, "guard not found")
        continue
    trig, num = re.compile(m.group(1)), re.compile(m.group(2))
    js_q = lambda s: ("'" + s) if trig.search(s) and not num.search(s) else s
    ok(f"{js}: guard present ({blobs} CSV download) and makes every planted value safe",
       blobs == 1 and all(js_q(v) == "'" + v for v in PLANTED))
    ok(f"{js}: the guard leaves harmless values alone", all(js_q(v) == v for v in HARMLESS))


print("\n3. The real downloads")
def raw(path, params):
    with urllib.request.urlopen(f"http://127.0.0.1:5000{path}?{urllib.parse.urlencode(params, doseq=True)}", timeout=900) as r:
        return r.read()


def scan(name, text):
    rows = list(csv.reader(io.StringIO(text.lstrip("﻿"), newline="")))
    bad = [c for r in rows for c in r if risky(c)]
    ok(f"{name}: {sum(len(r) for r in rows):,} cells, none would run as a formula", not bad, "; ".join(repr(c[:30]) for c in bad[:3]))


def scan_zip(label, b):
    z = zipfile.ZipFile(io.BytesIO(b))
    names = [n for n in z.namelist() if n.endswith(".csv")]
    ok(f"{label}: ZIP holds CSV files", bool(names), str(len(names)))
    for n in names:
        scan(f"{label} / {n.rsplit('_', 1)[-1]}", z.read(n).decode("utf-8"))


day = json.loads(raw("/api/clock", []))["replay_day"]
AT = day + "T12:00:00Z"
scan("services host list (hosts.csv)", raw("/api/svc/hosts.csv", [("at", AT)]).decode("utf-8"))
st = json.loads(raw("/api/stats", [("at", AT)]))
if st.get("infection"):
    scan_zip("communications report", raw("/api/insight/report", [("at", AT), ("kind", "infection"), ("value", st["infection"][0]["value"]),
                                                                    ("metric", "hosts"), ("all", "1")]))
for metric in ("vulnerable", "hosts"):
    scan_zip(f"services report ({metric})", raw("/api/svc/report", [("at", AT), ("metric", metric), ("all", "1")]))
for plat in ("comms", "services"):
    scan_zip(f"Executive report ({plat})", raw("/api/mgmt/report", [("platform", plat)]))

print(f"\n{checks - len(fails)} of {checks} CSV safety checks passed" + (f"; FAILED: {fails}" if fails else ""))
sys.exit(1 if fails else 0)
