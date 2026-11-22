#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""Every download is logged, and every page downloads the same way (r89). No database needed.

1. The server (static analysis of every platform module, route by route):
   * every Flask route that answers with a file (Content-Disposition attachment, send_file as_attachment, download_name),
     itself or through a helper it calls, writes an audit entry on its way (audit.add), or is a path data_access.py logs
     as an export (data_exported) on every download, whatever DATA_ACCESS_LOG says;
   * the audit event of every download is in the Audit portal's "Data access and exports" tab;
   * every attachment's file name is quoted; a route listed under the heavy-request limits has all its paths listed.
2. The pages (the held copies in LG_HELD_DIR first, then static/ and templates/):
   * no <a ... download>, no plain link (href, location, window.open, LGLoader.go) to a download route, no file name read
     from Content-Disposition and no createObjectURL of its own outside loader.js: every download goes through
     LGLoader.download, and a file the page builds itself through LGLoader.saveBlob;
   * LGLoader.download fetches, makes a blob, reads filename* (RFC 6266) before filename, tries once more when Looking
     Glass could not be reached, and words its errors plainly; the loader's link handling leaves download routes alone;
   * every page whose scripts download loads loader.js.
3. At run time (a small Flask app with data_access.py's real logger): one audit entry per download of the services host
   list and of the drill-down lists, with DATA_ACCESS_LOG on and off. The routes that need the database (combination
   reports, the review's report) are counted in tests/check_combos.py and tests/check_combo_review.py.
Run: .venv/bin/python tests/check_downloads.py   (LG_HELD_DIR=<folder> to check held page files)"""
import ast
import os
import re
import sys

PLAT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PLAT)
os.environ.setdefault("LG_QUIET", "1")

import audit_portal  # noqa: E402
import data_access  # noqa: E402

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info and not cond else ""))


# routes that answer with a file but write no audit entry of their own: each with its reason. Keep it short; only
# genuine non-downloads belong here (an inline preview is not an attachment, so it never needs listing).
ALLOW_ROUTES = {}
# page scripts with a createObjectURL that is not a download
ALLOW_OBJECT_URL = {"logo-tool.js": "a preview of the image the administrator picks, nothing is saved"}

ATTACH = re.compile(r"""attachment|as_attachment\s*=\s*True|download_name\s*=""")
AUDIT = re.compile(r"""audit(?:"\]|'\])?\.add\(""")
EVENT = re.compile(r"""audit(?:"\]|'\])?\.add\(\s*["']([a-z_]+)["']""")


def route_paths(fn):
    out = []
    for d in fn.decorator_list:
        if isinstance(d, ast.Call) and isinstance(d.func, ast.Attribute) and d.func.attr == "route" and d.args \
                and isinstance(d.args[0], ast.Constant) and isinstance(d.args[0].value, str):
            out.append(d.args[0].value)
    return out


def called_names(fn):
    return {n.func.id if isinstance(n.func, ast.Name) else n.func.attr
            for n in ast.walk(fn) if isinstance(n, ast.Call) and isinstance(n.func, (ast.Name, ast.Attribute))}


print("The server: every route that answers with a file writes an audit entry")
routes, attach_bad, quoting_bad = [], [], []
for name in sorted(os.listdir(PLAT)):
    if not name.endswith(".py"):
        continue
    src = open(os.path.join(PLAT, name), encoding="utf-8").read()
    for m in re.finditer(r"attachment; filename=(?!\\?\"|\{)", src):
        quoting_bad.append(f"{name}:{src.count(chr(10), 0, m.start()) + 1}")
    try:
        tree = ast.parse(src)
    except SyntaxError as exc:
        ok(f"{name} parses", False, str(exc))
        continue
    funcs = [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
    seg = {id(f): ast.get_source_segment(src, f) or "" for f in funcs}
    helpers_attach = {f.name for f in funcs if not route_paths(f) and ATTACH.search(seg[id(f)])}
    # a helper's audit entry counts only for a helper that sends the file itself, or one whose job is the logging
    # (audit_portal's logged_export): a helper that only MAKES the file (combos.package) does not log its download
    helpers_audit = {f.name: EVENT.findall(seg[id(f)]) for f in funcs if not route_paths(f) and AUDIT.search(seg[id(f)])
                     and (ATTACH.search(seg[id(f)]) or re.search(r"log|audit", f.name))}
    for f in funcs:
        paths = route_paths(f)
        if not paths:
            continue
        body, calls = seg[id(f)], called_names(f)
        if not (ATTACH.search(body) or calls & helpers_attach):
            continue
        events = EVENT.findall(body) + [e for h in calls & set(helpers_audit) for e in helpers_audit[h]]
        audited = bool(AUDIT.search(body) or calls & set(helpers_audit))
        by_data_access = [p for p in paths if data_access.SENSITIVE.get(p, ("",))[0] == "data_exported"]
        if by_data_access:
            events.append("data_exported")
        routes.append({"module": name, "func": f.name, "paths": paths, "audited": audited or bool(by_data_access), "events": events})
ok("the attachment routes were found (at least the ones known in r89)", len(routes) >= 12, str(len(routes)))
missing = [f"{r['module']}:{r['func']} {r['paths'][0]}" for r in routes if not r["audited"] and r["paths"][0] not in ALLOW_ROUTES]
ok("every one writes an audit entry on its way (or is logged by data_access.py as an export)", not missing, "; ".join(missing))
ok("the allow-list names only routes that exist", all(any(p in r["paths"] for r in routes) for p in ALLOW_ROUTES), str(ALLOW_ROUTES))
not_data = sorted({f"{e} ({r['func']})" for r in routes for e in r["events"] if audit_portal.TAB_OF.get(e) != "data"})
ok("…and its event is in the Audit portal's \"Data access and exports\" tab, with a label",
   not not_data and all(e in audit_portal.LABEL for r in routes for e in r["events"]), "; ".join(not_data))
ok("every attachment's file name is quoted (Content-Disposition)", not quoting_bad, ", ".join(quoting_bad))

print("…downloads stay logged when the views are not (DATA_ACCESS_LOG=0)")
da = open(os.path.join(PLAT, "data_access.py"), encoding="utf-8").read()
ok("data_access.py: a download (data_exported) is written before the DATA_ACCESS_LOG switch is asked",
   re.search(r'if event != "data_exported" and not enabled\(\)', da) is not None and "if not enabled() or" not in da)
ok("the services host list and both drill-down CSVs are logged as exports",
   data_access.SENSITIVE.get("/api/svc/hosts.csv", ("",))[0] == "data_exported"
   and set(data_access.DOWNLOADS) == {"/api/insight/drill", "/api/svc/drill"})

print("…the heavy-request limits know every path of a limited route")
app_src = open(os.path.join(PLAT, "app.py"), encoding="utf-8").read()
heavy = set()
for n in ast.walk(ast.parse(app_src)):
    if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "install" \
            and isinstance(n.func.value, ast.Name) and n.func.value.id == "request_limits":
        heavy = {e.value for e in n.args[1].elts if isinstance(e, ast.Constant)}
ok("the heavy-request list was read from app.py", len(heavy) > 5, str(len(heavy)))
partial = [r["paths"] for r in routes if len(r["paths"]) > 1 and set(r["paths"]) & heavy and not set(r["paths"]) <= heavy]
ok("a report route limited under one path is limited under all of them (/report and /report.pdf)", not partial, str(partial))
ok("…the two report.pdf paths among them", {"/api/insight/report.pdf", "/api/svc/report.pdf"} <= heavy)

print("\nThe pages: every download goes through LGLoader.download")
HELD = os.environ.get("LG_HELD_DIR", "")


def page_files(sub, ext):
    """{name: text}: the held copy (<name>.new in LG_HELD_DIR) when there is one, else the live file."""
    out = {}
    live = os.path.join(PLAT, sub)
    for n in sorted(os.listdir(live)):
        if n.endswith(ext):
            held = os.path.join(HELD, n + ".new") if HELD else ""
            out[n] = open(held if held and os.path.exists(held) else os.path.join(live, n), encoding="utf-8").read()
    return out


JS, TPL = page_files(os.path.join("static", "js"), ".js"), page_files("templates", ".html")
ok("the page files were read", "loader.js" in JS and len(JS) > 20 and len(TPL) > 10, f"{len(JS)} scripts, {len(TPL)} templates")
# a download route: what answers with a file (the API's files and reports, an advisory's file, a review's report)
DL = r"""(/api/[^"'`\s;]*(\.csv|\.zip|\.pdf|\.json|/export|/download|/request|/report)\b|/advisory/[^"'`\s;]*/file/|/review/[^"'`\s;]*/report(?!\?as=pdf))"""
NAV = re.compile(r"""((?<!dataset)\.href\s*=(?!=)|location\.assign\(|location\.replace\(|window\.open\(|LGLoader\.go\()[^;\n]*""" + DL)
bad = []
for n, t in JS.items():
    if n == "loader.js":
        continue
    for i, line in enumerate(t.splitlines(), 1):
        if NAV.search(line):
            bad.append(f"{n}:{i} a link to a download route")
        if re.search(r"""setAttribute\(\s*["']download["']|\.download\s*=(?!=)""", line):
            bad.append(f"{n}:{i} a download attribute")
        if "createObjectURL" in line and n not in ALLOW_OBJECT_URL:
            bad.append(f"{n}:{i} its own createObjectURL")
        if re.search(r"filename\*?=|filename=\"", line) or "Content-Disposition" in line:
            bad.append(f"{n}:{i} reads the file name itself")
for n, t in TPL.items():
    for i, line in enumerate(t.splitlines(), 1):
        if re.search(r"<a\b[^>]*\sdownload(\s|>|=)", line):
            bad.append(f"{n}:{i} <a ... download>")
        if re.search(r"""href=["'][^"']*""" + DL, line):
            bad.append(f"{n}:{i} a plain link to a download route")
ok("no page starts a download on its own (download attribute, plain link, createObjectURL, its own file-name parsing)",
   not bad, "; ".join(bad[:12]) + (f" (+{len(bad) - 12})" if len(bad) > 12 else ""))
ok("the createObjectURL allow-list names scripts that exist and still need it",
   all(n in JS and "createObjectURL" in JS[n] for n in ALLOW_OBJECT_URL))

L = JS["loader.js"]
ok("LGLoader.download fetches (one helper, fetchOnceMore) and makes a blob",
   "async download(" in L and "fetchOnceMore(" in L and "await fetch(url, opts)" in L and "await r.blob()" in L)
ok("…reads filename* (RFC 6266, UTF-8) before filename=\"…\"",
   "fileName(cd)" in L and "decodeURIComponent" in L and L.find("filename\\*") != -1 and L.find("filename\\*") < L.find('filename\\s*=\\s*"'))
ok("…tries once more on its own when Looking Glass could not be reached", "attempt < 2" in L and "unreachable(e)" in L)
ok("…words its errors plainly (never the browser's own text)",
   "The download did not finish: Looking Glass could not be reached (it may be restarting). Try again." in L
   and "The download did not finish. Try again." in L and not re.search(r"\be\.message\b", L[L.find("async download("):L.find("isDownload(")]))
ok("…offers POST with headers (the CSRF token), the response headers and the file (the Audit portal's SHA-256)",
   "method: method ||" in L and "headers: r.headers" in L and "blob }" in L)
ok("…one place saves a file (saveBlob), used by download() too", L.count("createObjectURL") == 1 and "saveBlob(blob, file)" in L)
ok("the loader's link handling leaves download routes alone (an advisory's report file never shows \"Opening …\")",
   "isDownload(u.pathname)" in L and re.search(r"report\|preview\|export\|download\|file", L) is not None)

print("…the scripts that download use the helper, and their pages load loader.js")
USERS = {n for n, t in JS.items() if n != "loader.js" and re.search(r"LGLoader\.(download|saveBlob|fetchForFile)\(|LGPdf\.download\(", t)}
for n in ("advisory.js", "findings.js", "audit.js", "combos.js", "intelligence.js", "beacon-unknown.js", "management.js", "pdf.js",
          "app.js", "services.js"):
    ok(f"{n} downloads through the shared helper", n in USERS)
ok("pdf.js: LGPdf.download is a thin wrapper over LGLoader.download", "window.LGLoader.download(" in JS["pdf.js"] and "fetch(" not in
   JS["pdf.js"].split("window.LGPdf")[0])
no_loader = []
for tn, t in TPL.items():
    used = [n for n in USERS if re.search(r"js/" + re.escape(n) + r"['\"?]", t)]
    if used and not re.search(r"js/loader\.js['\"?]", t):
        no_loader.append(f"{tn} ({', '.join(used)})")
ok("every page whose scripts download loads loader.js", not no_loader, "; ".join(no_loader))
ok("the Combinations page's download is a button, not a link", 'id="cbDownload" type="button"' in TPL.get("combinations.html", "")
   or ('<button' in TPL.get("combinations.html", "") and 'id="cbDownload"' in TPL.get("combinations.html", "")
       and not re.search(r'<a[^>]*id="cbDownload"', TPL.get("combinations.html", ""))))

print("\nAt run time: one audit entry per download (data_access.py's real logger)")
from flask import Flask, g, request  # noqa: E402

entries = []
app = Flask(__name__)


@app.before_request
def _who():
    g.user = {"user": request.headers.get("X-User", "")}


for p in ("/api/svc/hosts.csv", "/api/svc/drill", "/api/insight/drill"):
    app.add_url_rule(p, p, (lambda: ("ip\n", 200, {"Content-Disposition": 'attachment; filename="x.csv"'})))
data_access.register(app, lambda event, **kw: entries.append({"event": event, **kw}),
                     lambda: (getattr(g, "user", None) or {}).get("user", ""), lambda ip: "R1")
c = app.test_client()
DOWNLOAD_CALLS = (("/api/svc/hosts.csv", {"service": "Accessible RDP"}),
                  ("/api/svc/drill", {"metric": "hosts", "issue": "CVE-2024-1", "all": "1", "download": "1"}),
                  ("/api/insight/drill", {"kind": "infection", "value": "mirai", "metric": "hosts", "all": "1", "download": "1"}))
for switch in ("1", "0"):
    os.environ["DATA_ACCESS_LOG"] = switch
    for path, q in DOWNLOAD_CALLS:
        for _ in range(2):
            n = len(entries)
            c.get(path, query_string=q, headers={"X-User": "daniel"})
            ok(f"DATA_ACCESS_LOG={switch}: {path} downloaded: exactly one export entry", len(entries) == n + 1
               and entries[-1]["event"] == "data_exported" and entries[-1]["user"] == "daniel", str(entries[n:]))
    n = len(entries)
    c.get("/api/svc/drill", query_string={"metric": "hosts", "issue": "CVE-2024-2"}, headers={"X-User": "daniel"})
    ok(f"DATA_ACCESS_LOG={switch}: a view (no download) is " + ("logged as a view" if switch == "1" else "not logged"),
       (len(entries) == n + 1 and entries[-1]["event"] == "data_viewed") if switch == "1" else len(entries) == n, str(entries[n:]))
os.environ.pop("DATA_ACCESS_LOG", None)

print(f"\n{checks - len(fails)}/{checks} download checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
