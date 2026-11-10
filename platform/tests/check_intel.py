#!/bin/sh
# runs itself with the project's own Python (.venv), from wherever it is called
''''exec "$(dirname -- "$0")/../.venv/bin/python" "$0" "$@" # '''
"""Intel gathered (intel.py): researchers and admins get the indicators and leads, other roles are refused, and no
answer holds a constituent address (a source address of the communications or a services host).
Usage: tests/check_intel.py      (the app in-process; nothing is written)"""
import json, os, re, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
os.environ.setdefault("THREATMAP_SCHEDULE", "0")
import app as A  # noqa: E402
from flask import g  # noqa: E402

fails, checks = [], 0


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond: fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info else ""), flush=True)


def call(path, perms):
    with A.app.test_request_context(path):
        g.user = {"user": "lg-selftest-intel", "role": "x", "perms": set(perms), "csrf": None}
        ep = A.app.url_map.bind("localhost").match(path.split("?")[0])
        r = A.app.view_functions[ep[0]](**ep[1])
        code = r[1] if isinstance(r, tuple) else r.status_code
        r = r[0] if isinstance(r, tuple) else r
        return code, r.get_data(as_text=True)


now = A.replay_now()
day, sday = A.store.get(now), A.svc["store"].get(now)
if not day.events:
    print("SKIPPED: no events loaded for the replay day yet"); sys.exit(77)
RESEARCHER, EXTERNAL, ANALYST = {"definitions", "networks"}, {"view"}, {"view", "unmasked", "export", "malpedia"}
hosts = {e["src_ip"] for e in day.events if e.get("src_ip")} | {e["ip"] for e in sday.events if e.get("ip")}
ADDR = re.compile(r"(?<![\w.:])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])|(?<![\w:])(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}(?![\w:])")
# the busiest name whose reports carry indicators (a plain Sinkhole record has the name only)
_with = [(e.get("infection") or "").lower() for e in day.events if e.get("infection") and (e.get("http_host") or (e.get("extras") or {}).get("query"))]
top_inf = max(set(_with), key=_with.count) if _with else ""
issue = next((i for e in sday.events for i in (e.get("issues") or [])), "")

print("Intel gathered")
code, body = call("/api/intel/leads", RESEARCHER)
d = json.loads(body)
ok(f"researcher: leads answer ({len(d.get('leads', []))} leads over {', '.join(d.get('days', []))})", code == 200 and "leads" in d)
ok("leads are matches between places (two names, two reports or both platforms)",
   all(len(x["names"]) > 1 or len(x["reports"]) > 1 for x in d.get("leads", [])))
answers = [body]
for sec, n in (("infections", top_inf), ("issues", issue)):
    code, b = call(f"/api/intel?section={sec}&name={n}", RESEARCHER)
    g_ = json.loads(b); answers.append(b)
    kinds = sum(len(r["indicators"]) for r in g_.get("reports", []))
    ok(f"researcher: {sec} '{n}' has indicators ({len(g_.get('reports', []))} reports, {kinds} kinds)", code == 200 and kinds > 0)
leak = sorted({x for b in answers for x in ADDR.findall(b) if x in hosts})
ok("no constituent address in any answer", not leak, f"{len(leak)} found")
for label, perms in (("external", EXTERNAL), ("analyst (no definitions)", ANALYST)):
    code, _ = call("/api/intel/leads", perms)
    ok(f"{label}: refused", code == 403, f"HTTP {code}")
print(f"\n{checks - len(fails)} of {checks} intel checks passed" + (f"; FAILED: {fails}" if fails else ""))
sys.exit(1 if fails else 0)
