"""Management portal: aggregated answers only. Checks every management API answer (both platforms, with and without
filters, and an executive PDF) for IP addresses, host references or host names, and that other roles are refused.

Usage: .venv/bin/python tests/check_management.py      (uses the app in-process; no server needed)
"""
import json
import os
import re
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
os.chdir(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import needs_db  # noqa: E402
needs_db.require()
import app as A  # noqa: E402
from flask import g  # noqa: E402

IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
IPV6 = re.compile(r"\b(?:[0-9a-f]{1,4}:){3,7}[0-9a-f]{1,4}\b", re.I)
bad = 0


def ok(label, cond, info=""):
    global bad
    bad += not cond
    print(f"  {'ok  ' if cond else 'FAIL'} {label}{f'  [{info}]' if info else ''}")


A.store.get(A.replay_now()); A.svc["store"].get(A.replay_now())
known_ips = {e["src_ip"] for e in A.store.get(A.replay_now()).events if e["src_ip"]} | {e["ip"] for e in A.svc["store"].get(A.replay_now()).events}
MGMT = {"user": "lg-selftest-mgmt", "role": "management", "perms": {"management"}, "csrf": None}


def call(path, args, user=MGMT):
    with A.app.test_request_context(path, query_string=args):
        g.user = dict(user)
        ep = A.app.url_map.bind("localhost").match(path)
        r = A.app.view_functions[ep[0]](**ep[1])
        return (r[0], r[1]) if isinstance(r, tuple) else (r, r.status_code)


print("Management portal: aggregated answers only")
for platform, filt in (("comms", {}), ("comms", {"attack": "Botnet C2"}), ("services", {}), ("services", {"family": "Exposed service"})):
    t = time.time()
    r, code = call(f"/api/mgmt/{platform}", filt)
    body = r.get_data(as_text=True)
    leaked = [x for x in set(IPV4.findall(body)) | set(IPV6.findall(body)) if x in known_ips]
    d = json.loads(body)
    ok(f"{platform} {filt or 'everything'}: answers ({time.time() - t:.1f}s, {len(body) // 1024} KB)", code == 200, str(code))
    ok(f"{platform} {filt or 'everything'}: no IP address in the answer", not leaked, ", ".join(leaked[:3]))
    ok(f"{platform} {filt or 'everything'}: no host references", '"ref' not in body and "src_ip" not in body and '"ip"' not in body)
    k = d.get("kpis", {})
    print("       ", {x: k[x] for x in list(k)[:6]})
    if platform == "comms":
        top = (d.get("c2") or {}).get("top") or []
        ok(f"{platform} {filt or 'everything'}: C2 domains as numbers only (Domain 1, 2…), never the host",
           all(re.fullmatch(r"Domain \d+", str(x.get("value"))) and x.get("value") == x.get("label") for x in top), json.dumps(top[:2])[:200])
import io, zipfile  # noqa: E401,E402
for label, args in (("services", {"platform": "services"}), ("communications, filtered", {"platform": "comms", "attack": "Botnet C2"})):
    r, code = call("/api/mgmt/report", args)
    z = zipfile.ZipFile(io.BytesIO(r.get_data())) if code == 200 else None
    names = z.namelist() if z else []
    pdfs = [n for n in names if n.endswith(".pdf")]
    csvs = [n for n in names if n.endswith(".csv")]
    combos = [n for n in csvs if "combinations" in n]
    trend = [n for n in csvs if n.endswith("seven-day-trend.csv")]
    ok(f"executive report ({label}): PDF, combination CSVs and the 7-day trend",
       bool(pdfs) and len(combos) == 2 and len(trend) == 1 and len(csvs) == 3 and z.read(pdfs[0])[:4] == b"%PDF",
       ", ".join(n[-32:] for n in names))
    text = " ".join(z.read(n).decode("utf-8-sig") for n in csvs) if z else ""
    leaked = [x for x in set(IPV4.findall(text)) | set(IPV6.findall(text)) if x in known_ips]
    ok(f"executive report ({label}): no IP address in the CSVs", not leaked, ", ".join(leaked[:3]))
for role, perms in (("analyst", {"view", "unmasked", "export", "malpedia"}), ("researcher", {"definitions", "networks"}), ("external", {"view"})):
    r, code = call("/api/mgmt/comms", {}, {"user": "x", "role": role, "perms": perms, "csrf": None})
    ok(f"{role}: management portal refused", code == 403, str(code))
# role rules, on a temporary copy of the roles file (the real one is never written)
import shutil, tempfile  # noqa: E401,E402
from auth import Roles  # noqa: E402
tmpdir = tempfile.mkdtemp()
shutil.copy(A.AUTH["roles"].path, os.path.join(tmpdir, "roles.json"))
open(os.path.join(tmpdir, ".roles_networks_added"), "w").close()
roles = Roles(os.path.join(tmpdir, "roles.json"))
roles.save({**roles.roles, "analyst": list(roles.roles.get("analyst", [])) + ["management"], "custom-x": ["view", "management"],
            "management": ["management", "view", "unmasked"]})
ok("the management permission cannot be given to another role", "management" not in roles.roles.get("analyst", []) and "management" not in roles.roles.get("custom-x", []))
ok("the management role keeps exactly the portal (no platforms, no unmasked lists)", roles.roles.get("management") == ["management"], str(roles.roles.get("management")))
shutil.rmtree(tmpdir)
print(f"\n{'ALL PASSED' if not bad else f'{bad} FAILED'}")
sys.exit(1 if bad else 0)
