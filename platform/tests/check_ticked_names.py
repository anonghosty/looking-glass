#!/bin/sh
# runs itself with the project's own Python (.venv), from wherever it is called
''''exec "$(dirname -- "$0")/../.venv/bin/python" "$0" "$@" # '''
"""The infections and CVEs/issues an analyst ticks on the Combinations page go into the report (combo_review.py,
2026-11-14), end to end, in-process, on throwaway files: the search's "every category for these devices" carries each
name with its devices; a name these devices do not carry is refused; management sees the ticked names in words and
counts, never an address; "Add the analyst's views" works with names alone; the advisor's report lists the names and
their devices; the advisory of one organisation lists only the names its own devices carry.
Usage: tests/check_ticked_names.py"""
import csv, io, json, os, re, sys, tempfile, time, zipfile
from urllib.parse import quote
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
os.environ.setdefault("THREATMAP_SCHEDULE", "0")
import needs_db  # noqa: E402
needs_db.require()
import app as A  # noqa: E402
from flask import g  # noqa: E402

fails, checks = [], 0
IP_RX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
CVE_RX = re.compile(r"CVE-\d{4}-\d{4,}", re.I)
ANALYST, MGMT, ADVISOR = {"view", "unmasked", "export", "malpedia"}, {"management"}, {"advisory"}
MG = dict(role="management", user="lg-check-management")
ADV = dict(role="advisor", user="lg-check-advisor")


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond: fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info else ""), flush=True)


def call(path, perms, method="GET", body=None, role="analyst", user="lg-check-analyst", raw=False):
    with A.app.test_request_context(path, method=method, json=body):
        g.user = {"user": user, "role": role, "perms": set(perms), "csrf": None, "automation": True}
        ep = A.app.url_map.bind("localhost").match(path.split("?")[0], method=method)
        r = A.app.view_functions[ep[0]](**ep[1])
        code = r[1] if isinstance(r, tuple) else r.status_code
        r = r[0] if isinstance(r, tuple) else r
        return (code, r.get_data()) if raw and code == 200 else (code, json.loads(r.get_data(as_text=True) or "{}"))


tmp = tempfile.mkdtemp(prefix="lg-ticked-")
book, F = A.COMBOS, A.FINDINGS
saved = (book.path, book.data, book.loaded, F.path, F.mtime, F.data, F.people_of)
book.path, book.data, book.loaded = os.path.join(tmp, "codes.json"), {}, True
F.path, F.mtime, F.data = os.path.join(tmp, "findings.json"), None, {"seq": 0, "items": {}}
F.people_of = lambda kind: [{"user": f"lg-check-{kind}", "name": f"Check {kind}", "role": kind}]
real_store = book.review_paths["store"]; book.review_paths["store"] = os.path.join(tmp, "review_searches")
real_exports = book.export_paths["dir"]; book.export_paths["dir"] = os.path.join(tmp, "combo_exports")
real_adv, real_org = A.ADVISORIES.dir, A.ORG.path
A.ADVISORIES.dir, A.ORG.path = os.path.join(tmp, "advisories"), os.path.join(tmp, "organisation.json")
audit = A.AUTH["audit"]; real_add = audit.add; audited = []
A.ATTACK.offline = None
audit.add = lambda *a, **k: audited.append((a[0] if a else "", k.get("detail") or (a[2] if len(a) > 2 else "")))


def search(code, user="lg-check-analyst"):
    st, j = call("/api/combos/search", ANALYST, "POST", {"code": code}, user=user)
    jid = j.get("id")
    for _ in range(600):
        st, s = call(f"/api/combos/search/{jid}", ANALYST, user=user)
        if s.get("state") != "running":
            return jid, s
        time.sleep(0.2)
    return jid, s


def candidates():
    """researchers' codes whose devices carry other infections or CVEs/issues: a few reports, the first combinations"""
    for rep in ("scan_mikrotik_service", "scan_http_vulnerable", "scan_ssl_poodle", "scan_rdp", "scan_telnet", "scan_ssh"):
        try:
            gg = A.SVC_INTEL.gathered(rep) or {}
        except Exception:                                   # noqa: BLE001 (a report this installation has no data for)
            continue
        for c in (gg.get("combinations") or [])[:2]:
            yield c["code"]


try:
    print("An analyst searches a researcher's code and finds other infections or CVEs/issues on its devices")
    jid = s = None
    for code in candidates():
        jid, s = search(code)
        pv = s.get("preview") or {}
        if s.get("state") == "done" and (pv.get("infections") or pv.get("issues")):
            break
        jid = None
    if not jid:
        print("SKIP: no researcher's code here whose devices carry another infection or CVE/issue")
        sys.exit(0)
    pv = s["preview"]
    inf, iss = pv.get("infections") or [], pv.get("issues") or []
    print(f"  ({code}: {len(inf)} infection(s), {len(iss)} CVE/issue(s), {len(pv.get('cross') or [])} pattern(s))")
    ok("each name comes with exactly its devices, each with its address, for the analyst",
       all(x.get("devices") and len(x["devices"]) == x["hosts"] and IP_RX.match(x["devices"][0]["ip"]) for x in inf + iss)
       and not any("ips" in x for x in inf + iss), f"{[(x['name'], x['hosts'], len(x.get('devices') or [])) for x in (inf + iss)[:4]]}")
    t_inf, t_iss = [x["name"] for x in inf[:1]], [x["name"] for x in iss[:2]]
    body = {"codes": [], "infections": t_inf, "issues": t_iss, "title": "Ticked names", "to": "lg-check-management"}
    st, d = call(f"/api/combos/search/{jid}/review", ANALYST, "POST", dict(body, issues=t_iss + ["CVE-1999-0001-not-here"]))
    ok("a name these devices do not carry is refused", st == 400 and "Not on these devices" in d.get("error", ""), d.get("error", ""))
    st, d = call(f"/api/combos/search/{jid}/review", ANALYST, "POST", dict(body, infections=[], issues=[]))
    ok("nothing ticked is refused when there is something to tick", st == 400 if pv.get("cross") else True, d.get("error", "") or f"HTTP {st}")
    st, d = call(f"/api/combos/search/{jid}/review", ANALYST, "POST", body)
    ok("the analyst sends only names (no across-report pattern) to the manager named", st == 200 and d.get("finding") == "#1", d.get("error", ""))
    ok("…and it is logged with the counts", any("infection(s)" in str(x[1]) and "CVE/issue(s)" in str(x[1]) for x in audited), f"{audited[-1:]}")

    print("The manager sees the names in words and counts")
    st, fl = call("/api/findings", MGMT, **MG)
    f = (fl.get("findings") or [{}])[0]
    an = (f.get("review") or {}).get("analyst") or {}
    want = {x["name"]: x["hosts"] for x in inf + iss}
    ok("the ticked infections and CVEs/issues, each with its device count",
       [x["name"] for x in an.get("infections") or []] == t_inf and [x["name"] for x in an.get("issues") or []] == t_iss
       and all(x["hosts"] == want[x["name"]] for x in (an.get("infections") or []) + (an.get("issues") or [])), json.dumps(an)[:200])
    ok("…with no address anywhere, and no devices list", not IP_RX.search(json.dumps(fl))
       and not any(k in (f.get("review") or {}) for k in ("sent", "sent_infections", "sent_issues")))
    st, d = call("/api/findings/1/review-decision", MGMT, "POST", {"choice": "both", "text": "Add the CVEs to the report.", "to": "lg-check-advisor"}, **MG)
    ok("\"Add the analyst's views\" works with names alone", st == 200 and d["finding"]["review"]["decision"] == "both", d.get("error", ""))

    print("The advisor's report carries the names and their devices")
    st, z = call("/review/1/report", ADVISOR, raw=True, **ADV)
    ok("the advisor gets the report", st == 200, str(z)[:150] if st != 200 else "")
    if st == 200:
        zf = zipfile.ZipFile(io.BytesIO(z))
        oc = next((n for n in zf.namelist() if n.endswith("_other_categories.csv")), None)
        ok("…with the other categories file", bool(oc), ", ".join(zf.namelist()))
        rows = list(csv.reader(io.StringIO(zf.read(oc).decode("utf-8-sig")))) if oc else []
        names_iss = sorted(r[2] for r in rows[1:] if r[0] == "cve / issue")
        names_inf = sorted(r[2] for r in rows[1:] if r[0] == "infection (calling sinkholes)")
        ok("…exactly the ticked CVEs/issues and infections", names_iss == sorted(t_iss) and names_inf == sorted(t_inf), f"{names_iss} · {names_inf}")
        dv_iss = [r for r in rows[1:] if r[0] == "cve / issue device"]
        dv_inf = [r for r in rows[1:] if r[0] == "infection device"]
        n_iss = sum(want[n] for n in t_iss); n_inf = sum(want[n] for n in t_inf)
        ok("…each with exactly its devices and their addresses", len(dv_iss) == n_iss and len(dv_inf) == n_inf
           and all(IP_RX.match(r[2]) or ":" in r[2].split(" ")[0] for r in dv_iss + dv_inf), f"{len(dv_iss)}/{n_iss} · {len(dv_inf)}/{n_inf}")
        ok("…and nothing that was not ticked", not any(r[0] in ("cve / issue", "infection (calling sinkholes)") and r[2] not in t_iss + t_inf for r in rows[1:]))

    print("Each organisation's advisory names only what its own devices carry")
    st, a = call("/api/advisory/1", ADVISOR, **ADV)
    nets = a.get("networks") or []
    ok("the advisor opens the decided finding", st == 200 and nets, a.get("error", f"{len(nets)} networks"))
    by_net = {}
    for x in [y for y in inf if y["name"] in t_inf] + [y for y in iss if y["name"] in t_iss]:
        for dv in x["devices"]:
            by_net.setdefault(dv.get("network") or "", set()).add(x["name"])
    hit = miss = 0
    for n in nets[:6]:
        st, a2 = call(f"/api/advisory/1/net?network={quote(n['network'])}", ADVISOR, **ADV)
        aff = (a2.get("advisory") or {}).get("affected") or {}
        listed = {c.upper() for c in aff.get("cves") or []} | set(aff.get("issues") or []) | set(aff.get("categories") or [])
        mine = by_net.get(n["network"], set())
        norm = lambda nm: nm.upper() if CVE_RX.fullmatch(nm) else nm  # noqa: E731
        if mine:
            hit += 1
            ok(f"…{n['network']}: lists the ticked names its devices carry", all(norm(nm) in listed for nm in mine), f"{sorted(mine)} in {sorted(listed)[:8]}")
        else:
            miss += 1
    ok("…(at least one organisation carries a ticked name)", hit >= 1, f"{hit} with, {miss} without")

    print("The analyst's view only: the report is about the devices behind what was ticked, alone")
    A2 = "lg-check-analyst2"
    jid2, s2 = search(code, user=A2)
    pv2 = s2.get("preview") or {}
    small = sorted((pv2.get("issues") or []) + (pv2.get("infections") or []), key=lambda x: x["hosts"])
    pick = small[0]
    kind = "issues" if pick in (pv2.get("issues") or []) else "infections"
    st, d = call(f"/api/combos/search/{jid2}/review", ANALYST, "POST", {"codes": [], kind: [pick["name"]], "title": "Only these", "to": "lg-check-management"}, user=A2)
    fid2 = (d.get("finding") or "#").lstrip("#")
    ok("a second analyst sends one name", st == 200 and fid2, d.get("error", ""))
    st, d = call(f"/api/findings/{fid2}/review-decision", MGMT, "POST", {"choice": "analyst", "text": "Only the critical ones.", "to": "lg-check-advisor"}, **MG)
    ok("management chooses the analyst's view only", st == 200 and d["finding"]["review"]["decision"] == "analyst", d.get("error", ""))
    st, z = call(f"/review/{fid2}/report", ADVISOR, raw=True, **ADV)
    ok("the advisor gets its report", st == 200, str(z)[:150] if st != 200 else "")
    if st == 200:
        zf = zipfile.ZipFile(io.BytesIO(z))
        dv = next((n for n in zf.namelist() if n.endswith("_devices.csv")), None)
        rows = list(csv.reader(io.StringIO(zf.read(dv).decode("utf-8-sig")))) if dv else []
        ipcol = next((i for i, h in enumerate(rows[0]) if h.lower() in ("ip", "ip address", "host", "device")), None) if rows else None
        ips = {r[ipcol].split(" ")[0] for r in rows[1:] if ipcol is not None and len(r) > ipcol}
        want_ips = {dv_["ip"] for dv_ in pick["devices"]}
        ok("…its devices are exactly the ticked name's devices, not the whole combination", ips and ips == want_ips and len(ips) < s2["summary"]["devices"],
           f"{len(ips)} in the report · {len(want_ips)} ticked · {s2['summary']['devices']} in the combination · column {rows[0][ipcol] if rows and ipcol is not None else '?'}")
    st, a = call(f"/api/advisory/{fid2}", ADVISOR, **ADV)
    nets_ticked = {dv_.get("network") for dv_ in pick["devices"]}
    ok("…and the advisory's organisations are only theirs", st == 200 and {n["network"] for n in a.get("networks") or []} <= nets_ticked | {"Unknown"},
       f"{len(a.get('networks') or [])} networks · ticked on {len(nets_ticked)}")
    st, fl = call("/api/findings", MGMT, **MG)
    ok("…management still sees no address", not IP_RX.search(json.dumps(fl)))
finally:
    audit.add = real_add
    book.review_paths["store"] = real_store
    book.export_paths["dir"] = real_exports
    A.ADVISORIES.dir, A.ORG.path = real_adv, real_org
    book.path, book.data, book.loaded, F.path, F.mtime, F.data, F.people_of = saved
    import shutil; shutil.rmtree(tmp, ignore_errors=True)
print(f"\n{checks - len(fails)} of {checks} ticked-name checks passed" + (f"; FAILED: {fails}" if fails else ""))
sys.exit(1 if fails else 0)
