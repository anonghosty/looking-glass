#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""Three things a masked or signed-out viewer must never get (reviewers' findings, production release 2026-11-26), on
made-up records in memory (tests/madeup_days.py; no database, the accounts' files pointed at a temporary folder):

1. An external account's services record detail (/api/svc/detail) of records carrying certificate and TLS fields
   (expiry and issue dates, a browser error naming the host, subject and issuer names, a build date): no address, no
   host name, no e-mail, no date anywhere in the answer but the record's own time; the TLS facts say expired yes/no
   without a date and leave the browser error out.
2. A researcher's Intel gathered answer (/api/intel, an infection seen in two reports by the same devices, and a
   services issue): the internal device sets (_hosts) never leave, and no constituent address or host name is anywhere
   in the JSON (every key and value walked).
3. Signing out: POST /logout ends the session and clears the cookie, lands on the sign-in page, and that page's script
   (auth-card.js, the held copy with LG_HELD_DIR) removes every pinned item (tm.pins, tm.pins:<account>) from the
   browser's storage and nothing else (run in Node with a stand-in storage).
Run: .venv/bin/python tests/check_masked_detail_intel_signout.py"""
import glob
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "tests"))
os.environ.setdefault("LG_QUIET", "1")
os.environ.setdefault("THREATMAP_SCHEDULE", "0")
os.environ["TRUST_PROXY"] = "0"
os.environ.setdefault("LG_STEPUP_TESTS_OFF", "1")

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{str(info)[:400]}]" if info and not cond else ""), flush=True)


def walk(v, path=""):
    """(path, key or value) of every key and string in a JSON answer."""
    if isinstance(v, dict):
        for k, x in v.items():
            yield f"{path}.{k}", str(k)
            yield from walk(x, f"{path}.{k}")
    elif isinstance(v, list):
        for i, x in enumerate(v):
            yield from walk(x, f"{path}[{i}]")
    elif v is not None:
        yield path, str(v)


CONSTITUENT_IP = re.compile(r"(?<![\d.])192\.0\.2\.\d{1,3}(?![\d.])|2001:db8:[0-9a-f:]*", re.I)
EMAIL = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
DATE = re.compile(r"\b(?:19|20)\d{2}-\d{2}-\d{2}\b|\b(?:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)\w* \d{1,2} \d{2}:\d{2}", re.I)
MARK = "lakeside"          # every made-up constituent name: host names, certificate names, organisations

import app as A  # noqa: E402
import auth  # noqa: E402
import madeup_days as M  # noqa: E402

tmp = tempfile.mkdtemp(prefix="lg-check-masked-")
AU = A.AUTH
users, roles, sessions, audit = AU["users"], AU["roles"], AU["sessions"], AU["audit"]
saved = dict(get=users.get, perms=roles.perms, spath=sessions.path, s=dict(sessions.s), add=audit.add)
sessions.path = os.path.join(tmp, "sessions.json")
sessions.s.clear()
audit.add = lambda *a, **k: None
EXT, UA = auth.TEST_PREFIX + "masked-ext", "lg-check-masked"
ROLE = {EXT: "lg-masked-ext"}
users.get = lambda n: {"status": "active", "role": ROLE[n], "changed": 0} if n in ROLE else saved["get"](n)
roles.perms = lambda r: {"view"} if r == "lg-masked-ext" else saved["perms"](r)
H = {"User-Agent": UA}

try:
    # ------------------------------------------------------------------ made-up records
    sink = M.comms_source("event4_sinkhole_http", "Sinkhole HTTP")
    sdns = M.comms_source("event4_sinkhole_dns", "Sinkhole DNS")
    comms = []
    for i in range(8):                       # 8 devices, each in both reports (an across-reports pattern)
        ip = "2001:db8::7" if i == 7 else f"192.0.2.{i + 1}"
        base = {"src_ip": ip, "src_port": 50000 + i, "src_asn": "64500", "src_geo": "GH", "src_region": "GREATER ACCRA",
                "src_city": "ACCRA", "src_hostname": f"pc-{i}.lakeside-tel.example", "dst_ip": "198.51.100.7",
                "dst_port": 80, "dst_asn": "64501", "dst_geo": "US", "infection": "examplebot", "tag": "examplebot",
                "severity": "high", "protocol": "tcp"}
        comms.append((sink, dict(base, http_host="c2-made-up.example", http_url=f"/gate.php?id={i}&from={ip}",
                                 http_agent="ExampleBot/1.0", machine_name="LAKESIDE-PC")))
        comms.append((sdns, dict(base, dst_port=53, protocol="udp", query="c2-made-up.example")))
    tls = M.svc_source("scan_ssl", "SSL/TLS")
    svc = []
    for i in range(8):
        ip = "2001:db8::20" if i == 7 else f"192.0.2.{i + 40}"
        svc.append((tls, {"ip": ip, "port": 443, "protocol": "tcp", "asn": "64500", "geo": "GH", "region": "GREATER ACCRA",
                          "city": "ACCRA", "hostname": f"web{i}.lakeside-tel.example", "severity": "medium",
                          "tag": "ssl-freak;cve-2015-0204", "cert_expired": "Y", "freak_vulnerable": "Y",
                          "cert_expiration_date": "2024-03-01 12:00:00", "cert_issue_date": "2023-03-01 12:00:00",
                          "browser_error": f"certificate is valid for web{i}.lakeside-tel.example, not 192.0.2.{i + 40}",
                          "browser_trusted": "N", "self_signed": "Y", "cert_valid": "N", "sslv3_supported": "Y",
                          "subject_common_name": f"web{i}.lakeside-tel.example",
                          "issuer_common_name": "Example Trust CA (ca.lakeside-tel.example)",
                          "subject_organization_name": "Lakeside Telecom Ltd", "issuer_email_address": "pki@lakeside-tel.example",
                          "build_date": "2023-11-02", "server": f"nginx on web{i}.lakeside-tel.example",
                          "serial_number": "4f9a1c2b3d4e5f6071", "sha256_fingerprint": "ab" * 32}))
    M.install(A, comms=comms, svc=svc)

    # ------------------------------------------------------------------ 1. the services detail, external
    print("1. An external account's services record detail, records with certificate and TLS fields")
    tok = sessions.create(EXT, "127.0.0.1", UA)
    ext = A.app.test_client()
    ext.set_cookie("lg_session", tok)
    r = ext.get("/api/svc/events", query_string={"latest": "1", "limit": "2000"}, headers=H)
    evs = (r.json or {}).get("events") or []
    ok("the external account lists the made-up records (masked ids)", r.status_code == 200 and len(evs) == 8, r.status_code)
    found, tls_ok, n = [], True, 0
    for ev in evs:
        d = ext.get("/api/svc/detail", query_string={"id": ev["id"]}, headers=H)
        if d.status_code != 200:
            found.append(f"detail {d.status_code}")
            continue
        n += 1
        body = d.json
        for p, s in walk(body):
            if p == ".event.extracted_date":           # the record's own time: shown on both platforms by design
                continue
            if MARK in s.lower():
                found.append(f"{p}: a made-up host or organisation name")
            if CONSTITUENT_IP.search(s):
                found.append(f"{p}: an address")
            if EMAIL.search(s) and "<email>" not in s:
                found.append(f"{p}: an e-mail address")
            if DATE.search(s):
                found.append(f"{p}: a date ({DATE.search(s).group(0)})")
        facts = {f["key"]: f["value"] for f in (body.get("event") or {}).get("tls") or []}
        tls_ok = tls_ok and facts.get("expires") in ("Yes", "No") and "browser_error" not in facts and facts.get("self_signed") == "Yes"
    ok(f"all {n} details: no address, host name, e-mail or date in any field", n == 8 and not found, sorted(set(found))[:8])
    ok("…the TLS facts: expired yes/no without its date, self-signed kept, no browser error text", tls_ok)
    sessions.end(tok)

    # ------------------------------------------------------------------ 2. Intel gathered, a researcher
    print("2. A researcher's Intel gathered: no device set, no constituent address or host name")
    from flask import g
    rperms = set(roles.perms("researcher"))

    def call(path):
        with A.app.test_request_context(path, headers=H):
            g.user = {"user": auth.TEST_PREFIX + "masked-research", "role": "researcher", "perms": rperms, "csrf": None}
            ep = A.app.url_map.bind("localhost").match(path.split("?")[0])
            resp = A.app.view_functions[ep[0]](**ep[1])
            code = resp[1] if isinstance(resp, tuple) else resp.status_code
            resp = resp[0] if isinstance(resp, tuple) else resp
            return code, json.loads(resp.get_data(as_text=True))
    ok("the researcher sees no hosts (no 'unmasked')", "unmasked" not in rperms and "definitions" in rperms, sorted(rperms))
    for section, name in (("infections", "examplebot"), ("issues", "FREAK"), ("issues", "Expired certificate")):
        code, body = call(f"/api/intel?section={section}&name={name}")
        bad = []
        for p, s in walk(body):
            if p.endswith("._hosts") or p.endswith("._seen") or s in ("_hosts", "_seen"):
                bad.append(f"{p}: internal key")
            elif CONSTITUENT_IP.search(s):
                bad.append(f"{p}: address {CONSTITUENT_IP.search(s).group(0)}")
            elif MARK in s.lower():
                bad.append(f"{p}: a made-up host name {s!r}")
        ok(f"{section} {name}: answered, nothing of a device in the whole JSON", code == 200 and not bad, (code, bad[:6]))
        if section == "infections":
            cc = (body.get("across") or {}).get("cross_combos") or []
            ok("…the across-reports pattern is there (8 devices in both reports), counted only",
               cc and cc[0].get("devices") == 8 and all("_hosts" not in x for x in cc), cc[:1])
    # the module's own function too (outside a request it counts as a viewer who sees hosts: the set must still go)
    gathered = A.INTEL.gathered("infections", "examplebot")
    ok("intel.gathered() itself drops the device sets", all("_hosts" not in x for x in gathered["across"]["cross_combos"])
       and gathered["across"]["cross_combos"])

    # ------------------------------------------------------------------ 3. signing out clears the pins
    print("3. Signing out: the session ends, and the sign-in page removes the pinned items")
    tok = sessions.create(EXT, "127.0.0.1", UA)
    c = A.app.test_client()
    c.set_cookie("lg_session", tok)
    ok("signed in, the account's details answer", c.get("/api/me", headers=H).status_code == 200)
    r = c.post("/logout", headers=H, data={"csrf_token": sessions.s[auth._h(tok)]["csrf"]})   # as every Log out form sends it
    ok("POST /logout: to the sign-in page", r.status_code == 302 and r.headers.get("Location", "").endswith("/login"), r.headers.get("Location"))
    ok("…the session is ended on the server", auth._h(tok) not in sessions.s)
    ok("…and its cookie cleared", "lg_session=;" in r.headers.get("Set-Cookie", "") or "Max-Age=0" in r.headers.get("Set-Cookie", ""),
       r.headers.get("Set-Cookie"))
    c2 = A.app.test_client()
    c2.set_cookie("lg_session", tok)
    ok("…the old cookie no longer signs in", c2.get("/api/me", headers=H).status_code == 401)
    page = A.app.test_client().get("/login", headers=H)
    ok("the sign-in page loads its script (auth-card.js)", page.status_code == 200 and "js/auth-card.js" in page.get_data(as_text=True))
    held = os.environ.get("LG_HELD_DIR", "")
    js = os.path.join(held, "auth-card.js.new") if held and os.path.exists(os.path.join(held, "auth-card.js.new")) else \
        os.path.join(HERE, "static", "js", "auth-card.js")
    # as the other page checks find it (tests/page_harness.py): LG_NODE, then PATH, then the project's own copy
    node = os.environ.get("LG_NODE") or shutil.which("node") or next(iter(sorted(glob.glob(os.path.expanduser("~/lg-node/*/bin/node")))), None)
    if not node:
        # a maintainer's part (tests/page_harness.py): fails in LG_SUITE=all, one plain line on an installation
        if os.environ.get("LG_SUITE") == "all":
            ok("Node is available for the page check (LG_NODE)", False)
        else:
            print("  (its page-script part runs under Node: a maintainer's check, run by LG_SUITE=all; not part of an installation's checks)")
    else:
        runner = r"""
const fs = require("fs"), vm = require("vm");
const store = {"tm.pins": "[1]", "tm.pins:p-3f9a2c41": "[{\"id\":\"x\"}]", "tm.pins:p-77aa": "[]", "tm.theme": "dark", "lg.tab": "2"};
const ls = new Proxy(store, {get(t, k) {
  if (k === "getItem") return (x) => (x in t ? t[x] : null);
  if (k === "setItem") return (x, v) => { t[x] = String(v); };
  if (k === "removeItem") return (x) => { delete t[x]; };
  return t[k]; }});
const any = () => new Proxy(function () {}, {get: (t, k) => (k === Symbol.iterator ? [][Symbol.iterator] : k === "length" ? 0 : any()),
  apply: () => null});
const doc = {getElementById: () => null, querySelector: () => null, querySelectorAll: () => [], addEventListener() {},
  createElement: () => any(), body: any(), documentElement: any()};
const ctx = {localStorage: ls, location: {pathname: "/login", search: ""}, document: doc, history: {replaceState() {}},
  console, setTimeout, clearTimeout};
ctx.window = ctx;
let err = "";
try { vm.runInNewContext(fs.readFileSync(process.argv[2], "utf8"), ctx); } catch (e) { err = String(e); }
console.log(JSON.stringify({keys: Object.keys(store).sort(), err}));
"""
        rp = os.path.join(tmp, "run.js")
        with open(rp, "w", encoding="utf-8") as fh:
            fh.write(runner)
        out = subprocess.run([node, rp, js], capture_output=True, text=True, timeout=60)
        try:
            res = json.loads(out.stdout.strip().splitlines()[-1])
        except (ValueError, IndexError):
            res = {"keys": None, "err": out.stderr[-300:]}
        ok("the sign-in page's script removes every pinned item (tm.pins and tm.pins:<account>)",
           res["keys"] is not None and not any(k == "tm.pins" or k.startswith("tm.pins:") for k in res["keys"]), res)
        ok("…and keeps the rest of the browser's settings", res["keys"] is not None and {"tm.theme", "lg.tab"} <= set(res["keys"]), res)
finally:
    users.get, roles.perms, audit.add = saved["get"], saved["perms"], saved["add"]
    sessions.path = saved["spath"]
    sessions.s.clear()
    sessions.s.update(saved["s"])
    shutil.rmtree(tmp, ignore_errors=True)

print(f"\n{checks - len(fails)} of {checks} checks passed" + (f"; FAILED: {'; '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
