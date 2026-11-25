#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""Connectors (connectors.py, connector_net.py, connector_payload.py; the user 2026-11-24), in-process, with the
platforms faked: no network, no database, nothing written outside a temporary folder.

- the way out: https only; never this computer, link-local or metadata addresses (also when a name leads there);
  the certificate always checked (no option to switch it off); no redirect followed
- the key: stored encrypted (not readable in the file, not readable under another secret), never in any answer, never
  in the audit log; a key in .env for a target wins; no secret in .env: nothing can be stored
- test before save: a failed test gives no pass; the pass is for exactly the tested values (another TLP, address, key
  or person: refused); there is no way to save without it
- administrators only; the form token; the fresh check every time for saving, turning on, scope, TLP, key, delete;
  testing needs none
- what a target receives: only the constituency's networks and ranges; a device outside the ticked scope is not sent
- turning on: refused with nothing ticked, or when the checks fail
- the payload: no raw Shadowserver fields, no time to act; MISP: to_ids off, unpublished, "Your organisation only"; STIX:
  every reference inside the bundle, the TLP marking on every object that carries one
Run: .venv/bin/python tests/check_connectors.py"""
import json
import os
import re
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.environ.setdefault("LG_QUIET", "1")
os.environ.setdefault("THREATMAP_SCHEDULE", "0")
os.environ["TRUST_PROXY"] = "0"
os.environ.pop("LG_STEPUP_TESTS_OFF", None)
os.environ["ACCESS_MODE"] = "local"
SECRET = "ab" * 32
os.environ["CONNECTOR_KEY_SECRET"] = SECRET

from werkzeug.security import generate_password_hash  # noqa: E402

import app as A  # noqa: E402
import auth  # noqa: E402
import connector_net as net  # noqa: E402
import connector_payload as cp  # noqa: E402
import connectors as C  # noqa: E402

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{str(info)[:500]}]" if info != "" and not cond else ""), flush=True)


tmp = tempfile.mkdtemp(prefix="lg-connectors-")
AU = A.AUTH
users, sessions, throttle, audit = AU["users"], AU["sessions"], AU["throttle"], AU["audit"]
AUDIT = []
audit.add = lambda ev, **k: AUDIT.append((ev, k))
sessions.path, throttle.path = os.path.join(tmp, "s.json"), os.path.join(tmp, "t.json")
sessions.s.clear()
throttle.fail.clear()
CN = A.FEATURES["connectors"]
targets, vault = CN["targets"], CN["vault"]
targets.path, vault.path = os.path.join(tmp, "connectors.json"), os.path.join(tmp, "connector_keys.enc")
CN["paths"]["log"] = os.path.join(tmp, "connectors_log.jsonl")          # never the real data/ log
ST = A.FEATURES["stepup"]
ST["store"].path = os.path.join(tmp, "passkeys.json")
import base64  # noqa: E402
SEC = {n: base64.b32encode(os.urandom(20)).decode().rstrip("=") for n in ("lgcn-admin", "lgcn-analyst", "lgcn-auditor")}
with open(os.path.join(tmp, "users.json"), "w") as fh:
    json.dump({"users": {n: {"hash": generate_password_hash("x" * 20), "role": n.split("-")[1], "status": "active",
                             "totp": SEC[n], "changed": 0, "created": 1, "pw_set_at": int(time.time()),
                             "profile": {"full_name": f"Made-up {n.split('-')[1].title()}"}} for n in SEC}}, fh)
users.path, users.mtime = os.path.join(tmp, "users.json"), None
UA = "lg-check-connectors"
STEP = {n: int(time.time() // 30) - 1 for n in SEC}


def code(n):
    now_c = int(time.time() // 30)
    if STEP[n] > now_c + 1:
        with users.lock:
            users._load()
            users.data["users"][n]["totp_last"] = None
            users.save()
        STEP[n] = now_c - 1
    # the clock may have moved into the next 30-second step meanwhile: never a step older than the oldest accepted
    STEP[n] = max(STEP[n], now_c - 1)
    STEP[n] += 1
    return auth.totp_at(SEC[n], STEP[n] - 1)


def client(n):
    tok = sessions.create(n, "127.0.0.1", UA)
    c = A.app.test_client()
    c.set_cookie("lg_session", tok)
    return c, sessions.s[auth._h(tok)]["csrf"]


ad, ad_csrf = client("lgcn-admin")
an, an_csrf = client("lgcn-analyst")


def call(c, csrf, m, p, body=None, grant=False, who="lgcn-admin"):
    h = {"User-Agent": UA, "X-CSRF-Token": csrf}
    r = c.open(p, method=m, json=body if m != "GET" else None, headers=h)
    j = r.get_json(silent=True) or {}
    if grant and r.status_code == 403 and j.get("stepup"):
        g = c.post("/api/stepup/code", json={"code": code(who), "method": m, "path": p}, headers=h).get_json() or {}
        h["X-LG-Stepup"] = g.get("grant", "")
        r = c.open(p, method=m, json=body, headers=h)
    return r


# ---------------- the way out
print("== the way out (connector_net.py)")
for addr, why in (("http://misp.example.org", "https"), ("https://127.0.0.1/", "this computer"), ("https://[::1]/", "this computer"),
                  ("https://169.254.169.254/latest", "metadata"), ("https://169.254.10.1/", "link-local"), ("https://0.0.0.0/", "not a server")):
    try:
        h, p, _ = net.parse(addr)
        net.resolve(h, p)
        ok(f"{addr}: refused", False)
    except net.Refused as e:
        ok(f"{addr}: refused ({why})", why.split()[0].lower() in str(e).lower() or why == "https", str(e))
real_gai = net.socket.getaddrinfo
net.socket.getaddrinfo = lambda *a, **k: [(2, 1, 6, "", ("127.0.0.1", 443))]
try:
    net.resolve("rebind.example", 443)
    ok("a name that leads to this computer: refused", False)
except net.Refused:
    ok("a name that leads to this computer: refused", True)
net.socket.getaddrinfo = real_gai
ok("private network addresses are allowed (platforms inside the CSIRT's network)", net.allowed_ip(__import__("ipaddress").ip_address("10.0.0.5")) is None)
ctx = net.context()
ok("the certificate is always checked (CERT_REQUIRED, host name checked)", ctx.verify_mode == net.ssl.CERT_REQUIRED and ctx.check_hostname)
src = open(net.__file__, encoding="utf-8").read()
ok("no way to switch certificate checking off, no redirect handling", "CERT_NONE" not in src and "check_hostname = False" not in src
   and "Location" not in src)

# ---------------- a faked platform
SENT = []


def fake(method, address, headers=None, body=None):
    SENT.append((method, address, dict(headers or {}), body))
    if address.endswith("/objects/") and method == "POST":
        return 202, b'{"status":"complete"}', {}
    if "/taxii2/" in address:
        auth_ok = (headers or {}).get("Authorization") == "Bearer good-token"
        return (200, json.dumps({"id": "c1", "title": "Looking Glass", "can_write": True}).encode(), {}) if auth_ok else (401, b"{}", {})
    return 404, b"{}", {}


net.request = fake
net.resolve = lambda host, port: "10.0.0.9"
ADDR = "https://opencti.lab.test/taxii2/root/collections/c1/objects/"
print("== test before save")
r = call(an, an_csrf, "POST", "/api/connectors/test", {"kind": "opencti", "address": ADDR, "key": "good-token", "tlp": "amber"})
ok("an analyst cannot test or set up connectors", r.status_code == 403, r.status_code)
r = call(ad, "", "POST", "/api/connectors/test", {"kind": "opencti", "address": ADDR, "key": "good-token", "tlp": "amber"})
ok("without the form token: refused", r.status_code == 403, r.status_code)
r = call(ad, ad_csrf, "POST", "/api/connectors/test", {"kind": "opencti", "address": ADDR, "key": "bad-token", "tlp": "amber"})
j = r.get_json() or {}
ok("a wrong key: the test fails, saying the key was refused, and gives no pass", not j.get("ok") and "pass" not in j
   and "refused" in json.dumps(j.get("checks")), j)
r = call(ad, ad_csrf, "POST", "/api/connectors/test", {"kind": "opencti", "address": ADDR, "key": "good-token", "tlp": "amber"})
j = r.get_json() or {}
ok("testing needs no fresh check, and a passing test gives a pass", r.status_code == 200 and j.get("ok") and j.get("pass"), (r.status_code, j))
ok("…the test send went to <collection>/objects/ with the TAXII type", any(m == "POST" and a.endswith("/c1/objects/") and "taxii" in h.get("Content-Type", "")
                                                                         for m, a, h, _ in SENT), SENT[-1:])
P = j.get("pass")
r = call(ad, ad_csrf, "POST", "/api/connectors", {"kind": "opencti", "address": ADDR, "key": "good-token", "tlp": "red", "pass": P}, grant=True)
ok("saving other values than the tested ones (another TLP): refused", r.status_code == 400, r.status_code)
j = call(ad, ad_csrf, "POST", "/api/connectors/test", {"kind": "opencti", "address": ADDR, "key": "good-token", "tlp": "amber"}).get_json()
r = call(ad, ad_csrf, "POST", "/api/connectors", {"kind": "opencti", "address": ADDR, "key": "good-token", "tlp": "amber", "pass": "made-up"}, grant=True)
ok("a made-up pass: refused (no save without a passed test)", r.status_code == 400, r.status_code)
r = call(ad, ad_csrf, "POST", "/api/connectors", {"kind": "opencti", "address": ADDR, "key": "good-token", "tlp": "amber", "pass": j["pass"]})
ok("saving asks for the fresh check every time", r.status_code == 403 and (r.get_json() or {}).get("every_time"), r.status_code)
j = call(ad, ad_csrf, "POST", "/api/connectors/test", {"kind": "opencti", "address": ADDR, "key": "good-token", "tlp": "amber", "name": "CSIRT OpenCTI"}).get_json()
r = call(ad, ad_csrf, "POST", "/api/connectors", {"kind": "opencti", "address": ADDR, "key": "good-token", "tlp": "amber", "name": "CSIRT OpenCTI",
                                                  "pass": j["pass"]}, grant=True)
jt = r.get_json() or {}
ok("the tested values with their pass and the fresh check: saved, and off", r.status_code == 200 and jt.get("target", {}).get("on") is False, (r.status_code, jt))
TID = (jt.get("target") or {}).get("id", "")
r2 = call(ad, ad_csrf, "POST", "/api/connectors", {"kind": "opencti", "address": ADDR, "key": "good-token", "tlp": "amber", "name": "CSIRT OpenCTI",
                                                   "pass": j["pass"]}, grant=True)
ok("…a pass works once", r2.status_code == 400, r2.status_code)

print("== the key")
raw = open(vault.path, encoding="utf-8").read()
ok("stored encrypted: not readable in the file", "good-token" not in raw and TID in raw)
ok("…readable with the secret", vault.get(TID) == "good-token")
os.environ["CONNECTOR_KEY_SECRET"] = "cd" * 32
ok("…not with another secret", vault.get(TID) is None)
os.environ["CONNECTOR_KEY_SECRET"] = SECRET
lst = call(ad, ad_csrf, "GET", "/api/connectors").get_json() or {}
ok("never in any answer", "good-token" not in json.dumps(lst) and lst["targets"][0]["key"] == "stored", lst)
ok("never in the audit log", "good-token" not in json.dumps(AUDIT, default=str))
os.environ[C.env_name(TID)] = "env-token"
ok("a key in .env for the target wins", C.key_of(vault, TID) == ("env-token", ".env"))
del os.environ[C.env_name(TID)]
os.environ["CONNECTOR_KEY_SECRET"] = ""
r = call(ad, ad_csrf, "POST", "/api/connectors", {"kind": "opencti", "address": ADDR, "key": "good-token", "tlp": "amber", "pass": "x"}, grant=True)
ok("no CONNECTOR_KEY_SECRET in .env: nothing can be stored, saying what to do", r.status_code == 400 and "CONNECTOR_KEY_SECRET" in (r.get_json() or {}).get("error", ""), r.get_json())
os.environ["CONNECTOR_KEY_SECRET"] = SECRET

print("== what it receives, turning on")
r = call(ad, ad_csrf, "POST", f"/api/connectors/{TID}/on", {}, grant=True)
ok("turning on with nothing ticked: refused", r.status_code == 400 and "nothing is ticked" in (r.get_json() or {}).get("error", ""), r.get_json())
settings = A.FEATURES["connectors"] and getattr(A, "settings", None)
restricted_before = getattr(settings, "restricted", False)
r = call(ad, ad_csrf, "POST", f"/api/connectors/{TID}/scope", {"scope": {"networks": {"64514": ["198.18.144.0/24"]}, "cidrs": []}})
ok("changing what it receives asks for the fresh check every time", r.status_code == 403 and (r.get_json() or {}).get("every_time"), r.status_code)
r = call(ad, ad_csrf, "POST", f"/api/connectors/{TID}/scope", {"scope": {"networks": {"64514": ["198.18.144.0/23"]}}}, grant=True)
ok("blocks are /24", r.status_code == 400, r.get_json())
r = call(ad, ad_csrf, "POST", f"/api/connectors/{TID}/scope", {"scope": {"networks": {"64514": ["198.18.144.0/24"]}, "cidrs": []}}, grant=True)
ok("some address blocks of a network: saved", r.status_code == 200 or (restricted_before and r.status_code == 400), r.get_json())
sc = {"networks": {"64514": ["198.18.144.0/24"], "64512": "whole"}, "cidrs": ["10.20.0.0/16"]}
ok("in scope: an address in a ticked block", C.in_scope(sc, 64514, "198.18.144.7"))
ok("…not another block of the same network", not C.in_scope(sc, 64514, "198.18.17.101"))
ok("…a whole network", C.in_scope(sc, 64512, "203.0.113.9"))
ok("…another range", C.in_scope(sc, None, "10.20.3.4"))
ok("…nothing else", not C.in_scope(sc, 64999, "192.0.2.1"))
r = call(ad, ad_csrf, "POST", f"/api/connectors/{TID}/on", {}, grant=True)
ok("turning on after the checks pass (no test send)", r.status_code == 200 and (r.get_json() or {}).get("target", {}).get("on"), r.get_json())
ok("…audited without the key", any(e == "connector_on" for e, _ in AUDIT) and "good-token" not in json.dumps(AUDIT, default=str))
r = call(ad, ad_csrf, "POST", f"/api/connectors/{TID}/delete", {}, grant=True)
ok("deleting removes the target and its stored key", r.status_code == 200 and not targets.get(TID) and vault.get(TID) is None, r.status_code)

print("== the payload: analysis only")
know = {"facts": {"event4_sinkhole_http": {"title": "Sinkhole HTTP Events", "url": "https://example.org/r"}}, "amap": {"event4_sinkhole_http": {
    "techniques": ["T1071.001"], "why": "C2 over HTTP", "certainty": "observed", "status": "suggested", "role": "used"}},
    "attack": {"techniques": {"T1071.001": {"name": "Web Protocols", "url": "https://attack.mitre.org/techniques/T1071/001", "tactics": ["Command and Control"],
                                            "mitigations": [["M1031", "IDS"]]}}, "mitigations": {"M1031": {"name": "Network Intrusion Prevention", "text": "x"}}},
    "kb": {"m0yv": {"title": "m0yv", "description": "A file infector.", "action": "Reimage it."}}, "flags": {"infected": {"label": "Already compromised", "text": "x"}},
    "impact": None, "org": "Example CSIRT"}
devs = [{"ip": "198.18.144.7", "asn": 64514, "asn_name": "Lakeside", "reports": {"event4_sinkhole_http": {
    "count": 1, "first": "2026-11-23T19:09:38.000Z", "last": "2026-11-23T19:09:38.000Z", "infections": ["m0yv"], "tags": [],
    "codes": ["LG-C-0123ABCD"],     # given on purpose: Looking Glass's combination codes must never go out
    "beacons": [("clogin", "CLogin check-in")], "cves": [], "days_seen": 3, "first_reported": "2026-11-20"}}}]
b = cp.stix_bundle(devs, "2026-11-23", "amber", know, "2026-11-24T10:00:00.000Z")
ids = {o["id"] for o in b["objects"]}
refs = [r for o in b["objects"] for k, v in o.items() if k.endswith("_refs") and k != "object_marking_refs" for r in v] + \
       [v for o in b["objects"] for k, v in o.items() if k.endswith("_ref")]
ok("STIX: every reference is inside the bundle", all(r in ids for r in refs), [r for r in refs if r not in ids])
mitre_ids = {o["id"] for o in b["objects"] if o.get("x_mitre_id")}
mitre_ids |= {o["id"] for o in b["objects"] if o["type"] == "relationship" and o.get("source_ref") in mitre_ids}
ok("STIX: the TLP on every object of Looking Glass's own analysis, the address and network included",
   all(o.get("object_marking_refs") == [cp.TLP_STIX["amber"]] for o in b["objects"] if o["type"] != "identity" and o["id"] not in mitre_ids))
used = {x for o in b["objects"] for x in (o.get("labels") or []) + (o.get("x_opencti_labels") or [])}
ok("STIX: only the fixed labels go to OpenCTI (new labels would need its 'Manage labels' right)", used and used <= set(cp.LABELS), used)
dv = [o for o in b["objects"] if o["type"] == "ipv4-addr"][0]
ok("STIX: the address has an author, description and labels, and no score (a victim, never something to block)",
   dv.get("x_opencti_created_by_ref") and "victim" in dv.get("x_opencti_description", "") and dv.get("x_opencti_labels")
   and not any(k.endswith("score") for k in dv))
ok("STIX: MITRE's own entries carry no TLP or author (they merge onto the platform's MITRE data unchanged)",
   mitre_ids and all("object_marking_refs" not in o and "created_by_ref" not in o for o in b["objects"] if o["id"] in mitre_ids))
ok("STIX: OpenCTI's own id for a MITRE id (pycti's rule; T1020.001 is attack-pattern--63493ceb-3c1d-5c4c-9b87-e01d4351738a there)",
   cp.mitre_obj("attack-pattern", "T1020.001", "x", None, "2026-01-01T00:00:00.000Z")["id"] == "attack-pattern--63493ceb-3c1d-5c4c-9b87-e01d4351738a")
txt = json.dumps(b)
ok("STIX: no raw Shadowserver fields, no time to act, no operator ids", "http_url" not in txt and "time-to-act" not in txt and "operator" not in txt)
ok("STIX: the beacon's family and format only", "CLogin check-in" in txt)
ev = cp.misp_event(devs, "2026-11-23", "amber", know, "t1")
attrs = [a for o in ev["Event"]["Object"] for a in o["Attribute"]]
ok("MISP: unpublished, 'Your organisation only'", ev["Event"]["published"] is False and ev["Event"]["distribution"] == "0")
ok("MISP: every attribute to_ids off (the devices are victims)", attrs and all(a["to_ids"] is False for a in attrs))
ok("MISP: the TLP tag and the ATT&CK galaxy tag", {"tlp:amber", 'misp-galaxy:mitre-attack-pattern="Web Protocols - T1071.001"'} <= {t["name"] for t in ev["Event"]["Tag"]})
ok("MISP: the same day and target give the same event (updated, not duplicated)", ev["Event"]["uuid"] == cp.misp_event(devs, "2026-11-23", "amber", know, "t1")["Event"]["uuid"])
ap = [o for o in b["objects"] if o["type"] == "attack-pattern"]
ok("STIX: ATT&CK techniques carry x_mitre_id and no kill chain phases (OpenCTI's own MITRE data gives those)",
   ap and all(o.get("x_mitre_id") and "kill_chain_phases" not in o for o in ap))
tid_ident = [o["id"] for o in cp.test_objects("amber")["objects"] if o["type"] == "identity"]
ok("STIX: the test send's identity never reuses the CSIRT identity's id",
   tid_ident and all(i not in {o["id"] for o in b["objects"] if o["type"] == "identity"} for i in tid_ident))
ok("STIX and MISP: no Looking Glass combination code goes out", not re.search(r"LG-C-|lg-code|combination code", txt + json.dumps(ev), re.I))
rep = ev["Event"]["EventReport"][0]["content"]
ok("MISP report: a bulleted summary first, the address as a MISP link to its attribute, ATT&CK as a galaxy link",
   rep.index("## Summary") < rep.index("## Devices") and "- @[attribute](" in rep and "        - T1071.001 Web Protocols" in rep
   and '@[tag](misp-galaxy:mitre-attack-pattern="Web Protocols - T1071.001")' in rep and "<br>" not in rep)
import connectors_worker as W  # noqa: E402
a0 = ev["Event"]["Object"][0]["Attribute"][0]
old = {"Event": {"uuid": ev["Event"]["uuid"], "Tag": [{"id": "1", "name": "tlp:green"}, {"id": "2", "name": "tlp:amber"}, {"id": "3", "name": "analyst-own"}],
                 "Object": [{"Attribute": [{"uuid": a0["uuid"], "Tag": [{"id": "9", "name": 'looking-glass:lg-code="LG-C-0123ABCD"'},
                                                                         {"id": "8", "name": a0["Tag"][0]["name"]}, {"id": "7", "name": "kill-chain:x"}]}]}]}}
ok("MISP resend: only Looking Glass's own stale tags and an old TLP are removed (analysts' tags stay)",
   sorted(W.stale_misp_tags(json.dumps(old).encode(), ev)) == sorted([(a0["uuid"], "9"), (ev["Event"]["uuid"], "1")]),
   W.stale_misp_tags(json.dumps(old).encode(), ev))
print("== OpenCTI: revoking what a resend drops, retrying what it refused")
wd = tempfile.mkdtemp(prefix="lg-conn-w-")
W.keep_sent(wd, "t9", "2026-11-23", b["objects"])
kept = W.read_sent(wd, "t9", "2026-11-23")
ok("only Looking Glass's own objects are kept for revoking (never MITRE's links)", kept and all(W.ours(o) for o in kept)
   and not any(o["type"] == "relationship" and o.get("source_ref") in mitre_ids for o in kept))
ok("Looking Glass's own objects say revoked: false outright (a device back in scope is current again in OpenCTI)",
   all(o.get("revoked") is False for o in b["objects"] if o.get("created_by_ref")))
fewer = [o for o in b["objects"] if o["type"] != "sighting"]
dr = W.dropped_objects(wd, "t9", "2026-11-23", fewer)
ok("a resend without an earlier object revokes exactly that object", dr and {o["type"] for o in dr} == {"sighting"}
   and all(o["revoked"] is True for o in dr))
ok("a resend with everything revokes nothing", W.dropped_objects(wd, "t9", "2026-11-23", b["objects"]) == [])


class FakeNet:
    Refused = net.Refused

    def __init__(self, held):
        self.held, self.calls = held, []

    def request(self, method, url, headers=None, body=None):
        self.calls.append((method, url))
        asked = body["variables"]["f"]["filters"][0]["values"]
        nodes = [{"standard_id": "x--merged", "x_opencti_stix_ids": [i for i in asked if i in self.held]}]
        return 200, json.dumps({"data": {"a": {"edges": [{"node": n} for n in nodes]}, "b": {"edges": []}, "c": {"edges": []}}}).encode(), {}


ids_all = [o["id"] for o in b["objects"] if W.ours(o)]
fn = FakeNet(set(ids_all[1:]))
miss = W.opencti_missing(fn, {"address": "https://opencti.example.org/taxii2/root/collections/c1/objects/"}, "k", ids_all)
ok("the check finds an object OpenCTI did not take (merged objects count by any id they were sent under)", miss == ids_all[:1], miss)
ok("the check asks OpenCTI's own API on the same host", fn.calls and fn.calls[0] == ("POST", "https://opencti.example.org/graphql"))
ok("the worker does not collect combination codes", "combo_codes" not in open(os.path.join(ROOT, "connectors_worker.py"), encoding="utf-8").read())

print("== the Audit portal: Data sent out, and the paused target in the bell")
au, au_csrf = client("lgcn-auditor")
targets.save("aud1", {"name": "Lab MISP", "kind": "misp", "address": "https://misp.example.org", "tlp": "amber", "on": True,
                      "scope": {"networks": {"64514": "whole"}}, "created": 1795500000, "created_by": "lgcn-admin",
                      "paused": "The checks before sending did not pass: the key was refused."})
vault.put("aud1", "a-made-up-misp-key")
with open(CN["paths"]["log"], "a", encoding="utf-8") as f:
    for e in ({"at": 1795510000, "target": "aud1", "day": "2026-11-23", "status": "sent", "devices": 7, "objects": 7, "tlp": "amber"},
              {"at": 1795520000, "target": "aud1", "day": "2026-11-23", "status": "sent", "devices": 6, "objects": 0, "tlp": "amber", "revoked": 22},
              {"at": 1795000000, "target": "aud1", "day": "2026-11-17", "status": "failed", "detail": "MISP answered 500"}):
        f.write(json.dumps(e) + "\n")
r = call(au, au_csrf, "GET", "/api/audit/connectors?from=2026-11-24&to=2026-11-24")
j = r.get_json(silent=True) or {}
ok("the auditor reads Data sent out", r.status_code == 200 and any(t["name"] == "Lab MISP" for t in j.get("targets", [])), r.status_code)
row = next((t for t in j.get("targets", []) if t["name"] == "Lab MISP"), {})
ok("…each target as set up: platform, TLP, what it receives, its state, who added it (by name)", row.get("kind") == "MISP"
   and row.get("tlp") == "AMBER" and row.get("receives") == "1 whole network(s)" and row.get("paused", "").startswith("The checks")
   and row.get("added_by") == "Made-up Admin", row)
ok("…never a key", "a-made-up-misp-key" not in r.get_data(as_text=True) and "key" not in row)
ok("…only the period chosen (the two sends of 24 November, not the failure of the 17th)",
   [e["status"] for e in j.get("events", []) if e.get("target") == "aud1"] == ["sent", "sent"], j.get("events"))
ok("…with the totals (devices, objects, revoked)", j.get("totals", {}).get("revoked") == 22 and j["totals"]["devices"] >= 13, j.get("totals"))
ok("an analyst does not open it", call(an, an_csrf, "GET", "/api/audit/connectors").status_code == 403)
import system_alerts  # noqa: E402
bell = system_alerts.Alerts(tmp.rsplit("/data", 1)[0] if tmp.endswith("/data") else tmp)
bell.data = tmp
al = bell._connectors_paused(time.time())
ok("a paused target rings the administrators' bell, saying why", al and al[0]["title"] == "Connector paused: Lab MISP (MISP)"
   and "key was refused" in al[0]["text"] and al[0]["link"] == "/settings#connectors", al)
targets.save("aud1", None)
ok("…and the bell is quiet without one", bell._connectors_paused(time.time()) == [])

print(f"\n{checks - len(fails)} of {checks} connector checks passed" + (f"; FAILED: {fails}" if fails else ""))
sys.exit(1 if fails else 0)
