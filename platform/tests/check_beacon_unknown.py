#!/usr/bin/env python3
"""The generic fallback decoder and the requests Looking Glass could not decode (beacon_decode.generic, beacon_unknown.py).

Made-up values only, encoded by this test. No real victim data.

1. Generic fallback: Base64 JSON, hex + zlib key=value text, Base64 + one-byte XOR JSON come out with their layers;
   random bytes and block-cipher-like values do not ("decoded" garbage would be worse than nothing); bounded in time.
2. What leaves the server: a generic decode and an unknown value are masked in masked views (<encoded value>); a
   researcher sees the generic decode's layers only, never its text; an unknown value's shape says what it looks like
   without its content.
3. Families: unknown values grouped by request shape across C2 hosts, devices counted, never listed; a constant token
   is marked as one; a known format, a known undecodable family and a generic decode are not listed.
4. The API: analysts and admins only; the decoding request has no device address and carries sample values only when
   asked (logged as an export); not a beacon / sent / reopen are kept and logged; the issue link names no host.
Run: .venv/bin/python tests/check_beacon_unknown.py"""
import base64
import datetime
import json
import os
import random
import sys
import tempfile
import time
import zlib

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import logging  # noqa: E402
logging.disable(logging.WARNING)
from flask import Flask, g  # noqa: E402

import beacon_decode as B  # noqa: E402
import beacon_unknown as U  # noqa: E402
from beacon_samples import encode, line, made_up, rkey  # noqa: E402

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info and not cond else ""), flush=True)


rnd = random.Random(7)
obj = {"device": "made-up-tv-box", "model": "X96 test", "serial": "TEST-0000-1111", "build": "android-9"}

print("1. Generic fallback")
b64json = base64.b64encode(json.dumps(obj).encode()).decode()
d = B.first(f"GET /api/report?data={b64json} HTTP/1.1")
ok("Base64 JSON: decoded, layers said", d and d["generic"] and d["method"] == ["Base64"] and d["json"] == obj, json.dumps(d)[:200])
kv = "uid=TEST-1234&model=test box&ver=1.2.3&lang=en&country=XX&chan=demo"
hexz = zlib.compress(kv.encode()).hex()
d = B.first(f"GET /c.php?p={hexz} HTTP/1.1")
ok("hex + zlib key=value text: decoded", d and d.get("method") == ["hex", "zlib"] and d["text"] == kv, json.dumps(d)[:200])
xj = base64.b64encode(bytes(c ^ 0x5a for c in json.dumps(obj).encode())).decode()
d = B.first(f"GET /g?s={xj} HTTP/1.1")
ok("Base64 + one-byte XOR JSON: decoded", d and d.get("method") == ["Base64", "XOR 0x5a"] and d["json"] == obj, json.dumps(d)[:200])
noise = base64.b64encode(bytes(rnd.randrange(256) for _ in range(120))).decode()
ok("random bytes: nothing 'decoded'", B.decode(f"GET /x?q={noise} HTTP/1.1") == [])
aes = base64.b64encode(bytes(rnd.randrange(256) for _ in range(64))).decode()
ok("block-cipher-like bytes: nothing 'decoded'", B.decode(f"GET /y?k={aes} HTTP/1.1") == [])
ok("a plain long token (letters and digits) is not 'decoded' by XOR", B.decode("GET /z?t=" + "Ab3" * 20 + " HTTP/1.1") == [])
t = time.monotonic()
for _ in range(20):
    B.decode("GET /n?q=" + base64.b64encode(bytes(rnd.randrange(256) for _ in range(3000))).decode() + " HTTP/1.1")
ok("20 random 3 KB values within the time budget each", (time.monotonic() - t) / 20 < B.TIME_BUDGET + 0.05, f"{(time.monotonic() - t) / 20:.3f}s")
blob = encode(made_up(), rkey())
ok("the CLogin format still wins at its place (not generic)", B.first(line(blob))["format"] == "clogin")

print("2. What leaves the server")
m = B.mask_url(f"GET /api/report?data={b64json}&x=1 HTTP/1.1")
ok("a generic decode is masked in masked views", b64json not in m and "data=<encoded value>" in m and "x=1" in m, m)
m = B.mask_url(f"GET /x?q={noise} HTTP/1.1")
ok("an unknown value is masked in masked views", noise not in m and "<encoded value>" in m, m)
p = B.public(B.first(f"GET /api/report?data={b64json} HTTP/1.1"))
ok("a researcher sees the generic decode's layers only", p["format"] == "Generic decode (Base64)" and "TEST-0000" not in json.dumps(p))
v = B.view(f"GET /x?q={noise} HTTP/1.1", "android.test", "c2.example")
ok("analysts: an unknown value is said to be unknown, with its shape, not its content",
   v and v[0].get("unknown") and "random-looking" in v[0]["what"] and noise not in json.dumps(v), json.dumps(v)[:200])
ok("block alignment is noticed", "block cipher" in B.shape(aes)["hint"])
ok("a 20-byte hex value is hash-sized", B.shape("ab" * 20)["hint"] == "hash-sized")

print("3. Families")


class Day:
    def __init__(self, events):
        self.start, self.serial, self.events = datetime.datetime(2026, 11, 14), 1, events


evs = []
for i in range(7):                     # one family across generated domains: /q?q=<100 random bytes as hex>
    evs.append({"src_ip": f"192.0.2.{i + 1}", "infection": "dga.test", "source": "event4_sinkhole_http", "http_agent": "TestAgent/1",
                "http_host": f"gen{i}abc.example", "http_url": "GET /q?q=" + bytes(rnd.randrange(256) for _ in range(100)).hex() + " HTTP/1.1"})
tok = base64.b64encode(bytes(rnd.randrange(256) for _ in range(40))).decode()
for i in range(3):                     # a constant token
    evs.append({"src_ip": f"192.0.2.{50 + i}", "infection": "adware.test", "source": "event4_sinkhole_http",
                "http_host": "stats.example", "http_url": f"GET /t.php?d={tok} HTTP/1.1"})
evs.append({"src_ip": "192.0.2.90", "infection": "android.badbox2", "source": "event4_sinkhole_http", "http_host": "c2.example", "http_url": line(blob)})
evs.append({"src_ip": "192.0.2.91", "infection": "android.badbox2", "source": "event4_sinkhole_http", "http_host": "txy.ttyunos.com",
            "http_url": f"GET /api/desk/getData?a={aes} HTTP/1.1"})
evs.append({"src_ip": "192.0.2.92", "infection": "x.test", "source": "event4_sinkhole_http", "http_host": "h.example",
            "http_url": f"GET /api/report?data={b64json} HTTP/1.1"})
# a known family not decoded yet: listed too, so it can be asked for (the user, 2026-11-16). sustat was that example until
# it was found to be a token (2026-11-17): a made-up family stands in for it here, sustat is checked as never listed
B.OPAQUE.append(B.Opaque("stattest", "stattest statistics request", r"stattest\.example$", r"/u\.php$", ("p",), "not decoded"))
sus = base64.b64encode(bytes(rnd.randrange(256) for _ in range(24))).decode()
evs.append({"src_ip": "192.0.2.93", "infection": "android.badbox2", "source": "event4_sinkhole_http", "http_host": "v.stattest.example",
            "http_url": f"GET /u.php?p={sus} HTTP/1.1"})
evs.append({"src_ip": "192.0.2.94", "infection": "android.badbox2", "source": "event4_sinkhole_http", "http_host": "v.sustat.com",
            "http_url": f"GET /u.php?p={base64.b64encode(bytes(rnd.randrange(256) for _ in range(24))).decode()} HTTP/1.1"})
tmp = tempfile.mkdtemp()
audit = []
ctx = {"store": type("S", (), {"days": {0: Day(evs)}})(), "labels": lambda: {"event4_sinkhole_http": "Sinkhole HTTP"}, "base_dir": tmp,
       "sees_hosts": lambda: "unmasked" in g.user["perms"], "csrf_ok": lambda: g.user.get("tok") == "T",
       "audit": type("A", (), {"add": lambda self, *a, **k: audit.append((a, k))})(), "people_name": lambda u: {"ana": "Ana Analyst", "adam": "Adam Admin"}.get(u, u),
       "can_approve": lambda: "settings" in g.user["perms"]}
app = Flask(__name__)
un = U.install(app, ctx)
fams = un.families()
dga = [f for f in fams if f["param"] == "q"]
ok("one family across 7 generated domains, 7 devices counted", len(dga) == 1 and dga[0]["devices"] == 7 and dga[0]["hosts_total"] == 7
   and dga[0]["names"] == ["dga.test"], json.dumps([{k: v for k, v in f.items() if k != "_requests"} for f in fams])[:300])
cst = [f for f in fams if f["param"] == "d"]
ok("a constant token is marked as one", cst and cst[0]["constant"] and cst[0]["distinct"] == 1)
ok("a decoded check-in, an encrypted family and a generic decode are not listed; a family not decoded yet is",
   {f["param"] for f in fams} == {"q", "d", "p"}, str({f["param"] for f in fams}))
susf = [f for f in fams if f["param"] == "p"]
ok("... with its known name and status, so it can be asked for like the others",
   susf and susf[0]["known"] == "stattest statistics request (not decoded yet)" and all(f["known"] == "" for f in fams if f["param"] != "p"),
   str(susf and susf[0]["known"]))
ok("sustat, a campaign token (2026-11-17), is not listed for decoding", len(susf) == 1 and "sustat" not in json.dumps(fams))
ok("... and its request line keeps only that value", susf and all(sus in x["request"] for x in susf[0]["_requests"]))
ok("a plain-text value at a known family's place is not offered for a decoding request (security review of 228293b)",
   not B.sendable("GET /u.php?p=a plain sentence with words HTTP/1.1", "v.stattest.example")
   and not B.sendable("GET /u.php?p=hello.world.this.is.text HTTP/1.1", "v.stattest.example"))
listing_text = json.dumps(un.listing())
ok("no device address in the listing, and the value only in the request lines the administrator checks before approving",
   "192.0.2." not in listing_text and tok not in json.dumps([{k: v for k, v in f.items() if k != "requests"} for f in un.listing()]))


def call(user, perms, method, path, body=None, tok_="T"):
    with app.test_request_context(path, method=method, json=body):
        g.user = {"user": user, "perms": perms, "tok": tok_}
        ep, args = app.url_map.bind("localhost").match(path.split("?")[0], method=method)
        r = app.view_functions[ep](**args)
        r, code = (r if isinstance(r, tuple) else (r, 200))
        return code, r


ANA, RES = {"unmasked", "export", "view"}, {"definitions"}
print("4. The API")
ok("refused to a researcher", call("rita", RES, "GET", "/api/beacon/unknown")[0] == 403)
code, r = call("ana", ANA, "GET", "/api/beacon/unknown")
lst = r.get_json()
ok("an analyst gets the families (the sustat one among them)", code == 200 and lst["open"] == 3, str(lst["open"]))
ok("the send link opens a private report on the separate decoding repository, never a public issue, and names no host",
   all(f["issue_url"] == "https://github.com/anonghosty/http-requests-decoding/security/advisories/new" for f in lst["families"]))
fid = dga[0]["id"]
# an administrator approves a family before its decoding request can be downloaded (the user, 2026-11-16)
ADM = ANA | {"settings"}
post = lambda u, p, st, why="", seen="": call(u, p, "POST", f"/api/beacon/unknown/{fid}/state", {"state": st, "why": why, "seen": seen})[0]  # noqa: E731
ok("nothing can be downloaded before an administrator approves", call("ana", ANA, "GET", f"/api/beacon/unknown/{fid}/request")[0] == 409)
pre = next(f for f in lst["families"] if f["id"] == fid)["requests"]
ok("the page shows the exact request lines first (masked, with their infection names)",
   pre and all(set(x) == {"infection", "request"} for x in pre) and "192.0.2." not in json.dumps(pre), json.dumps(pre)[:200])
ok("asking to send needs a reason", post("ana", ANA, "asked") == 400)
ok("an analyst asks, with a reason", post("ana", ANA, "asked", "new DGA family on 7 devices") == 200)
ok("... an analyst cannot approve it", post("ana", ANA, "approved") == 403)
ok("... nor can it be marked as sent before approval", post("ana", ANA, "sent") == 409)
ok("an administrator does not approve without saying why", post("adam", ADM, "rejected") == 400)
ok("... does not approve, with a reason", post("adam", ADM, "rejected", "TLP:AMBER source, ask the provider first") == 200)
f_ = next(f for f in call("ana", ANA, "GET", "/api/beacon/unknown")[1].get_json()["families"] if f["id"] == fid)
ok("... the analyst sees who did not approve it and why, and who asked",
   f_["state"] == "rejected" and f_["state_by"] == "Adam Admin" and f_["state_why"].startswith("TLP:AMBER") and f_["asked_by"] == "Ana Analyst", str(f_)[:300])
ok("asked again", post("ana", ANA, "asked", "the provider agreed") == 200)
lst_adm = call("adam", ADM, "GET", "/api/beacon/unknown")[1].get_json()
ok("the administrator is told it waits for them", lst_adm["can_approve"] is True and lst_adm["waiting"] == 1
   and call("ana", ANA, "GET", "/api/beacon/unknown")[1].get_json()["can_approve"] is False)
import system_alerts  # noqa: E402
asks = [a for a in system_alerts.Alerts(tmp).current() if a["key"].startswith("decode-ask:")]
ok("the administrators' bell says a decoding request waits for approval, with the reason, and leads to it",
   len(asks) == 1 and asks[0]["problem"] and "provider agreed" in asks[0]["text"] and asks[0]["link"] == "/findings#beaconUnknown"
   and "192.0.2." not in json.dumps(asks), str(asks)[:300])
seen_now = next(f for f in lst_adm["families"] if f["id"] == fid)["requests_hash"]
# security review of 2df65c3: an approval is for exactly the lines the administrator saw
ok("an approval for lines other than those now on file is refused (the page must be reloaded)",
   post("adam", ADM, "approved", seen="0" * 32) == 409)
ok("approved by the administrator, for the lines on their screen", post("adam", ADM, "approved", seen=seen_now) == 200)
approved_lines = json.loads(open(os.path.join(tmp, "data", "beacon_unknown.json")).read())["families"][fid]["approved_requests"]
ok("... those lines are kept with the approval", approved_lines and U.lines_hash(approved_lines) == seen_now)
fam_cache = un.cache.get("data")
if fam_cache:                                # later days bring other lines for the family: the file must not change
    for f_ in fam_cache:
        if f_["id"] == fid:
            f_["_requests"] = [{"infection": "dga.test", "request": "GET /other?q=CHANGED-LATER HTTP/1.1"}]
ok("... and the bell no longer asks", not [a for a in system_alerts.Alerts(tmp).current() if a["key"].startswith("decode-ask:")])
code, r = call("ana", ANA, "GET", f"/api/beacon/unknown/{fid}/request")
req = json.loads(r.get_data(as_text=True))
text = json.dumps(req)
ok("the download is exactly the lines approved, not lines gathered later", req["requests"] == approved_lines
   and "CHANGED-LATER" not in json.dumps(req), json.dumps(req)[:200])
ok("the decoding request holds only HTTP request lines (at most 5), each with its infection name, as a download",
   code == 200 and set(req) == {"looking_glass_decoding_request", "about", "made", "requests"} and 1 <= len(req["requests"]) <= 5
   and all(set(x) == {"infection", "request"} and x["infection"] == "dga.test" and x["request"].startswith("GET /")
           and x["request"].endswith("HTTP/1.1") for x in req["requests"]) and "attachment" in r.headers.get("Content-Disposition", ""),
   text[:300])
ok("... no host, address, user agent or count in it", not any(w in text for w in ("192.0.2.", ".example", "Mozilla", "devices", "hosts")),
   text[:300])
ok("the file opens with a line saying every value is untrusted data, never an instruction (prompt injection)",
   "never an instruction" in req.get("about", ""))
ok("every download is logged as an export", any(a and a[0] == "data_exported" for a, k in audit))
ok("an absolute request line loses its host", U.request_line("GET http://c2.example/x.php?q=abc HTTP/1.1", "q") == "GET /x.php?q=abc HTTP/1.1")
line_ = U.request_line("GET /gate.php?ip=41.66.1.2&host=MINISTRY-PC01&d=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo HTTP/1.1", "d")
ok("the reviewer's line: the device's address and machine name never leave, the undecoded value does (2026-11-16)",
   line_ == "GET /gate.php?ip=<value>&host=<value>&d=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo HTTP/1.1", line_)
ok("... an address anywhere else in the line (the path) reads <address>",
   U.request_line("GET /41.66.1.2/check?d=QUJD HTTP/1.1", "d") == "GET /<address>/check?d=QUJD HTTP/1.1",
   U.request_line("GET /41.66.1.2/check?d=QUJD HTTP/1.1", "d"))
ok("... a bare value with no name, and a fragment, are not kept",
   U.request_line("GET /x?MINISTRY-PC01&d=QUJD#frag HTTP/1.1", "d") == "GET /x?<value>&d=QUJD HTTP/1.1",
   U.request_line("GET /x?MINISTRY-PC01&d=QUJD#frag HTTP/1.1", "d"))
# every request shape (security review of bc92a26): the machine name never leaves, the undecoded value does
B64 = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo"
shapes = {
    "parameters split by ;": (f"GET /gate.php?host=MINISTRY-PC01;d={B64} HTTP/1.1", f"GET /gate.php?host=<value>;d={B64} HTTP/1.1"),
    "a raw space inside the query": (f"GET /gate.php?user=Jane Doe MINISTRY-PC01&d={B64} HTTP/1.1", f"GET /gate.php?user=<value>&d={B64} HTTP/1.1"),
    "the kept name repeated": (f"GET /gate.php?d=MINISTRY-PC01&d={B64} HTTP/1.1", f"GET /gate.php?d=<value>&d={B64} HTTP/1.1"),
    "a target without a leading /": (f"GET gate.php?host=MINISTRY-PC01&d={B64} HTTP/1.1", f"GET gate.php?host=<value>&d={B64} HTTP/1.1"),
    "no method or protocol": (f"/gate.php?host=MINISTRY-PC01&d={B64}", f"/gate.php?host=<value>&d={B64}"),
}
# security review of 84bfb69: words after a raw space following the kept value, and a longer plain copy of its name
shapes["words after a space following the kept value"] = (f"GET /gate.php?d={B64} host=MINISTRY-PC01 HTTP/1.1",
                                                           f"GET /gate.php?d={B64}+<value> HTTP/1.1")
for what, (raw, want) in shapes.items():
    got = U.request_line(raw, "d")
    ok(f"... {what}: only the undecoded value leaves", got == want and "MINISTRY" not in got and "Jane" not in got, got)
got = U.request_line(f"GET /gate.php?d=MINISTRY-PC01-WORKSTATION-NAME-LONG&d={B64} HTTP/1.1", "d", B64)
ok("... a longer plain copy of the kept name: the copy holding the undecoded value is the one kept",
   got == f"GET /gate.php?d=<value>&d={B64} HTTP/1.1", got)
# security review of b556cf7: identity in the PATH (the query was already masked); the path leaves as its shape only
paths = {
    "a machine name in the path": (f"GET /u/MINISTRY-PC01/bot.php?d={B64} HTTP/1.1", f"GET /u/<seg>/bot.php?d={B64} HTTP/1.1"),
    "an e-mail address in the path": (f"GET /reg/john.mensah@ministry.gov.gh/x?d={B64} HTTP/1.1", f"GET /reg/<email>/x?d={B64} HTTP/1.1"),
    "a dashed address in the path": (f"GET /41-66-1-2/x.php?d={B64} HTTP/1.1", f"GET /<address>/x.php?d={B64} HTTP/1.1"),
    "; parameters in the path": (f"GET /x.php;id=PC01;d={B64} HTTP/1.1", "GET /x.php;id=<value>;d=<value> HTTP/1.1"),
    "a percent-encoded name": (f"GET /u/john%40ministry/x?d={B64} HTTP/1.1", f"GET /u/<seg>/x?d={B64} HTTP/1.1"),
    "a percent-encoded e-mail address": (f"GET /u/john%40ministry.gov.gh/x?d={B64} HTTP/1.1", f"GET /u/<email>/x?d={B64} HTTP/1.1"),
    "a lowercase machine name with digits": (f"GET /desktop-ab12cd/x?d={B64} HTTP/1.1", f"GET /<seg>/x?d={B64} HTTP/1.1"),
    "a number and a long token": (f"GET /u/123456/abcdefabcdefabcdefabcd/x?d={B64} HTTP/1.1", f"GET /u/<n>/<long>/x?d={B64} HTTP/1.1"),
}
for what, (raw, want) in paths.items():
    got = U.request_line(raw, "d")
    ok(f"... {what}: only the path's shape leaves", got == want and not any(w in got for w in ("MINISTRY", "PC01", "john", "41-66", "ab12cd")), got)
# security review of 8063734: names with digits or dashes fold, ";" parameter names too, and an old approved line with a
# raw space in its path folds the whole segment
for name in ("server01", "pc01", "finance-pc", "kofi-mensah"):
    got = U.request_line(f"GET /users/{name}/gate.php?d={B64} HTTP/1.1", "d")
    ok(f"... a machine or person name with digits or dashes folds: {name}", got == f"GET /users/<seg>/gate.php?d={B64} HTTP/1.1", got)
got = U.path_shape("/x.php;MINISTRY-PC01=1;sid=abc")
ok("... a ';' parameter NAME that is a machine name folds too", got == "/x.php;<seg>=<value>;sid=<value>", got)
got = U.shape_line(f"GET /u/MINISTRY PC01/x?d={B64} HTTP/1.1")
ok("... an approved line with a raw space in its path folds the whole segment",
   got == f"GET /u/<seg>/x?d={B64} HTTP/1.1" and "PC01" not in got, got)
for plain in ("/gate.php", "/api/v1/check", "/Panel/getTask.aspx", "/pixel/ad_track/index.html", "/"):
    ok(f"... a plain path stays as it is: {plain}", U.path_shape(plain) == plain, U.path_shape(plain))
ok("... folding twice changes nothing (lines approved earlier are folded again on download)",
   U.shape_line(U.request_line(f"GET /u/MINISTRY-PC01/bot.php?h=x&d={B64} HTTP/1.1", "d")) == f"GET /u/<seg>/bot.php?h=<value>&d={B64} HTTP/1.1"
   and U.shape_line(f"GET /u/MINISTRY-PC01/bot.php?h=<value>&d={B64} HTTP/1.1") == f"GET /u/<seg>/bot.php?h=<value>&d={B64} HTTP/1.1")
import response_cache  # noqa: E402
ok("decoding a record's request no longer empties the shared answers (it changes nothing)", not response_cache.changes_cached("/api/beacon/decode"))
ok("state change refused without the page's token", call("ana", ANA, "POST", f"/api/beacon/unknown/{fid}/state", {"state": "sent"}, tok_="")[0] == 403)
ok("marked as sent", call("ana", ANA, "POST", f"/api/beacon/unknown/{fid}/state", {"state": "sent"})[0] == 200)
ok("put away as not a beacon", call("ana", ANA, "POST", f"/api/beacon/unknown/{cst[0]['id']}/state", {"state": "dismissed", "why": "a campaign token"})[0] == 200)
lst = call("ana", ANA, "GET", "/api/beacon/unknown")[1].get_json()
st = {f["param"]: (f["state"], f["state_by"]) for f in lst["families"]}
ok("kept, with the readable name of who did it", st == {"q": ("sent", "Ana Analyst"), "d": ("dismissed", "Ana Analyst"), "p": ("open", "")}
   and lst["open"] == 1, str(st))
ok("... and who approved it", next(f for f in lst["families"] if f["id"] == fid)["approved_by"] == "Adam Admin")
# security review of f9a4d0d: a second "sent" at the same moment is refused under the lock, and the lines stay
ok("a second 'sent' is refused, checked again under the lock", post("ana", ANA, "sent") == 409
   and un.set_state(fid, "sent", "", "ana", allowed_from=("approved",)) is False)
kept = json.loads(open(os.path.join(tmp, "data", "beacon_unknown.json")).read())["families"][fid]
ok("... and the approved lines are still kept with it", kept["state"] == "sent" and kept.get("approved_requests") == approved_lines)
ok("a sent family is not reopened", post("ana", ANA, "open") == 409)
ok("a family put away is reopened", call("ana", ANA, "POST", f"/api/beacon/unknown/{cst[0]['id']}/state", {"state": "open"})[0] == 200
   and call("ana", ANA, "GET", "/api/beacon/unknown")[1].get_json()["open"] == 2)
ok("every change is in the audit log (asked, not approved, asked, approved, sent, put away, reopened)",
   sum(1 for a, k in audit if a and a[0] == "beacon_family_state") == 7, str(sum(1 for a, k in audit if a and a[0] == "beacon_family_state")))
ok("the state file is the owner's only (0600)", oct(os.stat(os.path.join(tmp, "data", "beacon_unknown.json")).st_mode & 0o777) == "0o600")

print(f"\n{checks - len(fails)}/{checks} checks passed")
if fails:
    print("FAILED: " + "; ".join(fails))
    sys.exit(1)
