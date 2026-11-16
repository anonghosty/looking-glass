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
tmp = tempfile.mkdtemp()
audit = []
ctx = {"store": type("S", (), {"days": {0: Day(evs)}})(), "labels": lambda: {"event4_sinkhole_http": "Sinkhole HTTP"}, "base_dir": tmp,
       "sees_hosts": lambda: "unmasked" in g.user["perms"], "csrf_ok": lambda: g.user.get("tok") == "T",
       "audit": type("A", (), {"add": lambda self, *a, **k: audit.append((a, k))})(), "people_name": lambda u: {"ana": "Ana Analyst"}.get(u, u)}
app = Flask(__name__)
un = U.install(app, ctx)
fams = un.families()
dga = [f for f in fams if f["param"] == "q"]
ok("one family across 7 generated domains, 7 devices counted", len(dga) == 1 and dga[0]["devices"] == 7 and dga[0]["hosts_total"] == 7
   and dga[0]["names"] == ["dga.test"], json.dumps([{k: v for k, v in f.items() if k != "_requests"} for f in fams])[:300])
cst = [f for f in fams if f["param"] == "d"]
ok("a constant token is marked as one", cst and cst[0]["constant"] and cst[0]["distinct"] == 1)
ok("known format, undecodable family and generic decode are not listed", {f["param"] for f in fams} == {"q", "d"}, str({f["param"] for f in fams}))
listing_text = json.dumps(un.listing())
ok("no device address and no value in the listing", "192.0.2." not in listing_text and tok not in listing_text)


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
ok("an analyst gets the families", code == 200 and lst["open"] == 2)
ok("the send link opens a private report on the separate decoding repository, never a public issue, and names no host",
   all(f["issue_url"] == "https://github.com/anonghosty/http-requests-decoding/security/advisories/new" for f in lst["families"]))
fid = dga[0]["id"]
code, r = call("ana", ANA, "GET", f"/api/beacon/unknown/{fid}/request")
req = json.loads(r.get_data(as_text=True))
text = json.dumps(req)
ok("the decoding request holds only HTTP request lines (at most 5), each with its infection name, as a download",
   code == 200 and set(req) == {"looking_glass_decoding_request", "made", "requests"} and 1 <= len(req["requests"]) <= 5
   and all(set(x) == {"infection", "request"} and x["infection"] == "dga.test" and x["request"].startswith("GET /")
           and x["request"].endswith("HTTP/1.1") for x in req["requests"]) and "attachment" in r.headers.get("Content-Disposition", ""),
   text[:300])
ok("... no host, address, user agent or count in it", not any(w in text for w in ("192.0.2.", ".example", "Mozilla", "devices", "hosts")),
   text[:300])
ok("every download is logged as an export", any(a and a[0] == "data_exported" for a, k in audit))
ok("an absolute request line loses its host", U.request_line("GET http://c2.example/x.php?q=abc HTTP/1.1") == "GET /x.php?q=abc HTTP/1.1")
ok("state change refused without the page's token", call("ana", ANA, "POST", f"/api/beacon/unknown/{fid}/state", {"state": "sent"}, tok_="")[0] == 403)
ok("marked as sent", call("ana", ANA, "POST", f"/api/beacon/unknown/{fid}/state", {"state": "sent"})[0] == 200)
ok("put away as not a beacon", call("ana", ANA, "POST", f"/api/beacon/unknown/{cst[0]['id']}/state", {"state": "dismissed", "why": "a campaign token"})[0] == 200)
lst = call("ana", ANA, "GET", "/api/beacon/unknown")[1].get_json()
st = {f["param"]: (f["state"], f["state_by"]) for f in lst["families"]}
ok("kept, with the readable name of who did it", st == {"q": ("sent", "Ana Analyst"), "d": ("dismissed", "Ana Analyst")} and lst["open"] == 0, str(st))
ok("reopened", call("ana", ANA, "POST", f"/api/beacon/unknown/{fid}/state", {"state": "open"})[0] == 200
   and call("ana", ANA, "GET", "/api/beacon/unknown")[1].get_json()["open"] == 1)
ok("every change is in the audit log", sum(1 for a, k in audit if a and a[0] == "beacon_family_state") == 3)
ok("the state file is the owner's only (0600)", oct(os.stat(os.path.join(tmp, "data", "beacon_unknown.json")).st_mode & 0o777) == "0o600")

print(f"\n{checks - len(fails)}/{checks} checks passed")
if fails:
    print("FAILED: " + "; ".join(fails))
    sys.exit(1)
