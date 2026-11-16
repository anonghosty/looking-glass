#!/usr/bin/env python3
"""The beacon decoder (beacon_decode.py) and who sees what of a decoded beacon.

Every blob here is made up: a sample JSON encoded by this test the way the zckypc check-in is encoded (JSON + trailer ->
Base64 -> repeating XOR with a 32-character hex key -> Base64), with random keys. No real victim data.

1. Decoding: the key is recovered and the JSON, trailer and notes come back exactly, for many keys and payload sizes;
   percent-encoded and space-mangled values too; other query values, short values and garbage give nothing.
2. Bounds: an over-long request line or value is not looked at; garbage and a worst-case value stay within the time
   budget.
3. Researchers: public() carries the format, operator, version, OS family and key only; mask_url() and the masked
   event (privacy.mask_event) never carry the blob; a value at the format's own place is masked even when it does not
   decode.
4. Intel gathered: the beacon kinds and the "beacon contradicts its name" lead are held back from a researcher while
   fewer than 5 devices carry them, shown from 5; an analyst sees them at once; the URL indicator never carries the
   blob; MAC, UUID, cpuid, cpumd5 and memory are in no answer.
5. The analysts' API: refused without the page's token or the 'unmasked' permission; answers the full JSON with them.
Run: .venv/bin/python tests/check_beacon_decode.py"""
import base64
import collections
import datetime
import json
import os
import random
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import logging  # noqa: E402
logging.disable(logging.WARNING)
import beacon_decode as B  # noqa: E402

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info and not cond else ""), flush=True)


sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from beacon_samples import TRAILER, encode, line, made_up, rkey, rnd  # noqa: E402,F401  (made-up check-ins only)


print("1. Decoding")
good, bad_keys = 0, []
t = time.monotonic()
for i in range(100):
    k, obj = rkey(), made_up(i)
    obj["spare2"] = "x" * rnd.randint(0, 200)          # payloads of different sizes
    d = B.first(line(encode(obj, k)))
    if d and d["key"] == k and d["json"] == obj and d["trailer"] == TRAILER:
        good += 1
    else:
        bad_keys.append(k)
took = (time.monotonic() - t) / 100
ok("the key, the JSON and the trailer come back exactly (100 random keys and sizes)", good == 100, f"{100 - good} failed, e.g. {bad_keys[:1]}")
ok("a decode takes well under the time budget", took < B.TIME_BUDGET / 2, f"{took:.3f}s each")
k, obj = rkey(), made_up()
d = B.first(line(encode(obj, k)))
ok("operator, version, OS family", d and (d["operator"], d["version"], d["os_family"]) == ("zckypc", "zckypc:4.4.3", "windows"))
ok("note: cpuid as ASCII", d and "cpuid as ASCII: GenuineIntel" in d["notes"])
ok("note: the 00:FF MAC prefix is a TAP-Windows adapter", d and any("00:FF" in n and "TAP-Windows" in n for n in d["notes"]))
ok("note: the trailer, XOR 0x72", d and any("XOR 0x72" in n and TRAILER in n for n in d["notes"]))
blob = encode(obj, k)
ok("a percent-encoded value decodes", (B.first(line(blob.replace("+", "%2B").replace("/", "%2F").replace("=", "%3D"))) or {}).get("key") == k)
ok("the format is tried away from its usual path too", (B.first(line(blob, "/other/path", "q")) or {}).get("format") == "clogin")
o2 = made_up(operator="WT", version="WT:1.0.0")
d2 = B.first(line(encode(o2, rkey())))
ok("other operators of the same check-in (WT) decode the same way", d2 and (d2["operator"], d2["version"]) == ("WT", "WT:1.0.0"))
ok("a trailer of another length (46) decodes", (B.first(line(encode(obj, k, TRAILER[:46]))) or {}).get("trailer") == TRAILER[:46])
ok("found among other query values", (B.first(f"GET /CLogin?a=1&key={blob}&b=2 HTTP/1.1") or {}).get("key") == k)
ok("a short value gives nothing", B.decode("GET /CLogin?key=abcdef HTTP/1.1") == [])
ok("a request without a query gives nothing", B.decode("GET /index.html HTTP/1.1") == [])
noise = base64.b64encode(bytes(rnd.randrange(256) for _ in range(600))).decode()
ok("random Base64 gives nothing", B.decode(line(noise)) == [])
other = base64.b64encode(base64.b64encode(json.dumps({"a": 1, "b": "c" * 80}).encode())).decode()
ok("Base64 of other JSON (no XOR layer, wrong fields) gives nothing", B.decode(line(other)) == [])
ok("a JWT-like token gives nothing", B.decode("GET /api?token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U HTTP/1.1") == [])

print("2. Bounds")
ok("a request line over MAX_URL is not looked at", B.decode(line(blob) + "&p=" + "a" * B.MAX_URL) == [])
ok("a value over MAX_BLOB is not a candidate", B.candidates(line("A" * (B.MAX_BLOB + 4))) == [])
t = time.monotonic()
for j in range(20):
    B.decode(line(base64.b64encode(bytes(rnd.randrange(256) for _ in range(B.MAX_BLOB * 3 // 4 - 8))).decode()))
ok("20 random maximum-size values, under the time budget each", (time.monotonic() - t) / 20 < B.TIME_BUDGET + 0.05, f"{(time.monotonic() - t) / 20:.3f}s each")
# a worst case for the key search: a value whose every column admits many hex characters (all 'A'..'Z' and 'a'..'z')
worst = base64.b64encode(b"".join(bytes([rnd.choice(b"0123456789abcdef") ^ c for c in b"QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB"]) for _ in range(150))).decode()
t = time.monotonic(); B.decode(line(worst))
ok("a value built to keep many keys open stays within the budget", time.monotonic() - t < B.TIME_BUDGET + 0.1, f"{time.monotonic() - t:.3f}s")

print("3. Researchers: what leaves the server")
p = B.public(d)
ok("public() is format, operator, version, OS family and whether it decoded only (no key: one per check-in)",
   set(p) == {"format", "id", "operator", "version", "os_family", "state"} and p["format"] == "CLogin check-in"
   and p["state"] == "decoded" and k not in json.dumps(p))
ident = [str(obj[f]) for f in B.DEVICE_FIELDS] + [obj["cpuid"], bytes.fromhex(obj["cpuid"]).decode()]
ok("public() carries no MAC, UUID, cpuid, cpumd5 or memory", not any(v and v in json.dumps(p) for v in ident if len(v) > 4))
m = B.mask_url(line(blob))
ok("mask_url() replaces the blob", blob not in m and "<clogin beacon>" in m and m.startswith("GET /CLogin?key=") and m.endswith(" HTTP/1.1"), m[:80])
m2 = B.mask_url(f"GET /CLogin?a=1&key={blob}&b=2 HTTP/1.1")
ok("mask_url() keeps the other query values", m2 == "GET /CLogin?a=1&key=<clogin beacon>&b=2 HTTP/1.1", m2[:90])
m3 = B.mask_url("GET /CLogin?key=" + "Q" * 20 + " HTTP/1.1")
ok("a value at the format's own place is masked even when it does not decode", "Q" * 20 not in m3, m3)
ok("an ordinary request line is left as it is", B.mask_url("GET /sck/29965/?m=a11&step=669 HTTP/1.0") == "GET /sck/29965/?m=a11&step=669 HTTP/1.0")
# the families that cannot be decoded from the request (made-up values of their shape)
aes = base64.b64encode(bytes(rnd.randrange(256) for _ in range(48))).decode()
tl = f"GET /api/desk/getData?a={aes}&b=Zm9vYmFyYmF6cXV4cXV1eA== HTTP/1.1"
mt = B.mask_url(tl)
ok("an encrypted family's values are masked (<ttyunos value>)", aes not in mt and mt.count("<ttyunos value>") == 2, mt)
sv = B.view(tl, "android.badbox2", "txy.ttyunos.com")
ok("analysts: the family is named, not decoded, with what it is", sv and sv[0]["decoded"] is False and sv[0]["format"] == "ttyunos" and "block cipher" in sv[0]["what"])
ok("the same path on another host is not named (the host decides)", B.seen(tl, "example.org") == [])
ok("Intel gathered: its format says what the value is: '(encrypted)'", B.field({"http_url": tl, "http_host": "txy.ttyunos.com"}, "format") == "ttyunos API request (encrypted)")
ok("...and its state", B.field({"http_url": tl, "http_host": "txy.ttyunos.com"}, "state") == "encrypted" and sv[0]["status"] == "encrypted")
# each family says whether its value is encoded at all (the user, 2026-11-16)
st = {o.name: o.state for o in B.OPAQUE}
ok("encrypted, a one-way hash, an ID, a token, not decoded yet: each family has its state",
   st == {"ttyunos": "encrypted", "weatherlive": "encrypted", "adoverocean": "hash", "pixellog": "id", "clickby": "token", "sustat": "unknown"}, str(st))
ok("...the ones with nothing encoded in them say 'not encoded'",
   all("not encoded" in B.status_text(s) and B.status_text(s, long=True).startswith("Not encoded") for s in ("hash", "id", "token"))
   and all(B.status_text(s, long=True).startswith("Encoded") for s in ("encrypted", "unknown", "cut")))
md5 = "".join(rnd.choice("0123456789abcdef") for _ in range(32))
ok("a hash family (adoverocean m=) is named as one-way", "one-way" in (B.seen(f"GET /ota/api/tasks/v2?m={md5}&n=MOBILE(0) HTTP/1.1", "www.adoverocean.com") or [{}])[0].get("what", ""))
cut = B.view(line(blob[:len(blob) // 2 // 4 * 4]), "android.badbox2", "zcky.example")     # the JSON cut in half
ok("a CLogin value cut short is named 'did not decode', never guessed", cut and cut[0]["decoded"] is False and cut[0]["format"] == "clogin"
   and cut[0]["state"] == "cut" and cut[0]["status"] == "did not decode")
import privacy  # noqa: E402


class _Asns:
    def alias(self, x):
        return "Network A"


ev = {"src_ip": "192.0.2.10", "dst_ip": "198.51.100.7", "http_url": line(blob), "http_host": "c2.example", "infection": "android.badbox2"}
me = privacy.mask_event(ev, _Asns())
ok("the masked event (demo, external role) carries no blob", blob not in json.dumps(me) and "<clogin beacon>" in me["http_url"])

print("4. Intel gathered and Looking Glass asks")
from flask import Flask, g  # noqa: E402
import intel as I  # noqa: E402
import intel_match as IM  # noqa: E402


class Day:
    def __init__(self, events):
        self.start, self.serial, self.events = datetime.datetime(2026, 11, 14), 1, events


def store(events):
    return type("S", (), {"days": {0: Day(events)}})()


def build(devices):
    k = None
    evs = []
    for i in range(devices):
        o = made_up(i)
        evs.append({"src_ip": f"192.0.2.{10 + i}", "infection": "android.badbox2", "source": "event4_sinkhole_http",
                    "http_url": line(encode(o, rkey())), "http_host": "c2.example", "http_agent": "Lingjiang"})   # a new key each, as seen
    ctx = {"store": store(evs), "svc_store": store([]), "labels": lambda: {"event4_sinkhole_http": "Sinkhole HTTP"},
           "defined": lambda: {}, "allowed": lambda: True}
    return I.Intel(ctx), evs, k


app = Flask(__name__)


def as_role(perms, fn):
    with app.test_request_context("/api/intel"):
        g.user = {"user": "t", "perms": set(perms), "csrf": "tok"}
        return fn()


RESEARCHER, ANALYST = {"definitions"}, {"unmasked", "view"}
for n in (1, 5):
    intel, evs, key = build(n)
    gr = as_role(RESEARCHER, lambda: intel.gathered("infections", "android.badbox2"))
    ld = as_role(RESEARCHER, lambda: intel.leads())
    # as the API sends them (intel.install): without the internal match keys
    ld["leads"] = [{k_: v for k_, v in x.items() if k_ not in ("names_key", "_seen")} for x in ld["leads"]]
    gr["leads"] = [{k_: v for k_, v in x.items() if k_ not in ("names_key", "_seen")} for x in gr["leads"]]
    kinds = {k["kind"]: k for r in gr["reports"] for k in r["indicators"]}
    shown = {k: [v["value"] for v in kinds[k]["values"]] for k in B.KINDS if k in kinds}
    contra = [x for x in ld["leads"] if x["priority"] == 5]
    if n == 1:
        ok("1 device: a researcher sees no beacon value (held back, counted)",
           all(not v for v in shown.values()) and all(kinds[k]["hidden"] for k in shown), json.dumps(shown))
        ok("1 device: no contradiction lead for a researcher", not contra)
        gra = as_role(ANALYST, lambda: intel.gathered("infections", "android.badbox2"))
        lda = as_role(ANALYST, lambda: intel.leads())
        ka = {k["kind"]: [v["value"] for v in k["values"]] for r in gra["reports"] for k in r["indicators"]}
        ok("1 device: an analyst sees the format, operator and version", ka.get("Beacon operator") == ["zckypc"] and ka.get("Beacon version") == ["zckypc:4.4.3"]
           and ka.get("Beacon format") == ["CLogin check-in"])
        ok("1 device: an analyst gets the contradiction lead", any(x["priority"] == 5 and x["value"] == "windows" for x in lda["leads"]))
    else:
        ok("5 devices: a researcher sees format, operator, version and OS family",
           shown.get("Beacon format") == ["CLogin check-in"] and shown.get("Beacon operator") == ["zckypc"] and shown.get("Beacon version") == ["zckypc:4.4.3"]
           and shown.get("Beacon OS") == ["windows"], json.dumps(shown))
        ok("5 devices: the decoded records are counted", kinds.get("Beacon format", {}).get("values", [{}])[0].get("count") == 5)
        ok("5 devices: the 'beacon contradicts its name' lead (windows under an android name)",
           len(contra) == 1 and contra[0]["value"] == "windows" and contra[0]["count"] == 5 and "Android" in contra[0]["text"]
           and contra[0]["verdict"] and contra[0]["names"][0]["name"] == "android.badbox2", json.dumps(contra)[:200])
        ok("5 devices: the lead is listed with the name's own leads too", any(x["priority"] == 5 for x in gr["leads"]))
        mv = IM.MatchView(intel, {"labels": lambda: {"event4_sinkhole_http": "Sinkhole HTTP"}})
        ex = as_role(RESEARCHER, lambda: mv.view("Beacon OS", "windows"))
        ok("5 devices: Explore on the lead finds the records", ex and ex["places"] and ex["places"][0]["records"] == 5)
    everything = json.dumps([gr, ld], default=str)
    urls = [v["value"] for r in gr["reports"] for k in r["indicators"] if k["kind"] == "URL" for v in k["values"]]
    ok(f"{n} device(s): the URL indicator carries the masked beacon, never the blob",
       urls and all("<clogin beacon>" in u for u in urls) and not any(e["http_url"].split("key=")[1].split(" ")[0] in everything for e in evs))
    leaked = []
    for e in evs:
        dd = B.first(e["http_url"])
        if dd["key"] in everything:
            leaked.append("key")                  # a new key per check-in: it would single out one record
        o = dd["json"]
        for f in B.DEVICE_FIELDS:
            if str(o[f]) and len(str(o[f])) > 4 and str(o[f]) in everything:
                leaked.append(f)
    ok(f"{n} device(s): no MAC, UUID, cpuid, cpumd5 or memory in any researcher answer", not leaked, ",".join(sorted(set(leaked))))

print("5. The analysts' API")
api = Flask("api")
B.install(api, {"csrf_ok": lambda: g.user.get("csrf") == "tok", "sees_hosts": lambda: "unmasked" in g.user.get("perms", ())})


def post(perms, token, body):
    with api.test_request_context("/api/beacon/decode", method="POST", json=body):
        g.user = {"user": "t", "perms": set(perms), "csrf": token}
        r = api.view_functions["api_beacon_decode"]()
        r, code = (r if isinstance(r, tuple) else (r, 200))
        return code, r.get_json()


body = {"url": line(blob), "name": "android.badbox2"}
ok("refused without the page's token", post(ANALYST, "", body)[0] == 403)
ok("refused to a researcher (no 'unmasked')", post(RESEARCHER, "tok", body)[0] == 403)
code, j = post(ANALYST, "tok", body)
bc = (j or {}).get("beacons") or [{}]
ok("an analyst gets the full JSON, the key and the notes", code == 200 and bc[0].get("json") == obj and bc[0].get("key") == k and bc[0].get("notes"))
ok("the analyst's notes name the contradiction with the name", any("android.badbox2" in n and "Windows" in n for n in bc[0].get("notes", [])))
ok("what the beacon says, never what to do: no action in the answer, even when it contradicts the name (the user, 2026-11-16)",
   not any("action" in x for x in bc) and not hasattr(B, "recommended_action"))
code, j2 = post(ANALYST, "tok", {"url": line(blob), "name": "android.badbox2", "host": "c2.example", "agent": "TestAgent/1"})
ok("... with the C2 host and user agent given, still none", code == 200 and not any("action" in x for x in (j2 or {}).get("beacons", [])))
ok("a request line with nothing in it answers an empty list", post(ANALYST, "tok", {"url": "GET / HTTP/1.1"}) == (200, {"beacons": []}))
ok("name to OS: android.badbox2 -> android, win32.x -> windows, mirai -> unknown",
   (B.name_os("android.badbox2"), B.name_os("win32.emotet"), B.name_os("mirai")) == ("android", "windows", ""))

print(f"\n{checks - len(fails)}/{checks} checks passed")
if fails:
    print("FAILED: " + "; ".join(fails))
    sys.exit(1)
