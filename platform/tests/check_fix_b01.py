#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""The fixes of the whole-codebase audit, batch 01 (27 Nov 2026), each a behaviour that failed before:

1-1  an analyst code over several days never holds all its days in memory at once (acodes.view)
1-2  the selection label holds a destination address or name back (dst_ip, dst_ref, dst_hostname)
1-3  a sent advisory can be sent on to more people after the last advisory closed the finding; a finding closed by
     anyone else still refuses it
1-4  the advisory's kept-search cache drops old entries and stays small
1-5  a long word (a URL) in an advisory's text is broken, never drawn off the PDF page (advisory_pdf.Flow)
1-6  a network look-up merges its answers into the registry as it is then: a name corrected meanwhile is kept; two
     writers never share one temporary file
1-7  the outside look-ups run without the registry lock held (asn_lookup), and the look-up route takes no lock round them
1-8  an analyst code of an unknown selection kind: 400, not a 500
1-9  a CVE ticked on an analyst code's page needs a session younger than 12 hours, like every other change
1-10 a Unicode digit in an address ("1.2.3.²") is no block, and no error
1-11 the warm-up timer after a start is a daemon thread

Stand-ins for the code book, the findings and the days; temporary folders only; nothing outside this computer.
LG_FIX_SRC=<folder> runs the checks against another copy of the platform's modules (the audited tree, to show they
fail there). Run: .venv/bin/python tests/check_fix_b01.py"""
import json
import os
import sys
import tempfile
import threading
import time

SRC_DIR = os.environ.get("LG_FIX_SRC") or os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, os.path.abspath(SRC_DIR))
os.environ.setdefault("LG_QUIET", "1")
from flask import Flask, g  # noqa: E402

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info and not cond else ""))


def call(app, path, user, role, perms, method="GET", body=None):
    """A route called in-process: (status, json). An exception is a 500, as the browser would get."""
    with app.test_request_context(path, method=method, json=body):
        g.user = {"user": user, "role": role, "perms": set(perms)}
        try:
            ep, kw = app.url_map.bind("localhost").match(path.split("?")[0], method=method)
            rv = app.view_functions[ep](**kw)
        except Exception as exc:                           # noqa: BLE001
            return 500, {"exception": repr(exc)}
        rv, st = rv if isinstance(rv, tuple) else (rv, rv.status_code)
        try:
            return st, rv.get_json() or {}
        except Exception:                                  # noqa: BLE001
            return st, {}


def closure_fn(fn, name, want=None, seen=None):
    """The inner function `name` reachable through fn's closures (that has `want` among its own free names)."""
    seen = seen or set()
    if id(fn) in seen:
        return None
    seen.add(id(fn))
    for cell in getattr(fn, "__closure__", None) or ():
        try:
            v = cell.cell_contents
        except ValueError:
            continue
        if callable(v) and hasattr(v, "__code__"):
            if v.__name__ == name and (want is None or want in v.__code__.co_freevars):
                return v
            hit = closure_fn(v, name, want, seen)
            if hit:
                return hit
    return None


def cell_of(fn, name):
    return fn.__closure__[fn.__code__.co_freevars.index(name)].cell_contents


# ====================================================================== analyst codes (1-1, 1-2, 1-8, 1-9)
import acodes  # noqa: E402


class Book:
    def __init__(self):
        self.lock, self.data = threading.RLock(), {}

    def _load(self):
        pass

    def get(self, c):
        e = self.data.get(c)
        return dict(e, code=c) if e else None

    def put(self, c, e):
        self.data[c] = dict(e)

    def record(self, *a, **k):
        pass


class Day:
    """A day loaded from the database: how many are alive at once is counted."""
    alive = peak = 0

    def __init__(self, events):
        self.events = events
        Day.alive += 1
        Day.peak = max(Day.peak, Day.alive)

    def __del__(self):
        Day.alive -= 1


SRC = "LG-A-00000AAA"


class Findings:
    asked_of = None

    def of_code(self, c):
        return ({"id": "7", "participants": ["rachel"], "title": "a finding", "text": "", "status": "analyst", "user": "rachel"}
                if c == SRC else None)

    def sees(self, f, user, admin, strict=False):
        return admin or user in (f.get("participants") or [])

    def recipient(self, kind, to):
        return "rachel", ""

    def create_analyst(self, *a, **k):
        return {"id": "9"}

    def all_open(self):
        return []


DAYS = [f"2026-11-0{i}" for i in range(1, 5)]
EVS = {iso: [{"id": f"r{i}{j}", "src_ip": f"192.0.2.{10 * i + j}", "infection": "examplebot", "source": "event4_sinkhole",
              "extracted_date": iso, "dst_ip": "198.51.100.7", "dst_hostname": "shop.example.gh"} for j in range(3)]
       for i, iso in enumerate(DAYS, 1)}
KNOWN = {"filters", "infection", "src_ip", "dst_ip", "source"}


def slice_on(day, kind, value):
    """As analytics_api._slice_on: a filter string, or one field (an unknown field is a KeyError there)."""
    if kind == "filters":
        return day, day.events, list(day.events)
    return day, day.events, [e for e in day.events if e[kind] == value]


FRESH, audited = [True], []
book, tmp = Book(), tempfile.mkdtemp(prefix="lg-fixb01-")
perms = {"researcher": {"definitions"}, "analyst": {"unmasked", "export"}, "admin": {"settings"}}
app = Flask("acodes_b01")
api = acodes.install(app, {"book": book, "findings": Findings(), "base_dir": tmp,
                           "is_demo": lambda: "unmasked" not in perms.get(getattr(g, "user", {}).get("role", ""), set()),
                           "csrf_ok": lambda: True, "fresh": lambda: FRESH[0],
                           "has_perm": lambda p: p in perms.get(getattr(g, "user", {}).get("role", ""), set()),
                           "audit": type("A", (), {"add": staticmethod(lambda *a, **k: audited.append((a, k)))})(),
                           "day": lambda platform, iso: Day(list(EVS.get(iso, []))), "slice": slice_on, "kinds": KNOWN,
                           "svc_scope": lambda q, d: [], "labels": dict, "cross": lambda hosts, **kw: {},
                           "network": lambda a: "", "defined": dict, "people_name": lambda u: u})
api.paths["ids"] = os.path.join(tmp, "acodes")
os.makedirs(api.paths["ids"], exist_ok=True)
book.put(SRC, {"kind": "a", "platform": "comms", "day": DAYS[0], "sel": {"kind": "infection", "value": "examplebot"}, "label": "src"})
with open(os.path.join(api.paths["ids"], f"{SRC}.json"), "w") as fh:
    json.dump(["r10", "r11"], fh)

print("1-1 An analyst code over four days: never all four days in memory at once")
MC = "LG-A-00000B01"
book.put(MC, {"kind": "a", "platform": "comms", "day": DAYS[-1], "days": DAYS, "label": "the devices of a search",
              "sel": {"from_code": SRC, "days": DAYS}})
with open(os.path.join(api.paths["ids"], f"{MC}.json"), "w") as fh:
    json.dump(sorted(e["id"] for d in DAYS for e in EVS[d]), fh)
Day.peak = Day.alive = 0
st, v = call(app, f"/api/intel/acode/{MC}", "rachel", "researcher", ["definitions"])
ok("the page opens with every record of its four days", st == 200 and v.get("records") == 12, f"{st} {v.get('records')} {v.get('exception', '')}")
ok("…at most one day held at any moment (was: all of them)", Day.peak <= 1, f"{Day.peak} days held at once")
ok("…and the days were read for the records and the across loop", st == 200 and (v.get("names") or [{}])[0].get("devices") == 12, str(v.get("names"))[:200])

print("1-2 The selection's label holds a destination's address and name back")
for kind_val, secret in (("dst_ip=198.51.100.7&infection=examplebot", "198.51.100.7"), ("dst_hostname=shop.example.gh", "shop.example.gh"),
                         ("dst_ref=h-1234abcd", "h-1234abcd")):
    st, d = call(app, "/api/analyst-codes", "ann", "analyst", ["unmasked", "export"], "POST",
                 {"platform": "comms", "kind": "filters", "value": kind_val, "at": f"{DAYS[0]}T10:00:00Z", "title": "t", "to": "rachel"})
    lab = d.get("label", "")
    stored = (book.get(d.get("code", "")) or {}).get("label", "")
    ok(f"{secret}: not in the label researchers read, nor in the code book", st == 200 and secret not in lab and secret not in stored
       and "1 destination (address held back)" in lab, f"{st} {lab!r}")

print("1-8 An unknown selection kind: refused with a reason, not a server error")
st, d = call(app, "/api/analyst-codes", "ann", "analyst", ["unmasked", "export"], "POST",
             {"platform": "comms", "kind": "nonsense", "value": "x", "at": f"{DAYS[0]}T10:00:00Z", "title": "t", "to": "rachel"})
ok("400 with words (was: a 500)", st == 400 and "not known" in d.get("error", ""), f"{st} {d}")
st, d = call(app, "/api/analyst-codes", "ann", "analyst", ["unmasked", "export"], "POST",
             {"platform": "comms", "kind": "infection", "value": "examplebot", "at": f"{DAYS[0]}T10:00:00Z", "title": "t", "to": "rachel"})
ok("…a known kind still makes its code", st == 200 and d.get("code", "").startswith("LG-A-"), f"{st} {d}")

print("1-9 A CVE ticked on an analyst code's page: the 12-hour session rule")
FRESH[0] = False
st, d = call(app, f"/api/intel/acode/{SRC}/issue", "rachel", "researcher", ["definitions"], "POST", {"name": "CVE-2023-48795"})
ok("a session older than 12 hours: refused, sign in again", st == 403 and "Sign in again" in d.get("error", ""), f"{st} {d}")
FRESH[0] = True
st, d = call(app, f"/api/intel/acode/{SRC}/issue", "rachel", "researcher", ["definitions"], "POST", {"name": "CVE-2023-48795"})
ok("…a fresh session goes on as before (no services devices here: 409)", st == 409, f"{st} {d}")

# ====================================================================== advisories (1-3, 1-4)
import advisory  # noqa: E402

print("1-3 Sending a sent advisory on to more people after the last advisory closed the finding")
T0 = time.time() - 3600


class AdvFindings:
    def __init__(self):
        self.items, self.sent = {}, []

    def get(self, fid):
        x = self.items.get(str(fid))
        return json.loads(json.dumps(x)) if x else None

    def sees(self, x, user, admin, strict=False):
        return True

    def advisory_sent(self, fid, comment, close, user, role):
        x = self.items[str(fid)]
        if close:
            x["status"] = "closed"
        x["history"].append({"status": x["status"], "kind": "advisory_sent", "user": user, "at": time.time(), "comment": comment})
        self.sent.append((fid, close))
        return x, ""


def finding(fid, closing_kind):
    return {"id": fid, "kind": "", "status": "closed", "title": "A finding", "network": "", "codes": [], "participants": ["ada"],
            "review": {"decision": "both"},
            "history": [{"status": "advisor", "kind": "status", "user": "mgr", "at": T0},
                        {"status": "closed", "kind": closing_kind, "user": "ada" if closing_kind == "advisory_sent" else "mgr", "at": T0 + 60}]}


def sent_advisory(ref, fid):
    return {"finding": fid, "network": "", "ref": ref, "rev": 1, "subject": "S", "description": "d", "actions": "a",
            "recipients": ["Org A"], "tlp": "TLP:AMBER", "status": "sent", "created": T0, "updated": T0, "by": "ada",
            "sends": [{"to": ["Org A"], "at": T0, "by": "ada", "report": {"n": 1, "name": "r.zip", "size": 3}}],
            "reports": [{"n": 1, "name": "r.zip", "at": T0, "by": "ada", "size": 3}],
            "history": [{"at": T0, "user": "ada", "what": "created"}]}


def adv_ctx(base, F, book_):
    return {"base_dir": base, "findings": F, "book": book_,
            "org": type("O", (), {"get": staticmethod(lambda: {"name": "Example CSIRT", "logo": ""})})(),
            "network": lambda a: "", "has_perm": lambda p: p in (getattr(g, "user", {}).get("perms") or set()),
            "csrf_ok": lambda: True, "fresh": lambda: True, "is_demo": lambda: False,
            "audit": type("A", (), {"add": staticmethod(lambda *a, **k: None)})(), "people_name": lambda u: u,
            "title_of": lambda k: k, "describe": lambda c: c, "scope_text": lambda: "", "attack": None}


atmp = tempfile.mkdtemp(prefix="lg-fixb01-adv-")
os.makedirs(os.path.join(atmp, "data", "advisories"))
AF = AdvFindings()
AF.items["5"] = finding("5", "advisory_sent")          # closed by its own (last) advisory being sent
AF.items["6"] = finding("6", "status")                 # closed by management
for ref, fid in (("ADV-2026-001", "5"), ("ADV-2026-002", "6")):
    with open(os.path.join(atmp, "data", "advisories", f"{ref}.json"), "w") as fh:
        json.dump(sent_advisory(ref, fid), fh)
aapp = Flask("advisory_b01")
advisory.install(aapp, adv_ctx(atmp, AF, type("B", (), {})()))
st, d = call(aapp, "/api/advisory/5/send", "ada", "advisor", ["advisory"], "POST", {"network": "", "recipients": "Team B"})
with open(os.path.join(atmp, "data", "advisories", "ADV-2026-001.json")) as fh:
    a1 = json.load(fh)
ok("sent on to Team B (was: 409, the finding closed)", st == 200 and len(a1.get("sends") or []) == 2 and a1["sends"][-1]["to"] == ["Team B"],
   f"{st} {d}")
ok("…with the same file, and the finding stays closed", st == 200 and a1["sends"][-1]["report"]["n"] == 1 and AF.items["5"]["status"] == "closed")
st, d = call(aapp, "/api/advisory/6/send", "ada", "advisor", ["advisory"], "POST", {"network": "", "recipients": "Team B"})
ok("a finding closed by management: still refused", st == 409 and "closed" in d.get("error", ""), f"{st} {d}")
st, d = call(aapp, "/api/advisory/5/net", "ada", "advisor", ["advisory"], "POST", {"network": "", "subject": "changed"})
ok("…and the closed finding's advisory is still not changed", st == 409, f"{st} {d}")

print("1-4 The kept-search cache of the advisories stays small")
btmp = tempfile.mkdtemp(prefix="lg-fixb01-adv2-")


class KeptBook:
    def review_kept(self, fid):
        return True

    def review_records(self, fid):
        return {"entry": {"section": "infections"}, "found": [{"src_ip": "192.0.2.1", "src_asn": "64500"}] * 100}, None


bapp = Flask("advisory_b01_cache")
advisory.install(bapp, adv_ctx(btmp, AdvFindings(), KeptBook()))
recs = None
for fn in bapp.view_functions.values():
    recs = closure_fn(fn, "records", "_cache")
    if recs:
        break
if recs is None:
    ok("the advisory's records() found", False)
else:
    for i in range(40):
        recs({"id": str(1000 + i), "review": {"decision": "both"}})
    n = len(cell_of(recs, "_cache"))
    ok("40 findings' kept searches read: at most 16 kept (was: every one, for ever)", n <= 16, f"{n} kept")
    again = recs({"id": "1039", "review": {"decision": "both"}})
    ok("…the newest is still served from the cache", again is not None and len(again["found"]) == 100)

# ====================================================================== the advisory PDF (1-5)
print("1-5 A long word in the advisory's text stays on the page")
import advisory_pdf  # noqa: E402
from reportlab.pdfbase import pdfmetrics  # noqa: E402


class FakeDoc:
    F = {"r": "Helvetica", "b": "Helvetica-Bold", "m": "Courier"}

    def __init__(self):
        self.drawn = []
        self.c = type("C", (), {"stringWidth": staticmethod(pdfmetrics.stringWidth)})()

    def new_page(self, title):
        return 560

    def s(self, t):
        return str(t)

    def text(self, x, y, t, size, color=None, bold=False, anchor=None):
        self.drawn.append((x, str(t), size, bold))


URL = "https://downloads.example.org/" + "a1b2c3d4" * 30 + "/advisory.pdf"
for how in ("rich", "para"):
    doc = FakeDoc()
    flow = advisory_pdf.Flow(doc, "Advisory")
    text = f"- Read **the vendor's note** at {URL} today" if how == "rich" else f"See {URL}"
    getattr(flow, how)(text)
    right = advisory_pdf.W - advisory_pdf.M
    worst = max(x + pdfmetrics.stringWidth(t, doc.F["b" if b else "r"], size) for x, t, size, b in doc.drawn)
    every = "".join(t for _, t, _, _ in doc.drawn)
    ok(f"{how}(): nothing drawn past the right margin (was: the URL ran off the page)", worst <= right + 0.5, f"{worst:.0f} > {right}")
    ok(f"{how}(): …and every character of the URL is drawn (never cut)", "".join(URL.split()) in every.replace(" ", ""))

# ====================================================================== the network registry (1-6, 1-7)
import asn_lookup  # noqa: E402

print("1-6 / 1-7 A network look-up and a name corrected meanwhile")
ntmp = tempfile.mkdtemp(prefix="lg-fixb01-asn-")
REG = os.path.join(ntmp, "asns.json")
with open(REG, "w") as fh:
    json.dump({"asns": {}}, fh)
real = (asn_lookup.ripestat, asn_lookup.peeringdb)
lock_free_during_lookup = []


def hand_edit():
    """What /api/networks/entry does meanwhile: read, change, write the file (under the registry lock, if any)."""
    lk = getattr(asn_lookup, "FILE_LOCK", None)
    held = threading.Event()

    def other():
        if lk is None:
            lock_free_during_lookup.append(False)
            return
        got = lk.acquire(timeout=2)            # from another thread, as another request would
        lock_free_during_lookup.append(got)
        if got:
            try:
                with open(REG, encoding="utf-8") as f:
                    data = json.load(f)
                data["asns"]["64501"] = {"name": "Named By Hand", "type": "bank", "reviewed": True, "source": "edited"}
                data["asns"]["64999"] = {"name": "Other Net", "type": "isp", "reviewed": True, "source": "edited"}
                with open(REG, "w", encoding="utf-8") as f:
                    json.dump(data, f)
            finally:
                lk.release()
        held.set()
    t = threading.Thread(target=other)
    t.start()
    t.join(5)
    if lk is None:                            # the old module: the edit written as the route did, without a lock
        with open(REG, encoding="utf-8") as f:
            data = json.load(f)
        data["asns"]["64501"] = {"name": "Named By Hand", "type": "bank", "reviewed": True, "source": "edited"}
        data["asns"]["64999"] = {"name": "Other Net", "type": "isp", "reviewed": True, "source": "edited"}
        with open(REG, "w", encoding="utf-8") as f:
            json.dump(data, f)


calls = []


def fake_ripestat(a):
    calls.append(a)
    if len(calls) == 1:
        hand_edit()                             # while the look-up waits on the outside service
    return f"EXAMPLE-{a} Example holder"


asn_lookup.ripestat, asn_lookup.peeringdb = fake_ripestat, lambda asns: {}
try:
    try:
        st = asn_lookup.identify(REG, {"64500": 9, "64501": 5})
    except Exception as exc:                    # noqa: BLE001
        st = {"exception": repr(exc)}
    reg = asn_lookup.load(REG)["asns"]
    ok("the look-up named the network it looked up", (reg.get("64500") or {}).get("name", "").startswith("EXAMPLE"), str(reg)[:300])
    ok("…the name corrected by hand meanwhile is kept (was: written over)", (reg.get("64501") or {}).get("name") == "Named By Hand",
       str(reg.get("64501")))
    ok("…and a network added meanwhile is still there (was: lost)", (reg.get("64999") or {}).get("name") == "Other Net", str(sorted(reg)))
    ok("1-7: the registry lock is free while the outside look-up runs", lock_free_during_lookup == [True], str(lock_free_during_lookup))
    os.makedirs(REG + ".tmp", exist_ok=True)   # another writer's temporary file, by the old shared name
    try:
        asn_lookup.save(REG, asn_lookup.load(REG))
        saved = True
    except OSError as exc:
        saved = repr(exc)
    ok("two writers never share one temporary file (was: asns.json.tmp for everyone)", saved is True, str(saved))
finally:
    asn_lookup.ripestat, asn_lookup.peeringdb = real

src = open(os.path.join(SRC_DIR, "app.py"), encoding="utf-8").read()
body = src.split("def api_networks_lookup", 1)[1].split("\n@app.route", 1)[0] if "def api_networks_lookup" in src else ""
ok("1-7: the look-up route holds no lock round the outside look-ups (source of app.py)",
   body and "with _NET_LOCK" not in body and "_NET_LOCK = _asn_lookup.FILE_LOCK" in src)

# ====================================================================== address blocks (1-10)
print("1-10 A Unicode digit in an address")
import address_blocks  # noqa: E402
try:
    r = address_blocks.block_of("192.0.2.²")
except Exception as exc:                        # noqa: BLE001
    r = repr(exc)
ok("'192.0.2.²' is no block, and no error (was: ValueError, the whole day's load stopped)", r == "", str(r))
try:
    tl = address_blocks.tally([{"ip": "192.0.2.²", "asn": "64500"}, {"ip": "192.0.2.7", "asn": "64500"}], [("ip", "asn")])
except Exception as exc:                        # noqa: BLE001
    tl = repr(exc)
ok("…a day with such a record still counts its other records", isinstance(tl, dict) and dict(tl) == {("192.0.2.0/24", "64500"): 1}, str(tl))
ok("…ordinary addresses as before", address_blocks.block_of("198.51.100.200") == "198.51.100.0/24"
   and address_blocks.block_of("2001:db8::1") == "2001:db8::/48")

# ====================================================================== the warm-up after a start (1-11)
print("1-11 The analyst codes' warm-up timer")
import acode_warm  # noqa: E402
import index_refresh  # noqa: E402
before = set(threading.enumerate())
was, index_refresh.SERVING = index_refresh.SERVING, True
os.environ["ANALYST_WARM_DELAY_S"] = "1"
ran = []
try:
    s = acode_warm.install(None, {"acodes": type("Api", (), {"warm": lambda self, stop=None: ran.append(1) or 1})()})
    new = [t for t in threading.enumerate() if t not in before and isinstance(t, threading.Timer)]
    ok("started in the service, as a daemon thread (was: not a daemon: a stop waited on it)",
       s["started"] and new and all(t.daemon for t in new), str([(t.name, t.daemon) for t in new]))
    time.sleep(1.5)
    ok("…and it still runs after its delay", ran == [1], str(ran))
finally:
    index_refresh.SERVING = was
    os.environ.pop("ANALYST_WARM_DELAY_S", None)

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
