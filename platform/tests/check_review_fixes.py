#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""The bugs the 2026-11-27 code review found (a Ponytail-style review of the release's changes), each kept fixed:
  - quarterly.classify: a report's other side no longer overwrites the list of collections left out (a None crashed
    the quarterly report; "ip" / "asn" were listed as left-out collections);
  - Abused or Compromised for a masked viewer: networks counted by their aliases (it said 0);
  - "Unknown network" in a filter: every record the counting rule reads as none (0, "AS0", "-"), not "" and "0" only;
  - a breakdown: a value whose key is empty is "not recorded", never a "(none)" row counted as a value.
(The Executive baseline's past days with a destination-only report: tests/check_count_keys.py.) In-process, made-up
data, no database, no network. Run: .venv/bin/python tests/check_review_fixes.py"""
import os
import sys
import types

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import analytics_api  # noqa: E402
import counting_keys as CK  # noqa: E402
import quarterly  # noqa: E402
import services  # noqa: E402

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    print(("  ok   " if cond else "  FAIL ") + label + ("" if cond else f"  [{info}]"))
    if not cond:
        fails.append(label)


print("1. quarterly.classify: the collections left out")


class _Reg:
    def __init__(self, items):
        self.items, self.unsupported = items, []

    def get(self, force=False):
        return self.items


class _DB:
    def list_collection_names(self):
        return ["event4_sinkhole_http", "event4_one_side", "scan_ssl", "a_helper_collection", "special_x"]


saved = (quarterly.sources.Registry, quarterly.services.ServiceRegistry)
# the LAST communication report has one side only (its other side is None): that used to overwrite the list
quarterly.sources.Registry = lambda db, exclude=(): _Reg([{"name": "event4_sinkhole_http", "layout": "standard"},
                                                          {"name": "event4_one_side", "layout": "target"}])
quarterly.services.ServiceRegistry = lambda db, exclude=(): _Reg([{"name": "scan_ssl"}])
try:
    out, left = quarterly.classify(_DB(), exclude={"special_x"})
    err = None
except Exception as ex:  # noqa: BLE001
    out, left, err = {}, {}, f"{type(ex).__name__}: {ex}"
finally:
    quarterly.sources.Registry, quarterly.services.ServiceRegistry = saved
ok("a one-sided report last, then collections left out: no error", err is None, err)
ok("the collections left out are the real ones, with their reason",
   set(left) == {"a_helper_collection", "special_x"} and "excluded" in left.get("special_x", ""), left)
ok("...no 'ip' or 'asn' among them", not ({"ip", "asn"} & set(left)), left)
ok("each report keeps its own other side", (out.get("event4_one_side") or {}).get("other") is None
   and (out.get("event4_sinkhole_http") or {}).get("other") == {"ip": "dst_ip", "asn": "dst_asn"}, out)

print("2. \"Unknown network\" selects every record without a network")
wanted = {"asn": {"", "0", None}}       # what privacy.resolve gives for the Unknown network row
recs = [{"asn": v} for v in ("", "0", None, 0, "AS0", "-", "00", "n/a")] + [{"asn": "64500"}, {"asn": 64501}]
picked = [r["asn"] for r in recs if services.matches(r, wanted)]
ok("0, 'AS0', '-', '00', 'n/a' match it like '' and '0' (the counting rule reads them all as none)",
   picked == ["", "0", None, 0, "AS0", "-", "00", "n/a"], picked)
ok("...a real network does not", all(not services.matches({"asn": a}, wanted) for a in ("64500", 64501)))
ok("...and a real network still selects only itself", services.matches({"asn": "64500"}, {"asn": {"64500"}})
   and not services.matches({"asn": "0"}, {"asn": {"64500"}}))

print("3. A breakdown: an empty key is not recorded, not a value")
import collections  # noqa: E402
analytics_api._A = analytics_api._A or types.SimpleNamespace(Counter=collections.Counter)   # the one app name it reads
ev =[{"asn": "64500"}, {"asn": "64500"}, {"asn": "0"}, {"asn": ""}, {"asn": "AS0"}]
rows, more = analytics_api._breakdown(ev, "asn", n=None, key=lambda a: CK.norm_asn(a))
ok("no '' row", all(r["value"] for r in rows), rows)
ok("the network counted once, the 3 without one as not recorded", more["distinct"] == 1 and more["none"] == 3
   and more["valued"] == 2, more)

print("4. Abused or Compromised, masked: networks counted by their aliases")
src = open(os.path.join(ROOT, "intelligence.py"), encoding="utf-8").read()
ok("the masked branch counts the aliases (a company rule on an alias reads none)",
   "if masked else" in src and '_s(x.get("asn")) for x in rows if _s(x.get("asn"))} - {_ck.UNKNOWN_NET} if masked' in src)
ok("...and the counting rule does read an alias as no network (why it said 0)", CK.norm_asn("Telco 3") == "")

print("5. Never a sign-in name when an account has no full name (whole-codebase audit, 2026-11-27)")
import re  # noqa: E402
import tempfile  # noqa: E402
import people  # noqa: E402
import person_code  # noqa: E402
person_code.configure(tempfile.mkdtemp(prefix="lg-review-pc-"))      # the person codes' key: temporary, never data/


class _Users:
    def get(self, n):
        return {"grace": {"profile": {"full_name": "Grace Mensah"}}}.get(n)


P = people.People(_Users())
ok("a removed account (no full name): its person code, not its sign-in name",
   P.name("old.analyst") == person_code.code("old.analyst") and "old.analyst" not in P.name("old.analyst"), P.name("old.analyst"))
ok("...a name saved with the record still wins", P.name("old.analyst", "Kofi Mensah") == "Kofi Mensah")
ok("...an account with a full name: the full name", P.name("grace") == "Grace Mensah")
ok("...values that are not accounts stay as they are",
   [P.name(v) for v in ("Looking Glass", "manage script", "looking-glass", "")] == ["Looking Glass", "manage script", "looking-glass", ""])
ok("signed_by (every PDF's 'Generated ... by'): full name and person code", people.signed_by("grace") == f"Grace Mensah ({person_code.code('grace')})",
   people.signed_by("grace"))
ok("...no full name: the person code alone", people.signed_by("old.analyst") == person_code.code("old.analyst"))
code_files = [os.path.join(ROOT, f) for f in os.listdir(ROOT) if f.endswith(".py")]
raw = [os.path.basename(f) for f in code_files
       if re.search(r'"generated_by":\s*(job\["user"\]|who\b|me\(\)\[0\]|\(getattr\(_A\.g, "user", None\) or \{\}\)\.get\("user")',
                    open(f, encoding="utf-8").read())]
ok("no PDF's 'generated by' is built from a raw sign-in name anywhere in the code", not raw, raw)

print("6. Step-up (a fresh code or passkey) on the high-value changes the audit found without it (your yes, 2026-11-27)")
import stepup  # noqa: E402
from flask import Flask as _F  # noqa: E402
_app = _F("review-fixes-stepup")
want = [("POST", "/api/pipeline/apikey", ("settings", False)), ("POST", "/api/pipeline/settings", ("settings", False)),
        ("POST", "/api/pipeline/release", ("settings", False)), ("POST", "/api/organisation", ("settings", False)),
        ("POST", "/api/password-policy", ("accounts", False)), ("POST", "/api/password-policy/force", ("accounts", True)),
        ("GET", "/review/12/report", ("export", False))]
for m, path, expect in want:
    with _app.test_request_context(path, method=m):
        got = stepup.rule_for(m, path)
    ok(f"{m} {path}: asks for step-up ({expect[0]}{', every time' if expect[1] else ''})", got == expect, got)
with _app.test_request_context("/review/12/report?as=pdf", method="GET"):
    ok("...the review's PDF preview in the browser's viewer stays a view (no step-up)", stepup.rule_for("GET", "/review/12/report") is None)
with _app.test_request_context("/api/organisation", method="GET"):
    ok("...reading the organisation needs none", stepup.rule_for("GET", "/api/organisation") is None)
ok("...a person without the Settings permission is refused before being asked to confirm",
   all(stepup.NEEDS_PERM.get(p) == "settings" for _, p, _k in want[:6]))

print("7. Country flags come with Looking Glass: no outside fetch (your yes, 2026-11-27)")
import glob  # noqa: E402
import security  # noqa: E402
held = os.environ.get("LG_HELD_DIR", "")
js = {}
for name in ("app.js", "services.js"):
    p = os.path.join(held, name + ".new") if held and os.path.exists(os.path.join(held, name + ".new")) else os.path.join(ROOT, "static", "js", name)
    js[name] = open(p, encoding="utf-8").read() if os.path.exists(p) else ""
ok("the map and Services pages load flags from /static/img/flags, never flagcdn.com",
   all("/static/img/flags/" in t and "flagcdn" not in t for t in js.values()), {k: ("flagcdn" in t) for k, t in js.items()})
csp = " ".join(str(v) for k, v in vars(security).items() if isinstance(v, str) and "img-src" in v)
ok("...and the page policy no longer allows flagcdn.com", "img-src" in csp and "flagcdn" not in csp, csp[:120])
flags = sorted(glob.glob(os.path.join(ROOT, "static", "img", "flags", "*.png"))) or \
    sorted(glob.glob(os.path.join(held, "flags_new", "*.png")) if held else [])
ok("...the flags ship (252 public-domain flags), each a real PNG", len(flags) >= 250
   and all(open(f, "rb").read(8) == b"\x89PNG\r\n\x1a\n" for f in flags), len(flags))

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
