#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
# runs itself with the project's own Python (.venv), from wherever it is called
''''exec "$(dirname -- "$0")/../.venv/bin/python" "$0" "$@" # '''
"""A CVE's title and definition from its public record (cves.known_titles, the user 2026-11-19: a CVE read "No definition
yet" on a code card and a bare "CVE" on Settings -> Definitions while its CVE.org / NVD record was cached).
1. the rule, on a made-up cache in a scratch folder (nobody is asked, no connection made): CISA's KEV name first, then
   the title the CVE's issuer gave it, then the first whole sentence of the description; nothing for a CVE looked up
   with no public record, nor for one never looked up; not a CVE id: nothing;
2. the platform uses that one rule: the code cards' definitions (app._defined_titles), with a researcher's own
   definition winning, and the Definitions list's title;
3. tooltips sit above every panel (the Overview's KPI tooltips opened under it, 2026-11-19).
Usage: tests/check_cve_record_titles.py"""
import json
import os
import re
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
import cves  # noqa: E402

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info else ""), flush=True)


print("1. the rule, on a made-up cache")
now = time.time()
made_up = {
    "kev": {"t": now, "items": {"CVE-2099-0001": {"name": "Example Vendor Gateway Command Injection Vulnerability"}}},
    "cveorg": {
        "CVE-2099-0001": {"t": now, "data": {"cna_title": "Issuer title, not used: KEV wins", "description": "Not used."}},
        "CVE-2099-0002": {"t": now, "data": {"cna_title": "Missing authentication in Example Router", "description": "Long text."}},
        "CVE-2099-0003": {"t": now, "data": {"cna_title": "", "description": "An example flaw in Example OS 9.6. lets a remote attacker run code. More text follows."}},
        "CVE-2099-0004": {"t": now, "data": {"missing": True}},
    },
    "nvd": {
        "CVE-2099-0003": {"t": now, "data": {"description": "NVD's text first. Then more."}},
        "CVE-2099-0004": {"t": now, "data": {"missing": True}},
        "CVE-2099-0005": {"t": now, "data": {"description": "Only NVD has this one, e.g. Example Corp. It is short"}},
    },
    "epss": {},
}
with tempfile.TemporaryDirectory() as tmp:
    path = os.path.join(tmp, "cve_cache.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(made_up, f)
    ci = cves.CveIntel(path)
    ci._get = lambda *a, **k: (_ for _ in ()).throw(AssertionError("a connection was tried"))   # nobody may be asked
    t = ci.known_titles()
    ok("KEV name first", t.get("CVE-2099-0001") == "Example Vendor Gateway Command Injection Vulnerability", t.get("CVE-2099-0001"))
    ok("then the issuer's title", t.get("CVE-2099-0002") == "Missing authentication in Example Router", t.get("CVE-2099-0002"))
    ok("then the first whole sentence (NVD's description before CVE.org's)", t.get("CVE-2099-0003") == "NVD's text first.", t.get("CVE-2099-0003"))
    ok("a sentence is never cut at an abbreviation", t.get("CVE-2099-0005") == "Only NVD has this one, e.g. Example Corp. It is short", t.get("CVE-2099-0005"))
    ok("looked up, no public record: no title", "CVE-2099-0004" not in t)
    ok("never looked up: no title", ci.known_title("CVE-2099-0009") == "")
    ok("not a CVE id: nothing", ci.known_title("Expired certificate") == "" and ci.known_title("") == "")
    ok("one CVE by the same rule (any case)", ci.known_title(" cve-2099-0002 ") == "Missing authentication in Example Router")
    ok("the cache file is left as it was", json.load(open(path, encoding="utf-8")) == made_up)
    # what it is, in full (the user, 2026-11-19: "it's supposed to explain it fully")
    ci.cache["kev"]["items"]["CVE-2099-0003"] = {"name": "x", "short": "Example OS contains a flaw that lets an attacker run code."}
    d3 = ci.known_description("CVE-2099-0003")
    ok("the full description: NVD's first, whole", d3.startswith("NVD's text first. Then more."), d3)
    ok("…with CISA's explanation added when the record says less", d3.endswith("CISA: Example OS contains a flaw that lets an attacker run code."), d3)
    ok("…CVE.org's when NVD has none", ci.known_description("CVE-2099-0002") == "Long text.")
    ok("…nothing for a CVE never looked up, nor for a name that is not a CVE", ci.known_description("CVE-2099-0009") == "" and ci.known_description("Expired certificate") == "")

print("2. the platform uses the one rule")
src = open(os.path.join(HERE, "app.py"), encoding="utf-8").read()
body = re.search(r"def _defined_titles\(\):\n(.*?)\n    return out", src, re.S)
body = body.group(1) if body else ""
ok("the code cards' definitions include the CVEs' public titles", "cve_intel.known_titles()" in body)
ok("a researcher's own definition wins (applied after)", 0 <= body.find("known_titles") < body.find("issues_kb()"))
ok("the Definitions list's title uses the same rule", "title=item[\"title\"] or cve_intel.known_title(name)" in src)
ok("no other CVE title rule left in that list", "(c.get(\"kev\") or {}).get(\"name\", \"\"))" not in src)

ok("the Definitions list shows what it is in full under the title", 'item["description"] = desc' in src and "cve_intel.known_description(name)" in src)

print("2b. a look-up window closed while it runs stops the look-up (the user, 2026-11-19)")
ok("the server stops a look-up between two names, for the person who started it only, with the page's CSRF token",
   '@app.route("/api/lookups/<jid>/stop", methods=["POST"])' in src and 'j["cancel"] = True' in src
   and src.count("raise _LookupStopped()") >= 3 and 'job["state"] = "stopped"' in src)
ok("…the queued CVE records are not fetched once stopped", "if stop and stop():" in open(os.path.join(HERE, "cves.py"), encoding="utf-8").read())
S_ = os.environ.get("LG_HELD_DIR", "")
pdfjs = os.path.join(S_, "pdf.js.new") if S_ and os.path.exists(os.path.join(S_, "pdf.js.new")) else os.path.join(HERE, "static", "js", "pdf.js")
js = open(pdfjs, encoding="utf-8").read()
ok("the window: closing it aborts the list being gathered and stops the server's job", "ctrl.abort()" in js and "/stop`" in js
   and "if (win.onClose) win.onClose()" in js and "e.stopped = true" in js)
ok("…and it opens at once, gathering a long list inside it (prepare)", "values = await prepare(ctrl.signal)" in js)

print("3. tooltips above every panel")
css = open(os.path.join(HERE, "static", "css", "app.css"), encoding="utf-8").read()


def z(sel):
    m = re.search(r"(?m)^" + re.escape(sel) + r" \{[^}]*z-index: *(\d+)", css)
    return int(m.group(1)) if m else None


tip = z(".tip")
for sel, what in ((".intro", "the Overview"), (".ac-modal", "dialogs"), (".lgs-pop", "drop-downs")):
    ok(f"a tooltip is above {what}", tip is not None and z(sel) is not None and tip > z(sel), f".tip {tip} vs {sel} {z(sel)}")
ok("a tooltip never takes a click", re.search(r"(?m)^\.tip \{[^}]*pointer-events: none", css) is not None)

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {fails}" if fails else ""))
sys.exit(1 if fails else 0)
