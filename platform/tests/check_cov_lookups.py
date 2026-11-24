#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""The outside look-ups, with every answer made up and nothing sent anywhere (r91 coverage):
- cves.py: CISA KEV, EPSS, CVE.org and NVD answers read into cards (scores, sources, exploited, titles, descriptions),
  404 = no record, other errors = a reason, KEV kept after a failed download and not asked again for a while, the NVD
  pace (no sixth request in 30 s), the time budget and the stop of a batch, the background prefetch, merging another
  process's cache
- malpedia.py: the search words made from a Shadowserver name, family / actor / sample look-ups, values checked before
  anything is asked, the per-minute limit, the bounded cache
- asn_lookup.py: holder names cleaned, network types from names, retries on 503, the registry file, the identify job
- netypes.py: built-in and added network types, what is refused
- geo.py: places found, not found (stored), failed (not stored, a pause before the next try), the country fallback
Every request goes to a fake that answers from the made-up records below (RFC 5737 addresses, private AS numbers,
CVE-2099-* ids, example names) and writes down what was asked. Files go to a temporary folder only.
Run: .venv/bin/python tests/check_cov_lookups.py"""
import io
import json
import os
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import asn_lookup  # noqa: E402
import cves  # noqa: E402
import geo  # noqa: E402
import malpedia  # noqa: E402
import netypes  # noqa: E402

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info and not cond else ""), flush=True)


class Log:
    def __init__(self):
        self.lines = []

    def warning(self, msg, *a):
        self.lines.append(msg % a if a else msg)


ASKED = []
ANSWERS = {}          # url prefix -> answer (dict/list), an int (HTTP error code), or an exception


def fake_urlopen(req, *a, **kw):
    url = req.full_url if isinstance(req, urllib.request.Request) else req
    ASKED.append(url)
    for prefix in sorted(ANSWERS, key=len, reverse=True):
        if url.startswith(prefix):
            ans = ANSWERS[prefix]
            if callable(ans):
                ans = ans(url)
            if isinstance(ans, int):
                raise urllib.error.HTTPError(url, ans, "made-up error", {}, None)
            if isinstance(ans, BaseException):
                raise ans
            return io.BytesIO(json.dumps(ans).encode())
    raise AssertionError(f"unexpected request {url}")


real_urlopen, real_sleep = urllib.request.urlopen, time.sleep
urllib.request.urlopen = fake_urlopen
SLEPT = []
time.sleep = lambda s: SLEPT.append(s)
TMP = tempfile.mkdtemp(prefix="lg-cov-lookups-")

try:
    # ------------------------------------------------------------------ cves.py
    print("CVE ids and titles")
    ok("a CVE id, any case, with spaces around: yes", cves.is_cve(" cve-2099-0001 ") and cves.is_cve("CVE-2099-1234567"))
    ok("…not a CVE id: no", not cves.is_cve("CVE-99-1") and not cves.is_cve(None) and not cves.is_cve("CVE-2099-12345678"))
    ok("the title is the first whole sentence",
       cves.short_title("A flaw in Widget 9.6. Attackers can read files.") == "A flaw in Widget 9.6.")
    ok("…'e.g.' and 'Inc.' do not end it", cves.short_title("Made by ExampleCo Inc. The flaw, e.g. Apache, is bad. More.")
       == "Made by ExampleCo Inc. The flaw, e.g. Apache, is bad.")
    ok("…no sentence end: the whole text; nothing: ''", cves.short_title("  no end here ") == "no end here" and cves.short_title(None) == "")

    K, E, N, O = "CVE-2099-0001", "CVE-2099-0002", "CVE-2099-0003", "CVE-2099-0004"
    ANSWERS.update({
        cves.KEV: {"catalogVersion": "2099.01.01", "dateReleased": "2099-01-01", "vulnerabilities": [
            {"cveID": K, "vendorProject": "ExampleCo", "product": "Widget", "vulnerabilityName": "ExampleCo Widget Flaw",
             "dateAdded": "2099-01-02", "shortDescription": "A made-up flaw in Widget.", "requiredAction": "Apply the update.",
             "dueDate": "2099-02-01", "knownRansomwareCampaignUse": "Known"}, {"vendorProject": "no id: skipped"}]},
        cves.EPSS: {"data": [{"cve": K, "epss": "0.5", "percentile": "0.91", "date": "2099-01-03"}]},
        cves.CVEORG.format(year="2099", group="0", id=K): {
            "cveMetadata": {"state": "PUBLISHED", "datePublished": "2099-01-01T00:00", "dateUpdated": "2099-01-05T00:00",
                            "assignerShortName": "example"},
            "containers": {"cna": {"title": "", "descriptions": [{"lang": "en", "value": "Widget lets anyone in. More text."}],
                                   "problemTypes": [{"descriptions": [{"cweId": "CWE-287"}]}],
                                   "references": [{"url": "https://example.org/advisory"}, {"url": "ftp://example.org/x"}]},
                           "adp": [{"providerMetadata": {"shortName": "CISA-ADP"},
                                    "metrics": [{"cvssV3_1": {"baseScore": 9.8, "baseSeverity": "CRITICAL", "version": "3.1",
                                                              "vectorString": "CVSS:3.1/AV:N"}}]}]}},
        cves.CVEORG.format(year="2099", group="0", id=E): {
            "cveMetadata": {"state": "PUBLISHED"},
            "containers": {"cna": {"title": "Example Gadget overflow", "descriptions": [{"lang": "en-GB", "value": "Gadget overflows."}],
                                   "metrics": [{"cvssV4_0": {"baseScore": 7.1, "baseSeverity": "HIGH"}}]}}},
        cves.CVEORG.format(year="2099", group="0", id=N): 404,
        cves.CVEORG.format(year="2099", group="0", id=O): 500,
        cves.NVD + K: {"vulnerabilities": [{"cve": {
            "descriptions": [{"lang": "es", "value": "no"}, {"lang": "en", "value": "NVD: Widget lets anyone in."}],
            "metrics": {"cvssMetricV31": [{"type": "Secondary", "cvssData": {"baseScore": 5.0}},
                                          {"type": "Primary", "cvssData": {"version": "3.1", "baseScore": 9.8,
                                                                           "baseSeverity": "CRITICAL", "vectorString": "V"}}]},
            "weaknesses": [{"description": [{"value": "CWE-287"}, {"value": "NVD-CWE-noinfo"}]}],
            "references": [{"url": "https://example.org/patch", "tags": ["Patch"]}, {"url": "https://example.org/blog"},
                           {"url": "mailto:x@example.org"}],
            "published": "2099-01-01T00:00:00", "lastModified": "2099-01-09T00:00:00", "vulnStatus": "Analyzed"}}]},
        cves.NVD + E: {"vulnerabilities": [{"cve": {"descriptions": [], "metrics": {"cvssMetricV2": [
            {"cvssData": {"baseScore": 4.3}, "baseSeverity": "MEDIUM"}]}}}]},
        cves.NVD + N: 404,
    })
    log = Log()
    cpath = os.path.join(TMP, "cve_cache.json")
    ci = cves.CveIntel(cpath, api_key="", logger=log)
    ok("a new cache: empty sections", ci.cache["nvd"] == {} and ci.cache["kev"]["items"] == {})
    steps = []
    cards = ci.lookup_many([K, E, N.lower(), O, "not-a-cve", K], progress=lambda kind, text, done=None: steps.append((kind, text)))
    ok("the batch: one card per CVE id, duplicates and non-ids dropped", list(cards) == [K, E, N, O], str(list(cards)))
    ok("…KEV downloaded once, EPSS asked once for all four",
       sum(u == cves.KEV for u in ASKED) == 1 and sum(u.startswith(cves.EPSS) for u in ASKED) == 1
       and ASKED[[u.startswith(cves.EPSS) for u in ASKED].index(True)].endswith(",".join([K, E, N, O])), str(ASKED))
    ok("…NVD never asked in the batch (the background check does that)", not any(u.startswith(cves.NVD) for u in ASKED))
    ok("…the steps say what happened", any("4 CVEs in 1 request" in t for _, t in steps) and any("0 already known, 4 to fetch" in t for _, t in steps)
       and any("NVD analysis: 0 of 4" in t and "NVD_API_KEY" in t for _, t in steps), str(steps))
    items = [t for k_, t in steps if k_ == "item"]
    ok("…each record's line: CVSS + KEV, not found, the error",
       any(t.startswith(K) and "CVSS 9.8" in t and "ACTIVELY EXPLOITED" in t for t in items)
       and any(t.startswith(N) and "not found on CVE.org" in t for t in items)
       and any(t.startswith(O) and "answered 500" in t for t in items), str(items))
    c = cards[K]
    ok("an exploited CVE: found, exploited, KEV title, EPSS, ADP score named as its source",
       c["found"] and c["exploited"] and c["title"] == f"{K}: ExampleCo Widget Flaw" and c["epss"] == 0.5
       and c["epss_percentile"] == 0.91 and c["cvss"]["score"] == 9.8 and c["cvss"]["source"] == "CVE.org (CISA-ADP)"
       and c["cwes"] == ["CWE-287"] and c["references"] == ["https://example.org/advisory"] and c["ref_source"] == "CVE.org", str(c))
    ok("…the CNA's own CVSS 4.0, title, no KEV", cards[E]["cvss"]["version"] == "4.0" and cards[E]["cvss"]["source"] == "CVE.org (CNA)"
       and not cards[E]["exploited"] and cards[E]["cna_title"] == "Example Gadget overflow")
    ok("…no record on CVE.org (404): not found", cards[N]["found"] is False and cards[N]["sources"] == [])
    ok("…CVE.org failed: not found yet, looked up again later", cards[O]["found"] is False and cards[O]["pending"] is True)
    ok("the answers are kept in the cache file", json.load(open(cpath))["kev"]["version"] == "2099.01.01")

    n0 = len(ASKED)
    ci.lookup_many([K, E])
    ok("a second batch: nothing asked again (KEV for a day, EPSS and CVE.org for a week)", len(ASKED) == n0, str(ASKED[n0:]))
    steps = []
    ci.lookup_many([K], progress=lambda kind, text, done=None: steps.append(text))
    ok("…and says so", any("every score already known" in t for t in steps) and any("1 already known, 0 to fetch" in t for t in steps))

    print("NVD")
    d = ci.nvd(K, fetch=True)
    ok("NVD's record: the Primary CVSS, English text, CWE only, tagged references first, reference count",
       d["cvss"]["score"] == 9.8 and d["description"].startswith("NVD:") and d["cwes"] == ["CWE-287"]
       and d["references"][0] == "https://example.org/patch" and d["reference_count"] == 2 and d["status"] == "Analyzed", str(d))
    ok("…cached: asked once", ci.nvd(K) == d and sum(u.startswith(cves.NVD + K) for u in ASKED) == 1)
    d2 = ci.nvd(E, fetch=True)
    ok("…CVSS 2 with the severity beside the data", d2["cvss"]["version"] == "V2" and d2["cvss"]["severity"] == "MEDIUM", str(d2))
    ok("…404: no record", ci.nvd(N, fetch=True) == {"missing": True})
    ok("…not fetched, nothing cached: None", ci.nvd("CVE-2099-0009", fetch=False) is None)
    c = ci.card(K, fetch=False)
    ok("with NVD's analysis the card names NVD as source of score and references",
       c["nvd"] and c["sources"] == ["NVD", "CVE.org"] and c["cvss"]["source"] == "NVD" and c["ref_source"] == "NVD", str(c))
    ci.calls = [time.time()] * 5
    try:
        ci.nvd("CVE-2099-0010", fetch=True, wait=False); refused = False
    except RuntimeError as exc:
        refused = "30 seconds" in str(exc)
    ok("a sixth NVD request within 30 s is refused when not waiting", refused)
    ci.calls = [time.time() - 30.5] * 5
    ANSWERS[cves.NVD + "CVE-2099-0010"] = {"vulnerabilities": []}
    ok("…waiting: it waits for the slot, then asks", ci.nvd("CVE-2099-0010", fetch=True, wait=True) == {"missing": True} and SLEPT)
    keyed = cves.CveIntel(os.path.join(TMP, "k.json"), api_key=" made-up-key ")
    keyed.calls = [time.time()] * 5
    keyed._nvd_slot(False)
    ok("with an API key, 45 per 30 s", len(keyed.calls) == 6 and keyed.status()["nvd_key"] is True)

    print("Titles and descriptions from the cache")
    t = ci.known_titles()
    ok("KEV's name first, else the CNA's title, else the first sentence", t.get(K) == "ExampleCo Widget Flaw"
       and t.get(E) == "Example Gadget overflow" and N not in t, str(t))
    ok("one title; not a CVE: ''", ci.known_title(E.lower()) == "Example Gadget overflow" and ci.known_title("x") == "")
    ok("description: NVD's, then CISA's short text when it says more",
       ci.known_description(K) == "NVD: Widget lets anyone in. CISA: A made-up flaw in Widget.", ci.known_description(K))
    ok("…CVE.org's when NVD has none; nothing: ''", ci.known_description(E) == "Gadget overflows."
       and ci.known_description("CVE-2099-0999") == "" and ci.known_description("nope") == "")
    ci.cache["kev"]["items"]["CVE-2099-0777"] = {"short": "Only CISA knows."}
    ok("…only CISA's text", ci.known_description("CVE-2099-0777") == "Only CISA knows.")
    try:
        ci.card("bad"); bad = False
    except ValueError:
        bad = True
    ok("a card for something that is no CVE id: refused", bad)
    ok("cards without fetching: from the cache", set(ci.cards([K, "x", E], fetch=False)) == {K, E})
    st = ci.status()
    ok("status: KEV entries, updated, cached counts", st["kev_entries"] == 2 and st["kev_updated"] and st["nvd_cached"] >= 3)

    print("Failures, budget, stop, prefetch, other processes")
    log2 = Log()
    ANSWERS[cves.KEV] = urllib.error.URLError("made-up: no route")
    c2 = cves.CveIntel(os.path.join(TMP, "c2.json"), logger=log2)
    ok("KEV unreachable: an empty catalog, a warning", c2.kev() == {} and log2.lines and "not refreshed" in log2.lines[0])
    n0 = len(ASKED)
    c2.kev()
    ok("…not asked again within 15 minutes", len(ASKED) == n0)
    ANSWERS[cves.EPSS] = 503
    c2.epss(["CVE-2099-0005"])
    ok("EPSS unreachable: a warning, nothing stored", any("EPSS not reached" in x for x in log2.lines) and not c2.cache["epss"])
    ANSWERS[cves.EPSS] = {"data": []}
    ANSWERS[cves.CVEORG.format(year="2099", group="0", id="CVE-2099-0005")] = {"cveMetadata": {}, "containers": {}}
    steps = []
    c2.lookup_many(["CVE-2099-0005"], progress=lambda kind, text, done=None: steps.append(text), budget=1e-9)
    ok("time budget spent: the record is not fetched now", any("time budget spent" in s for s in steps), str(steps))
    n0 = len(ASKED)
    c2.lookup_many(["CVE-2099-0005"], stop=lambda: True)
    ok("stopped: no record fetched", not any("cvelistV5" in u for u in ASKED[n0:]))
    ANSWERS[cves.NVD + "CVE-2099-0005"] = urllib.error.URLError("made-up timeout")
    ANSWERS[cves.NVD + "CVE-2099-0006"] = {"vulnerabilities": [{"cve": {"descriptions": [{"lang": "en", "value": "Six."}]}}]}
    ANSWERS[cves.CVEORG.format(year="2099", group="0", id="CVE-2099-0006")] = 404
    SLEPT.clear()
    n = c2.prefetch(["CVE-2099-0005", "CVE-2099-0006", "junk"])
    ok("prefetch: NVD for each, a failure waits 30 s and is logged", n == 1 and 30 in SLEPT
       and any("NVD look-up of CVE-2099-0005 failed" in x for x in log2.lines), f"{n} {SLEPT}")
    ANSWERS[cves.CVEORG.format(year="2099", group="0", id="CVE-2099-0007")] = 404
    ok("…stopped: nothing more", c2.prefetch(["CVE-2099-0007"], stop=lambda: True) == 0)
    ok("…already in the cache: skipped", c2.prefetch(["CVE-2099-0006"]) == 0)
    # another process wrote newer answers into the file
    other = json.load(open(cpath))
    other["nvd"]["CVE-2099-0888"] = {"t": time.time() + 5, "data": {"description": "From the background check."}}
    other["kev"]["t"] = time.time() + 5
    with open(cpath, "w") as f:
        json.dump(other, f)
    os.utime(cpath, (time.time() + 10, time.time() + 10))
    ci._checked = 0
    ci._refresh()
    ok("another process's newer answers are merged in", ci.cache["nvd"].get("CVE-2099-0888", {}).get("data", {}).get("description")
       == "From the background check.")
    ci._checked = 0
    with open(cpath, "w") as f:
        f.write("not json")
    os.utime(cpath, (time.time() + 20, time.time() + 20))
    ci._refresh()
    ok("…an unreadable file is ignored", "CVE-2099-0888" in ci.cache["nvd"])
    # started with no cache file, then another process (the background check, quarterly.py) writes it first: the next
    # look-up merges it instead of failing (review 2026-11-23: "<=" between a signature and the start value raised)
    fresh_path = os.path.join(TMP, "fresh-start.json")
    late = cves.CveIntel(fresh_path)
    writer = cves.CveIntel(fresh_path)
    writer.cache["nvd"]["CVE-2099-0777"] = {"t": time.time() + 5, "data": {"description": "Written by another process."}}
    writer._save()
    late._checked = 0
    try:
        late._refresh()
        raised = ""
    except Exception as exc:          # noqa: BLE001  (the check reports what was raised)
        raised = f"{type(exc).__name__}: {exc}"
    ok("no cache file at the start, another process writes it first: merged, nothing raised",
       not raised and late.cache["nvd"].get("CVE-2099-0777", {}).get("data", {}).get("description") == "Written by another process.", raised)
    # the file replaced within the same tick by a smaller one is still read (signatures compare only with ==)
    st = os.stat(fresh_path)
    writer.cache["nvd"] = {"CVE-2099-0776": {"t": time.time() + 9, "data": {"description": "Smaller, same tick."}}}
    writer._save()
    os.utime(fresh_path, ns=(st.st_atime_ns, st.st_mtime_ns))
    late._checked = 0
    late._refresh()
    ok("…a smaller file written in the same tick is read too", "CVE-2099-0776" in late.cache["nvd"])
    broken = cves.CveIntel(os.path.join(TMP, "no-such-folder", "c.json"))
    broken._save()
    ok("a cache that cannot be written: no crash", broken.cache["kev"]["items"] == {})
    ANSWERS["https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2099/12xxx/"] = ValueError("not json")
    try:
        broken.cveorg("CVE-2099-12345"); msg = ""
    except RuntimeError as exc:
        msg = str(exc)
    ok("an unreadable answer: 'could not be reached'", msg.startswith("could not be reached"), msg)
    ok("cards with fetching go through the batch", set(broken.cards(["CVE-2099-0002"], fetch=True)) == {"CVE-2099-0002"})

    # ------------------------------------------------------------------ malpedia.py
    print("Malpedia")
    B = malpedia.BASE
    ok("search words: prefix and the words Shadowserver adds are taken off",
       malpedia.Malpedia.needles("android.likely-lumma-stealer-beacon")[:2] == ["android.likely-lumma-stealer-beacon", "lumma"],
       str(malpedia.Malpedia.needles("android.likely-lumma-stealer-beacon")))
    ok("…variants without digits, dashes; nothing under 3 characters", malpedia.Malpedia.needles("elf.mirai-2") ==
       ["elf.mirai-2", "mirai-2", "mirai-", "mirai2", "mirai 2"] and malpedia.Malpedia.needles("ab") == [],
       str(malpedia.Malpedia.needles("elf.mirai-2")))
    ANSWERS.update({
        B + "find/family/elf.examplebot": [],
        B + "find/family/examplebot": [{"name": "elf.examplebot", "alt_names": ["ExBot"]}, {"name": "win.examplebot_loader", "alt_names": []},
                                       {"name": ""}],
        B + "find/family/demo": [{"name": "win.othername", "alt_names": ["Demo"]}],
        B + "find/family/sampleworm": [{"name": "win.thingy", "alt_names": ["x-sampleworm-y"]}],
        B + "get/family/elf.examplebot": {"common_name": "ExampleBot", "description": "A made-up bot.", "alt_names": ["ExBot"],
                                          "urls": [f"https://example.org/{i}" for i in range(15)], "updated": "2099-01-01"},
        B + "get/yara/elf.examplebot": {"tlp_white": [1, 2], "tlp_amber": [3]},
        B + "get/family/win.othername": {"common_name": "Other"},
        B + "get/yara/win.othername": 500,
        B + "find/family/apt-example": [],
        B + "find/family/aptexample": [],
        B + "find/family/apt%20example": [],
        B + "find/actor/aptexample": [],
        B + "find/actor/apt-example": [{"name": "zz", "common_name": "Someone", "synonyms": ["APT Example"]}],
        B + "get/actor/zz": {"value": "Made-up Actor", "description": "A made-up group.",
                             "meta": {"synonyms": ["APT Example"], "country": "ZZ", "refs": ["https://example.org/a"],
                                      "cfr-target-category": ["Government"]}, "families": {"win.b": {}, "win.a": {}}},
        B + "get/actor/nobody": 404,
        B + "get/sample/": 404,
        B + "get/sample/" + "a" * 32: {"family": "elf.examplebot"},
    })
    mp = malpedia.Malpedia("", os.path.join(TMP, "mp.json"))
    ok("no token: switched off", not mp.enabled and malpedia.Malpedia(" t ", os.path.join(TMP, "x.json")).enabled)
    r = mp.lookup("infection", "elf.examplebot")
    ok("a name: the family found by its own name, platform first, its card with YARA counts and 12 references",
       r["family"]["name"] == "ExampleBot" and r["matches"][0]["id"] == "elf.examplebot" and r["matches"][0]["score"] == 105
       and r["family"]["yara"] == {"WHITE": 2, "AMBER": 1} and len(r["family"]["references"]) == 12
       and r["family"]["reference_count"] == 15, str(r)[:400])
    ok("…the loader variant matched as a partial name", any(m["id"] == "win.examplebot_loader" and m["score"] == 60 for m in r["matches"]))
    r = mp.lookup("infection", "demo")
    ok("an alternative name matches at 90; YARA failing leaves an empty count",
       r["matches"][0]["matched_by"] == "alternative name Demo" and r["family"]["yara"] == {}, str(r)[:300])
    m = mp.find("sampleworm")
    ok("…a word inside an alternative name: 40", m and m[0]["score"] == 40, str(m))
    r = mp.lookup("tag", "apt-example")
    ok("no family: an actor by an alias", r["family"] is None and r["actor_match"]["matched_by"] == "threat actor alias APT Example"
       and r["actor"]["name"] == "Made-up Actor" and r["actor"]["families"] == ["win.a", "win.b"]
       and r["actor"]["sectors"] == ["Government"], str(r)[:400])
    ANSWERS[B + "find/actor/apt-example"] = [{"name": "apt-example", "common_name": ""}]
    mp.cache.pop("find/actor/apt-example")
    ok("…or by its own name", mp.find_actor("apt-example")["score"] == 100)
    ANSWERS[B + "find/actor/apt-example"] = [{"name": "q", "common_name": "w", "synonyms": []}]
    mp.cache.pop("find/actor/apt-example")
    ok("…no exact match: none", mp.find_actor("apt-example") is None)
    ok("an actor chosen by id", mp.lookup("actor", "zz")["actor"]["id"] == "zz")
    ok("…unknown (404): none; a bad id: none", mp.actor("nobody") is None and mp.actor("Bad Id!") is None)
    ok("a family chosen by id", mp.lookup("family", "elf.examplebot")["family"]["id"] == "elf.examplebot")
    ok("…a bad family id: none", mp.family("not a family") is None)
    ANSWERS[B + "get/family/win.gone"] = 404
    ok("…unknown family: none", mp.family("win.gone") is None)
    h = "A" * 32
    r = mp.lookup("md5", h)
    ok("a hash: the sample collection, lower-cased", r["kind"] == "sample" and r["found"] and r["hash"] == "a" * 32)
    ok("…a hash in any field is a sample; unknown: not found", mp.lookup("infection", "b" * 40)["found"] is False)
    bad = []
    for f_, v_ in (("md5", "xyz"), ("actor", "Bad Id!"), ("family", "emotet"), ("infection", "x" * 101)):
        try:
            mp.lookup(f_, v_); bad.append(False)
        except ValueError:
            bad.append(True)
    try:
        mp.sample("nothex"); bad.append(False)
    except ValueError:
        bad.append(True)
    ok("values checked before anything is asked: bad hash, actor, family id, too long", all(bad), str(bad))
    ok("an empty value: nothing asked", mp.lookup("infection", "  ")["kind"] == "none")
    n0 = len(ASKED)
    mp.lookup("infection", "elf.examplebot")
    ok("answers cached: Malpedia not asked twice", len(ASKED) == n0)
    ANSWERS[B + "get/family/win.err"] = 503
    ANSWERS[B + "get/family/win.down"] = urllib.error.URLError("made-up")
    errs = []
    for fid in ("win.err", "win.down"):
        try:
            mp.family(fid); errs.append("")
        except RuntimeError as exc:
            errs.append(str(exc))
    ok("errors: 'answered 503', 'could not be reached'", "answered 503" in errs[0] and "could not be reached" in errs[1], str(errs))
    mp.calls = [time.time()] * malpedia.MAX_PER_MINUTE
    try:
        mp.family("win.new"); limited = False
    except RuntimeError as exc:
        limited = "Too many" in str(exc)
    ok("at most 30 look-ups a minute", limited)
    mp.calls = []
    old_max = malpedia.MAX_CACHE
    malpedia.MAX_CACHE = 3
    ANSWERS[B + "get/family/win.fresh"] = {"common_name": "Fresh"}
    ANSWERS[B + "get/yara/win.fresh"] = {}
    mp.family("win.fresh")
    malpedia.MAX_CACHE = old_max
    ok("the cache is bounded: the oldest answers dropped", len(mp.cache) == 3 and "get/family/win.fresh" in mp.cache
       and len(json.load(open(os.path.join(TMP, "mp.json")))) == 3)
    ok("…and read back by a new instance", len(malpedia.Malpedia("", os.path.join(TMP, "mp.json")).cache) == 3)

    # ------------------------------------------------------------------ asn_lookup.py + netypes.py
    print("Networks (AS numbers)")
    ok("holder names cleaned", asn_lookup.clean("EXAMPLE-AS, GH") == "Example"
       and asn_lookup.clean("EXNET-AS - Example Networks, GH") == "Example Networks" and asn_lookup.clean("") == "")
    ok("types from names", [asn_lookup.classify(64500, x) for x in ("Example University", "Example Bank Ltd", "Example Telecom", "", "Zzz")]
       == ["education", "finance", "isp", "unknown", "unknown"])
    ok("…private AS numbers are private", asn_lookup.classify(64512, "Example Telecom") == "private"
       and asn_lookup.classify(4200000001, "") == "private")
    ok("look-up needed: missing, failed, unknown source; never for reviewed",
       asn_lookup.needs_lookup(None) and asn_lookup.needs_lookup({"holder": "lookup failed: X"})
       and asn_lookup.needs_lookup({"source": "unknown"}) and not asn_lookup.needs_lookup({"source": "unknown", "reviewed": True})
       and not asn_lookup.needs_lookup({"source": "ripestat", "holder": "X"}))
    tries = {"n": 0}

    def ripe(url):
        tries["n"] += 1
        q = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
        res = q["resource"][0]
        if res == "AS64500" and tries["n"] == 1:
            return 503
        if res == "AS64502":
            return 500
        return {"data": {"holder": {"AS64500": "EXNET-AS - Example Networks, GH", "AS64501": "EXAMPLE-UNI Example University, GH"}.get(res, "")}}
    ANSWERS["https://stat.ripe.net/"] = ripe
    ANSWERS["https://www.peeringdb.com/"] = {"data": [{"asn": 64500, "name": "Example Net", "info_types": ["Cable/DSL/ISP"]},
                                                      {"asn": 64503, "name": "", "info_type": "Content"}]}
    SLEPT.clear()
    ok("RIPEstat: retried after 503, then the holder", asn_lookup.ripestat("64500") == "EXNET-AS - Example Networks, GH" and 5 in SLEPT)
    try:
        asn_lookup.ripestat("64502"); raised = False
    except urllib.error.HTTPError:
        raised = True
    ok("…a 500: raised at once", raised)
    pdb = asn_lookup.peeringdb(["64500", "64503"])
    ok("PeeringDB: name and type", pdb == {"64500": {"name": "Example Net", "type": "isp"}, "64503": {"name": "", "type": "hosting"}}, str(pdb))
    ddir = os.path.join(TMP, "asn")
    os.makedirs(ddir)
    reg_path = os.path.join(ddir, "asns.json")
    asn_lookup.save(reg_path, {"asns": {"64504": {"name": "Locked", "reviewed": True, "source": "manual", "type": "bank"}}})
    netypes.add(ddir, "Example Sector", "Partner")
    seen = []
    st = asn_lookup.identify(reg_path, {"64500": 30, "64501": 20, "64502": 10, "64504": 5, "0": 99},
                             meta={"64500": {"country": "GH", "role": "constituent"}}, progress=seen.append)
    reg = asn_lookup.load(reg_path)["asns"]
    ok("identify: looked up the unknown ones, the reviewed one kept, AS0 skipped",
       st["state"] == "done" and st["added"] == 2 and st["failed"] == 1 and st["known"] == 1
       and reg["64504"]["name"] == "Locked" and "0" not in reg, str(st))
    ok("…PeeringDB's name and type first, RIPEstat's holder", reg["64500"]["name"] == "Example Net" and reg["64500"]["type"] == "isp"
       and reg["64500"]["source"] == "peeringdb+ripestat" and reg["64500"]["country"] == "GH")
    ok("…a failed look-up is marked and tried again next time", reg["64502"]["source"] == "failed"
       and asn_lookup.needs_lookup(reg["64502"]) and "1 failed" in st["message"])
    ok("…demo aliases given, busiest network first", reg["64500"]["demo_alias"] == "Telco 1" and reg["64501"]["demo_alias"].startswith("Institution")
       and reg["64504"]["demo_alias"] == "Institution 2", str({a: v.get("demo_alias") for a, v in reg.items()}))
    ok("…progress reported with a short log", seen and len(seen[-1]["log"]) <= 12)
    st = asn_lookup.identify(reg_path, {"64500": 1, "64501": 1})
    ok("nothing to look up: says so", st["message"] == "Every network is already identified.")
    ANSWERS["https://www.peeringdb.com/"] = urllib.error.URLError("made-up")
    stop = threading.Event()
    stop.set()
    st = asn_lookup.identify(reg_path, {"64505": 1}, progress=seen.append, stop=stop)
    ok("PeeringDB down and stopped at once: 'Stopped.'", st["state"] == "stopped" and st["message"] == "Stopped."
       and any("names from RIPEstat only" in x for x in seen[-1]["log"]), str(st))
    ANSWERS["https://www.peeringdb.com/"] = {"data": []}
    many = {str(64510 - i): 1 for i in range(10)}
    st = asn_lookup.identify(os.path.join(ddir, "many.json"), many)
    ok("ten look-ups: saved as it goes", st["done"] == 10 and len(asn_lookup.load(os.path.join(ddir, "many.json"))["asns"]) == 10)
    ok("an unreadable registry reads as empty", asn_lookup.load(os.path.join(ddir, "nothing.json")) == {"asns": {}})
    job = asn_lookup.IdentifyJob(os.path.join(ddir, "job.json"))
    gate = threading.Event()

    def slow_collect():
        gate.wait(10)
        return {"64509": 1}, {}
    ok("the job: started once", job.start(slow_collect) is True)
    second = job.start(lambda: ({}, {}))
    gate.set()
    job.thread.join(10)
    ok("…not twice at the same time; done", second is False and job.status["state"] == "done" and job.status.get("started"), str(job.status))

    def boom():
        raise RuntimeError("made-up collect failure")
    job.start(boom)
    job.thread.join(10)
    ok("…a failing job says why", job.status["state"] == "failed" and "made-up collect failure" in job.status["message"])
    asns = {"1": {"type": "example-sector"}, "2": {"type": "nonexistent"}}
    asn_lookup.assign_aliases(asns, ddir)
    ok("aliases use the site's own types", asns["1"]["demo_alias"] == "Partner 1" and asns["2"]["demo_alias"] == "Network 1", str(asns))

    print("Network types")
    nd = os.path.join(TMP, "nt")
    os.makedirs(nd)
    ok("built-in types", "isp" in netypes.keys(nd) and netypes.labels(nd)["bank"] == "Bank" and netypes.aliases(nd)["school"] == "Institution")
    key = netypes.add(nd, "  Space   Agency ", "agency", by="Grace", today="2099-01-01")
    ts = netypes.all_types(nd)
    ok("an added type: key, label, alias title-cased, after the built-in ones", key == "space-agency"
       and ts[-1] == {"key": "space-agency", "label": "Space Agency", "alias": "Agency", "builtin": False, "by": "Grace", "added": "2099-01-01"})
    refused = []
    for lab, al in (("Space Agency", ""), ("bank", ""), ("x", ""), ("<b>bad</b>", ""), ("Fine Name", "Not 1"), ("!!", "")):
        try:
            netypes.add(nd, lab, al); refused.append(False)
        except ValueError:
            refused.append(True)
    ok("refused: an existing label or key, too short, < >, a bad alias word, no letters", all(refused), str(refused))
    with open(os.path.join(nd, "network_types.json"), "w") as f:
        f.write("{broken")
    ok("an unreadable file: built-in types still; adding starts a new file",
       len(netypes.all_types(nd)) == len(netypes.BUILTIN) and netypes.add(nd, "Second Sector", "") == "second-sector"
       and netypes.aliases(nd)["second-sector"] == "Organisation")
    # the same tick (filesig.py): a file rewritten with its modification time put back exactly is still seen as changed
    tp = os.path.join(nd, "network_types.json")
    st = os.stat(tp)
    netypes.all_types(nd)
    with open(tp, "w", encoding="utf-8") as f:
        f.write("{broken again}")
    os.utime(tp, ns=(st.st_atime_ns, st.st_mtime_ns))
    ok("a file rewritten within the same clock tick (same modification time) is still read again",
       os.stat(tp).st_mtime_ns == st.st_mtime_ns and len(netypes.all_types(nd)) == len(netypes.BUILTIN))

    # ------------------------------------------------------------------ geo.py
    print("Places (geocoder)")
    gpath = os.path.join(TMP, "geocache.json")
    with open(gpath, "w") as f:
        json.dump({"GH|OLD|": None, "GH||": [-1.0, 7.9]}, f)
    g = geo.Geocoder("made-up-map-key", gpath)
    ok("old failed look-ups stored as 'no location' are forgotten once", "GH|OLD|" not in g.cache and g.cache.get("__v2__"))
    found = {"features": [{"geometry": {"coordinates": [-0.18661, 5.60372]}}]}

    def mapbox(url):
        q = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
        if q["q"][0] == "ACCRA, GREATER ACCRA":
            return found
        if q["q"][0] == "NOWHERE":
            return {"features": []}
        if q["q"][0] == "ASHANTI":
            return {"features": [{"geometry": {"coordinates": [-1.6, 6.7]}}]}
        if q["q"][0] == "ZZ":
            return {"features": []}
        return 500
    ANSWERS[geo.GEOCODE_URL] = mapbox
    ok("a city: found, rounded", g.lookup("gh", "GREATER ACCRA", "ACCRA") == [-0.1866, 5.6037])
    ok("…asked with the country and the key, only Mapbox", ASKED[-1].startswith(geo.GEOCODE_URL) and "country=gh" in ASKED[-1])
    n0 = len(ASKED)
    ok("…cached: not asked again", g.lookup("GH", "greater accra", "accra") == [-0.1866, 5.6037] and len(ASKED) == n0)
    ok("a region alone", g.lookup("GH", "ASHANTI", "") == [-1.6, 6.7])
    ok("a place Mapbox does not know: stored as none, the country instead", g.lookup("GH", "", "NOWHERE") == [-1.0, 7.9]
       and g.cache["GH||NOWHERE"] is None)
    ok("…asked again later: the country, from the cache", g.lookup("GH", "", "NOWHERE") == [-1.0, 7.9])
    ok("no country: none", g.lookup("", "X", "Y") is None)
    ok("a country only", g.lookup("ZZ", "", "") is None and g.cache["ZZ||"] is None)
    ok("a failed look-up: not stored, the country instead, then a pause", g.lookup("GH", "", "FAILTOWN") == [-1.0, 7.9]
       and "GH||FAILTOWN" not in g.cache and g._down_until > time.time())
    n0 = len(ASKED)
    ok("…during the pause nothing is asked", g.lookup("GH", "", "OTHERTOWN") == [-1.0, 7.9] and len(ASKED) == n0)
    ok("…the country unknown and the pause on: none", g.lookup("YY", "", "") is None and "YY||" not in g.cache)
    g._down_until = 0
    for i in range(30):
        g._store(f"GH||T{i}", [0, 0])
    ok("stored places are written after 25 new ones (not each one)", "GH||T0" in json.load(open(gpath))
       and "GH||T29" not in json.load(open(gpath)))
    g.flush()
    g2 = geo.Geocoder(None, gpath)
    ok("without a key nothing is asked; the file is read back", g2.lookup("GH", "", "NEW") == [-1.0, 7.9] and "GH||T29" in g2.cache)
    with open(gpath, "w") as f:
        f.write("{bad")
    ok("an unreadable cache: starts empty", geo.Geocoder("k", gpath).cache == {})
finally:
    urllib.request.urlopen, time.sleep = real_urlopen, real_sleep
    import shutil
    shutil.rmtree(TMP, ignore_errors=True)

outside = [u for u in ASKED if not u.startswith(tuple(ANSWERS))]
ok("every request went to the fake, none anywhere else", not outside, str(outside))
print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
