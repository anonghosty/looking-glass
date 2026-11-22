#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""The PDFs' References section and the advisory preview's marks (the user, 2026-11-18), with made-up names and links
only, no database:
1. order: defined names first, by criticality (critical, high, medium, low, then "not rated"); an actively exploited
   CVE keeps its CVSS level, is flagged "Actively exploited" with its CVSS score, and comes first within its level;
   the Shadowserver reports last, ordered by their own severity;
2. each name's links: its own page first, each once, at most the PDF's number, the rest counted;
3. criticality from records: the highest severity of the records that carry a name (infection, issue, CVE in an issue
   or a tag, the issue a tag stands for); a level is never invented;
4. the definition cards carry no references any more (the References section has them);
5. the References pages: every group drawn, its flag beside it, every address in full and linked;
6. the advisory preview: who and when in the header and the footer, and a watermark picture behind the content; the
   generated advisory never.
Run: .venv/bin/python tests/check_pdf_refs.py"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("LG_QUIET", "1")
import tempfile  # noqa: E402
import pdf_refs as R  # noqa: E402
R.KNOWN["path"] = os.path.join(tempfile.mkdtemp(), "name_levels.json")      # never the installation's own files
R.SEEN["path"] = os.path.join(tempfile.mkdtemp(), "name_kinds.json")        # (2026-11-19: its made-up names reached the map)
_REAL_KINDS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "name_kinds.json")
_REAL_BEFORE = os.path.getmtime(_REAL_KINDS) if os.path.exists(_REAL_KINDS) else None

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info else ""), flush=True)


U = "https://example.org/"
cards = [
    ("lowbot", {"url": U + "lowbot", "references": [U + "a", U + "b"]}),
    ("CVE-2099-0002", {"kind": "cve", "cvss": {"score": 8.1, "severity": "HIGH"}, "nvd_url": U + "nvd2"}),
    ("CVE-2099-0001", {"kind": "cve", "cvss": {"score": 7.5, "severity": "HIGH"}, "exploited": True, "nvd_url": U + "nvd1",
                       "references": [U + "nvd1", U + "x1"]}),
    ("Exposed admin panel", {"curated": True, "curated_references": [U + "panel"]}),
    ("quietbot", {"found": True, "url": U + "quietbot", "references": [U + f"r{i}" for i in range(9)]}),
    ("no-links", {"curated": True}),
    ("unrated thing", {"curated": True, "curated_references": [U + "u"]}),
]
levels = {"lowbot": "low", "Exposed admin panel": "medium", "quietbot": "critical"}
reports = [{"title": "Report Low", "url": U + "rl", "severity": "low"}, {"title": "Report Critical", "url": U + "rc", "severity": "critical"},
           {"title": "Report Info", "url": U + "ri", "severity": "info"}, {"title": "No page", "url": "", "severity": "high"}]
gs = R.groups(cards, levels, reports)
names = [g["title"] for g in gs if g["kind"] == "name"]

print("1. Order and flags")
ok("defined names first, the most critical first; an exploited CVE first within its level; not rated last",
   names == ["quietbot", "CVE-2099-0001", "CVE-2099-0002", "Exposed admin panel", "lowbot", "unrated thing"], str(names))
ok("a name with no link is left out (nothing to list)", "no-links" not in names)
cve1 = next(g for g in gs if g["title"] == "CVE-2099-0001")
ok("an actively exploited CVE keeps its CVSS level, with its score and the 'Actively exploited' flag (choice A)",
   cve1["level"] == "high" and cve1["flags"] == ["CVSS 7.5", "Actively exploited"], str(cve1))
ok("…a CVE that is not exploited: its level and score only",
   next(g for g in gs if g["title"] == "CVE-2099-0002")["flags"] == ["CVSS 8.1"])
ok("a name without any severity is 'not rated', never given one", next(g for g in gs if g["title"] == "unrated thing")["level"] == "")
rep = gs[-1]
ok("the Shadowserver reports come last, as one group", rep["kind"] == "reports" and rep["title"] == "Shadowserver reports")
ok("…ordered by Shadowserver's severity, a report without a page left out",
   [r["title"] for r in rep["items"]] == ["Report Critical", "Report Low", "Report Info"], str([r["title"] for r in rep["items"]]))
ok("…Shadowserver's 'info' shown as INFO (its own word), not as 'not rated'", rep["items"][2]["level"] == "info")
ok("a CVSS score alone gives the level when no severity word is given", R.level(9.8) == "critical" and R.level(5.0) == "medium" and R.level(0) == "")

print("2. Each name's links")
qb = next(g for g in gs if g["title"] == "quietbot")
ok("its own page first, at most 6 on the card PDFs, the rest counted", qb["refs"][0] == U + "quietbot" and len(qb["refs"]) == 6 and qb["more"] == 4,
   f"{len(qb['refs'])} + {qb['more']}")
ok("…and 'more on the Malpedia page' for a Malpedia entry", qb["more_where"] == "Malpedia")
ok("each link once (the NVD page given twice is listed once)", next(g for g in gs if g["title"] == "CVE-2099-0001")["refs"] == [U + "nvd1", U + "x1"])
g_cve = R.groups([("CVE-2023-48795", {"kind": "cve", "found": True, "references": [f"https://example.org/c{i}" for i in range(9)]})], {}, [])
ok("a CVE's extra references are 'on the NVD page', even when it is found (2026-11-18: read Malpedia)",
   g_cve[0]["more"] == 3 and g_cve[0]["more_where"] == "NVD", g_cve[0].get("more_where"))
ok("the analysis report keeps its 10", len(next(g for g in R.groups(cards, levels, [], shown=10) if g["title"] == "quietbot")["refs"]) == 10)

print("3. Criticality from the records")
recs = [{"infection": "quietbot", "severity": "medium"}, {"infection": "quietbot", "severity": "critical"},
        {"issues": ["Exposed admin panel", "cve-2099-0003"], "severity": "high"},
        {"tags": "router,cve-2099-0004", "severity": "low"}, {"infection": "noisy", "severity": "info"}]
lv = R.levels_from_records(recs)
ok("the highest severity of the records that carry a name", lv.get("quietbot") == "critical", str(lv))
ok("issues and the CVEs named in issues and tags, by their numbers",
   lv.get("Exposed admin panel") == "high" and lv.get("CVE-2099-0003") == "high" and lv.get("CVE-2099-0004") == "low", str(lv))
ok("'info' is Shadowserver's lowest level, kept as it is", lv.get("noisy") == "info")
ok("a word that is no severity (empty, unknown) is not rated, never a level", R.level("") == "" and R.level("unknown") == "")


class Day:
    def __init__(self, ev, start):
        self.events, self.start, self.serial = ev, start, 0


days = [Day(recs[:2], 1), Day(recs[2:], 2)]
ok("the days' records give the same levels, kept while the days are the same",
   R.day_levels(days) == lv and R.day_levels(days) is R.day_levels(days))
R.DAYS.clear()
ok("no days known (a tool, a check): no levels, never an error", R.platform_levels("Network communications") == {})
# a name the PDF's own records do not carry (an infection its devices showed in another report; a review kept before
# severities were kept, 2026-11-18: m0yv read "not rated"): the days in memory of both platforms give its level
R.DAYS.update(comms=lambda: [Day([{"infection": "m0yv", "severity": "critical"}], 3)], services=lambda: [Day([], 4)])
g_m = R.groups([("m0yv", {"found": True, "url": U + "m0yv"})], {}, [])
ok("a name not in the PDF's records: its level from the days in memory (both platforms)", g_m[0]["level"] == "critical", str(g_m[0]))
R.DAYS.clear()
# …and once its days have left memory: remembered (2026-11-18: m0yv, kept with an earlier review, read "not rated")
g_r = R.groups([("m0yv", {"found": True, "url": U + "m0yv"})], {}, [])
known = json.load(open(R.KNOWN["path"])) if os.path.exists(R.KNOWN["path"]) else {}
ok("a name whose days have left memory keeps its level (remembered: names and levels only)",
   g_r[0]["level"] == "critical" and known.get("m0yv") == "critical" and all(isinstance(v, str) for v in known.values()), str(known)[:120])
R.remember({"m0yv": "low"})
ok("…the most severe ever seen is kept (a later 'low' does not lower it)", json.load(open(R.KNOWN["path"])).get("m0yv") == "critical")
tmp = tempfile.mkdtemp(); os.makedirs(os.path.join(tmp, "data"))
json.dump({"reports": {"event4_sinkhole": {"title": "Sinkhole Events", "url": "https://www.shadowserver.org/x/sinkhole-events-report/",
                                           "severity": "critical"}}}, open(os.path.join(tmp, "data", "report_map_snapshot.json"), "w"))
ok("a report is known by its page, whatever name the PDF gives it (2026-11-18: 'Sinkhole Events Report' read not rated)",
   R.severity_by_url("https://www.shadowserver.org/x/sinkhole-events-report", tmp) == "critical"
   and R.severity_by_url("https://example.org/other", tmp) == "")

print("3b. Learned once from every report (name_levels_catchup.py)")
import name_levels_catchup as C  # noqa: E402
import index_refresh  # noqa: E402


class Coll:
    def __init__(self, docs):
        self.docs, self.asked = docs, []

    def find(self, q, proj):
        self.asked.append(proj)
        out = [{k: v for k, v in d.items() if k in proj} for d in self.docs]
        return type("Cur", (), {"batch_size": lambda s, n: iter(out)})()


old_day = [{"infection": "oldbot", "severity": "critical", "ip": "192.0.2.9"}] * 3 + [{"issues": ["Old issue"], "severity": "medium", "ip": "192.0.2.8"}]
fake = {"event4_sinkhole_http": Coll(old_day), "scan_http": Coll([{"tags": "cve-2099-0009", "severity": "high"}])}
base = tempfile.mkdtemp()
r = C.catch_up(fake, list(fake), base, pause=0)
known = json.load(open(R.KNOWN["path"]))
ok("every report read once: a name only on old days gets its level (m0yv's case)", known.get("oldbot") == "critical" and known.get("Old issue") == "medium"
   and known.get("CVE-2099-0009") == "high" and r["records"] == 5, str(r))
ok("…only infection, issues, tags and severity are read, never an address",
   all(set(p) == {"infection", "issues", "tags", "severity", "_id"} and p["_id"] == 0 for c in fake.values() for p in c.asked)
   and not any("192.0.2" in str(v) or "192.0.2" in k for k, v in known.items()))
ok("…it marks itself done, and then never starts again", C.is_done(base))
was = index_refresh.SERVING
try:
    index_refresh.SERVING = True
    os.environ["NAME_LEVELS_DELAY_S"] = "1"
    ok("…a start after it is done: not started", not C.install(None, {"db": fake, "collections": lambda: list(fake), "base_dir": base})["started"])
    base2 = tempfile.mkdtemp()
    os.environ["NAME_LEVELS_DELAY_S"] = "0"
    ok("NAME_LEVELS_DELAY_S 0: never started", not C.install(None, {"db": fake, "collections": lambda: list(fake), "base_dir": base2})["started"])
finally:
    index_refresh.SERVING = was
    os.environ.pop("NAME_LEVELS_DELAY_S", None)
ok("in a check or a tool (not the running service): never started",
   not C.install(None, {"db": fake, "collections": lambda: list(fake), "base_dir": tempfile.mkdtemp()})["started"])

print("4-6. The PDFs")
import combo_pdf as CP  # noqa: E402
said, pills, links, images = [], [], [], []


def doc(meta=None):
    d = CP.AnalystDoc({"platform_label": "Publicly accessible services", "scope": "made-up", "header": "h", **(meta or {})})
    t0, p0, l0, i0 = d.text, d.pill, d.c.linkURL, d.c.drawImage
    d.text = lambda x, y, t, *a, **k: (said.append(str(t)), t0(x, y, t, *a, **k))[1]
    d.pill = lambda x, y, t, *a, **k: (pills.append(str(t)), p0(x, y, t, *a, **k))[1]
    d.c.linkURL = lambda u, *a, **k: (links.append(u), l0(u, *a, **k))[1]
    d.c.drawImage = lambda *a, **k: (images.append(1), i0(*a, **k))[1]
    return d


d1 = doc()
d1.new_page("Explained")
d1.explanation(30, 500, 360, "quietbot", cards[4][1], "1 of 2 devices", False)
ok("a definition card carries no references any more", not any(U in s or "REFERENCES" == s for s in said), [s for s in said if U in s][:2])
said.clear(); pills.clear(); links.clear()
R.draw(d1, gs, "The sources behind this report.")
order = [s for s in said if s in names or s in ("Shadowserver reports", "Report Critical", "Report Low", "Report Info")]
ok("the References pages draw every group in its order", order == names + ["Shadowserver reports", "Report Critical", "Report Low", "Report Info"], str(order))
ok("…each with its criticality flag and the exploited CVE's flags",
   pills.count("CRITICAL") >= 2 and "NOT RATED" in pills and "Actively exploited" in pills and "CVSS 7.5" in pills, str(pills[:10]))
long_ = "https://example.org/" + "x" * 300
said.clear(); links.clear()
R.draw(d1, R.groups([("longname", {"url": long_})], {}, []), "intro")
joined = "".join(s.strip() for s in said if s.strip().startswith(("1. https", "xxx")) or (s.strip() and set(s.strip()) == {"x"}))
ok("a long address is drawn in full over several lines, every line a link", joined == "1. " + long_ and links.count(long_) >= 2,
   f"{links.count(long_)} linked lines")
d1.done()

said.clear(); images.clear()
pv = doc({"advisory": {"tlp": "TLP:AMBER", "preview": {"who": "Grace Mensah", "at": "2026-11-19 09:14 UTC", "ref": "ADV-2026-009"}}})
pv.new_page("Advisory"); pv.new_page("References"); pv.footer()
marks = [s for s in said if s.startswith("PREVIEW · NOT FOR DISTRIBUTION · Grace Mensah · 2026-11-19 09:14 UTC · ADV-2026-009")]
ok("the preview: who and when in the header of every page and in the footer", len(marks) >= 3, f"{len(marks)} lines")
ok("…and a watermark picture behind every page's content", len(images) == 2, f"{len(images)} pictures")
said.clear(); images.clear()
gen = doc({"advisory": {"tlp": "TLP:AMBER"}})
gen.new_page("Advisory"); gen.footer()
ok("the generated advisory: no preview mark, no watermark", not any("PREVIEW" in s for s in said) and not images)

ok("the installation's own name files were never written by this check",
   (os.path.getmtime(_REAL_KINDS) if os.path.exists(_REAL_KINDS) else None) == _REAL_BEFORE)

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {fails}" if fails else ""))
sys.exit(1 if fails else 0)
