# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""The References section of every PDF (the user, 2026-11-18): the references leave the definition cards and are listed
at the end, one group per defined name (infection, issue, CVE), then the Shadowserver reports, everything ordered by
criticality and flagged with it. One function for every PDF (advisory, combination, analysis and Executive reports),
so they order and flag alike.

Criticality, each from where it is known; nothing is given a level it does not have ("not rated", last):
* a CVE: the CVSS severity NVD gives it; one CISA lists as actively exploited keeps that level, carries an
  "Actively exploited" flag and its CVSS score, and comes first within its level (the user's choice A, 2026-11-18);
* an infection or an issue: the highest severity Shadowserver gave the records that carry it in this report;
* a Shadowserver report: the severity Shadowserver gives that report type (its report definitions).
"""
import json
import os
import filesig  # noqa: E402

# Shadowserver's own scale, "info" its lowest (an inventory report): shown as Shadowserver says it, never as "not rated"
LEVELS = ("critical", "high", "medium", "low", "info")
WORD = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", "info": "Info", "": "Not rated"}
REFS_SHOWN = 6                # links listed per name at most (as on the cards); the rest are on its own page (Malpedia, NVD)


def level(v):
    """A severity word or a CVSS score as one of LEVELS, or "" when it is none of them (info, unknown, empty)."""
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        return "critical" if v >= 9 else "high" if v >= 7 else "medium" if v >= 4 else "low" if v > 0 else ""
    s = str(v or "").strip().lower()
    return s if s in LEVELS else ""


def highest(values):
    """The most severe of several severity words ("" when none is a level)."""
    got = [level(v) for v in values]
    return next((lv for lv in LEVELS if lv in got), "")


def _as_list(v):
    if isinstance(v, str):
        return [x.strip() for x in v.split(",") if x.strip()]
    return [str(x) for x in (v or []) if str(x).strip()]


def lift(levels, name, sev):
    """Keep the most severe level seen for a name in {name: level}."""
    lv = level(sev)
    if name and lv and (name not in levels or LEVELS.index(lv) < LEVELS.index(levels[name])):
        levels[name] = lv


def levels_from_records(records, levels=None, kinds=None):
    """{name: highest severity} over records, for every name a record carries: its infection, its issues (a CVE by its
    number), the CVEs in its tags and the issues its tags stand for (issue_tags.py, as the advisory reads them).
    kinds: a dict that also learns every name the records carry, rated or not, as "Infection" or "Issue" (the severity
    map lists the names no record rates too)."""
    import re
    import issue_tags
    levels = {} if levels is None else levels
    seen = (lambda n, k: kinds.setdefault(n, k) if n else None) if kinds is not None else (lambda n, k: None)
    for e in records or []:
        sev = e.get("severity")
        inf = e.get("infection")
        lift(levels, inf, sev)
        seen(inf if isinstance(inf, str) else None, "Infection")
        for i in _as_list(e.get("issues")):
            cv = re.search(r"CVE-\d{4}-\d{4,7}", i, re.I)
            lift(levels, cv.group(0).upper() if cv else i, sev)
            seen(cv.group(0).upper() if cv else i, "Issue")
        tags = _as_list(e.get("tags"))
        for t in tags:
            cv = re.search(r"CVE-\d{4}-\d{4,7}", t, re.I)
            if cv:
                lift(levels, cv.group(0).upper(), sev)
                seen(cv.group(0).upper(), "Issue")
        for t in issue_tags.split(tags)[0]:
            lift(levels, t, sev)
            seen(t, "Issue")
    return levels


def refs_of(x_):
    """A name's sources: its own page first (Malpedia, NVD), then its references, each once (as the cards had them)."""
    seen, out = set(), []
    for u in [x_.get("url"), x_.get("nvd_url"), x_.get("cveorg_url"), x_.get("kev_url")] + list(x_.get("references") or []) \
            + list(x_.get("curated_references") or []):
        if isinstance(u, str) and u.startswith(("http://", "https://")) and u not in seen:
            seen.add(u); out.append(u)
    return out


def _order(lv, first, i):
    return (LEVELS.index(lv) if lv in LEVELS else len(LEVELS), 0 if first else 1, i)


def groups(explained, record_levels=None, reports=(), shown=REFS_SHOWN):
    """The References section, in order: [{"kind": "name" | "reports", "title", "level", "flags": [...], "refs": [urls],
    "more": n, "items": [...]}].
    explained: [(name, card)] as the PDF explains them (card: the definition / Malpedia / CVE entry);
    record_levels: {name: highest record severity} for infections and issues (from the report's own records);
    reports: [{"title", "url", "severity"}] the Shadowserver reports the PDF draws on;
    shown: links listed per name (each PDF keeps the number it showed before: 6 on the cards, 10 in the analysis report)."""
    record_levels = record_levels or {}
    named = []
    for i, (name, x_) in enumerate(explained or []):
        refs = refs_of(x_ or {})
        if not refs:
            continue
        flags, first = [], False
        if (x_ or {}).get("kind") == "cve":
            cv = (x_ or {}).get("cvss") or {}
            lv = level(cv.get("severity")) or level(cv.get("score"))
            if cv.get("score") is not None:
                flags.append(f"CVSS {cv['score']}")
            if (x_ or {}).get("exploited") or (x_ or {}).get("kev"):
                flags.append("Actively exploited"); first = True
        else:
            # the PDF's own records first; else the days in memory of both platforms (a name its devices showed in
            # another report, a review kept before severities were kept): the same rule, never an invented level
            lv = level(record_levels.get(name)) or level(all_levels().get(name))
            if not lv:
                # a name no record rates: a researcher's rating from the severity map (severity_map.py), said as such
                lv = researcher_level(name)
                if lv:
                    flags.append("Researcher's rating")
        named.append(({"kind": "name", "title": str(name), "level": lv, "flags": flags, "refs": refs[:shown],
                       "more": max(0, len(refs) - shown),
                       # a CVE's are on NVD's page even when it is "found" (2026-11-18: read "on the Malpedia page")
                       "more_where": "NVD" if (x_ or {}).get("kind") == "cve" else "Malpedia" if (x_ or {}).get("found") else "source"},
                      _order(lv, first, i)))
    out = [g for g, _ in sorted(named, key=lambda t: t[1])]
    reps = [({"title": str(r.get("title") or ""), "url": r.get("url") or "", "level": level(r.get("severity")),
              "where": str(r.get("where") or "")}, i)
            for i, r in enumerate(reports or []) if r.get("url")]
    if reps:
        items = [r for r, _ in sorted(reps, key=lambda t: _order(t[0]["level"], False, t[1]))]
        out.append({"kind": "reports", "title": "Shadowserver reports", "level": "", "flags": [], "refs": [], "more": 0,
                    "items": items})
    return out


# ------------------------------------------------------------------ the Shadowserver reports a PDF draws on
_SNAP = {}


def _snapshot(base_dir):
    p = os.path.join(base_dir, "data", "report_map_snapshot.json")
    try:
        m = filesig.sig(p)
    except OSError:
        return {}
    if _SNAP.get(p, (None,))[0] != m:
        try:
            with open(p, encoding="utf-8") as fh:
                _SNAP[p] = (m, (json.load(fh) or {}).get("reports") or {})
        except (OSError, ValueError):
            _SNAP[p] = (m, {})
    return _SNAP[p][1]


def report_entries(names, base_dir=None):
    """[{"title", "url", "severity", "where"}] for report keys or titles, each once, from the report map snapshot (the
    source the advisory already reads: titles, shadowserver.org pages and Shadowserver's severity per report type)."""
    reps, out, seen = _snapshot(base_dir or os.path.dirname(os.path.abspath(__file__))), [], set()
    try:
        from report_map import sibling
    except Exception:                                    # noqa: BLE001
        sibling = (lambda s: s)
    for n in names or []:
        n = str(n or "")
        key = next((k for k in (n, sibling(n), "scan_" + n, "event4_" + n, "scan6_" + n) if k in reps), None)
        if key is None:
            key = next((k for k, e in reps.items() if e.get("title") == n), None)
        e = reps.get(key) or {}
        if not e.get("url") or key in seen:
            continue
        seen.add(key)
        out.append({"title": e.get("title") or n, "url": e["url"], "severity": e.get("severity") or "",
                    "where": " · ".join(x for x in (e.get("section"), e.get("group")) if x)})
    return out


# ------------------------------------------------------------------ drawn on the canvas PDFs (combination, advisory,
# Executive): one page flow, a group heading with its criticality flag, then its numbered links
def draw(doc, gs, intro, title="References"):
    """The References pages on a canvas document (executive_pdf.Doc and its children): every group, never cut."""
    if not gs:
        return
    from reportlab.lib.utils import simpleSplit
    from executive_pdf import AMBER, BLUE, DIM, M, MUTE, RED, SLATE, TXT, W
    from reportlab.lib.colors import HexColor
    colour = {"critical": RED, "high": AMBER, "medium": BLUE, "low": SLATE, "info": SLATE}
    link = HexColor("#8fb4ff")
    y = doc.new_page(title)
    bottom = 40

    def need(h):
        nonlocal y
        if y - h < bottom:
            y = doc.new_page(f"{title} (continued)")

    for ln in simpleSplit(doc.s(intro), doc.F["r"], 9.2, W - 2 * M):
        doc.text(M, y - 9, ln, 9.2, DIM); y -= 13
    y -= 6

    def heading(text, lv, flags, size=10.5):
        nonlocal y
        need(30)
        doc.text(M, y - 11, text, size, TXT, True)
        x = M + doc.c.stringWidth(doc.s(text), doc.F["b"], size) + 10
        x = doc.pill(x, y - 10, WORD[lv].upper(), colour.get(lv, SLATE), 7.2)
        for f in flags:
            x = doc.pill(x, y - 10, f, RED if f == "Actively exploited" else SLATE, 7.2)
        y -= 22

    def wrap(text, width, size):
        """A long address breaks anywhere and goes on, never cut (it has no spaces to wrap at)."""
        out, line = [], ""
        for ch in doc.s(text):
            if line.strip() and doc.c.stringWidth(line + ch, doc.F["r"], size) > width:
                out.append(line); line = "    " + ch
            else:
                line += ch
        return out + ([line] if line.strip() else [])

    def urls(refs, indent):
        nonlocal y
        for i, u in enumerate(refs, 1):
            lines = wrap(f"{i}. {u}", W - 2 * M - indent, 8.2) or [u]
            need(11 * len(lines) + 2)
            for ln in lines:                              # every line of the address is the link
                doc.text(M + indent, y - 9, ln, 8.2, link)
                w = doc.c.stringWidth(ln, doc.F["r"], 8.2)
                doc.c.linkURL(u, (M + indent, y - 11, M + indent + w, y - 1), relative=0)
                y -= 11

    for g in gs:
        if g["kind"] == "name":
            heading(g["title"], g["level"], g["flags"])
            urls(g["refs"], 14)
            if g.get("more"):
                need(12)
                doc.text(M + 14, y - 9, f"and {g['more']} more on the {g.get('more_where') or 'source'} page", 8, MUTE); y -= 12
            y -= 8
        else:
            need(40)
            doc.text(M, y - 12, g["title"], 12, TXT, True); y -= 24
            for r in g["items"]:
                heading(r["title"], r["level"], [], 10)
                if r.get("where"):
                    need(12)
                    doc.text(M + 14, y - 8, r["where"], 8, MUTE); y -= 12
                urls([r["url"]], 14)
                y -= 6


# ------------------------------------------------------------------ the analysis and Executive reports work from figures,
# not records: their names' criticality comes from the days in memory, once per set of days (about 0.1 s a day)
_DAY_LEVELS = {}
DAYS = {}                     # {"comms": () -> days, "services": () -> days}: set by features.py at start


def all_levels():
    """Every name's level known: the names remembered from earlier days (data/name_levels.json), then day_levels of both
    platforms' days in memory, the most severe kept."""
    out = dict(_known())
    for get in DAYS.values():
        try:
            for n, lv in day_levels(get()).items():
                lift(out, n, lv)
        except Exception:                                # noqa: BLE001
            continue
    return out


def severity_by_url(url, base_dir=None):
    """Shadowserver's severity for the report whose shadowserver.org page this is ("" when unknown): a report is known by
    its page exactly, whatever name a PDF gives it ("Sinkhole Events Report" and "Sinkhole Events" alike)."""
    u = str(url or "").rstrip("/")
    for e in _snapshot(base_dir or os.path.dirname(os.path.abspath(__file__))).values():
        if isinstance(e, dict) and str(e.get("url") or "").rstrip("/") == u and u:
            return e.get("severity") or ""
    return ""


def platform_levels(platform_label):
    """day_levels of the platform a PDF is about (its label, as the PDFs carry it); {} when the days are not known."""
    plat = "comms" if "communication" in str(platform_label or "").lower() else "services"
    try:
        return day_levels(DAYS[plat]()) if plat in DAYS else {}
    except Exception:                                    # noqa: BLE001  (unflagged rather than no PDF)
        return {}


def day_levels(days):
    """{name: highest severity} over every record of these days (store.days.values()), kept while the days are the same."""
    days = [d for d in days or [] if getattr(d, "events", None) is not None]
    key = tuple((getattr(d, "start", None), getattr(d, "serial", 0), len(d.events)) for d in days)
    hit = _DAY_LEVELS.get(key)
    if hit is not None:
        return hit
    out, kinds = {}, {}
    for d in days:
        levels_from_records(d.events, out, kinds)
    if len(_DAY_LEVELS) > 4:                             # two platforms, a change of days now and then
        _DAY_LEVELS.clear()
    _DAY_LEVELS[key] = out
    remember(out)
    remember_kinds(kinds)
    return out


# names remembered with their level once their days have left memory (2026-11-18: a review kept on an earlier day named
# m0yv, whose records were no longer in memory, and it read "not rated"; asking the database took 5 s a name, the
# names are not indexed). Names and levels only: no host, no address, no count.
KNOWN = {"path": os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "name_levels.json"), "mtime": None, "levels": {}}
KNOWN_MAX = 50000


def _known():
    p = KNOWN["path"]
    try:
        m = filesig.sig(p)
    except OSError:
        return KNOWN["levels"]
    if KNOWN["mtime"] != m:
        try:
            with open(p, encoding="utf-8") as fh:
                d = json.load(fh)
            KNOWN["levels"] = {str(k): v for k, v in (d.items() if isinstance(d, dict) else []) if level(v)}
        except (OSError, ValueError):
            pass
        KNOWN["mtime"] = m
    return KNOWN["levels"]


def remember(levels):
    """Keep these names' levels (the most severe ever seen) in data/name_levels.json; written only when one changes."""
    cur = dict(_known())
    changed = False
    for n, lv in (levels or {}).items():
        before = cur.get(n)
        lift(cur, n, lv)
        changed = changed or cur.get(n) != before
    if not changed or len(cur) > KNOWN_MAX:
        return
    p = KNOWN["path"]
    try:
        os.makedirs(os.path.dirname(p), exist_ok=True)
        tmp = p + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(cur, fh, sort_keys=True)
        os.replace(tmp, p)
        KNOWN["levels"], KNOWN["mtime"] = cur, filesig.sig(p)
    except OSError:
        pass                                             # a read-only folder: the levels in memory still work


# ------------------------------------------------------------------ the severity map (severity_map.py, the user 2026-11-18)
# Every name the reports carried, rated or not, with its kind (data/name_kinds.json: names and kinds only, no host, no
# address, no count), so the map lists the names no record rates; and the researchers' ratings of those names.
SEEN = {"path": os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "name_kinds.json"), "mtime": None, "kinds": {}}
RATINGS = {"get": None}       # severity_map.py: () -> {name: {"level", "by", "at"}}


def all_kinds():
    """{name: "Infection" | "Issue"} for every name the reports carried (days loaded and the one-time read of every report)."""
    p = SEEN["path"]
    try:
        m = filesig.sig(p)
    except OSError:
        return SEEN["kinds"]
    if SEEN["mtime"] != m:
        try:
            with open(p, encoding="utf-8") as fh:
                d = json.load(fh)
            SEEN["kinds"] = {str(k): v for k, v in (d.items() if isinstance(d, dict) else []) if v in ("Infection", "Issue")}
        except (OSError, ValueError):
            pass
        SEEN["mtime"] = m
    return SEEN["kinds"]


def remember_kinds(kinds):
    """Keep the names not seen before in data/name_kinds.json (a name's first kind stays); written only when one is new."""
    cur = dict(all_kinds())
    new = {str(n): k for n, k in (kinds or {}).items() if n and n not in cur and k in ("Infection", "Issue")}
    if not new or len(cur) + len(new) > KNOWN_MAX:
        return
    cur.update(new)
    p = SEEN["path"]
    try:
        os.makedirs(os.path.dirname(p), exist_ok=True)
        tmp = p + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(cur, fh, sort_keys=True)
        os.replace(tmp, p)
        SEEN["kinds"], SEEN["mtime"] = cur, filesig.sig(p)
    except OSError:
        pass


def researcher_level(name):
    """A researcher's rating of a name no record rates ("" when none): only ever used where Shadowserver gives no level."""
    get = RATINGS.get("get")
    if not get or not name:
        return ""
    try:
        r = get() or {}
    except Exception:                                    # noqa: BLE001  (unflagged rather than no PDF)
        return ""
    hit = r.get(name) or next((v for k, v in r.items() if k.lower() == str(name).lower()), None)
    return level((hit or {}).get("level"))
