# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""The quarterly report and the quarterly purge (r85, the user 2026-11-20).

Once a quarter has ended (the first check after 00:00 UTC on the next quarter's 3rd day, when the quarter's last
day's reports have arrived; the user 2026-11-20), Looking Glass counts the
quarter's Shadowserver reports and its own workflow, and keeps the result in data/quarterly/<YYYYQn>/:
  quarterly_<Q>_management.pdf, management_summary_<Q>.csv              the management role only (the Executive portal)
  quarterly_<Q>_advisor.pdf, advisor_networks_ / advisor_organisations_ /
  advisor_network_issues_<Q>.csv                                         the advisor role only (the advisory portal)
  admin_purge_<Q>.csv                                                    admins (Settings → Quarterly)
  summary.json   the counts the next quarter compares against (per network and report, no address); kept for ever:
                 the statistics that survive the purge
  status.json    VALID or NOT VALID, every accuracy check, when it was made, the 15th working day, the purge day, the cutoff
  purge_permit.json   only when the report is VALID (and made before its purge day) AND the quarterly purge is turned on:
                 the database pipeline's permission to delete the raw report rows dated before the cutoff, on the purge
                 day. The platform never deletes anything itself and never writes the pipeline's files; the pipeline
                 reads this file read-only, works the dates out again and refuses anything else (quarterly_purge.py in
                 the pipeline's folder).
  purge_result.json   the pipeline's result, copied here once it purged (and written to the audit log)
data/quarterly/purge_confirmed.json   the purge's switch (the user 2026-11-21, r88): OFF on every installation until an
                 administrator turns it on in Settings → Quarterly, once, after seeing what it deletes (the Settings
                 permission, CSRF and their own password again). {enabled, by, by_name, at, at_ts, shown}: who, when and
                 what the page showed. Written only by that route (set_purge). Turning it off removes every waiting
                 permit; turning it on writes the permit for the newest VALID quarter whose purge day has not passed.
                 The pipeline reads this file too and refuses to purge unless it says enabled. The timing stays fixed.

Reading: MongoDB find / aggregate / count_documents only, and the platform's data/ files. Counting is two-stage:
MongoDB groups (month, network, host); Python counts the groups, so no document ever holds a network's addresses.
Addresses are kept only in memory, as hashes, and never written: every output carries counts only, and a final check
(guard 8) removes every output and fails the run if any of them holds an address.

Field mapping (the platform's own rules): single-host reports (services.ServiceRegistry) use ip / asn / region /
sector; communications (sources.Registry, detect_layout) use the constituent's side, the first prefix of
sources.PREFIXES[layout]; destination-only reports use dst_. The quarter is chosen by file name (it starts with the
report day and is indexed): from the first day, up to (not including) the next quarter's first day.

Who gets what (r89, the user 2026-11-21: each role downloads only its own): the management role the management PDF and
summary CSV; the advisor role the advisor PDF and their three CSVs; administrators only the purge CSV, "Make it again",
the accuracy checks and the purge's status and switch. Admin accounts hold every permission (to preview the portals),
so the rule is by role as well (may_see / may_download): an admin previewing a portal sees where each quarter stands,
without the downloads. Researchers, analysts, auditors and external accounts get nothing. Every download is sealed
(insider.py), stamped with who and when (CSV) and in the audit log.
The cards say what is true NOW (the purge's switch today, each quarter's purge as it stands, where the quarter stands,
an empty quarter in plain words); the PDFs and the CSVs keep what was true when the report was made (a record).
The oldest report day in the database (one indexed query per report collection) is cached in data/quarterly/state.json.
The constituency (Settings → Constituency; r89): every count, figure and list counts only the hosts in it, with the
platforms' own object and rule (settings.Settings.in_scope; a communication is kept when its source OR destination host
is in it), applied in the second stage (keep_host); the rows outside it are counted apart, so the recount (guard 3)
still accounts for every stored row. Each report says what it was counted for (status.json, summary.json, every CSV and
PDF), and a comparison with a quarter counted for another constituency says so. The PURGE is not scoped: it clears old
stored rows of every network, and its figures (the admin CSV, the PDFs' retention rows) say so.
Installed from features.py: quarterly.install(app, ctx). The PDFs are drawn by quarterly_pdf.py.
"""
import collections
import contextlib
import csv
import fcntl
import hashlib
import io
import json
import os
import re
import shutil
import statistics
import tempfile
import threading
import time
import zipfile
from datetime import date, datetime, timedelta, timezone

from flask import Response, g, jsonify, request

import counting_keys as _ck
import csvsafe
import job_schedule
import netypes
import services
import sources
import special_reports
from privacy import IPV4_FULL, IPV6, AsnRegistry

KEEP_DAYS = 31                       # the purge always keeps the last 31 days
MAKE_ON_DAY = 3                      # made automatically on the next quarter's 3rd day (its last day's reports are in by then)
WORKING_DAYS = 15                    # working days (Monday to Friday) to download the reports before the purge
UNKNOWN_NET = _ck.UNKNOWN_NET              # the one wording of every page (counting_keys.py)
UNKNOWN_REGION = _ck.UNKNOWN_REGION
ADDR_RE = re.compile(IPV4_FULL.pattern + "|" + IPV6.pattern)
Q_RE = re.compile(r"\A\d{4}Q[1-4]\Z")      # \Z: "$" would also accept a trailing newline
SYSTEM_USER = "looking-glass"
CHECK_EVERY = 600                    # seconds between the background checks
OLDEST_EVERY = 6 * 3600              # seconds between the background look-ups of the oldest report day (cached)
# the collections the purge may touch: the pipeline's own rule (report_names.valid + quarterly_purge.NOT_REPORTS)
REPORT_NAME = re.compile(r"^[a-z0-9][a-z0-9_]{0,63}$")
NOT_REPORTS = ("files_", "discovered_fields_", "lg_", "system.")
CONFIRM_FILE = "purge_confirmed.json"   # data/quarterly/: the purge's switch (off until an administrator turns it on)
# why a quarter has no purge permit (status.json "no_permit_why"; Settings → Quarterly and the bell show it)
WHY_INVALID = "the report is NOT VALID"
WHY_MADE_LATE = ("made after its purge day: nothing is deleted for this quarter (the next quarter's purge covers its "
                 "rows)")
WHY_OFF = "the quarterly purge is off on this installation (Settings → Quarterly): nothing is deleted"
WHY_ON_LATE = ("the quarterly purge was turned on after this quarter's purge day: nothing is deleted for this quarter "
               "(the next quarter's purge covers its rows)")
WHY_NOT_NEWEST = "a newer quarter's report exists: only the newest quarter gets a purge permit"
OFF_TEXT = "The quarterly purge is off on this installation: no report rows are deleted."

# every output of a quarter: kind -> (file name, readable name, who gets it)
FILES = {
    "pdf_management": ("quarterly_{q}_management.pdf", "Management report (PDF)", ("management",)),
    "management": ("management_summary_{q}.csv", "Management summary (CSV)", ("management",)),
    "pdf_advisor": ("quarterly_{q}_advisor.pdf", "Advisor report (PDF)", ("advisor",)),
    "advisor": ("advisor_networks_{q}.csv", "Networks and reports (CSV)", ("advisor",)),
    "orgs": ("advisor_organisations_{q}.csv", "Organisations and follow-up (CSV)", ("advisor",)),
    "issues": ("advisor_network_issues_{q}.csv", "Issues and CVEs per network (CSV)", ("advisor",)),
    "admin": ("admin_purge_{q}.csv", "Rows and the purge (CSV)", ("admin",)),
}
# who is an audience: its permission, and for the two portals a role that is not "admin" (admins hold every permission
# to preview the portals; the management and advisory permissions are otherwise exclusive to their roles, auth.py)
AUDIENCE_PERM = {"management": "management", "advisor": "advisory", "admin": "settings"}
PREVIEW_NOTE = {"management": "Quarterly reports are for management only: you see where each quarter stands, without the downloads.",
                "advisor": "Quarterly reports are for advisors only: you see where each quarter stands, without the downloads."}


def file_name(kind, quarter):
    return FILES[kind][0].format(q=quarter)


def may_see(audience, role, has_perm):
    """The one rule for a quarterly audience (its list and its files): the audience's permission, and for management and
    advisors not an admin account (which holds every permission only to preview the portals)."""
    perm = AUDIENCE_PERM.get(audience)
    if not perm or not has_perm(perm):
        return False
    return audience == "admin" or role != "admin"


def may_download(kind, audience, role, has_perm):
    """A file is served (and listed) only on its own audience's route, to that audience (may_see)."""
    return kind in FILES and audience in FILES[kind][2] and may_see(audience, role, has_perm)


# ------------------------------------------------------------------ dates
def parse_quarter(text):
    m = re.fullmatch(r"(\d{4})Q([1-4])", str(text or "").strip().upper())
    if not m:
        raise ValueError("a quarter looks like 2026Q4")
    return int(m.group(1)), int(m.group(2))


def quarter_of(d):
    return d.year, (d.month - 1) // 3 + 1


def qname(y, q):
    return f"{y}Q{q}"


def make_due(today):
    """The ended quarter whose report is due to be made automatically on `today`, or None: from the next quarter's
    MAKE_ON_DAY-th day (the quarter's last day's reports arrive the day after it; the user 2026-11-20)."""
    y, q = prev_quarter(*quarter_of(today))
    return qname(y, q) if today >= quarter_range(y, q)[1] + timedelta(days=MAKE_ON_DAY - 1) else None


def quarter_range(y, q):
    """(first day, first day of the next quarter, [the three months 'YYYY-MM'])."""
    lo = date(y, 3 * q - 2, 1)
    hi = date(y + 1, 1, 1) if q == 4 else date(y, 3 * q + 1, 1)
    return lo, hi, [f"{y}-{3 * q - 2 + i:02d}" for i in range(3)]


def prev_quarter(y, q):
    return (y - 1, 4) if q == 1 else (y, q - 1)


def in_quarter(filename, lo, hi):
    """The one selection rule (the same strings as the MongoDB query)."""
    return lo.isoformat() <= str(filename) < hi.isoformat()


def working_days_after(d, n):
    """The n-th working day (Monday to Friday) after d. Public holidays are not counted (the user's choice)."""
    k = d
    while n > 0:
        k += timedelta(days=1)
        if k.weekday() < 5:
            n -= 1
    return k


def purge_dates(y, q):
    """The quarter's last day; the 15th working day after it (the last day to download); the purge day (the next
    working day); the cutoff (rows dated before it are deleted: the last 31 days before the purge day are kept).
    The pipeline works the same dates out on its own (quarterly_purge.dates) and refuses a permit that differs."""
    lo, hi, _ = quarter_range(y, q)
    last = hi - timedelta(days=1)
    day15 = working_days_after(last, WORKING_DAYS)
    purge = working_days_after(day15, 1)
    return {"last_day": last, "working_day_15": day15, "purge_day": purge, "cutoff": purge - timedelta(days=KEEP_DAYS)}


def purge_filter(cutoff_iso):
    """The rows the purge deletes (the pipeline's quarterly_purge.purge_filter, the same): file names that start with a
    report day before the cutoff."""
    return {"filename": {"$gte": "0000-00-00", "$lt": cutoff_iso, "$regex": "^[0-9]{4}-[0-9]{2}-[0-9]{2}"}}


def purgeable(db):
    """The collections the pipeline's purge may touch (its own rule): report names with the filename index."""
    out = []
    for n in sorted(db.list_collection_names()):
        if n.startswith(NOT_REPORTS) or not REPORT_NAME.match(n) or n.startswith(("files_", "discovered_fields_")):
            continue
        try:
            idx = db[n].index_information()
        except Exception:                  # noqa: BLE001  (not readable: the guards report the collection)
            continue
        if any((v.get("key") or [("", 0)])[0][0] == "filename" for v in idx.values()):
            out.append(n)
    return out


def oldest_day(db, exclude=()):
    """The oldest report day in the database, or None when no report row is there: one indexed query per report
    collection (the filename index; a file name starts with its report day, as the report selects rows), never a scan.
    Raises when the database cannot be read (the caller keeps the cached day)."""
    best, ex = None, set(exclude)
    for n in purgeable(db):
        if n in ex or special_reports.is_special(n):
            continue
        doc = db[n].find_one({"filename": {"$gte": "0000-00-00", "$regex": "^[0-9]{4}-[0-9]{2}-[0-9]{2}"}},
                             {"filename": 1, "_id": 0}, sort=[("filename", 1)])
        d = _day((doc or {}).get("filename"))
        if d and (best is None or d < best):
            best = d
    return best


# ------------------------------------------------------------------ helpers
def hkey(v):
    """An address as an in-memory key only (never written anywhere)."""
    s = str(v).strip() if v is not None else ""
    return hashlib.blake2b(s.encode(), digest_size=8).digest() if s else None


def norm_asn(v):
    """The one network-number rule of every page (counting_keys.norm_asn): 0, AS0 and anything not a number: none."""
    return _ck.norm_asn(v)


def no_addresses(text):
    return ADDR_RE.sub("[address]", str(text or ""))


def region_label(v):
    """A region as every page shows and groups it (counting_keys.region_key: the administrator's matches, the map, the
    country's name; "Nairobi", not "NAIROBI")."""
    return _ck.region_key(v)


def readable(name, kind):
    if kind == "service":
        return services.service_of(name)
    return services.official_name(name) or sources.label_for(name)


def family(name, kind):
    return services.family_of(name) if kind == "service" else sources.attack_class(name)


# ------------------------------------------------------------------ CVE names
_AKA = re.compile(r"\b(?:aka|also known as)\s+(?:the |a |an )?[\"']?([A-Z][\w-]*(?:\s+[\w-]+){0,3}?)[\"']?\s*(?:attack|vulnerability|bug|flaw)?\s*[.,;)]",
                  re.I)


def cve_name(cv, cve):
    """A CVE's short name for a table: CISA's KEV name, else the title its issuer gave it, else the name its description
    gives ("aka a Terrapin attack"), else the description's first sentence when it is short, else its subject (before
    "allows", "could", ...) when that is short; "" when there is none (the table shows the id alone and the full
    description is in the CSV). Never cut, never "…" (the full-text rule)."""
    if cv is None:
        return ""
    cve = str(cve or "").strip().upper()
    try:
        kev = ((cv.cache.get("kev") or {}).get("items") or {}).get(cve) or {}
        if kev.get("name"):
            return " ".join(str(kev["name"]).split())
        o = (cv.cache.get("cveorg", {}).get(cve) or {}).get("data") or {}
        if (o.get("cna_title") or "").strip():
            return " ".join(o["cna_title"].split())
        desc = cv.known_description(cve)
    except Exception:                      # noqa: BLE001  (an unreadable cache: the id alone)
        return ""
    if not desc:
        return ""
    m = _AKA.search(desc)
    if m:
        name = m.group(0)
        name = re.sub(r"^(?:aka|also known as)\s+(?:the |a |an )?", "", name, flags=re.I).strip(" \"'.,;)")
        if 3 <= len(name) <= 60:
            return name[:1].upper() + name[1:]
    import cves
    first = cves.short_title(desc).rstrip(".")
    if len(first) <= 90:
        return first
    subject = re.split(r",\s|\s(?:allows?|could|may|might|which|that|when|where|before)\s", first)[0].strip()
    while subject.count("(") > subject.count(")"):      # never a bracket left open ("ESXi (7.0"): the words before it
        subject = subject[:subject.rfind("(")].strip()
    return subject if 12 <= len(subject) <= 90 else ""


def cve_description(cv, cve):
    try:
        return " ".join(str(cv.known_description(cve) or "").split()) if cv is not None else ""
    except Exception:                      # noqa: BLE001
        return ""


# ------------------------------------------------------------------ classification
def classify(db, exclude):
    """{collection: {kind, layout, label, family, fields{ip,asn,region,sector}}} from the platform's registries, plus
    the collections they leave out (helpers, special, unclassified)."""
    out, other = {}, {}
    comm = sources.Registry(db, exclude=exclude)
    comm.get(force=True)
    on_portal = {e["name"] for e in comm.items}
    for e in comm.items + comm.unsupported:
        lay = e.get("layout")
        sp = "dst_" if lay == "target" else sources.PREFIXES.get(lay or "standard", ("src_", ""))[0]
        # the other side, for the constituency: the map keeps an event when its source OR destination host is in it
        # (inbound, Spam URL: the local host is the report's own ip/asn, as sources.normalise reads it into dst_*; count
        # audit round 2, item 8: it was the source only here)
        # its own name, not "other" (review 2026-11-27: "other" is this function's list of collections left out; the
        # loop overwrote it, so a None crashed the report and "ip"/"asn" were listed as left-out collections)
        if lay == "inbound":
            side = {"ip": "ip", "asn": "asn"}
        else:
            dp = "" if lay == "target" else sources.PREFIXES.get(lay or "standard", ("src_", "dst_"))[1]
            side = {k: dp + k for k in ("ip", "asn")} if dp and dp != sp else None
        out[e["name"]] = {"kind": "communication", "layout": lay or "unrecognised",
                          "fields": {k: sp + k for k in ("ip", "asn", "region", "sector")},
                          "other": side, "portal": e["name"] in on_portal}
    svc = services.ServiceRegistry(db, exclude=exclude)
    svc.get(force=True)
    on_portal |= {e["name"] for e in svc.items}
    for e in svc.items + svc.unsupported:
        out.setdefault(e["name"], {"kind": "service", "layout": "single-host",
                                   "fields": {k: k for k in ("ip", "asn", "region", "sector")}})
        out[e["name"]]["portal"] = e["name"] in on_portal
    # a report the platforms' registries could not read in full (unsupported): counted here, never loaded by a page;
    # the report says which (X["not_on_portal"], count audit round 2, item 8)
    for n in db.list_collection_names():
        if n in out or n.startswith(("files_", "discovered_fields_", "system.")):
            continue
        if n in exclude:
            other[n] = "excluded (EXCLUDE_COLLECTIONS)"
        elif special_reports.is_special(n):
            other[n] = "special report (one-off, not in the statistics)"
        else:
            other[n] = "no host field the platform recognises (or unreadable)"
    for n, e in out.items():
        e["label"], e["family"] = readable(n, e["kind"]), family(n, e["kind"])
    return out, other


# ------------------------------------------------------------------ collection
def keep_host(scope, k):
    """The constituency (Settings → Constituency), the platforms' own rule and object: settings.Settings.in_scope, the
    same call the day loaders make (app.py, services.py). A group of rows is kept when its host is in the constituency,
    or, for a communication, its other side's host (k["oa"], k["oh"]). Always kept without a restriction."""
    if scope is None or not getattr(scope, "restricted", False):
        return True
    if scope.in_scope(norm_asn(k.get("a")), str(k.get("h") or "").strip()):
        return True
    # (MongoDB leaves a missing field out of the group's key: a row without dst_asn still has its dst_ip)
    return ("oa" in k or "oh" in k) and scope.in_scope(norm_asn(k.get("oa")), str(k.get("oh") or "").strip())


def constituency(scope):
    """What a report was counted for: {label, key}. key changes whenever the constituency does (a quarter compared
    against one counted for another constituency says so)."""
    if scope is None or not getattr(scope, "restricted", False):
        return {"label": "the whole country", "key": "all"}
    n, m = len(scope.asns), len(scope.nets)
    parts = ([f"{n} network{'s' if n != 1 else ''}"] if n else []) + ([f"{m} address range{'s' if m != 1 else ''}"] if m else [])
    key = hashlib.sha256(json.dumps([sorted(scope.asns), sorted(str(x) for x in scope.nets)]).encode()).hexdigest()[:16]
    return {"label": " and ".join(parts) + " (the constituency set in Settings)", "key": key}


def collect_db(db, y, q, today, exclude=(), kev=None, light=False, scope=None):
    """scope: the platform's settings object (its constituency); None or unrestricted counts every network. The rows'
    days (rep_day: the stored rows, for the admin's purge figures and the recount) are always the whole database."""
    lo, hi, months = quarter_range(y, q)
    match = {"filename": {"$gte": lo.isoformat(), "$lt": hi.isoformat()}}
    reps, other = classify(db, set(exclude))
    kev = kev or {}
    R = {"quarter": qname(y, q), "lo": lo, "hi": hi, "months": months, "today": today, "reports": reps, "other": {},
         "failed": {}, "rep_recs": collections.Counter(), "rep_hosts": collections.defaultdict(dict),
         "rep_total": collections.Counter(), "rep_day": collections.defaultdict(collections.Counter),
         "rep_noaddr": collections.Counter(), "net_total": collections.Counter(), "net_month": collections.Counter(),
         "net_hosts": collections.defaultdict(dict), "all_hosts": {}, "last_seen": {},
         "region": collections.defaultdict(set), "region_recs": collections.Counter(),
         "sector": collections.defaultdict(set), "sector_recs": collections.Counter(),
         "inf_hosts": collections.defaultdict(set), "inf_recs": collections.Counter(),
         "issue_hosts": collections.defaultdict(set), "issue_recs": collections.Counter(),
         "kev_hosts": set(), "kev_recs": 0, "cve_hosts": collections.defaultdict(set), "kev_cves": set(),
         "rep_out": collections.Counter(), "constituency": constituency(scope)}
    restricted = scope is not None and getattr(scope, "restricted", False)
    mi = {m: i for i, m in enumerate(months)}
    for n, why in other.items():
        try:
            R["other"][n] = {"why": why, "records": db[n].count_documents(match)}
        except Exception as exc:       # noqa: BLE001  unreadable: reported, never skipped silently
            R["failed"][n] = no_addresses(f"{type(exc).__name__}: {exc}")[:300]
    for name, e in sorted(reps.items()):
        f = e["fields"]
        key = {"m": {"$substrCP": ["$filename", 0, 7]}, "a": "$" + f["asn"], "h": "$" + f["ip"]}
        infection = e["kind"] == "communication" and e["family"] == "Botnet C2" or e["family"] == "Compromised"
        if infection:
            key.update(i="$infection", f="$family", t="$tag")
        if e["kind"] == "service" and not light:
            key.update(t="$tag", p="$ssl_poodle", fr="$freak_vulnerable", ce="$cert_expired", dt="$device_type")
        if restricted and e.get("other"):              # the other side's host, only to decide the constituency
            key.update(oa="$" + e["other"]["asn"], oh="$" + e["other"]["ip"])
        # stage 0 (count audit round 2, item 2): one row per (report day, line hash), as the day loaders keep it
        # (counting_keys.row_key): a row sent in two files of one day (a country file and an ASN file) counts once; a
        # row without a line hash is its own. Only the fields the next stage reads are carried.
        fields = sorted({v[1:] for v in key.values() if isinstance(v, str) and v.startswith("$")} - {"filename"}
                        | {f["region"], f["sector"]})
        first = {"_id": {"d": {"$substrCP": ["$filename", 0, 10]}, "l": {"$ifNull": ["$line_hash", "$_id"]}},
                 "c": {"$sum": 1}, "fn": {"$first": "$filename"}}
        for i, fld in enumerate(fields):
            first[f"f{i}"] = {"$first": "$" + fld}
        alias = {fld: f"$f{i}" for i, fld in enumerate(fields)}
        key2 = {k: ({"$substrCP": ["$fn", 0, 7]} if k == "m" else alias.get(v[1:], v) if isinstance(v, str) else v)
                for k, v in key.items()}
        pipe = [{"$match": match}, {"$group": first},
                {"$group": {"_id": key2, "n": {"$sum": 1}, "x": {"$sum": {"$subtract": ["$c", 1]}},
                            "d": {"$max": {"$substrCP": ["$fn", 0, 10]}},
                            "r": {"$first": alias[f["region"]]}, "s": {"$first": alias[f["sector"]]}}}]
        try:
            days, lo_t, hi_t, undated = collections.Counter(), None, None, 0
            for d in db[name].aggregate([{"$match": match}, {"$group": {
                    "_id": {"$substrCP": ["$filename", 0, 10]}, "n": {"$sum": 1},
                    "lo": {"$min": "$extracted_date"}, "hi": {"$max": "$extracted_date"},
                    "u": {"$sum": {"$cond": [{"$ifNull": ["$extracted_date", False]}, 0, 1]}}}}], allowDiskUse=True):
                days[d["_id"]] = d["n"]
                undated += d.get("u") or 0
                for k_, v_ in (("lo", d.get("lo")), ("hi", d.get("hi"))):
                    s_ = v_.strftime("%Y-%m-%d") if isinstance(v_, datetime) else str(v_ or "")[:10]
                    if s_:
                        if k_ == "lo" and (lo_t is None or s_ < lo_t):
                            lo_t = s_
                        if k_ == "hi" and (hi_t is None or s_ > hi_t):
                            hi_t = s_
            groups = list(db[name].aggregate(pipe, allowDiskUse=True, batchSize=5000))   # stage 1: (month, network, host)
        except Exception as exc:       # noqa: BLE001  unreadable: reported, never skipped silently
            R["failed"][name] = no_addresses(f"{type(exc).__name__}: {exc}")[:300]
            continue
        R["rep_day"][name] = days
        R["rep_total"][name] += 0
        sp = R.setdefault("event_span", {})
        if lo_t:
            sp[name] = (lo_t, hi_t)
        R.setdefault("undated", collections.Counter())[name] += undated
        for g_ in groups:               # stage 2: counted here, in the constituency only (rows outside it counted apart)
            R.setdefault("rep_dups", collections.Counter())[name] += g_.get("x") or 0
            if not keep_host(scope, g_["_id"]):
                R["rep_out"][name] += g_["n"]
                continue
            _add(R, name, e, g_["_id"], g_["n"], g_.get("d") or "", g_.get("r"), g_.get("s"), mi, kev, infection, light)
    return R


def _add(R, name, e, k, n, day, region, sector, mi, kev, infection, light):
    m = k.get("m")
    asn, h = norm_asn(k.get("a")), hkey(k.get("h"))
    bit = 1 << mi.get(m, 0)
    R["rep_recs"][(name, m, asn)] += n
    R["rep_total"][name] += n
    R["net_total"][asn] += n
    R["net_month"][(asn, m)] += n
    if h is None:
        R["rep_noaddr"][name] += n
        return
    for d in (R["rep_hosts"].setdefault((name, asn), {}), R["net_hosts"][asn], R["all_hosts"]):
        d[h] = d.get(h, 0) | bit
    if day > R["last_seen"].get(h, ""):
        R["last_seen"][h] = day
    if light:
        return
    rg = region_label(region)
    # Shadowserver's own sector column: "Industry (Shadowserver)" (the user, 2026-11-26). The report's Sectors are the
    # network types of the hosts' networks, worked out in figures() from net_hosts (counting_keys.sector_of), as on
    # every page
    sc = _ck.industry_of(sector) or "Not given"
    R["region"][rg].add(h); R["region_recs"][rg] += n
    R.setdefault("industry", collections.defaultdict(set))[sc].add(h)
    R.setdefault("industry_recs", collections.Counter())[sc] += n
    if infection:
        inf = infection_key(k, name, e["kind"])        # named readably when the report is put together (infection_name)
        R["inf_hosts"][inf].add(h); R["inf_recs"][inf] += n
    if e["kind"] == "service":
        doc = {"tag": k.get("t"), "ssl_poodle": k.get("p"), "freak_vulnerable": k.get("fr"), "cert_expired": k.get("ce"),
               "device_type": k.get("dt")}
        rec = services.normalise_service(doc, {"family": e["family"], "name": name, "label": e["label"]})
        hit = False
        for iss in rec["issues"]:
            R["issue_hosts"][(asn, iss)].add(h); R["issue_recs"][(asn, iss)] += n
            if iss in kev:
                R["cve_hosts"][iss].add(h); R["kev_cves"].add(iss); hit = True
        if hit:
            R["kev_hosts"].add(h); R["kev_recs"] += n


# ------------------------------------------------------------------ workflow (findings, advisories)
def workflow(base, y, q, last_seen, title_of=lambda k: k, F=None):
    import advisory
    import findings
    lo, hi, months = quarter_range(y, q)
    t_lo = datetime(lo.year, lo.month, lo.day, tzinfo=timezone.utc).timestamp()
    t_hi = datetime(hi.year, hi.month, hi.day, tzinfo=timezone.utc).timestamp()

    def inq(t):
        return t is not None and t_lo <= t < t_hi

    def day(t):
        return datetime.fromtimestamp(t, timezone.utc).strftime("%Y-%m-%d")
    F = F or findings.Findings(os.path.join(base, "data", "findings.json"), people=None)
    with F.lock:
        F._load()
        items = {k: dict(v) for k, v in F.data["items"].items()}
    W = {"opened": 0, "opened_month": collections.Counter(), "closed": 0, "advisory_sent": 0, "expired": 0,
         "still_open": 0, "status": collections.Counter(), "decisions": [], "decision_counts": collections.Counter(),
         "reviews": 0, "to_decision": [], "to_advisory": [], "cases": 0}
    kids = collections.defaultdict(list)
    for x in items.values():
        if x.get("parent"):
            kids[x["parent"]].append(x)
    for x in items.values():
        H = x.get("history") or []
        opened = x.get("at")
        top = not x.get("parent")
        if inq(opened) and top:
            W["opened"] += 1; W["opened_month"][day(opened)[:7]] += 1
            if x.get("kind") == "case":
                W["cases"] += 1
        if opened is not None and opened < t_hi and top:
            W["status"][findings.LABEL.get(x["status"], x["status"])] += 1
            if x["status"] in findings.OPEN:
                W["still_open"] += 1
        if top and any(h.get("status") == "closed" and inq(h.get("at")) for h in H):
            W["closed"] += 1
        if any(h.get("kind") == "advisory_sent" and inq(h.get("at")) for h in H):
            W["advisory_sent"] += 1
        if any(h.get("kind") == "expired" and inq(h.get("at")) for h in H):
            W["expired"] += 1
        # management's decisions: one per finding, and one per organisation of a case (a case is decided per sub-finding)
        if x.get("kind") != "case":
            dec = [h for h in H if h.get("kind") == "decision"]
            was_mgmt = any(h.get("status") == "management" for h in H) or dec
            if was_mgmt and opened is not None and opened < t_hi:
                dq = [h for h in dec if inq(h.get("at"))]
                if dq:
                    h = dq[-1]
                    W["reviews"] += 1
                    W["decision_counts"][h["decision"]] += 1
                    W["decisions"].append({"finding": f"#{x['id']}", "title": no_addresses(x.get("title")),
                                           "organisation": no_addresses(x.get("network") or (x.get("review") or {}).get("network") or ""),
                                           "decision": "approved" if h["decision"] == "accepted" else "rejected",
                                           "date": day(h["at"]), "reason": no_addresses(h.get("comment") or "")})
                elif not dec and x["status"] == "management":
                    W["reviews"] += 1
                    W["decision_counts"]["waiting"] += 1
        # time to act: from opening (a case: its own) to the first decision and the first advisory sent
        if top:
            fam = [x] + kids.get(x["id"], [])

            def first(kind, fam=fam):
                return min((h["at"] for z in fam for h in z.get("history") or [] if h.get("kind") == kind), default=None)
            d1, a1 = first("decision"), first("advisory_sent")
            if inq(d1) and opened is not None:
                W["to_decision"].append((d1 - opened) / 86400)
            if inq(a1) and opened is not None:
                W["to_advisory"].append((a1 - opened) / 86400)
    W["decisions"].sort(key=lambda r: (r["date"], r["finding"]))
    W["approved"] = W["decision_counts"]["accepted"]
    W["rejected"] = W["decision_counts"]["rejected"]
    W["waiting"] = W["decision_counts"]["waiting"]

    def med(v):
        return round(statistics.median(v), 1) if v else None
    W["median_to_decision"], W["median_to_advisory"] = med(W["to_decision"]), med(W["to_advisory"])

    # advisories sent in the quarter (the advisory portal's own counting: per send, per recipient, per month)
    store = advisory.Store(os.path.join(base, "data", "advisories"))
    imp = advisory.Impact(base)
    A = {"sends": 0, "advisories": [], "per_month": collections.Counter(), "to": collections.Counter(),
         "impact": collections.Counter(), "orgs": collections.defaultdict(collections.Counter)}
    org_of = _org_namer(base)
    for a in sorted(store.all(), key=lambda a: a.get("ref", "")):
        sq = [s for s in a.get("sends") or [] if inq(s.get("at"))]
        if not sq:
            continue
        dv = _advisory_devices(base, a, with_asns=True)
        org = org_of(a.get("network"), dv[2])
        A["advisories"].append({"ref": a["ref"], "organisation": org, "sent": day(min(s["at"] for s in sq)),
                                "subject": no_addresses(a.get("subject"))})
        A["orgs"][org]["advisories"] += 1
        for s in sq:
            A["sends"] += 1
            A["per_month"][day(s["at"])[:7]] += 1
            for r in s.get("to") or []:
                A["to"][r] += 1
        # the devices it named: the report's own device list (read in memory; only counts leave)
        first_send = day(min(s["at"] for s in sq))
        names, devs, _asns = dv
        for fl in imp.of_names(names, title_of):
            A["impact"][(fl.get("label") or fl.get("flag"), fl.get("level") or "")] += 1
        A["orgs"][org]["devices"] += len(devs)
        A["orgs"][org]["still_seen"] += sum(1 for h in devs if last_seen.get(h, "") > first_send)
    for x in items.values():
        # like "Still open": only findings opened before the quarter ended (a quarter made again later must not count
        # cases opened after it; Q3/Q4 test on lg-test, 2026-11-21)
        opened = x.get("at")
        if (x.get("kind") != "case" and x["status"] in findings.OPEN and x.get("network")
                and opened is not None and opened < t_hi):
            A["orgs"][org_of(x["network"], ())]["cases_open"] += 1
    return W, A


def _org_namer(base):
    """An organisation of the advisor's follow-up, named as the network registry names it when the report is made
    (count audit round 2, item 17: keyed by the name stored when the advisory or finding was made, so a renamed or
    re-spelt network was two organisations): by the AS numbers of its devices when known, else by its stored name
    (folded) when the registry knows that name, else that name trimmed."""
    reg = AsnRegistry(os.path.join(base, "data", "asns.json"))
    by_fold = {}
    for a, v in reg.all().items():
        by_fold.setdefault(_ck.fold(v.get("name")), a)

    def name(stored, asns):
        if not stored or stored == "All networks":
            return "All networks"
        names = sorted({reg.company(a, False) for a in asns if _ck.norm_asn(a)} - {""})
        if names:
            return " / ".join(names)
        a = by_fold.get(_ck.fold(stored))
        return reg.company(a, False) if a else _ck.clean_name(stored)
    return name


def _advisory_devices(base, a, with_asns=False):
    folder = os.path.join(base, "data", "advisories", "files", a["ref"])
    reps = a.get("reports") or []
    names, devs, asns = set(), set(), set()
    if not reps:
        return (names, devs, asns) if with_asns else (names, devs)
    p = os.path.join(folder, f"{reps[-1].get('n', len(reps))}.zip")
    try:
        with zipfile.ZipFile(p) as zf:
            for n in zf.namelist():
                if not n.endswith(".csv"):
                    continue
                for r in csv.DictReader(io.StringIO(zf.read(n).decode("utf-8-sig", "replace"))):
                    h = hkey(r.get("ip"))
                    if h:
                        devs.add(h)
                    if _ck.norm_asn(r.get("asn")):
                        asns.add(_ck.norm_asn(r.get("asn")))
                    for part in re.split(r"[;|]", r.get("reports") or ""):
                        if part.strip():
                            names.add(part.strip())
    except (OSError, zipfile.BadZipFile, KeyError):
        pass
    return (names, devs, asns) if with_asns else (names, devs)


# ------------------------------------------------------------------ summaries (what survives the purge)
def summary_of(R, netname):
    """The quarter's counts, per network and report: what the next quarter compares against. No address, no hash."""
    recs_rn = collections.Counter()
    for (name, _m, asn), v in R["rep_recs"].items():
        recs_rn[(name, asn)] += v
    per_rn = {}
    for (name, asn), v in recs_rn.items():
        per_rn[f"{name}|{asn}"] = {"report": name, "label": R["reports"][name]["label"], "asn": asn, "network": netname(asn),
                                   "records": v, "unique": len(R["rep_hosts"].get((name, asn), {}))}
    per_net = {asn: {"network": netname(asn), "records": v, "unique": len(R["net_hosts"].get(asn, {}))}
               for asn, v in R["net_total"].items() if v}
    per_rep = {}
    hosts_of = collections.defaultdict(set)     # every report's addresses, in one pass (audit 2026-11-27, 6-3)
    for (r, _a), hs in R["rep_hosts"].items():
        hosts_of[r].update(hs)
    for name, v in R["rep_total"].items():
        if v:
            hosts = hosts_of.get(name, set())
            per_rep[name] = {"label": R["reports"][name]["label"], "family": R["reports"][name]["family"], "records": v,
                             "unique": len(hosts)}
    return {"quarter": R["quarter"], "constituency": R.get("constituency") or constituency(None),
            "totals": {"records": sum(R["rep_total"].values()), "unique": len(R["all_hosts"]),
                                                # companies, unknown left out (as figures(): count audit round 2)
                                                "networks": len({netname(a) for a, v in R["net_total"].items() if v and a}),
                                                "reports": sum(1 for v in R["rep_total"].values() if v)},
            "per_network": per_net, "per_report": per_rep, "per_report_network": per_rn}


def read_json(path):
    try:
        with open(path, encoding="utf-8") as fh:
            d = json.load(fh)
        return d if isinstance(d, dict) else None
    except (OSError, ValueError):
        return None


def inside(top, *parts):
    """The path of parts under top, resolved, refused unless it stays inside top (a quarter name from an address, or a
    file name read back from status.json, can never point elsewhere; CodeQL py/path-injection, 2026-11-21)."""
    root = os.path.realpath(top)
    p = os.path.realpath(os.path.join(root, *parts))
    if not p.startswith(root + os.sep):
        raise ValueError("outside the quarterly folder")
    return p


def quarter_dir(base, quarter):
    if not Q_RE.match(str(quarter or "")):
        raise ValueError("not a quarter")
    return inside(os.path.join(base, "data", "quarterly"), str(quarter))


def previous_summary(db, base, y, q, today, exclude, netname, scope=None):
    """The previous quarter's counts: its kept summary.json (made before its rows were purged) when it was VALID, else
    counted from MongoDB now (counts only, for the constituency set now). A kept summary counted for another
    constituency (or before r89, when every report counted the whole country) says so in its source."""
    py, pq = prev_quarter(y, q)
    try:
        s = read_json(os.path.join(quarter_dir(base, qname(py, pq)), "summary.json"))
    except ValueError:
        s = None
    if s and s.get("valid") and isinstance(s.get("totals"), dict):
        was = (s.get("constituency") or {}).get("key", "all")
        same = was == constituency(scope)["key"]
        return dict(s, source="the previous quarter's kept summary" + ("" if same else ", counted for a different constituency"),
                    other_constituency=not same)
    P = collect_db(db, py, pq, today, exclude, light=True, scope=scope)
    return dict(summary_of(P, netname), source="counted from the reports now", failed=sorted(P["failed"]))


# ------------------------------------------------------------------ figures
def figures(R, PS, base, today, cv=None):
    """Everything the outputs show, computed once from the collected data (R this quarter, PS the previous one's counts)."""
    reg = AsnRegistry(os.path.join(base, "data", "asns.json"))

    def netname(asn):                      # = app.py ctx["network"]
        return (reg.company(asn, False) if asn else "") or UNKNOWN_NET
    months = R["months"]
    elapsed = [m for m in months if m <= today.strftime("%Y-%m")]
    X = {"netname": netname, "months": months, "elapsed": elapsed}
    tot = {}
    for i, m in enumerate(months + ["quarter"]):
        recs = sum(v for (r, mm, a), v in R["rep_recs"].items() if m == "quarter" or mm == m)
        # networks: companies, "Unknown network" left out (counted apart: X["unknown_network"]), as on every page
        # (count audit round 2, item 5: AS numbers with unknown here, companies in the list, companies without it on
        # the Executive portal)
        if m == "quarter":
            uniq = len(R["all_hosts"])
            nets = len({netname(a) for a, v in R["net_total"].items() if v and a})
            repn = sum(1 for r, v in R["rep_total"].items() if v)
        else:
            b = 1 << i
            uniq = sum(1 for v in R["all_hosts"].values() if v & b)
            nets = len({netname(a) for (a, mm), v in R["net_month"].items() if mm == m and v and a})
            repn = len({r for (r, mm, a), v in R["rep_recs"].items() if mm == m and v})
        tot[m] = {"records": recs, "unique": uniq, "networks": nets, "reports": repn}
    X["totals"] = tot
    X["noaddr"] = sum(R["rep_noaddr"].values())
    fam_recs, fam_hosts = collections.Counter(), collections.defaultdict(set)
    rep_rows = []
    hosts_of = collections.defaultdict(set)     # every report's addresses, in one pass (audit 2026-11-27, 6-3)
    for (r, a), hs in R["rep_hosts"].items():
        hosts_of[r].update(hs)
    for name, v in R["rep_total"].items():
        e = R["reports"][name]
        hosts = hosts_of.get(name, set())
        fam_recs[e["family"]] += v
        fam_hosts[e["family"]].update(hosts)
        rep_rows.append({"name": name, "label": e["label"], "family": e["family"], "records": v, "unique": len(hosts)})
    X["families"] = sorted(({"label": f, "records": fam_recs[f], "unique": len(fam_hosts[f])} for f in fam_recs), key=lambda r: -r["unique"])
    X["reports"] = sorted(rep_rows, key=lambda r: (-r["unique"], r["label"]))
    by_name_hosts, by_name_recs = collections.defaultdict(set), collections.Counter()
    for a, hs in R["net_hosts"].items():
        by_name_hosts[netname(a)].update(hs)
    for a, v in R["net_total"].items():
        by_name_recs[netname(a)] += v
    # every network by company; the records without a network are the last row, "Unknown network", marked: shown, never
    # counted as a network
    X["networks"] = sorted(({"label": n, "records": by_name_recs[n], "unique": len(by_name_hosts[n]), "unknown": n == UNKNOWN_NET}
                            for n in by_name_recs), key=lambda r: (r["unknown"], -r["unique"], r["label"]))
    X["unknown_network"] = {"records": by_name_recs.get(UNKNOWN_NET, 0), "unique": len(by_name_hosts.get(UNKNOWN_NET, ()))}
    rec = []
    asns_of = collections.defaultdict(list)     # every company's AS numbers, each named once (audit 2026-11-27, 6-3)
    for a in R["net_total"]:
        asns_of[netname(a)].append(a)
    for n in by_name_recs:
        if n == UNKNOWN_NET:
            continue
        asns = asns_of.get(n, [])
        if elapsed and all(sum(R["net_month"][(a, m)] for a in asns) for m in elapsed):
            rec.append({"label": n, "unique": len(by_name_hosts[n]), "records": by_name_recs[n]})
    X["recurring"] = sorted(rec, key=lambda r: (-r["unique"], r["label"]))
    # better or worse against the previous quarter (its counts: kept, or counted now)
    X["prev"] = PS
    X["prev_has_data"] = bool(PS and (PS.get("totals") or {}).get("records"))
    if X["prev_has_data"]:
        # by company (names folded: counting_keys.fold), as every network count; "unknown network" is not a network
        # that came or went
        now_n = {_ck.fold(netname(a)) for a, v in R["net_total"].items() if v and a}
        was_n = {_ck.fold((v or {}).get("network") or netname(a)) for a, v in (PS.get("per_network") or {}).items()
                 if a and (v or {}).get("records")}
        pt = PS["totals"]
        X["better_worse"] = {"networks appeared": len(now_n - was_n), "networks gone": len(was_n - now_n),
                             "unique addresses previous quarter": pt.get("unique", 0),
                             "unique addresses this quarter": len(R["all_hosts"]),
                             "change in unique addresses": len(R["all_hosts"]) - int(pt.get("unique", 0) or 0),
                             "records previous quarter": pt.get("records", 0),
                             "records this quarter": sum(R["rep_total"].values()),
                             "change in records": sum(R["rep_total"].values()) - int(pt.get("records", 0) or 0)}
    else:
        X["better_worse"] = None
    X["regions"] = sorted(({"label": k, "unique": len(v), "records": R["region_recs"][k]} for k, v in R["region"].items()),
                          key=lambda r: (-r["unique"], r["label"]))
    # Sectors: the network type of each host's network (data/asns.json, counting_keys.sector_of), the same buckets as
    # the Executive portal and the services page; Industry (Shadowserver): the reports' own sector column (the user,
    # 2026-11-26). An address seen in two networks of different types counts in each.
    sec_of = _ck.Sectors(reg.all(), netypes.labels(os.path.join(base, "data")))
    sec_h, sec_r = collections.defaultdict(set), collections.Counter()
    for a, hs in R["net_hosts"].items():
        sec_h[sec_of(a)].update(hs)
    for a, v in R["net_total"].items():
        if v:
            sec_r[sec_of(a)] += v
    X["sectors"] = sorted(({"label": k, "unique": len(sec_h[k]), "records": sec_r[k]} for k in sec_r),
                          key=lambda r: (-r["unique"], r["label"]))
    X["industries"] = sorted(({"label": k, "unique": len(v), "records": (R.get("industry_recs") or {}).get(k, 0)}
                              for k, v in (R.get("industry") or {}).items()), key=lambda r: (-r["unique"], r["label"]))
    # what the counts leave out or say about the rows (count audit round 2): copies of a row in another file of the
    # same day (counted once), rows without a time, the dates the events span, reports the portal does not show
    X["duplicates"] = sum((R.get("rep_dups") or {}).values())
    X["undated"] = sum((R.get("undated") or {}).values())
    spans = list((R.get("event_span") or {}).values())
    X["event_span"] = (min(s[0] for s in spans), max(s[1] for s in spans)) if spans else None
    X["not_on_portal"] = sorted(({"label": R["reports"][n]["label"], "records": v} for n, v in R["rep_total"].items()
                                 if v and R["reports"].get(n, {}).get("portal") is False), key=lambda r: (-r["records"], r["label"]))
    titles = _infection_titles(base)
    by_name = {}                      # two raw names with one readable name (an alias in the knowledge base) are one row
    for k, v in R["inf_hosts"].items():
        x = by_name.setdefault(infection_name(k, titles), [set(), 0])
        x[0] |= v; x[1] += R["inf_recs"][k]
    X["infections"] = sorted(({"label": lb, "unique": len(hs), "records": n} for lb, (hs, n) in by_name.items()),
                             key=lambda r: (-r["unique"], r["label"]))
    X["_cve_texts"] = used = set()

    def cve_label(c):
        """"CVE-2023-48795: Terrapin attack", or the id alone when no short name is known."""
        t = cve_name(cv, c)
        used.add(t)
        return f"{c}: {t}" if t else c

    def cve_desc(c):
        t = cve_description(cv, c)
        used.add(t)
        return t
    X["cve_label"], X["cve_desc"] = cve_label, cve_desc
    X["kev"] = {"hosts": len(R["kev_hosts"]), "records": R["kev_recs"],
                "top": sorted(({"cve": c, "label": cve_label(c), "unique": len(hs)} for c, hs in R["cve_hosts"].items()),
                              key=lambda r: (-r["unique"], r["cve"]))}
    per_net = collections.defaultdict(list)
    kev = R.get("kev_set") or set()
    for (a, iss), hs in R["issue_hosts"].items():
        per_net[a].append({"issue": iss, "unique": len(hs), "records": R["issue_recs"][(a, iss)], "kev": iss in kev})
    # every issue of every network: the advisor_network_issues CSV says it holds every one; the PDF draws the top 5 and says so
    X["net_issues"] = {a: sorted(v, key=lambda r: (-r["unique"], r["issue"])) for a, v in per_net.items()}
    return X


def _infection_titles(base):
    """{name in lower case: readable title}, as the platform's knowledge base names infections: data/infections.json
    (shipped) with this site's own definitions (data/definitions.json) on top (app.knowledge_base)."""
    out = {}
    for fn in ("infections.json", "definitions.json"):
        try:
            with open(os.path.join(base, "data", fn), encoding="utf-8") as f:
                d = json.load(f).get("infections") or {}
        except (OSError, ValueError, AttributeError):
            continue
        for k, v in d.items():
            if isinstance(v, dict) and (v.get("title") or k.lower() not in out):
                out[k.lower()] = str(v.get("title") or out.get(k.lower()) or k)
    return out


TAG_KEY = "\x1f"                       # marks an infection key made from a row with no infection or family


def infection_key(k, name, kind):
    """What a row of an infection report is counted under: its infection, else its family (as the map names it); a row
    with neither is kept apart with its report and tags (never shown as is: infection_name names it)."""
    for x in ("i", "f"):
        v = str(k.get(x) or "").strip()
        if v:
            return v
    return TAG_KEY.join(("", kind or "", name or "", str(k.get("t") or "").strip()))


def infection_name(key, titles):
    """The readable name of an infection key, as headers and lists show names ("Andromeda (Gamarue)"): the knowledge
    base's title, else the name itself. A row with no infection or family: the title of one of its tags when the
    knowledge base knows it, else the issues its tags stand for ("Badcandy, Device implant", issue_tags), else the
    report's readable name; never the raw tag list ("badcandy;device-implant;ssl")."""
    if not key.startswith(TAG_KEY):
        return titles.get(key.lower(), key)
    _, kind, name, tag = (key.split(TAG_KEY, 3) + ["", "", ""])[:4]
    parts = [t.strip() for t in tag.replace(",", ";").split(";") if t.strip()]
    for t in parts:
        if titles.get(t.lower()):
            return titles[t.lower()]
    import issue_tags
    named = issue_tags.split(parts)[0]
    if named:
        return ", ".join(named)
    return readable(name, kind) if name else "Not named in the report"


def cve_intel(base):
    """The platform's CVE cache, read only: nothing is downloaded here (kev() is never called; the cached KEV list is used)."""
    try:
        import cves
        return cves.CveIntel(os.path.join(base, "data", "cve_cache.json"))
    except Exception:                  # noqa: BLE001
        return None


def kev_ids(cv):
    return set(((cv.cache.get("kev") or {}).get("items") or {}).keys()) if cv else set()


def issue_label(X, issue):
    return X["cve_label"](issue) if issue.upper().startswith("CVE-") else issue


# ------------------------------------------------------------------ guards
def guards(db, R, X, W, A, rows):
    """Accuracy guards, run every time. [(name, ok, detail)]. rows: what the CSV writers will write (counts check)."""
    G = []

    def ok(name, cond, detail=""):
        G.append((name, bool(cond), detail))
    lo_s, hi_s = R["lo"].isoformat(), R["hi"].isoformat()
    months = R["months"]
    # the records per report and per (report, network), summed once: each guard below looks them up instead of summing
    # every row again per report / network (audit 2026-11-27, 6-2: O(n^2), hours for a big constituency, lock held)
    rec_rep, rec_rn = collections.Counter(), collections.Counter()
    for (n, m, a), v in R["rep_recs"].items():
        rec_rep[n] += v
        rec_rn[(n, a)] += v
    hosts_per_net = collections.defaultdict(list)
    for (n, a), h in R["rep_hosts"].items():
        hosts_per_net[a].append(len(h))
    bad = [r for r in R["rep_total"] if rec_rep.get(r, 0) != R["rep_total"][r]]
    bad += [f"network {a or '-'}" for a in R["net_total"] if sum(R["net_month"][(a, m)] for m in months) != R["net_total"][a]]
    ok("1 months add up to the quarter (every report and network)", not bad, ", ".join(map(str, bad[:5])))
    bad = []
    for (n, a), hs in R["rep_hosts"].items():
        if len(hs) > rec_rn.get((n, a), 0):
            bad.append(f"{n}/{a}")
        for i, m in enumerate(months):
            if sum(1 for v in hs.values() if v & (1 << i)) > R["rep_recs"].get((n, m, a), 0):
                bad.append(f"{n}/{a}/{m}")
    for a, hs in R["net_hosts"].items():
        per = hosts_per_net.get(a, [])
        if per and not (max(per) <= len(hs) <= sum(per)):
            bad.append(f"network {a}: all reports {len(hs)} outside {max(per)}..{sum(per)}")
        if len(hs) > R["net_total"][a]:
            bad.append(f"network {a}: more addresses than records")
    ok("2 unique addresses <= records; all-reports uniques between the largest report and the sum", not bad, "; ".join(bad[:5]))
    bad = []
    for n in R["rep_total"]:
        try:
            k = db[n].count_documents({"filename": {"$gte": lo_s, "$lt": hi_s}})
            # every stored row is either counted (in the constituency), set apart (outside it) or a copy of a row in
            # another file of the same day (counted once): none lost, none twice
            dup = (R.get("rep_dups") or {}).get(n, 0)
            if k != R["rep_total"][n] + R["rep_out"][n] + dup or k != sum(R["rep_day"][n].values()):
                bad.append(f"{n}: {k} counted, {R['rep_total'][n]} in the report + {R['rep_out'][n]} outside the constituency"
                           f" + {dup} copies in another file of the same day")
            for i, m in enumerate(months):
                m_hi = months[i + 1] + "-01" if i + 1 < len(months) else hi_s
                km = db[n].count_documents({"filename": {"$gte": m + "-01", "$lt": m_hi}})
                if km != sum(v for d, v in R["rep_day"][n].items() if d.startswith(m)):
                    bad.append(f"{n} {m}: {km} counted")
        except Exception as exc:       # noqa: BLE001
            bad.append(f"{n}: recount failed ({type(exc).__name__})")
    ok("3 independent recount (count_documents) equals every report's total (in the constituency + outside it) and month rows",
       not bad, "; ".join(bad[:5]))
    with_net = sum(v for a, v in R["net_total"].items() if a)
    unknown = R["net_total"].get("", 0)
    total = sum(R["rep_total"].values())
    ok("4 nothing lost: records = with a network + unknown network", total == with_net + unknown == sum(R["rep_recs"].values()),
       f"{total} = {with_net} + {unknown}")
    pd = R["purge"]
    bad = []
    if (pd["purge_day"] - pd["cutoff"]).days < KEEP_DAYS or pd["cutoff"] > pd["purge_day"]:
        bad.append(f"cutoff inside the last {KEEP_DAYS} days")
    cut = min(pd["cutoff"], R["hi"]).isoformat()
    for n in R["rep_total"]:
        try:
            k = db[n].count_documents({"filename": {"$gte": lo_s, "$lt": cut}})
        except Exception:              # noqa: BLE001
            k = None
        if k != rows["purge"].get(n):
            bad.append(f"{n}: {k} counted, {rows['purge'].get(n)} in the admin CSV")
        if n in R["purge_all"] and k is not None and R["purge_all"][n] < k:
            bad.append(f"{n}: the purge's count {R['purge_all'][n]} is below this quarter's {k}")
    ok(f"5 purge dry count equals count_documents; the last {KEEP_DAYS} days are kept", not bad, "; ".join(bad[:5]))
    c6 = (rows["advisories_listed"] == len(A["advisories"]) and rows["decisions_listed"] == len(W["decisions"])
          and W["approved"] + W["rejected"] == len(W["decisions"])
          and W["approved"] + W["rejected"] + W["waiting"] == W["reviews"]
          and sum(A["per_month"].values()) == A["sends"])
    ok("6 advisories and cases: counts equal the items listed; approved + rejected + waiting = decisions", c6,
       f"approved {W['approved']} rejected {W['rejected']} waiting {W['waiting']} decisions {W['reviews']}")
    last = R["hi"] - timedelta(days=1)
    c7 = ((R["lo"], R["hi"]) == quarter_range(*parse_quarter(R["quarter"]))[:2]
          and in_quarter(f"{R['lo']}-000000.csv", R["lo"], R["hi"]) and in_quarter(f"{last}-235959.csv", R["lo"], R["hi"])
          and not in_quarter(f"{R['hi']}-000000.csv", R["lo"], R["hi"])
          and not in_quarter(f"{R['lo'] - timedelta(days=1)}-235959.csv", R["lo"], R["hi"])
          and R["lo"].day == 1 and R["hi"].day == 1 and R["months"][0] == R["lo"].strftime("%Y-%m")
          and R["months"][-1] == last.strftime("%Y-%m"))
    ok("7 dates: the first and last day are in, the days either side are out", c7, f"{R['lo']} to {last}")
    return G


def status_line(G, R):
    bad = [g_ for g_ in G if not g_[1]]
    if bad or R["failed"]:
        why = [g_[0] for g_ in bad] + [f"collection could not be read: {n}" for n in sorted(R["failed"])]
        return "NOT VALID", "; ".join(why)
    return "VALID", "every accuracy check passed"


# ------------------------------------------------------------------ CSV
def _write(path, head, header, rows):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", newline="", encoding="utf-8") as f:
        w = csvsafe.writer(f)
        for r in head:
            w.writerow(r)
        w.writerow([])
        w.writerow(header)
        w.writerows(rows)


def csv_rows(R, X, W, A, PS):
    """Every CSV table, built once (the guards check these exact rows)."""
    months, Q = R["months"], R["quarter"]
    netname = X["netname"]
    prev_ok = X["prev_has_data"]
    prn = (PS or {}).get("per_report_network") or {}
    pnet = (PS or {}).get("per_network") or {}
    recs_rn = collections.Counter()
    for (name, _m, asn), v in R["rep_recs"].items():
        recs_rn[(name, asn)] += v
    adv = []
    keys = sorted(recs_rn, key=lambda k: (netname(k[1]), k[1], R["reports"][k[0]]["label"]))
    for name, asn in keys:
        hs = R["rep_hosts"].get((name, asn), {})
        e = R["reports"][name]
        row = [Q, asn or "", netname(asn), e["label"], e["family"]]
        for i, m in enumerate(months):
            row += [R["rep_recs"].get((name, m, asn), 0), sum(1 for v in hs.values() if v & (1 << i))]
        p = prn.get(f"{name}|{asn}") or {}
        pu = int(p.get("unique", 0) or 0)
        row += [recs_rn[(name, asn)], len(hs), p.get("records", 0) if prev_ok else "", pu if prev_ok else "",
                (len(hs) - pu) if prev_ok else ""]
        adv.append(row)
    for asn in sorted((a for a, v in R["net_total"].items() if v), key=lambda a: (netname(a), a)):
        hs = R["net_hosts"].get(asn, {})
        row = [Q, asn or "", netname(asn), "All reports (unique across reports)", ""]
        for i, m in enumerate(months):
            row += [R["net_month"][(asn, m)], sum(1 for v in hs.values() if v & (1 << i))]
        p = pnet.get(asn) or {}
        pu = int(p.get("unique", 0) or 0)
        row += [R["net_total"][asn], len(hs), p.get("records", 0) if prev_ok else "", pu if prev_ok else "",
                (len(hs) - pu) if prev_ok else ""]
        adv.append(row)
    # admin
    pd = R["purge"]
    lo, hi = R["lo"], R["hi"]
    end = min(R["today"], hi - timedelta(days=1))
    elapsed_days = [(lo + timedelta(days=i)).isoformat() for i in range(max(0, (end - lo).days + 1))]
    cut = min(pd["cutoff"], hi).isoformat()
    admin, purge = [], {}
    names = set(R["reports"]) | set(R["other"]) | set(R["failed"])
    for name in sorted(names, key=lambda n: (readable(n, R["reports"].get(n, {}).get("kind", "service")), n)):
        e = R["reports"].get(name)
        label = e["label"] if e else readable(name, "service")
        all_before = R["purge_all"].get(name, "")
        if name in R["failed"]:
            admin.append([Q, label, name, "FAILED", "", *[""] * len(months), len(elapsed_days), "", "", "", "", all_before, R["failed"][name]])
            continue
        if e is None:
            o = R["other"][name]
            admin.append([Q, label, name, o["why"], o["records"], *[""] * len(months), len(elapsed_days), "", "", "", "", all_before, ""])
            continue
        days = R["rep_day"].get(name, collections.Counter())
        per_m = [sum(v for d, v in days.items() if d.startswith(m)) for m in months]
        with_data = sum(1 for d in elapsed_days if days.get(d))
        purge[name] = sum(v for d, v in days.items() if d < cut)
        admin.append([Q, label, name, "report (" + e["kind"] + ")", sum(days.values()), *per_m, len(elapsed_days), with_data,
                      len(elapsed_days) - with_data, purge[name], sum(days.values()) - purge[name], all_before, ""])
    # management
    mg = []

    def add(sec, name, period, metric, value, note=""):
        mg.append([sec, name, period, metric, value, note])
    for m in months + ["quarter"]:
        t = X["totals"][m]
        for k, lab in (("records", "records"), ("unique", "unique addresses"), ("networks", "networks"), ("reports", "reports with data")):
            add("Totals", "All reports", Q if m == "quarter" else m, lab, t[k])
    add("Totals", "All reports", Q, "records without an address", X["noaddr"])
    # count audit round 2: what the counts leave out or say about the rows, stated (X from figures())
    un = X.get("unknown_network") or {}
    add("Totals", "All reports", Q, "records without a network (Unknown network, not counted as a network)",
        un.get("records", 0), f"{un.get('unique', 0)} unique addresses")
    add("Totals", "All reports", Q, "rows also in another file of the same day (counted once)", X.get("duplicates", 0))
    add("Totals", "All reports", Q, "rows without a time (counted, by their file's date)", X.get("undated", 0))
    if X.get("event_span"):
        add("Totals", "All reports", Q, "event dates of the rows", f"{X['event_span'][0]} to {X['event_span'][1]}",
            "the quarter holds the reports sent in it (by file date); their events can start a day earlier")
    for r in X.get("not_on_portal") or []:
        add("Totals", r["label"], Q, "records counted here, not shown on the portal", r["records"],
            "a report the portal's pages cannot read in full")
    for r in X["families"]:
        add("Report families", r["label"], Q, "unique addresses", r["unique"], f"{r['records']} records")
    for r in X["reports"][:15]:
        add("Top reports", r["label"], Q, "unique addresses", r["unique"], f"{r['records']} records; {r['family']}")
    for r in X["networks"][:15]:
        add("Top networks", r["label"], Q, "unique addresses", r["unique"], f"{r['records']} records")
    # regions, sectors, recurring networks, KEV CVEs and infections: every row (the PDF's cards show the top ones and
    # say "all in the management_summary CSV")
    for r in X["regions"]:
        add("Regions", r["label"], Q, "unique addresses", r["unique"], f"{r['records']} records")
    for r in X["sectors"]:
        add(_ck.SECTOR_LABEL, r["label"], Q, "unique addresses", r["unique"], f"{r['records']} records")
    for r in X.get("industries") or []:
        add(_ck.INDUSTRY_LABEL, r["label"], Q, "unique addresses", r["unique"], f"{r['records']} records")
    add("Recurring networks", "Networks with records in every month so far", Q, "networks", len(X["recurring"]),
        "months so far: " + ", ".join(X["elapsed"]))
    for r in X["recurring"]:
        add("Recurring networks", r["label"], Q, "unique addresses", r["unique"], f"{r['records']} records")
    pq = qname(*prev_quarter(*parse_quarter(Q)))
    if X["better_worse"]:
        for k, v in X["better_worse"].items():
            add("Better or worse", k, Q, "count", v, f"against {pq} ({(PS or {}).get('source', '')})")
    else:
        add("Better or worse", "Previous quarter", pq, "records", 0, "no data for the previous quarter: nothing to compare")
    add("Actively exploited (CISA KEV)", "Addresses with a KEV CVE", Q, "unique addresses", X["kev"]["hosts"], f"{X['kev']['records']} records")
    for r in X["kev"]["top"]:
        add("Actively exploited (CISA KEV)", r["label"], Q, "unique addresses", r["unique"])
    for r in X["infections"]:
        add("Infections", r["label"], Q, "unique addresses", r["unique"], f"{r['records']} records")
    add("Advisories", "Advisories sent", Q, "sends", A["sends"], f"{len(A['advisories'])} advisories")
    for a in A["advisories"]:
        add("Advisories", f"{a['ref']} {a['subject']}", a["sent"], "advisory sent", 1, a["organisation"])
    for m in months:
        add("Advisories", "Sent", m, "sends", A["per_month"].get(m, 0))
    for org, n in sorted(A["to"].items(), key=lambda kv: (-kv[1], kv[0])):
        add("Advisories", org, Q, "sends to this organisation", n)
    for (lab, lv), n in sorted(A["impact"].items(), key=lambda kv: (-kv[1], str(kv[0]))):
        add("Advisories", lab, Q, "advisories with this impact", n, lv)
    for k, lab in (("opened", "opened"), ("closed", "closed"), ("advisory_sent", "advisory sent"), ("still_open", "still open"),
                   ("expired", "expired (time to act)")):
        add("Cases and findings", "Findings", Q, lab, W[k])
    for m in months:
        add("Cases and findings", "Opened", m, "findings", W["opened_month"].get(m, 0))
    for s, n in sorted(W["status"].items()):
        add("Cases and findings", s, Q, "findings by status now", n)
    add("Time to act", "Expired unanswered (time to act passed)", Q, "findings", W["expired"])
    add("Time to act", "Median days from opening to the decision", Q, "days", "" if W["median_to_decision"] is None else W["median_to_decision"],
        f"{len(W['to_decision'])} decided")
    add("Time to act", "Median days from opening to the advisory sent", Q, "days", "" if W["median_to_advisory"] is None else W["median_to_advisory"],
        f"{len(W['to_advisory'])} sent")
    for k in ("approved", "rejected", "waiting"):
        add("Management decisions", "Decisions (one per organisation of a case)", Q, k, W[k])
    for d in W["decisions"]:
        add("Management decisions", f"{d['finding']} {d['title']}", d["date"], d["decision"], d["reason"], d["organisation"])
    orgs = []
    for org, c in sorted(A["orgs"].items()):
        orgs.append([Q, org, c["advisories"], c["devices"], c["still_seen"], c["devices"] - c["still_seen"], c["cases_open"]])
    iss = []
    for asn, lst in sorted(X["net_issues"].items(), key=lambda kv: (netname(kv[0]), kv[0])):
        for r in lst:
            cv = r["issue"].upper().startswith("CVE-")
            iss.append([Q, asn or "", netname(asn), issue_label(X, r["issue"]), "CVE" if cv else "issue",
                        "yes" if r["kev"] else "no", r["unique"], r["records"], X["cve_desc"](r["issue"]) if cv else ""])
    return {"advisor": adv, "admin": admin, "purge": purge, "management": mg, "orgs": orgs, "issues": iss,
            "advisories_listed": sum(1 for r in mg if r[0] == "Advisories" and r[3] == "advisory sent"),
            "decisions_listed": sum(1 for r in mg if r[0] == "Management decisions" and r[1].startswith("#"))}


def write_csvs(out, R, rows, status, made):
    Q, months = R["quarter"], R["months"]
    pd = R["purge"]

    empty = [["No report rows", empty_text(Q, R.get("oldest_day"))]] if not sum(R["rep_total"].values()) else []

    counted = ["Counted for", (R.get("constituency") or constituency(None))["label"]]

    def head(title):
        return [["Report status", status[0], status[1]], [title, Q, made], counted] + empty
    files = {}
    p = os.path.join(out, file_name("advisor", Q))
    _write(p, head("Advisor: networks and reports"),
           ["quarter", "asn", "network", "report", "report family"] + [x for m in months for x in (f"records {m}", f"unique addresses {m}")]
           + ["records quarter", "unique addresses quarter", "records previous quarter", "unique addresses previous quarter",
              "change in unique addresses vs previous quarter"], rows["advisor"])
    files["advisor"] = p
    p = os.path.join(out, file_name("orgs", Q))
    _write(p, head("Advisor: organisations and follow-up"),
           ["quarter", "organisation", "advisories sent", "devices named in them", "still seen after the advisory was sent",
            "not seen since", "cases still open"], rows["orgs"])
    files["orgs"] = p
    p = os.path.join(out, file_name("issues", Q))
    _write(p, head("Advisor: top issues and CVEs per network"),
           ["quarter", "asn", "network", "issue or CVE", "kind", "in CISA KEV", "unique addresses", "records", "CVE description"], rows["issues"])
    files["issues"] = p
    p = os.path.join(out, file_name("management", Q))
    _write(p, head("Management summary"), ["section", "name", "period", "metric", "value", "note"], rows["management"])
    files["management"] = p
    p = os.path.join(out, file_name("admin", Q))
    on = bool(R.get("purge_on"))
    hd = head("Administrator: rows and the purge") + [
        ["Rows and the purge", "all networks in the database, not only the constituency",
         "the stored rows and the purge's figures below cover every network: the purge clears old stored rows"],
        ["Quarterly purge", "on" if on else "off",
         ("on when this report was made (turned on in Settings → Quarterly): the database pipeline deletes on the purge "
          "day unless an administrator turns it off before then") if on else
         ("off when this report was made: nothing will be deleted unless an administrator turns it on in Settings → "
          "Quarterly before the purge day")],
        ["Quarter ends", pd["last_day"].isoformat(), ""],
        [f"{WORKING_DAYS}th working day (Mon-Fri) after: download before the end of this day", pd["working_day_15"].isoformat(),
         "" if on else "matters only if the quarterly purge is turned on"],
        ["Purge day (the next working day)", pd["purge_day"].isoformat(), "" if on else "only if the quarterly purge is turned on"],
        [f"Cutoff (purge day minus {KEEP_DAYS} days)", pd["cutoff"].isoformat(),
         "the database pipeline deletes the report rows dated before this day, of every quarter" if on else
         "if the quarterly purge is turned on: the report rows dated before this day, of every quarter, would be deleted"],
        ["Rows the purge deletes (all quarters, counted now)" if on else "Rows the purge would delete if turned on (all quarters, counted now)",
         sum(v for v in R["purge_all"].values()), ""],
        ["Collections that could not be read", len(R["failed"]), "; ".join(sorted(R["failed"]))]]
    _write(p, hd, ["quarter", "report", "collection", "kind", "rows in quarter"] + [f"rows {m}" for m in months]
           + ["days so far", "days with data", "days without data", "rows of this quarter before the cutoff",
              "rows of this quarter kept", "rows the purge deletes (all quarters)", "error"], rows["admin"])
    files["admin"] = p
    return files


# ------------------------------------------------------------------ the run
def make(db, quarter, base, today=None, exclude=(), F=None, scope=None):
    """scope: the platform's settings object (Settings → Constituency): every count, figure and list follows it; the
    purge's figures (purge_all, the admin CSV's stored rows) are always the whole database."""
    y, q = parse_quarter(quarter)
    today = today or datetime.now(timezone.utc).date()
    cv = cve_intel(base)
    kev = kev_ids(cv)
    _ck.configure_from_base(base)                      # outside the platform: its region rule from the same files
    R = collect_db(db, y, q, today, exclude, kev, scope=scope)
    R["kev_set"] = kev
    R["purge_on"] = purge_on(base)                     # what the reports say about the purge (and the permit's rule)
    R["purge"] = purge_dates(y, q)
    try:                                               # the empty-quarter sentence says from which day rows are held
        R["oldest_day"], R["oldest_known"] = oldest_day(db, exclude), True
    except Exception:                  # noqa: BLE001  (not known: the sentence leaves the day out)
        R["oldest_day"], R["oldest_known"] = None, False
    R["purge_all"] = {}
    for n in purgeable(db):
        try:
            R["purge_all"][n] = db[n].count_documents(purge_filter(R["purge"]["cutoff"].isoformat()))
        except Exception as exc:       # noqa: BLE001
            R["failed"].setdefault(n, no_addresses(f"{type(exc).__name__}: {exc}")[:300])
    reg = AsnRegistry(os.path.join(base, "data", "asns.json"))
    PS = previous_summary(db, base, y, q, today, exclude, lambda a: (reg.company(a, False) if a else "") or UNKNOWN_NET, scope)
    X = figures(R, PS, base, today, cv)
    W, A = workflow(base, y, q, R["last_seen"], title_of=lambda k: readable(k, "service"), F=F)
    rows = csv_rows(R, X, W, A, PS)
    G = guards(db, R, X, W, A, rows)
    return R, PS, X, W, A, rows, G


def publish(out, R, X, W, A, rows, G, made, prev_hosts=()):
    """Writes the CSVs and the two PDFs; then checks no output carries an address (guard 8). Returns (status, files)."""
    import quarterly_pdf
    os.makedirs(out, exist_ok=True)
    R["_guards"], R["_purge"] = G, rows["purge"]
    status = status_line(G, R)
    files = write_csvs(out, R, rows, status, made)
    drawn = []
    for kind, fn in (("pdf_management", quarterly_pdf.write_management), ("pdf_advisor", quarterly_pdf.write_advisor)):
        p = os.path.join(out, file_name(kind, R["quarter"]))
        drawn.append((p, fn(p, R, X, W, A, status, made)))
        files[kind] = p
    known = set(R["all_hosts"]) | set(prev_hosts)
    texts = " ".join(X.get("_cve_texts") or ())

    def leaky(text):
        """An address in the text: any address of the data (by its hash), or any address-shaped text that is not part of
        a published CVE text (those carry version numbers such as 0.46.6.1, never an address of the data)."""
        for m in ADDR_RE.finditer(text):
            if hkey(m.group(0)) in known or m.group(0) not in texts:
                return True
        return False
    leaks = [os.path.basename(p) for k, p in files.items() if not k.startswith("pdf") and leaky(open(p, encoding="utf-8").read())]
    leaks += [os.path.basename(p) for p, d in drawn if any(leaky(t) for t in d)]
    if leaks:                           # never leave an output with an address in it
        for p in files.values():
            if os.path.exists(p):
                os.remove(p)
        G.append(("8 no address in any output", False, "removed: " + ", ".join(leaks)))
        return ("NOT VALID", "an output carried an address; every output was removed"), {}
    G.append(("8 no address in any output", True, ""))
    return status, files


# ------------------------------------------------------------------ kept quarters (data/quarterly)
def pipeline_purge(base):
    """The pipeline's own record of its purges (<its DATA_DIR>/quarterly_purge_status.json), read only; {} if none."""
    try:
        import pipeline_link
        pdir = pipeline_link.find_dir(base)
        dd = pipeline_link.data_dir(pdir) if pdir else None
        return (read_json(os.path.join(str(dd), "quarterly_purge_status.json")) or {}) if dd else {}
    except Exception:                  # noqa: BLE001
        return {}


def quarters(base):
    """Every kept quarter, newest first: [(quarter, status dict)]."""
    top = os.path.join(base, "data", "quarterly")
    out = []
    try:
        names = os.listdir(top)
    except OSError:
        return out
    for n in names:
        if Q_RE.match(n) and not os.path.islink(os.path.join(top, n)):
            st = read_json(os.path.join(top, n, "status.json"))
            if st:
                out.append((n, st))
    return sorted(out, key=lambda x: x[0], reverse=True)


def _write_json(path, obj):
    tmp = f"{path}.{os.getpid()}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=1, default=str)
    os.replace(tmp, path)


# ------------------------------------------------------------------ the purge's switch and the permit's rule
def permit_rule(valid, made_day, purge_day, on, today):
    """(permit, why not): the one rule for a quarter's purge permit. VALID, made on or before its purge day, the purge
    turned on (Settings → Quarterly), and its purge day not passed."""
    if not valid:
        return False, WHY_INVALID
    if made_day > purge_day:
        return False, WHY_MADE_LATE
    if not on:
        return False, WHY_OFF
    if today > purge_day:
        return False, WHY_ON_LATE
    return True, ""


def permit_doc(st):
    """The permit as the pipeline reads it, from a quarter's status.json (its own report's dates and when it was made:
    the pipeline refuses a report made after its purge day)."""
    return {"quarter": st["quarter"], "valid": True, "status": "VALID", "generated_at": st["generated_at"],
            **{k: st[k] for k in ("last_day", "working_day_15", "purge_day", "cutoff")}, "keep_days": KEEP_DAYS,
            "note": "Written by Looking Glass for the database pipeline's quarterly purge (quarterly_purge.py), which "
                    "checks every date again itself, and that the purge is turned on (purge_confirmed.json)."}


def confirm_path(base):
    return os.path.join(base, "data", "quarterly", CONFIRM_FILE)


def confirmation(base):
    """The purge's switch: {enabled, by, by_name, at, at_ts, shown}. Off ({"enabled": False}) when the file is missing,
    unreadable or says anything but enabled: true."""
    d = read_json(confirm_path(base)) or {}
    return dict(d, enabled=d.get("enabled") is True)


def purge_on(base):
    return confirmation(base)["enabled"]


def _day(text):
    if isinstance(text, date):
        return text
    try:
        return date.fromisoformat(str(text or "")[:10])
    except ValueError:
        return None


# ------------------------------------------------------------------ what the cards say (true now; r89)
def say_day(d, weekday=True):
    """"Thursday 22 October 2026" (or "22 October 2026"): never a zero-padded day."""
    d = _day(d)
    if d is None:
        return ""
    return (f"{d:%A} " if weekday else "") + f"{d.day} {d:%B %Y}"


def make_day(y, q):
    """The day a quarter's reports are made automatically (the next quarter's MAKE_ON_DAY-th day)."""
    return quarter_range(y, q)[1] + timedelta(days=MAKE_ON_DAY - 1)


def empty_text(quarter, oldest=None):
    """The plain sentence for a quarter with no report rows (the cards, the PDFs and the CSVs' first lines)."""
    return f"No report rows were loaded for {quarter}" + (
        f" (Looking Glass holds report rows from {say_day(oldest, False)} on)." if _day(oldest) else ".")


def purge_state(on, conf=None):
    """The purge's switch as it is now, for the portals' cards."""
    if not on:
        return OFF_TEXT
    since = say_day((conf or {}).get("at"), False)
    return (f"The quarterly purge is on{f' (turned on {since})' if since else ''}: on the working day after the "
            f"{WORKING_DAYS}th working day after a quarter ends, the report rows older than {KEEP_DAYS} days are deleted. "
            "These reports, findings, cases and advisories are kept.")


def _tail(audience, y, q, on):
    """The dates a role needs about a quarter that is not made yet: management and advisors the day to download by
    (only while the purge is on); administrators the purge day and the cutoff."""
    pd = purge_dates(y, q)
    if audience == "admin":
        if on:
            return (f"; with the quarterly purge on, the report rows dated before {say_day(pd['cutoff'])} are deleted on "
                    f"{say_day(pd['purge_day'])}")
        return "; the quarterly purge is off, so nothing is deleted for it"
    return f" (download before the end of {say_day(pd['working_day_15'])})" if on else ""


def stands(today, audience, kept=(), on=False, since=""):
    """Where the quarter stands now, in plain sentences (every card shows them, even with no report kept): an ended
    quarter whose reports are not made yet, then the quarter in progress."""
    out = []
    y, q = quarter_of(today)
    py, pq = prev_quarter(y, q)
    pn, mk = qname(py, pq), make_day(py, pq)
    auto = not since or quarter_range(py, pq)[1].isoformat() > str(since)      # made by itself (quarterly.tick)
    if pn not in set(kept):
        if today < mk:
            out.append(f"{pn} has ended: its reports are made on {say_day(mk)}{_tail(audience, py, pq, on)}.")
        elif today == mk and auto:
            out.append(f"{pn} has ended: its reports are made today, {say_day(mk)}{_tail(audience, py, pq, on)}.")
        elif auto:
            out.append(f"{pn} has ended: its reports were due on {say_day(mk)}, and none is kept yet."
                       + (" Make them with Make it again." if audience == "admin" else ""))
    last = quarter_range(y, q)[1] - timedelta(days=1)
    out.append(f"{qname(y, q)} is in progress: it ends {say_day(last)}; its reports are made on {say_day(make_day(y, q))}"
               f"{_tail(audience, y, q, on)}.")
    return out


def purge_fact(st, on, today, permit=False, result=None):
    """A kept quarter's purge as it stands NOW (the switch today, its own dates), for the cards. The PDFs and the CSVs
    keep what was true when the report was made."""
    pday, cut, d15, made = (_day(st.get(k)) for k in ("purge_day", "cutoff", "working_day_15", "generated_at"))
    if result and result.get("outcome") == "done":
        return (f"Purged on {say_day(result.get('at'))}: the report rows dated before {say_day(result.get('cutoff'))} "
                "were deleted. These reports stay here.")
    if not st.get("valid"):
        return "No purge for this quarter: the report is NOT VALID, so nothing is deleted for it."
    if pday is None:
        return ""
    if made and made > pday:
        return f"No purge for this quarter: its purge day ({say_day(pday)}) had passed when it was made."
    if today > pday:
        if permit:
            return f"Its purge day ({say_day(pday)}) has passed: the database pipeline has not reported the purge yet."
        return (f"No purge for this quarter: its purge day ({say_day(pday)}) has passed"
                + (" (the next quarter's purge covers its rows)." if on else "."))
    if not on:
        return (f"No report rows are deleted while the quarterly purge is off. If an administrator turns it on before "
                f"{say_day(pday)}, the report rows dated before {say_day(cut)} are deleted that day: download before the end "
                f"of {say_day(d15)}.")
    if permit:
        return (f"Download before the end of {say_day(d15)}: the report rows dated before {say_day(cut)} are deleted on "
                f"{say_day(pday)}. These reports stay here.")
    why = st.get("no_permit_why") or ""
    if why == WHY_NOT_NEWEST:
        return "No purge for this quarter: a newer quarter's report exists, and only the newest quarter's purge runs."
    if why and why != WHY_OFF:
        return f"No purge for this quarter: {why}."
    return "No purge permit is written for this quarter, so nothing is deleted for it."


def can_make(today, gone="", oldest=None, known=True):
    """The quarters "Make it again" offers: ended, among the last four, with report rows (from the oldest report day in
    the database on; all of the four when that day is not known) and not purged."""
    out = []
    y, q = prev_quarter(*quarter_of(today))
    od = _day(oldest)
    for _ in range(4):
        lo, hi, _m = quarter_range(y, q)
        if (not gone or str(gone) <= lo.isoformat()) and (not known or (od is not None and od < hi)):
            out.append(qname(y, q))
        y, q = prev_quarter(y, q)
    return out


def can_make_note(today, oldest=None):
    """Why "Make it again" offers nothing, in plain words."""
    cy, cq = quarter_of(today)
    od = _day(oldest)
    if od is None or od >= quarter_range(cy, cq)[0]:
        return f"No ended quarter has report rows yet: the first report is made on {say_day(make_day(cy, cq))}."
    return "No ended quarter of the last four can be counted again: their report rows were deleted by the quarterly purge."


def purge_preview(base, today):
    """What the purge would delete next, for Settings → Quarterly and the audit log: the newest VALID report's dates and
    its dry count (rows_purge_deletes, counted when it was made), whether its purge day has passed; and the rule's next
    purge day (the newest ended quarter whose purge day has not passed, else this quarter's)."""
    y, q = quarter_of(today)
    py, pq = prev_quarter(y, q)
    ny, nq = (py, pq) if purge_dates(py, pq)["purge_day"] >= today else (y, q)
    nd = purge_dates(ny, nq)
    out = {"quarter": "", "rows": None, "purge_day": "", "cutoff": "", "working_day_15": "", "passed": False,
           "permit": False, "next": {"quarter": qname(ny, nq), "purge_day": nd["purge_day"].isoformat(),
                                     "cutoff": nd["cutoff"].isoformat()}, "keep_days": KEEP_DAYS}
    for qn, st in quarters(base):
        if st.get("valid"):
            pday = _day(st.get("purge_day"))
            rows = st.get("rows_purge_deletes")
            out.update(quarter=qn, rows=int(rows) if isinstance(rows, (int, float)) else None,
                       purge_day=st.get("purge_day", ""), cutoff=st.get("cutoff", ""), working_day_15=st.get("working_day_15", ""),
                       passed=bool(pday is None or today > pday),
                       permit=os.path.isfile(os.path.join(quarter_dir(base, qn), "purge_permit.json")))
            break
    return out


def sync_permits(base, on, today):
    """After the switch changed: the permits follow it. Off: every waiting permit is removed. On: the newest quarter's
    permit is written when the rule allows it (VALID, made before its purge day, the day not passed). Each kept quarter's
    status.json says why it has no permit. A quarter already purged is left as it is. Returns [(quarter, what)]."""
    done = []
    for i, (qn, st) in enumerate(quarters(base)):
        d = quarter_dir(base, qn)
        p = os.path.join(d, "purge_permit.json")
        if os.path.exists(os.path.join(d, "purge_result.json")):
            if os.path.lexists(p):
                os.remove(p)
            continue
        pday, made = _day(st.get("purge_day")), _day(st.get("generated_at"))
        if pday is None or made is None:
            permit, why = False, WHY_INVALID
        else:
            permit, why = permit_rule(bool(st.get("valid")), made, pday, on, today)
        if permit and i:
            permit, why = False, WHY_NOT_NEWEST
        if permit:
            _write_json(p, permit_doc(st))
            done.append((qn, "purge permit written"))
        elif os.path.lexists(p):
            os.remove(p)
            done.append((qn, "purge permit removed"))
        if (bool(st.get("permit")), st.get("no_permit_why", ""), st.get("purge_on")) != (permit, why, on):
            _write_json(os.path.join(d, "status.json"), dict(st, permit=permit, no_permit_why=why, purge_on=on))
    return done


def shown_name(full_name_of, user, saved=""):
    """How Settings → Quarterly names who switched the purge: the full name now (full_name_of(user)), else the name saved
    with the switch when it is not the sign-in name itself (before 2026-11-27 the sign-in name was saved there when an
    account had no full name), else the person code (people.person_label). Never the sign-in name."""
    user = str(user or "").strip()
    full = ""
    if user and full_name_of:
        try:
            full = str(full_name_of(user) or "").strip()
        except Exception:                  # noqa: BLE001  (the accounts file is being rewritten: the saved name or code)
            full = ""
    if full:
        return full
    saved = str(saved or "").strip()
    if saved and saved != user:
        return saved
    import people
    return people.person_label(user)


def set_purge(base, enabled, user, full_name, shown, now=None):
    """Turn the quarterly purge on or off (Settings → Quarterly; the route checked the permission, CSRF and the password).
    The switch is written first (the pipeline then refuses at once when it is off), then the permits follow it.
    Returns (the switch as written, [(quarter, what happened to its permit)])."""
    now = now or time.time()
    today = datetime.fromtimestamp(now, timezone.utc).date()
    os.makedirs(os.path.join(base, "data", "quarterly"), mode=0o700, exist_ok=True)
    # by: the sign-in name (kept in the file, as in the audit log); by_name: how the pages name the person, the full name
    # else the person code, never the sign-in name (audit 2026-11-27, 6-6)
    rec = {"enabled": bool(enabled), "by": user, "by_name": shown_name(None, user, full_name),
           "at": datetime.fromtimestamp(now, timezone.utc).isoformat(timespec="seconds"), "at_ts": round(now),
           "shown": shown}
    _write_json(confirm_path(base), rec)
    return rec, sync_permits(base, bool(enabled), today)


class Refused(Exception):
    """A quarter that cannot be made (not ended yet, or its raw rows were deleted)."""


class Waiting(Refused):
    """Not now: a pipeline run is loading reports (job_schedule.pipeline_paused); the next check tries again."""


def build(db, base, quarter, made, today=None, now=None, exclude=(), F=None, scope=None):
    """Make one quarter's outputs and put them in data/quarterly/<Q>/ in one step (the old ones replaced). The permit
    is written only when the report is VALID and made on or before its purge day. Returns its status.json."""
    y, q = parse_quarter(quarter)
    now = now or time.time()
    today = today or datetime.fromtimestamp(now, timezone.utc).date()
    lo, hi, _ = quarter_range(y, q)
    if today < hi:
        raise Refused(f"{quarter} has not ended yet: it is made once it has (from {hi})")
    gone = str(pipeline_purge(base).get("purged_before") or "")
    if gone and gone > lo.isoformat():
        raise Refused(f"the raw report rows dated before {gone} were deleted by the quarterly purge, so {quarter} cannot be "
                      "counted again; its kept report stays the record")
    top = os.path.join(base, "data", "quarterly")
    os.makedirs(top, mode=0o700, exist_ok=True)
    final = quarter_dir(base, quarter)
    tmp = tempfile.mkdtemp(prefix=f".{quarter}.", dir=top)
    t0 = time.time()
    try:
        R, PS, X, W, A, rows, G = make(db, quarter, base, today, exclude, F, scope)
        R["now_ts"] = now                  # the PDFs' "made" time is the build's own time (pretend dates in tests too)
        status, files = publish(tmp, R, X, W, A, rows, G, made)
        pd = R["purge"]
        valid = status[0] == "VALID"
        gen = datetime.fromtimestamp(now, timezone.utc).isoformat(timespec="seconds")
        permit, no_permit_why = permit_rule(valid, today, pd["purge_day"], bool(R.get("purge_on")), today)
        st = {"quarter": quarter, "status": status[0], "valid": valid, "why": status[1], "made": made,
              "generated_at": gen, "generated_ts": round(now), "took_s": round(time.time() - t0, 1),
              "guards": [{"name": g_[0], "ok": g_[1], "detail": g_[2]} for g_ in G],
              "failed_collections": sorted(R["failed"]),
              **{k: v.isoformat() for k, v in pd.items()}, "keep_days": KEEP_DAYS, "working_days": WORKING_DAYS,
              "permit": permit, "no_permit_why": no_permit_why, "purge_on": bool(R.get("purge_on")),
              "rows_purge_deletes": sum(R["purge_all"].values()), "rows": sum(R["rep_total"].values()),
              "constituency": R["constituency"]["label"], "constituency_key": R["constituency"]["key"],
              "rows_outside_constituency": sum(R["rep_out"].values()),
              **({"oldest_day": R["oldest_day"].isoformat() if R.get("oldest_day") else ""} if R.get("oldest_known") else {}),
              "files": {k: {"name": os.path.basename(p), "bytes": os.path.getsize(p),
                            "sha256": hashlib.sha256(open(p, "rb").read()).hexdigest()} for k, p in files.items()}}
        summ = dict(summary_of(R, X["netname"]), valid=valid, generated_at=gen,
                    workflow={k: W[k] for k in ("opened", "closed", "advisory_sent", "expired", "still_open", "approved",
                                                "rejected", "waiting", "reviews")},
                    advisories={"sends": A["sends"], "advisories": len(A["advisories"])},
                    kev={"hosts": X["kev"]["hosts"], "records": X["kev"]["records"]})
        _write_json(os.path.join(tmp, "summary.json"), summ)
        _write_json(os.path.join(tmp, "status.json"), st)
        if permit:
            _write_json(os.path.join(tmp, "purge_permit.json"), permit_doc(st))
        old = None
        if os.path.isdir(final):
            keep = os.path.join(final, "purge_result.json")
            if os.path.exists(keep):                     # the purge's record stays with its quarter
                shutil.copy2(keep, os.path.join(tmp, "purge_result.json"))
            old = f"{final}.old-{int(now)}"
            os.replace(final, old)
        os.replace(tmp, final)
        os.chmod(final, 0o700)
        for n in os.listdir(final):                      # owner-only, like the platform's other data files
            os.chmod(os.path.join(final, n), 0o600)
        if old:
            shutil.rmtree(old, ignore_errors=True)
        return st
    finally:
        if os.path.isdir(tmp):
            shutil.rmtree(tmp, ignore_errors=True)


# ------------------------------------------------------------------ the bell (system_alerts.py)
def _long(d):
    try:
        return date.fromisoformat(str(d)[:10]).strftime("%A %d %B %Y")
    except ValueError:
        return str(d)


def bell(base, now=None):
    """The quarterly alerts, for system_alerts.Alerts: {key, problem, title, text, at, link, perms, links}.
    perms: who sees it (any of them); links: where each goes (the first the person holds)."""
    now = now or time.time()
    today = datetime.fromtimestamp(now, timezone.utc).date()
    out = []
    kept = quarters(base)
    if not kept:
        return out
    q, st = kept[0]                                   # the newest quarter only
    at = float(st.get("generated_ts") or now)
    links = {"settings": "/settings#quarterly", "management": "/management#quarterly", "advisory": "/advisory#quarterly"}
    try:
        purge_day = date.fromisoformat(st.get("purge_day", ""))
    except ValueError:
        purge_day = today
    on = purge_on(base)
    if st.get("valid") and today <= purge_day:
        if not on:                                   # what is true now, whatever the report said when it was made
            text = "download it from your page. The quarterly purge is off on this installation, so no report rows are deleted."
        elif st.get("permit") and os.path.isfile(os.path.join(quarter_dir(base, q), "purge_permit.json")):
            text = (f"download it before the end of {_long(st.get('working_day_15'))}; the raw report rows older than "
                    f"{_long(st.get('cutoff'))} are deleted on {_long(st.get('purge_day'))}.")
        else:
            text = f"download it from your page. {st.get('no_permit_why', '').capitalize()}."
        out.append({"key": f"quarterly-ready:{q}:{round(at)}", "problem": False,
                    "title": f"{q} reports ready", "text": text, "at": at, "link": links["settings"],
                    "perms": ("settings", "management", "advisory"), "links": links})
    elif not st.get("valid"):
        out.append({"key": f"quarterly-invalid:{q}:{round(at)}", "problem": True, "title": f"The {q} report is NOT VALID",
                    "text": (f"{st.get('why', '')}. No purge permit was written, so nothing is deleted. Settings → Quarterly "
                             "shows each check; make it again once the cause is fixed."), "at": at,
                    "link": "/settings#quarterly", "perms": ("settings",)})
    vq = next(((qn, s) for qn, s in kept if s.get("valid")), None)
    if not on and vq:                                # off, and a VALID report exists: once per quarter, administrators
        out.append({"key": f"quarterly-purge-off:{vq[0]}", "problem": False, "title": "The quarterly purge is off",
                    "text": "turn it on in Settings → Quarterly, or leave it off to keep every report row.",
                    "at": float(vq[1].get("generated_ts") or now), "link": "/settings#quarterly", "perms": ("settings",)})
    for qq, s2 in kept[:2]:                            # the purge's result, for 7 days
        res = read_json(os.path.join(base, "data", "quarterly", qq, "purge_result.json"))
        if res and res.get("outcome") == "done":
            t = float(res.get("ts") or 0) or now
            if now - t < 7 * 86400:
                out.append({"key": f"quarterly-purged:{qq}:{res.get('at', '')}", "problem": False,
                            "title": f"Quarterly purge done ({qq})",
                            "text": (f"{int(res.get('rows_deleted') or 0):,} raw report rows dated before {_long(res.get('cutoff'))} "
                                     f"were deleted from {int(res.get('collections_touched') or 0)} report collections on "
                                     f"{str(res.get('at', ''))[:10]}. Findings, cases, advisories and the quarterly reports are kept."),
                            "at": t, "link": "/settings#quarterly", "perms": ("settings",)})
    last = pipeline_purge(base).get("last") or {}
    if last.get("outcome") in ("refused", "failed") and last.get("quarter"):
        lq = last["quarter"]
        mine = dict(kept).get(lq) or {}
        if mine.get("permit"):                         # a purge Looking Glass allowed, and the pipeline did not do
            out.append({"key": f"quarterly-purge-refused:{lq}:{last.get('why', '')[:60]}", "problem": True,
                        "title": f"The {lq} purge did not run",
                        "text": f"the database pipeline says: {last.get('why', '')}. Nothing was deleted. See Settings → Quarterly.",
                        "at": now, "link": "/settings#quarterly", "perms": ("settings",)})
    return out


# ------------------------------------------------------------------ the background check and the routes
def install(app, ctx):
    """ctx: base_dir, db, has_perm, csrf_ok, audit, people_name, findings, logger, serving, exclude, settings (the
    platform's settings object: its constituency scopes the reports' counts)."""
    base, hp, audit = ctx["base_dir"], ctx["has_perm"], ctx["audit"]
    log = ctx.get("logger")
    top = os.path.join(base, "data", "quarterly")
    state_path = os.path.join(top, "state.json")
    busy = {"quarter": None, "since": 0, "error": "", "by": ""}
    lock = threading.Lock()

    def exclude():
        return [x.strip() for x in (os.environ.get("EXCLUDE_COLLECTIONS", "outdated_dnssec_key") or "").split(",") if x.strip()]

    def state():
        os.makedirs(top, mode=0o700, exist_ok=True)
        s = read_json(state_path) or {}
        if not s.get("since"):                        # the first start: only quarters ending after it are made by themselves
            s["since"] = datetime.now(timezone.utc).date().isoformat()
            _write_json(state_path, s)
        return s

    def remember_oldest(d):
        s = state()
        s.update(oldest_day=d.isoformat() if d else "", oldest_checked_ts=round(time.time()))
        _write_json(state_path, s)

    def oldest(refresh=False):
        """(the oldest report day in the database or None, known): cached in state.json; looked up (one indexed query
        per report collection) only when not cached yet, or when refresh asks (the background check, every
        OLDEST_EVERY seconds; a report made and a purge done refresh it too)."""
        s = read_json(state_path) or {}
        if "oldest_day" in s and not refresh:
            return _day(s["oldest_day"]), True
        db = ctx.get("db")
        if db is None:
            return _day(s.get("oldest_day")), "oldest_day" in s
        try:
            d = oldest_day(db, exclude())
        except Exception:              # noqa: BLE001  (the database cannot be read now: the cached day, if any)
            if log:
                log.exception("quarterly: the oldest report day could not be read")
            return _day(s.get("oldest_day")), "oldest_day" in s
        remember_oldest(d)
        return d, True

    def make_now(quarter, made, by):
        """One quarter, one at a time (also across processes: a lock file)."""
        with lock:
            if busy["quarter"]:
                raise Refused(f"{busy['quarter']} is being made: wait until it is ready")
            busy.update(quarter=quarter, since=time.time(), error="", by=by)
        try:
            os.makedirs(top, mode=0o700, exist_ok=True)
            # never beside a pipeline run (r91, job_schedule.py): the pipeline's run lock is held shared while the report
            # is made, so no run starts loading meanwhile, and a run that is loading now makes this wait for the next check
            with contextlib.ExitStack() as paused:
                try:
                    held = paused.enter_context(job_schedule.pipeline_paused(base))
                except job_schedule.PipelineBusy:
                    raise Waiting(job_schedule.BUSY_TEXT) from None
                if held is None and log:
                    log.warning("quarterly %s: the database pipeline's run lock could not be read here; the report is made "
                                "without waiting for a pipeline run", quarter)
                with open(os.path.join(top, ".lock"), "w") as lf:
                    try:
                        fcntl.flock(lf, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    except OSError:
                        raise Refused("a quarterly report is being made by another process, or the database pipeline is "
                                      "purging: try again in a few minutes") from None
                    st = build(ctx["db"], base, quarter, made, exclude=exclude(), F=ctx.get("findings"),
                               scope=ctx.get("settings"))
            if "oldest_day" in st:                     # counted with the report: the cached oldest report day follows
                remember_oldest(_day(st["oldest_day"]))
            audit.add("quarterly_made", user=by, target=quarter,
                      detail=f"{st['status']} · {made} · purge permit {'written' if st['permit'] else 'not written'}"
                             + ("" if st["valid"] else f" · {st['why'][:200]}"))
            return st
        except Exception as exc:
            busy["error"] = str(exc) if isinstance(exc, Refused) else f"it could not be made ({type(exc).__name__}); the service log says more"
            if log and not isinstance(exc, Refused):
                log.exception("quarterly report %s failed", quarter)
            raise
        finally:
            busy["quarter"] = None

    def take_results():
        """The pipeline's purges, once each: kept with their quarter and written to the audit log."""
        ps = pipeline_purge(base)
        took = False
        for q, res in (ps.get("done") or {}).items():
            if not Q_RE.match(str(q)) or not isinstance(res, dict):
                continue
            d = quarter_dir(base, q)
            p = os.path.join(d, "purge_result.json")
            if not os.path.isdir(d) or os.path.exists(p):
                continue
            clean = {k: res.get(k) for k in ("quarter", "at", "outcome", "purge_day", "cutoff", "keep_days", "rows_deleted",
                                             "collections_touched")}
            clean["collections"] = {str(n): {"deleted": int((v or {}).get("deleted") or 0)} for n, v in (res.get("collections") or {}).items()}
            try:
                clean["ts"] = datetime.fromisoformat(str(res.get("at"))).timestamp()
            except ValueError:
                clean["ts"] = time.time()
            _write_json(p, clean)
            audit.add("quarterly_purge", user=SYSTEM_USER, target=q,
                      detail=(f"{int(clean['rows_deleted'] or 0):,} rows deleted from {int(clean['collections_touched'] or 0)} "
                              f"report collections, dated before {clean['cutoff']} (purge day {clean['purge_day']}); "
                              f"done by the database pipeline at {clean['at']}"))
            took = True
        if took:                                      # rows were deleted: the oldest report day moved
            oldest(refresh=True)

    def tick(now=None):
        now = now or time.time()
        today = datetime.fromtimestamp(now, timezone.utc).date()
        since = state()["since"]
        quarter = make_due(today)
        hi = quarter_range(*parse_quarter(quarter))[1] if quarter else None
        if quarter and hi.isoformat() > since and not os.path.exists(os.path.join(quarter_dir(base, quarter), "status.json")):
            try:
                make_now(quarter, "made automatically after the quarter ended", SYSTEM_USER)
            except Waiting:
                if log:
                    log.info("quarterly %s waits: the database pipeline is loading reports; tried again at the next "
                             "check (in %d minutes)", quarter, CHECK_EVERY // 60)
            except Refused:
                pass
        if not purge_on(base) and not busy["quarter"] and any(
                os.path.lexists(os.path.join(quarter_dir(base, qn), "purge_permit.json")) for qn, _ in quarters(base)):
            sync_permits(base, False, today)          # off: no permit waits (one left from before r88 included)
        take_results()
        if now - float((read_json(state_path) or {}).get("oldest_checked_ts") or 0) > OLDEST_EVERY:
            oldest(refresh=True)                       # new reports loaded since: Make it again's list follows

    def loop():
        time.sleep(90)
        while True:
            try:
                tick()
            except Exception:              # noqa: BLE001  (logged; tried again at the next check)
                if log:
                    log.exception("quarterly check failed")
            time.sleep(CHECK_EVERY)

    if ctx.get("serving"):
        threading.Thread(target=loop, daemon=True, name="quarterly").start()

    # ---------------- the lists and the downloads
    def me():
        return (getattr(g, "user", None) or {}).get("user", "")

    def role():
        return (getattr(g, "user", None) or {}).get("role", "")

    def listing(audience, admin=False, today=None):
        """Every kept quarter as the card shows it: what is true now (the purge as it stands, an empty quarter in plain
        words) and the files this person may download (may_download: none for an admin previewing a portal)."""
        out = []
        on = purge_on(base)
        today = today or datetime.now(timezone.utc).date()
        od, _known = oldest()
        who_am_i = role()
        here = constituency(ctx.get("settings"))["key"]
        for q, st in quarters(base):
            d = quarter_dir(base, q)
            files = []
            for kind, (_n, label, _who) in FILES.items():
                f = (st.get("files") or {}).get(kind)
                if f and may_download(kind, audience, who_am_i, hp) and os.path.exists(os.path.join(d, f["name"])):
                    files.append({"kind": kind, "label": label, "name": f["name"], "bytes": f["bytes"],
                                  "url": f"{PREFIX[audience]}/{q}/{kind}"})
            result = read_json(os.path.join(d, "purge_result.json"))
            permit_file = os.path.isfile(os.path.join(d, "purge_permit.json"))
            rows = st.get("rows")
            if not isinstance(rows, (int, float)):        # reports made before r89: their kept summary's total
                rows = ((read_json(os.path.join(d, "summary.json")) or {}).get("totals") or {}).get("records")
            row = {"quarter": q, "status": st.get("status"), "valid": st.get("valid"), "why": st.get("why", ""),
                   "generated_at": st.get("generated_at"), "made": st.get("made", ""), "last_day": st.get("last_day"),
                   "download_before": st.get("working_day_15"), "purge_day": st.get("purge_day"), "cutoff": st.get("cutoff"),
                   "permit": bool(st.get("permit")) and on and permit_file, "purge_on": on, "files": files,
                   "purge_text": purge_fact(st, on, today, permit_file, result), "rows": rows,
                   "empty_text": empty_text(q, od) if rows == 0 else "",
                   # reports made before r89 counted every network: the whole country
                   "counted_for": st.get("constituency") or "the whole country",
                   "other_constituency": (st.get("constituency_key") or "all") != here}
            if admin:
                row.update(guards=st.get("guards") or [], no_permit_why=st.get("no_permit_why", ""),
                           failed_collections=st.get("failed_collections") or [], rows_purge_deletes=st.get("rows_purge_deletes"),
                           purge_result=result)
            out.append(row)
        return out

    def card(audience, admin=False):
        """A card's whole answer: the quarters, where the quarter stands now, the purge's switch now, and for an admin
        previewing a portal the note that replaces the downloads."""
        today = datetime.now(timezone.utc).date()
        on = purge_on(base)
        kept = listing(audience, admin, today)
        out = {"quarters": kept, "now": stands(today, audience, [k["quarter"] for k in kept], on, state().get("since", "")),
               "purge_state": purge_state(on, confirmation(base)), "note": ""}
        if not may_see(audience, role(), hp):
            out["note"] = PREVIEW_NOTE.get(audience, "")
        return out

    def download(audience, quarter, kind):
        if not Q_RE.match(quarter or "") or kind not in FILES:
            return jsonify(error="No such file."), 404
        if not may_download(kind, audience, role(), hp):
            return jsonify(error=REFUSE[audience]), 403
        st = read_json(os.path.join(quarter_dir(base, quarter), "status.json")) or {}
        f = (st.get("files") or {}).get(kind)
        if not f:
            return jsonify(error="No such file."), 404
        try:
            path = inside(quarter_dir(base, quarter), os.path.basename(str(f["name"])))
        except ValueError:
            return jsonify(error="No such file."), 404
        try:
            with open(path, "rb") as fh:
                data = fh.read()
        except OSError:
            return jsonify(error="The file is no longer kept here."), 404
        u = me()
        when = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        if f["name"].endswith(".csv"):                # stamped: who downloaded it, and when (under the status line)
            import insider                            # the full name and the person's code, never the sign-in name
            who = insider.stamp_who(u, (ctx.get("people_name") or (lambda x: ""))(u))
            text = data.decode("utf-8")
            first, _, rest = text.partition("\n")
            buf = io.StringIO()
            csvsafe.writer(buf).writerow(["Downloaded", who, when])
            data = (first + "\n" + buf.getvalue() + rest).encode("utf-8")
        audit.add("quarterly_download", user=u, target=quarter, detail=f"{FILES[kind][1]} · {f['name']}")
        mime = "application/pdf" if f["name"].endswith(".pdf") else "text/csv"
        return Response(data, mimetype=mime, headers={"Content-Disposition": f'attachment; filename="{f["name"]}"',
                                                      "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"})

    PREFIX = {"management": "/api/mgmt/quarterly", "advisor": "/api/advisory/quarterly", "admin": "/api/admin/quarterly"}
    REFUSE = {"management": "The quarterly management report is for the management role only.",
              "advisor": "The quarterly advisor report is for advisors only.",
              "admin": "The quarterly reports' administration is for administrators (permission 'settings')."}
    PERM = AUDIENCE_PERM

    # the lists: the audience's permission (an admin previewing a portal gets the card without downloads); the files:
    # may_download, the one rule (the role's own files only)
    @app.route("/api/mgmt/quarterly")
    def api_quarterly_mgmt():
        if not hp(PERM["management"]):
            return jsonify(error=REFUSE["management"]), 403
        return jsonify(**card("management"))

    @app.route("/api/mgmt/quarterly/<quarter>/<kind>")
    def api_quarterly_mgmt_file(quarter, kind):
        if not may_see("management", role(), hp):
            return jsonify(error=REFUSE["management"]), 403
        return download("management", quarter, kind)

    @app.route("/api/advisory/quarterly")
    def api_quarterly_advisor():
        if not hp(PERM["advisor"]):
            return jsonify(error=REFUSE["advisor"]), 403
        return jsonify(**card("advisor"))

    @app.route("/api/advisory/quarterly/<quarter>/<kind>")
    def api_quarterly_advisor_file(quarter, kind):
        if not may_see("advisor", role(), hp):
            return jsonify(error=REFUSE["advisor"]), 403
        return download("advisor", quarter, kind)

    @app.route("/api/admin/quarterly")
    def api_quarterly_admin():
        if not may_see("admin", role(), hp):
            return jsonify(error=REFUSE["admin"]), 403
        today = datetime.now(timezone.utc).date()
        ps = pipeline_purge(base)
        od, known = oldest()
        can = can_make(today, str(ps.get("purged_before") or ""), od, known)
        return jsonify(**card("admin", admin=True), can_make=can, can_make_note="" if can else can_make_note(today, od),
                       oldest_day=od.isoformat() if od else "", making=busy["quarter"], error=busy["error"],
                       pipeline={"found": bool(ps), "purged_before": ps.get("purged_before", ""),
                                 "last": {k: (ps.get("last") or {}).get(k) for k in ("quarter", "at", "outcome", "why",
                                                                                      "purge_day", "cutoff", "rows_deleted")}},
                       rules={"working_days": WORKING_DAYS, "keep_days": KEEP_DAYS}, purge=purge_view(today))

    def purge_view(today=None):
        """The switch as Settings → Quarterly shows it: on or off, since when, by whom, and what the purge would delete."""
        c = confirmation(base)
        # never the sign-in name (audit 2026-11-27, 6-6): "by" and "by_name" both carry the full name or the person code
        who = shown_name(ctx.get("people_name"), c.get("by", ""), c.get("by_name", "")) if (c.get("by") or c.get("by_name")) else ""
        return {"enabled": c["enabled"], "since": c.get("at", "") if c["enabled"] else "",
                "by": who if c["enabled"] else "", "by_name": who if c["enabled"] else "",
                "changed_at": c.get("at", ""), "changed_by_name": who,
                "preview": purge_preview(base, today or datetime.now(timezone.utc).date())}

    @app.route("/api/admin/quarterly/purge", methods=["POST"])
    def api_quarterly_purge():
        """Turn the quarterly purge on or off (r88, the user 2026-11-21): the Settings permission, the page's CSRF token,
        a session younger than 12 hours and the administrator's own password again (password_policy.check_own_password:
        a wrong one counts as a failed sign-in). Turning it on needs the figures the page showed (they must still be the
        same). Every change is in the audit log: who, when, what it would delete then."""
        if not hp(PERM["admin"]):
            return jsonify(error=REFUSE["admin"]), 403
        if request.mimetype != "application/json" or not ctx["csrf_ok"]():
            return jsonify(error="Refused (the request did not come from this page)."), 403
        if not ctx.get("fresh", lambda: False)():
            return jsonify(error="Sign in again to make changes (your session is older than 12 hours).", reauth=True), 403
        if not all(k in ctx for k in ("users", "throttle", "client")):
            return jsonify(error="This needs a signed-in administrator's own password."), 403
        body = request.get_json(silent=True) or {}
        enabled = body.get("enabled")
        if not isinstance(enabled, bool):
            return jsonify(error="Say whether to turn the quarterly purge on or off."), 400
        if enabled == purge_on(base):
            return jsonify(error=f"The quarterly purge is already {'on' if enabled else 'off'}.", purge=purge_view()), 409
        today = datetime.now(timezone.utc).date()
        pv = purge_preview(base, today)
        shown = body.get("shown") if isinstance(body.get("shown"), dict) else {}
        if enabled and (str(shown.get("quarter") or "") != pv["quarter"] or shown.get("rows") != pv["rows"]
                        or str(shown.get("purge_day") or "") != (pv["purge_day"] or pv["next"]["purge_day"])):
            return jsonify(error="What the purge would delete has changed since this page was opened: read it again, then confirm.",
                           purge=purge_view(today)), 409
        import password_policy                       # the one password re-check (also Settings → Workers and Password policy)
        bad = password_policy.check_own_password(ctx, "quarterly_purge_password_failed",
                                                 f"Settings → Quarterly: wrong password (turning the purge {'on' if enabled else 'off'})")
        if bad:
            return bad
        u = me()
        full = (ctx.get("people_name") or (lambda x: ""))(u) or u
        os.makedirs(top, mode=0o700, exist_ok=True)
        with open(os.path.join(top, ".lock"), "w") as lf:      # never while a report is being made (it writes permits too)
            try:
                fcntl.flock(lf, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                return jsonify(error="A quarterly report is being made, or the database pipeline is purging: try again "
                                     "in a few minutes."), 409
            if busy["quarter"]:
                return jsonify(error=f"{busy['quarter']} is being made: try again once it is ready."), 409
            seen = {"quarter": pv["quarter"], "rows": pv["rows"], "purge_day": pv["purge_day"] or pv["next"]["purge_day"],
                    "cutoff": pv["cutoff"] or pv["next"]["cutoff"], "keep_days": KEEP_DAYS}
            _rec, changes = set_purge(base, enabled, u, full, seen)
        if pv["quarter"]:
            what = (f"{pv['rows']:,}" if isinstance(pv["rows"], int) else "an unknown number of") + \
                   f" raw report rows dated before {pv['cutoff']} (the {pv['quarter']} report's count; purge day {pv['purge_day']}" + \
                   (", passed" if pv["passed"] else "") + ")"
        else:
            what = (f"no VALID quarterly report yet, so no count; the next purge day by the rule is {pv['next']['purge_day']} "
                    f"(rows dated before {pv['next']['cutoff']})")
        perm = "; ".join(f"{q}: {w}" for q, w in changes) or "no purge permit written or removed"
        audit.add("quarterly_purge_on" if enabled else "quarterly_purge_off", user=u, target=pv["quarter"],
                  detail=(f"turned {'on' if enabled else 'off'} by {full} · it would delete then: {what} · {perm}")[:900])
        return jsonify(ok=True, purge=purge_view(today))

    @app.route("/api/admin/quarterly/<quarter>/<kind>")
    def api_quarterly_admin_file(quarter, kind):
        if not may_see("admin", role(), hp):
            return jsonify(error=REFUSE["admin"]), 403
        return download("admin", quarter, kind)

    @app.route("/api/admin/quarterly/make", methods=["POST"])
    def api_quarterly_make():
        """Make a quarter's report again (an administrator): in the background; the page asks until it is ready."""
        if not hp(PERM["admin"]):
            return jsonify(error=REFUSE["admin"]), 403
        if not ctx["csrf_ok"]():
            return jsonify(error="Refused (the request did not come from this page)."), 403
        quarter = str((request.get_json(silent=True) or {}).get("quarter") or "").strip().upper()
        if not Q_RE.match(quarter):
            return jsonify(error="Choose a quarter, like 2026Q4."), 400
        y, q = parse_quarter(quarter)
        today = datetime.now(timezone.utc).date()
        if today < quarter_range(y, q)[1]:
            return jsonify(error=f"{quarter} has not ended yet."), 409
        od, known = oldest()
        if quarter not in can_make(today, str(pipeline_purge(base).get("purged_before") or ""), od, known):
            return jsonify(error=f"{quarter} cannot be made again: only an ended quarter of the last four with report rows "
                                 "that were not purged can."), 409
        if busy["quarter"]:
            return jsonify(error=f"{busy['quarter']} is being made: wait until it is ready."), 409
        if job_schedule.pipeline_running(base):        # never beside a pipeline run (r91)
            return jsonify(error=job_schedule.BUSY_TEXT), 409
        u = me()

        def run():
            try:
                make_now(quarter, "made again on request", u)
            except Exception:              # noqa: BLE001  (kept in busy["error"]; the page shows it)
                pass
        threading.Thread(target=run, daemon=True, name="quarterly-make").start()
        return jsonify(ok=True, making=quarter), 202

    return {"tick": tick, "make": make_now, "busy": busy, "take_results": take_results}
