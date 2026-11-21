"""The quarterly report and the quarterly purge (r85, the user 2026-11-20).

Once a quarter has ended (the first check after 00:00 UTC on the next quarter's 3rd day, when the quarter's last
day's reports have arrived; the user 2026-11-20), Looking Glass counts the
quarter's Shadowserver reports and its own workflow, and keeps the result in data/quarterly/<YYYYQn>/:
  quarterly_<Q>_management.pdf, management_summary_<Q>.csv              management (the Executive portal) and admins
  quarterly_<Q>_advisor.pdf, advisor_networks_ / advisor_organisations_ /
  advisor_network_issues_<Q>.csv                                         advisors (the advisory portal) and admins
  admin_purge_<Q>.csv                                                    admins (Settings → Quarterly)
  summary.json   the counts the next quarter compares against (per network and report, no address); kept for ever:
                 the statistics that survive the purge
  status.json    VALID or NOT VALID, every accuracy check, when it was made, the 15th working day, the purge day, the cutoff
  purge_permit.json   only when the report is VALID (and made before its purge day): the database pipeline's permission
                 to delete the raw report rows dated before the cutoff, on the purge day. The platform never deletes
                 anything itself and never writes the pipeline's files; the pipeline reads this file read-only, works
                 the dates out again and refuses anything else (quarterly_purge.py in the pipeline's folder).
  purge_result.json   the pipeline's result, copied here once it purged (and written to the audit log)

Reading: MongoDB find / aggregate / count_documents only, and the platform's data/ files. Counting is two-stage:
MongoDB groups (month, network, host); Python counts the groups, so no document ever holds a network's addresses.
Addresses are kept only in memory, as hashes, and never written: every output carries counts only, and a final check
(guard 8) removes every output and fails the run if any of them holds an address.

Field mapping (the platform's own rules): single-host reports (services.ServiceRegistry) use ip / asn / region /
sector; communications (sources.Registry, detect_layout) use the constituent's side, the first prefix of
sources.PREFIXES[layout]; destination-only reports use dst_. The quarter is chosen by file name (it starts with the
report day and is indexed): from the first day, up to (not including) the next quarter's first day.

Who gets what: management the management PDF and summary CSV; advisors the advisor PDF and their three CSVs; admins
everything, the purge CSV, "Make it again" and the purge's status. Researchers, analysts and external accounts get
nothing. Every download is sealed (insider.py), stamped with who and when (CSV) and in the audit log.
Installed from features.py: quarterly.install(app, ctx). The PDFs are drawn by quarterly_pdf.py.
"""
import collections
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

import csvsafe
import services
import sources
import special_reports
from privacy import IPV4_FULL, IPV6, AsnRegistry

KEEP_DAYS = 31                       # the purge always keeps the last 31 days
MAKE_ON_DAY = 3                      # made automatically on the next quarter's 3rd day (its last day's reports are in by then)
WORKING_DAYS = 15                    # working days (Monday to Friday) to download the reports before the purge
UNKNOWN_NET = "Unknown network"
UNKNOWN_REGION = "Region unknown"    # as the services platform says it (services_api.region_label)
ADDR_RE = re.compile(IPV4_FULL.pattern + "|" + IPV6.pattern)
Q_RE = re.compile(r"\A\d{4}Q[1-4]\Z")      # \Z: "$" would also accept a trailing newline
SYSTEM_USER = "looking-glass"
CHECK_EVERY = 600                    # seconds between the background checks
# the collections the purge may touch: the pipeline's own rule (report_names.valid + quarterly_purge.NOT_REPORTS)
REPORT_NAME = re.compile(r"^[a-z0-9][a-z0-9_]{0,63}$")
NOT_REPORTS = ("files_", "discovered_fields_", "lg_", "system.")

# every output of a quarter: kind -> (file name, readable name, who gets it)
FILES = {
    "pdf_management": ("quarterly_{q}_management.pdf", "Management report (PDF)", ("management", "admin")),
    "management": ("management_summary_{q}.csv", "Management summary (CSV)", ("management", "admin")),
    "pdf_advisor": ("quarterly_{q}_advisor.pdf", "Advisor report (PDF)", ("advisor", "admin")),
    "advisor": ("advisor_networks_{q}.csv", "Networks and reports (CSV)", ("advisor", "admin")),
    "orgs": ("advisor_organisations_{q}.csv", "Organisations and follow-up (CSV)", ("advisor", "admin")),
    "issues": ("advisor_network_issues_{q}.csv", "Issues and CVEs per network (CSV)", ("advisor", "admin")),
    "admin": ("admin_purge_{q}.csv", "Rows and the purge (CSV)", ("admin",)),
}


def file_name(kind, quarter):
    return FILES[kind][0].format(q=quarter)


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


# ------------------------------------------------------------------ helpers
def hkey(v):
    """An address as an in-memory key only (never written anywhere)."""
    s = str(v).strip() if v is not None else ""
    return hashlib.blake2b(s.encode(), digest_size=8).digest() if s else None


def norm_asn(v):
    if v in (None, ""):
        return ""
    if isinstance(v, float):
        v = int(v)
    s = str(v).strip().upper().replace("AS", "")
    return s if s.isdigit() and s != "0" else ""


def no_addresses(text):
    return ADDR_RE.sub("[address]", str(text or ""))


def region_label(v):
    """A region as the platform shows it ("Nairobi", not "NAIROBI"; services_api.region_label, combos.py)."""
    s = str(v or "").strip()
    return s.title() if s else UNKNOWN_REGION


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
    for e in comm.items + comm.unsupported:
        lay = e.get("layout")
        sp = "dst_" if lay == "target" else sources.PREFIXES.get(lay or "standard", ("src_", ""))[0]
        out[e["name"]] = {"kind": "communication", "layout": lay or "unrecognised",
                          "fields": {k: sp + k for k in ("ip", "asn", "region", "sector")}}
    svc = services.ServiceRegistry(db, exclude=exclude)
    svc.get(force=True)
    for e in svc.items + svc.unsupported:
        out.setdefault(e["name"], {"kind": "service", "layout": "single-host",
                                   "fields": {k: k for k in ("ip", "asn", "region", "sector")}})
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
def collect_db(db, y, q, today, exclude=(), kev=None, light=False):
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
         "kev_hosts": set(), "kev_recs": 0, "cve_hosts": collections.defaultdict(set), "kev_cves": set()}
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
        pipe = [{"$match": match},
                {"$group": {"_id": key, "n": {"$sum": 1}, "d": {"$max": {"$substrCP": ["$filename", 0, 10]}},
                            "r": {"$first": "$" + f["region"]}, "s": {"$first": "$" + f["sector"]}}}]
        try:
            days = collections.Counter({d["_id"]: d["n"] for d in db[name].aggregate(
                [{"$match": match}, {"$group": {"_id": {"$substrCP": ["$filename", 0, 10]}, "n": {"$sum": 1}}}], allowDiskUse=True)})
            groups = list(db[name].aggregate(pipe, allowDiskUse=True, batchSize=5000))   # stage 1: (month, network, host)
        except Exception as exc:       # noqa: BLE001  unreadable: reported, never skipped silently
            R["failed"][name] = no_addresses(f"{type(exc).__name__}: {exc}")[:300]
            continue
        R["rep_day"][name] = days
        R["rep_total"][name] += 0
        for g_ in groups:               # stage 2: counted here
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
    sc = str(sector or "").strip() or "Not given"
    R["region"][rg].add(h); R["region_recs"][rg] += n
    R["sector"][sc].add(h); R["sector_recs"][sc] += n
    if infection:
        inf = next((str(k.get(x)).strip() for x in ("i", "f", "t") if str(k.get(x) or "").strip()), name)
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
    for a in sorted(store.all(), key=lambda a: a.get("ref", "")):
        sq = [s for s in a.get("sends") or [] if inq(s.get("at"))]
        if not sq:
            continue
        org = a.get("network") or "All networks"
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
        names, devs = _advisory_devices(base, a)
        for fl in imp.of_names(names, title_of):
            A["impact"][(fl.get("label") or fl.get("flag"), fl.get("level") or "")] += 1
        A["orgs"][org]["devices"] += len(devs)
        A["orgs"][org]["still_seen"] += sum(1 for h in devs if last_seen.get(h, "") > first_send)
    for x in items.values():
        if x.get("kind") != "case" and x["status"] in findings.OPEN and x.get("network"):
            A["orgs"][x["network"]]["cases_open"] += 1
    return W, A


def _advisory_devices(base, a):
    folder = os.path.join(base, "data", "advisories", "files", a["ref"])
    reps = a.get("reports") or []
    names, devs = set(), set()
    if not reps:
        return names, devs
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
                    for part in re.split(r"[;|]", r.get("reports") or ""):
                        if part.strip():
                            names.add(part.strip())
    except (OSError, zipfile.BadZipFile, KeyError):
        pass
    return names, devs


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
    for name, v in R["rep_total"].items():
        if v:
            hosts = set()
            for (r, _a), hs in R["rep_hosts"].items():
                if r == name:
                    hosts.update(hs)
            per_rep[name] = {"label": R["reports"][name]["label"], "family": R["reports"][name]["family"], "records": v,
                             "unique": len(hosts)}
    return {"quarter": R["quarter"], "totals": {"records": sum(R["rep_total"].values()), "unique": len(R["all_hosts"]),
                                                "networks": sum(1 for v in R["net_total"].values() if v),
                                                "reports": sum(1 for v in R["rep_total"].values() if v)},
            "per_network": per_net, "per_report": per_rep, "per_report_network": per_rn}


def read_json(path):
    try:
        with open(path, encoding="utf-8") as fh:
            d = json.load(fh)
        return d if isinstance(d, dict) else None
    except (OSError, ValueError):
        return None


def quarter_dir(base, quarter):
    if not Q_RE.match(str(quarter or "")):
        raise ValueError("not a quarter")
    return os.path.join(base, "data", "quarterly", quarter)


def previous_summary(db, base, y, q, today, exclude, netname):
    """The previous quarter's counts: its kept summary.json (made before its rows were purged) when it was VALID, else
    counted from MongoDB now (counts only)."""
    py, pq = prev_quarter(y, q)
    try:
        s = read_json(os.path.join(quarter_dir(base, qname(py, pq)), "summary.json"))
    except ValueError:
        s = None
    if s and s.get("valid") and isinstance(s.get("totals"), dict):
        return dict(s, source="the previous quarter's kept summary")
    P = collect_db(db, py, pq, today, exclude, light=True)
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
        if m == "quarter":
            uniq = len(R["all_hosts"])
            nets = sum(1 for a, v in R["net_total"].items() if v)
            repn = sum(1 for r, v in R["rep_total"].items() if v)
        else:
            b = 1 << i
            uniq = sum(1 for v in R["all_hosts"].values() if v & b)
            nets = len({a for (a, mm), v in R["net_month"].items() if mm == m and v})
            repn = len({r for (r, mm, a), v in R["rep_recs"].items() if mm == m and v})
        tot[m] = {"records": recs, "unique": uniq, "networks": nets, "reports": repn}
    X["totals"] = tot
    X["noaddr"] = sum(R["rep_noaddr"].values())
    fam_recs, fam_hosts = collections.Counter(), collections.defaultdict(set)
    rep_rows = []
    for name, v in R["rep_total"].items():
        e = R["reports"][name]
        hosts = set()
        for (r, a), hs in R["rep_hosts"].items():
            if r == name:
                hosts.update(hs)
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
    X["networks"] = sorted(({"label": n, "records": by_name_recs[n], "unique": len(by_name_hosts[n])} for n in by_name_recs),
                           key=lambda r: (-r["unique"], r["label"]))
    rec = []
    for n in by_name_recs:
        asns = [a for a in R["net_total"] if netname(a) == n]
        if elapsed and all(sum(R["net_month"][(a, m)] for a in asns) for m in elapsed):
            rec.append({"label": n, "unique": len(by_name_hosts[n]), "records": by_name_recs[n]})
    X["recurring"] = sorted(rec, key=lambda r: (-r["unique"], r["label"]))
    # better or worse against the previous quarter (its counts: kept, or counted now)
    X["prev"] = PS
    X["prev_has_data"] = bool(PS and (PS.get("totals") or {}).get("records"))
    if X["prev_has_data"]:
        now_n = {a for a, v in R["net_total"].items() if v and a}       # "unknown network" is not a network that came or went
        was_n = {a for a, v in (PS.get("per_network") or {}).items() if a and (v or {}).get("records")}
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
    X["sectors"] = sorted(({"label": k, "unique": len(v), "records": R["sector_recs"][k]} for k, v in R["sector"].items()),
                          key=lambda r: (-r["unique"], r["label"]))
    titles = _infection_titles(base)
    X["infections"] = sorted(({"label": titles.get(k.lower(), k), "unique": len(v), "records": R["inf_recs"][k]} for k, v in R["inf_hosts"].items()),
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
    X["net_issues"] = {a: sorted(v, key=lambda r: (-r["unique"], r["issue"]))[:10] for a, v in per_net.items()}
    return X


def _infection_titles(base):
    try:
        with open(os.path.join(base, "data", "infections.json"), encoding="utf-8") as f:
            d = json.load(f).get("infections") or {}
        return {k.lower(): (v.get("title") or k) for k, v in d.items() if isinstance(v, dict)}
    except (OSError, ValueError):
        return {}


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
    bad = [r for r in R["rep_total"] if sum(v for (n, m, a), v in R["rep_recs"].items() if n == r) != R["rep_total"][r]]
    bad += [f"network {a or '-'}" for a in R["net_total"] if sum(R["net_month"][(a, m)] for m in months) != R["net_total"][a]]
    ok("1 months add up to the quarter (every report and network)", not bad, ", ".join(map(str, bad[:5])))
    bad = []
    for (n, a), hs in R["rep_hosts"].items():
        if len(hs) > sum(v for (nn, m, aa), v in R["rep_recs"].items() if nn == n and aa == a):
            bad.append(f"{n}/{a}")
        for i, m in enumerate(months):
            if sum(1 for v in hs.values() if v & (1 << i)) > R["rep_recs"].get((n, m, a), 0):
                bad.append(f"{n}/{a}/{m}")
    for a, hs in R["net_hosts"].items():
        per = [len(h) for (n, aa), h in R["rep_hosts"].items() if aa == a]
        if per and not (max(per) <= len(hs) <= sum(per)):
            bad.append(f"network {a}: all reports {len(hs)} outside {max(per)}..{sum(per)}")
        if len(hs) > R["net_total"][a]:
            bad.append(f"network {a}: more addresses than records")
    ok("2 unique addresses <= records; all-reports uniques between the largest report and the sum", not bad, "; ".join(bad[:5]))
    bad = []
    for n in R["rep_total"]:
        try:
            k = db[n].count_documents({"filename": {"$gte": lo_s, "$lt": hi_s}})
            if k != R["rep_total"][n] or k != sum(R["rep_day"][n].values()):
                bad.append(f"{n}: {k} counted, {R['rep_total'][n]} in the report")
            for i, m in enumerate(months):
                m_hi = months[i + 1] + "-01" if i + 1 < len(months) else hi_s
                km = db[n].count_documents({"filename": {"$gte": m + "-01", "$lt": m_hi}})
                if km != sum(v for d, v in R["rep_day"][n].items() if d.startswith(m)):
                    bad.append(f"{n} {m}: {km} counted")
        except Exception as exc:       # noqa: BLE001
            bad.append(f"{n}: recount failed ({type(exc).__name__})")
    ok("3 independent recount (count_documents) equals every report's total and month rows", not bad, "; ".join(bad[:5]))
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
    for r in X["families"]:
        add("Report families", r["label"], Q, "unique addresses", r["unique"], f"{r['records']} records")
    for r in X["reports"][:15]:
        add("Top reports", r["label"], Q, "unique addresses", r["unique"], f"{r['records']} records; {r['family']}")
    for r in X["networks"][:15]:
        add("Top networks", r["label"], Q, "unique addresses", r["unique"], f"{r['records']} records")
    for r in X["regions"][:20]:
        add("Regions", r["label"], Q, "unique addresses", r["unique"], f"{r['records']} records")
    for r in X["sectors"][:20]:
        add("Sectors", r["label"], Q, "unique addresses", r["unique"], f"{r['records']} records")
    add("Recurring networks", "Networks with records in every month so far", Q, "networks", len(X["recurring"]),
        "months so far: " + ", ".join(X["elapsed"]))
    for r in X["recurring"][:15]:
        add("Recurring networks", r["label"], Q, "unique addresses", r["unique"], f"{r['records']} records")
    pq = qname(*prev_quarter(*parse_quarter(Q)))
    if X["better_worse"]:
        for k, v in X["better_worse"].items():
            add("Better or worse", k, Q, "count", v, f"against {pq} ({(PS or {}).get('source', '')})")
    else:
        add("Better or worse", "Previous quarter", pq, "records", 0, "no data for the previous quarter: nothing to compare")
    add("Actively exploited (CISA KEV)", "Addresses with a KEV CVE", Q, "unique addresses", X["kev"]["hosts"], f"{X['kev']['records']} records")
    for r in X["kev"]["top"][:10]:
        add("Actively exploited (CISA KEV)", r["label"], Q, "unique addresses", r["unique"])
    for r in X["infections"][:15]:
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

    def head(title):
        return [["Report status", status[0], status[1]], [title, Q, made]]
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
    hd = head("Administrator: rows and the purge") + [
        ["Quarter ends", pd["last_day"].isoformat(), ""],
        [f"{WORKING_DAYS}th working day (Mon-Fri) after: download before the end of this day", pd["working_day_15"].isoformat(), ""],
        ["Purge day (the next working day)", pd["purge_day"].isoformat(), ""],
        [f"Cutoff (purge day minus {KEEP_DAYS} days)", pd["cutoff"].isoformat(),
         "the database pipeline deletes the report rows dated before this day, of every quarter"],
        ["Rows the purge deletes (all quarters, counted now)", sum(v for v in R["purge_all"].values()), ""],
        ["Collections that could not be read", len(R["failed"]), "; ".join(sorted(R["failed"]))]]
    _write(p, hd, ["quarter", "report", "collection", "kind", "rows in quarter"] + [f"rows {m}" for m in months]
           + ["days so far", "days with data", "days without data", "rows of this quarter before the cutoff",
              "rows of this quarter kept", "rows the purge deletes (all quarters)", "error"], rows["admin"])
    files["admin"] = p
    return files


# ------------------------------------------------------------------ the run
def make(db, quarter, base, today=None, exclude=(), F=None):
    y, q = parse_quarter(quarter)
    today = today or datetime.now(timezone.utc).date()
    cv = cve_intel(base)
    kev = kev_ids(cv)
    R = collect_db(db, y, q, today, exclude, kev)
    R["kev_set"] = kev
    R["purge"] = purge_dates(y, q)
    R["purge_all"] = {}
    for n in purgeable(db):
        try:
            R["purge_all"][n] = db[n].count_documents(purge_filter(R["purge"]["cutoff"].isoformat()))
        except Exception as exc:       # noqa: BLE001
            R["failed"].setdefault(n, no_addresses(f"{type(exc).__name__}: {exc}")[:300])
    reg = AsnRegistry(os.path.join(base, "data", "asns.json"))
    PS = previous_summary(db, base, y, q, today, exclude, lambda a: (reg.company(a, False) if a else "") or UNKNOWN_NET)
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


class Refused(Exception):
    """A quarter that cannot be made (not ended yet, or its raw rows were deleted)."""


def build(db, base, quarter, made, today=None, now=None, exclude=(), F=None):
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
        R, PS, X, W, A, rows, G = make(db, quarter, base, today, exclude, F)
        status, files = publish(tmp, R, X, W, A, rows, G, made)
        pd = R["purge"]
        valid = status[0] == "VALID"
        gen = datetime.fromtimestamp(now, timezone.utc).isoformat(timespec="seconds")
        permit = valid and today <= pd["purge_day"]
        st = {"quarter": quarter, "status": status[0], "valid": valid, "why": status[1], "made": made,
              "generated_at": gen, "generated_ts": round(now), "took_s": round(time.time() - t0, 1),
              "guards": [{"name": g_[0], "ok": g_[1], "detail": g_[2]} for g_ in G],
              "failed_collections": sorted(R["failed"]),
              **{k: v.isoformat() for k, v in pd.items()}, "keep_days": KEEP_DAYS, "working_days": WORKING_DAYS,
              "permit": permit,
              "no_permit_why": "" if permit else ("the report is NOT VALID" if not valid else
                                                  "made after its purge day: nothing is deleted for this quarter (the next "
                                                  "quarter's purge covers its rows)"),
              "rows_purge_deletes": sum(R["purge_all"].values()),
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
            _write_json(os.path.join(tmp, "purge_permit.json"), {
                "quarter": quarter, "valid": True, "status": "VALID", "generated_at": gen,
                **{k: v.isoformat() for k, v in pd.items()}, "keep_days": KEEP_DAYS,
                "note": "Written by Looking Glass for the database pipeline's quarterly purge (quarterly_purge.py), which "
                        "checks every date again itself."})
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
    if st.get("valid") and today <= purge_day:
        if st.get("permit"):
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
    """ctx: base_dir, db, has_perm, csrf_ok, audit, people_name, findings, logger, serving, exclude."""
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

    def make_now(quarter, made, by):
        """One quarter, one at a time (also across processes: a lock file)."""
        with lock:
            if busy["quarter"]:
                raise Refused(f"{busy['quarter']} is being made: wait until it is ready")
            busy.update(quarter=quarter, since=time.time(), error="", by=by)
        try:
            os.makedirs(top, mode=0o700, exist_ok=True)
            with open(os.path.join(top, ".lock"), "w") as lf:
                try:
                    fcntl.flock(lf, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except OSError:
                    raise Refused("another Looking Glass process is making a quarterly report") from None
                st = build(ctx["db"], base, quarter, made, exclude=exclude(), F=ctx.get("findings"))
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

    def tick(now=None):
        now = now or time.time()
        today = datetime.fromtimestamp(now, timezone.utc).date()
        since = state()["since"]
        quarter = make_due(today)
        hi = quarter_range(*parse_quarter(quarter))[1] if quarter else None
        if quarter and hi.isoformat() > since and not os.path.exists(os.path.join(quarter_dir(base, quarter), "status.json")):
            try:
                make_now(quarter, "made automatically after the quarter ended", SYSTEM_USER)
            except Refused:
                pass
        take_results()

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

    def listing(audience, admin=False):
        out = []
        for q, st in quarters(base):
            files = []
            for kind, (_n, label, who) in FILES.items():
                f = (st.get("files") or {}).get(kind)
                if f and audience in who and os.path.exists(os.path.join(quarter_dir(base, q), f["name"])):
                    files.append({"kind": kind, "label": label, "name": f["name"], "bytes": f["bytes"],
                                  "url": f"{PREFIX[audience]}/{q}/{kind}"})
            row = {"quarter": q, "status": st.get("status"), "valid": st.get("valid"), "why": st.get("why", ""),
                   "generated_at": st.get("generated_at"), "made": st.get("made", ""), "last_day": st.get("last_day"),
                   "download_before": st.get("working_day_15"), "purge_day": st.get("purge_day"), "cutoff": st.get("cutoff"),
                   "permit": bool(st.get("permit")), "files": files}
            if admin:
                row.update(guards=st.get("guards") or [], no_permit_why=st.get("no_permit_why", ""),
                           failed_collections=st.get("failed_collections") or [], rows_purge_deletes=st.get("rows_purge_deletes"),
                           purge_result=read_json(os.path.join(quarter_dir(base, q), "purge_result.json")))
            out.append(row)
        return out

    def download(audience, quarter, kind):
        if not Q_RE.match(quarter or "") or kind not in FILES or audience not in FILES[kind][2]:
            return jsonify(error="No such file."), 404
        st = read_json(os.path.join(quarter_dir(base, quarter), "status.json")) or {}
        f = (st.get("files") or {}).get(kind)
        if not f:
            return jsonify(error="No such file."), 404
        path = os.path.join(quarter_dir(base, quarter), f["name"])
        try:
            with open(path, "rb") as fh:
                data = fh.read()
        except OSError:
            return jsonify(error="The file is no longer kept here."), 404
        u = me()
        when = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        if f["name"].endswith(".csv"):                # stamped: who downloaded it, and when (under the status line)
            who = (ctx.get("people_name") or (lambda x: ""))(u) or u
            text = data.decode("utf-8")
            first, _, rest = text.partition("\n")
            buf = io.StringIO()
            csvsafe.writer(buf).writerow(["Downloaded", f"{who} ({u})" if who != u else u, when])
            data = (first + "\n" + buf.getvalue() + rest).encode("utf-8")
        audit.add("quarterly_download", user=u, target=quarter, detail=f"{FILES[kind][1]} · {f['name']}")
        mime = "application/pdf" if f["name"].endswith(".pdf") else "text/csv"
        return Response(data, mimetype=mime, headers={"Content-Disposition": f'attachment; filename="{f["name"]}"',
                                                      "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"})

    PREFIX = {"management": "/api/mgmt/quarterly", "advisor": "/api/advisory/quarterly", "admin": "/api/admin/quarterly"}
    REFUSE = {"management": "The quarterly management report is for the management role (and admins).",
              "advisor": "The quarterly advisor report is for advisors (and admins).",
              "admin": "The quarterly reports' administration is for administrators (permission 'settings')."}
    PERM = {"management": "management", "advisor": "advisory", "admin": "settings"}

    @app.route("/api/mgmt/quarterly")
    def api_quarterly_mgmt():
        if not hp(PERM["management"]):
            return jsonify(error=REFUSE["management"]), 403
        return jsonify(quarters=listing("management"))

    @app.route("/api/mgmt/quarterly/<quarter>/<kind>")
    def api_quarterly_mgmt_file(quarter, kind):
        if not hp(PERM["management"]):
            return jsonify(error=REFUSE["management"]), 403
        return download("management", quarter, kind)

    @app.route("/api/advisory/quarterly")
    def api_quarterly_advisor():
        if not hp(PERM["advisor"]):
            return jsonify(error=REFUSE["advisor"]), 403
        return jsonify(quarters=listing("advisor"))

    @app.route("/api/advisory/quarterly/<quarter>/<kind>")
    def api_quarterly_advisor_file(quarter, kind):
        if not hp(PERM["advisor"]):
            return jsonify(error=REFUSE["advisor"]), 403
        return download("advisor", quarter, kind)

    @app.route("/api/admin/quarterly")
    def api_quarterly_admin():
        if not hp(PERM["admin"]):
            return jsonify(error=REFUSE["admin"]), 403
        today = datetime.now(timezone.utc).date()
        gone = str(pipeline_purge(base).get("purged_before") or "")
        can = []
        y, q = prev_quarter(*quarter_of(today))
        for _ in range(4):                               # the last four ended quarters whose rows are still there
            lo = quarter_range(y, q)[0]
            if not gone or gone <= lo.isoformat():
                can.append(qname(y, q))
            y, q = prev_quarter(y, q)
        ps = pipeline_purge(base)
        return jsonify(quarters=listing("admin", admin=True), can_make=can, making=busy["quarter"], error=busy["error"],
                       pipeline={"found": bool(ps), "purged_before": ps.get("purged_before", ""),
                                 "last": {k: (ps.get("last") or {}).get(k) for k in ("quarter", "at", "outcome", "why",
                                                                                      "purge_day", "cutoff", "rows_deleted")}},
                       rules={"working_days": WORKING_DAYS, "keep_days": KEEP_DAYS})

    @app.route("/api/admin/quarterly/<quarter>/<kind>")
    def api_quarterly_admin_file(quarter, kind):
        if not hp(PERM["admin"]):
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
        if datetime.now(timezone.utc).date() < quarter_range(y, q)[1]:
            return jsonify(error=f"{quarter} has not ended yet."), 409
        if busy["quarter"]:
            return jsonify(error=f"{busy['quarter']} is being made: wait until it is ready."), 409
        u = me()

        def run():
            try:
                make_now(quarter, "made again on request", u)
            except Exception:              # noqa: BLE001  (kept in busy["error"]; the page shows it)
                pass
        threading.Thread(target=run, daemon=True, name="quarterly-make").start()
        return jsonify(ok=True, making=quarter), 202

    return {"tick": tick, "make": make_now, "busy": busy, "take_results": take_results}
