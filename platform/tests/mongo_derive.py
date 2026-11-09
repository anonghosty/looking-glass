"""Shared by tests/verify_*.py: independent re-derivation of both platforms' records straight from MongoDB (own code, not the platform's)."""
import re
from datetime import datetime, timedelta, timezone

CLASS_RULES = [(r"ddos", "DDoS"), (r"brute_force", "Brute force"), (r"initial_access", "Initial access"),
               (r"spoof", "IP spoofing"), (r"spam", "Spam"), (r"sinkhole|drone", "Botnet C2"), (r"scan|darknet", "Scanning")]
klass = lambda n: next((l for p, l in CLASS_RULES if re.search(p, n)), "Other")
FAM = [(r"^compromised_", "Compromised"), (r"^blocklist", "Blocklisted"), (r"^device_id", "Identified device"),
       (r"^scan6?_", "Exposed service"), (r"^population6?_", "Service population")]
fam = lambda n: next((f for p, f in FAM if re.match(p, n)), "Other")
MARK = {"exposed-admin-panel": "Exposed admin panel", "device-implant": "Device implant", "badcandy": "Badcandy",
        "cpanel-compromised": "Cpanel compromised", "open-dir": "Open dir", "vulnerable": "Vulnerable"}


def S(v):
    if v is None:
        return ""
    if isinstance(v, datetime):
        return v.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    return str(v)


def day_docs(db, names, start):
    end = start + timedelta(days=1)
    pre = (start.strftime("%Y-%m-%d"), end.strftime("%Y-%m-%d"))
    for n in names:
        for d in db[n].find({"$or": [{"filename": {"$regex": "^" + p}} for p in pre]}):
            ed = d.get("extracted_date")
            if isinstance(ed, str):
                try:
                    ed = datetime.fromisoformat(ed.replace("Z", "+00:00"))
                except ValueError:
                    continue
            if not isinstance(ed, datetime):
                continue
            if ed.tzinfo is None:
                ed = ed.replace(tzinfo=timezone.utc)
            if start <= ed < end:
                yield n, d, ed.timestamp()


def comms(db, names, layouts, start):
    out = []
    for n, d, t in day_docs(db, names, start):
        lay = layouts.get(n, "standard")
        g = lambda k: S(d.get(k))
        if lay == "legacy":
            src = lambda p: S(d.get(p.replace("src_", "")))
        else:
            src = lambda p: S(d.get(p))
        dst = (lambda p: S(d.get(p)) or S(d.get(p.replace("dst_", "")))) if lay == "inbound" else (lambda p: S(d.get(p)))
        inf = g("infection") or (g("type") if lay == "legacy" and g("type").lower() not in ("tcp", "udp", "icmp", "sctp") else "") \
            or g("family") or g("tag") or g("application") or n
        out.append({"source": n, "attack_class": klass(n), "src_ip": src("src_ip"), "src_asn": src("src_asn"),
                    "src_region": src("src_region"), "src_city": src("src_city"), "severity": g("severity"),
                    "dst_geo": dst("dst_geo"), "dst_ip": dst("dst_ip") or S(d.get("dst_network")).split("/")[0],
                    "http_host": g("http_host"), "infection": inf, "_t": t})
    return out


def services(db, names, labels, start):
    out = []
    for n, d, t in day_docs(db, names, start):
        tags = [x.strip() for x in S(d.get("tag")).replace(",", ";").split(";") if x.strip()]
        issues = [x.upper() for x in tags if x.lower().startswith("cve-")]
        if S(d.get("ssl_poodle")).upper() == "Y": issues.append("POODLE (SSLv3)")
        if S(d.get("freak_vulnerable")).upper() == "Y": issues.append("FREAK")
        if S(d.get("cert_expired")).upper() == "Y": issues.append("Expired certificate")
        issues += [MARK[x] for x in tags if x in MARK]
        if fam(n) == "Compromised" and not issues:
            issues.append("Compromised")
        out.append({"ip": S(d.get("ip")), "asn": S(d.get("asn")), "region": S(d.get("region")), "city": S(d.get("city")),
                    "severity": S(d.get("severity")).strip().lower(), "issues": issues, "tags": tags,
                    "report": n, "family": fam(n), "service": labels.get(n, n), "vendor": S(d.get("device_vendor")),
                    "sector": S(d.get("sector")), "_t": t})
    return out


def title(s):
    return " ".join(w.capitalize() if not w.isupper() or len(w) > 3 else w for w in str(s or "").lower().split()) if s else ""
