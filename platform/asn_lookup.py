"""Identify networks (AS numbers): company name and type, from free public sources, into data/asns.json.

Sources (no account or key needed; only AS numbers are sent):
  * PeeringDB  (https://www.peeringdb.com/api/net)     the network's own brand name and type (ISP, content, enterprise,
                                                       education, government, non-profit...) for networks listed there,
                                                       asked in batches of 50
  * RIPEstat   (https://stat.ripe.net, as-overview)    the registered holder of every AS number (all regions)
The type of networks not in PeeringDB is estimated from the name (University, Bank, Ministry, Telecom...).

Entries already in the registry are skipped (and never overwritten when reviewed=true); entries whose earlier look-up
failed are tried again. Used by the Settings page ("Identify networks", a background job with progress) and by
manage/asn_registry.py (command line). The platform picks up the updated file by itself within a few seconds.
"""
import json
import os
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

UA = "looking-glass-network-lookup (https://www.shadowserver.org reports; CSIRT tool)"
PDB_TYPES = {"cable/dsl/isp": "isp", "nsp": "isp", "network services": "isp", "content": "hosting",
             "enterprise": "enterprise", "educational/research": "education", "non-profit": "nonprofit",
             "government": "government", "route server": "ixp", "route collector": "ixp"}
TYPE_RULES = [
    (r"\bpolice\b|law enforcement|gendarmerie|interior ministry", "lawenforcement"),
    (r"\barmy\b|armed forces|\bmilitary\b|ministry of defen[cs]e|\bdefen[cs]e force", "defence"),
    (r"hospital|clinic|health|medical|pharma|\bnhis\b", "health"),
    (r"universit|college|academ|institute|polytechnic|research|education|kofi annan centre", "education"),
    (r"\bschool\b|secondary school|high school", "school"),
    (r"electricity|\bpower\b|energy|\bgrid\b|water company|water board|utilit", "energy"),
    (r"\bmining\b|\bmines\b|\bgold\b|petroleum|\boil\b|\bgas\b", "mining"),
    (r"airline|airport|aviation|railway|\bports?\b|harbou?r|shipping|logistics|transport", "transport"),
    (r"broadcast|television|\btv\b|\bradio\b|\bmedia\b|newspaper", "media"),
    (r"satellite|starlink|\bvsat\b", "satellite"),
    (r"government|ministry|parliament|social security|national insurance|authority|agency|council|police|army|"
     r"defen[cs]e|presiden", "government"),
    (r"bank\b|banque|finance|insurance|capital|microfinance|savings", "finance"),   # Ecobank, Stanbic Bank…
    (r"cloudflare|amazon|microsoft|google|digitalocean|hetzner|leaseweb|strato|m247|netactuate|datacamp|ovh|linode|"
     r"akamai|fastly|oracle|alibaba|tencent|host|data ?cent|cloud|cdn|server", "hosting"),
    (r"internet exchange|\bix\b|-ix\b|ixp", "ixp"),
    (r"telecom|mobile|cellular|wireless|broadband|fib(re|er)|network|communications|\bisp\b|internet|net\b|"
     r"mtn|airtel|vodafone|orange|safaricom|telkom|glo\b|moov|tigo|telecel", "isp"),
]
ALIAS_PREFIX = {"isp": "Telco", "education": "Institution", "government": "Institution", "finance": "Institution",
                "nonprofit": "Institution", "enterprise": "Organisation", "ixp": "Exchange", "hosting": "Provider",
                "private": "Network", "unknown": "Network"}   # fallback; netypes.py has every type (and the site's own)


def _get(url, timeout=20):
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json"})
    for attempt in range(4):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            if e.code in (429, 502, 503, 504) and attempt < 3:
                time.sleep(min(60, int(e.headers.get("Retry-After") or 0) or 5 * (attempt + 1)))
                continue
            raise
    return None


def ripestat(asn):
    """Registered holder, e.g. 'EXAMPLE-AS, GH'; '' when unknown. Raises on network errors."""
    url = "https://stat.ripe.net/data/as-overview/data.json?" + urllib.parse.urlencode(
        {"resource": f"AS{asn}", "sourceapp": "looking-glass-threatmap"})
    return ((_get(url) or {}).get("data") or {}).get("holder") or ""


def peeringdb(asns):
    """{asn: {'name', 'type'}} for the networks listed in PeeringDB (others are simply absent)."""
    out = {}
    for i in range(0, len(asns), 50):
        chunk = [str(a) for a in asns[i:i + 50]]
        url = "https://www.peeringdb.com/api/net?" + urllib.parse.urlencode(
            {"asn__in": ",".join(chunk), "fields": "asn,name,info_type,info_types"})
        for n in (_get(url) or {}).get("data", []):
            kinds = n.get("info_types") or ([n["info_type"]] if n.get("info_type") else [])
            t = next((PDB_TYPES[k.lower()] for k in kinds if k and k.lower() in PDB_TYPES), "")
            out[str(n.get("asn"))] = {"name": (n.get("name") or "").strip(), "type": t}
        time.sleep(1.5)                      # be gentle with the free API
    return out


def clean(holder):
    """'EXAMPLE-AS, GH' -> 'Example'; 'EXNET-AS - Example Networks, GH' -> 'Example Networks' (best effort)."""
    h = re.sub(r",\s*[A-Z]{2}$", "", holder or "").strip()
    parts = re.split(r"\s+-\s+", h, maxsplit=1)
    name = parts[1] if len(parts) > 1 and len(parts[1]) > 3 else parts[0]
    name = re.sub(r"(-AS\d*|_AS|-ASN\d*|\bAS\b)$", "", name, flags=re.I).strip(" -_")
    return name.title() if name.isupper() else name


def classify(asn, text):
    a = int(asn)
    if 64512 <= a <= 65534 or 4200000000 <= a <= 4294967294:
        return "private"
    if not text:
        return "unknown"
    for pat, t in TYPE_RULES:
        if re.search(pat, text, re.I):
            return t
    return "unknown"


def needs_lookup(entry):
    return (not entry or (not entry.get("reviewed") and (str(entry.get("holder", "")).startswith("lookup failed")
                                                        or entry.get("source") in ("", "unknown", "failed"))))


def load(path):
    try:
        with open(path, encoding="utf-8") as f:
            reg = json.load(f)
    except (OSError, ValueError):
        reg = {}
    reg.setdefault("asns", {})
    return reg


def save(path, reg):
    reg["_about"] = ("Looking Glass ASN registry. Key = AS number. 'name' is what is shown; edit it and set "
                     "reviewed=true to lock it. 'demo_alias' replaces name and number in demo mode. Filled by "
                     "Settings > Identify networks, or manage/asn_registry.py (PeeringDB and RIPEstat).")
    reg["_updated"] = time.strftime("%Y-%m-%d")
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(reg, f, indent=2, ensure_ascii=False)
    os.replace(tmp, path)


def assign_aliases(asns, data_dir=None):
    prefixes = dict(ALIAS_PREFIX)
    if data_dir:
        try:
            import netypes
            prefixes.update(netypes.aliases(data_dir))
        except Exception:                      # the built-in words still work
            pass
    used = {v.get("demo_alias") for v in asns.values()}
    for a in sorted(asns, key=lambda k: -asns[k].get("events_last_check", 0)):
        v = asns[a]
        if v.get("demo_alias"):
            continue
        prefix, n = prefixes.get(v.get("type"), "Network"), 1
        while f"{prefix} {n}" in used:
            n += 1
        v["demo_alias"] = f"{prefix} {n}"
        used.add(v["demo_alias"])


def identify(path, counts, meta=None, progress=None, stop=None):
    """Look up every AS number in `counts` (asn -> events) that the registry lacks; update the registry file.
    `meta` gives {asn: {'country', 'role'}}; `progress(dict)` is called as it goes; `stop` (Event) ends it early.
    Returns the final progress dict."""
    meta = meta or {}
    st = {"state": "running", "total": 0, "done": 0, "added": 0, "known": 0, "failed": 0, "current": "", "log": [],
          "message": ""}

    def tell(line=None):
        if line:
            st["log"] = (st["log"] + [line])[-12:]
        if progress:
            progress(dict(st))

    reg = load(path)
    asns = reg["asns"]
    for a, n in counts.items():
        if a in asns:
            asns[a]["events_last_check"] = n
    todo = [a for a, _ in sorted(counts.items(), key=lambda kv: -kv[1]) if a != "0" and needs_lookup(asns.get(a))]
    st["known"] = sum(1 for a in counts if a != "0") - len(todo)
    st["total"] = len(todo)
    tell(f"{st['known']} network(s) already identified: skipped. {len(todo)} to look up.")
    if not todo:
        st.update(state="done", message="Every network is already identified.")
        save(path, reg); tell(); return st
    st["current"] = "PeeringDB (names and types, 50 at a time)"; tell("Asking PeeringDB for names and types...")
    try:
        pdb = peeringdb(todo)
        tell(f"PeeringDB knows {len(pdb)} of them.")
    except Exception as exc:                          # PeeringDB down or blocked: RIPEstat alone still works
        pdb = {}
        tell(f"PeeringDB not reachable ({exc.__class__.__name__}): names from RIPEstat only.")
    for a in todo:
        if stop is not None and stop.is_set():
            st["message"] = "Stopped."; break
        st["current"] = f"AS{a}"; tell()
        try:
            holder = ripestat(a)
            ok = True
        except Exception as exc:
            holder, ok = f"lookup failed: {exc.__class__.__name__}", False
        p = pdb.get(a, {})
        name = p.get("name") or clean(holder) or f"AS{a}"
        kind = p.get("type") or classify(a, f"{p.get('name', '')} {holder}")
        m = meta.get(a, {})
        asns[a] = {"name": name, "holder": holder, "type": kind, "country": m.get("country", ""), "role": m.get("role", ""),
                   "reviewed": False, "source": ("peeringdb+ripestat" if p else "ripestat") if ok else "failed",
                   "events_last_check": counts.get(a, 0)}
        st["done"] += 1
        if ok:
            st["added"] += 1
            tell(f"AS{a}: {name} ({kind})")
        else:
            st["failed"] += 1
            tell(f"AS{a}: look-up failed ({holder[15:]}); tried again next time")
        if st["done"] % 10 == 0:                      # save as it goes: the lists show the names straight away
            assign_aliases(asns, os.path.dirname(path)); save(path, reg)
        time.sleep(0.25)                              # RIPEstat fair use
    assign_aliases(asns, os.path.dirname(path))
    save(path, reg)
    st["current"] = ""
    st["state"] = "done" if not st["message"] else "stopped"
    st["message"] = st["message"] or f"Identified {st['added']} network(s); {st['known']} already known" + \
        (f"; {st['failed']} failed (tried again next time)" if st["failed"] else "") + "."
    tell()
    return st


class IdentifyJob:
    """One background look-up at a time, with its progress for the Settings page."""

    def __init__(self, path):
        self.path, self.lock, self.thread, self.stop = path, threading.Lock(), None, threading.Event()
        self.status = {"state": "idle", "total": 0, "done": 0, "added": 0, "known": 0, "failed": 0, "current": "",
                       "log": [], "message": ""}

    def running(self):
        return self.thread is not None and self.thread.is_alive()

    def start(self, collect):
        """collect() -> (counts, meta), called in the background thread."""
        with self.lock:
            if self.running():
                return False
            self.stop.clear()
            self.status = {"state": "running", "total": 0, "done": 0, "added": 0, "known": 0, "failed": 0,
                           "current": "collecting the networks in the data", "log": [], "message": "", "started": time.time()}

            def work():
                try:
                    counts, meta = collect()
                    identify(self.path, counts, meta, progress=self._update, stop=self.stop)
                except Exception as exc:              # never leave the page waiting forever
                    self._update({**self.status, "state": "failed", "message": f"Look-up failed: {exc}"})
            self.thread = threading.Thread(target=work, name="asn-identify", daemon=True)
            self.thread.start()
            return True

    def _update(self, st):
        st = dict(st)
        st["started"] = self.status.get("started")
        self.status = st
