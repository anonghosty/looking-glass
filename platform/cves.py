"""Vulnerability (CVE) look-ups for the issues of the publicly accessible / vulnerable services platform.

* NVD (NIST National Vulnerability Database): description, CVSS score and severity, weakness (CWE), dates, references.
  Optional NVD_API_KEY in .env raises the limit from 5 to 50 requests per 30 seconds.
* CISA KEV (Known Exploited Vulnerabilities catalog): whether the CVE is confirmed to be actively exploited, when CISA
  added it, known ransomware use, CISA's required action and due date. One download, refreshed daily.
* EPSS (FIRST.org Exploit Prediction Scoring System): the probability that the CVE is exploited in the next 30 days.
* CVE.org (the CVE Program's official records, cvelistV5 on GitHub): description, the CNA's / CISA-ADP CVSS, weakness and
  references. No key and no tight limit (measured: 12 records in 6.7 s), so every CVE is explained at once; NVD's own
  analysis is added by the background check at NVD's pace (5 requests per 30 s without a key).

Batches: KEV one download a day; EPSS one request per 100 CVEs; CVE.org four records at a time; NVD only in the
background (one worker process at a time), so nobody waits for NVD and NVD is never asked faster than it allows.

Answers are cached in data/cve_cache.json (NVD and EPSS for a week, KEV for a day). Only values that look like a CVE id
(CVE-YYYY-NNNN...) are ever sent out.
"""
import json
import os
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")
NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId="
KEV = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS = "https://api.first.org/data/v1/epss?cve="
NVD_PAGE = "https://nvd.nist.gov/vuln/detail/"
CVEORG = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/{year}/{group}xxx/{id}.json"
CVEORG_PAGE = "https://www.cve.org/CVERecord?id="
KEV_PAGE = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
TTL, KEV_TTL = 7 * 86400, 86400


def is_cve(name):
    return bool(CVE_RE.match((name or "").strip().upper()))


class CveIntel:
    def __init__(self, cache_path, api_key="", logger=None):
        self.path, self.key, self.log = cache_path, (api_key or "").strip(), logger
        self.lock, self.nvd_lock = threading.Lock(), threading.Lock()
        self.calls = []                          # NVD request times (rolling 30-second window)
        try:
            with open(cache_path, encoding="utf-8") as f:
                self.cache = json.load(f)
        except (OSError, ValueError):
            self.cache = {}
        for k in ("nvd", "epss", "cveorg"):
            self.cache.setdefault(k, {})
        self._mtime, self._checked = (os.path.getmtime(cache_path) if os.path.exists(cache_path) else 0), time.time()
        self.cache.setdefault("kev", {"t": 0, "items": {}})

    # ------------------------------------------------------------------ plumbing
    def _refresh(self):
        """Other worker processes (the background check) write the cache too: merge their newer answers."""
        if time.time() - self._checked < 20:
            return
        self._checked = time.time()
        try:
            m = os.path.getmtime(self.path)
            if m <= self._mtime:
                return
            with open(self.path, encoding="utf-8") as f:
                disk = json.load(f)
        except (OSError, ValueError):
            return
        with self.lock:
            for k in ("nvd", "epss", "cveorg"):
                mine = self.cache.setdefault(k, {})
                for cid, v in (disk.get(k) or {}).items():
                    if v.get("t", 0) > (mine.get(cid) or {}).get("t", 0):
                        mine[cid] = v
            if (disk.get("kev") or {}).get("t", 0) > self.cache["kev"].get("t", 0):
                self.cache["kev"] = disk["kev"]
            self._mtime = m

    def _save(self):
        tmp = f"{self.path}.{os.getpid()}.tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(self.cache, f)
            os.replace(tmp, self.path)
            self._mtime = os.path.getmtime(self.path)
        except OSError:
            pass

    def _get(self, url, headers=None, timeout=30):
        h = {"User-Agent": "LookingGlass/1.0", "Accept": "application/json", **(headers or {})}
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=h), timeout=timeout) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            raise RuntimeError(f"answered {e.code}") from None
        except (urllib.error.URLError, TimeoutError, ValueError) as e:
            raise RuntimeError(f"could not be reached ({getattr(e, 'reason', e)})") from None

    def _nvd_slot(self, wait):
        """NVD allows 5 requests per 30 s without a key (50 with one). wait=False: raise instead of waiting."""
        limit = 45 if self.key else 5
        while True:
            with self.nvd_lock:
                now = time.time()
                self.calls = [t for t in self.calls if now - t < 31]
                if len(self.calls) < limit:
                    self.calls.append(now)
                    return
                delay = 31 - (now - self.calls[0])
            if not wait:
                raise RuntimeError("NVD allows only a few look-ups per 30 seconds; the rest follow in the background")
            time.sleep(max(0.5, delay))

    # ------------------------------------------------------------------ sources
    def kev(self):
        """CISA's catalog of exploited vulnerabilities: {CVE: entry}; refreshed once a day (kept if CISA is unreachable)."""
        k = self.cache["kev"]
        if time.time() - k.get("t", 0) > KEV_TTL:
            try:
                d = self._get(KEV, timeout=60) or {}
                items = {v["cveID"].upper(): {
                    "vendor": v.get("vendorProject", ""), "product": v.get("product", ""), "name": v.get("vulnerabilityName", ""),
                    "date_added": v.get("dateAdded", ""), "short": v.get("shortDescription", ""), "action": v.get("requiredAction", ""),
                    "due": v.get("dueDate", ""), "ransomware": v.get("knownRansomwareCampaignUse", ""), "notes": v.get("notes", "")}
                    for v in d.get("vulnerabilities", []) if v.get("cveID")}
                if items:
                    with self.lock:
                        self.cache["kev"] = {"t": time.time(), "items": items, "version": d.get("catalogVersion", ""),
                                             "released": d.get("dateReleased", "")}
                        self._save()
            except RuntimeError as exc:
                if self.log:
                    self.log.warning("CISA KEV catalog not refreshed: %s", exc)
        return self.cache["kev"].get("items", {})

    def epss(self, ids):
        """EPSS for several CVEs at once (one request for up to 100)."""
        now = time.time()
        need = [i for i in ids if now - (self.cache["epss"].get(i) or {}).get("t", 0) > TTL]
        for i in range(0, len(need), 100):
            try:
                d = self._get(EPSS + ",".join(need[i:i + 100])) or {}
            except RuntimeError as exc:
                if self.log:
                    self.log.warning("EPSS not reached: %s", exc)
                break
            got = {r["cve"].upper(): r for r in d.get("data", [])}
            with self.lock:
                for c in need[i:i + 100]:
                    r = got.get(c)
                    self.cache["epss"][c] = {"t": now, "score": float(r["epss"]) if r else None,
                                             "percentile": float(r["percentile"]) if r else None, "date": r.get("date", "") if r else ""}
                self._save()
        return {i: self.cache["epss"].get(i) for i in ids}

    def nvd(self, cve, fetch=True, wait=False):
        """NVD's record (cached a week). fetch=False: only what is cached (None if nothing yet)."""
        cve = cve.upper()
        hit = self.cache["nvd"].get(cve)
        if hit and time.time() - hit["t"] < TTL:
            return hit["data"]
        if not fetch:
            return hit["data"] if hit else None
        self._nvd_slot(wait)
        d = self._get(NVD + urllib.parse.quote(cve), headers={"apiKey": self.key} if self.key else None)
        v = ((d or {}).get("vulnerabilities") or [{}])[0].get("cve") if d else None
        data = {"missing": True}
        if v:
            desc = next((x["value"] for x in v.get("descriptions", []) if x.get("lang") == "en"), "")
            cvss = None
            for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                ms = (v.get("metrics") or {}).get(key) or []
                if ms:
                    m = next((x for x in ms if x.get("type") == "Primary"), ms[0])
                    c = m.get("cvssData", {})
                    cvss = {"version": c.get("version", key[10:]), "score": c.get("baseScore"),
                            "severity": c.get("baseSeverity") or m.get("baseSeverity", ""), "vector": c.get("vectorString", "")}
                    break
            cwes = sorted({x["value"] for w in v.get("weaknesses", []) for x in w.get("description", []) if x.get("value", "").startswith("CWE-")})
            refs = [r["url"] for r in v.get("references", []) if r.get("url", "").startswith(("http://", "https://"))]
            tagged = [r["url"] for r in v.get("references", []) if set(r.get("tags") or []) & {"Vendor Advisory", "Patch", "Mitigation"}]
            data = {"description": desc, "cvss": cvss, "cwes": cwes[:5], "published": (v.get("published") or "")[:10],
                    "modified": (v.get("lastModified") or "")[:10], "status": v.get("vulnStatus", ""),
                    "references": list(dict.fromkeys(tagged + refs))[:10], "reference_count": len(refs)}
        with self.lock:
            self.cache["nvd"][cve] = {"t": time.time(), "data": data}
            self._save()
        return data

    @staticmethod
    def _cvss_of(metrics):
        for key in ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"):
            for m in metrics or []:
                c = m.get(key)
                if c and c.get("baseScore") is not None:
                    return {"version": c.get("version", key[5:].replace("_", ".")), "score": c.get("baseScore"),
                            "severity": c.get("baseSeverity", ""), "vector": c.get("vectorString", "")}
        return None

    def cveorg(self, cve, fetch=True):
        """The official CVE record (CVE.org): the CNA's description, CVSS, weakness and references; CISA's ADP scores
        when the CNA gave none. Cached a week."""
        cve = cve.upper()
        hit = self.cache["cveorg"].get(cve)
        if hit and time.time() - hit["t"] < TTL:
            return hit["data"]
        if not fetch:
            return hit["data"] if hit else None
        _, year, num = cve.split("-")
        d = self._get(CVEORG.format(year=year, group=num[:-3] or "0", id=cve), timeout=20)
        data = {"missing": True}
        if d:
            meta, cont = d.get("cveMetadata") or {}, d.get("containers") or {}
            cna, adp = cont.get("cna") or {}, cont.get("adp") or []
            desc = next((x["value"] for x in cna.get("descriptions", []) if str(x.get("lang", "")).startswith("en")), "")
            cvss = self._cvss_of(cna.get("metrics"))
            src = "CVE.org (CNA)"
            if not cvss:
                for a in adp:
                    cvss = self._cvss_of(a.get("metrics"))
                    if cvss:
                        src = f"CVE.org ({(a.get('providerMetadata') or {}).get('shortName', 'ADP')})"
                        break
            if cvss:
                cvss["source"] = src
            cwes = sorted({x.get("cweId") for p in cna.get("problemTypes", []) for x in p.get("descriptions", []) if x.get("cweId")})
            refs = [r["url"] for r in cna.get("references", []) if str(r.get("url", "")).startswith(("http://", "https://"))]
            data = {"state": meta.get("state", ""), "description": desc, "cvss": cvss, "cwes": cwes[:5],
                    "published": (meta.get("datePublished") or "")[:10], "modified": (meta.get("dateUpdated") or "")[:10],
                    "cna_title": cna.get("title", ""), "assigner": meta.get("assignerShortName", ""),
                    "references": refs[:10], "reference_count": len(refs)}
        with self.lock:
            self.cache["cveorg"][cve] = {"t": time.time(), "data": data}
            self._save()
        return data

    def lookup_many(self, ids, progress=None):
        """Explain several CVEs as one batch, reporting each step to progress(kind, text, done=None):
        KEV (one download), EPSS (one request per 100), CVE.org (four at a time), NVD from the cache only."""
        from concurrent.futures import ThreadPoolExecutor
        say = progress or (lambda *a, **k: None)
        ids = list(dict.fromkeys(i.strip().upper() for i in ids if is_cve(i)))
        self._refresh()
        k = self.kev()
        say("step", f"CISA Known Exploited Vulnerabilities catalog: {len(k):,} entries "
                    f"(updated {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime(self.cache['kev'].get('t', 0)))})")
        need = [i for i in ids if time.time() - (self.cache["epss"].get(i) or {}).get("t", 0) > TTL]
        if need:
            say("step", f"EPSS: {len(need)} CVE{'s' if len(need) != 1 else ''} in {(len(need) + 99) // 100} request(s) to FIRST.org")
            self.epss(need)
        else:
            say("step", "EPSS: every score already known (cached)")
        todo = [i for i in ids if not ((self.cache["cveorg"].get(i) or {}).get("t", 0) > time.time() - TTL)]
        cached = len(ids) - len(todo)
        say("step", f"CVE.org records: {cached} already known, {len(todo)} to fetch (4 at a time)")
        done = [cached]

        def one(i):
            try:
                d = self.cveorg(i, fetch=True)
                kv = (k.get(i) or {})
                bits = [f"CVSS {d['cvss']['score']}" if d.get("cvss") else "no CVSS", "ACTIVELY EXPLOITED (KEV)" if kv else "not in KEV"]
                msg = f"{i}: {'not found on CVE.org' if d.get('missing') else ', '.join(bits)}"
            except RuntimeError as exc:
                msg = f"{i}: CVE.org {exc}"
            done[0] += 1
            say("item", msg, done=done[0])

        with ThreadPoolExecutor(max_workers=4) as ex:
            list(ex.map(one, todo))
        nvd_have = sum(1 for i in ids if self.cache["nvd"].get(i))
        if nvd_have < len(ids):
            say("step", f"NVD analysis: {nvd_have} of {len(ids)} already added; the rest are added by the background "
                        f"check at NVD's pace ({'50' if self.key else '5'} requests per 30 s"
                        f"{'' if self.key else '; an NVD_API_KEY in .env makes it 10 times faster'}).")
        else:
            say("step", f"NVD analysis: all {len(ids)} already added")
        return {i: self.card(i, fetch=False) for i in ids}

    # ------------------------------------------------------------------ what the platform shows
    def card(self, cve, fetch=True, wait=False):
        """Everything known about one CVE: NVD's analysis when it has been added, else the official CVE.org record
        (fetched now when fetch=True; NVD itself only from the cache, the background check adds it)."""
        cve = cve.strip().upper()
        if not is_cve(cve):
            raise ValueError("not a CVE id")
        self._refresh()
        kev = self.kev().get(cve)
        n = self.nvd(cve, fetch=False)
        err = ""
        try:
            o = self.cveorg(cve, fetch=fetch)
        except RuntimeError as exc:
            o, err = None, f"CVE.org {exc}"
        e = self.cache["epss"].get(cve) or {}
        if fetch and not e:
            e = self.epss([cve]).get(cve) or {}
        has_n, has_o = bool(n and not n.get("missing")), bool(o and not o.get("missing"))
        out = {"found": has_n or has_o, "kind": "cve", "id": cve, "title": cve, "url": NVD_PAGE + cve,
               "cveorg_url": CVEORG_PAGE + cve, "pending": not (has_n or has_o) and (n is None or o is None), "reason": err,
               "nvd": has_n, "sources": [x for x, y in (("NVD", has_n), ("CVE.org", has_o)) if y],
               "exploited": bool(kev), "kev": kev or None, "kev_url": KEV_PAGE if kev else "",
               "epss": e.get("score"), "epss_percentile": e.get("percentile"), "epss_date": e.get("date", "")}
        if has_o:
            out.update(o)
            out["ref_source"] = "CVE.org"
        if has_n:                                 # NVD's analysis on top (its CVSS, weakness and reference list)
            out.update({k: v for k, v in n.items() if v not in (None, "", [])})
            out["ref_source"] = "NVD"
            if out.get("cvss"):
                out["cvss"] = dict(out["cvss"], source=out["cvss"].get("source") or "NVD")
        if kev and kev.get("name"):
            out["title"] = f"{cve}: {kev['name']}"
        return out

    def cards(self, ids, fetch=True, budget=20.0):
        """Several CVEs as one batch (see lookup_many); fetch=False: only what is cached."""
        ids = [i.strip().upper() for i in ids if is_cve(i)]
        if fetch:
            return self.lookup_many(ids)
        return {i: self.card(i, fetch=False) for i in ids}

    def prefetch(self, ids, stop=None):
        """Background: fill the cache for every CVE in the data, at NVD's pace."""
        ids = [i.strip().upper() for i in ids if is_cve(i)]
        self.lookup_many(ids)                    # KEV, EPSS and CVE.org first: everything is explained at once
        n = 0
        for i in ids:
            if stop and stop():
                break
            hit = self.cache["nvd"].get(i)
            if hit and time.time() - hit["t"] < TTL:
                continue
            try:
                self.nvd(i, fetch=True, wait=True); n += 1
            except RuntimeError as exc:
                if self.log:
                    self.log.warning("NVD look-up of %s failed: %s", i, exc)
                time.sleep(30)
        return n

    def status(self):
        k = self.cache["kev"]
        return {"kev_entries": len(k.get("items", {})), "kev_updated": time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(k["t"])) if k.get("t") else "",
                "nvd_cached": len(self.cache["nvd"]), "cveorg_cached": len(self.cache["cveorg"]), "nvd_key": bool(self.key)}
