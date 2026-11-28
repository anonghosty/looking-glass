#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""The connectors' sender (the user, 2026-11-24): a separate process, run every 15 minutes by its own systemd timer
(deploy/looking-glass-connectors.*), never inside the web service, so a slow platform never slows a page.

Each run, for every target that is on (connectors.py):
1. the checks again (address, certificate, key, the platform's rights) without a test send: one that fails pauses the
   target, says why on Settings -> Connectors and rings the administrators' bell; nothing is sent;
2. the report days to send: the last 30 days from the day it was turned on (the back-fill), then each new day once
   its reports have arrived; a day whose reports or Looking Glass's knowledge changed is worked out again;
3. per day, the devices in what the target receives (its ticked networks, address blocks and ranges), their analysis
   (connector_payload.py), and only the objects that are new or changed since the last send (a content hash per object);
4. a day the quarterly purge removed: its objects revoked (OpenCTI) or its event deleted (MISP); a day sent again
   without some of its earlier objects: those revoked (OpenCTI; MISP's event is replaced whole);
4b. OpenCTI imports after accepting a send: VERIFY_AFTER later, the sender asks which of Looking Glass's objects it
   holds and sends the missing ones again, RETRIES times, then logs and audits them as refused;
5. every send, failure and revocation in data/connectors_log.jsonl and the audit log; three failures in a row pause
   the target.
Reads MongoDB with the platform's read-only account. Run by hand: .venv/bin/python connectors_worker.py [--once]
"""
import datetime as dt
import hashlib
import json
import os
import re
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
DAYS = max(1, min(90, int(os.environ.get("CONNECTOR_BACKFILL_DAYS", "30") or 30)))   # the back-fill (the user: 30 days)
BATCH_OBJECTS = 400            # OpenCTI: objects per TAXII envelope
VERIFY_AFTER = 600             # OpenCTI: seconds after a send before asking which objects it took (it imports later)
RETRIES = 3                    # OpenCTI: sends again of objects it did not take, before reporting them as refused
IDS_PER_QUERY = 100
TAXII = "application/taxii+json;version=2.1"


def _now_iso():
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _iso(v):
    if isinstance(v, dt.datetime):
        v = v if v.tzinfo else v.replace(tzinfo=dt.timezone.utc)
        return v.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    m = re.match(r"(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})", str(v or ""))
    return f"{m.group(1)}T{m.group(2)}.000Z" if m else None


class State:
    """What was sent: per target, per day, the data signature and each object's content hash."""

    def __init__(self, path):
        self.path = path
        try:
            with open(path, encoding="utf-8") as f:
                self.d = json.load(f)
        except (OSError, ValueError):
            self.d = {}

    def of(self, tid):
        return self.d.setdefault(tid, {"days": {}, "fails": 0})

    def save(self):
        tmp = f"{self.path}.{os.getpid()}.tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(self.d, f)
        os.replace(tmp, self.path)


def report_collections(db):
    return [c for c in db.list_collection_names() if not c.startswith(("lg_", "system.", "files_", "discovered_fields_"))]


def day_signature(db, cols, day):
    """How many records each report has for that day: a day whose counts changed is worked out again."""
    sig = {}
    for c in cols:
        n = db[c].count_documents({"filename": {"$regex": "^" + re.escape(day)}})
        if n:
            sig[c] = n
    return sig


def beacon_summary(v):
    """One kept beacon answer (data/beacon_summaries.json, beacon_keep.py: a list of [field, value] pairs, the public
    summary of one request's beacon) as a dict; {} for no beacon or anything unreadable (audit 2026-11-27: each pair
    was read as a summary of its own, and dict() of a pair stopped the sender for every target)."""
    if isinstance(v, dict):
        return v
    if not isinstance(v, (list, tuple)):
        return {}
    out = {}
    for p in v:
        if isinstance(p, (list, tuple)) and len(p) == 2 and isinstance(p[0], str):
            out[p[0]] = p[1]
    return out


def devices_of(db, cols, day, keep, base_dir, beacons):
    """{ip: device} for that day, only the addresses keep(asn, ip) lets through; Looking Glass's analysis per report."""
    import beacon_keep
    out = {}
    fields = {"src_ip": 1, "ip": 1, "src_asn": 1, "asn": 1, "timestamp": 1, "infection": 1, "tag": 1, "http_url": 1, "http_host": 1}
    for c in cols:
        for r in db[c].find({"filename": {"$regex": "^" + re.escape(day)}}, fields):
            ip = r.get("src_ip") or r.get("ip")
            asn = r.get("src_asn") or r.get("asn")
            if not ip or not keep(asn, ip):
                continue
            d = out.setdefault(ip, {"ip": ip, "asn": asn, "reports": {}})
            e = d["reports"].setdefault(c, {"count": 0, "first": None, "last": None, "infections": set(), "tags": set(),
                                            "beacons": set(), "cves": set()})
            e["count"] += 1
            t = _iso(r.get("timestamp")) or f"{day}T00:00:00.000Z"
            e["first"] = min(e["first"] or t, t)
            e["last"] = max(e["last"] or t, t)
            if r.get("infection"):
                e["infections"].add(str(r["infection"]))
            tags = [x.strip() for x in re.split(r"[;,]", str(r.get("tag") or "")) if x.strip()]
            e["tags"].update(tags)
            e["cves"].update(m.upper() for x in tags for m in re.findall(r"cve-\d{4}-\d{4,}", x, re.I))
            # Looking Glass's combination codes never leave Looking Glass (the user, 2026-11-24): not collected here
            if r.get("http_url"):
                # kept under the lower-cased host, as the decoder keeps it (beacon_decode.field; audit 2026-11-28, r1-6)
                b = beacon_summary(beacons.get(beacon_keep.key_of(r.get("http_url"), str(r.get("http_host") or "").lower() or None)))
                if b.get("format"):
                    e["beacons"].add((str(b.get("id", "")), str(b["format"])))
    # how many days each device was seen in each report, and the first (what the database still holds)
    for c in cols:
        ips = [ip for ip, d in out.items() if c in d["reports"]]
        for i in range(0, len(ips), 500):
            part = ips[i:i + 500]
            seen = {}
            for r in db[c].find({"$or": [{"src_ip": {"$in": part}}, {"ip": {"$in": part}}]}, {"src_ip": 1, "ip": 1, "filename": 1}):
                ip = r.get("src_ip") or r.get("ip")
                seen.setdefault(ip, set()).add(str(r.get("filename", ""))[:10])
            for ip in part:
                days = sorted(x for x in seen.get(ip, {day}) if re.match(r"\d{4}-\d{2}-\d{2}$", x)) or [day]
                rep = out[ip]["reports"][c]
                rep["days_seen"], rep["first_reported"] = len(days), days[0]
    for d in out.values():
        for e in d["reports"].values():
            for k in ("infections", "tags", "cves"):
                e[k] = sorted(e[k])
            e["beacons"] = sorted(e["beacons"])
    return out


def object_hashes(objs):
    """A content hash per object, its time stamps left out (they change at every build)."""
    out = {}
    for o in objs:
        core = {k: v for k, v in o.items() if k not in ("created", "modified")}
        out[o["id"]] = hashlib.sha256(json.dumps(core, sort_keys=True).encode()).hexdigest()[:24]
    return out


def run(base_dir=HERE, now=None, log=print):
    from dotenv import dotenv_values
    for k, v in dotenv_values(os.path.join(base_dir, ".env")).items():
        if v is not None:
            os.environ.setdefault(k, v)
    import advisory
    import connector_net as net
    import connector_payload as cp
    import connectors as C
    import db_connect
    from auth import Audit
    from pymongo import MongoClient
    data = os.path.join(base_dir, "data")
    targets = C.Targets(os.path.join(data, "connectors.json"))
    on = {k: v for k, v in targets.all().items() if v.get("on") and not v.get("paused")}
    if not on:
        return 0
    vault = C.Vault(os.path.join(data, "connector_keys.enc"))
    state = State(os.path.join(data, "connectors_state.json"))
    audit = Audit(os.path.join(data, "audit.log"))
    log_path = os.path.join(data, "connectors_log.jsonl")

    def write_log(**e):
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(dict(at=int(time.time()), **e)) + "\n")
    db = MongoClient(**db_connect.kwargs(os.environ.get), username=os.environ.get("MONGO_USER") or None,
                     password=os.environ.get("MONGO_PASSWORD") or None, authSource=os.environ.get("MONGO_AUTH_SOURCE", "admin"),
                     serverSelectionTimeoutMS=8000)[os.environ.get("MONGO_DB", "shadowserver")]
    cols = report_collections(db)
    know = cp.know_from(base_dir, advisory.Impact(base_dir))
    know_sig = hashlib.sha256(json.dumps([know["amap"], know["kb"], know["flags"], sorted(know["facts"])], sort_keys=True,
                                         default=str).encode()).hexdigest()[:16]
    try:
        with open(os.path.join(data, "beacon_summaries.json"), encoding="utf-8") as f:
            beacons = json.load(f).get("entries") or {}
    except (OSError, ValueError):
        beacons = {}
    today = (now or dt.datetime.now(dt.timezone.utc)).date()
    sent_total = 0
    for tid, t in on.items():
        key, _ = C.key_of(vault, tid)
        ok, checks = C.probe(t["kind"], t["address"], key or "", t["tlp"], send_test=False) if key else (False, [{"text": "no key"}])
        if not ok:
            t["paused"] = "The checks before sending did not pass: " + checks[-1]["text"]
            targets.save(tid, t)
            write_log(target=tid, status="paused", detail=t["paused"])
            audit.add("connector_paused", user="looking-glass", target=t["name"], detail=t["paused"][:200])
            continue
        st = state.of(tid)
        start = max(today - dt.timedelta(days=DAYS), dt.datetime.fromtimestamp(t.get("turned_on") or time.time(), dt.timezone.utc).date()
                    - dt.timedelta(days=DAYS))
        scope = t.get("scope") or {}
        # failed: a send or a revocation failed in this run. A run that failed counts ONCE toward the failures in a row
        # that pause the target, whatever failed in it (audit 2026-11-28, r1-5: a failed revocation never counted, so a
        # target that always refused was never paused; re-review: a revocation and a send failing in one run counted 2)
        failed = False

        def gone(day, prev, t=t, key=key, tid=tid, st=st):
            """The purge removed this day: revoke what was sent. Forgotten only once the revocation went through; a
            failed one is tried again next run (audit 2026-11-27: it was forgotten either way, and the day's data
            stayed on the target)."""
            if revoke(net, C, data, t, key, tid, day, prev, write_log, audit):
                st["days"].pop(day, None)
                return True
            return False
        window = {(start + dt.timedelta(days=i)).isoformat() for i in range((today - start).days)}
        # days sent earlier that are now older than the back-fill window: the quarterly purge removes exactly these
        # (it keeps the last 31 days), so they are looked at too, or a purged day would never be revoked. Looked at
        # once a day (the purge runs at most daily), not every 15 minutes: the day checked is kept in the target's
        # state, and only once every revocation went through (a failed one is tried again next run; audit 2026-11-28, r1-4)
        if st.get("old_checked") != today.isoformat():
            old_ok = True
            for day in sorted(d for d in list(st["days"]) if d not in window and re.match(r"\d{4}-\d{2}-\d{2}$", d)):
                prev = st["days"].get(day) or {}
                if prev.get("objects") and not day_signature(db, cols, day):
                    gone_ok = gone(day, prev)
                    failed |= not gone_ok
                    old_ok &= gone_ok
                    state.save()
            if old_ok:
                st["old_checked"] = today.isoformat()
                state.save()
        for i in range((today - start).days):
            day = (start + dt.timedelta(days=i)).isoformat()
            sig = day_signature(db, cols, day)
            prev = st["days"].get(day) or {}
            if not sig:
                if prev.get("objects"):                          # the purge removed this day: revoke what was sent
                    failed |= not gone(day, prev)
                continue
            full_sig = hashlib.sha256(json.dumps([sig, know_sig, scope, t["tlp"], cp.FORMAT], sort_keys=True).encode()).hexdigest()[:16]
            retrying = False
            if t["kind"] == "opencti" and prev.get("verify_at") and time.time() >= prev["verify_at"]:
                # OpenCTI imports after it accepted the send: ask which of Looking Glass's objects it holds; a missing one
                # is sent again (its hash forgotten), up to RETRIES times, then reported as refused
                try:
                    missing = opencti_missing(net, t, key, prev.get("ours") or [])
                except (ValueError, net.Refused) as e:
                    missing = None
                    write_log(target=tid, day=day, status="failed", detail=f"checking what OpenCTI holds: {str(e)[:200]}")
                if missing is not None:
                    prev.pop("verify_at", None)
                    if missing and prev.get("retries", 0) < RETRIES:
                        for oid in missing:
                            (prev.get("objects") or {}).pop(oid, None)
                        prev["retries"] = prev.get("retries", 0) + 1
                        retrying = True
                        write_log(target=tid, day=day, status="retry", detail=f"{len(missing)} object(s) not in OpenCTI after the send: sent again")
                    elif missing:
                        write_log(target=tid, day=day, status="refused",
                                  detail=f"OpenCTI did not take {len(missing)} object(s) after {RETRIES} tries: " + ", ".join(missing[:10]))
                        audit.add("connector_refused", user="looking-glass", target=t["name"],
                                  detail=f"{day}: {len(missing)} object(s) refused by OpenCTI (see its Data -> Ingestion work errors)")
                    st["days"][day] = prev
                    state.save()
            if prev.get("sig") == full_sig and not retrying:
                continue
            devs = devices_of(db, cols, day, lambda asn, ip, s=scope: C.in_scope(s, asn, ip), base_dir, beacons)
            devices = list(devs.values())
            try:
                if t["kind"] == "opencti":
                    bundle = cp.stix_bundle(devices, day, t["tlp"], know, _now_iso())
                    hashes = object_hashes(bundle["objects"])
                    old = prev.get("objects") or {}
                    changed = [o for o in bundle["objects"] if old.get(o["id"]) != hashes[o["id"]]]
                    # what Looking Glass sent for this day before and no longer sends (a device out of scope, an
                    # analysis that changed): revoked in OpenCTI, the same objects with revoked: true
                    dropped = dropped_objects(data, tid, day, bundle["objects"])
                    col = C.collection_url(t["address"])
                    out = changed + dropped
                    for j in range(0, len(out), BATCH_OBJECTS):
                        s, b, _ = net.request("POST", col + "objects/", {"Authorization": f"Bearer {key}", "Accept": TAXII,
                                                                       "Content-Type": TAXII}, {"objects": out[j:j + BATCH_OBJECTS]})
                        if s not in (200, 201, 202):
                            raise ValueError(f"OpenCTI answered {s}: {b[:200]!r}")
                    st["days"][day] = {"sig": full_sig, "objects": hashes, "devices": len(devices),
                                       "ours": [o["id"] for o in bundle["objects"] if ours(o)],
                                       "verify_at": time.time() + VERIFY_AFTER, "retries": prev.get("retries", 0) if retrying else 0}
                    keep_sent(data, tid, day, bundle["objects"])
                    write_log(target=tid, day=day, status="sent", devices=len(devices), objects=len(changed), tlp=t["tlp"],
                              **({"revoked": len(dropped)} if dropped else {}))
                    sent_total += len(out)
                else:
                    ev = cp.misp_event(devices, day, t["tlp"], know, tid)
                    misp_send(net, t, key, ev)
                    st["days"][day] = {"sig": full_sig, "objects": {"event": ev["Event"]["uuid"]}, "devices": len(devices)}
                    write_log(target=tid, day=day, status="sent", devices=len(devices), objects=len(ev["Event"]["Object"]), tlp=t["tlp"])
                    sent_total += len(devices)
                audit.add("connector_sent", user="looking-glass", target=t["name"], detail=f"{day}: {len(devices)} device(s), TLP:{t['tlp'].upper()}")
                st["fails"] = 0
            except (ValueError, net.Refused) as e:
                failed = True
                write_log(target=tid, day=day, status="failed", detail=str(e)[:300])
                audit.add("connector_failed", user="looking-glass", target=t["name"], detail=f"{day}: {str(e)[:200]}")
                break
            state.save()
        if failed:
            st["fails"] = st.get("fails", 0) + 1           # once per run
        if failed and st.get("fails", 0) >= 3:
            t["paused"] = "Three runs in a row failed; the last: " + (C.read_log(log_path, tid, 1) or [{}])[0].get("detail", "")
            targets.save(tid, t)
            audit.add("connector_paused", user="looking-glass", target=t["name"], detail=t["paused"][:200])
        t2 = targets.get(tid) or t
        t2["last"] = {"at": int(time.time()), "ok": not failed}
        targets.save(tid, t2)
        state.save()
    log(f"connectors: {sent_total} object(s) sent")
    return sent_total


def misp_send(net, t, key, ev):
    """Add the day's event, or replace it when it was sent before (the same uuid)."""
    base = t["address"].rstrip("/")
    h = {"Authorization": key, "Accept": "application/json", "Content-Type": "application/json"}
    uid = ev["Event"]["uuid"]
    s, old, _ = net.request("GET", f"{base}/events/view/{uid}", h)
    s2, b, _ = net.request("POST", f"{base}/events/edit/{uid}" if s == 200 else f"{base}/events/add", h, ev)
    if s2 not in (200, 201):
        raise ValueError(f"MISP answered {s2}: {b[:200]!r}")
    if s == 200:
        for a_uuid, tag in stale_misp_tags(old, ev):
            s3, b3, _ = net.request("POST", f"{base}/tags/removeTagFromObject/{a_uuid}/{tag}", h, {})
            if s3 != 200:
                raise ValueError(f"MISP answered {s3} removing an old tag: {b3[:200]!r}")


def stale_misp_tags(old_body, ev):
    """Tags MISP keeps from an earlier send that this send no longer carries (an edit adds tags, never removes them):
    on attributes, only Looking Glass's own looking-glass:* tags; on the event, only a TLP tag that is no longer the
    target's. Tags analysts added themselves are left alone. Returns (uuid, tag id) pairs."""
    try:
        old = json.loads(old_body).get("Event") or {}
    except (ValueError, AttributeError):
        return []
    new_attr = {a["uuid"]: {t["name"] for t in a.get("Tag") or []} for o in ev["Event"].get("Object") or [] for a in o["Attribute"]}
    out = []
    for o in old.get("Object") or []:
        for a in o.get("Attribute") or []:
            if a.get("uuid") in new_attr:
                out += [(a["uuid"], t["id"]) for t in a.get("Tag") or []
                        if str(t.get("name", "")).startswith("looking-glass:") and t["name"] not in new_attr[a["uuid"]]]
    new_ev = {t["name"] for t in ev["Event"].get("Tag") or []}
    out += [(old.get("uuid") or ev["Event"]["uuid"], t["id"]) for t in old.get("Tag") or []
            if str(t.get("name", "")).startswith("tlp:") and t["name"] not in new_ev]
    return out


REVOCABLE = ("grouping", "observed-data", "note", "sighting", "relationship")


def _sent_path(data, tid, day):
    return os.path.join(data, "connectors_sent", tid, f"{day}.json.gz")


def keep_sent(data, tid, day, objs):
    """The day's per-device objects as sent to OpenCTI, compressed (0600): a revocation must carry the whole object, and
    after the purge Looking Glass no longer has the records to build it again."""
    import gzip
    p = _sent_path(data, tid, day)
    os.makedirs(os.path.dirname(p), mode=0o700, exist_ok=True)
    keep = [o for o in objs if o["type"] in REVOCABLE and ours(o)]
    fd = os.open(p + ".tmp", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(gzip.compress(json.dumps(keep).encode()))
    os.replace(p + ".tmp", p)


def ours(o):
    """Looking Glass's own objects (signed by the CSIRT): only these are revoked or checked. MITRE's techniques,
    mitigations and their links carry no author: they belong to the platform's MITRE data and are never revoked."""
    return bool(o.get("created_by_ref") or o.get("x_opencti_created_by_ref"))


def read_sent(data, tid, day):
    """The day's objects as last sent (keep_sent), [] when none."""
    import gzip
    try:
        with open(_sent_path(data, tid, day), "rb") as f:
            return [o for o in json.loads(gzip.decompress(f.read())) if ours(o)]
    except (OSError, ValueError):
        return []


def dropped_objects(data, tid, day, objs):
    """Looking Glass's objects sent for this day before and missing from this send, as revocations."""
    now_ids = {o["id"] for o in objs}
    return [dict(o, modified=_now_iso(), revoked=True) for o in read_sent(data, tid, day) if o["id"] not in now_ids]


def opencti_missing(net, t, key, ids):
    """The STIX ids among `ids` that OpenCTI does not hold, asked through its GraphQL API with the connector's key (the
    user may read knowledge). OpenCTI finds an object by any id it was sent under (merged objects keep them all)."""
    from urllib.parse import urlsplit
    u = urlsplit(t["address"])
    gql = f"{u.scheme}://{u.netloc}/graphql"
    h = {"Authorization": f"Bearer {key}", "Accept": "application/json", "Content-Type": "application/json"}
    q = ("query($f: FilterGroup) { a: stixCoreObjects(first: 500, filters: $f) { edges { node { standard_id x_opencti_stix_ids } } } "
         "b: stixCoreRelationships(first: 500, filters: $f) { edges { node { standard_id x_opencti_stix_ids } } } "
         "c: stixSightingRelationships(first: 500, filters: $f) { edges { node { standard_id x_opencti_stix_ids } } } }")
    found = set()
    for i in range(0, len(ids), IDS_PER_QUERY):
        part = ids[i:i + IDS_PER_QUERY]
        f = {"mode": "and", "filters": [{"key": "ids", "values": part}], "filterGroups": []}
        s, b, _ = net.request("POST", gql, h, {"query": q, "variables": {"f": f}})
        if s != 200:
            raise ValueError(f"OpenCTI's API answered {s}")
        j = json.loads(b)
        if j.get("errors"):
            raise ValueError("OpenCTI's API: " + str(j["errors"][0].get("message", ""))[:150])
        for k in ("a", "b", "c"):
            for e in ((j.get("data") or {}).get(k) or {}).get("edges", []):
                n = e["node"]
                found.add(n.get("standard_id"))
                found.update(n.get("x_opencti_stix_ids") or [])
    return [i for i in ids if i not in found]


def revoke(net, C, data, t, key, tid, day, prev, write_log, audit):
    """A day the purge removed: its objects revoked in OpenCTI (the same objects, revoked: true), its event deleted in
    MISP."""
    try:
        if t["kind"] == "opencti":
            now = _now_iso()
            objs = [dict(o, modified=now, revoked=True) for o in read_sent(data, tid, day)]
            col = C.collection_url(t["address"])
            for j in range(0, len(objs), BATCH_OBJECTS):
                s, b, _ = net.request("POST", col + "objects/", {"Authorization": f"Bearer {key}", "Accept": TAXII, "Content-Type": TAXII},
                                      {"objects": objs[j:j + BATCH_OBJECTS]})
                if s not in (200, 201, 202):
                    raise ValueError(f"OpenCTI answered {s}")
        else:
            uid = (prev.get("objects") or {}).get("event")
            s, _, _ = net.request("POST", f"{t['address'].rstrip('/')}/events/delete/{uid}",
                                  {"Authorization": key, "Accept": "application/json", "Content-Type": "application/json"}, {})
            if s not in (200, 404):
                raise ValueError(f"MISP answered {s}")
        try:
            os.remove(_sent_path(data, tid, day))
        except OSError:
            pass
        write_log(target=tid, day=day, status="revoked", detail="the quarterly purge removed this day")
        audit.add("connector_revoked", user="looking-glass", target=t["name"], detail=f"{day}: removed by the purge, revoked there too")
        return True
    except (ValueError, net.Refused) as e:
        write_log(target=tid, day=day, status="failed", detail=f"revoking: {str(e)[:200]}")
        return False


if __name__ == "__main__":
    run()
