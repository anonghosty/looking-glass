#!/usr/bin/env python3
"""Independent check of a Looking Glass audit log: Python 3.8 or newer, standard library only.

It ships inside every proof package (Audit portal -> Integrity and evidence -> Proof package) as verify_audit_log.py,
so an auditor can check the log on their own computer, without Looking Glass and without trusting it. The code is
short on purpose: read it before you rely on it.

    python verify_audit_log.py                         check the package this script is in
    python verify_audit_log.py --earlier HASH@ENTRY    and prove the log up to an earlier audit's head is unchanged
    python verify_audit_log.py --json                  the result as JSON

The format it checks
  log/audit_archive/audit-*.log.gz   older entries (gzip), oldest file first by name
  log/audit.log                      the newest entries
  Each entry is one line of JSON. Every entry since the chain started has "prev": the SHA-256 (hex, of the UTF-8 bytes
  of the whole previous line, without its newline) of the line before it. The first chained entry's "prev" is 64 zeros,
  or the last hash of the newest archive removed by the retention (log/audit_archive/removed.jsonl).
  log/audit.head                     {"head": hash of the last line, "entries": number of entries, archives removed included}
  log/audit.seal                     the entries written before the chain started: their number and the SHA-256 of
                                     those lines joined by "\n"
  log/audit_archive/removed.jsonl    one note per archive the retention removed; each must also be an entry in the
                                     chain (event "audit_archive_removed"); removed.recorded counts those recorded.
                                     Whether a removal was allowed is judged from the chain, not the note: the time of
                                     its chain entry, and the retention setting in force then (event
                                     "audit_retention_set", recorded at start-up and whenever it changes)
  MANIFEST.json                      the SHA-256 of every file in the package when it was made

What a whole chain proves: no entry was changed, inserted or removed after it was written, and nothing was cut from the
end (audit.head). On its own it cannot prove that the whole log was not rewritten from scratch by someone with access to
the server; that is what --earlier proves. The head hash of an entry depends on every entry before it, so if the head
hash noted at an earlier audit is still found at the same entry number, every entry up to it is the one that was there
at that audit.
"""
import argparse
import glob
import gzip
import hashlib
import json
import os
import re
import sys
import time

ZERO = "0" * 64


def sha(line):
    return hashlib.sha256(line.encode("utf-8")).hexdigest()


def file_sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def _lines(path):
    opener = gzip.open if path.endswith(".gz") else open
    try:
        with opener(path, "rt", encoding="utf-8") as f:
            return [ln.rstrip("\n") for ln in f if ln.strip()]
    except FileNotFoundError:
        return []


def _json(path, many=False):
    try:
        with open(path, encoding="utf-8") as f:
            return [json.loads(ln) for ln in f if ln.strip()] if many else json.load(f)
    except (OSError, ValueError):
        return [] if many else None


def when(t):
    return time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(t)) if isinstance(t, (int, float)) and t else ""


def _pre_chain(lines):
    for i, ln in enumerate(lines):
        try:
            if "prev" in json.loads(ln):
                return lines[:i]
        except ValueError:
            pass
    return []


def parse_earlier(text):
    """'HASH' or 'HASH@ENTRY' (the head hash and entry number noted at an earlier audit)."""
    m = re.fullmatch(r"\s*([0-9a-fA-F]{64})(?:\s*@\s*(\d+))?\s*", text or "")
    if not m:
        raise ValueError("expected the 64-character head hash, optionally followed by @ and the entry number")
    return m.group(1).lower(), (int(m.group(2)) if m.group(2) else None)


def check(folder, earlier=None, gap_days=30):
    """Check the log in `folder` (the folder holding audit.log and audit_archive/). `earlier` = (hash, entry or None);
    gap_days: a jump in time around a removed archive longer than this is reported."""
    archives = sorted(glob.glob(os.path.join(folder, "audit_archive", "audit-*.log.gz")))
    lines = []
    for p in archives:
        lines.extend(_lines(p))
    lines.extend(_lines(os.path.join(folder, "audit.log")))
    removed = _json(os.path.join(folder, "audit_archive", "removed.jsonl"), many=True)
    gone = sum(int(r.get("entries") or 0) for r in removed)       # entries of archives the retention removed

    prev = removed[-1]["last_hash"] if removed else None
    before = chained = 0
    first_t = last_t = None
    brk, started = None, False
    hashes = []
    for i, ln in enumerate(lines):
        n = gone + i + 1                                           # the entry's number since the log began
        try:
            rec = json.loads(ln)
        except ValueError:
            brk = brk or {"entry": n, "what": "a line that is not a valid entry"}
            prev = sha(ln); hashes.append(prev)
            continue
        t = rec.get("t")
        first_t = t if first_t is None else first_t
        last_t = t if t is not None else last_t
        if "prev" not in rec:
            if started and not brk:
                brk = {"entry": n, "t": t, "what": "an entry without its link after the chain started"}
            before += 1
        else:
            started = True
            if rec["prev"] != (prev if prev is not None else ZERO) and not brk:
                brk = {"entry": n, "t": t, "what": "the entry before this one was changed, inserted or removed"}
            chained += 1
        prev = sha(ln); hashes.append(prev)

    head = hashes[-1] if hashes else ZERO
    head_entry = gone + len(lines)
    saved = _json(os.path.join(folder, "audit.head"))
    head_file = "missing"
    if saved:
        head_file = "matches" if saved.get("head") == head and saved.get("entries") == head_entry else "differs"
        if head_file == "differs" and not brk:
            brk = {"entry": head_entry, "t": last_t, "what": "the last entries do not match audit.head (entries removed from the end?)"}

    seal, seal_state = _json(os.path.join(folder, "audit.seal")), "none"
    if seal:
        pre = _pre_chain(lines)
        if len(pre) == seal.get("entries") and sha("\n".join(pre)) == seal.get("sha256"):
            seal_state = "intact"
        elif removed and len(pre) < (seal.get("entries") or 0):
            seal_state = "partly removed by the retention"
        else:
            seal_state = "changed"
            brk = brk or {"entry": gone + 1, "t": seal.get("first"), "what": "entries written before the chain were changed after they were sealed"}

    # Every archive the retention removed must also be recorded in the chain itself (an entry with event
    # "audit_archive_removed", its "target" the archive and "removed"."last_hash" its last link), not only in the notes
    # file. audit_archive/removed.recorded says how many notes are recorded so far (the rest go in with the next entry).
    # A recorded note may lack its entry only when that entry is older than the oldest entry kept.
    try:
        recorded = min(int(open(os.path.join(folder, "audit_archive", "removed.recorded")).read().strip() or 0), len(removed))
    except (OSError, ValueError):
        recorded = 0
    seen, oldest_t = {}, None
    for ln in lines:
        try:
            rec = json.loads(ln)
        except ValueError:
            continue
        oldest_t = rec.get("t") if oldest_t is None else oldest_t
        if rec.get("event") in ("audit_archive_removed", "audit_archive_deleted_early"):
            seen[rec.get("target")] = (rec.get("removed") or {}).get("last_hash")
    unaccounted = [n.get("archive") for n in removed[:recorded] if seen.get(n.get("archive")) != n.get("last_hash")
                   and not (oldest_t is not None and (n.get("removed_at") or 0) < oldest_t)]
    if unaccounted and not brk:
        brk = {"entry": gone + 1, "t": first_t, "what": f"retention notes with no entry in the chain ({', '.join(unaccounted[:3])}): "
                                                        "an archive was removed or noted outside Looking Glass"}

    # An archive may only be removed once its newest entry is older than the retention. The note is written by whoever
    # removed the archive, so the two values that decide are taken from the chain, not from the note: the removal time
    # is the time of the chain entry Looking Glass wrote for it (now, if not recorded yet), and the retention is the
    # setting in force then, recorded in the chain (event "audit_retention_set", "target" the days). A note claiming a
    # later removal or a shorter retention is a forged note. Before the first recorded setting the note's own retention
    # is all there is: such a removal is marked "retention not recorded". A note's dates of its own entries could be
    # faked to look old too, so the time from a removed archive's newest entry to the next archive's oldest (or the
    # first entry still kept, whose time is inside the chain) should not jump by more than gap_days.
    def num(x, default=0.0):
        try:
            return float(x)
        except (TypeError, ValueError):
            return default
    history, rec_at = [], {}
    for ln in lines:
        if '"audit_retention_set"' not in ln and '"audit_archive_' not in ln:
            continue
        try:
            rec = json.loads(ln)
        except ValueError:
            continue
        if rec.get("event") == "audit_retention_set":
            try:
                history.append((num(rec.get("t")), int(rec.get("target"))))
            except (TypeError, ValueError):
                pass
        elif rec.get("event") in ("audit_archive_removed", "audit_archive_deleted_early"):
            rec_at[(rec.get("target"), (rec.get("removed") or {}).get("last_hash"))] = num(rec.get("t"))
    removals = []
    for i, n in enumerate(removed):
        key = (n.get("archive"), n.get("last_hash"))
        pending = False
        if key in rec_at:
            at = rec_at[key]
        elif i < len(removed) - 1 and first_t is not None and num(n.get("removed_at")) < num(first_t):
            continue                          # its chain entry went with a later removal (judged when it was recorded)
        else:
            at, pending = time.time(), True
        days = None
        for t, d in history:
            if t <= at + 1:
                days = d
        recorded_setting = days is not None
        if days is None:
            days = int(num(n.get("retention_days")))
        why = []
        # Looking Glass records a removal in the same write that makes it: a note not recorded in the chain, with no
        # retention setting in the chain to judge it by, can only be judged by its own claims, so it is not accepted
        if pending and not recorded_setting:
            why.append("it is not recorded in the chain and no retention setting is recorded to judge it by (Looking Glass "
                       "records each removal in the same write that makes it)")
        if num(n.get("removed_at")) > at + 60:
            why.append(f"its note claims a removal time ({when(num(n.get('removed_at')))}) later than the removal was recorded ({when(at)})")
        if recorded_setting and n.get("retention_days") is not None and num(n.get("retention_days")) < days:
            why.append(f"its note claims a retention of {n.get('retention_days')} days, the setting was {days} days")
        newest = num(n.get("newest"), None)
        if newest is None:
            why.append("its note gives no newest entry")
        elif newest > min(at, num(n.get("removed_at"), at)) - days * 86400 + 1:
            why.append(f"its newest entry ({when(newest)}) was not yet {days} days old when it was removed")
        removals.append({"archive": n.get("archive"), "entries": n.get("entries"), "oldest": n.get("oldest"), "newest": n.get("newest"),
                         "removed_at": at, "retention_days": days, "retention_recorded": recorded_setting,
                         "early": bool(why), "why": "; ".join(why)})
    removed_early = [x["archive"] for x in removals if x["early"]]
    if removed_early and not brk:
        brk = {"entry": gone + 1, "t": first_t, "what": f"archives removed before their retention ended ({', '.join(removed_early[:3])}): "
                                                        "entries were deleted outside the retention"}
    gaps = []
    for i, n in enumerate(removed):
        nxt = removed[i + 1].get("oldest") if i + 1 < len(removed) else first_t
        if n.get("newest") and nxt and float(nxt) - float(n["newest"]) > gap_days * 86400:
            gaps.append({"after": n.get("archive"), "from": n["newest"], "to": nxt, "days": int((float(nxt) - float(n["newest"])) // 86400)})

    out = {"ok": brk is None, "entries": head_entry, "removals_recorded": recorded - len(unaccounted),
           "removals_pending": len(removed) - recorded, "removed_early": removed_early, "removal_gaps": gaps,
           "removals": removals, "retention_history": [{"t": t, "days": d} for t, d in history], "kept": len(lines), "removed_by_retention": gone, "chained": chained,
           "before_chain": before, "first": first_t, "last": last_t, "head": head, "head_entry": head_entry,
           "head_file": head_file, "seal": dict(seal, state=seal_state) if seal else None, "archives": len(archives), "break": brk}

    if earlier:
        h, n = earlier
        found = None
        for i, x in enumerate(hashes):
            if x == h:
                found = {"entry": gone + i + 1, "where": "kept"}
                try:
                    found["t"] = json.loads(lines[i]).get("t")
                except ValueError:
                    pass
                break
        if not found and removed and removed[-1].get("last_hash") == h:
            found = {"entry": gone, "where": "the last entry of an archive removed by the retention", "t": removed[-1].get("newest")}
        e = {"hash": h, "entry_given": n, "found": bool(found)}
        if found:
            e.update(found)
            e["same_entry"] = n is None or n == found["entry"]
            e["proven"] = out["ok"] and e["same_entry"] and found["where"] == "kept"
        else:
            e["proven"] = False
        out["earlier"] = e
    return out


def check_manifest(root):
    """The files of a proof package against its MANIFEST.json."""
    m = _json(os.path.join(root, "MANIFEST.json"))
    if not m:
        return None
    bad = []
    for f in m.get("files", []):
        p = os.path.join(root, *f["path"].split("/"))
        if not os.path.exists(p):
            bad.append(f"{f['path']}: missing")
        elif file_sha(p) != f["sha256"]:
            bad.append(f"{f['path']}: changed")
    return {"files": len(m.get("files", [])), "problems": bad, "made": m.get("generated"), "by": m.get("generated_by")}


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    ap = argparse.ArgumentParser(description="Check a Looking Glass audit log (proof package) independently.")
    ap.add_argument("folder", nargs="?", default=here, help="the unzipped proof package (default: the folder of this script)")
    ap.add_argument("--earlier", help="the head hash noted at an earlier audit, as HASH or HASH@ENTRY")
    ap.add_argument("--json", action="store_true", help="print the result as JSON")
    ap.add_argument("--gap-days", type=int, default=30, help="report a jump in time around a removed archive longer than this")
    a = ap.parse_args()
    root = os.path.abspath(a.folder)
    log = os.path.join(root, "log") if os.path.isdir(os.path.join(root, "log")) else root
    try:
        earlier = parse_earlier(a.earlier) if a.earlier else None
    except ValueError as e:
        ap.error(f"--earlier: {e}")
    r = check(log, earlier, a.gap_days)
    r["manifest"] = check_manifest(root)
    good = r["ok"] and (not r["manifest"] or not r["manifest"]["problems"]) and (not earlier or r["earlier"]["proven"])
    if a.json:
        print(json.dumps(r, indent=2))
        return 0 if good else 1

    print("Looking Glass audit log: independent check")
    print(f"  folder            {log}")
    if r["manifest"] is not None:
        m = r["manifest"]
        print(f"  package files     {m['files']} listed in MANIFEST.json (made {m['made']} by {m['by']}): "
              + ("all unchanged" if not m["problems"] else "PROBLEMS: " + "; ".join(m["problems"])))
    print(f"  entries           {r['entries']} ({r['kept']} kept, {r['removed_by_retention']} removed by the retention; "
          f"{r['chained']} chained, {r['before_chain']} written before the chain started)")
    print(f"  from - to         {when(r['first'])} - {when(r['last'])}")
    print(f"  head              entry {r['head_entry']}: {r['head']}  (audit.head: {r['head_file']})")
    if r["seal"]:
        print(f"  seal              {r['seal']['entries']} entries before the chain, sealed {when(r['seal'].get('sealed_at'))}: {r['seal']['state']}")
    if r["removed_by_retention"] or r["removals_pending"]:
        print(f"  retention         {r['removals_recorded']} removed archive(s) recorded in the chain"
              + (f", {r['removals_pending']} to be recorded with the next entry" if r["removals_pending"] else ""))
        for x in r["removals"]:
            print(f"                    {x['archive']}: {x['entries']} entries up to {when(x['newest'])}, removed {when(x['removed_at'])} "
                  f"(retention {x['retention_days']} days{'' if x['retention_recorded'] else ', setting not recorded in the chain'})"
                  + (f"  NOT ALLOWED: {x['why']}" if x["early"] else ""))
    if r["retention_history"]:
        print("  retention setting " + " · ".join(f"{h['days']} days from {when(h['t'])}" for h in r["retention_history"]))
        for g in r["removal_gaps"]:
            print(f"  ATTENTION         {g['days']} days without any entry after {g['after']} ({when(g['from'])} to {when(g['to'])}): "
                  "real use writes more often; ask why, or whether entries were removed and the note's dates changed")
    if r["ok"]:
        print("  chain             WHOLE: no entry was changed, inserted or removed, and nothing was cut from the end")
    else:
        b = r["break"]
        print(f"  chain             BROKEN at entry {b['entry']}{' (' + when(b.get('t')) + ')' if b.get('t') else ''}: {b['what']}")
    if earlier:
        e = r["earlier"]
        if not e["found"]:
            print(f"  earlier head      NOT FOUND: {e['hash']} is not in this log. The log was rewritten, or the hash was noted wrongly.")
        elif e["where"] != "kept":
            print(f"  earlier head      found as {e['where']} (entry {e['entry']}): the entries up to it are no longer kept, "
                  "so they cannot be compared; the chain from it on is checked above.")
        elif not e["same_entry"]:
            print(f"  earlier head      found at entry {e['entry']}, NOT at entry {e['entry_given']} as noted: entries before it were added or removed.")
        else:
            print(f"  earlier head      found at entry {e['entry']} ({when(e.get('t'))})"
                  + (": the log up to it is exactly the log of the earlier audit." if r["ok"] else ", but the chain is broken (see above)."))
    print("RESULT: " + ("verified" if good else "NOT verified"))
    return 0 if good else 1


if __name__ == "__main__":
    sys.exit(main())
