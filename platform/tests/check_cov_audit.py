#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""The audit log's evidence code beyond the portal's own checks (r91 coverage), in temporary folders only:
- audit_verifier.py, the auditor's independent check, run as its command line: a whole log verified (text and JSON),
  the package's MANIFEST, --earlier proven / at another entry / not found / malformed, --key (only that key trusted; an
  empty or missing key file refused), and every break it must report: a changed line, a line that is not an entry, an
  entry without its link, audit.head missing or different, a damaged archive, a bad retention note, an archive recorded
  as rotated but gone, a removal before the retention ended, the seal changed or contradicting the chain, checkpoints
  that are unreadable, beyond the end, at the wrong hash or wrongly signed; a genuine retention removal passes with the
  long silence it leaves flagged
- audit_chain.py: the older walk (_verify_legacy) agrees on whole and broken logs; the removal judgement (forged times,
  a shorter claimed retention, a note disagreeing with its rotation, no newest entry, too young); notes the chain does
  not account for; the old single copy adopted; damaged archives read around and never pruned
- audit_checkpoint.py, its command line (help, key, now, sign-file, backup-age, verify-file, unknown): signed
  checkpoints, a half-made key replaced, no ssh-keygen (nothing signed, said so), the copy folder (missing, copied, a
  name already there, read-only), the daily loop, which backup is the newest signed one
Made-up entries only. Run: .venv/bin/python tests/check_cov_audit.py"""
import contextlib
import gzip
import io
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
for k in ("AUDIT_CHECKPOINT_COPY_DIR", "AUDIT_RETENTION_DAYS", "AUDIT_ROTATE_MB", "AUDIT_GAP_DAYS", "AUDIT_CHECKPOINT_HOURS"):
    os.environ.pop(k, None)
import audit_chain as AC  # noqa: E402
import audit_checkpoint as CK  # noqa: E402
import audit_verifier as AV  # noqa: E402

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info and not cond else ""), flush=True)


ROOT = tempfile.mkdtemp(prefix="lg-cov-audit-")
KG = bool(shutil.which("ssh-keygen"))
DAY = 86400


def entry(chain, event="login", user="grace", t=None, **extra):
    return chain.append(dict({"t": round(t if t is not None else time.time(), 3), "event": event, "user": user, "target": "",
                              "detail": "made-up entry", "ip": "", "location": "", "ua": ""}, **extra))


def verifier(*args):
    """audit_verifier.main() as an auditor runs it: (exit code, printed text)."""
    out, err = io.StringIO(), io.StringIO()
    old = sys.argv
    sys.argv = ["verify_audit_log.py", *args]
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                rc = AV.main()
            except SystemExit as e:
                rc = e.code
    finally:
        sys.argv = old
    return rc, out.getvalue() + err.getvalue()


def copy(src, name):
    dst = os.path.join(ROOT, name)
    shutil.copytree(src, dst)
    return dst


def lines_of(folder):
    return open(os.path.join(folder, "audit.log")).read().splitlines()


def write_lines(folder, lines):
    with open(os.path.join(folder, "audit.log"), "w") as f:
        f.write("\n".join(lines) + "\n")


try:
    # ------------------------------------------------------------------ a whole log with a signed checkpoint
    print("A whole log, checked by the auditor's script")
    base = os.path.join(ROOT, "base")
    os.makedirs(base)
    ch = AC.Chain(os.path.join(base, "audit.log"))
    ch.record_retention_setting()
    ok("the retention setting is recorded once, not again unchanged", ch.record_retention_setting() is None)
    for i in range(5):
        entry(ch, user=f"user{i}")
    cli = CK._CliAudit(base)
    signer = CK.Signer(base)
    ck = signer.make(cli)
    ok("a checkpoint: the head and entry, signed when ssh-keygen is there, recorded in the chain",
       ck and ck["entry"] >= 6 and ck["signed"] is KG and ck["copied"] == ""
       and json.loads(lines_of(base)[-1])["event"] == CK.CHECKPOINT_EVENT, str(ck))
    if signer.make(cli) is not None:             # the first one also recorded the new key: one more entry since
        pass
    ok("…nothing new since its own entry: no further one", signer.make(cli) is None)
    entry(ch, user="after")
    r = AV.check(base)
    ok("the check: whole, every entry chained, each checkpoint at its entry",
       r["ok"] and r["chained"] == r["kept"] and r["checkpoints"]["count"] >= 1
       and r["checkpoints"]["matched"] == r["checkpoints"]["count"] and r["head_file"] == "matches", json.dumps(r.get("break")))
    if KG:
        ok("…their signatures valid with the key recorded in the chain", set(r["checkpoints"]["signatures"]) == {"valid"}, str(r["checkpoints"]))
    # a proof package: log/ and a MANIFEST
    pkg = os.path.join(ROOT, "pkg")
    shutil.copytree(base, os.path.join(pkg, "log"))
    files = []
    for dp, _, fs in os.walk(os.path.join(pkg, "log")):
        for f in fs:
            p = os.path.join(dp, f)
            files.append({"path": os.path.relpath(p, pkg).replace(os.sep, "/"), "sha256": AV.file_sha(p)})
    with open(os.path.join(pkg, "MANIFEST.json"), "w") as f:
        json.dump({"files": files, "generated": "2099-01-01", "generated_by": "Grace"}, f)
    rc, out = verifier(pkg)
    ok("the command line: verified, package files unchanged, chain WHOLE", rc == 0 and "RESULT: verified" in out
       and "all unchanged" in out and "WHOLE" in out and "checkpoints" in out, out[-600:])
    rc, out = verifier(pkg, "--json")
    ok("…as JSON", rc == 0 and json.loads(out)["ok"] is True and json.loads(out)["manifest"]["problems"] == [])
    head, n = r["head"], r["head_entry"]
    rc, out = verifier(pkg, "--earlier", f"{head}@{n}")
    ok("--earlier HASH@ENTRY at its entry: proven", rc == 0 and "exactly the log of the earlier audit" in out, out[-300:])
    rc, out = verifier(pkg, "--earlier", f"{head}@{n + 3}")
    ok("…at another entry: not verified, says so", rc == 1 and f"NOT at entry {n + 3}" in out)
    rc, out = verifier(pkg, "--earlier", "a" * 64)
    ok("…a hash not in the log: NOT FOUND", rc == 1 and "NOT FOUND" in out)
    rc, out = verifier(pkg, "--earlier", "nonsense")
    ok("…malformed: refused by the command line", rc == 2 and "--earlier" in out)
    try:
        AV.parse_earlier("x"); refused = False
    except ValueError:
        refused = True
    ok("parse_earlier: a hash alone, upper case allowed; nonsense refused", AV.parse_earlier(" " + "AB" * 32 + " ") == ("ab" * 32, None)
       and refused)
    keyfile = os.path.join(ROOT, "noted.pub")
    with open(keyfile, "w") as f:
        f.write("﻿the key I noted: " + (signer.public()[0] or "ssh-ed25519 AAAAmadeup") + "\n")
    rc, out = verifier(pkg, "--key", keyfile)
    ok("--key with the key the auditor noted: verified", rc == 0 or not KG, out[-300:])
    empty = os.path.join(ROOT, "empty.pub")
    open(empty, "w").close()
    rc, out = verifier(pkg, "--key", empty)
    ok("--key file without a key: refused", rc == 2 and "no signing public key" in out)
    rc, out = verifier(pkg, "--key", os.path.join(ROOT, "missing.pub"))
    ok("--key file missing: refused", rc == 2 and "--key" in out)
    if KG:
        other = os.path.join(ROOT, "other_key")
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", other], check=True, capture_output=True)
        rc, out = verifier(pkg, "--key", other + ".pub")
        ok("…another key: the checkpoint's signature does not match it", rc == 1 and "does not match the key given with --key" in out, out[-400:])
        r2 = AV.check(os.path.join(pkg, "log"), extra_keys=[])
        ok("…an empty key list never falls back to the log's own keys", set(r2["checkpoints"]["signatures"]) == {"INVALID"}
           and r2["checkpoints"]["trusted"] == "the key given with --key only")
    with open(os.path.join(pkg, "log", "audit.log"), "a") as f:
        f.write("")
    first = files[0]["path"]
    with open(os.path.join(pkg, *first.split("/")), "a") as f:
        f.write("\n")
    os.remove(os.path.join(pkg, *files[-1]["path"].split("/")))
    rc, out = verifier(pkg)
    ok("a package file changed or missing: PROBLEMS, not verified", rc == 1 and "PROBLEMS" in out and "changed" in out
       and "missing" in out, out[-500:])
    ok("check_manifest without a MANIFEST: none", AV.check_manifest(base) is None)

    # ------------------------------------------------------------------ breaks
    print("Every break is found (the auditor's check and the portal's older walk)")
    d = copy(base, "changed")
    ls = lines_of(d)
    rec = json.loads(ls[2]); rec["user"] = "someone-else"; ls[2] = json.dumps(rec)
    write_lines(d, ls)
    r = AV.check(d)
    ok("a changed entry: the next one's link breaks", not r["ok"] and "changed, inserted or removed" in r["break"]["what"]
       and r["break"]["entry"] == 4, json.dumps(r["break"]))
    leg = AC.Chain(os.path.join(d, "audit.log"))._verify_legacy()
    ok("…the older walk agrees", not leg["ok"] and leg["break"]["entry"] == 4, json.dumps(leg["break"]))
    rc, out = verifier(d)
    ok("…the command line: BROKEN at entry 4", rc == 1 and "BROKEN at entry 4" in out)
    rc, out = verifier(d, "--earlier", f"{AV.sha(ls[0])}@1")
    ok("…an earlier head found, but the chain is broken", "but the chain is broken" in out, out[-300:])

    d = copy(base, "junk")
    ls = lines_of(d)
    write_lines(d, ls[:3] + ["not json at all", "[1, 2]"] + ls[3:])
    r = AV.check(d)
    ok("a line that is not an entry", not r["ok"] and r["break"]["what"] == "a line that is not a valid entry" and r["break"]["entry"] == 4)
    leg = AC.Chain(os.path.join(d, "audit.log"))._verify_legacy()   # r91 fix: a JSON list no longer crashes it
    ok("…the older walk too, also with a JSON list among the lines", not leg["ok"] and "not a valid entry" in leg["break"]["what"]
       and leg["break"]["entry"] == 4)

    d = copy(base, "unlinked")
    with open(os.path.join(d, "audit.log"), "a") as f:
        f.write(json.dumps({"t": time.time(), "event": "login", "user": "outside"}) + "\n")
    r = AV.check(d)
    ok("an entry without its link after the chain started", not r["ok"] and "without its link" in r["break"]["what"])
    ok("…the older walk too", "without its link" in AC.Chain(os.path.join(d, "audit.log"))._verify_legacy()["break"]["what"])

    d = copy(base, "nohead")
    os.remove(os.path.join(d, "audit.head"))
    r = AV.check(d)
    ok("audit.head missing: entries could have been cut from the end", not r["ok"] and "audit.head is missing" in r["break"]["what"]
       and r["head_file"] == "missing")
    d = copy(base, "cut")
    write_lines(d, lines_of(d)[:-1])
    r = AV.check(d)
    ok("the last entry cut: it does not match audit.head", not r["ok"] and "do not match audit.head" in r["break"]["what"])
    ok("…the older walk too", "audit.head" in AC.Chain(os.path.join(d, "audit.log"))._verify_legacy()["break"]["what"])

    d = copy(base, "damaged")
    os.makedirs(os.path.join(d, "audit_archive"), exist_ok=True)
    bad_gz = os.path.join(d, "audit_archive", "audit-20000101-000000.log.gz")
    with open(bad_gz, "wb") as f:
        f.write(b"this is not gzip data")
    r = AV.check(d)
    ok("a damaged archive: reported as a break, by file name only", not r["ok"] and "damaged" in r["break"]["what"]
       and "audit-20000101-000000.log.gz: unreadable" in r["break"]["what"] and r["archives"] == 0, json.dumps(r["break"]))
    dch = AC.Chain(os.path.join(d, "audit.log"))
    ok("…the portal reads around it", len(dch.lines()) == len(lines_of(d)))
    dch.retention_days = 0
    dch.prune(now=time.time() + 10 * DAY)
    ok("…and the retention never deletes it unread", os.path.exists(bad_gz))
    with open(os.path.join(d, "audit_archive", "audit-20000102-000000.log.gz"), "wb") as f:
        f.write(gzip.compress(b""))
    os.remove(os.path.join(d, "audit.log"))
    ok("…the newest archive damaged or empty: the next link starts afresh (the entry is still written)", dch._tail() is None)
    entry(dch, user="still-written")
    ok("…written", "still-written" in open(os.path.join(d, "audit.log")).read())

    d = copy(base, "badnote")
    os.makedirs(os.path.join(d, "audit_archive"), exist_ok=True)
    with open(os.path.join(d, "audit_archive", "removed.jsonl"), "w") as f:
        f.write("not a note\n\n" + json.dumps({"archive": "x.log.gz", "last_hash": "0" * 64, "entries": 0}) + "\n")
    r = AV.check(d)
    ok("retention notes that are not notes (one unreadable, one for an empty archive)", not r["ok"]
       and "2 line(s) in the retention notes" in r["break"]["what"], json.dumps(r["break"]))
    ok("…the portal skips them", AC.Chain(os.path.join(d, "audit.log")).removed() == [])

    # ------------------------------------------------------------------ the seal of entries written before the chain
    print("Entries written before the chain, and their seal")
    sd = os.path.join(ROOT, "sealed")
    os.makedirs(sd)
    with open(os.path.join(sd, "audit.log"), "w") as f:
        for i in range(3):
            f.write(json.dumps({"t": 1000 + i, "event": "login", "user": f"old{i}"}) + "\n")
    sc = AC.Chain(os.path.join(sd, "audit.log"))
    ok("nothing chained yet: nothing to seal", sc.seal() is None)
    entry(sc, user="first-chained")
    s = sc.seal()
    ok("sealed once, not twice", s and s["entries"] == 3 and sc.seal() is None and sc.read_seal()["sha256"] == s["sha256"])
    entry(sc, "audit_sealed", detail=f"{s['entries']} entries written before the chain sealed · SHA-256 {s['sha256']}")
    entry(sc)
    r = AV.check(sd)
    ok("sealed and recorded in the chain: intact, whole", r["ok"] and r["seal"]["state"] == "intact" and r["before_chain"] == 3,
       json.dumps(r.get("break")))
    ok("…the older walk: intact", sc._verify_legacy()["seal"]["state"] == "intact")
    rc, out = verifier(sd)
    ok("…the command line lists the seal", "3 entries before the chain" in out and rc == 0, out[-500:])
    d = copy(sd, "seal_file")
    sp = os.path.join(d, "audit.seal")
    v = json.load(open(sp)); v["entries"] = 2
    json.dump(v, open(sp, "w"))
    r = AV.check(d)
    ok("audit.seal rewritten: it differs from the seal recorded in the chain", not r["ok"] and "differs from the seal recorded" in r["break"]["what"])
    ok("…the older walk: changed", AC.Chain(os.path.join(d, "audit.log"))._verify_legacy()["seal"]["state"] == "changed")
    d = copy(sd, "seal_lines")
    ls = lines_of(d)
    ls[0] = ls[0].replace("old0", "new0")
    write_lines(d, ls)
    r = AV.check(d)
    ok("an entry before the chain changed: the seal says so", not r["ok"] and r["seal"]["state"] == "changed")

    # ------------------------------------------------------------------ checkpoints
    print("Checkpoints that do not fit")
    d = copy(base, "cps")
    cpd = os.path.join(d, "audit_checkpoints")
    with open(os.path.join(cpd, "checkpoint-00000000-000001.json"), "w") as f:
        f.write("{broken")
    with open(os.path.join(cpd, "checkpoint-00000000-000002.json"), "w") as f:
        json.dump({"head": "b" * 64, "entry": 9999, "made": 1}, f)
    with open(os.path.join(cpd, "checkpoint-00000000-000003.json"), "w") as f:
        json.dump({"head": "c" * 64, "entry": 1, "made": 1}, f)
    r = AV.check(d)
    probs = " | ".join(p["what"] for p in r["checkpoints"]["problems"])
    ok("unreadable, beyond the end of the log, a different hash at its entry", not r["ok"] and "cannot be read" in probs
       and "beyond the end of the log" in probs and "is not the one it recorded" in probs
       and r["checkpoints"]["signatures"].get("no signature") == 2, probs)
    rc, out = verifier(d)
    ok("…the command line names each", out.count("ATTENTION") >= 3 and "latest: entry" in out)
    r = AV.check(base, checkpoints=os.path.join(ROOT, "no-such-folder"))
    ok("a checkpoint folder that does not exist: none counted", r["ok"] and r["checkpoints"]["count"] == 0)
    ok("signatures: none, or not checked without ssh-keygen", AV.signature(os.path.join(base, "audit.log"), "x", []) == "no signature")

    # ------------------------------------------------------------------ retention: a genuine removal and forged ones
    print("Retention removals")
    gd = os.path.join(ROOT, "genuine")
    os.makedirs(gd)
    gc = AC.Chain(os.path.join(gd, "audit.log"))
    old = time.time() - 500 * DAY
    entry(gc, t=old)
    entry(gc, t=old + 60)
    gc.rotate_bytes = 1                         # the next write rotates; the archive is past the 400 days: removed
    entry(gc, user="now")
    gc.rotate_bytes = 5_000_000
    entry(gc, user="later")
    r = AV.check(gd)
    ok("a genuine removal: recorded in the chain, the chain whole from its last link", r["ok"] and r["removed_by_retention"] == 2
       and r["removals_recorded"] == 1 and not r["removals"][0]["early"], json.dumps(r.get("break")))
    ok("…the 500 days without entries after it are flagged for the auditor", r["removal_gaps"] and r["removal_gaps"][0]["days"] >= 499)
    rc, out = verifier(gd)
    ok("…the command line: the removal, the setting, ATTENTION for the silence", rc == 0 and "removed archive(s) recorded" in out
       and "retention setting" in out and "days without any entry" in out, out[-900:])
    leg = gc._verify_legacy()
    ok("…the older walk: whole, with the removal and the gap", leg["ok"] and leg["removals_recorded"] == 1 and leg["removal_gaps"], json.dumps(leg.get("break")))
    note = gc.removed()[0]
    rc, out = verifier(gd, "--earlier", note["last_hash"])
    ok("an earlier head in a removed archive: found as such, not provable", "found as the last entry of an archive removed" in out, out[-300:])
    fnd, gaps, hist = AC.removal_findings(gc.removed(), gc.lines(), 400, 30)
    ok("removal_findings: allowed, judged by the recorded setting and rotation", fnd and not fnd[0]["early"] and fnd[0]["retention_recorded"]
       and fnd[0]["rotation_recorded"] and gaps and hist, str(fnd))

    d = copy(gd, "rotated_gone")
    ed = AC.Chain(os.path.join(d, "audit.log"))
    # a rotation entry for an archive that is neither here nor covered by a note (written in the chain, so it is whole)
    entry(ed, AC.ARCHIVED_EVENT, target="audit-ghost.log.gz",
          archived={"entries": 2, "oldest": time.time() - DAY, "newest": time.time(), "last_hash": "9" * 64})
    r = AV.check(d)
    ok("an archive recorded as rotated, deleted without a note: found", not r["ok"] and "recorded as rotated are missing" in r["break"]["what"],
       json.dumps(r["break"]))

    d = copy(gd, "early")
    # a note added outside Looking Glass under a made-up name, with the real last link (so the links still hold) and the
    # head file adjusted to the extra entries: only the judgement of the removal gives it away
    real_link = AC.Chain(os.path.join(d, "audit.log")).removed()[-1]["last_hash"]
    with open(os.path.join(d, "audit_archive", "removed.jsonl"), "a") as f:
        f.write(json.dumps({"archive": "audit-made-up.log.gz", "entries": 4, "last_hash": real_link, "oldest": time.time() - 2 * DAY,
                            "newest": time.time() - DAY, "removed_at": time.time() + 900 * DAY, "retention_days": 1}) + "\n")
    hp = os.path.join(d, "audit.head")
    hv = json.load(open(hp)); hv["entries"] += 4
    json.dump(hv, open(hp, "w"))
    r = AV.check(d)
    why = r["removals"][-1]["why"]
    ok("a removal noted outside Looking Glass: its name differs from the rotation of that link, a later removal time, a "
       "shorter retention claimed", not r["ok"] and r["removals"][-1]["early"] and "archive name (audit-made-up.log.gz" in why
       and "later than the removal was recorded" in why and "claims a retention of 1 days" in why
       and "before their retention ended" in r["break"]["what"], why + json.dumps(r["break"]))
    rc, out = verifier(d)
    ok("…the command line: NOT ALLOWED, to be recorded with the next entry", "NOT ALLOWED" in out and "to be recorded with the next entry" in out)
    dch = AC.Chain(os.path.join(d, "audit.log"))
    leg = dch._verify_legacy()
    ok("…the older walk: removed before its retention ended", not leg["ok"] and "before their retention ended" in leg["break"]["what"], json.dumps(leg["break"]))
    fnd, _, _ = AC.removal_findings(dch.removed(), dch.lines(), 400, 30)
    ok("…removal_findings: early", fnd[-1]["early"])
    with open(os.path.join(d, "audit_archive", "removed.recorded"), "w") as f:
        f.write("2")
    ok("…counted as recorded but with no chain entry: unaccounted", AC.removals_unrecorded(dch.lines(), dch.removed(), 2) == ["audit-made-up.log.gz"])
    r = AV.check(d)
    ok("…the auditor's check: notes with no entry in the chain", "no entry in the chain" in r["break"]["what"], json.dumps(r["break"]))
    leg = dch._verify_legacy()
    ok("…the older walk too", "no entry in the chain" in leg["break"]["what"])

    d = copy(gd, "lying_note")
    rj = os.path.join(d, "audit_archive", "removed.jsonl")
    n0 = json.loads(open(rj).read().splitlines()[0])
    n0.update(entries=9, oldest=1.0, newest=2.0)
    with open(rj, "w") as f:
        f.write(json.dumps(n0) + "\n")
    r = AV.check(d)
    ok("a note changed after the removal: it disagrees with the rotation recorded in the chain", not r["ok"]
       and "disagrees with the rotation" in r["removals"][0]["why"] and "entries (9, recorded 2)" in r["removals"][0]["why"], r["removals"][0]["why"])

    print("The removal judgement, one rule at a time")
    now = time.time()
    good = {"archive": "a", "entries": 3, "last_hash": "e" * 64, "oldest": now - 500 * DAY, "newest": now - 450 * DAY,
            "removed_at": now, "retention_days": 400}
    ok("allowed: older than the retention", AC.judge_removal(good, now, 400) == "")
    ok("a later removal time claimed", "later than the removal was recorded" in AC.judge_removal(dict(good, removed_at=now + 5 * DAY), now, 400))
    ok("a shorter retention claimed", "claims a retention of 1 days" in AC.judge_removal(dict(good, retention_days=1), now, 400))
    ok("…unless the setting was not recorded", AC.judge_removal(dict(good, retention_days=1), now, 400, setting_recorded=False) == "")
    ok("no newest entry", "gives no newest entry" in AC.judge_removal(dict(good, newest=None), now, 400))
    ok("too young", "not yet 400 days old" in AC.judge_removal(dict(good, newest=now - DAY), now, 400))
    rot = {"last_hash": "f" * 64, "entries": 4, "oldest": now - 600 * DAY, "newest": now - 10 * DAY}
    dis = AC.disagrees(good, rot)
    ok("a note against its rotation: last link, entries, oldest, newest", all(x in dis for x in ("last link", "entries (3, recorded 4)",
                                                                                                "oldest entry", "newest entry")), dis)
    ok("…and the rotation's newest decides the age", "not yet 400 days old" in AC.judge_removal(good, now, 400, rotation=rot))
    ok("agreeing: nothing", AC.disagrees(good, dict(good)) == "")
    rr = AC.removal_record(dict(good, newest=now - DAY), 400, now=now)
    ok("a removal that was not allowed is recorded as an alert", rr["event"] == "audit_archive_deleted_early" and rr["removed"]["early"]
       and "BEFORE its retention ended" in rr["detail"])
    ok("…an allowed one as a plain removal", AC.removal_record(good, 400, now=now)["event"] == "audit_archive_removed")
    hist = AC.retention_history(['{"event": "audit_retention_set", "t": 10, "target": "30"}', 'x "audit_retention_set" y',
                                 '{"event": "audit_retention_set", "t": 20, "target": "abc"}', '{"event": "login"}'])
    ok("retention history: unreadable settings skipped", hist == [(10.0, 30)])
    ok("the setting in force at a time; before the first: the fallback", AC.setting_at(hist, 15, 400) == 30 and AC.setting_at(hist, 5, 400) == 400)
    ok("rotation entries: unreadable lines skipped", AC.rotations_in(['"audit_archived" broken', '{"event": "audit_archived", "target": "n", "archived": {"entries": 1}}'])
       == {"n": {"entries": 1}})
    ar = AC.archived_record("n.log.gz", ["not json", "also not"])
    ok("a rotation of lines that are not entries: unknown times", ar["archived"]["oldest"] is None and "unknown" in ar["detail"])
    notes = [dict(good, archive="first", removed_at=now - 900 * DAY), dict(good, archive="second", last_hash="1" * 64, oldest=now - 10 * DAY)]
    lines = [json.dumps({"t": now - 100 * DAY, "event": "login"}),
             json.dumps({"t": now, "event": "audit_archive_removed", "target": "second", "removed": {"last_hash": "1" * 64}})]
    fnd, gaps, _ = AC.removal_findings(notes, lines, 400, 30)
    ok("removal_findings: a note whose chain entry went with a later removal is skipped; no setting recorded: the note's",
       [x["archive"] for x in fnd] == ["second"] and fnd[0]["retention_recorded"] is False and fnd[0]["retention_days"] == 400, str(fnd))
    ok("…the long silence after each removed archive", gaps and gaps[0]["after"] == "first")
    ok("removals_unrecorded: the older note excused, the newest never", AC.removals_unrecorded(lines, notes, 2) == []
       and AC.removals_unrecorded(lines[:1], notes, 2) == ["second"])

    print("Old copies and archives")
    od = os.path.join(ROOT, "oldcopy")
    os.makedirs(od)
    with open(os.path.join(od, "audit.log.1"), "w") as f:
        f.write(json.dumps({"t": 5, "event": "login"}) + "\n")
    oc = AC.Chain(os.path.join(od, "audit.log"))
    ok("the single older copy of old versions becomes the first archive", len(oc.archives()) == 1 and oc.archives()[0].endswith("-old.log.gz")
       and not os.path.exists(os.path.join(od, "audit.log.1")) and oc.count == 1)
    ok("…read twice from its cache", oc.lines() == oc.lines())
    ok("a log file that cannot be read: no lines", oc._lines_of(os.path.join(od, "nothing.log")) == [])
    oc2 = AC.Chain(os.path.join(od, "audit.log"))
    ok("nothing to rotate without a log file", oc2.rotate() is None)

    # ------------------------------------------------------------------ audit_checkpoint.py
    print("Checkpoints and backup signatures (audit_checkpoint.py)")
    top = os.path.join(ROOT, "install")
    data = os.path.join(top, "data")
    os.makedirs(data)
    CK.HERE = top                                   # its command line works on <here>/data: the temporary one
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        rc = CK.main(["help"])
    ok("help", rc == 0 and "Commands:" in out.getvalue())
    err = io.StringIO()
    with contextlib.redirect_stderr(err):
        rc = CK.main(["frobnicate"])
    ok("an unknown command: 2", rc == 2 and "unknown command" in err.getvalue())
    if KG:
        with contextlib.redirect_stdout(io.StringIO()) as o:
            rc = CK.main(["key"])
        line, fp = o.getvalue().splitlines()[:2]
        ok("key: made, its public key and fingerprint printed, and recorded in the chain",
           rc == 0 and line.startswith("ssh-ed25519 ") and fp == CK.fingerprint(line)
           and any(json.loads(x)["event"] == CK.KEY_EVENT for x in lines_of(data)))
        ok("…owner-only", stat.S_IMODE(os.stat(os.path.join(data, "audit_signing", "signing_key")).st_mode) == 0o600)
        with contextlib.redirect_stdout(io.StringIO()) as o:
            rc = CK.main(["now"])
        ok("now: a signed checkpoint", rc == 0 and json.loads(o.getvalue())["signed"] is True)
        for name, digest in (("bk-1.tar.gz", "1" * 64), ("bk-2.tar.gz", "2" * 64)):
            p = os.path.join(top, name + ".sha256")
            with open(p, "w") as f:
                f.write(f"{digest}  {name}\n")
            with contextlib.redirect_stdout(io.StringIO()) as o:
                rc = CK.main(["sign-file", p, CK.BACKUP_NS])
            ok(f"sign-file {name}: its signature, the backup recorded in the chain", rc == 0 and o.getvalue().strip() == p + ".sig"
               and json.loads(lines_of(data)[-1])["target"] == name)
        for args, want in ((["bk-1.tar.gz"], "NOT THE NEWEST"), (["bk-2.tar.gz", "2" * 64], "the newest signed backup"),
                           (["bk-2.tar.gz", "9" * 64], "NOT RECORDED"), (["bk-9.tar.gz"], "NOT RECORDED")):
            with contextlib.redirect_stdout(io.StringIO()) as o:
                CK.main(["backup-age", *args])
            ok(f"backup-age {' '.join(a[:12] for a in args)}: {want}", want in o.getvalue(), o.getvalue())
        f_ = CK.backup_freshness(data, "bk-1.tar.gz")
        ok("…backup_freshness: recorded, one newer since", f_["recorded"] and not f_["is_newest"] and f_["newer"] == 1 and f_["newest"] == "bk-2.tar.gz")
        p2 = os.path.join(top, "bk-2.tar.gz.sha256")
        with contextlib.redirect_stdout(io.StringIO()) as o:
            rc = CK.main(["verify-file", p2, CK.BACKUP_NS])
        ok("verify-file with the installation's key: valid", rc == 0 and o.getvalue().strip() == "valid")
        with contextlib.redirect_stdout(io.StringIO()) as o:
            rc = CK.main(["verify-file", p2, CK.BACKUP_NS, other + ".pub"])
        ok("…with another key: INVALID", rc == 1 and o.getvalue().strip() == "INVALID")
        with contextlib.redirect_stdout(io.StringIO()) as o:
            rc = CK.main(["verify-file", p2, CK.CHECKPOINT_NS])
        ok("…under the other namespace: INVALID (a backup signature is no checkpoint)", rc == 1)
        ok("verify_file: no signature file; no key", CK.verify_file(os.path.join(top, "none"), CK.BACKUP_NS, ["k"]) == "no signature"
           and CK.verify_file(p2, CK.BACKUP_NS, ["", "  "]) == "INVALID")
        s = CK.Signer(data)
        try:
            s.sign(p2, "made-up-namespace"); refused = False
        except ValueError:
            refused = True
        ok("an unknown signing namespace is refused", refused)
        st = s.status()
        ok("status for the Audit portal", st["key"] == fp and st["count"] >= 1 and st["latest_signed"] and st["ssh_keygen"] and not st["copy_dir"])
        with open(os.path.join(s.dir, "checkpoint-99999999-999999.json"), "w") as f:
            f.write("{not json")
        ok("an unreadable newest checkpoint is passed over", s.last()[1] and s.last()[0].endswith(".json") and "99999999" not in s.last()[0])
        # a half-made key (only the public half): replaced by a new pair
        hd = os.path.join(ROOT, "half")
        os.makedirs(os.path.join(hd, "audit_signing"))
        with open(os.path.join(hd, "audit_signing", "signing_key.pub"), "w") as f:
            f.write("ssh-ed25519 AAAAhalfmade\n")
        hs = CK.Signer(hd)
        line2, _ = hs.ensure_key()
        ok("a half-made key is replaced by a new pair", line2 and "AAAAhalfmade" not in line2 and os.path.exists(hs.key))
        # the copy folder
        cdir = os.path.join(ROOT, "copies")
        os.makedirs(cdir)
        os.environ["AUDIT_CHECKPOINT_COPY_DIR"] = os.path.join(ROOT, "not-mounted")
        entry(AC.Chain(os.path.join(data, "audit.log")), user="x1")
        entry(AC.Chain(os.path.join(data, "audit.log")), user="x2")
        ck = s.make(CK._CliAudit(data))
        ok("a copy folder that is not there: said in the chain, not fatal", ck["copied"] == "the copy folder does not exist or is not mounted"
           and "copy FAILED" in json.loads(lines_of(data)[-1])["detail"])
        os.environ["AUDIT_CHECKPOINT_COPY_DIR"] = cdir
        ck = s.make(CK._CliAudit(data), force=True)
        ok("…a copy folder: checkpoint and signature copied", ck["copied"] == "the copy folder" and len(os.listdir(cdir)) == 2
           and "copied to the copy folder" in json.loads(lines_of(data)[-1])["detail"])
        cp_path = os.path.join(s.dir, ck["file"])
        ok("…never replacing a file there", CK.copy_out(cp_path, cp_path + ".sig") == "a file of that name is already in the copy folder")
        if os.geteuid() != 0:
            ro = os.path.join(ROOT, "readonly")
            os.makedirs(ro)
            os.chmod(ro, 0o500)
            os.environ["AUDIT_CHECKPOINT_COPY_DIR"] = ro
            ok("…a read-only folder: what to change", "read-only for the service" in CK.copy_out(cp_path, None))
            os.chmod(ro, 0o700)
        os.environ.pop("AUDIT_CHECKPOINT_COPY_DIR")
    ok("a fingerprint of a line that is no key: none", CK.fingerprint("onlyoneword") is None)
    # without ssh-keygen
    real_kg = CK.ssh_keygen
    CK.ssh_keygen = lambda: None
    try:
        nd = os.path.join(ROOT, "nokeygen")
        os.makedirs(nd)
        ns = CK.Signer(nd)
        ok("no ssh-keygen: no key", ns.ensure_key() == (None, None))
        ok("…sign returns nothing", ns.sign(os.path.join(nd, "f"), CK.BACKUP_NS) is None)
        ck = ns.make(CK._CliAudit(nd))
        ok("…a checkpoint is still made, NOT signed, and says so", ck and not ck["signed"]
           and "NOT signed (ssh-keygen not found)" in json.loads(lines_of(nd)[-1])["detail"])
        ok("…verify: not checked", CK.verify_file(os.path.join(nd, "audit_checkpoints", ck["file"]), CK.CHECKPOINT_NS, ["k"]) == "no signature")
        open(os.path.join(nd, "f.sig"), "w").close()
        ok("…a signature present but no ssh-keygen: not checked", CK.verify_file(os.path.join(nd, "f"), CK.BACKUP_NS, ["k"])
           == "not checked (ssh-keygen not found)")
        CK.HERE = os.path.join(ROOT, "nokg_install")
        os.makedirs(os.path.join(CK.HERE, "data"))
        with contextlib.redirect_stderr(io.StringIO()) as e:
            rk = CK.main(["key"])
            rs = CK.main(["sign-file", os.path.join(nd, "f"), CK.BACKUP_NS])
        with contextlib.redirect_stdout(io.StringIO()):
            rn = CK.main(["now"])
        ok("…the command line says so and fails", rk == 1 and rs == 1 and rn == 1 and "ssh-keygen was not found" in e.getvalue())
    finally:
        CK.ssh_keygen = real_kg

    print("The daily loop")

    class Stop(Exception):
        pass

    class FakeSigner:
        def __init__(self, last=None, fail=False):
            self._last, self.fail, self.made = last, fail, 0

        def last(self):
            if self.fail:
                raise RuntimeError("made-up failure")
            return None, self._last

        def make(self, audit):
            self.made += 1

    class Logger:
        def __init__(self):
            self.n = 0

        def exception(self, msg):
            self.n += 1
    real_sleep = CK.time.sleep
    slept = []

    def fake_sleep(sec):
        slept.append(sec)
        if sec == 3600:
            raise Stop
    CK.time.sleep = fake_sleep
    try:
        for label, sg, env, want in (("no checkpoint yet: one is made", FakeSigner(), "24", 1),
                                     ("the last one is fresh: none", FakeSigner({"made": time.time()}), "24", 0),
                                     ("the last one is a day old: one", FakeSigner({"made": time.time() - DAY}), "24", 1),
                                     ("switched off (0 hours): none", FakeSigner(), "0", 0)):
            os.environ["AUDIT_CHECKPOINT_HOURS"] = env
            try:
                CK.loop(sg, None)
            except Stop:
                pass
            ok(label, sg.made == want and slept[0] == 300)
        os.environ["AUDIT_CHECKPOINT_HOURS"] = "24"
        lg = Logger()
        try:
            CK.loop(FakeSigner(fail=True), None, lg)
        except Stop:
            pass
        ok("a failing checkpoint is logged, the loop goes on", lg.n == 1)
    finally:
        CK.time.sleep = real_sleep
        os.environ.pop("AUDIT_CHECKPOINT_HOURS", None)
    os.environ["AUDIT_CHECKPOINT_HOURS"] = "not a number"
    ok("a setting that is not a number: the default", CK._env_num("AUDIT_CHECKPOINT_HOURS", 24) == 24.0
       and AC._env_num("AUDIT_CHECKPOINT_HOURS", 7) == 7.0)
    os.environ.pop("AUDIT_CHECKPOINT_HOURS")
finally:
    shutil.rmtree(ROOT, ignore_errors=True)

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
