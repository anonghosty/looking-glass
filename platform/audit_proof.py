"""Proof the auditor takes away (2026-11-11): the audit log's proof package and the continuity check.

The Integrity card's "chain whole" is Looking Glass checking itself. An auditor needs to check it without trusting
Looking Glass, and to carry the proof away. So:

- GET /api/audit/proof.zip: the proof package. The log's files exactly as stored (audit.log, the archives, the
  retention notes, audit.head, audit.seal), copied at one moment under the log's own lock; MANIFEST.json with the
  SHA-256 of every file; verify_audit_log.py (audit_verifier.py: Python standard library only) that recomputes the
  whole chain on the auditor's computer; and README.txt. The package's own SHA-256 and the head it holds are written
  into the audit log, so every later package carries the receipt of this one.
- GET /api/audit/continuity?earlier=HASH@ENTRY: the head hash and entry number noted at an earlier audit must still be
  at that entry. Each entry's hash depends on every entry before it, so this proves the log up to the earlier audit is
  unchanged, even against someone who could rewrite the whole file. The verifier does the same offline (--earlier).

Both only read (GET), need the 'audit' permission, and are logged (audit_export / audit_verified).
"""
import hashlib
import io
import json
import os
import shutil
import tempfile
import time
import zipfile

import audit_verifier

HERE = os.path.dirname(os.path.abspath(__file__))

README = """Looking Glass: audit log proof package
=====================================

Made {generated} by {by}. Head of the log in this package: entry {head_entry}
  {head}

What is in it
  log/                  the audit log's files exactly as Looking Glass stores them (one moment, under the log's lock)
  audit_log.csv         every entry in log/ ({csv_rows} rows, oldest first, archives included) as a spreadsheet to
                        work with: one row per entry, numbered as in the chain (the last row is the head,
                        entry {head_entry}), readable names and the detail as logged. It is made from log/ above, and MANIFEST.json holds its SHA-256, so the verifier also
                        tells you if it was changed. The proof is log/; the CSV is the readable copy of it.
  MANIFEST.json        the SHA-256 of every file in this package when it was made
  verify_audit_log.py   an independent verifier: Python 3.8 or newer, standard library only. Read it: it is short.
  README.txt            this file

First, check the verifier itself: it came from the server it checks.
  Its SHA-256: {verifier_sha}
  Compare with the one published in "How the audit log proves itself" (docs/AUDIT_LOG_PROOF.md) at
  https://github.com/anonghosty/looking-glass , or use platform/audit_verifier.py from there instead.

Check it on your own computer (no Looking Glass, no network needed)
  python verify_audit_log.py
  It recomputes every link of the chain, the seal of the entries written before the chain started, and the head,
  and checks every file against MANIFEST.json. It ends with "RESULT: verified" or "RESULT: NOT verified".

Keep for your working papers
  1. The SHA-256 of this ZIP file (shown in the portal after the download; recorded in the audit log too).
  2. The head above: entry {head_entry} and its hash.

At the next audit
  Take a new proof package and run
    python verify_audit_log.py --earlier {head}@{head_entry}
  Each entry's hash depends on every entry before it. If this hash is still entry {head_entry}, every entry up to it is
  exactly the one in this package: nothing was changed, inserted or removed in between, even by someone able to
  rewrite the whole log on the server. The Audit portal does the same check (Integrity and evidence).

What it does not prove
  That the log was complete when written: entries are made by the application. The entries written before the chain
  started are covered from their seal on, not before it. A log rewritten before your first package cannot be told
  apart; from your first package on, it can.

How and why this works, step by step: "How the audit log proves itself" (docs/AUDIT_LOG_PROOF.md) at
  https://github.com/anonghosty/looking-glass

The log holds names, addresses and browser details of the people who used Looking Glass: keep the package confidential.
"""


def verifier_sha256():
    """SHA-256 of the verifier this server hands out (printed in the evidence report and the package, to compare with
    the one published on GitHub)."""
    return hashlib.sha256(open(os.path.join(HERE, "audit_verifier.py"), "rb").read()).hexdigest()


def snapshot(chain, dest):
    """Copy the log's files into dest/ at one moment: under the same lock every writer takes."""
    import fcntl
    src = os.path.dirname(chain.path)
    lock_fd = os.open(chain.path + ".lock", os.O_WRONLY | os.O_CREAT, 0o600)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        os.makedirs(os.path.join(dest, "audit_archive"))
        for name in ("audit.log", "audit.head", "audit.seal"):
            p = os.path.join(src, name)
            if os.path.exists(p):
                shutil.copyfile(p, os.path.join(dest, name))
        for p in chain.archives() + [os.path.join(chain.dir, "removed.jsonl"), os.path.join(chain.dir, "removed.recorded")]:
            if os.path.exists(p):
                shutil.copyfile(p, os.path.join(dest, "audit_archive", os.path.basename(p)))
    finally:
        os.close(lock_fd)


def snapshot_records(log):
    """Every entry in the snapshot, oldest first: the archives (by name, as the verifier reads them), then audit.log.
    Returns (records, lines that are not an entry)."""
    out, skipped = [], 0
    arch = os.path.join(log, "audit_archive")
    paths = sorted(os.path.join(arch, n) for n in os.listdir(arch) if n.startswith("audit-") and n.endswith(".log.gz")) \
        if os.path.isdir(arch) else []
    for p in paths + [os.path.join(log, "audit.log")]:
        for ln in audit_verifier._lines(p):
            try:
                rec = json.loads(ln)
            except ValueError:
                rec = None
            if isinstance(rec, dict):
                out.append(rec)
            else:
                skipped += 1
    return out, skipped


def build(chain, generated_by, to_csv=None):
    """The proof package (bytes) and what it holds. to_csv(records) -> bytes: the readable CSV of the snapshot's
    entries (audit_log.csv), made from the same copy as log/ so the two always match."""
    with tempfile.TemporaryDirectory(prefix="lg-proof-") as tmp:
        log = os.path.join(tmp, "log")
        snapshot(chain, log)
        r = audit_verifier.check(log)                 # the same code the auditor runs
        generated = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
        csv_rows = csv_skipped = 0
        if to_csv:
            recs, csv_skipped = snapshot_records(log)
            # the chain numbers entries from its very first one; entries removed by the retention are not in log/, so
            # the first row is entry head_entry - (entries kept) + 1, and the last one is the head
            first = max(1, int(r.get("head_entry") or len(recs)) - len(recs) + 1)
            with open(os.path.join(tmp, "audit_log.csv"), "wb") as f:
                f.write(to_csv(recs, first))
            csv_rows = len(recs)
        files = []
        for base, _, names in os.walk(log):
            for n in sorted(names):
                p = os.path.join(base, n)
                rel = "log/" + os.path.relpath(p, log).replace(os.sep, "/")
                files.append({"path": rel, "bytes": os.path.getsize(p), "sha256": audit_verifier.file_sha(p)})
        if to_csv:
            p = os.path.join(tmp, "audit_log.csv")
            files.append({"path": "audit_log.csv", "bytes": os.path.getsize(p), "sha256": audit_verifier.file_sha(p)})
        verifier = open(os.path.join(HERE, "audit_verifier.py"), "rb").read()
        files.append({"path": "verify_audit_log.py", "bytes": len(verifier), "sha256": hashlib.sha256(verifier).hexdigest()})
        files.sort(key=lambda f: f["path"])
        manifest = {"what": "Looking Glass audit log proof package", "generated": generated, "generated_by": generated_by,
                    "head": r["head"], "head_entry": r["head_entry"], "entries_kept": r["kept"],
                    "removed_by_retention": r["removed_by_retention"], "chain_whole_when_made": r["ok"], "files": files}
        if to_csv:
            manifest["csv"] = {"path": "audit_log.csv", "rows": csv_rows, "lines_not_entries": csv_skipped,
                               "made_from": "the log/ files in this package (same moment)"}
        readme = README.format(generated=generated, by=generated_by, head=r["head"], head_entry=r["head_entry"],
                               verifier_sha=hashlib.sha256(verifier).hexdigest(), csv_rows=csv_rows)
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            for f in files:
                if f["path"] == "verify_audit_log.py":
                    z.writestr("verify_audit_log.py", verifier)
                else:                                  # log/… and audit_log.csv
                    z.write(os.path.join(tmp, *f["path"].split("/")), f["path"])
            z.writestr("MANIFEST.json", json.dumps(manifest, indent=2))
            z.writestr("README.txt", readme)
        data = buf.getvalue()
    return data, {"head": r["head"], "head_entry": r["head_entry"], "ok": r["ok"], "sha256": hashlib.sha256(data).hexdigest(),
                  "files": len(files), "generated": generated}


def install(app, audit, allowed, deny, who, to_csv=None):
    """Register the two routes. who() = (account name, readable name) of the person asking; to_csv: see build()."""
    from flask import Response, jsonify, request

    @app.route("/api/audit/proof.zip")
    def api_audit_proof():
        if not allowed():
            return deny()
        user, label = who()
        data, info = build(audit.chain, label or user, to_csv)
        audit.add("audit_export", user=user, target="proof",
                  detail=f"proof package · head entry {info['head_entry']} {info['head']} · {info['files']} files · "
                         f"package SHA-256 {info['sha256']}" + ("" if info["ok"] else " · chain BROKEN"))
        stamp = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
        return Response(data, mimetype="application/zip", headers={
            "Content-Disposition": f'attachment; filename="audit_proof_{stamp}.zip"', "Cache-Control": "no-store",
            "X-Audit-Head": f"{info['head']}@{info['head_entry']}"})

    @app.route("/api/audit/continuity")
    def api_audit_continuity():
        if not allowed():
            return deny()
        try:
            earlier = audit_verifier.parse_earlier(request.args.get("earlier", ""))
        except ValueError as e:
            return jsonify(error=f"The earlier head: {e}."), 400
        r = audit_verifier.check(os.path.dirname(audit.chain.path), earlier)
        e = r["earlier"]
        user, _ = who()
        audit.add("audit_verified", user=user, target="continuity",
                  detail=f"earlier head {e['hash']}" + (f"@{e['entry_given']}" if e["entry_given"] else "")
                         + (f" · found at entry {e['entry']}" if e["found"] else " · NOT FOUND") + (" · proven" if e["proven"] else ""))
        return jsonify(earlier=dict(e, when=audit_verifier.when(e.get("t"))), chain_ok=r["ok"], head=r["head"], head_entry=r["head_entry"],
                       brk=r["break"])
