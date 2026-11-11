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
  MANIFEST.json         the SHA-256 of every file in this package when it was made
  verify_audit_log.py   an independent verifier: Python 3.8 or newer, standard library only. Read it: it is short.
  README.txt            this file

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

The log holds names, addresses and browser details of the people who used Looking Glass: keep the package confidential.
"""


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
        for p in chain.archives() + [os.path.join(chain.dir, "removed.jsonl")]:
            if os.path.exists(p):
                shutil.copyfile(p, os.path.join(dest, "audit_archive", os.path.basename(p)))
    finally:
        os.close(lock_fd)


def build(chain, generated_by):
    """The proof package (bytes) and what it holds."""
    with tempfile.TemporaryDirectory(prefix="lg-proof-") as tmp:
        log = os.path.join(tmp, "log")
        snapshot(chain, log)
        r = audit_verifier.check(log)                 # the same code the auditor runs
        generated = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
        files = []
        for base, _, names in os.walk(log):
            for n in sorted(names):
                p = os.path.join(base, n)
                rel = "log/" + os.path.relpath(p, log).replace(os.sep, "/")
                files.append({"path": rel, "bytes": os.path.getsize(p), "sha256": audit_verifier.file_sha(p)})
        verifier = open(os.path.join(HERE, "audit_verifier.py"), "rb").read()
        files.append({"path": "verify_audit_log.py", "bytes": len(verifier), "sha256": hashlib.sha256(verifier).hexdigest()})
        files.sort(key=lambda f: f["path"])
        manifest = {"what": "Looking Glass audit log proof package", "generated": generated, "generated_by": generated_by,
                    "head": r["head"], "head_entry": r["head_entry"], "entries_kept": r["kept"],
                    "removed_by_retention": r["removed_by_retention"], "chain_whole_when_made": r["ok"], "files": files}
        readme = README.format(generated=generated, by=generated_by, head=r["head"], head_entry=r["head_entry"])
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            for f in files:
                if f["path"] == "verify_audit_log.py":
                    z.writestr("verify_audit_log.py", verifier)
                else:
                    z.write(os.path.join(tmp, *f["path"].split("/")), f["path"])
            z.writestr("MANIFEST.json", json.dumps(manifest, indent=2))
            z.writestr("README.txt", readme)
        data = buf.getvalue()
    return data, {"head": r["head"], "head_entry": r["head_entry"], "ok": r["ok"], "sha256": hashlib.sha256(data).hexdigest(),
                  "files": len(files), "generated": generated}


def install(app, audit, allowed, deny, who):
    """Register the two routes. who() = (account name, readable name) of the person asking."""
    from flask import Response, jsonify, request

    @app.route("/api/audit/proof.zip")
    def api_audit_proof():
        if not allowed():
            return deny()
        user, label = who()
        data, info = build(audit.chain, label or user)
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
