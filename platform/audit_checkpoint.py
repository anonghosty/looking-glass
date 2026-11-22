#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""Signed checkpoints of the audit log, and signed backup checksums (external review follow-up, 2026-11-14).

The chain (audit_chain.py) shows that no entry was changed after it was written, but someone with full access to the
server could rewrite the whole log and recompute every link. An auditor guards against that by noting the head at each
audit (verify_audit_log.py --earlier). A checkpoint does the same every day, without waiting for an audit:

  data/audit_checkpoints/checkpoint-<UTC time>.json       {"head": the hash of entry N, "entry": N, "made": time, ...}
  data/audit_checkpoints/checkpoint-<UTC time>.json.sig   its SSH signature (ssh-keygen -Y sign, namespace below)

Each one is signed with this installation's own Ed25519 key (data/audit_signing/, made on first use, owner-only),
whose public key is written into the chain itself (event audit_signing_key) when it is made. A copy is written to
AUDIT_CHECKPOINT_COPY_DIR (a folder on another computer: a mounted share, a disk) when it is set, and another computer
can fetch them instead (docs/OPERATIONS.md). The checker (audit_verifier.py) finds each checkpoint's hash at its entry
number: a checkpoint kept away from this server proves the log up to it was not rewritten later.

What it cannot do: the key is on this server, so someone who controls the server can sign new checkpoints too. The
checkpoints already copied elsewhere are what they cannot change; that is why the copy matters. The signature shows that
a copy came from this installation and was not altered on the way or where it is kept.

The same key signs the checksum of every backup (manage/backup.sh -> sign-file, namespace looking-glass-backup), and
each signed backup is recorded in the chain. The private key is left out of the backups (a restored installation makes
a new key, recorded in the chain); the public key stays in the chain and in the backups.

    python audit_checkpoint.py now                       make a checkpoint now
    python audit_checkpoint.py key                       the public key and its fingerprint (makes the key if needed)
    python audit_checkpoint.py sign-file FILE NAMESPACE  sign a file (backup.sh); prints the signature's path
    python audit_checkpoint.py verify-file FILE NAMESPACE [PUBKEY]   check a signature (verify_backup.sh)
    python audit_checkpoint.py backup-age ARCHIVE [SHA256]   is it the newest backup this installation signed?
"""
import fcntl
import glob
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
CHECKPOINT_NS = "looking-glass-audit"
BACKUP_NS = "looking-glass-backup"
NAMESPACES = (CHECKPOINT_NS, BACKUP_NS)
SIGNER = "looking-glass"
KEY_EVENT = "audit_signing_key"
CHECKPOINT_EVENT = "audit_checkpoint"


def _env_num(name, default):
    try:
        return float(os.environ.get(name, "") or default)
    except ValueError:
        return float(default)


def ssh_keygen():
    return shutil.which("ssh-keygen")


class Signer:
    """The installation's signing key and its checkpoints, next to the audit log (data/)."""

    def __init__(self, data_dir):
        self.data = data_dir
        self.key_dir = os.path.join(data_dir, "audit_signing")
        self.key = os.path.join(self.key_dir, "signing_key")
        self.pub = self.key + ".pub"
        self.dir = os.path.join(data_dir, "audit_checkpoints")

    # ------------------------------------------------------------------ the key
    def public(self):
        """(public key line, fingerprint) or (None, None) when there is no key."""
        try:
            with open(self.pub, encoding="utf-8") as f:
                line = f.read().strip()
        except OSError:
            return None, None
        return line, fingerprint(line)

    def ensure_key(self, audit=None):
        """Make the key on first use (ssh-keygen, Ed25519, no passphrase: the service signs unattended; owner-only
        files) and record its public key in the chain, so a checker knows which key signed what. Returns
        (public key line, fingerprint); (None, None) without ssh-keygen."""
        line, fp = self.public()
        if line and os.path.exists(self.key):
            return line, fp
        kg = ssh_keygen()
        if not kg:
            return None, None
        os.makedirs(self.key_dir, mode=0o700, exist_ok=True)
        lock = os.open(os.path.join(self.key_dir, ".lock"), os.O_WRONLY | os.O_CREAT, 0o600)
        try:
            fcntl.flock(lock, fcntl.LOCK_EX)
            line, fp = self.public()
            if line and os.path.exists(self.key):     # another process made it meanwhile
                return line, fp
            for p in (self.key, self.pub):            # a half-made key (one file of the two) is replaced
                if os.path.exists(p):
                    os.remove(p)
            old = os.umask(0o077)
            try:
                subprocess.run([kg, "-q", "-t", "ed25519", "-N", "", "-C", "looking-glass audit and backup signing",
                                "-f", self.key], check=True, capture_output=True, timeout=30)
            finally:
                os.umask(old)
            os.chmod(self.key, 0o600)
            line, fp = self.public()
        finally:
            os.close(lock)
        if audit is not None and line:
            audit.add(KEY_EVENT, user="Looking Glass", target=fp,
                      detail=f"new signing key for audit checkpoints and backup checksums: {line}")
        return line, fp

    # ------------------------------------------------------------------ signing a file
    def sign(self, path, namespace, audit=None):
        """path.sig, or None without ssh-keygen. Refuses a namespace it does not know."""
        if namespace not in NAMESPACES:
            raise ValueError(f"unknown signing namespace {namespace!r}")
        line, _ = self.ensure_key(audit)
        if not line:
            return None
        sig = path + ".sig"
        if os.path.exists(sig):
            os.remove(sig)
        subprocess.run([ssh_keygen(), "-q", "-Y", "sign", "-f", self.key, "-n", namespace, path],
                       check=True, capture_output=True, timeout=60)
        os.chmod(sig, 0o600)
        return sig

    # ------------------------------------------------------------------ checkpoints
    def checkpoints(self):
        return sorted(glob.glob(os.path.join(self.dir, "checkpoint-*.json")))

    def last(self):
        for p in reversed(self.checkpoints()):
            try:
                with open(p, encoding="utf-8") as f:
                    return p, json.load(f)
            except (OSError, ValueError):
                continue
        return None, None

    def make(self, audit, force=False):
        """One checkpoint of the log as it is now: written, signed, copied, and recorded in the chain. Skipped (None)
        when nothing was written since the last one but that one's own chain entry, unless force. Returns the
        checkpoint (a dict, with "file", "signed", "copied")."""
        import audit_verifier
        os.makedirs(self.dir, mode=0o700, exist_ok=True)
        lock = os.open(os.path.join(self.dir, ".lock"), os.O_WRONLY | os.O_CREAT, 0o600)
        try:
            fcntl.flock(lock, fcntl.LOCK_EX)
            chain = audit.chain
            lock_log = os.open(chain.path + ".lock", os.O_WRONLY | os.O_CREAT, 0o600)
            try:                                       # the log as one moment: under the lock every writer takes
                fcntl.flock(lock_log, fcntl.LOCK_EX)
                r = audit_verifier.check(os.path.dirname(chain.path))
            finally:
                os.close(lock_log)
            _, prev = self.last()
            if prev and not force and int(r["head_entry"]) <= int(prev.get("entry", 0)) + 1:
                return None
            line, fp = self.ensure_key(audit)
            now = time.time()
            ck = {"format": 1, "what": "Looking Glass audit log checkpoint", "head": r["head"], "entry": r["head_entry"],
                  "chain_whole": bool(r["ok"]), "made": round(now, 3),
                  "made_utc": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(now)), "key": fp or ""}
            name = f"checkpoint-{time.strftime('%Y%m%d-%H%M%S', time.gmtime(now))}.json"
            path = os.path.join(self.dir, name)
            n = 1
            while os.path.exists(path):               # never replace one (names have one-second resolution)
                n += 1
                path = os.path.join(self.dir, name.replace(".json", f"_{n:02d}.json"))
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(json.dumps(ck, sort_keys=True) + "\n")
            sig = None
            try:
                sig = self.sign(path, CHECKPOINT_NS, audit) if line else None
            except (OSError, subprocess.SubprocessError):
                sig = None
            copied = copy_out(path, sig)
        finally:
            os.close(lock)
        state = ("signed" if sig else "NOT signed (ssh-keygen not found)") + (f", copied to {copied}" if copied == "the copy folder"
                                                                              else f", copy FAILED: {copied}" if copied else "")
        audit.add(CHECKPOINT_EVENT, user="Looking Glass", target=os.path.basename(path),
                  detail=f"entry {ck['entry']}: {ck['head']} · chain {'whole' if ck['chain_whole'] else 'BROKEN'} · {state}"
                         + (f" · key {fp}" if fp else ""))
        return dict(ck, file=os.path.basename(path), signed=bool(sig), copied=copied)

    def status(self):
        """For the Audit portal: the key, how many checkpoints, the latest, and the copy folder."""
        line, fp = self.public()
        p, last = self.last()
        return {"key": fp, "public_key": line, "count": len(self.checkpoints()), "latest": last,
                "latest_signed": bool(p and os.path.exists(p + ".sig")), "every_hours": _env_num("AUDIT_CHECKPOINT_HOURS", 24),
                "copy_dir": bool(os.environ.get("AUDIT_CHECKPOINT_COPY_DIR", "").strip()), "ssh_keygen": bool(ssh_keygen())}


def copy_out(path, sig):
    """Copy a checkpoint and its signature to AUDIT_CHECKPOINT_COPY_DIR (never replacing a file there). Returns
    "" (no copy folder), "the copy folder", or why it failed (said in the chain and the bell, never fatal)."""
    dest = os.environ.get("AUDIT_CHECKPOINT_COPY_DIR", "").strip()
    if not dest:
        return ""
    if not os.path.isdir(dest):
        return "the copy folder does not exist or is not mounted"
    try:
        for p in [path] + ([sig] if sig else []):
            target = os.path.join(dest, os.path.basename(p))
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o640)
            with os.fdopen(fd, "wb") as out, open(p, "rb") as src:
                shutil.copyfileobj(src, out)
        return "the copy folder"
    except FileExistsError:
        return "a file of that name is already in the copy folder"
    except OSError as e:
        import errno
        if e.errno in (errno.EROFS, errno.EACCES, errno.EPERM):
            # the service's own sandbox (ProtectSystem=strict) lets it write only data/ unless the folder is added
            return "the copy folder is read-only for the service: add it to the service's ReadWritePaths (docs/OPERATIONS.md)"
        return f"the copy folder refused it ({type(e).__name__})"


def fingerprint(pub_line):
    """SHA256:… of an OpenSSH public key line (what ssh-keygen -l shows), without calling ssh-keygen."""
    import base64
    import hashlib
    try:
        blob = base64.b64decode(pub_line.split()[1])
    except (IndexError, ValueError):
        return None
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")


def verify_file(path, namespace, pub_lines):
    """Whether path.sig is a valid signature of path by one of these public keys: "valid", "INVALID", "no signature",
    or "not checked (ssh-keygen not found)". The same check the standalone verifier makes."""
    sig = path + ".sig"
    if not os.path.exists(sig):
        return "no signature"
    kg = ssh_keygen()
    if not kg:
        return "not checked (ssh-keygen not found)"
    keys = [ln.strip() for ln in pub_lines if ln and ln.strip()]
    if not keys:
        return "INVALID"
    with tempfile.NamedTemporaryFile("w", suffix=".allowed", delete=False) as a:
        for k in keys:
            a.write(f'{SIGNER} namespaces="{namespace}" {k}\n')
    try:
        with open(path, "rb") as data:
            r = subprocess.run([kg, "-Y", "verify", "-f", a.name, "-I", SIGNER, "-n", namespace, "-s", sig],
                               stdin=data, capture_output=True, timeout=60)
        return "valid" if r.returncode == 0 else "INVALID"
    finally:
        os.remove(a.name)


def loop(signer, audit, logger=None):
    """The service's daily checkpoint (started from app.py with the other background jobs): checked every hour,
    made when the last one is older than AUDIT_CHECKPOINT_HOURS (default 24; 0 = off). Every worker process may run it:
    the checkpoint folder's lock and the age check make it one checkpoint per period."""
    time.sleep(300)                                    # not during start-up
    while True:
        hours = _env_num("AUDIT_CHECKPOINT_HOURS", 24)
        if hours > 0:
            try:
                _, last = signer.last()
                if not last or time.time() - float(last.get("made", 0)) >= hours * 3600 - 60:
                    signer.make(audit)
            except Exception:                          # noqa: BLE001  never stop the service over a checkpoint
                if logger:
                    logger.exception("Audit checkpoint failed")
        time.sleep(3600)


def backup_freshness(data_dir, archive_name, sha256=None):
    """Is this backup the newest one this installation signed? From the audit log's "backup_signed" entries (security
    review of a40f17a: an older genuine backup still verifies, and someone who can write to the backup folder could make
    it look newest by its file date). Returns {"recorded", "at", "newest", "newest_at", "is_newest", "newer"}: newer is
    how many backups were signed after it. Not recorded: a backup from another installation, or from before signing."""
    sys.path.insert(0, HERE)
    import audit_chain
    rows = []
    for ln in audit_chain.Chain(os.path.join(data_dir, "audit.log")).lines():
        if '"backup_signed"' not in ln:
            continue
        try:
            rec = json.loads(ln)
        except ValueError:
            continue
        if rec.get("event") == "backup_signed":
            rows.append(rec)
    mine = [r for r in rows if r.get("target") == archive_name and (not sha256 or sha256 in str(r.get("detail") or ""))]
    newest = rows[-1] if rows else None
    out = {"recorded": bool(mine), "at": mine[-1].get("t") if mine else None,
           "newest": newest.get("target") if newest else None, "newest_at": newest.get("t") if newest else None}
    out["is_newest"] = bool(mine) and newest is mine[-1]
    out["newer"] = (len(rows) - 1 - rows.index(mine[-1])) if mine else None
    return out


class _CliAudit:
    """The audit log as the command line writes it: the same file, chain and entry format as the service (auth.Audit),
    without loading the web application."""

    def __init__(self, data_dir):
        sys.path.insert(0, HERE)
        import audit_chain
        self.chain = audit_chain.Chain(os.path.join(data_dir, "audit.log"))

    def add(self, event, user="", target="", detail="", ip=None, ua=None):
        self.chain.append({"t": round(time.time(), 3), "event": event, "user": user or "", "target": target or "",
                           "detail": str(detail)[:300], "ip": "", "location": "", "ua": ""})


def main(argv):
    data_dir = os.path.join(HERE, "data")
    s = Signer(data_dir)
    if not argv or argv[0] in ("-h", "--help", "help"):
        print(__doc__.split("\n    python", 1)[0].strip())
        print("\nCommands: now · key · sign-file FILE NAMESPACE · verify-file FILE NAMESPACE [PUBKEY_FILE]")
        return 0
    cmd = argv[0]
    if cmd == "key":
        line, fp = s.ensure_key(_CliAudit(data_dir))
        if not line:
            print("ssh-keygen was not found: install openssh-client.", file=sys.stderr)
            return 1
        print(line)
        print(fp)
        return 0
    if cmd == "now":
        ck = s.make(_CliAudit(data_dir), force=True)
        print(json.dumps(ck, indent=2))
        return 0 if ck and ck.get("signed") else 1
    if cmd == "sign-file" and len(argv) == 3:
        a = _CliAudit(data_dir)
        sig = s.sign(argv[1], argv[2], a)
        if not sig:
            print("ssh-keygen was not found: the file is NOT signed.", file=sys.stderr)
            return 1
        _, fp = s.public()
        if argv[2] == BACKUP_NS:                       # every signed backup is in the chain: what, its checksum, the key
            with open(argv[1], encoding="utf-8") as f:
                sums = f.read().split()
            a.add("backup_signed", user="Looking Glass", target=os.path.basename(argv[1])[:-len(".sha256")] if argv[1].endswith(".sha256") else os.path.basename(argv[1]),
                  detail=f"backup checksum SHA-256 {sums[0] if sums else '?'} signed · key {fp}")
        print(sig)
        return 0
    if cmd == "backup-age" and len(argv) in (2, 3):
        f = backup_freshness(data_dir, os.path.basename(argv[1]), argv[2] if len(argv) == 3 else None)
        when = lambda t: time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(t)) if t else "?"
        if not f["recorded"]:
            print("NOT RECORDED: this installation's audit log has no signed backup of this name and checksum "
                  "(another installation's backup, or one made before backups were signed)")
        elif f["is_newest"]:
            print(f"the newest signed backup (signed {when(f['at'])})")
        else:
            print(f"NOT THE NEWEST: signed {when(f['at'])}; {f['newer']} newer backup(s) signed since, the latest "
                  f"{f['newest']} ({when(f['newest_at'])}). Restoring it brings back an older state.")
        return 0
    if cmd == "verify-file" and len(argv) in (3, 4):
        if len(argv) == 4:
            with open(argv[3], encoding="utf-8") as f:
                keys = f.read().splitlines()
        else:
            keys = [s.public()[0] or ""]
        state = verify_file(argv[1], argv[2], keys)
        print(state)
        return 0 if state == "valid" else 1
    print(f"unknown command: {' '.join(argv)} (help: python audit_checkpoint.py help)", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
