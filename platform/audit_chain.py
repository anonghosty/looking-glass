"""The audit log as evidence (2026-11-11): tamper-evident, and kept for a set time instead of thrown away.

Tamper evidence. Every new entry carries "prev": the SHA-256 of the line before it, so the lines form a chain. Changing,
inserting or removing a line anywhere breaks the chain from that point; verify() walks every line kept and says
whether the chain is whole, and where it breaks if not. The newest link (the "head": its hash and the number of
entries) is also written to data/audit.head. An auditor notes the head at the end of an audit (it is printed in the
evidence report); comparing it next time shows that nothing was cut from the end in between either. Entries written
before the chain started (older versions) are counted, shown as "before the chain started", and not judged.

Retention. When data/audit.log reaches AUDIT_ROTATE_MB (default 5) it is compressed into data/audit_archive/
(audit-<time>.log.gz, owner-only) and a new file goes on with the same chain. Archives older than AUDIT_RETENTION_DAYS
(default 400: a yearly audit and some margin) are deleted, and the last hash of each deleted archive is noted in
data/audit_archive/removed.jsonl, so the chain still checks out after the oldest entries are gone. Before this, the
log kept one older copy and deleted the rest.

Every value is in .env, so each CSIRT sets the retention its own audits and laws require.
"""
import glob
import gzip
import hashlib
import json
import os
import time

ZERO = "0" * 64


def sha(line):
    return hashlib.sha256(line.encode("utf-8")).hexdigest()


def _env_num(name, default):
    try:
        return float(os.environ.get(name, "") or default)
    except ValueError:
        return float(default)


class Chain:
    """The audit log's files and their hash chain. Not thread-safe on its own: auth.Audit calls it under its lock."""

    def __init__(self, path):
        self.path = path
        self.dir = os.path.join(os.path.dirname(path), "audit_archive")
        self.head_path = os.path.join(os.path.dirname(path), "audit.head")
        self.retention_days = int(_env_num("AUDIT_RETENTION_DAYS", 400))
        self.rotate_bytes = int(_env_num("AUDIT_ROTATE_MB", 5) * 1_000_000)
        self._cache = {}                      # archive name -> (mtime, lines)
        self._adopt_old_copy()
        self.last, self.count = self._load_head()

    # ------------------------------------------------------------------ files
    def archives(self):
        return sorted(glob.glob(os.path.join(self.dir, "audit-*.log.gz")))

    def _lines_of(self, p):
        if p.endswith(".gz"):
            m = os.path.getmtime(p)
            c = self._cache.get(p)
            if c and c[0] == m:
                return c[1]
            with gzip.open(p, "rt", encoding="utf-8") as f:
                lines = [ln.rstrip("\n") for ln in f if ln.strip()]
            self._cache[p] = (m, lines)
            return lines
        try:
            with open(p, encoding="utf-8") as f:
                return [ln.rstrip("\n") for ln in f if ln.strip()]
        except OSError:
            return []

    def lines(self):
        """Every line kept, oldest first: the archives, then the current file."""
        out = []
        for p in self.archives():
            try:
                out.extend(self._lines_of(p))
            except (OSError, EOFError):
                pass
        out.extend(self._lines_of(self.path))
        return out

    def _adopt_old_copy(self):
        """The single older copy older versions kept (audit.log.1) becomes the first archive, so nothing is lost."""
        old = self.path + ".1"
        if not os.path.exists(old):
            return
        try:
            os.makedirs(self.dir, mode=0o700, exist_ok=True)
            dst = os.path.join(self.dir, f"audit-{time.strftime('%Y%m%d-%H%M%S', time.gmtime(os.path.getmtime(old)))}-old.log.gz")
            if not os.path.exists(dst):
                self._gzip(old, dst)
        except OSError:                       # another process adopted it at the same moment
            pass

    def _gzip(self, src, dst):
        fd = os.open(dst, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with open(src, "rb") as fi, os.fdopen(fd, "wb") as raw, gzip.GzipFile(fileobj=raw, mode="wb") as fo:
            fo.write(fi.read())
        os.remove(src)

    def _load_head(self):
        """The newest link: the hash of the last line kept and how many lines there are."""
        lines = self.lines()
        return (sha(lines[-1]) if lines else ZERO), len(lines)

    # ------------------------------------------------------------------ writing
    def _tail(self):
        """The last line actually in the log (the current file, else the newest archive): more than one process writes
        it (the service, the in-process checks, manage/ scripts), so the link is always taken from the file itself."""
        try:
            with open(self.path, "rb") as f:
                f.seek(0, 2)
                size = f.tell()
                f.seek(max(0, size - 262144))
                tail = [ln for ln in f.read().decode("utf-8", "replace").split("\n") if ln.strip()]
            if tail:
                return tail[-1]
        except OSError:
            pass
        arch = self.archives()
        if arch:
            lines = self._lines_of(arch[-1])
            return lines[-1] if lines else None
        return None

    def append(self, rec):
        """Add one record (a dict) as a chained line, under a lock shared by every process; returns the line."""
        import fcntl
        lock_fd = os.open(self.path + ".lock", os.O_WRONLY | os.O_CREAT, 0o600)
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            if os.path.exists(self.path) and os.path.getsize(self.path) > self.rotate_bytes:
                self.rotate()
            last = self._tail()
            rec = dict(rec, prev=sha(last) if last else (self.removed()[-1]["last_hash"] if self.removed() else ZERO))
            line = json.dumps(rec, ensure_ascii=False)
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            with os.fdopen(fd, "a", encoding="utf-8") as f:
                f.write(line + "\n")
            try:
                with open(self.head_path) as f:
                    count = int(json.load(f).get("entries", 0)) + 1
            except (OSError, ValueError):
                count = len(self.lines())
            self.last, self.count = sha(line), count
            self._write_head()
            return line
        finally:
            os.close(lock_fd)                 # releases the lock

    def _write_head(self):
        tmp = self.head_path + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump({"head": self.last, "entries": self.count, "at": round(time.time(), 3)}, f)
        os.replace(tmp, self.head_path)

    def rotate(self):
        """Compress the current file into the archive (the chain goes on in the new file), then apply the retention."""
        if not os.path.exists(self.path):
            return
        os.makedirs(self.dir, mode=0o700, exist_ok=True)
        self._gzip(self.path, os.path.join(self.dir, f"audit-{time.strftime('%Y%m%d-%H%M%S', time.gmtime())}.log.gz"))
        self.prune()

    def prune(self, now=None):
        """Delete archives whose newest entry is older than the retention; note each one's last hash first."""
        now = now or time.time()
        cut = now - self.retention_days * 86400
        for p in self.archives():
            lines = self._lines_of(p)
            try:
                newest = json.loads(lines[-1]).get("t", 0) if lines else 0
            except ValueError:
                newest = 0
            if newest and newest < cut:
                note = {"archive": os.path.basename(p), "entries": len(lines), "last_hash": sha(lines[-1]) if lines else ZERO,
                        "newest": newest, "removed_at": round(now, 3), "retention_days": self.retention_days}
                fd = os.open(os.path.join(self.dir, "removed.jsonl"), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
                with os.fdopen(fd, "a", encoding="utf-8") as f:
                    f.write(json.dumps(note) + "\n")
                os.remove(p)
                self._cache.pop(p, None)

    def removed(self):
        try:
            with open(os.path.join(self.dir, "removed.jsonl"), encoding="utf-8") as f:
                return [json.loads(ln) for ln in f if ln.strip()]
        except (OSError, ValueError):
            return []

    # ------------------------------------------------------------------ the seal of entries written before the chain
    @property
    def seal_path(self):
        return os.path.join(os.path.dirname(self.path), "audit.seal")

    @staticmethod
    def _pre_chain(lines):
        """The entries written before the chain started (older versions wrote no link): every line before the first
        chained one."""
        for i, ln in enumerate(lines):
            if '"prev"' in ln:
                try:
                    if "prev" in json.loads(ln):
                        return lines[:i]
                except ValueError:
                    pass
        return []

    def seal(self):
        """Seal the entries written before the chain started, once: their SHA-256, count and time span go to
        data/audit.seal. Returns the new seal (the caller records it in the chain, so the seal itself is protected),
        or None when there is nothing to seal or it is sealed already. From then on, changing any of them is detected;
        nothing can prove they were unchanged before the seal, and the evidence says so."""
        import fcntl
        lock_fd = os.open(self.path + ".lock", os.O_WRONLY | os.O_CREAT, 0o600)
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            if os.path.exists(self.seal_path):
                return None
            pre = self._pre_chain(self.lines())
            if not pre:
                return None
            ts = []
            for ln in (pre[0], pre[-1]):
                try:
                    ts.append(json.loads(ln).get("t"))
                except ValueError:
                    ts.append(None)
            s = {"entries": len(pre), "sha256": sha("\n".join(pre)), "first": ts[0], "last": ts[1], "sealed_at": round(time.time(), 3)}
            fd = os.open(self.seal_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as f:
                json.dump(s, f)
            return s
        finally:
            os.close(lock_fd)

    def read_seal(self):
        try:
            with open(self.seal_path) as f:
                return json.load(f)
        except (OSError, ValueError):
            return None

    # ------------------------------------------------------------------ checking
    def verify(self):
        """Walk every line kept. Returns a dict: ok, entries, chained, before_chain, first/last time, break (where the
        chain breaks: entry number, time, what), head (the newest hash, and whether it matches data/audit.head)."""
        lines, removed = self.lines(), self.removed()
        prev_line_hash = removed[-1]["last_hash"] if removed else None     # the oldest archives were removed by retention
        before = chained = 0
        first_t = last_t = None
        brk = None
        started = False
        for i, ln in enumerate(lines):
            try:
                rec = json.loads(ln)
            except ValueError:
                brk = brk or {"entry": i + 1, "what": "a line that is not a valid entry"}
                prev_line_hash = sha(ln)
                continue
            t = rec.get("t")
            first_t = first_t if first_t is not None else t
            last_t = t if t is not None else last_t
            if "prev" not in rec:
                if started and not brk:                 # once chained, every later entry must be too
                    brk = {"entry": i + 1, "t": t, "what": "an entry without its link (written outside Looking Glass)"}
                before += 1
            else:
                started = True
                expected = prev_line_hash if prev_line_hash is not None else ZERO
                if rec["prev"] != expected and not brk:
                    brk = {"entry": i + 1, "t": t, "what": "the entry before this one was changed, inserted or removed"}
                chained += 1
            prev_line_hash = sha(ln)
        head = sha(lines[-1]) if lines else ZERO
        try:
            with open(self.head_path) as f:
                saved = json.load(f)
        except (OSError, ValueError):
            saved = {}
        gone = sum(int(r.get("entries") or 0) for r in removed)     # archives the retention removed still count
        head_ok = (not saved) or (saved.get("head") == head and saved.get("entries") == len(lines) + gone)
        if saved and not head_ok and not brk:
            brk = {"entry": len(lines), "t": last_t, "what": "the newest entries do not match data/audit.head (entries removed from the end?)"}
        # the entries before the chain: unchanged since they were sealed? (retention may since have removed the oldest)
        seal, seal_state = self.read_seal(), "none"
        if seal:
            pre = self._pre_chain(lines)
            if len(pre) == seal["entries"] and sha("\n".join(pre)) == seal["sha256"]:
                seal_state = "intact"
            elif removed and len(pre) < seal["entries"]:
                seal_state = "partly removed by the retention"
            else:
                seal_state = "changed"
                brk = brk or {"entry": 1, "t": seal.get("first"), "what": "entries written before the chain were changed after they were sealed"}
        return {"ok": brk is None, "seal": dict(seal, state=seal_state) if seal else None, "entries": len(lines), "chained": chained, "before_chain": before, "first": first_t, "last": last_t,
                "break": brk, "head": head, "head_file": bool(saved), "archives": len(self.archives()),
                "removed_archives": len(removed), "retention_days": self.retention_days,
                "rotate_mb": round(self.rotate_bytes / 1_000_000, 1)}
