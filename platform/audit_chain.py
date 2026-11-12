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
data/audit_archive/removed.jsonl, so the chain still checks out after the oldest entries are gone. Each removal is
also recorded as an entry in the chain itself (event audit_archive_removed, with the archive's last link), so it
cannot be hidden or changed afterwards; verify() reports a note without its chain entry. Before this, the log kept
one older copy and deleted the rest.

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


REMOVAL_EVENTS = ("audit_archive_removed", "audit_archive_deleted_early")


def _utc(t):
    return time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(t)) if t else "unknown"


def removed_early(note):
    """True when a note says an archive was removed before its retention ended: its newest entry is not older than the
    retention at the time it was removed. prune() never does that, so such a note means an archive was deleted by
    hand or by someone hiding entries (external review, 2026-11-12: an archive seconds old, deleted with a hand-written
    note, used to pass as a normal removal)."""
    try:
        return float(note.get("newest") or 0) > float(note.get("removed_at") or 0) - float(note.get("retention_days") or 0) * 86400 + 1
    except (TypeError, ValueError):
        return True


def removal_record(note):
    """The chain entry for an archive the retention removed (its note in removed.jsonl): which archive, how many
    entries, its last link and newest time. Recorded in the chain itself, so the removal cannot be hidden or changed
    later; the notes file alone could be. A removal before the retention ended is recorded as an alert instead."""
    early = removed_early(note)
    head = (f"removed BEFORE its retention ended: its newest entry ({_utc(note.get('newest'))}) was not yet "
            f"{note.get('retention_days')} days old when it was removed ({_utc(note.get('removed_at'))})" if early else
            f"removed by the retention of {note.get('retention_days')} days")
    return {"t": round(time.time(), 3), "event": REMOVAL_EVENTS[1 if early else 0], "user": "Looking Glass",
            "target": note.get("archive", ""),
            "detail": f"{note.get('entries')} entries up to {_utc(note.get('newest'))} {head} · last link {note.get('last_hash')}",
            "removed": {"entries": note.get("entries"), "last_hash": note.get("last_hash"), "oldest": note.get("oldest"),
                        "newest": note.get("newest"), "removed_at": note.get("removed_at"),
                        "retention_days": note.get("retention_days"), "early": early},
            "ip": "", "location": "", "ua": ""}


def removal_findings(notes, first_kept_t, gap_days):
    """What the retention notes say that needs an auditor's attention.
    early: archives removed before their retention ended (removed_early).
    gaps:  a jump in time around a removed archive that real use does not leave: between one removed archive's newest
           entry and the next one's oldest, or the first entry still kept. A note's dates are written next to the log
           and could be faked to look old; the first kept entry's time is inside the chain and cannot. Normal use
           writes something at least every few days, so more than gap_days (AUDIT_GAP_DAYS, default 30) is flagged."""
    early = [n.get("archive") for n in notes if removed_early(n)]
    gaps = []
    for i, n in enumerate(notes):
        nxt = notes[i + 1].get("oldest") if i + 1 < len(notes) else first_kept_t
        if n.get("newest") and nxt and float(nxt) - float(n["newest"]) > gap_days * 86400:
            gaps.append({"after": n.get("archive"), "from": n["newest"], "to": nxt, "days": int((float(nxt) - float(n["newest"])) // 86400)})
    return early, gaps


def removals_unrecorded(lines, notes, recorded):
    """Retention notes the chain does not account for. `recorded`: how many notes the chain says it has recorded (the
    rest are recorded with the next entry). A recorded note needs its entry in the lines kept, unless that entry may
    itself be gone by the retention (the note is older than the oldest entry kept)."""
    seen, oldest = {}, None
    for ln in lines:
        if '"audit_archive_' not in ln and oldest is not None:
            continue
        try:
            rec = json.loads(ln)
        except ValueError:
            continue
        if oldest is None:
            oldest = rec.get("t")
        if rec.get("event") in REMOVAL_EVENTS:
            seen[rec.get("target")] = (rec.get("removed") or {}).get("last_hash")
    bad = []
    for n in notes[:recorded]:
        if seen.get(n.get("archive")) == n.get("last_hash"):
            continue
        if oldest is not None and (n.get("removed_at") or 0) < oldest:
            continue                          # its entry was in an archive the retention removed later
        bad.append(n.get("archive"))
    return bad


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
                self._gzip(old, dst, counter=False)
        except OSError:                       # another process adopted it at the same moment
            pass

    def _gzip(self, src, dst, counter=True):
        """Compress src into a new archive and remove src. An archive is never replaced: names have one-second
        resolution, so two rotations in the same second (external review, 2026-11-12) used to overwrite the first
        one and lose its entries. A taken name gets a counter (audit-<time>_02.log.gz: '_' sorts after '.', so the
        archives stay in order). Returns the archive's path."""
        base, n = dst[:-len(".log.gz")], 1
        while True:
            try:
                fd = os.open(dst, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                break
            except FileExistsError:
                if not counter:               # adopting audit.log.1: someone else did it already
                    raise
                n += 1
                dst = f"{base}_{n:02d}.log.gz"
        with open(src, "rb") as fi, os.fdopen(fd, "wb") as raw, gzip.GzipFile(fileobj=raw, mode="wb") as fo:
            fo.write(fi.read())
        os.remove(src)
        return dst

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
        """Add one record (a dict) as a chained line, under a lock shared by every process; returns the line.
        Archives the retention removed since the last write are recorded first, each as its own chained entry."""
        import fcntl
        lock_fd = os.open(self.path + ".lock", os.O_WRONLY | os.O_CREAT, 0o600)
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            if os.path.exists(self.path) and os.path.getsize(self.path) > self.rotate_bytes:
                self.rotate()
            notes = self.removed()
            done = self._recorded_count()
            if len(notes) > done:             # archives removed by the retention since the last write
                for note in notes[done:]:
                    self._write(removal_record(note))
                self._set_recorded_count(len(notes))
            return self._write(rec)
        finally:
            os.close(lock_fd)                 # releases the lock

    def _write(self, rec):
        """One chained line (the caller holds the lock)."""
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

    # how many retention notes (removed.jsonl, append-only) are already recorded in the chain: only to know which are
    # new. The check does not trust it: verify() looks for a chain entry for every note.
    def _recorded_count(self):
        try:
            with open(os.path.join(self.dir, "removed.recorded")) as f:
                return int(f.read().strip() or 0)
        except (OSError, ValueError):
            return 0

    def _set_recorded_count(self, n):
        os.makedirs(self.dir, mode=0o700, exist_ok=True)
        tmp = os.path.join(self.dir, "removed.recorded.tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(str(n))
        os.replace(tmp, os.path.join(self.dir, "removed.recorded"))

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
                try:
                    oldest = json.loads(lines[0]).get("t") if lines else None
                except ValueError:
                    oldest = None
                note = {"archive": os.path.basename(p), "entries": len(lines), "last_hash": sha(lines[-1]) if lines else ZERO,
                        "oldest": oldest, "newest": newest, "removed_at": round(now, 3), "retention_days": self.retention_days}
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
        # every archive the retention removed is recorded in the chain itself (removal_record), not only in the notes file
        recorded = min(self._recorded_count(), len(removed))
        missing = removals_unrecorded(lines, removed, recorded)
        if missing and not brk:
            brk = {"entry": 1, "t": first_t, "what": f"retention notes with no entry in the chain ({', '.join(missing[:3])}): "
                                                    "an archive was removed or noted outside Looking Glass"}
        early, gaps = removal_findings(removed, first_t, int(_env_num("AUDIT_GAP_DAYS", 30)))
        if early and not brk:
            brk = {"entry": 1, "t": first_t, "what": f"archives removed before their retention ended ({', '.join(early[:3])}): "
                                                    "entries were deleted outside the retention"}
        return {"ok": brk is None, "seal": dict(seal, state=seal_state) if seal else None,
                "removals_recorded": recorded - len(missing), "removals_pending": len(removed) - recorded,
                "removals": [{"archive": n.get("archive"), "entries": n.get("entries"), "oldest": n.get("oldest"),
                              "newest": n.get("newest"), "removed_at": n.get("removed_at"),
                              "retention_days": n.get("retention_days"), "early": removed_early(n)} for n in removed],
                "removal_gaps": gaps, "entries": len(lines), "chained": chained, "before_chain": before, "first": first_t, "last": last_t,
                "break": brk, "head": head, "head_entry": len(lines) + gone, "removed_entries": gone,
                "head_file": bool(saved), "archives": len(self.archives()),
                "removed_archives": len(removed), "retention_days": self.retention_days,
                "rotate_mb": round(self.rotate_bytes / 1_000_000, 1)}
