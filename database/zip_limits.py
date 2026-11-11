"""Limits for unpacking the report zips, so a zip bomb (a few kilobytes that unpack to gigabytes) or a zip with
thousands of files cannot fill the disk or stall the pipeline.

The sizes a zip states about itself can be forged, so the real bytes are counted while unpacking and unpacking stops
the moment a limit is passed. A refused zip is moved to <DATA_DIR>/quarantine/ with a note of the reason (not deleted,
so an analyst can look at it, and not retried on every run).

The defaults are generous on purpose: Looking Glass is used by CSIRTs of large countries, where one report can unpack
to hundreds of megabytes. Each can be changed in .env:

  ZIP_MAX_UNPACKED_MB   2048   unpacked size of one zip, all files together
  ZIP_MAX_RATIO         200    unpacked / packed size of one file (report CSVs: well under 50); checked once a
                               file passes ZIP_RATIO_FROM_MB, since tiny files can compress far more harmlessly
  ZIP_RATIO_FROM_MB     10
  ZIP_MAX_FILES         100    files in one zip (Shadowserver sends one CSV per zip)
  ZIP_KEEP_FREE_MB      1024   disk space that must stay free while unpacking (when it runs out the zip is not
                               quarantined: it is the disk, not the zip, so it is tried again next run)
"""
from __future__ import annotations

import os
import shutil
import time
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

MB = 1 << 20
CHUNK = 1 << 20


class ZipRefused(Exception):
    """The zip broke a limit; the message says which, in words an analyst can act on."""


@dataclass(frozen=True)
class Limits:
    max_unpacked: int = 2048 * MB
    max_ratio: float = 200.0
    ratio_from: int = 10 * MB
    max_files: int = 100
    keep_free: int = 1024 * MB

    @classmethod
    def from_env(cls, get=os.environ.get) -> "Limits":
        def num(name, default, kind=int):
            try:
                v = kind(str(get(name, "") or default).strip())
                return v if v > 0 else kind(default)
            except ValueError:
                return kind(default)
        return cls(max_unpacked=num("ZIP_MAX_UNPACKED_MB", 2048) * MB, max_ratio=num("ZIP_MAX_RATIO", 200, float),
                   ratio_from=num("ZIP_RATIO_FROM_MB", 10) * MB, max_files=num("ZIP_MAX_FILES", 100),
                   keep_free=num("ZIP_KEEP_FREE_MB", 1024) * MB)


class LowDisk(Exception):
    """Not the zip's fault: the disk is nearly full. The zip stays where it is and is tried again next run."""


class Budget:
    """What one zip may still write: the unpacked-size limit, counted as bytes arrive, and the free disk space, read
    from the disk itself every FREE_EVERY bytes (zips are unpacked in parallel, so a figure taken at the start would
    not see the others)."""
    FREE_EVERY = 32 * MB

    def __init__(self, limits: Limits, folder: Path):
        self.limits, self.folder, self.written, self.next_look = limits, folder, 0, 0
        self.look()

    def look(self) -> None:
        if shutil.disk_usage(self.folder).free < self.limits.keep_free:
            raise LowDisk(f"less than {self.limits.keep_free // MB} MB of disk free (ZIP_KEEP_FREE_MB)")
        self.next_look = self.written + self.FREE_EVERY

    def take(self, n: int) -> None:
        self.written += n
        if self.written > self.limits.max_unpacked:
            raise ZipRefused(f"unpacks to more than {self.limits.max_unpacked // MB} MB (ZIP_MAX_UNPACKED_MB)")
        if self.written >= self.next_look:
            self.look()


def check_listing(infos, limits: Limits) -> None:
    """Before anything is written: the number of files, and the sizes the zip states (a cheap first check)."""
    files = [i for i in infos if not i.is_dir()]
    if len(files) > limits.max_files:
        raise ZipRefused(f"holds {len(files)} files, more than {limits.max_files} (ZIP_MAX_FILES)")
    stated = sum(i.file_size for i in files)
    if stated > limits.max_unpacked:
        raise ZipRefused(f"says it unpacks to {stated // MB} MB, more than {limits.max_unpacked // MB} MB (ZIP_MAX_UNPACKED_MB)")


def safe_path(base: Path, name: str) -> Path:
    """Where a file inside the zip may go: always under `base` (no absolute paths, no '..', no drive letters)."""
    parts = [p for p in PurePosixPath(name.replace("\\", "/")).parts if p not in ("", "/", ".", "..") and ":" not in p]
    if not parts:
        raise ZipRefused(f"has a file with an unusable name: {name[:80]!r}")
    return base.joinpath(*parts)


def copy_member(zf, info, dst: Path, budget: Budget) -> int:
    """Unpack one file, counting the real bytes; stops at the first limit passed (the partial file is removed)."""
    lim, n = budget.limits, 0
    dst.parent.mkdir(parents=True, exist_ok=True)
    try:
        with zf.open(info) as src, open(dst, "wb") as out:
            while True:
                chunk = src.read(CHUNK)
                if not chunk:
                    break
                n += len(chunk)
                budget.take(len(chunk))
                if n > lim.ratio_from and n / max(info.compress_size, 1) > lim.max_ratio:
                    raise ZipRefused(f"{os.path.basename(info.filename)[:80]} is compressed more than "
                                     f"{lim.max_ratio:g} times, the sign of a zip bomb (ZIP_MAX_RATIO)")
                out.write(chunk)
    except BaseException:
        dst.unlink(missing_ok=True)
        raise
    return n


def quarantine(zip_path: Path, base_dir: Path, reason: str) -> Path:
    """Move a refused zip out of the way, with a note of why; it is not unpacked or retried again."""
    q = base_dir / "quarantine"
    q.mkdir(parents=True, exist_ok=True)
    dst = q / zip_path.name
    if dst.exists():
        dst = q / f"{zip_path.stem}-{int(time.time())}{zip_path.suffix}"
    shutil.move(str(zip_path), dst)
    dst.with_name(dst.name + ".reason.txt").write_text(
        f"{time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}  refused: {reason}\n"
        "Not unpacked. If it is a genuine report, raise the limit named above in .env and move the zip back into "
        "attachments_backup/.\n", encoding="utf-8")
    return dst
