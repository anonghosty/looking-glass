#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""
Shadowserver pipeline: pull report e-mails -> unzip -> sort by service -> load into MongoDB.

Replaces (and merges) the two original scripts: the e-mail script pull_emails_and_create_services.py (no longer
shipped) and the loader mongo_added_json.py (kept for the equivalence tests).

The MongoDB layout is exactly the same as the original scripts produced
(database ``shadowserver`` by default):

  <service>                    one document per unique CSV row (one per JSON file)
                               fields: <CSV columns...>, filename, category, line_hash,
                               logged_date (str) + extracted_date (datetime) when the
                               row's ``timestamp`` parses as "%Y-%m-%d %H:%M:%S"
                               unique index (filename, category, line_hash)
  discovered_fields_<service>  {category, field_name}  - one per CSV header seen
  files_<service>              {filename, category, path} - one per file on disk

Once a quarter, after loading, the quarterly purge deletes the report rows dated before its cutoff, on its day only and
with Looking Glass's permit (quarterly_purge.py); files dated before that cutoff are not loaded again.

Usage:
  python shadowserver_pipeline.py                 # full run (e-mail + load)
  python shadowserver_pipeline.py --stage email   # only pull/unzip/sort
  python shadowserver_pipeline.py --stage load    # only load sorting_backup into MongoDB
  python shadowserver_pipeline.py --check         # verify config, MongoDB, IMAP, indexes
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import email
import errno
import fcntl
import hashlib
import imaplib
import itertools
import json
import logging
import os
import re
import shutil
import signal
import sqlite3
import sys
import time
import zipfile
from collections import Counter
from concurrent.futures import FIRST_COMPLETED, ProcessPoolExecutor, ThreadPoolExecutor, wait
from concurrent.futures import as_completed as futures_completed
from concurrent.futures.process import BrokenProcessPool
from dataclasses import dataclass
from email.header import decode_header
from pathlib import Path
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).resolve().parent))
import mail_sources  # noqa: E402  IMAP, Gmail API or Microsoft Graph (MAIL_PROVIDER)
import zip_limits  # noqa: E402  size, ratio and file-count limits for unpacking (zip bombs)
import report_names  # noqa: E402  which report names may become a folder and a MongoDB collection
import mail_auth  # noqa: E402  who signed each report e-mail (DKIM), recorded; log only
import report_api  # noqa: E402  the reports from Shadowserver's report API (REPORT_SOURCE=api)
import report_types  # noqa: E402  a report type that never arrived before is logged as new
import worker_settings  # noqa: E402  Settings → Workers: the platform's requests, checked and applied here
import retention  # noqa: E402  old sorted copies removed once in MongoDB (SORTED_KEEP_DAYS); the run's status and free disk
import quarterly_purge  # noqa: E402  the quarterly purge, with Looking Glass's permit (rows before the cutoff, once a quarter)

log = logging.getLogger("shadowserver")

# Per-file detail lines ([ATTACHMENT], [LINK], [UNZIP], [MOVE], [LOAD] ...) are shown by
# default like the original scripts; --quiet turns them into DEBUG (summary lines only).
DETAIL = logging.INFO


def detail(msg, *args):
    log.log(DETAIL, msg, *args)


def human(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} GB"

PROJECT_DIR = Path(__file__).resolve().parent

# Report file names: YYYY-MM-DD-<service>[-<number>]-<country>-geo[_asNNNN].csv, for any country (ghana-geo,
# kenya-geo, south-africa-geo, ...). The number is Shadowserver's id for the recipient (a few digits; other
# CSIRTs have other ids of any length), so any number of digits is accepted; service names never end in -<digits>.
# Numbered/unnumbered and _as#### variants as in the original script. REPORT_SUFFIX in .env (a regular expression)
# replaces "<country>-geo" when a CSIRT's reports are named differently. The filter part may also be -asn, -netblock or
# -domain (2026-11-14): reports without an IP address (Compromised Account, Ransomware Victim, Sandbox-DNS) can reach a
# CSIRT through a domain filter, and their files would otherwise never be sorted or loaded.
# 2026-11-26 (count audit): ".CSV" in any case, a country part in any case ("-Kenya-geo"), and a numeric part after the
# AS number ("_as64500_2.csv") are accepted too; they were left in unzipped_backup without a word. The report name itself
# stays as it is (report_names.valid: an uppercase one is quarantined, and counted). A REPORT_SUFFIX of a CSIRT's own is
# used exactly as written. CSV files that still do not match are counted and listed (not_matched), never left in silence.
DEFAULT_SUFFIX = r"(?i:[a-z][a-z0-9_-]*?-(?:geo|asn|netblock|domain))"


def compile_service_re() -> "re.Pattern[str]":
    suffix = os.environ.get("REPORT_SUFFIX") or DEFAULT_SUFFIX
    return re.compile(r"^\d{4}-\d{2}-\d{2}-(.*?)(?:-\d+)?-(?:" + suffix + r")(?:_as\d+)?(?:_\d+)?\.(?i:csv)$")


def sorted_name(fn: str) -> str:
    """The name a report file is sorted and loaded under: its ".CSV" (any case) written ".csv", the rest unchanged."""
    return fn[:-4] + ".csv" if fn[-4:].lower() == ".csv" else fn


NOT_MATCHED_LISTED = 100        # names kept in pipeline_status.json (the count is always the full one; the log has all)


SERVICE_RE = compile_service_re()   # compiled again by load_env_file, so REPORT_SUFFIX in .env applies
LINK_RE = re.compile(r'https://dl\.shadowserver\.org/[^\s"<]+')
CD_FILENAME_RE = re.compile(r'filename\*?=(?:UTF-8\'\')?"?([^";]+)"?')

TS_FMT = "%Y-%m-%d %H:%M:%S"
_TS_FAST = re.compile(r"([0-9]{4})-([0-9]{2})-([0-9]{2}) ([0-9]{2}):([0-9]{2}):([0-9]{2})\Z")

ROW_INDEX = [("filename", 1), ("category", 1), ("line_hash", 1)]
HOST_INDEX = [("ip", 1), ("filename", 1)]
# The largest CSV field read (audit 2026-11-27: Python's default of 128 KB stopped the rest of a report at the first
# bigger field, on every run). 16 MB is MongoDB's own limit for a whole row, so a bigger field could never be stored;
# a row with one is counted (rows_bad_csv) and the rest of the file is still loaded.
CSV_FIELD_MAX = 16 * 2**20
# a CSV column named "_id" became the row's MongoDB id: the rows of other files (and other rows with the same value)
# collided with it and were dropped as "already in the database". Such a column is kept as "csv_id" (audit 2026-11-27).
# The loader's other fields (filename, category, line_hash, logged_date, extracted_date) keep the original loader's
# behaviour, which tests/test_equivalence.py pins.
RESERVED_COLUMNS = ("_id",)
# report attachments: only these decide that an e-mail's links are not needed (an inline logo is not a report)
REPORT_ATTACHMENT = (".zip", ".csv")


# --------------------------------------------------------------------------- config

def load_env_file(path: Path) -> None:
    """Minimal KEY=VALUE loader (no shell expansion, so passwords with $ or # are safe)."""
    if not path.is_file():
        return
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key, value = key.strip(), value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
            value = value[1:-1]
        os.environ.setdefault(key, value)
    global SERVICE_RE
    SERVICE_RE = compile_service_re()


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default)


@dataclass(frozen=True)
class Settings:
    env_file: Path
    imap_server: str
    imap_user: str
    imap_password: str
    imap_folder: str
    imap_verify_tls: bool
    mongo: dict
    mongo_db: str
    mongo_cache_gb: float
    base_dir: Path
    workers: int
    insert_chunk: int
    download_threads: int
    fetch_batch: int
    days: int
    zip_limits: zip_limits.Limits = zip_limits.Limits()

    @property
    def attachments_dir(self) -> Path:
        return self.base_dir / "attachments_backup"

    @property
    def unzipped_dir(self) -> Path:
        return self.base_dir / "unzipped_backup"

    @property
    def sorting_dir(self) -> Path:
        return self.base_dir / "sorting_backup"

    @property
    def journal_path(self) -> Path:
        return self.base_dir / ".pipeline_state.sqlite"


def load_settings(args: argparse.Namespace) -> Settings:
    env_file = Path(args.env_file).expanduser().resolve()
    load_env_file(env_file)
    import db_connect                  # where the database is: loopback or internal only; TLS for another computer
    try:
        mongo = {**db_connect.kwargs(lambda k: _env(k) or None), "appname": "shadowserver-pipeline"}
    except db_connect.Refused as why:
        raise SystemExit(f"The pipeline will not run: {why} ({env_file}, see README.md)") from None
    if _env("MONGO_USER"):
        mongo.update(username=_env("MONGO_USER"), password=_env("MONGO_PASSWORD"),
                     authSource=_env("MONGO_AUTH_SOURCE", "admin"))
    base_dir = Path(_env("DATA_DIR") or PROJECT_DIR).expanduser().resolve()
    workers = args.workers or int(_env("WORKERS", "0") or 0) or min(6, os.cpu_count() or 2)
    return Settings(
        env_file=env_file,
        imap_server=_env("IMAP_SERVER"),
        imap_user=_env("IMAP_USER"),
        imap_password=_env("IMAP_PASSWORD"),
        imap_folder=_env("IMAP_FOLDER", "inbox"),
        imap_verify_tls=_env("IMAP_VERIFY_TLS", "true").lower() in ("1", "true", "yes", "on"),
        mongo=mongo,
        mongo_db=_env("MONGO_DB", "shadowserver"),
        mongo_cache_gb=float(_env("MONGO_CACHE_GB", "1.5")),
        base_dir=base_dir,
        workers=max(1, workers),
        insert_chunk=int(_env("INSERT_CHUNK", "2000")),
        download_threads=int(_env("DOWNLOAD_THREADS", "4")),
        fetch_batch=int(_env("IMAP_FETCH_BATCH", "25")),
        # 7 when unset: the default Settings → Workers shows (worker_settings.FIELDS), .env.example and the installer
        days=args.days if args.days is not None else int(_env("EMAIL_DAYS", "7")),
        zip_limits=zip_limits.Limits.from_env(_env),
    )


def mongo_client(mongo_kwargs: dict, **extra):
    from pymongo import MongoClient
    return MongoClient(**mongo_kwargs, **extra)


# --------------------------------------------------------------------------- helpers

def safe_filename(name: str) -> str:
    name = name.replace("\x00", "").replace("\\", "/").rsplit("/", 1)[-1].strip()
    return "" if name in ("", ".", "..") else name


def atomic_write(path: Path, data: bytes) -> None:
    tmp = path.with_name(f".{path.name}.part")
    with open(tmp, "wb") as fh:
        fh.write(data)
    os.replace(tmp, path)


def move_replace(src: str | Path, dst: str | Path) -> None:
    """Move src to dst, overwriting dst (same behaviour as the original remove+move)."""
    try:
        os.replace(src, dst)
    except OSError:  # e.g. cross-device
        if os.path.exists(dst):
            os.remove(dst)
        shutil.move(str(src), str(dst))


def file_fingerprint(path) -> tuple[int, int, str]:
    """(size, change time in ns, sha256) of a file; the size and time are taken before the content is read."""
    st = os.stat(path)
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return st.st_size, st.st_mtime_ns, h.hexdigest()


def parse_ts(ts):
    """Exactly equivalent to datetime.strptime(ts, TS_FMT) but ~4.5x faster on the common
    zero-padded form. Returns None where strptime would raise ValueError; raises TypeError
    for non-strings (as strptime does)."""
    if not isinstance(ts, str):
        raise TypeError(f"timestamp must be str, not {type(ts).__name__}")
    m = _TS_FAST.match(ts)
    if m:
        try:
            return dt.datetime(*map(int, m.groups()))
        except ValueError:
            return None
    try:
        return dt.datetime.strptime(ts, TS_FMT)
    except ValueError:
        return None


def format_logged(ts: str, parsed: dt.datetime) -> str:
    if parsed.year >= 1000 and _TS_FAST.match(ts):
        return ts  # canonical form already: identical to strftime output
    return parsed.strftime(TS_FMT)


def batched(iterable, n):
    if hasattr(itertools, "batched"):
        return itertools.batched(iterable, n)
    it = iter(iterable)
    return iter(lambda: tuple(itertools.islice(it, n)), ())


# --------------------------------------------------------------------------- stage 1: e-mail
# (the mailbox itself, IMAP among the others, is read by mail_sources.py)

class SenderCheckUnavailable(mail_sources.MailSourceError, RuntimeError):
    """Block mode is on and the sender check cannot run: no e-mail is read this run. A mail-source failure (the run
    goes on with the files on disk, and the API when it is set up), with its reason for the bell."""


def _header_text(value) -> str:
    if not value:
        return ""
    try:
        return str(email.header.make_header(decode_header(value))).replace("\n", " ").strip()
    except Exception:  # noqa: BLE001
        return str(value).replace("\n", " ").strip()


def _handle_message(msg, attach_dir: Path, stats: Counter, links: set, label: str = "", files: list | None = None) -> int:
    """Saves the message's attachments and collects its links. Returns how many attachments could not be saved
    (the message is then not marked done, so the next run tries again). `files` gets every attachment name."""
    body = []
    new_attachments = 0
    existing_attachments = 0
    failed = 0
    reports = 0                     # report attachments (.zip, .csv) saved, already there or failed
    links_before = len(links)
    for part in msg.walk():
        if part.get_content_maintype() == "multipart":
            continue
        if part.get_content_type() in ("text/plain", "text/html"):
            try:
                body.append(part.get_payload(decode=True).decode(errors="ignore"))
            except Exception as exc:  # noqa: BLE001
                log.debug("Could not decode body part: %s", exc)
                continue
        if not part.get("Content-Disposition"):
            continue
        filename = part.get_filename()
        if not filename:
            continue
        # every encoded piece of the name (a long name can be split in several), not only the first
        filename = safe_filename(_header_text(filename))
        if not filename:
            log.warning("    [WARNING] attachment without a usable filename skipped")
            continue
        if files is not None:
            files.append(filename)
        if filename.lower().endswith(REPORT_ATTACHMENT):
            reports += 1
        path = attach_dir / filename
        if path.exists():
            stats["attachments_skipped"] += 1
            existing_attachments += 1
            log.debug("    [SKIP] already exists (attachment): %s", filename)
            continue
        try:
            payload = part.get_payload(decode=True)
            if payload is None:
                raise ValueError("empty payload")
            atomic_write(path, payload)
            stats["attachments_saved"] += 1
            new_attachments += 1
            detail("    [ATTACHMENT] saved %s (%s)", filename, human(len(payload)))
        except Exception as exc:  # noqa: BLE001
            failed += 1
            stats["attachments_failed"] += 1
            log.error("    [ERROR] failed to save attachment %r: %s (retried next run)", filename, exc)

    # Fallback: an e-mail without any attachment (large reports come as a link only) -> its Shadowserver links.
    # Checked 2026-11-08: when an e-mail has both, the link gives the same report as the attachment, so an e-mail
    # whose attachment is already on disk (or failed and is retried) needs no link download. Only a REPORT attachment
    # (.zip, .csv) counts (audit 2026-11-27: an inline logo or a signature image stopped the link being fetched, and the
    # report was lost).
    if reports == 0 and body:
        links.update(LINK_RE.findall("".join(body)))

    parts = []
    if new_attachments:
        parts.append(f"{new_attachments} new attachment(s)")
    if existing_attachments:
        parts.append(f"{existing_attachments} already saved")
    if len(links) > links_before:
        parts.append(f"{len(links) - links_before} new link(s)")
    if failed:
        parts.append(f"{failed} FAILED")
    detail("[EMAIL %s] %s | %s | %s", label, _header_text(msg.get("Date"))[:31],
           _header_text(msg.get("Subject"))[:90] or "(no subject)", ", ".join(parts) or "nothing to fetch")
    return failed


def _filename_from_response(url: str, headers) -> str:
    match = CD_FILENAME_RE.findall(headers.get("Content-Disposition", ""))
    if match:
        return match[0]
    name = os.path.basename(urlparse(url).path)
    return name or f"download_{hashlib.sha1(url.encode(), usedforsecurity=False).hexdigest()[:16]}.bin"


def _download_link(session, url: str, dest: Path, max_bytes: int = 2048 * 2**20):
    """Returns (status, text, filename): status True = downloaded, False = already present, None = failed.
    max_bytes: a download stops (and nothing is kept) past this size, ZIP_MAX_UNPACKED_MB as for the API (external
    review, 2026-11-12: link downloads had no cap, so one link could fill the disk)."""
    tmp = None
    try:
        with session.get(url, stream=True, timeout=(30, 300)) as resp:
            if resp.status_code != 200:
                return None, f"HTTP {resp.status_code} for {url}", ""
            name = safe_filename(_filename_from_response(url, resp.headers))
            if not name:
                return None, f"no usable filename for {url}", ""
            path = dest / name
            if path.exists():
                return False, name, name
            try:
                announced = int(resp.headers.get("Content-Length") or 0)
            except ValueError:
                announced = 0
            if announced > max_bytes:
                return None, f"{url}: {human(announced)}, larger than {human(max_bytes)} (ZIP_MAX_UNPACKED_MB): not downloaded", ""
            tmp = path.with_name(f".{name}.part")
            size = 0
            with open(tmp, "wb") as fh:
                for block in resp.iter_content(chunk_size=1 << 20):
                    size += len(block)
                    if size > max_bytes:
                        raise OSError(f"larger than {human(max_bytes)} (ZIP_MAX_UNPACKED_MB): download stopped")
                    fh.write(block)
            os.replace(tmp, path)
            tmp = None
            return True, f"{name} ({human(size)})", name
    except Exception as exc:  # noqa: BLE001
        return None, f"{url}: {exc}", ""
    finally:
        if tmp is not None:
            try:
                os.unlink(tmp)
            except OSError:
                pass


def _download_links(links, dest: Path, threads: int, stats: Counter, max_bytes: int = 2048 * 2**20) -> list:
    """Download the links; returns [(url, filename)] of those now on disk (downloaded or already there)."""
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry

    session = requests.Session()
    retry = Retry(total=3, backoff_factor=2, status_forcelist=(429, 500, 502, 503, 504),
                  allowed_methods=frozenset({"GET"}))
    adapter = HTTPAdapter(pool_connections=threads, pool_maxsize=threads, max_retries=retry)
    session.mount("https://", adapter)
    total = len(links)
    ok = []
    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = {pool.submit(_download_link, session, u, dest, max_bytes): u for u in sorted(links)}
        for i, fut in enumerate(futures_completed(futures), 1):
            result, text, name = fut.result()
            if result is not None:
                ok.append((futures[fut], name))
            if result is True:
                stats["links_downloaded"] += 1
                detail("[LINK %d/%d] downloaded %s", i, total, text)
            elif result is False:
                stats["links_skipped"] += 1
                detail("[LINK %d/%d] already exists: %s", i, total, text)
            else:
                stats["links_failed"] += 1
                log.warning("[LINK %d/%d] FAILED %s", i, total, text)
    session.close()
    return ok


def _sender_verdict(auth, raw):
    """Who signed the message (mail_auth.py); None when the check is off or could not run."""
    if not auth:
        return None
    try:
        return auth[0].check(raw)
    except Exception as exc:  # noqa: BLE001  (never stops the pipeline)
        log.warning("    [SENDER] could not be checked: %s", exc)
        return None


def _sender_record(auth, key, res, msg, names, stats, action) -> None:
    if not (auth and res):
        return
    try:
        stats[f"sender_{res['result']}"] += 1
        if action != "kept":
            stats[f"sender_{action}"] += 1
        auth[1].add(key, res, _header_text(msg.get("Subject")) or "", names, action)
        if res["result"] != "pass":
            what = {"kept": "kept: blocking is off, the check only records",
                    "quarantined": "HELD BACK in quarantine/mail_auth/ until an administrator releases it",
                    "retry": "not processed this run: tried again next run"}.get(action, action)
            log.warning("    [SENDER %s] from %s: %s (%s)", res["result"].upper(), res["from_domain"] or "?",
                        res["reason"] or "no reason given", what)
            tip = mail_auth.hint(res["result"], res["reason"])
            if tip:
                log.warning("    [SENDER] what it usually means: %s", tip)
    except Exception as exc:  # noqa: BLE001
        log.warning("    [SENDER] could not be recorded: %s", exc)


def pull_emails(s: Settings, stats: Counter, refetch: bool = False) -> None:
    """Fetch the report e-mails of the last `days` days from MAIL_PROVIDER (IMAP, Gmail API or Microsoft Graph,
    mail_sources.py), save new attachments and download Shadowserver links. Messages and links already handled
    on an earlier run are skipped (.mail_state.sqlite), so frequent runs only fetch what is new."""
    s.attachments_dir.mkdir(parents=True, exist_ok=True)
    src = mail_sources.make_source(os.environ)
    state = mail_sources.MailState(s.base_dir / ".mail_state.sqlite")
    t0 = time.monotonic()
    links: set[str] = set()
    per_message: dict[str, set] = {}
    unfinished: set[str] = set()
    saved_files: list[tuple[str, str]] = []
    # the sender check (mail_auth.py): every message's DKIM signature, recorded. MAIL_AUTH=log only records;
    # MAIL_AUTH=enforce holds back (quarantines) a message that does not pass
    auth = None
    blocking = mail_auth.mode() == "enforce"
    if mail_auth.mode() != "off":
        try:
            auth = (mail_auth.Checker(os.environ.get("MAIL_AUTH_DOMAIN") or "shadowserver.org"),
                    mail_auth.Log(s.base_dir / ".mail_state.sqlite"))
        except Exception as exc:  # noqa: BLE001
            if blocking:
                # Block mode fails CLOSED: without the check no message can be judged, so none is read this run (they
                # stay unread in the mailbox and are tried next run). It used to go on unchecked (external review,
                # 2026-11-12: Block silently stopped blocking when the sender log could not be opened). A mail-source
                # failure, with its reason (audit 2026-11-27: a RuntimeError stopped the whole run, the files already
                # on disk were not loaded either, and the bell gave no reason)
                src.close()
                raise SenderCheckUnavailable(
                    f"Block mode is on but the sender check is unavailable ({exc}): no e-mail is read this run, so "
                    "nothing unchecked is loaded. It is tried again next run.",
                    "Block mode is on but the sender check could not run, so no e-mail was read") from exc
            log.warning("Sender check unavailable this run: %s", exc)
    # messages an administrator released since the last run: their attachments join the others, their links are fetched
    try:
        for rkey, rlinks, rfiles, who in mail_auth.take_releases(s.base_dir, s.attachments_dir):
            per_message[rkey] = rlinks
            links |= rlinks
            saved_files += [(f, rkey) for f in rfiles]
            if auth:
                auth[1].set_action(rkey, "released")
            log.warning("Sender check: a held-back message was RELEASED by %s (%d file(s), %d link(s))", who or "?",
                        len(rfiles), len(rlinks))
    except Exception as exc:  # noqa: BLE001
        log.warning("Sender check: releases could not be processed this run: %s", exc)
    try:
        items = src.list(s.days)
        done = set() if refetch else state.done_messages()
        legacy = getattr(src, "legacy", {}) or {}            # keys of earlier versions (Message-ID): handled already
        todo = [it for it in items if it[0] not in done and legacy.get(it[0]) not in done]
        total = len(todo)
        stats["emails_known"] = len(items) - total
        log.info("%s: %d message(s) since %s, %d new, %d already handled earlier", src.describe(), len(items),
                 mail_sources.since_date(s.days).isoformat(), total, stats["emails_known"])
        for key, raw in src.fetch(todo):
            stats["emails"] += 1
            n = stats["emails"]
            try:
                msg = email.message_from_bytes(raw)
            except Exception as exc:  # noqa: BLE001
                log.error("Failed to parse e-mail: %s", exc)
                continue
            mine: set[str] = set()
            names: list[str] = []
            res = _sender_verdict(auth, raw)
            if blocking and res and res["result"] == "temperror":
                unfinished.add(key)                  # DNS did not answer: decided on the next run, nothing saved now
                _sender_record(auth, key, res, msg, [], stats, "retry")
                continue
            if blocking and res and res["result"] in mail_auth.BLOCK:
                # held back: its attachments go to quarantine/mail_auth/<id>/, its links are only noted, nothing is
                # loaded; an administrator can release it (Audit portal, or python3 mail_auth.py release <id>)
                qdir = mail_auth.quarantine_dir(s.base_dir, key)
                qdir.mkdir(parents=True, exist_ok=True)
                if _handle_message(msg, qdir, Counter(), mine, f"{n}/{total} (held back)", names):
                    unfinished.add(key)              # a held-back attachment could not be saved: fetched again next run
                mail_auth.write_meta(qdir, key, res, _header_text(msg.get("Subject")), names, mine)
                _sender_record(auth, key, res, msg, names, stats, "quarantined")
                per_message[key] = set()             # handled: kept in quarantine, not fetched again
                continue
            if _handle_message(msg, s.attachments_dir, stats, mine, f"{n}/{total}", names):
                unfinished.add(key)                  # an attachment could not be saved: not done, try again
            _sender_record(auth, key, res, msg, names, stats, "kept")
            per_message[key] = mine
            saved_files += [(f, key) for f in names]
            links |= mine
            if n % 100 == 0 or n == total:
                log.info("-- progress: %d/%d e-mails (%.0f%%) | attachments: %d new, %d already saved | "
                         "links found: %d | %.0fs", n, total, 100 * n / max(total, 1),
                         stats["attachments_saved"], stats["attachments_skipped"], len(links),
                         time.monotonic() - t0)
    finally:
        # messages the mailbox did not hand over (a refused batch): counted, tried again next run. Those deleted from the
        # mailbox between the listing and the fetch are gone, nothing to try again: a warning, not an error (review r2)
        not_fetched = getattr(src, "failed", 0)
        stats["emails_not_fetched"] += not_fetched if isinstance(not_fetched, int) else 0
        gone = getattr(src, "gone", 0)
        stats["emails_gone"] += gone if isinstance(gone, int) else 0
        src.close()

    known = set() if refetch else state.done_links()
    new_links = links - known
    stats["links_known"] = len(links) - len(new_links)
    ok_links = set(known & links)
    if new_links:
        log.info("Downloading %d Shadowserver link(s) with %d threads (%d downloaded on earlier runs)",
                 len(new_links), s.download_threads, stats["links_known"])
        got = _download_links(new_links, s.attachments_dir, s.download_threads, stats, max_bytes=s.zip_limits.max_unpacked)
        state.mark_links(got)
        ok_links |= {u for u, _ in got}
    # a message is finished once its attachments are saved and every one of its links is on disk
    state.mark_messages([k for k, ls in per_message.items() if ls <= ok_links and k not in unfinished])
    state.mark_files([(f, k) for f, k in saved_files if (s.attachments_dir / f).exists()])
    if unfinished:
        log.warning("%d e-mail(s) had an attachment that could not be saved: they are fetched again next run",
                    len(unfinished))
    state.forget_older_than(max(30, s.days + 7))
    state.close()
    if auth:
        try:
            auth[1].forget_older_than(max(90, s.days + 7))
            auth[1].close()
        except Exception:  # noqa: BLE001
            pass
        checked = sum(stats[f"sender_{r}"] for r in mail_auth.RESULTS)
        if checked:
            log.info("Sender check (%s): %d message(s): %s%s", "blocking" if blocking else "log only, nothing held back",
                     checked, ", ".join(f"{stats[f'sender_{r}']} {r}" for r in mail_auth.RESULTS if stats[f"sender_{r}"]),
                     "".join(f" | {stats[f'sender_{a}']} {a}" for a in ("quarantined", "retry") if stats[f"sender_{a}"]))
    log.info("E-mail: %d new message(s) | attachments: %d saved, %d already there, %d failed | links: %d downloaded, "
             "%d already there, %d failed, %d skipped (done earlier) (%.1fs)",
             stats["emails"], stats["attachments_saved"], stats["attachments_skipped"], stats["attachments_failed"],
             stats["links_downloaded"],
             stats["links_skipped"], stats["links_failed"], stats["links_known"], time.monotonic() - t0)


# --------------------------------------------------------------------------- stage 1b: unzip + sort

def _extract_zip(zip_path: Path, unzipped_dir: Path, sorting_dir: Path,
                 limits: zip_limits.Limits = zip_limits.Limits(), quarantined: list | None = None) -> str:
    """Extract one zip. Report CSVs go to sorting_backup/<service>/ (overwrite), everything else to
    unzipped_backup/<zipname>/ like before. Everything is unpacked into a .partial folder first, within the limits of
    zip_limits.py (real bytes counted), and only moved into place once the whole zip is unpacked: a zip that breaks
    a limit halfway leaves nothing behind, and is quarantined. `quarantined` gets the name of every report file moved
    to quarantine for its report name (counted for the run's status; it was only in the log)."""
    target = unzipped_dir / zip_path.name
    if target.exists():
        return "zips_skipped", []
    tmp = unzipped_dir / f"{zip_path.name}.partial"
    shutil.rmtree(tmp, ignore_errors=True)
    tmp.mkdir(parents=True)
    try:
        staged = []
        with zipfile.ZipFile(zip_path) as zf:
            infos = zf.infolist()
            zip_limits.check_listing(infos, limits)
            budget = zip_limits.Budget(limits, unzipped_dir)
            for i, info in enumerate(infos):
                if info.is_dir():
                    continue
                base = os.path.basename(info.filename)
                m = SERVICE_RE.match(base)
                if not m:
                    zip_limits.copy_member(zf, info, zip_limits.safe_path(tmp, info.filename), budget)
                    continue
                zip_limits.copy_member(zf, info, tmp / f".route-{i}", budget)
                staged.append((tmp / f".route-{i}", sorted_name(base), m.group(1)))
        # a Special Report's own name (special-badbox -> special_badbox): cut where the country part begins, learnt from
        # the ordinary reports sorted before and those in this zip (report_names.special_name)
        tails = report_names.learn_tails(sorting_dir) | {
            t for _, b, g in staged if (t := report_names.country_tail(b, g))}
        staged = [(p, b, report_names.special_name(b, g, tails)) for p, b, g in staged]
        routed = []
        for path, base, service in staged:                 # the whole zip is unpacked: now move the reports in
            if not report_names.valid(service):            # an unusable report name never reaches MongoDB
                report_names.quarantine(path.rename(path.with_name(base)), unzipped_dir.parent, service)
                log.warning("[QUARANTINE] %s (from %s): %s. Moved to quarantine/%s/", base, zip_path.name,
                            report_names.why(service), report_names.FOLDER)
                if quarantined is not None:
                    quarantined.append(base)
                continue
            service_dir = sorting_dir / service
            service_dir.mkdir(parents=True, exist_ok=True)
            existed = (service_dir / base).exists()
            move_replace(path, service_dir / base)
            routed.append((base, service, existed))
        os.replace(tmp, target)
        return "zips_extracted", routed
    except zip_limits.ZipRefused as exc:
        shutil.rmtree(tmp, ignore_errors=True)
        where = zip_limits.quarantine(zip_path, unzipped_dir.parent, str(exc))
        return "zips_refused", [str(exc), where.name]
    except zipfile.BadZipFile:
        shutil.rmtree(tmp, ignore_errors=True)
        zip_path.unlink(missing_ok=True)
        return "zips_bad_deleted", []
    except NotImplementedError as exc:
        # a compression method this Python cannot unpack: the same every run, so quarantined like a refused zip
        # (audit 2026-11-27: retried for ever)
        shutil.rmtree(tmp, ignore_errors=True)
        reason = f"uses a compression method that cannot be unpacked here ({exc})"
        where = zip_limits.quarantine(zip_path, unzipped_dir.parent, reason)
        return "zips_refused", [reason, where.name]
    except OSError as exc:
        # a file error while unpacking (a member "notes/a.txt" beside a member "notes", a name the disk refuses...):
        # the same zip fails the same way every run, so it is quarantined like a refused one (review 2026-11-13: it was
        # retried for ever and its reports never loaded). A full disk is not the zip's fault: retried next run.
        shutil.rmtree(tmp, ignore_errors=True)
        if exc.errno in (errno.ENOSPC, errno.EDQUOT, errno.EIO, errno.EROFS, errno.EAGAIN, errno.EBUSY, errno.ENOMEM):
            return "zips_failed", [str(exc)]
        reason = f"could not be unpacked: {exc.strerror or exc.__class__.__name__}" + (
            f" ({os.path.basename(str(exc.filename))})" if exc.filename else "")
        where = zip_limits.quarantine(zip_path, unzipped_dir.parent, reason)
        return "zips_refused", [reason, where.name]
    except Exception as exc:  # noqa: BLE001  (left in place, retried next run; also zip_limits.LowDisk)
        shutil.rmtree(tmp, ignore_errors=True)
        return "zips_failed", [str(exc)]


def _forget_broken(s: Settings, name: str) -> int:
    """A downloaded file was broken and deleted: reopen its e-mail / link in the mail record (re-fetched next run)."""
    path = s.base_dir / ".mail_state.sqlite"
    if not path.exists():
        return 0
    try:
        st = mail_sources.MailState(path)
        try:
            return st.forget_file(name)
        finally:
            st.close()
    except Exception as exc:  # noqa: BLE001
        log.error("Could not reopen %s in the mail record: %s", name, exc)
        return 0


def unzip_and_sort(s: Settings, stats: Counter) -> None:
    for d in (s.attachments_dir, s.unzipped_dir, s.sorting_dir):
        d.mkdir(parents=True, exist_ok=True)
    t0 = time.monotonic()

    zips, seen = [], set()
    for root, _, files in os.walk(s.attachments_dir):
        for fn in sorted(files):
            if fn.lower().endswith(".zip"):
                if fn in seen:  # same name -> same target dir, original skipped it too
                    stats["zips_skipped"] += 1
                    continue
                seen.add(fn)
                zips.append(Path(root, fn))
    todo = [z for z in zips if not (s.unzipped_dir / z.name).exists()]
    stats["zips_skipped"] += len(zips) - len(todo)
    log.info("Unzip: %d zip(s) in %s, %d new to extract, %d already extracted earlier",
             len(zips), s.attachments_dir.name, len(todo), len(zips) - len(todo))

    if todo:
        threads = max(2, min(8, s.workers))
        total = len(todo)
        quarantined: list = []                 # report files moved to quarantine for their name (list.append: thread-safe)
        with ThreadPoolExecutor(max_workers=threads) as pool:
            futures = {pool.submit(_extract_zip, z, s.unzipped_dir, s.sorting_dir, s.zip_limits, quarantined): z
                       for z in todo}
            for i, fut in enumerate(futures_completed(futures), 1):
                z = futures[fut]
                result, items = fut.result()
                stats[result] += 1
                if result == "zips_extracted":
                    detail("[UNZIP %d/%d] %s -> %d report CSV(s)", i, total, z.name, len(items))
                    for base, service, existed in items:
                        stats["csv_sorted"] += 1
                        detail("    [%s] %s -> %s", "OVERWRITE" if existed else "SORT", base, service)
                elif result == "zips_bad_deleted":
                    reopened = _forget_broken(s, z.name)
                    log.warning("[UNZIP %d/%d] [DELETE] corrupt or mislabeled zip: %s%s", i, total, z.name,
                                " (its e-mail/link is fetched again next run)" if reopened > 0 else
                                f" (fetched again {mail_sources.MailState.REFETCH_MAX} times, broken each time: not fetched "
                                "again. Ask Shadowserver to send it again)" if reopened < 0 else
                                " (not in the mail record: run with --days N --all to fetch it again)")
                elif result == "zips_refused":
                    log.warning("[UNZIP %d/%d] [QUARANTINE] %s not unpacked: it %s. Moved to quarantine/%s",
                                i, total, z.name, items[0], items[1])
                elif result == "zips_failed":
                    log.error("[UNZIP %d/%d] FAILED %s: %s (will retry next run)", i, total, z.name,
                              items[0] if items else "")
        stats["csv_quarantined"] += len(quarantined)

    # Sweep: CSV attachments that arrived un-zipped, plus anything left from older runs.
    tails = report_names.learn_tails(s.sorting_dir)
    not_matched: list[str] = []
    for search_dir in (s.unzipped_dir, s.attachments_dir):
        for root, dirs, files in os.walk(search_dir):
            dirs[:] = [d for d in dirs if not d.endswith(".partial")]
            for fn in sorted(files):
                m = SERVICE_RE.match(fn)
                if not m:
                    # a CSV whose name is not a report file name: never loaded. Counted and listed (count audit
                    # 2026-11-26: "-kenya.csv", "-ke-cidr.csv" stayed in unzipped_backup without a word)
                    if fn.lower().endswith(".csv") and not fn.startswith("."):
                        not_matched.append(os.path.relpath(os.path.join(root, fn), s.base_dir))
                    continue
                rname = report_names.special_name(fn, m.group(1), tails)   # "special-x" loads as special_x
                if not report_names.valid(rname):           # an unusable report name never reaches MongoDB
                    report_names.quarantine(os.path.join(root, fn), s.base_dir, rname)
                    log.warning("[QUARANTINE] %s: %s. Moved to quarantine/%s/", fn, report_names.why(rname),
                                report_names.FOLDER)
                    stats["csv_quarantined"] += 1
                    continue
                service_dir = s.sorting_dir / rname
                service_dir.mkdir(parents=True, exist_ok=True)
                dest = sorted_name(fn)
                existed = (service_dir / dest).exists()
                move_replace(os.path.join(root, fn), service_dir / dest)
                stats["csv_moved"] += 1
                detail("[%s] %s -> %s", "OVERWRITE" if existed else "MOVE", fn, rname)
    stats["csv_not_matched"] += len(not_matched)
    stats["not_matched_names"] = sorted(not_matched)
    for name in sorted(not_matched):
        log.warning("[NOT MATCHED] %s: not a report file name (YYYY-MM-DD-<report>-...-geo.csv, or REPORT_SUFFIX): "
                    "not loaded. Rename it, or remove it once checked", name)

    log.info("Unzip: %d extracted (%d report CSVs sorted), %d already done, %d bad deleted, %d quarantined (limits), "
             "%d failed | %d loose CSV moved | %d quarantined (report name) | %d CSV not matched (%.1fs)",
             stats["zips_extracted"], stats["csv_sorted"], stats["zips_skipped"], stats["zips_bad_deleted"],
             stats["zips_refused"], stats["zips_failed"], stats["csv_moved"], stats["csv_quarantined"],
             stats["csv_not_matched"], time.monotonic() - t0)
    services = [(d.name, sum(1 for f in os.scandir(d) if f.name.endswith(".csv")))
                for d in sorted(os.scandir(s.sorting_dir), key=lambda e: e.name) if d.is_dir()]
    log.info("Service folders populated: %d (%d CSV files)", len(services), sum(c for _, c in services))
    for name, count in services:
        if count:
            detail("  - %s: %d file(s)", name, count)
    # a report type that never arrived before (by e-mail or by API) is logged as new (report_types.py)
    stats["new_report_types"] += len(report_types.note_new(s.base_dir, [n for n, c in services if c], log))


# --------------------------------------------------------------------------- stage 2: documents

def iter_csv_docs(path: str, filename: str, category: str, errors: str = "strict", info: dict | None = None):
    """Yield one MongoDB document per unique row, identical to mongo_added_json.py.

    The file is streamed (constant memory). Splitting each physical line with
    str.splitlines() yields exactly the same line list as the original
    ``file.read().splitlines()``, so the csv parsing and line_hash are unchanged.

    line_hash is kept exactly as the original loader made it (every stored hash depends on it), with two known limits
    (external review, 2026-11-14; tests/test_line_hash.py):
      * only the header's fields go into it: two rows that differ only in values beyond the header are one row (the
        extra values are dropped either way, and counted as "extra columns");
      * the fields are joined with commas without the CSV quoting: "x,y","z" and "x","y,z" give the same hash, so the
        second of such a pair, in the same file, is taken for a duplicate. Shadowserver's fields rarely line up like
        that (it takes a comma inside one field and the same text split across the next one). Such a pair is now
        counted (info["same_hash"]), not stored, as before.

    Every row read lands in exactly one count (count audit, 2026-11-26): info["rows_read"] = the rows yielded (then
    inserted, already in the database, or failed) + info["same_in_file"] (the same row again in this file, stored once)
    + info["same_hash"] + info["bad_timestamp"] (not stored, as before). info["no_time"]: yielded rows without a
    timestamp (stored, but no page shows them). The file is read with "utf-8-sig" (a byte-order mark made the first
    header '\\ufeff"timestamp"', so no row got its date), and split into lines at \\n, \\r\\n and \\r only, as the
    original did, not also at the other characters str.splitlines() splits at (U+2028, NEL, \\x1c-\\x1e...), which cut
    a row in two.

    Audit 2026-11-27: a field over Python's 128 KB default stopped the rest of the file with csv.Error, on every run.
    Fields up to CSV_FIELD_MAX are read now; a row that still cannot be read is counted (info["bad_csv"], also in
    rows_read) and the rows after it are loaded. A column named "_id" (RESERVED_COLUMNS) is kept as "csv_id"
    (info["renamed"]). The rows seen are remembered by 16 bytes of their hash, not its 64
    hexadecimal characters, so a big file needs about a third less memory in its worker."""
    info = info if info is not None else {}
    with open(path, "rb") as fb:
        info["bom"] = fb.read(3) == b"\xef\xbb\xbf"
    if csv.field_size_limit() < CSV_FIELD_MAX:
        csv.field_size_limit(CSV_FIELD_MAX)
    with open(path, "r", encoding="utf-8-sig", errors=errors, newline="") as fh:
        # newline="": the file yields lines ending at \n, \r\n or \r (the line ends the original split at); the ending
        # is cut off as splitlines() did, so the csv parsing and line_hash of every ordinary row are unchanged
        lines = (raw.rstrip("\r\n") for raw in fh)
        reader = csv.DictReader(lines)
        for k in ("rows_read", "same_in_file", "same_hash", "bad_timestamp", "no_time", "bad_csv"):
            info.setdefault(k, 0)
        try:
            headers = reader.fieldnames
        except csv.Error as exc:                 # the header itself cannot be read: nothing of the file can
            info["headers"] = None
            info["bad_csv"] += 1
            info["bad_csv_why"] = str(exc)[:200]
            return
        if headers is not None:
            taken = set(headers)
            renamed = []
            for i, h in enumerate(headers):
                if h in RESERVED_COLUMNS:
                    new = "csv_" + h.lstrip("_")
                    while new in taken:
                        new += "_"
                    taken.add(new)
                    renamed.append((h, new))
                    headers[i] = new
            if renamed:
                reader.fieldnames = headers
                info["renamed"] = renamed
        info["headers"] = list(headers) if headers is not None else None
        if headers is None:
            return
        # 16 bytes of line_hash -> Python's own hash of the row's values: a second row with the same line_hash and other
        # values is the documented "x,y","z" / "x","y,z" pair, told apart from a true repeat at the cost of one hash
        seen: dict[bytes, int] = {}
        sha256 = hashlib.sha256
        rows = iter(reader)
        stuck_at = None
        while True:
            try:
                row = next(rows)
            except StopIteration:
                break
            except csv.Error as exc:
                # one row that cannot be read (a field over CSV_FIELD_MAX, a NUL byte): counted, the next line goes on
                info["rows_read"] += 1
                info["bad_csv"] += 1
                info.setdefault("bad_csv_why", f"line {reader.reader.line_num}: {str(exc)[:200]}")
                if reader.reader.line_num == stuck_at:      # nothing more could be read: stop, never loop
                    break
                stuck_at = reader.reader.line_num
                continue
            info["rows_read"] += 1
            values = [str(row.get(field, "")) for field in headers]
            line = ",".join(values)
            digest = sha256(line.encode()).digest()
            key = digest[:16]
            if key in seen:
                if seen[key] == hash(tuple(values)):
                    info["same_in_file"] += 1
                else:
                    info["same_hash"] += 1
                continue
            if None in row:  # more values than headers: the original crashed the whole batch on this
                del row[None]
                info["extra_columns"] = info.get("extra_columns", 0) + 1
            row["filename"] = filename
            row["category"] = category
            row["line_hash"] = digest.hex()
            if "extracted_date" not in row:
                timestamp_str = row.get("timestamp")
                if timestamp_str:
                    parsed = parse_ts(timestamp_str)
                    if parsed is None:
                        info["bad_timestamp"] += 1
                        continue
                    row.setdefault("logged_date", format_logged(timestamp_str, parsed))
                    row["extracted_date"] = parsed
                else:
                    info["no_time"] += 1
            yield row
            seen[key] = hash(tuple(values))


def json_doc(path: str, filename: str, category: str) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        json_data = fh.read()
    json_object = json.loads(json_data)
    doc = {
        "filename": filename,
        "category": category,
        "line_hash": hashlib.sha256(json_data.encode()).hexdigest(),
        **json_object,
    }
    if "extracted_date" not in doc:
        timestamp_str = json_object.get("timestamp")
        if timestamp_str:
            parsed = parse_ts(timestamp_str)
            if parsed is not None:
                doc.setdefault("logged_date", parsed.strftime(TS_FMT))
                doc["extracted_date"] = parsed
    return doc


# --------------------------------------------------------------------------- stage 2: workers

_WORKER_DB = None


def _init_worker(mongo_kwargs: dict, db_name: str, log_level: int) -> None:
    global _WORKER_DB
    signal.signal(signal.SIGINT, signal.SIG_IGN)  # parent handles Ctrl-C
    logging.basicConfig(level=log_level, format="%(asctime)s %(levelname)-7s [w%(process)d] %(message)s")
    logging.getLogger("pymongo").setLevel(logging.WARNING)
    _WORKER_DB = mongo_client(mongo_kwargs, maxPoolSize=2)[db_name]


def _insert_docs(coll, docs: list) -> tuple[int, int, int]:
    """Unordered bulk insert. Returns (inserted, duplicates, failed).

    After a dropped connection (AutoReconnect) the whole chunk is sent again; the rows the first try had already
    written then come back as duplicates. They are told apart by their _id (insert_many gives every row its _id before
    sending, and the second try sends the same ones): a duplicate whose _id is in the database is this chunk's own row,
    counted as inserted, not as "already in the database" (audit 2026-11-27)."""
    from pymongo.errors import AutoReconnect, BulkWriteError, DuplicateKeyError, InvalidDocument

    retried = False
    for attempt in range(5):
        try:
            return len(coll.insert_many(docs, ordered=False).inserted_ids), 0, 0
        except BulkWriteError as exc:
            errs = exc.details.get("writeErrors", [])
            dups = [e for e in errs if e.get("code") == 11000]
            other = [e for e in errs if e.get("code") != 11000]
            if other:
                log.warning("%s: %d write error(s), first: %s", coll.name, len(other), other[0].get("errmsg"))
            inserted, dup = exc.details.get("nInserted", 0), len(dups)
            if retried and dups:
                ids = [docs[e["index"]].get("_id") for e in dups
                       if isinstance(e.get("index"), int) and 0 <= e["index"] < len(docs)]
                ids = [i for i in ids if i is not None]
                try:
                    mine = coll.count_documents({"_id": {"$in": ids}}) if ids else 0
                except Exception as cexc:  # noqa: BLE001  (counted as before: duplicates)
                    log.warning("%s: rows written before the reconnect could not be counted: %s", coll.name, cexc)
                    mine = 0
                inserted, dup = inserted + mine, dup - mine
            return inserted, dup, len(other)
        except InvalidDocument:
            ins = dup = bad = 0
            for doc in docs:
                try:
                    coll.insert_one(doc)
                    ins += 1
                except DuplicateKeyError:
                    dup += 1
                except InvalidDocument as exc:
                    bad += 1
                    log.warning("%s: invalid document skipped: %s", coll.name, exc)
            return ins, dup, bad
        except AutoReconnect as exc:
            retried = True
            wait_s = 2 ** attempt
            log.warning("MongoDB connection issue (%s), retrying in %ss", exc, wait_s)
            time.sleep(wait_s)
    raise RuntimeError("MongoDB unavailable after retries")


STAMPS = "lg_load_stamps"


def stamp_loaded(category: str, filename: str, inserted: int) -> None:
    """Mark that rows of this report were added for the day its file is named after (the file name starts with the
    date). Looking Glass reads these marks every 15 seconds instead of counting every report's rows (review of d82a436),
    and counts only when a mark moved. Best effort: a mark that cannot be written only makes the platform count."""
    day = filename[:10]
    if not re.match(r"\d{4}-\d{2}-\d{2}$", day):
        return
    try:
        _WORKER_DB[STAMPS].update_one({"_id": f"{category}|{day}"},
                                      {"$set": {"coll": category, "day": day, "at": dt.datetime.now(dt.timezone.utc)},
                                       "$inc": {"rows": int(inserted)}}, upsert=True)
    except Exception as exc:  # noqa: BLE001
        log.debug("load stamp not written for %s %s: %s", category, day, exc)


def load_file(category: str, path: str, filename: str, chunk: int) -> dict:
    coll = _WORKER_DB[category]
    started = time.monotonic()
    res = {"category": category, "filename": filename, "rows": 0, "inserted": 0,
           "duplicates": 0, "failed": 0, "headers": None, "notes": [], "rows_read": 0}
    # what the file was when it was loaded (size, change time, sha256): a report sent again under the same name, with
    # other content, is loaded again (Journal.remember / changed_since_load; count audit 2026-11-26)
    try:
        res["size"], res["mtime_ns"], res["sha256"] = file_fingerprint(path)
    except OSError:
        res["size"] = res["mtime_ns"] = res["sha256"] = None

    def push(docs):
        ins, dup, bad = _insert_docs(coll, docs)
        res["rows"] += len(docs)
        res["inserted"] += ins
        res["duplicates"] += dup
        res["failed"] += bad
        if ins:
            stamp_loaded(category, filename, ins)

    if filename.lower().endswith(".csv"):
        own = 0
        for errors in ("strict", "replace"):
            info: dict = {}
            try:
                for docs in batched(iter_csv_docs(path, filename, category, errors, info), chunk):
                    push(list(docs))
                break
            except UnicodeDecodeError:
                if errors == "replace":
                    raise
                res["notes"].append("non-UTF-8 bytes replaced")
                # the file is read again from its start: the rows read so far are counted once, not twice, and those
                # this run already inserted are not "already in DB" the second time (review 2026-11-13)
                own = res["inserted"]
                res["rows"] = res["duplicates"] = res["failed"] = 0
        res["duplicates"] = max(0, res["duplicates"] - own)
        res["headers"] = info.get("headers")
        if info.get("extra_columns"):
            res["notes"].append(f"{info['extra_columns']} row(s) had extra columns (dropped)")
        res["bad_timestamp"] = info.get("bad_timestamp", 0)
        for k in ("rows_read", "same_in_file", "same_hash", "no_time", "extra_columns", "bad_csv"):
            res[k] = info.get(k, 0)
        if info.get("bad_csv"):
            res["notes"].append(f"{info['bad_csv']} row(s) could not be read as CSV and were not stored "
                                f"(first: {info.get('bad_csv_why', '')}); the other rows were loaded")
        if info.get("renamed"):
            res["notes"].append("column(s) named like a MongoDB field of the loader's kept under another name: "
                                + ", ".join(f"{a} as {b}" for a, b in info["renamed"]))
        res["replaced"] = int("non-UTF-8 bytes replaced" in res["notes"])
        if info.get("bom"):
            res["notes"].append("the file starts with a byte-order mark (read without it)")
        if info.get("headers") is not None and "timestamp" not in info["headers"]:
            res["notes"].append("the file has no timestamp column: its rows are stored, but no page shows them")
    elif filename.lower().endswith(".json"):
        res["rows_read"] = 1
        try:
            push([json_doc(path, filename, category)])
        except Exception as exc:  # noqa: BLE001  (original: print and skip; now a failed row, tried again next run)
            res["notes"].append(f"JSON error: {exc}")
            res["failed"] += 1
    res["seconds"] = time.monotonic() - started
    return res


# --------------------------------------------------------------------------- stage 2: orchestration

class Journal:
    """Remembers files whose load started but did not finish, so an interrupted run
    is completed next time (duplicates are rejected by the unique index)."""

    def __init__(self, path: Path):
        self.db = sqlite3.connect(path)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=NORMAL")
        self.db.execute("CREATE TABLE IF NOT EXISTS inflight (category TEXT, filename TEXT, "
                        "PRIMARY KEY (category, filename))")
        # what each file was when it was loaded (count audit, 2026-11-26): a report sent again under the same name
        # overwrote its sorted copy, and was never loaded again because its name was already in MongoDB. sha256 is
        # empty for a file loaded before this was kept (its size and time are taken on the first run that sees it).
        self.db.execute("CREATE TABLE IF NOT EXISTS loaded (category TEXT, filename TEXT, size INTEGER, "
                        "mtime_ns INTEGER, sha256 TEXT, PRIMARY KEY (category, filename))")
        # files loaded without a single row to store (only a header, only bad rows): nothing of them is in MongoDB, so
        # their name was not found there and they were read again on every run (audit 2026-11-27). Kept with what they
        # were; read again only when they change.
        self.db.execute("CREATE TABLE IF NOT EXISTS empty (category TEXT, filename TEXT, size INTEGER, "
                        "mtime_ns INTEGER, sha256 TEXT, PRIMARY KEY (category, filename))")
        # how many runs a file stopped the loader's worker process even when it was loaded alone (review r2): the kernel
        # picks the process it ends by the machine's memory, not by file, so one such stop does not quarantine a file;
        # a second one, on another run, does. Cleared once it loads.
        self.db.execute("CREATE TABLE IF NOT EXISTS crashes (category TEXT, filename TEXT, runs INTEGER, "
                        "PRIMARY KEY (category, filename))")
        self.db.commit()

    def crashed_alone(self, category: str, filename: str) -> int:
        """Count one more run on which this file stopped its worker when loaded alone; returns the runs so far."""
        self.db.execute("INSERT INTO crashes VALUES (?, ?, 1) ON CONFLICT (category, filename) DO UPDATE SET "
                        "runs = runs + 1", (category, filename))
        self.db.commit()
        return self.db.execute("SELECT runs FROM crashes WHERE category=? AND filename=?",
                               (category, filename)).fetchone()[0]

    def crash_names(self) -> set:
        return set(self.db.execute("SELECT category, filename FROM crashes"))

    def forget_crashes(self, category: str, filename: str) -> None:
        self.db.execute("DELETE FROM crashes WHERE category=? AND filename=?", (category, filename))
        self.db.commit()

    def not_loaded_whole(self) -> set:
        """{(category, filename)} of the files quarantined after they stopped the loader, not loaded whole since."""
        return set(self.db.execute("SELECT category, filename FROM loaded WHERE sha256=?", (QUARANTINED_PART,)))

    def empty_names(self) -> dict:
        """{category: {filename}} of every report's files that had no row to store (SORTED_KEEP_DAYS counts them as
        loaded: nothing of them is in MongoDB, so MongoDB alone never names them; review r2)."""
        out: dict = {}
        for c, fn in self.db.execute("SELECT category, filename FROM empty"):
            out.setdefault(c, set()).add(fn)
        return out

    def empties(self, category: str) -> dict:
        """{filename: (size, mtime_ns, sha256)} of one report's files that had no row to store."""
        return {fn: (sz, mt, sha) for fn, sz, mt, sha in
                self.db.execute("SELECT filename, size, mtime_ns, sha256 FROM empty WHERE category=?", (category,))}

    def remember_empty(self, items) -> None:
        """items: (category, filename, size, mtime_ns, sha256)."""
        self.db.executemany("INSERT OR REPLACE INTO empty VALUES (?, ?, ?, ?, ?)", items)
        self.db.commit()

    def forget_empty(self, category: str, filename: str) -> None:
        self.db.execute("DELETE FROM empty WHERE category=? AND filename=?", (category, filename))
        self.db.commit()

    def pending(self) -> set:
        return set(self.db.execute("SELECT category, filename FROM inflight"))

    def fingerprints(self, category: str) -> dict:
        """{filename: (size, mtime_ns, sha256)} of one report's loaded files."""
        return {fn: (sz, mt, sha) for fn, sz, mt, sha in
                self.db.execute("SELECT filename, size, mtime_ns, sha256 FROM loaded WHERE category=?", (category,))}

    def remember(self, items) -> None:
        """items: (category, filename, size, mtime_ns, sha256 or '')."""
        self.db.executemany("INSERT OR REPLACE INTO loaded VALUES (?, ?, ?, ?, ?)", items)
        self.db.commit()

    def add_many(self, items) -> None:
        self.db.executemany("INSERT OR IGNORE INTO inflight VALUES (?, ?)", items)
        self.db.commit()

    def done(self, category: str, filename: str) -> None:
        self.db.execute("DELETE FROM inflight WHERE category=? AND filename=?", (category, filename))
        self.db.commit()

    def close(self) -> None:
        self.db.close()


def changed_since_load(path: str, known, stat=None):
    """Was this already loaded file replaced on disk by other content since it was loaded? known: the journal's
    (size, mtime_ns, sha256) or None. Returns (changed, fingerprint to remember or None). Cheap when nothing changed:
    the content is read only when the size or time differ."""
    st = stat or os.stat(path)
    if known is None:                      # loaded before fingerprints were kept: remember it as it is now, unread
        return False, (st.st_size, st.st_mtime_ns, "")
    size, mtime_ns, sha = known
    if (st.st_size, st.st_mtime_ns) == (size, mtime_ns):
        return False, None
    if sha and st.st_size == size:
        fp = file_fingerprint(path)
        if fp[2] == sha:                   # touched or copied again, same content
            return False, fp
        return True, fp
    return True, None                      # another size, or no hash to compare: load it again (copies are refused)


def loaded_filenames(coll) -> set:
    """Filenames that already have rows (the original did one find_one per file)."""
    from pymongo.errors import OperationFailure
    try:
        return set(coll.distinct("filename"))
    except OperationFailure:  # >16MB result: fall back to a cursor
        pipeline = [{"$sort": {"filename": 1}}, {"$group": {"_id": "$filename"}}]
        return {d["_id"] for d in coll.aggregate(pipeline, allowDiskUse=True)}


LOADER_QUARANTINE = "loader"
# the journal's fingerprint of a file moved to quarantine/loader/ (no file has it): when the file is moved back, it is
# loaded again, although rows it stored before it stopped the loader put its name in MongoDB (review r2)
QUARANTINED_PART = "quarantined: not loaded whole"
CRASH_RUNS = 2              # runs on which a file stopped its worker alone before it is quarantined (review r2)


def _quarantine_loader(path: str, base_dir: Path, category: str, reason: str) -> str:
    """Move a sorted report file the loader cannot load to quarantine/loader/<report>/, with a note of why (kept for an
    analyst, not tried again on every run). Returns where it went, relative to the data folder."""
    q = Path(base_dir) / "quarantine" / LOADER_QUARANTINE / category
    q.mkdir(parents=True, exist_ok=True)
    src = Path(path)
    try:                                   # where it must go back to, under its own name (never the quarantine's name)
        home = str(src.relative_to(base_dir))
    except ValueError:
        home = f"sorting_backup/{category}/{src.name}"
    dst = q / src.name
    if dst.exists():
        dst = q / f"{int(time.time())}-{src.name}"
    shutil.move(str(src), str(dst))
    renamed = (f" It is kept here as {dst.name} because a file of that name was quarantined before: give it back its "
               f"own name, {src.name}, when you move it back (under another name it would be loaded as another report "
               f"file, its rows stored twice).") if dst.name != src.name else ""
    dst.with_name(dst.name + ".reason.txt").write_text(
        f"{time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}  not loaded whole: {reason}.\n"
        f"Some of its rows may already be stored in MongoDB (those written before the loader stopped); the others are "
        f"not.\n"
        f"To try it again (for example on a computer with more memory, or with fewer WORKERS), move it back to\n"
        f"  {home}\n"
        f"in the data folder: the next run loads it again, and the rows already stored are skipped.{renamed}\n",
        encoding="utf-8")
    return str(dst.relative_to(base_dir))


def load_into_mongo(s: Settings, stats: Counter) -> None:
    from pymongo import UpdateOne
    from pymongo.errors import ConnectionFailure

    if not s.sorting_dir.is_dir():
        log.warning("Nothing to load: %s does not exist", s.sorting_dir)
        return
    t0 = time.monotonic()
    client = mongo_client(s.mongo, serverSelectionTimeoutMS=10000)
    client.admin.command("ping")
    db = client[s.mongo_db]
    journal = Journal(s.journal_path)
    retry = journal.pending()
    if retry:
        log.info("Resuming %d file(s) from an interrupted run", len(retry))
    crashed_before = journal.crash_names()

    root = str(s.sorting_dir)
    # rows dated before the last quarterly purge's cutoff were deleted on purpose: their files are never loaded again
    # (a sorted copy still on disk, a mailbox fetched again; quarterly_purge.py)
    purged = quarterly_purge.purged_before(s.base_dir)
    tasks = []  # (size, category, path, filename)
    known_fields: dict[str, set] = {}
    categories = []
    for c in sorted(os.listdir(root)):
        if not os.path.isdir(os.path.join(root, c)):
            continue
        if not report_names.valid(c):              # a folder left by an older version: never a collection name
            report_names.quarantine(os.path.join(root, c), s.base_dir, c)
            log.warning("[QUARANTINE] folder %s: %s. Moved to quarantine/%s/", c, report_names.why(c), report_names.FOLDER)
            stats["reports_quarantined"] += 1
            continue
        categories.append(c)

    for category in categories:
        before = len(tasks)
        try:                                       # one report that fails is logged; the others still load
            cat_path = os.path.join(root, category)
            coll = db[category]
            coll.create_index(ROW_INDEX, unique=True)
            # one host's rows by address and day (the Abused or Compromised look-up; speed review 2026-11-15: without it
            # a look-up read every row of the week). Only rows that have an address are in it.
            coll.create_index(HOST_INDEX, name="ip_filename", partialFilterExpression={"ip": {"$exists": True}})
            loaded = loaded_filenames(coll)
            files_coll = db[f"files_{category}"]
            registered = {d.get("filename") for d in files_coll.find({}, {"filename": 1, "_id": 0})}
            new_file_docs = []
            cat_seen = cat_new = 0
            prints = journal.fingerprints(category)
            empties = journal.empties(category)
            remember = []
            for r, _, files in os.walk(cat_path):
                for fn in files:
                    p = os.path.join(r, fn)
                    cat_seen += 1
                    if fn not in registered:
                        new_file_docs.append({"filename": fn, "category": category, "path": p})
                        registered.add(fn)
                    if fn not in loaded and fn in empties and (category, fn) not in retry:
                        # loaded before with no row to store: not again, unless the file changed since
                        try:
                            again, _fp = changed_since_load(p, empties[fn])
                        except OSError:
                            again = True
                        if not again:
                            stats["files_already_loaded"] += 1
                            continue
                    changed = False
                    back = (prints.get(fn) or (None, None, None))[2] == QUARANTINED_PART
                    if back and (category, fn) not in retry:
                        # moved back from quarantine/loader/: it may have rows stored from before it stopped the loader,
                        # so its name is in MongoDB, but it was never loaded whole (review r2: it counted as loaded and its
                        # other rows were never stored). Loaded again; the rows already stored are skipped.
                        log.warning("[LOAD] %s/%s is back from quarantine/%s/: loaded again (rows stored before it was "
                                    "quarantined are skipped)", category, fn, LOADER_QUARANTINE)
                    elif fn in loaded and (category, fn) not in retry:
                        try:
                            changed, fp = changed_since_load(p, prints.get(fn))
                        except OSError:
                            changed, fp = False, None
                        if not changed:
                            if fp is not None:
                                remember.append((category, fn, *fp))
                            stats["files_already_loaded"] += 1
                            continue
                    if quarterly_purge.is_purged(fn, purged):
                        stats["files_purged_not_loaded"] += 1
                        continue
                    if changed:
                        # the same name with other content (a report sent again): loaded again; its rows already
                        # stored are refused by the unique index, the new ones are added. Remembered once loaded.
                        stats["files_reloaded"] += 1
                        stats["reloaded_names"] = [*stats.get("reloaded_names", []), f"{category}/{fn}"]
                        log.warning("[RELOAD] %s/%s changed on disk since it was loaded (sent again under the same "
                                    "name): loaded again, rows already stored are skipped", category, fn)
                    if fn.lower().endswith((".csv", ".json")):
                        try:
                            size = os.path.getsize(p)
                        except OSError:
                            size = 0
                        tasks.append((size, category, p, fn))
                        cat_new += 1
            if remember:
                journal.remember(remember)
            detail("[SCAN] %-40s %5d file(s): %5d already in MongoDB, %5d to load",
                   category, cat_seen, cat_seen - cat_new, cat_new)
            if new_file_docs:
                files_coll.insert_many(new_file_docs, ordered=False)
                stats["files_registered"] += len(new_file_docs)
            known_fields[category] = {
                d.get("field_name") for d in db[f"discovered_fields_{category}"].find({}, {"field_name": 1, "_id": 0})
            }
        except ConnectionFailure:                  # MongoDB itself is gone: that stops the run, as before
            raise
        except Exception as exc:                   # noqa: BLE001
            del tasks[before:]
            stats["reports_failed"] += 1
            log.error("[SCAN] %s not loaded this run: %s (the other reports carry on)", category, exc)

    log.info("Load: %d categories, %d file(s) to load, %d already in MongoDB (scan %.1fs)",
             len(categories), len(tasks), stats["files_already_loaded"], time.monotonic() - t0)
    if not tasks:
        journal.close()
        client.close()
        return

    tasks.sort(key=lambda t: t[0], reverse=True)  # big files first -> better load balancing
    journal.add_many((c, fn) for _, c, _, fn in tasks)

    def record_fields(category: str, headers) -> None:
        if not headers:
            return
        known = known_fields.setdefault(category, set())
        new = list(dict.fromkeys(h for h in headers if h not in known))
        if not new:
            return
        db[f"discovered_fields_{category}"].bulk_write([
            UpdateOne({"category": category, "field_name": h},
                      {"$setOnInsert": {"category": category, "field_name": h}}, upsert=True)
            for h in new
        ], ordered=False)
        known.update(new)

    total = len(tasks)
    done_count = 0
    last_report = time.monotonic()
    t_load = time.monotonic()
    pending_iter = iter(tasks)
    log_level = log.getEffectiveLevel()

    def handle(task, fut) -> None:
        """One finished load: its counts, its journal entry. Raises BrokenProcessPool when its worker process died."""
        nonlocal done_count
        _, category, path, fn = task
        try:
            res = fut.result()
        except BrokenProcessPool:
            raise
        except Exception as exc:  # noqa: BLE001  (stays in journal -> retried)
            done_count += 1
            stats["file_errors"] += 1
            log.error("[LOAD %d/%d] FAILED %s/%s: %s (will retry next run)",
                      done_count, total, category, fn, exc)
            return
        done_count += 1
        if (category, fn) in crashed_before:     # it stopped its worker on an earlier run, and loaded now: count cleared
            journal.forget_crashes(category, fn)
            crashed_before.discard((category, fn))
        # rows that could not be written (not duplicates: invalid documents, write errors) make the file
        # an error for the run, its exit code and the platform's bell, and it stays in the journal, so
        # the next run tries it again (its rows already stored are skipped as duplicates). External
        # review, 2026-11-14: such a file was marked done, never retried, and the run reported fine.
        if res["failed"]:
            stats["files_rows_failed"] += 1
        else:
            journal.done(category, fn)
            if res.get("sha256"):
                journal.remember([(category, fn, res["size"], res["mtime_ns"], res["sha256"])])
                if not res["inserted"] and not res["duplicates"]:      # nothing of it in MongoDB: not read again
                    journal.remember_empty([(category, fn, res["size"], res["mtime_ns"], res["sha256"])])
                else:
                    journal.forget_empty(category, fn)
        record_fields(category, res["headers"])
        stats["files_loaded"] += 1
        for k in ("rows", "inserted", "duplicates", "failed"):
            stats[f"rows_{k}"] += res[k]
        stats["rows_bad_timestamp"] += res.get("bad_timestamp", 0)
        # every row read, and where it went (count audit 2026-11-26): read = inserted + already in
        # DB + same row again in the file + same hash, other row + bad timestamp + unreadable CSV + failed
        stats["rows_read"] += res.get("rows_read", 0)
        for k in ("same_in_file", "same_hash", "no_time", "extra_columns", "bad_csv"):
            stats[f"rows_{k}"] += res.get(k, 0)
        stats["files_bytes_replaced"] += res.get("replaced", 0)
        extra = []
        if res["duplicates"]:
            extra.append(f"{res['duplicates']:,} already in DB")
        if res.get("same_in_file"):
            extra.append(f"{res['same_in_file']:,} repeated in the file (stored once)")
        if res.get("same_hash"):
            extra.append(f"{res['same_hash']:,} NOT stored: same row hash as another row of the file")
        if res.get("no_time"):
            extra.append(f"{res['no_time']:,} without a timestamp (stored, not shown on any page)")
        if res.get("bad_timestamp"):
            extra.append(f"{res['bad_timestamp']:,} bad timestamp skipped")
        if res.get("bad_csv"):
            extra.append(f"{res['bad_csv']:,} NOT stored: could not be read as CSV")
        if res["failed"]:
            extra.append(f"{res['failed']:,} FAILED, the file is tried again next run")
        detail("[LOAD %d/%d] %s/%s: %s rows inserted%s (%.1fs)", done_count, total, category,
               fn, f"{res['inserted']:,}", f", {', '.join(extra)}" if extra else "",
               res.get("seconds", 0))
        for note in res["notes"]:
            log.warning("%s/%s: %s", category, fn, note)

    def pool_pass(pending, workers: int, window: int) -> list:
        """Load the tasks of `pending` in a pool of `workers` processes, `window` handed over at a time. Returns [] when
        all were answered, or the tasks in flight when a worker process died (BrokenProcessPool: out of memory, a
        crash): that pool is given up, the tasks not handed over yet stay in `pending`."""
        nonlocal last_report
        futures: dict = {}
        lost: list = []
        stop_now = False
        pool = ProcessPoolExecutor(max_workers=workers, initializer=_init_worker,
                                   initargs=(s.mongo, s.mongo_db, log_level))

        def submit_next() -> bool:
            task = next(pending, None)
            if task is None:
                return False
            _, category, path, fn = task
            try:
                futures[pool.submit(load_file, category, path, fn, s.insert_chunk)] = task
            except BrokenProcessPool:
                lost.append(task)
                raise
            return True

        try:
            for _ in range(window):
                if not submit_next():
                    break
            while futures:
                finished, _ = wait(futures, timeout=5, return_when=FIRST_COMPLETED)
                for fut in finished:
                    task = futures.pop(fut)
                    try:
                        handle(task, fut)
                    except BrokenProcessPool:
                        lost.append(task)
                        raise
                    submit_next()
                now = time.monotonic()
                if now - last_report >= 10 or not futures:
                    rate = stats["rows_inserted"] / max(now - t_load, 1e-6)
                    log.info("  %d/%d files | %s rows inserted | %.0f rows/s",
                             done_count, total, f"{stats['rows_inserted']:,}", rate)
                    last_report = now
        except BrokenProcessPool:
            # the loads that did finish before the pool broke are counted; the others were in flight
            for fut, task in list(futures.items()):
                if fut.done() and not fut.cancelled() and not isinstance(fut.exception(), BrokenProcessPool):
                    handle(task, fut)
                else:
                    lost.append(task)
            return lost
        except KeyboardInterrupt:
            log.error("Load interrupted; unfinished files will be resumed on the next run")
            stop_now = True
            raise
        finally:
            pool.shutdown(wait=not stop_now, cancel_futures=True)
        return []

    try:
        # A worker process that dies (the kernel ends it when memory runs out, or a crash) used to stop the whole load,
        # and the same file stopped it again on every run (audit 2026-11-27). Now the files in flight then are set
        # aside, a new pool carries on with the others, and each set-aside file is then loaded ALONE. One that stops its
        # worker even then is a file error of this run, kept in the journal and tried again next run (the kernel picks
        # the process it ends by the machine's memory, not by file: review r2); when it stops its worker alone on a
        # second run too, it is moved to quarantine/loader/ (counted, named in the bell), the others load.
        suspects: list = []
        lost = pool_pass(pending_iter, s.workers, s.workers * 2)
        while lost:
            suspects += lost
            log.error("[LOAD] a loader process stopped (out of memory, or a crash) while loading %s: tried again one "
                      "at a time once the others are loaded", ", ".join(f"{c}/{fn}" for _, c, _, fn in lost))
            lost = pool_pass(pending_iter, s.workers, s.workers * 2)
        for task in suspects:
            if not pool_pass(iter([task]), 1, 1):
                continue
            _, category, path, fn = task
            runs = journal.crashed_alone(category, fn)
            if runs < CRASH_RUNS:
                stats["file_errors"] += 1                 # stays in the journal: tried again next run
                log.error("[LOAD] FAILED %s/%s: it stopped the loader's worker process even alone (out of memory, or a "
                          "crash); tried again next run, and moved to quarantine/%s/ if it stops it again then "
                          "(rows it stored before are kept)", category, fn, LOADER_QUARANTINE)
                continue
            where = _quarantine_loader(path, s.base_dir, category,
                                       f"the loader's worker process stopped while loading this file alone on {runs} "
                                       "separate runs (it ran out of memory, or crashed), so it would stop every run")
            # a fingerprint no file has: moved back, it is loaded again although its name is in MongoDB (review r2)
            journal.remember([(category, fn, -1, -1, QUARANTINED_PART)])
            journal.forget_empty(category, fn)
            journal.forget_crashes(category, fn)
            journal.done(category, fn)
            stats["files_crashed"] += 1
            stats["crashed_names"] = [*stats.get("crashed_names", []), f"{category}/{fn}"]
            log.error("[LOAD] %s/%s stopped the loader's worker process even alone, on %d runs: moved to %s, not loaded "
                      "whole (rows it stored before it stopped may be in MongoDB)", category, fn, runs, where)
    finally:
        journal.close()
        client.close()

    log.info("Load: %d files, %s rows read: %s inserted, %s already in MongoDB, %s repeated in the same file, %s with "
             "the same row hash as another row (not stored), %d with a bad timestamp (not stored), %d unreadable as CSV "
             "(not stored), %d failed in %d file(s) tried again next run | %s without a timestamp | %d file(s) loaded "
             "again (changed) | %d file errors | %d file(s) quarantined (stopped the loader) (%.1fs)",
             stats["files_loaded"], f"{stats['rows_read']:,}", f"{stats['rows_inserted']:,}",
             f"{stats['rows_duplicates']:,}", f"{stats['rows_same_in_file']:,}", f"{stats['rows_same_hash']:,}",
             stats["rows_bad_timestamp"], stats["rows_bad_csv"], stats["rows_failed"], stats["files_rows_failed"],
             f"{stats['rows_no_time']:,}", stats["files_reloaded"], stats["file_errors"], stats["files_crashed"],
             time.monotonic() - t0)


# --------------------------------------------------------------------------- check

def run_checks(s: Settings) -> int:
    results: list[tuple[str, str, str]] = []

    def add(status, name, detail=""):
        results.append((status, name, detail))

    # config
    if s.env_file.is_file():
        mode = s.env_file.stat().st_mode & 0o777
        add("OK" if mode & 0o077 == 0 else "WARN", "config file", f"{s.env_file} (mode {mode:o})")
    else:
        add("FAIL", "config file", f"{s.env_file} not found (copy .env.example to .env)")
    provider = (os.environ.get("MAIL_PROVIDER") or "imap").lower()
    need = {"imap": ("IMAP_SERVER", "IMAP_USER", "IMAP_PASSWORD"),
            "gmail_api": ("GMAIL_SERVICE_ACCOUNT_FILE", "GMAIL_USER"),
            "microsoft_graph": ("MS_TENANT_ID", "MS_CLIENT_ID", "MS_CLIENT_SECRET", "MS_MAILBOX")}.get(provider, ())
    mongo_keys = ("MONGO_USER", "MONGO_PASSWORD")
    if (os.environ.get("MONGO_LOCAL") or "true").lower() == "false" and not os.environ.get("MONGO_USER"):
        mongo_keys = ()          # a MongoDB used as it is, without access control (warned about by install.sh)
    missing = [k for k in (*need, *mongo_keys) if not os.environ.get(k)]
    add("FAIL" if missing else "OK", "required settings", ", ".join(missing) + " missing" if missing else "all present")

    # python deps
    try:
        import pymongo
        import requests
        add("OK", "python packages", f"pymongo {pymongo.version}, requests {requests.__version__}")
    except ImportError as exc:
        add("FAIL", "python packages", f"{exc} (run ./deploy.sh)")
        return _print_results(results)

    # data dirs
    for d in (s.attachments_dir, s.unzipped_dir, s.sorting_dir):
        if d.is_dir() and os.access(d, os.W_OK):
            add("OK", f"dir {d.name}", str(d))
        else:
            add("WARN", f"dir {d.name}", f"{d} missing or not writable (created on first run)")

    # memory
    try:
        mem = {l.split(":")[0]: int(l.split()[1]) for l in open("/proc/meminfo") if ":" in l}
        total_gb, avail_gb = mem["MemTotal"] / 2**20, mem["MemAvailable"] / 2**20
        add("OK" if avail_gb > s.mongo_cache_gb + 2 else "WARN", "memory",
            f"{avail_gb:.1f} GB available of {total_gb:.1f} GB; workers={s.workers}")
    except Exception:  # noqa: BLE001
        pass

    # mongo
    from pymongo.errors import OperationFailure, PyMongoError
    try:
        client = mongo_client(s.mongo, serverSelectionTimeoutMS=5000)
        info = client.server_info()
        client.admin.command("ping")
        add("OK", "mongodb connection", f"{s.mongo['host']}:{s.mongo['port']} v{info.get('version')}, auth ok")
        try:
            status = client.admin.command("serverStatus")
            cache_gb = status["wiredTiger"]["cache"]["maximum bytes configured"] / 2**30
            ok = cache_gb <= s.mongo_cache_gb * 1.05
            add("OK" if ok else "WARN", "mongodb cache size",
                f"{cache_gb:.2f} GB (expected <= {s.mongo_cache_gb} GB)")
        except (OperationFailure, KeyError) as exc:
            add("WARN", "mongodb cache size", f"could not read: {exc}")

        db = client[s.mongo_db]
        names = set(db.list_collection_names())
        # the pipeline's own bookkeeping (lg_*: lg_load_stamps) is not a report: no row index, no row shape (a fresh
        # installation, 2026-11-19, failed its check on it)
        services = sorted(n for n in names if not n.startswith(("files_", "discovered_fields_", "system.", "lg_")))
        add("OK", f"database '{s.mongo_db}'", f"{len(services)} service collection(s)")
        bad_index, bad_shape, total_docs = [], [], 0
        for name in services:
            coll = db[name]
            idx = coll.index_information().values()
            if not any(i.get("unique") and list(i["key"]) == ROW_INDEX for i in idx):
                bad_index.append(name)
            total_docs += coll.estimated_document_count()
            sample = coll.find_one({"line_hash": {"$exists": True}}) or coll.find_one()
            if sample is not None:
                if not all(k in sample for k in ("filename", "category", "line_hash")) or sample.get("category") != name:
                    bad_shape.append(name)
                elif sample.get("timestamp") and "extracted_date" in sample \
                        and not isinstance(sample["extracted_date"], dt.datetime):
                    bad_shape.append(name)
        add("FAIL" if bad_index else "OK", "unique index (filename, category, line_hash)",
            f"missing on: {', '.join(bad_index)}" if bad_index else f"present on all {len(services)}")
        add("FAIL" if bad_shape else "OK", "document structure",
            f"unexpected shape in: {', '.join(bad_shape)}" if bad_shape else "filename/category/line_hash/extracted_date OK")
        add("OK", "documents", f"{total_docs:,} rows across service collections")
        if s.sorting_dir.is_dir():
            on_disk = {e.name for e in os.scandir(s.sorting_dir) if e.is_dir()}
            not_loaded = sorted(on_disk - set(services))
            add("WARN" if not_loaded else "OK", "services loaded",
                f"not yet in MongoDB: {', '.join(not_loaded[:10])}{' ...' if len(not_loaded) > 10 else ''}"
                if not_loaded else f"all {len(on_disk)} service folders present")
        client.close()
    except PyMongoError as exc:
        add("FAIL", "mongodb connection", f"{exc.__class__.__name__}: {str(exc)[:200]}")

    # journal
    if s.journal_path.exists():
        try:
            j = Journal(s.journal_path)
            n = len(j.pending())
            j.close()
            add("WARN" if n else "OK", "interrupted loads", f"{n} file(s) will be resumed" if n else "none")
        except sqlite3.Error as exc:
            add("WARN", "interrupted loads", str(exc))

    # mailbox (IMAP, Gmail API or Microsoft Graph)
    try:
        add("OK", f"mailbox ({provider})", mail_sources.test_source(os.environ, 1))
    except Exception as exc:  # noqa: BLE001
        add("FAIL", f"mailbox ({provider})", str(exc)[:300])

    return _print_results(results)


def _print_results(results) -> int:
    width = max(len(n) for _, n, _ in results)
    for status, name, detail in results:
        print(f"[{status:>4}] {name:<{width}}  {detail}")
    failed = sum(1 for st, _, _ in results if st == "FAIL")
    warned = sum(1 for st, _, _ in results if st == "WARN")
    print(f"\n{len(results)} checks: {failed} failed, {warned} warning(s)")
    return 1 if failed else 0


# --------------------------------------------------------------------------- main

def fetch_reports(s: Settings, stats: Counter, refetch: bool = False) -> None:
    """Get the reports the way REPORT_SOURCE says (report_api.py): "email" reads the mailbox, "api" asks Shadowserver's
    report API. When the chosen way cannot be used this run and the other one is set up, the run uses the other one
    and says why; the next run tries the chosen way again. Runs on the pipeline's own schedule either way."""
    env = os.environ
    chosen = report_api.source(env)
    have_api, have_mail = bool(report_api.creds(env)), report_api.mail_configured(env)

    def by_api():
        report_api.pull(s.base_dir, s.attachments_dir, s.days, s.download_threads, stats, log, env, refetch,
                        max_mb=max(1, s.zip_limits.max_unpacked // 2**20))

    def by_mail():
        pull_emails(s, stats, refetch=refetch)

    first, second = (by_api, by_mail) if chosen == "api" else (by_mail, by_api)
    second_ok = have_mail if chosen == "api" else have_api
    names = ("Shadowserver API", "e-mail") if chosen == "api" else ("e-mail", "Shadowserver API")
    log.info("Reports: %s (REPORT_SOURCE=%s)%s", names[0], chosen,
             f"; {names[1]} is the fallback" if second_ok else "")
    try:
        first()
        return
    except (report_api.ApiError, imaplib.IMAP4.error, OSError, mail_sources.MailSourceError) as exc:
        stats["email_failed" if chosen == "email" else "api_unusable"] += 1
        if chosen == "email":                         # why, in a few words, for the bell and the Task monitor (2026-11-26)
            stats["email_error"] = getattr(exc, "reason", "") or "the mailbox could not be read"
        if not second_ok:
            log.error("%s failed: %s (continuing with files already on disk; no other way is set up)", names[0], exc)
            return
        log.error("%s failed: %s; this run uses the %s instead", names[0], exc, names[1])
    try:
        second()
        stats["fallback_used"] += 1
    except (report_api.ApiError, imaplib.IMAP4.error, OSError, mail_sources.MailSourceError) as exc:
        log.error("%s failed too: %s (continuing with files already on disk)", names[1], exc)


def prune_sorted_backup(s: Settings, stats: Counter) -> None:
    """SORTED_KEEP_DAYS: remove sorted copies older than that whose rows are in MongoDB (retention.py). Never stops a run."""
    days = retention.keep_days(_env)
    if not days:
        return
    try:
        client = mongo_client(s.mongo, serverSelectionTimeoutMS=10000)
        client.admin.command("ping")
        db = client[s.mongo_db]
        pending, empty = set(), {}
        if s.journal_path.exists():
            j = Journal(s.journal_path); pending = j.pending(); empty = j.empty_names()
            # a file moved back from quarantine/loader/ and not loaded whole yet: its name is in MongoDB (rows it stored
            # before it stopped the loader), but its sorted copy is the only copy of its other rows: kept, as pending
            pending |= j.not_loaded_whole(); j.close()

        purged = quarterly_purge.purged_before(s.base_dir)

        class _Done(set):
            """The loaded files, and those whose rows the quarterly purge deleted (their sorted copies can go too)."""
            def __contains__(self, fn):
                return set.__contains__(self, fn) or quarterly_purge.is_purged(fn, purged)

        def loaded_of(report):
            # the files loaded with no row to store (the journal's `empty` table) are loaded too, although MongoDB has
            # nothing of them: without them their sorted copies were never removed (review r2)
            return _Done(loaded_filenames(db[report]) | empty.get(report, set())) if report_names.valid(report) else None
        n, size = retention.prune_sorted(str(s.sorting_dir), str(s.base_dir), days, loaded_of, pending, log)
        stats["retention_files"] += n; stats["retention_bytes"] += size
    except Exception as exc:  # noqa: BLE001
        log.warning("[RETENTION] skipped this run: %s", exc.__class__.__name__)


def hold_run_lock(path) -> int | None:
    """One run at a time, on the folder's run lock (.pipeline.lock, the one run.sh and bin/shadowserver take with flock
    and the platform's job_schedule.py looks at). Returns the descriptor that holds it, or None when another run holds
    it. A run started by run.sh already holds it through the descriptor it inherited: that one is used (flock on the same
    open file is this run's own lock). Audit 2026-11-27: only run.sh took it, so the script started by itself (cron, by
    hand) could run beside another run.
    run.sh says which descriptor it is (LG_RUN_LOCK_FD=9); without that, the open descriptors are looked through
    (/proc/self/fd). The lock file is opened read-only and is readable by others (0644, as run.sh's own; review r2):
    flock needs no write access, so the platform (another Linux user) can open it to see that a run is busy, and a lock
    file left by a run as root (sudo ./run.sh) no longer makes every later run fail."""
    path = str(path)
    try:
        want = os.stat(path, follow_symlinks=False)
    except OSError:
        want = None

    def same_file(fd) -> bool:
        try:
            st = os.fstat(fd)
        except OSError:
            return False
        return want is not None and (st.st_dev, st.st_ino) == (want.st_dev, want.st_ino)

    def take(fd) -> bool:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return True
        except OSError:
            return False

    told = (os.environ.get("LG_RUN_LOCK_FD") or "").strip()
    if told.isdigit() and same_file(int(told)) and take(int(told)):
        return int(told)
    if want is not None and os.path.isdir("/proc/self/fd"):
        for name in os.listdir("/proc/self/fd"):
            try:
                fd = int(name)
            except ValueError:
                continue
            if same_file(fd) and take(fd):
                return fd
    fd = os.open(path, os.O_RDONLY | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0), 0o644)
    try:
        st = os.fstat(fd)
        if st.st_uid == os.geteuid() and st.st_mode & 0o777 != 0o644:
            os.fchmod(fd, 0o644)            # the run's umask (077) left it 0600: readable by the platform again
    except OSError:
        pass
    if not take(fd):
        os.close(fd)
        return None
    return fd


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--stage", choices=("all", "email", "load"), default="all")
    ap.add_argument("--check", action="store_true", help="verify setup and exit")
    ap.add_argument("--test-mail", action="store_true", help="only log in to the mailbox, count recent messages, exit")
    ap.add_argument("--all", action="store_true", help="handle every e-mail of the period again, also those done earlier")
    ap.add_argument("--days", type=int, help="pull e-mails received in the last N days (default EMAIL_DAYS or 7)")
    ap.add_argument("--workers", type=int, help="parallel loader processes (default WORKERS, else 6 or the processor cores when fewer)")
    ap.add_argument("--env-file", default=str(PROJECT_DIR / ".env"))
    ap.add_argument("-v", "--verbose", action="store_true", help="also show skipped files and debug info")
    ap.add_argument("-q", "--quiet", action="store_true", help="summary lines only (no per-file lines)")
    args = ap.parse_args(argv)
    # everything this run writes (reports, attachments, quarantine, state, logs) is for this account only: the
    # reports name constituents' hosts, and other users of the machine could read them (external review, 2026-11-12)
    os.umask(0o077)

    global DETAIL
    if args.quiet:
        DETAIL = logging.DEBUG

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)-7s %(message)s")
    logging.getLogger("pymongo").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    if not (args.check or args.test_mail):
        # a run (any stage) changes the folder: one at a time, also when this script is started without run.sh
        try:
            run_lock = hold_run_lock(quarterly_purge.RUN_LOCK)
        except OSError as exc:
            log.error("The run lock %s could not be taken (%s): exiting.", quarterly_purge.RUN_LOCK, exc)
            return 1
        if run_lock is None:
            log.error("Another pipeline run is in progress - exiting.")
            return 1
    if args.stage in ("all", "email") and not (args.check or args.test_mail):
        # Settings → Workers: the platform's requests (settings, API key, releases), checked again and applied to this
        # pipeline's own .env and quarantine before anything else, so this run already uses them (worker_settings.py)
        try:
            env_file = Path(args.env_file).expanduser().resolve()
            pre = worker_settings.read_env(env_file)
            base = Path(pre.get("DATA_DIR") or PROJECT_DIR).expanduser().resolve()
            worker_settings.apply_requests(worker_settings.find_platform_data(PROJECT_DIR, pre), env_file, base, log)
        except Exception as exc:  # noqa: BLE001  (never stops the run)
            log.warning("Settings → Workers requests could not be applied this run: %s", exc)
    s = load_settings(args)

    if args.check:
        return run_checks(s)
    if args.test_mail:
        try:
            print("OK: " + mail_sources.test_source(os.environ, args.days or 1))
            return 0
        except Exception as exc:  # noqa: BLE001
            print(f"FAIL: {exc}")
            return 1

    stats: Counter = Counter()
    t0 = time.monotonic()
    failed = False
    try:
        if args.stage in ("all", "email"):
            fetch_reports(s, stats, refetch=args.all)
            unzip_and_sort(s, stats)
        if args.stage in ("all", "load"):
            load_into_mongo(s, stats)
            prune_sorted_backup(s, stats)
            # the quarterly purge, on its day only and with Looking Glass's permit; never stops the run (quarterly_purge.py)
            quarterly_purge.run_safely(lambda: mongo_client(s.mongo, serverSelectionTimeoutMS=10000)[s.mongo_db],
                                       worker_settings.find_platform_data(PROJECT_DIR), s.base_dir, log)
    except BaseException:
        failed = True
        raise
    finally:
        # what the platform's bell shows: when this run finished, whether it went well, and the free disk (retention.py)
        errors, warnings = run_problems(stats)
        st = retention.status(str(s.base_dir), not failed and not errors,
                              stats, retention.min_free_gb(_env), problems=(errors, warnings))
        if st["disk_low"]:
            log.warning("[DISK] only %.1f GB free where the reports are kept (warning below %g GB, DISK_MIN_FREE_GB)",
                        st["free_gb"], st["min_free_gb"])
        for e in errors:
            log.error("[RUN] %s", e["text"])
        for w in warnings:
            log.warning("[RUN] %s", w["text"])
    log.info("Done in %.1fs", time.monotonic() - t0)
    return 1 if run_errors(stats) else 0


def _n(stats, key) -> int:
    try:
        return int(stats.get(key, 0) or 0)
    except (TypeError, ValueError):
        return 0


def _names(items, total, noun) -> str:
    """'a, b and c' or 'a, b, c (the first 3 of 9 <noun>; all in the pipeline log)': never cut without saying so."""
    items = [str(x) for x in items][:20]
    if not items:
        return ""
    shown = ", ".join(items)
    return shown if total <= len(items) else f"{shown} (the first {len(items)} of {total:,} {noun}; all in the pipeline log)"


def run_problems(stats) -> tuple[list, list]:
    """(errors, warnings) of a run: [{"key", "count", "text"}]. Errors make the run fail (exit code 1, "had problems"
    in Settings → Task monitor and the bell): a report, a file or rows not loaded this run. Warnings: loaded, but
    something an administrator should look at. Count audit, 2026-11-26: before, only file errors, files with failed
    rows and an unreadable mailbox counted, so a run that left whole reports out reported "ok". One text for the status
    file, the Task monitor and the bell (they show it as it is)."""
    errors, warnings = [], []

    def add(to, key, count, text):
        if count:
            to.append({"key": key, "count": int(count), "text": text})

    n = lambda k: _n(stats, k)  # noqa: E731
    add(errors, "file_errors", n("file_errors"),
        f"{n('file_errors'):,} file(s) could not be loaded (tried again next run)")
    add(errors, "files_rows_failed", n("files_rows_failed"),
        f"{n('rows_failed'):,} row(s) not written in {n('files_rows_failed'):,} file(s), tried again next run")
    if n("email_failed"):
        why = str(stats.get("email_error") or "")[:120]
        add(errors, "email_failed", n("email_failed"),
            f"the mailbox could not be read ({why})" if why else "the mailbox could not be read")
    if n("api_unusable") and not n("fallback_used"):
        add(errors, "api_unusable", n("api_unusable"),
            "the Shadowserver API could not be used, and no other way of getting the reports worked this run")
    add(errors, "api_failed", n("api_failed"),
        f"{n('api_failed'):,} report(s) could not be downloaded from the Shadowserver API (tried again next run)")
    add(errors, "api_list_full", n("api_list_full"),
        f"the Shadowserver API's list reached its limit on {n('api_list_full'):,} day(s), so reports may be missing "
        "(raise REPORT_API_LIST_LIMIT in the pipeline's .env)")
    add(errors, "emails_not_fetched", n("emails_not_fetched"),
        f"{n('emails_not_fetched'):,} e-mail(s) in the mailbox could not be fetched this run (tried again next run)")
    cr = n("files_crashed")
    if cr:
        add(errors, "files_crashed", cr,
            f"{cr:,} report file(s) stopped the loader's worker process even when loaded alone, on {CRASH_RUNS} separate "
            f"runs (out of memory, or a crash) and were moved to quarantine/{LOADER_QUARANTINE}/: not loaded whole (some "
            f"of their rows may already be stored; moved back, a file is loaded again and those rows are skipped): "
            f"{_names(stats.get('crashed_names') or [], cr, 'files')}")
    add(errors, "attachments_failed", n("attachments_failed"),
        f"{n('attachments_failed'):,} e-mail attachment(s) could not be saved (fetched again next run)")
    add(errors, "links_failed", n("links_failed"),
        f"{n('links_failed'):,} report link(s) could not be downloaded (tried again next run)")
    add(errors, "zips_failed", n("zips_failed"),
        f"{n('zips_failed'):,} zip file(s) could not be unpacked (tried again next run)")
    add(errors, "zips_refused", n("zips_refused"),
        f"{n('zips_refused'):,} zip file(s) were not unpacked and were moved to quarantine (a limit, or a file that "
        "cannot be unpacked): their reports are not loaded")
    add(errors, "zips_bad_deleted", n("zips_bad_deleted"),
        f"{n('zips_bad_deleted'):,} broken zip file(s) were deleted and are fetched again where possible: their "
        "reports are not loaded yet")
    q = n("csv_quarantined") + n("reports_quarantined")
    add(errors, "reports_quarantined", q,
        f"{q:,} report file(s) or folder(s) have a name that cannot be a report name and were moved to "
        "quarantine/report-names/: not loaded")
    add(errors, "reports_failed", n("reports_failed"),
        f"{n('reports_failed'):,} report(s) could not be read from the sorted folder and were not loaded this run "
        "(tried again next run)")

    nm = n("csv_not_matched")
    if nm:
        names = _names(stats.get("not_matched_names") or [], nm, "files")
        add(warnings, "csv_not_matched", nm,
            f"{nm:,} CSV file(s) do not have a report file name, so they were not loaded: {names}. Rename them, or "
            "remove them once checked")
    if n("api_unusable") and n("fallback_used"):
        add(warnings, "api_fallback", n("api_unusable"),
            "the Shadowserver API could not be used, so this run read the mailbox instead")
    add(warnings, "emails_gone", n("emails_gone"),
        f"{n('emails_gone'):,} e-mail(s) were deleted or moved out of the reports folder after it was listed and before "
        "they were fetched: not read (they are no longer there to fetch)")
    add(warnings, "api_bad_items", n("api_bad_items"),
        f"{n('api_bad_items'):,} item(s) of the Shadowserver API's list had no usable file name or id and were skipped")
    add(warnings, "rows_bad_timestamp", n("rows_bad_timestamp"),
        f"{n('rows_bad_timestamp'):,} row(s) had a timestamp that could not be read and were not stored")
    add(warnings, "rows_bad_csv", n("rows_bad_csv"),
        f"{n('rows_bad_csv'):,} row(s) could not be read as CSV (a field larger than 16 MB, or a broken line) and were "
        "not stored; the other rows of their files were loaded")
    add(warnings, "rows_same_hash", n("rows_same_hash"),
        f"{n('rows_same_hash'):,} row(s) were not stored: they give the same row hash as another row of their file "
        "(fields joined without their quotes)")
    add(warnings, "rows_no_time", n("rows_no_time"),
        f"{n('rows_no_time'):,} row(s) have no timestamp: they are stored, but no page shows them")
    add(warnings, "rows_extra_columns", n("rows_extra_columns"),
        f"{n('rows_extra_columns'):,} row(s) had more values than their file's header: the extra values were dropped")
    add(warnings, "files_bytes_replaced", n("files_bytes_replaced"),
        f"{n('files_bytes_replaced'):,} file(s) had bytes that are not UTF-8: they were loaded with those bytes replaced")
    rl = n("files_reloaded")
    if rl:
        add(warnings, "files_reloaded", rl,
            f"{rl:,} file(s) changed on disk since they were loaded (sent again under the same name) and were loaded "
            f"again: {_names(stats.get('reloaded_names') or [], rl, 'files')}")
    return errors, warnings


def run_errors(stats) -> int:
    """What makes a run fail (exit code 1, the bell's warning): every error of run_problems, by its count."""
    return sum(e["count"] for e in run_problems(stats)[0])


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
