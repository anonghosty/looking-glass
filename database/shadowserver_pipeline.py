#!/usr/bin/env python3
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
import ssl
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
# replaces "<country>-geo" when a CSIRT's reports are named differently.
def compile_service_re() -> "re.Pattern[str]":
    suffix = os.environ.get("REPORT_SUFFIX") or r"[a-z][a-z0-9_-]*?-geo"
    return re.compile(r"^\d{4}-\d{2}-\d{2}-(.*?)(?:-\d+)?-(?:" + suffix + r")(?:_as\d+)?\.csv$")


SERVICE_RE = compile_service_re()   # compiled again by load_env_file, so REPORT_SUFFIX in .env applies
LINK_RE = re.compile(r'https://dl\.shadowserver\.org/[^\s"<]+')
CD_FILENAME_RE = re.compile(r'filename\*?=(?:UTF-8\'\')?"?([^";]+)"?')

TS_FMT = "%Y-%m-%d %H:%M:%S"
_TS_FAST = re.compile(r"([0-9]{4})-([0-9]{2})-([0-9]{2}) ([0-9]{2}):([0-9]{2}):([0-9]{2})\Z")

ROW_INDEX = [("filename", 1), ("category", 1), ("line_hash", 1)]
_MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")


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
    mongo = {
        "host": _env("MONGO_HOST", "127.0.0.1"),
        "port": int(_env("MONGO_PORT", "27017")),
        "appname": "shadowserver-pipeline",
    }
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
        days=args.days if args.days is not None else int(_env("EMAIL_DAYS", "1")),
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

def _imap_since(days: int) -> str:
    d = dt.date.today() - dt.timedelta(days=days)
    return f"{d.day:02d}-{_MONTHS[d.month - 1]}-{d.year}"  # locale independent


def _fetch_messages(imap, ids, batch_size):
    """Fetch messages in batches (one round trip per batch). BODY.PEEK leaves them unread."""
    for chunk in batched(ids, batch_size):
        id_set = b",".join(chunk).decode()
        typ, data = imap.fetch(id_set, "(BODY.PEEK[])")
        if typ != "OK":
            log.error("IMAP fetch failed for ids %s", id_set)
            continue
        for item in data:
            if isinstance(item, tuple) and len(item) > 1:
                try:
                    yield email.message_from_bytes(item[1])
                except Exception as exc:  # noqa: BLE001
                    log.error("Failed to parse e-mail: %s", exc)


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
    # whose attachment is already on disk (or failed and is retried) needs no link download.
    if new_attachments == 0 and existing_attachments == 0 and failed == 0 and body:
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
    return name or f"download_{hashlib.sha1(url.encode()).hexdigest()[:16]}.bin"


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
                # 2026-11-12: Block silently stopped blocking when the sender log could not be opened)
                src.close()
                raise RuntimeError(f"Block mode is on but the sender check is unavailable ({exc}): no e-mail is read "
                                   "this run, so nothing unchecked is loaded. It is tried again next run.") from exc
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
                 limits: zip_limits.Limits = zip_limits.Limits()) -> str:
    """Extract one zip. Report CSVs go to sorting_backup/<service>/ (overwrite), everything else to
    unzipped_backup/<zipname>/ like before. Everything is unpacked into a .partial folder first, within the limits of
    zip_limits.py (real bytes counted), and only moved into place once the whole zip is unpacked: a zip that breaks
    a limit halfway leaves nothing behind, and is quarantined."""
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
                staged.append((tmp / f".route-{i}", base, m.group(1)))
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
        with ThreadPoolExecutor(max_workers=threads) as pool:
            futures = {pool.submit(_extract_zip, z, s.unzipped_dir, s.sorting_dir, s.zip_limits): z for z in todo}
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

    # Sweep: CSV attachments that arrived un-zipped, plus anything left from older runs.
    tails = report_names.learn_tails(s.sorting_dir)
    for search_dir in (s.unzipped_dir, s.attachments_dir):
        for root, dirs, files in os.walk(search_dir):
            dirs[:] = [d for d in dirs if not d.endswith(".partial")]
            for fn in sorted(files):
                m = SERVICE_RE.match(fn)
                if not m:
                    continue
                rname = report_names.special_name(fn, m.group(1), tails)   # "special-x" loads as special_x
                if not report_names.valid(rname):           # an unusable report name never reaches MongoDB
                    report_names.quarantine(os.path.join(root, fn), s.base_dir, rname)
                    log.warning("[QUARANTINE] %s: %s. Moved to quarantine/%s/", fn, report_names.why(rname),
                                report_names.FOLDER)
                    continue
                service_dir = s.sorting_dir / rname
                service_dir.mkdir(parents=True, exist_ok=True)
                existed = (service_dir / fn).exists()
                move_replace(os.path.join(root, fn), service_dir / fn)
                stats["csv_moved"] += 1
                detail("[%s] %s -> %s", "OVERWRITE" if existed else "MOVE", fn, rname)

    log.info("Unzip: %d extracted (%d report CSVs sorted), %d already done, %d bad deleted, %d quarantined (limits), "
             "%d failed | %d loose CSV moved (%.1fs)", stats["zips_extracted"], stats["csv_sorted"], stats["zips_skipped"],
             stats["zips_bad_deleted"], stats["zips_refused"], stats["zips_failed"], stats["csv_moved"], time.monotonic() - t0)
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
    ``file.read().splitlines()``, so the csv parsing and line_hash are unchanged."""
    info = info if info is not None else {}
    with open(path, "r", encoding="utf-8", errors=errors, newline="") as fh:
        lines = (piece for raw in fh for piece in raw.splitlines())
        reader = csv.DictReader(lines)
        headers = reader.fieldnames
        info["headers"] = list(headers) if headers is not None else None
        if headers is None:
            return
        seen: set[str] = set()
        sha256 = hashlib.sha256
        for row in reader:
            line = ",".join([str(row.get(field, "")) for field in headers])
            line_hash = sha256(line.encode()).hexdigest()
            if line_hash in seen:
                continue
            if None in row:  # more values than headers: the original crashed the whole batch on this
                del row[None]
                info["extra_columns"] = info.get("extra_columns", 0) + 1
            row["filename"] = filename
            row["category"] = category
            row["line_hash"] = line_hash
            if "extracted_date" not in row:
                timestamp_str = row.get("timestamp")
                if timestamp_str:
                    parsed = parse_ts(timestamp_str)
                    if parsed is None:
                        info["bad_timestamp"] = info.get("bad_timestamp", 0) + 1
                        continue
                    row.setdefault("logged_date", format_logged(timestamp_str, parsed))
                    row["extracted_date"] = parsed
            yield row
            seen.add(line_hash)


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
    """Unordered bulk insert. Returns (inserted, duplicates, failed)."""
    from pymongo.errors import AutoReconnect, BulkWriteError, DuplicateKeyError, InvalidDocument

    for attempt in range(5):
        try:
            return len(coll.insert_many(docs, ordered=False).inserted_ids), 0, 0
        except BulkWriteError as exc:
            errs = exc.details.get("writeErrors", [])
            dup = sum(1 for e in errs if e.get("code") == 11000)
            other = [e for e in errs if e.get("code") != 11000]
            if other:
                log.warning("%s: %d write error(s), first: %s", coll.name, len(other), other[0].get("errmsg"))
            return exc.details.get("nInserted", 0), dup, len(other)
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
            wait_s = 2 ** attempt
            log.warning("MongoDB connection issue (%s), retrying in %ss", exc, wait_s)
            time.sleep(wait_s)
    raise RuntimeError("MongoDB unavailable after retries")


def load_file(category: str, path: str, filename: str, chunk: int) -> dict:
    coll = _WORKER_DB[category]
    started = time.monotonic()
    res = {"category": category, "filename": filename, "rows": 0, "inserted": 0,
           "duplicates": 0, "failed": 0, "headers": None, "notes": []}

    def push(docs):
        ins, dup, bad = _insert_docs(coll, docs)
        res["rows"] += len(docs)
        res["inserted"] += ins
        res["duplicates"] += dup
        res["failed"] += bad

    if filename.endswith(".csv"):
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
    elif filename.endswith(".json"):
        try:
            push([json_doc(path, filename, category)])
        except Exception as exc:  # noqa: BLE001  (original: print and skip)
            res["notes"].append(f"JSON error: {exc}")
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
        self.db.commit()

    def pending(self) -> set:
        return set(self.db.execute("SELECT category, filename FROM inflight"))

    def add_many(self, items) -> None:
        self.db.executemany("INSERT OR IGNORE INTO inflight VALUES (?, ?)", items)
        self.db.commit()

    def done(self, category: str, filename: str) -> None:
        self.db.execute("DELETE FROM inflight WHERE category=? AND filename=?", (category, filename))
        self.db.commit()

    def close(self) -> None:
        self.db.close()


def loaded_filenames(coll) -> set:
    """Filenames that already have rows (the original did one find_one per file)."""
    from pymongo.errors import OperationFailure
    try:
        return set(coll.distinct("filename"))
    except OperationFailure:  # >16MB result: fall back to a cursor
        pipeline = [{"$sort": {"filename": 1}}, {"$group": {"_id": "$filename"}}]
        return {d["_id"] for d in coll.aggregate(pipeline, allowDiskUse=True)}


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

    root = str(s.sorting_dir)
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
            loaded = loaded_filenames(coll)
            files_coll = db[f"files_{category}"]
            registered = {d.get("filename") for d in files_coll.find({}, {"filename": 1, "_id": 0})}
            new_file_docs = []
            cat_seen = cat_new = 0
            for r, _, files in os.walk(cat_path):
                for fn in files:
                    p = os.path.join(r, fn)
                    cat_seen += 1
                    if fn not in registered:
                        new_file_docs.append({"filename": fn, "category": category, "path": p})
                        registered.add(fn)
                    if fn in loaded and (category, fn) not in retry:
                        stats["files_already_loaded"] += 1
                        continue
                    if fn.endswith((".csv", ".json")):
                        try:
                            size = os.path.getsize(p)
                        except OSError:
                            size = 0
                        tasks.append((size, category, p, fn))
                        cat_new += 1
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

    with ProcessPoolExecutor(max_workers=s.workers, initializer=_init_worker,
                             initargs=(s.mongo, s.mongo_db, log_level)) as pool:
        futures: dict = {}

        def submit_next() -> bool:
            task = next(pending_iter, None)
            if task is None:
                return False
            _, category, path, fn = task
            futures[pool.submit(load_file, category, path, fn, s.insert_chunk)] = task
            return True

        try:
            for _ in range(s.workers * 2):
                if not submit_next():
                    break
            while futures:
                finished, _ = wait(futures, timeout=5, return_when=FIRST_COMPLETED)
                for fut in finished:
                    _, category, path, fn = futures.pop(fut)
                    done_count += 1
                    try:
                        res = fut.result()
                    except BrokenProcessPool:
                        raise
                    except Exception as exc:  # noqa: BLE001  (stays in journal -> retried)
                        stats["file_errors"] += 1
                        log.error("[LOAD %d/%d] FAILED %s/%s: %s (will retry next run)",
                                  done_count, total, category, fn, exc)
                    else:
                        journal.done(category, fn)
                        record_fields(category, res["headers"])
                        stats["files_loaded"] += 1
                        for k in ("rows", "inserted", "duplicates", "failed"):
                            stats[f"rows_{k}"] += res[k]
                        stats["rows_bad_timestamp"] += res.get("bad_timestamp", 0)
                        extra = []
                        if res["duplicates"]:
                            extra.append(f"{res['duplicates']:,} already in DB")
                        if res.get("bad_timestamp"):
                            extra.append(f"{res['bad_timestamp']:,} bad timestamp skipped")
                        if res["failed"]:
                            extra.append(f"{res['failed']:,} FAILED")
                        detail("[LOAD %d/%d] %s/%s: %s rows inserted%s (%.1fs)", done_count, total, category,
                               fn, f"{res['inserted']:,}", f", {', '.join(extra)}" if extra else "",
                               res.get("seconds", 0))
                        for note in res["notes"]:
                            log.warning("%s/%s: %s", category, fn, note)
                    submit_next()
                now = time.monotonic()
                if now - last_report >= 10 or not futures:
                    rate = stats["rows_inserted"] / max(now - t_load, 1e-6)
                    log.info("  %d/%d files | %s rows inserted | %.0f rows/s",
                             done_count, total, f"{stats['rows_inserted']:,}", rate)
                    last_report = now
        except (KeyboardInterrupt, BrokenProcessPool):
            log.error("Load interrupted; unfinished files will be resumed on the next run")
            pool.shutdown(wait=False, cancel_futures=True)
            raise
        finally:
            journal.close()
            client.close()

    log.info("Load: %d files, %s rows inserted, %s duplicates skipped, %d rows with bad timestamp skipped "
             "(as before), %d failed rows, %d file errors (%.1fs)",
             stats["files_loaded"], f"{stats['rows_inserted']:,}", f"{stats['rows_duplicates']:,}",
             stats["rows_bad_timestamp"], stats["rows_failed"], stats["file_errors"], time.monotonic() - t0)


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
        services = sorted(n for n in names if not n.startswith(("files_", "discovered_fields_", "system.")))
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
        if not second_ok:
            log.error("%s failed: %s (continuing with files already on disk; no other way is set up)", names[0], exc)
            return
        log.error("%s failed: %s; this run uses the %s instead", names[0], exc, names[1])
    try:
        second()
        stats["fallback_used"] += 1
    except (report_api.ApiError, imaplib.IMAP4.error, OSError, mail_sources.MailSourceError) as exc:
        log.error("%s failed too: %s (continuing with files already on disk)", names[1], exc)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--stage", choices=("all", "email", "load"), default="all")
    ap.add_argument("--check", action="store_true", help="verify setup and exit")
    ap.add_argument("--test-mail", action="store_true", help="only log in to the mailbox, count recent messages, exit")
    ap.add_argument("--all", action="store_true", help="handle every e-mail of the period again, also those done earlier")
    ap.add_argument("--days", type=int, help="pull e-mails received in the last N days (default EMAIL_DAYS or 1)")
    ap.add_argument("--workers", type=int, help="parallel loader processes (default WORKERS or 6)")
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
    if args.stage in ("all", "email"):
        fetch_reports(s, stats, refetch=args.all)
        unzip_and_sort(s, stats)
    if args.stage in ("all", "load"):
        load_into_mongo(s, stats)
    log.info("Done in %.1fs", time.monotonic() - t0)
    return 1 if stats["file_errors"] or stats["email_failed"] else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
