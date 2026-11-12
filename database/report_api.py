"""The reports straight from Shadowserver's report API, instead of (or as well as) by e-mail.

REPORT_SOURCE in .env chooses how each run gets the reports: "email" (the mailbox, mail_sources.py) or "api" (this
module). The run keeps the schedule it already has (run.sh, every 30 minutes by default) and decides each time:
  - api:   list the reports of the last EMAIL_DAYS days (reports/list) and download the new ones; if the API cannot be
           used this run (no key, key refused, Shadowserver unreachable) and a mailbox is set up, the run reads the
           mailbox instead and says why;
  - email: read the mailbox; if the mailbox cannot be read this run and an API key is saved, the run uses the API.
Either way the files land in attachments_backup/ under the same names as the e-mail attachments (for example
2026-11-10-scan_http-example-geo.csv), so unzipping, sorting and loading stay exactly as they are.

The API, as Shadowserver documents it (github.com/The-Shadowserver-Foundation/api_utils, wiki "call_api" and
"API: Reports Query", read 2026-11-12): POST https://transform.shadowserver.org/api2/<method>, a JSON body with
"apikey", and the header HMAC2 = hex HMAC-SHA256 of the exact body bytes with the secret. reports/list takes
"date" (YYYY-MM-DD or YYYY-MM-DD:YYYY-MM-DD) and answers [{id, file, report, timestamp, type, url}]; a file is
downloaded from https://dl.shadowserver.org/<id> (CSV). reports/download was retired on 2026-03-01. The documents give
no checksum, no paging and no rate limit for keyed calls, so every file is checked here: a safe CSV name, not empty,
a header line, at most ZIP_MAX_UNPACKED_MB; downloads are written to a .part file and moved into place only when whole.
Each file downloaded is recorded (name, id, size, SHA-256) in .mail_state.sqlite (table api_files), so a run never
downloads the same file twice and the Audit portal can show where every report came from.
"""
import datetime as dt
import hashlib
import hmac
import json
import os
import re
import sqlite3
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

API_URL = "https://transform.shadowserver.org/api2/"
DL_URL = "https://dl.shadowserver.org/"
FILE_RX = re.compile(r"^\d{4}-\d{2}-\d{2}-[A-Za-z0-9_.-]{1,180}\.csv$")
ID_RX = re.compile(r"^[A-Za-z0-9_\-?=&.%~+]{8,512}$")
SOURCES = ("email", "api")


class ApiError(Exception):
    """The API cannot be used this run (the message says why, without the key or secret)."""


def source(env=None) -> str:
    v = ((env if env is not None else os.environ).get("REPORT_SOURCE") or "email").strip().lower()
    return "api" if v == "api" else "email"


def creds(env=None):
    env = env if env is not None else os.environ
    k, s = (env.get("SHADOWSERVER_API_KEY") or "").strip(), (env.get("SHADOWSERVER_API_SECRET") or "").strip()
    return (k, s) if k and s else None


def mail_configured(env=None) -> bool:
    """Is a mailbox set up (so a run can fall back to it)? Placeholders from .env.example do not count."""
    env = env if env is not None else os.environ
    real = lambda k: (env.get(k) or "").strip() not in ("", "change-me", "mail.example.org", "user@example.org")
    p = (env.get("MAIL_PROVIDER") or "imap").strip().lower()
    if p in ("gmail_api", "gmail", "google"):
        return real("GMAIL_USER")
    if p in ("microsoft_graph", "graph", "microsoft", "m365"):
        return all(real(k) for k in ("MS_TENANT_ID", "MS_CLIENT_ID", "MS_CLIENT_SECRET", "MS_MAILBOX"))
    return all(real(k) for k in ("IMAP_SERVER", "IMAP_USER", "IMAP_PASSWORD"))


def call(method: str, body: dict, key: str, secret: str, url: str = None, timeout: int = 45):
    """One API call; the answer as JSON. Raises ApiError (never with the key or secret in it)."""
    import requests
    payload = dict(body or {}, apikey=key)
    raw = json.dumps(payload).encode()
    sig = hmac.new(secret.encode(), raw, hashlib.sha256).hexdigest()
    try:
        r = requests.post((url or os.environ.get("SHADOWSERVER_API_URL") or API_URL).rstrip("/") + "/" + method, data=raw,
                          headers={"HMAC2": sig, "Content-Type": "application/json", "User-Agent": "LookingGlass-pipeline"},
                          timeout=timeout)
    except requests.RequestException as exc:
        raise ApiError(f"Shadowserver's API could not be reached ({type(exc).__name__})") from None
    try:
        ans = r.json()
    except ValueError:
        ans = None
    if r.status_code != 200:
        why = (ans or {}).get("error") if isinstance(ans, dict) else ""
        raise ApiError(f"Shadowserver refused {method} (HTTP {r.status_code}{': ' + str(why)[:160] if why else ''})")
    if isinstance(ans, dict) and ans.get("error"):
        raise ApiError(f"Shadowserver refused {method}: {str(ans['error'])[:160]}")
    return ans


def check(key: str, secret: str, url: str = None):
    """(ok, message): the key works (test/ping) and may list reports (reports/subscribed)."""
    try:
        pong = call("test/ping", {}, key, secret, url, timeout=20)
        if not (isinstance(pong, dict) and pong.get("pong")):
            return False, "unexpected answer to test/ping"
        subs = call("reports/subscribed", {}, key, secret, url, timeout=20)
    except ApiError as exc:
        return False, str(exc)
    names = [str(x) for x in subs] if isinstance(subs, list) else []
    return True, ("accepted; reports for " + ", ".join(names[:6])) if names else "accepted, but no report list is subscribed to this key"


class Files:
    """The files downloaded from the API (table api_files in .mail_state.sqlite)."""

    def __init__(self, path: Path):
        self.db = sqlite3.connect(str(path))
        self.db.execute("CREATE TABLE IF NOT EXISTS api_files (file TEXT PRIMARY KEY, id TEXT, day TEXT, report TEXT, "
                        "type TEXT, bytes INTEGER, sha256 TEXT, at TEXT)")
        self.db.commit()

    def done(self) -> set:
        return {r[0] for r in self.db.execute("SELECT file FROM api_files")}

    def add(self, it: dict, size: int, digest: str) -> None:
        self.db.execute("INSERT OR REPLACE INTO api_files VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                        (it["file"], it["id"], it.get("timestamp", ""), it.get("report", ""), it.get("type", ""), size, digest,
                         dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")))
        self.db.commit()

    def forget_older_than(self, days: int) -> None:
        cut = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=days)).isoformat(timespec="seconds")
        self.db.execute("DELETE FROM api_files WHERE at < ?", (cut,))
        self.db.commit()

    def close(self) -> None:
        self.db.close()


def _download(it: dict, dest_dir: Path, max_bytes: int, timeout: int = 120):
    """(path, size, sha256) of one report file, checked, or raises ApiError. Written to .<file>.part first."""
    import requests
    dest, part = dest_dir / it["file"], dest_dir / f".{it['file']}.part"
    h, size = hashlib.sha256(), 0
    try:
        with requests.get(DL_URL + it["id"], stream=True, timeout=timeout,
                          headers={"User-Agent": "LookingGlass-pipeline"}) as r:
            if r.status_code != 200:
                raise ApiError(f"HTTP {r.status_code}")
            with open(part, "wb") as fh:
                for chunk in r.iter_content(256 * 1024):
                    size += len(chunk)
                    if size > max_bytes:
                        raise ApiError(f"larger than {max_bytes // 2**20} MB (ZIP_MAX_UNPACKED_MB)")
                    h.update(chunk)
                    fh.write(chunk)
        with open(part, "rb") as fh:
            head = fh.read(4096)
        if not size or b"," not in head.split(b"\n", 1)[0] or b"\x00" in head:
            raise ApiError("not a CSV report (empty, or no header line)")
        os.replace(part, dest)
        return dest, size, h.hexdigest()
    except requests.RequestException as exc:
        raise ApiError(type(exc).__name__) from None
    finally:
        if part.exists():
            part.unlink()


def pull(base_dir: Path, attach_dir: Path, days: int, threads: int, stats, log, env=None, refetch: bool = False,
         max_mb: int = 2048) -> int:
    """Download the reports of the last `days` days (UTC) that are not downloaded yet. Returns how many were new.
    Raises ApiError when the API cannot be used at all this run (the caller may then read the mailbox)."""
    env = env if env is not None else os.environ
    c = creds(env)
    if not c:
        raise ApiError("no Shadowserver API key and secret saved (Settings → Workers, or the installer)")
    today = dt.datetime.now(dt.timezone.utc).date()
    start = today - dt.timedelta(days=max(1, days))
    t0 = time.monotonic()
    items = call("reports/list", {"date": f"{start.isoformat()}:{today.isoformat()}"}, *c)
    if not isinstance(items, list):
        raise ApiError("reports/list did not answer with a list")
    attach_dir.mkdir(parents=True, exist_ok=True)
    files = Files(base_dir / ".mail_state.sqlite")
    try:
        done = set() if refetch else files.done()
        todo, bad = [], 0
        for it in items:
            f, i = str((it or {}).get("file") or ""), str((it or {}).get("id") or "")
            if not (FILE_RX.match(f) and ID_RX.match(i)):
                bad += 1
                continue
            if f in done:
                stats["api_known"] += 1
                continue
            todo.append(dict(it, file=f, id=i))
        if bad:
            log.warning("Shadowserver API: %d listed item(s) without a usable file name or id were skipped", bad)
        log.info("Shadowserver API: %d report(s) listed for %s to %s, %d new, %d downloaded on earlier runs",
                 len(items), start, today, len(todo), stats["api_known"])

        def one(it):
            try:
                _, size, digest = _download(it, attach_dir, max_mb * 2**20)
                return it, size, digest, ""
            except ApiError as exc:
                return it, 0, "", str(exc)
        new = 0
        with ThreadPoolExecutor(max_workers=max(1, min(threads, 8))) as ex:
            for it, size, digest, err in ex.map(one, todo):
                if err:
                    stats["api_failed"] += 1
                    log.warning("[API] FAILED %s: %s (tried again next run)", it["file"], err)
                    continue
                files.add(it, size, digest)
                stats["api_downloaded"] += 1
                new += 1
                log.debug("[API] %s (%d bytes)", it["file"], size)
        files.forget_older_than(max(60, days + 14))
    finally:
        files.close()
    log.info("Shadowserver API: %d downloaded, %d failed, %d already there (%.1fs)", stats["api_downloaded"],
             stats["api_failed"], stats["api_known"], time.monotonic() - t0)
    return new
