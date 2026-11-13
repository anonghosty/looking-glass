"""Where the Shadowserver report e-mails come from.

MAIL_PROVIDER in .env chooses the source:

  imap             any mail server over IMAP (also Gmail / Google Workspace with an app password)
                   IMAP_SERVER, IMAP_USER, IMAP_PASSWORD, IMAP_FOLDER, IMAP_VERIFY_TLS
  gmail_api        Google Workspace through the Gmail API, with a service account and domain-wide delegation
                   (no mailbox password stored)      GMAIL_SERVICE_ACCOUNT_FILE, GMAIL_USER, GMAIL_LABEL
  microsoft_graph  Microsoft 365 / Exchange Online through Microsoft Graph, with an app registration
                   (Mail.Read application permission) MS_TENANT_ID, MS_CLIENT_ID, MS_CLIENT_SECRET, MS_MAILBOX, MS_FOLDER

Every source only reads: messages are never marked read, moved or deleted. Each yields the raw message (RFC 822 bytes)
of the messages received in the last N days, under a stable key, so the pipeline can skip messages it has already
handled (MailState). How to create the credentials: docs/MAIL_SETUP.md.
"""
from __future__ import annotations

import base64
import datetime as dt
import email
import hashlib
import imaplib
import json
import os
import re
import socket
import sqlite3
import ssl
import time
from pathlib import Path
from urllib.parse import quote

PROVIDERS = ("imap", "gmail_api", "microsoft_graph")
_MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")


class MailSourceError(OSError):
    """A clear, user-facing reason why the mailbox cannot be read (wrong password, missing permission...)."""


def _truthy(v: str) -> bool:
    return (v or "").strip().lower() in ("1", "true", "yes", "on")


def since_date(days: int) -> dt.date:
    return dt.date.today() - dt.timedelta(days=days)


def _batched(seq, n):
    for i in range(0, len(seq), n):
        yield seq[i:i + n]


# --------------------------------------------------------------------------------------------------------- IMAP
def imap_quote(name: str) -> str:
    """A folder name as an IMAP quoted string, so names with spaces or quotes work ("Shadow Reports").
    imaplib sends arguments as they are; an unquoted name with a space is refused by the server."""
    if len(name) > 1 and name.startswith('"') and name.endswith('"'):
        return name
    return '"' + name.replace("\\", "\\\\").replace('"', '\\"') + '"'


class ImapSource:
    kind = "imap"

    def __init__(self, env):
        self.server = env.get("IMAP_SERVER", "")
        self.user = env.get("IMAP_USER", "")
        self.password = env.get("IMAP_PASSWORD", "")
        self.folder = env.get("IMAP_FOLDER", "inbox") or "inbox"
        # the certificate is checked unless .env turns it off (only for a self-signed certificate); external review,
        # 2026-11-12: the default used to be off
        self.verify = _truthy(env.get("IMAP_VERIFY_TLS", "true"))
        self.batch = int(env.get("IMAP_FETCH_BATCH", "25") or 25)
        self.timeout = int(env.get("MAIL_TIMEOUT", "120") or 120)
        self.imap = None
        missing = [k for k, v in (("IMAP_SERVER", self.server), ("IMAP_USER", self.user), ("IMAP_PASSWORD", self.password)) if not v]
        if missing:
            raise MailSourceError(", ".join(missing) + " missing in .env")

    def describe(self) -> str:
        return f"IMAP {self.user} on {self.server}, folder '{self.folder}'"

    def _connect(self):
        if self.imap:
            return
        ctx = ssl.create_default_context()
        if not self.verify:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        try:
            self.imap = imaplib.IMAP4_SSL(self.server, ssl_context=ctx, timeout=self.timeout)
        except socket.gaierror as exc:
            raise MailSourceError(f"the mail server name '{self.server}' does not exist (check the spelling; "
                                  "type only the name, e.g. mail.example.org)") from exc
        except ssl.SSLCertVerificationError as exc:
            raise MailSourceError(f"the certificate of {self.server} is not trusted ({exc.verify_message}); "
                                  "set IMAP_VERIFY_TLS=false only if the server uses a self-signed certificate") from exc
        except OSError as exc:
            raise MailSourceError(f"cannot reach {self.server} on port 993 ({exc})") from exc
        try:
            self.imap.login(self.user, self.password)
        except imaplib.IMAP4.error as exc:
            text = str(exc)
            hint = ""
            if "gmail" in self.server.lower() or "google" in self.server.lower():
                hint = " (Gmail needs an app password, not the account password: docs/MAIL_SETUP.md)"
            elif "outlook" in self.server.lower() or "office365" in self.server.lower():
                hint = " (Microsoft 365 no longer accepts passwords over IMAP: use MAIL_PROVIDER=microsoft_graph)"
            raise MailSourceError(f"login refused for {self.user}: {text}{hint}") from exc
        try:
            typ, _ = self.imap.select(imap_quote(self.folder), readonly=True)
        except imaplib.IMAP4.error as exc:
            raise MailSourceError(f"the mail server refused the folder '{self.folder}' ({exc})") from exc
        try:                                          # the server's own numbering of this folder (with UID: the message key)
            _, dat = self.imap.response("UIDVALIDITY")
            self.uidvalidity = (dat[0].decode() if dat and dat[0] else "0").strip()
        except Exception:  # noqa: BLE001
            self.uidvalidity = "0"
        if typ != "OK":
            raise MailSourceError(f"folder '{self.folder}' not found in {self.user}")

    def list(self, days: int):
        """[(key, seq id)] for messages since the date, newest last. The key is the SERVER's identity of the message
        (UIDVALIDITY and UID), never its Message-ID header, which the sender writes: a forged mail reusing a coming
        report's Message-ID could get that report skipped as already handled (external review, 2026-11-12).
        self.legacy maps each key to the Message-ID key earlier versions used, so mail already handled is not
        handled again after the update."""
        self._connect()
        d = since_date(days)
        typ, data = self.imap.search(None, f'SINCE "{d.day:02d}-{_MONTHS[d.month - 1]}-{d.year}"')
        ids = data[0].split() if typ == "OK" and data and data[0] else []
        out, self.legacy = [], {}
        for chunk in _batched(ids, 200):
            typ, data = self.imap.fetch(b",".join(chunk).decode(),
                                        "(UID BODY.PEEK[HEADER.FIELDS (MESSAGE-ID DATE SUBJECT FROM)])")
            if typ != "OK":
                continue
            for item in data:
                if not (isinstance(item, tuple) and len(item) > 1):
                    continue
                seq = item[0].split()[0]
                hdr = email.message_from_bytes(item[1])
                mid = (hdr.get("Message-ID") or "").strip()
                old = "imap:" + (mid or hashlib.sha1(item[1]).hexdigest())
                m = re.search(rb"\bUID (\d+)", item[0])
                key = f"imap:{getattr(self, 'uidvalidity', '0')}:{m.group(1).decode()}" if m else old
                self.legacy[key] = old
                out.append((key, seq))
        return out

    def fetch(self, items):
        """yield (key, raw bytes) for [(key, seq id)]."""
        self._connect()
        for chunk in _batched(list(items), self.batch):
            keys = {seq: key for key, seq in chunk}
            typ, data = self.imap.fetch(b",".join(s for _, s in chunk).decode(), "(BODY.PEEK[])")
            if typ != "OK":
                continue
            for item in data:
                if isinstance(item, tuple) and len(item) > 1:
                    seq = item[0].split()[0]
                    yield keys.get(seq, "imap:" + hashlib.sha1(item[1]).hexdigest()), item[1]

    def close(self):
        if self.imap:
            try:
                self.imap.logout()
            except Exception:  # noqa: BLE001
                pass
            self.imap = None


# --------------------------------------------------------------------------------------------------------- HTTP helper
def _retry_after(value, default):
    """Seconds to wait from a Retry-After header: a number of seconds, or an HTTP date (review 2026-11-13: a date
    crashed the download); anything else, the default. Never more than a minute."""
    v = (value or "").strip()
    if v.isdigit():
        return min(60, int(v)) or default
    if v:
        try:
            from email.utils import parsedate_to_datetime
            secs = (parsedate_to_datetime(v) - dt.datetime.now(dt.timezone.utc)).total_seconds()
            return min(60, max(1, int(secs))) if secs > 0 else default
        except (TypeError, ValueError, OverflowError):
            pass
    return min(60, default)


class _Http:
    def __init__(self):
        import requests
        self.requests = requests
        self.s = requests.Session()
        self.s.headers["User-Agent"] = "shadowserver-pipeline"

    def call(self, method, url, what, **kw):
        for attempt in range(5):
            try:
                r = self.s.request(method, url, timeout=(20, 120), **kw)
            except self.requests.RequestException as exc:
                raise MailSourceError(f"{what}: cannot reach {url.split('/')[2]} ({exc.__class__.__name__})") from exc
            if r.status_code in (429, 503, 504) and attempt < 4:
                time.sleep(_retry_after(r.headers.get("Retry-After"), 2 ** (attempt + 1)))
                continue
            return r
        return r


def _api_error(r) -> str:
    try:
        j = r.json()
    except ValueError:
        return f"HTTP {r.status_code}"
    e = j.get("error")
    if isinstance(e, dict):
        return f"HTTP {r.status_code} {e.get('code') or e.get('status') or ''}: {e.get('message', '')}".strip()
    return f"HTTP {r.status_code} {e or ''}: {j.get('error_description', '')}".strip()


# --------------------------------------------------------------------------------------------------------- Gmail API
class GmailSource:
    kind = "gmail_api"
    SCOPE = "https://www.googleapis.com/auth/gmail.readonly"
    API = "https://gmail.googleapis.com/gmail/v1/users/"

    def __init__(self, env):
        self.key_file = env.get("GMAIL_SERVICE_ACCOUNT_FILE", "")
        self.user = env.get("GMAIL_USER", "")
        self.label = env.get("GMAIL_LABEL", "INBOX") or "INBOX"
        if not (self.key_file and self.user):
            raise MailSourceError("GMAIL_SERVICE_ACCOUNT_FILE and GMAIL_USER must be set in .env")
        p = Path(self.key_file).expanduser()
        if not p.is_absolute():
            p = Path(__file__).resolve().parent / p
        try:
            self.sa = json.loads(p.read_text(encoding="utf-8"))
            self.sa["client_email"], self.sa["private_key"]
        except (OSError, ValueError, KeyError) as exc:
            raise MailSourceError(f"cannot read the service account key {p} ({exc.__class__.__name__}); "
                                  "it must be the JSON key file downloaded from Google Cloud") from exc
        self.http = _Http()
        self.token = None
        self.label_id = None

    def describe(self) -> str:
        return f"Gmail API {self.user}, label '{self.label}' (service account {self.sa['client_email']})"

    def _auth(self):
        if self.token and self.token[1] > time.time() + 60:
            return self.token[0]
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding

        def b64(b):
            return base64.urlsafe_b64encode(b).rstrip(b"=")
        now = int(time.time())
        uri = self.sa.get("token_uri", "https://oauth2.googleapis.com/token")
        claims = {"iss": self.sa["client_email"], "sub": self.user, "scope": self.SCOPE, "aud": uri,
                  "iat": now, "exp": now + 3600}
        signing = b64(json.dumps({"alg": "RS256", "typ": "JWT"}).encode()) + b"." + b64(json.dumps(claims).encode())
        key = serialization.load_pem_private_key(self.sa["private_key"].encode(), password=None)
        jwt = signing + b"." + b64(key.sign(signing, padding.PKCS1v15(), hashes.SHA256()))
        r = self.http.call("POST", uri, "Google sign-in", data={
            "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer", "assertion": jwt.decode()})
        if r.status_code != 200:
            msg = _api_error(r)
            if "unauthorized_client" in msg:
                msg += (" - domain-wide delegation is missing: in admin.google.com add the service account's client ID "
                        f"with the scope {self.SCOPE}")
            elif "invalid_grant" in msg:
                msg += f" - check GMAIL_USER ({self.user}) is a mailbox of your Google Workspace domain"
            raise MailSourceError(f"Google refused the service account: {msg}")
        j = r.json()
        self.token = (j["access_token"], time.time() + int(j.get("expires_in", 3600)))
        return self.token[0]

    def _get(self, path, what, **params):
        r = self.http.call("GET", self.API + quote(self.user) + path, what,
                           headers={"Authorization": "Bearer " + self._auth()}, params=params)
        if r.status_code != 200:
            msg = _api_error(r)
            if r.status_code == 403 and ("has not been used" in msg or "disabled" in msg):
                msg += " - enable the Gmail API in the service account's Google Cloud project"
            raise MailSourceError(f"{what}: {msg}")
        return r

    def _label(self):
        if self.label_id:
            return self.label_id
        labels = self._get("/labels", "Gmail labels").json().get("labels", [])
        for lb in labels:
            if lb["id"].lower() == self.label.lower() or lb["name"].lower() == self.label.lower():
                self.label_id = lb["id"]
                return self.label_id
        raise MailSourceError(f"label '{self.label}' not found in {self.user}")

    def list(self, days: int):
        d = since_date(days)
        after = int(dt.datetime(d.year, d.month, d.day).timestamp())
        out, token = [], None
        label = self._label()
        while True:
            params = {"q": f"after:{after}", "labelIds": label, "maxResults": 500}
            if token:
                params["pageToken"] = token
            j = self._get("/messages", "Gmail message list", **params).json()
            out += [("gmail:" + m["id"], m["id"]) for m in j.get("messages", [])]
            token = j.get("nextPageToken")
            if not token:
                break
        return list(reversed(out))

    def fetch(self, items):
        for key, mid in items:
            raw = self._get(f"/messages/{mid}", "Gmail message", format="raw").json()["raw"]
            yield key, base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))

    def close(self):
        pass


# --------------------------------------------------------------------------------------------------------- Microsoft Graph
class GraphSource:
    kind = "microsoft_graph"
    API = "https://graph.microsoft.com/v1.0/users/"
    WELL_KNOWN = {"inbox", "archive", "junkemail", "deleteditems", "sentitems", "drafts"}

    def __init__(self, env):
        self.tenant = env.get("MS_TENANT_ID", "")
        self.client = env.get("MS_CLIENT_ID", "")
        self.secret = env.get("MS_CLIENT_SECRET", "")
        self.mailbox = env.get("MS_MAILBOX", "")
        self.folder = env.get("MS_FOLDER", "inbox") or "inbox"
        missing = [k for k, v in (("MS_TENANT_ID", self.tenant), ("MS_CLIENT_ID", self.client),
                                  ("MS_CLIENT_SECRET", self.secret), ("MS_MAILBOX", self.mailbox)) if not v]
        if missing:
            raise MailSourceError(", ".join(missing) + " missing in .env")
        self.http = _Http()
        self.token = None
        self.folder_id = None

    def describe(self) -> str:
        return f"Microsoft Graph {self.mailbox}, folder '{self.folder}'"

    def _auth(self):
        if self.token and self.token[1] > time.time() + 60:
            return self.token[0]
        r = self.http.call("POST", f"https://login.microsoftonline.com/{quote(self.tenant)}/oauth2/v2.0/token",
                           "Microsoft sign-in", data={
                               "client_id": self.client, "client_secret": self.secret, "grant_type": "client_credentials",
                               "scope": "https://graph.microsoft.com/.default"})
        if r.status_code != 200:
            msg = _api_error(r)
            hint = ""
            if "AADSTS7000215" in msg:
                hint = " - the client secret is wrong (copy its Value, not its Secret ID)"
            elif "AADSTS7000222" in msg:
                hint = " - the client secret has expired: create a new one"
            elif "AADSTS700016" in msg:
                hint = " - no app with this client ID in this tenant"
            elif "AADSTS90002" in msg or "AADSTS900023" in msg:
                hint = " - the tenant ID is wrong"
            elif "AADSTS53003" in msg:
                hint = (" - a Conditional Access policy of your tenant blocks this app: ask the Entra admin to exclude it "
                        "(workload identity) or allow this server's address")
            elif "AADSTS700026" in msg:
                hint = " - this app has no client secret: create one under Certificates & secrets"
            raise MailSourceError(f"Microsoft refused the app: {msg.splitlines()[0][:300]}{hint}")
        j = r.json()
        self.token = (j["access_token"], time.time() + int(j.get("expires_in", 3600)))
        return self.token[0]

    def _get(self, url, what, params=None, raw=False):
        if not url.startswith("https://"):
            url = self.API + quote(self.mailbox) + url
        r = self.http.call("GET", url, what, headers={"Authorization": "Bearer " + self._auth()}, params=params)
        if r.status_code != 200:
            msg = _api_error(r)
            if r.status_code == 403 or "AccessDenied" in msg or "ErrorAccessDenied" in msg:
                msg += (" - give the app the Microsoft Graph application permission Mail.Read and grant admin consent; "
                        "if mailbox access is restricted (application access policy / RBAC), include this mailbox")
            elif r.status_code == 404:
                msg += f" - mailbox {self.mailbox} or folder '{self.folder}' not found"
            raise MailSourceError(f"{what}: {msg}")
        return r if raw else r.json()

    def _folder(self):
        if self.folder_id:
            return self.folder_id
        if self.folder.lower() in self.WELL_KNOWN:
            self.folder_id = self.folder.lower()
            self._get(f"/mailFolders/{self.folder_id}", "Mail folder")
            return self.folder_id
        name = self.folder.replace("'", "''")
        for base in ("/mailFolders", "/mailFolders/inbox/childFolders"):
            hits = self._get(base, "Mail folders", params={"$filter": f"displayName eq '{name}'"}).get("value", [])
            if hits:
                self.folder_id = hits[0]["id"]
                return self.folder_id
        raise MailSourceError(f"folder '{self.folder}' not found in {self.mailbox}")

    def list(self, days: int):
        d = since_date(days)
        params = {"$filter": f"receivedDateTime ge {d.isoformat()}T00:00:00Z", "$select": "id,internetMessageId",
                  "$orderby": "receivedDateTime asc", "$top": "100"}
        url, out = f"/mailFolders/{self._folder()}/messages", []
        self.legacy = {}
        while url:
            j = self._get(url, "Message list", params=params)
            for m in j.get("value", []):
                # the mailbox's own id, never the sender-written internetMessageId (external review, 2026-11-12)
                key = "graph:id:" + m["id"]
                self.legacy[key] = "graph:" + (m.get("internetMessageId") or m["id"])
                out.append((key, m["id"]))
            url, params = j.get("@odata.nextLink"), None
        return out

    def fetch(self, items):
        for key, mid in items:
            yield key, self._get(f"/messages/{mid}/$value", "Message", raw=True).content

    def close(self):
        pass


# --------------------------------------------------------------------------------------------------------- factory, test
def make_source(env=None):
    env = os.environ if env is None else env
    kind = (env.get("MAIL_PROVIDER") or "imap").strip().lower()
    if kind == "imap":
        return ImapSource(env)
    if kind in ("gmail_api", "gmail", "google"):
        return GmailSource(env)
    if kind in ("microsoft_graph", "graph", "microsoft", "m365"):
        return GraphSource(env)
    raise MailSourceError(f"MAIL_PROVIDER must be one of {', '.join(PROVIDERS)}, not '{kind}'")


def test_source(env=None, days: int = 1) -> str:
    """Log in and count the messages of the last `days` days. Returns a summary; raises MailSourceError."""
    src = make_source(env)
    try:
        n = len(src.list(days))
        return f"{src.describe()}: login OK, {n} message(s) in the last {days} day(s)"
    finally:
        src.close()


# --------------------------------------------------------------------------------------------------------- state
class MailState:
    """Messages fully handled (attachments saved, all links downloaded) and links downloaded, so frequent runs
    (every 30 minutes) only fetch what is new."""

    def __init__(self, path: Path):
        self.db = sqlite3.connect(str(path))
        self.db.execute("CREATE TABLE IF NOT EXISTS messages (key TEXT PRIMARY KEY, done_at TEXT)")
        self.db.execute("CREATE TABLE IF NOT EXISTS links (url TEXT PRIMARY KEY, file TEXT, done_at TEXT)")
        # which message each saved attachment came from, so a file found broken later (corrupt zip) sends its
        # message back for a fresh download instead of being lost
        self.db.execute("CREATE TABLE IF NOT EXISTS files (file TEXT PRIMARY KEY, key TEXT, done_at TEXT)")
        # how often each broken file was fetched again (review 2026-11-13: a file that arrives broken every time was
        # deleted and fetched again on every run, for ever)
        self.db.execute("CREATE TABLE IF NOT EXISTS refetched (file TEXT PRIMARY KEY, times INTEGER, last_at TEXT)")
        self.db.commit()

    REFETCH_MAX = 3            # fresh downloads of one broken file; after that it is left alone (the log says so)

    def mark_files(self, items) -> None:
        now = dt.datetime.now().isoformat(timespec="seconds")
        self.db.executemany("INSERT OR REPLACE INTO files VALUES (?, ?, ?)", [(f, k, now) for f, k in items])
        self.db.commit()

    def forget_file(self, name: str) -> int:
        """A saved file turned out broken and was deleted: fetch it again on the next run (its message and any
        link that gave it are no longer marked done). Returns how many records were reopened; -1 when the file was
        already fetched again REFETCH_MAX times and still arrived broken: then it stays as done, so it stops."""
        row = self.db.execute("SELECT times FROM refetched WHERE file = ?", (name,)).fetchone()
        times = row[0] if row else 0
        if times >= self.REFETCH_MAX:
            return -1
        self.db.execute("INSERT OR REPLACE INTO refetched VALUES (?, ?, ?)",
                        (name, times + 1, dt.datetime.now().isoformat(timespec="seconds")))
        n = self.db.execute("DELETE FROM messages WHERE key IN (SELECT key FROM files WHERE file = ?)", (name,)).rowcount
        n += self.db.execute("DELETE FROM links WHERE file = ?", (name,)).rowcount
        self.db.execute("DELETE FROM files WHERE file = ?", (name,))
        self.db.commit()
        return n

    def done_messages(self) -> set:
        return {r[0] for r in self.db.execute("SELECT key FROM messages")}

    def done_links(self) -> set:
        return {r[0] for r in self.db.execute("SELECT url FROM links")}

    def mark_messages(self, keys) -> None:
        now = dt.datetime.now().isoformat(timespec="seconds")
        self.db.executemany("INSERT OR REPLACE INTO messages VALUES (?, ?)", [(k, now) for k in keys])
        self.db.commit()

    def mark_links(self, items) -> None:
        now = dt.datetime.now().isoformat(timespec="seconds")
        self.db.executemany("INSERT OR REPLACE INTO links VALUES (?, ?, ?)", [(u, f, now) for u, f in items])
        self.db.commit()

    def forget_older_than(self, days: int) -> None:
        cut = (dt.datetime.now() - dt.timedelta(days=days)).isoformat(timespec="seconds")
        self.db.execute("DELETE FROM messages WHERE done_at < ?", (cut,))
        self.db.execute("DELETE FROM links WHERE done_at < ?", (cut,))
        self.db.execute("DELETE FROM files WHERE done_at < ?", (cut,))
        self.db.commit()

    def close(self) -> None:
        self.db.close()


__all__ = ["PROVIDERS", "MailSourceError", "make_source", "test_source", "MailState", "since_date", "imap_quote"]
