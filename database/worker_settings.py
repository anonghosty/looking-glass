"""The pipeline's settings that Looking Glass's Settings → Workers may change, and how a change reaches the pipeline.

One copy of the rules: which settings may change, and what each may be (FIELDS, validate). The platform loads this
module to show and check the settings; the pipeline uses it to apply them.

How a change gets here (external review, 2026-11-12): the platform's service is hardened (ProtectSystem=strict,
ProtectHome=read-only, ReadWritePaths=<platform>/data), so it cannot, and should not, write the pipeline's .env or
quarantine. It writes a REQUEST into its own data/pipeline_requests/ instead (a settings change, an API key, a
release). At the start of every run (shadowserver_pipeline.py, before reports are fetched) the pipeline reads the
requests, CHECKS EACH ONE AGAIN with these rules (a request file is never trusted as it is), applies the valid ones to
its own .env or quarantine, and writes the result to data/pipeline_requests/done/ (never the key or secret). The
platform shows "waiting for the next run" until then, and records each result in the audit log.

Passwords (mailbox, database), the mailbox address and the server are never in FIELDS: they cannot be requested.
"""
import datetime as dt
import json
import os
import re
import secrets
import tempfile
from pathlib import Path

DOMAIN_RX = re.compile(r"^(?=.{3,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
FOLDER_RX = re.compile(r"^[^\x00-\x1f\"\\]{1,120}$")
KEY_RX = re.compile(r"^[A-Z][A-Z0-9_]{1,63}$")
API_KEYS = ("SHADOWSERVER_API_KEY", "SHADOWSERVER_API_SECRET")
REQ_ID_RX = re.compile(r"^\d{8}T\d{6}Z-[0-9a-f]{12}$")
QID_RX = re.compile(r"^[0-9a-f]{20}$")

# (key, group, label, kind, default, lo|choices, hi, help, shown for MAIL_PROVIDER)
FIELDS = [
    ("REPORT_SOURCE", "email", "How the reports are fetched", "choice", "email", ("email", "api"), None,
     "By e-mail: the mailbox the reports are sent to. Shadowserver API: straight from Shadowserver with the API key below. "
     "Each scheduled run uses this; if it cannot be used that run and the other way is set up, the run uses the other "
     "way and says why in its log.", None),
    ("MAIL_AUTH", "sender", "Sender check", "choice", "log", ("log", "enforce", "off"), None,
     "Check each report e-mail's DKIM signature. Record only: every result is kept and shown in the Audit portal, "
     "nothing is held back. Block: a report that does not pass is held back (quarantine) until an administrator releases it.", None),
    ("MAIL_AUTH_DOMAIN", "sender", "Expected signer", "domain", "shadowserver.org", None, None,
     "The domain that must have signed a genuine report.", None),
    ("EMAIL_DAYS", "email", "Days back per run", "int", "7", 1, 60,
     "How many days back every run looks (e-mail or API); reports already fetched are skipped.", None),
    ("IMAP_FOLDER", "email", "Mailbox folder", "folder", "inbox", None, None, "The folder holding the reports.", "imap"),
    ("GMAIL_LABEL", "email", "Gmail label", "folder", "INBOX", None, None, "The label holding the reports.", "gmail_api"),
    ("MS_FOLDER", "email", "Mailbox folder", "folder", "inbox", None, None, "The folder holding the reports.", "microsoft_graph"),
    ("IMAP_FETCH_BATCH", "email", "Messages per fetch", "int", "25", 1, 500, "E-mails downloaded per request.", "imap"),
    ("IMAP_VERIFY_TLS", "email", "Check the mail server's certificate", "bool", "true", None, None,
     "Off only for a self-signed certificate: with it off, someone on the network path could read the mailbox.", "imap"),
    ("MAIL_TIMEOUT", "email", "Mail server timeout (seconds)", "int", "120", 5, 600, "How long to wait for the mail server.", None),
    ("WORKERS", "load", "Loader processes", "int", "6", 1, 64, "Parallel processes loading reports into MongoDB (each 100-200 MB of memory).", None),
    ("INSERT_CHUNK", "load", "Records per insert", "int", "2000", 100, 100000, "Records written to MongoDB at a time.", None),
    ("DOWNLOAD_THREADS", "load", "Download threads", "int", "4", 1, 32, "Reports downloaded from Shadowserver links at the same time.", None),
    ("ZIP_MAX_UNPACKED_MB", "unzip", "Largest unpacked size (MB)", "int", "2048", 16, 1048576,
     "A zip that would unpack to more is quarantined, not unpacked (zip bombs).", None),
    ("ZIP_MAX_RATIO", "unzip", "Largest compression ratio", "int", "200", 10, 100000, "Unpacked size divided by packed size.", None),
    ("ZIP_MAX_FILES", "unzip", "Most files in one zip", "int", "100", 1, 1000000, "", None),
    ("ZIP_KEEP_FREE_MB", "unzip", "Disk space kept free (MB)", "int", "1024", 0, 1048576, "Unpacking stops before the disk gets this full.", None),
]
GROUPS = [("email", "Getting the reports"), ("sender", "Sender check (DKIM, e-mail only)"), ("load", "Loading performance"),
          ("unzip", "Unzip limits")]
CHOICE_LABELS = {"REPORT_SOURCE": {"email": "By e-mail (the mailbox)", "api": "Shadowserver report API"},
                 "MAIL_AUTH": {"log": "Record only", "enforce": "Block", "off": "Off"}}
SPEC = {f[0]: f for f in FIELDS}


def validate(values, provider):
    """({key: clean value}, [errors]) for the fields given; unknown keys (passwords among them) are refused."""
    clean, errors = {}, []
    for k, v in (values or {}).items():
        f = SPEC.get(k)
        if not f or (f[8] and f[8] != provider):
            errors.append(f"{k} cannot be set here")
            continue
        kind, lo, hi, label = f[3], f[5], f[6], f[2]
        v = str(v if v is not None else "").strip()
        if "\n" in v or "\r" in v:
            errors.append(f"{label}: one line only")
            continue
        if kind == "int":
            if not re.fullmatch(r"\d{1,9}", v) or not (lo <= int(v) <= hi):
                errors.append(f"{label}: a whole number from {lo:,} to {hi:,}")
                continue
            v = str(int(v))
        elif kind == "bool":
            if v.lower() not in ("true", "false"):
                errors.append(f"{label}: true or false")
                continue
            v = v.lower()
        elif kind == "choice":
            if v not in lo:
                errors.append(f"{label}: one of {', '.join(lo)}")
                continue
        elif kind == "domain":
            v = v.lower()
            if not DOMAIN_RX.match(v):
                errors.append(f"{label}: a domain name, for example shadowserver.org")
                continue
        elif kind == "folder":
            if not FOLDER_RX.match(v):
                errors.append(f"{label}: 1-120 characters, no quotes or backslashes")
                continue
        clean[k] = v
    return clean, errors


def valid_api(key, secret):
    return bool(re.fullmatch(r"[A-Za-z0-9._-]{8,200}", str(key or "")) and re.fullmatch(r"[\x21-\x7e]{8,200}", str(secret or "")))


def read_env(path):
    out = {}
    try:
        lines = Path(path).read_text(encoding="utf-8").splitlines()
    except OSError:
        return out
    for ln in lines:
        s = ln.strip()
        if s and not s.startswith("#") and "=" in s:
            k, v = s.split("=", 1)
            v = v.strip()
            if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
                v = v[1:-1]
            out[k.strip()] = v
    return out


def write_env(path, updates):
    """Set KEY=value lines in place (new keys at the end); everything else, comments and passwords included, stays as
    it was. Written to a temporary file and moved over, keeping the file's mode (600)."""
    path = Path(path)
    for k, v in updates.items():
        if not KEY_RX.match(k) or "\n" in str(v) or "\r" in str(v):
            raise ValueError(f"refused: {k}")
    lines = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
    left = dict(updates)
    for i, ln in enumerate(lines):
        m = re.match(r"^\s*([A-Z][A-Z0-9_]*)\s*=", ln)
        if m and m.group(1) in left:
            lines[i] = f"{m.group(1)}={left.pop(m.group(1))}"
    if left:
        lines += ["", "# set from Looking Glass Settings → Workers"] + [f"{k}={v}" for k, v in left.items()]
    mode = path.stat().st_mode & 0o777 if path.exists() else 0o600
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".env.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
        os.chmod(tmp, mode or 0o600)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


# ------------------------------------------------------------------ requests (platform writes, pipeline applies)
def req_dir(platform_data_dir) -> Path:
    return Path(platform_data_dir) / "pipeline_requests"


def make_request(platform_data_dir, kind: str, payload: dict, by: str) -> str:
    """The platform: one request, written atomically, mode 600 (it may hold the API secret until applied)."""
    d = req_dir(platform_data_dir)
    d.mkdir(mode=0o700, parents=True, exist_ok=True)
    rid = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + secrets.token_hex(6)
    body = {"id": rid, "kind": kind, "by": str(by)[:120], "at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"), **payload}
    fd, tmp = tempfile.mkstemp(dir=str(d), prefix=".req.", suffix=".tmp")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(body, fh)
    os.chmod(tmp, 0o600)
    os.replace(tmp, d / f"{rid}.json")
    return rid


def public(req: dict) -> dict:
    """A request as it may be shown or kept: never the key or secret."""
    out = {k: v for k, v in req.items() if k not in ("key", "secret")}
    if req.get("kind") == "apikey":
        out["values"] = "Shadowserver API key and secret (not shown)"
    return out


def pending(platform_data_dir):
    d = req_dir(platform_data_dir)
    out = []
    for p in sorted(d.glob("*.json")) if d.exists() else []:
        try:
            req = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if isinstance(req, dict):
            out.append(public(req))
    return out


def results(platform_data_dir, limit=20):
    d = req_dir(platform_data_dir) / "done"
    out = []
    for p in sorted(d.glob("*.json"), key=lambda q: q.stat().st_mtime, reverse=True)[:limit] if d.exists() else []:
        try:
            r = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if isinstance(r, dict):
            out.append(r)
    return out


def find_platform_data(project_dir, env=None):
    """The platform's data folder: PLATFORM_DIR in the pipeline's .env, else the platform beside the pipeline."""
    env = env if env is not None else os.environ
    cands = [env.get("PLATFORM_DIR") or ""] + [str(Path(project_dir).parent / n) for n in ("platform", "threatmap")]
    for c in cands:
        if c and (Path(c) / "app.py").exists() and (Path(c) / "data").is_dir():
            return Path(c).resolve() / "data"
    return None


def apply_requests(platform_data_dir, env_file, base_dir, log):
    """The pipeline, at the start of a run: check and apply every request, oldest first. Returns how many were applied.
    A request that fails the checks is refused (its result says why) and changes nothing."""
    if not platform_data_dir:
        return 0
    d = req_dir(platform_data_dir)
    files = sorted(d.glob("*.json")) if d.exists() else []
    if not files:
        return 0
    done = d / "done"
    done.mkdir(mode=0o700, exist_ok=True)
    applied = 0
    for p in files:
        try:
            req = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            req = {}
        req = req if isinstance(req, dict) else {}
        rid = str(req.get("id") or "")
        status, why, changed = "refused", "", []
        try:
            if not REQ_ID_RX.match(rid) or p.name != f"{rid}.json":
                raise ValueError("not a request made by the platform")
            env = read_env(env_file)
            kind = req.get("kind")
            if kind == "settings":
                provider = (env.get("MAIL_PROVIDER") or "imap").lower()
                clean, errors = validate(req.get("values") or {}, provider)
                if errors:
                    raise ValueError("; ".join(errors))
                after = dict(env, **clean)
                if after.get("REPORT_SOURCE") == "api" and not (after.get(API_KEYS[0]) and after.get(API_KEYS[1])):
                    raise ValueError("the API was chosen but no API key is saved")
                ch = {k: v for k, v in clean.items() if env.get(k, SPEC[k][4]) != v}
                if ch:
                    write_env(env_file, ch)
                changed = [f"{k}: {env.get(k, SPEC[k][4])} → {v}" for k, v in ch.items()]
            elif kind == "apikey":
                if not valid_api(req.get("key"), req.get("secret")):
                    raise ValueError("not an API key and secret")
                write_env(env_file, {API_KEYS[0]: str(req["key"]).strip(), API_KEYS[1]: str(req["secret"]).strip()})
                changed = ["Shadowserver API key and secret (values not recorded)"]
            elif kind == "release":
                qid = str(req.get("qid") or "")
                import mail_auth
                match = [q for q, _ in mail_auth.held(base_dir) if q.name == qid] if QID_RX.match(qid) else []
                if not match:
                    raise ValueError("no such held-back report")
                mail_auth.request_release(match[0], req.get("by") or "?")
                changed = [f"held-back report {qid} released"]
            else:
                raise ValueError(f"unknown request {kind!r}")
            status = "applied"
            applied += 1
        except Exception as exc:  # noqa: BLE001  (a bad request is refused, the run goes on)
            why = str(exc)[:300]
        result = dict(public(req), id=rid or p.stem, status=status, reason=why, changed=changed,
                      applied_at=dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"))
        out = done / f"{(rid or p.stem)[:40]}.json"
        tmp = done / f".{out.name}.tmp"
        tmp.write_text(json.dumps(result), encoding="utf-8")
        os.chmod(tmp, 0o600)
        os.replace(tmp, out)
        try:
            p.unlink()                       # the request (and any secret in it) is gone once handled
        except OSError:
            pass
        (log.warning if status != "applied" else log.info)(
            "Settings → Workers request %s (%s, by %s): %s%s", rid or p.name, req.get("kind", "?"), req.get("by", "?"),
            status, f": {why}" if why else (f": {'; '.join(changed)}" if changed else ": nothing changed"))
    return applied
