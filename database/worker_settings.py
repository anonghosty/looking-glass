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

Requests may only make the pipeline STRICTER on their own (external review, 2026-11-12). The administrator's password
is checked by the web app, but the pipeline cannot tell whether a person approved a file in the platform's data/: a
bug in the web app or a compromise of its account could write one. So a request that WEAKENS the pipeline (weakens())
waits until someone confirms it on the server, on the pipeline's own account:  ./confirm_request.sh <request id>
That writes <pipeline DATA_DIR>/confirmed_requests/<id>.json holding the SHA-256 of the request exactly as confirmed,
in the pipeline's folder, which the hardened web service cannot write. A request changed after its confirmation no
longer matches and is not applied. Unconfirmed requests are refused after CONFIRM_DAYS days. Weakening means: the
sender check lowered (Block -> Record only -> Off), a different expected signer, the mail server's certificate check
turned off, the API given up for the mailbox (api -> email), an unzip limit loosened (more unpacked size, ratio or
files, less disk space kept free), a new Shadowserver API key, and releasing a held-back report. Tightening, folders
and performance are applied at the next run as before. A malformed request is never shown as a change nor
confirmable, and every field printed from a request (screen or log) has its control codes removed (clean()), so a
forged file cannot redraw the confirmation screen.
"""
import datetime as dt
import hashlib
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


MAIL_AUTH_RANK = {"off": 0, "log": 1, "enforce": 2}
CONFIRM_DAYS = 7
CONFIRM_DIR = "confirmed_requests"
# unzip limits: a higher value of the first three, or a lower value of the last, loosens the zip-bomb protection
ZIP_HIGHER_IS_LOOSER = ("ZIP_MAX_UNPACKED_MB", "ZIP_MAX_RATIO", "ZIP_MAX_FILES")
ZIP_LOWER_IS_LOOSER = ("ZIP_KEEP_FREE_MB",)
# control characters (C0, DEL, C1 such as \x9b) and the bidirectional overrides that reorder what a terminal shows
_UNSAFE = re.compile(r"[\x00-\x1f\x7f-\x9f‎‏‪-‮⁦-⁩]")


def clean(value, limit=300) -> str:
    """Text from a request file as it may be printed (terminal, log): control codes shown as '?', never acted on.
    A request file can be written by whoever this step guards against (external review, 2026-11-12)."""
    return _UNSAFE.sub("?", str(value if value is not None else ""))[:limit]


def problems(req, env):
    """Why this request is malformed ([] = well formed): the same checks the pipeline applies before anything else."""
    kind = req.get("kind")
    if kind == "settings":
        return validate(req.get("values") or {}, (env.get("MAIL_PROVIDER") or "imap").lower())[1]
    if kind == "apikey":
        return [] if valid_api(req.get("key"), req.get("secret")) else ["not an API key and secret"]
    if kind == "release":
        return [] if QID_RX.match(str(req.get("qid") or "")) else ["no such held-back report"]
    return [f"unknown request {clean(kind, 40)!r}"]


def _int(v):
    try:
        return int(str(v).strip())
    except (TypeError, ValueError):
        return None


def weakens(req, env):
    """Why this request would make the pipeline less strict (empty: it may be applied without confirmation).
    env: the pipeline's current .env values (a value already in force is no change)."""
    kind = req.get("kind")
    if kind == "apikey":
        return ["a new Shadowserver API key (the pipeline would fetch whatever that account receives)"]
    if kind == "release":
        return ["releasing a report the sender check held back"]
    if kind != "settings":
        return []
    out, vals = [], req.get("values") or {}
    cur = lambda k: str(env.get(k, SPEC[k][4]) if k in SPEC else env.get(k, "")).strip().lower()
    new = lambda k: clean(vals[k], 80).strip().lower()
    if "MAIL_AUTH" in vals and MAIL_AUTH_RANK.get(new("MAIL_AUTH"), -1) < MAIL_AUTH_RANK.get(cur("MAIL_AUTH"), 1):
        out.append(f"the sender check lowered: {cur('MAIL_AUTH')} → {new('MAIL_AUTH')}")
    if "MAIL_AUTH_DOMAIN" in vals and new("MAIL_AUTH_DOMAIN") != cur("MAIL_AUTH_DOMAIN"):
        out.append(f"a different expected signer: {cur('MAIL_AUTH_DOMAIN')} → {new('MAIL_AUTH_DOMAIN')}")
    if "IMAP_VERIFY_TLS" in vals and new("IMAP_VERIFY_TLS") == "false" and cur("IMAP_VERIFY_TLS") != "false":
        out.append("the mail server's certificate check turned off")
    if "REPORT_SOURCE" in vals and new("REPORT_SOURCE") == "email" and cur("REPORT_SOURCE") == "api":
        out.append("from Shadowserver's signed API back to the mailbox (where a forged e-mail can arrive)")
    for k in ZIP_HIGHER_IS_LOOSER + ZIP_LOWER_IS_LOOSER:
        if k in vals:
            a, b = _int(cur(k)), _int(new(k))
            if a is not None and b is not None and (b > a if k in ZIP_HIGHER_IS_LOOSER else b < a):
                out.append(f"an unzip limit loosened: {k} {a} → {b}")
    return out


def request_sha(path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def confirmation(base_dir, rid):
    """The confirmation written on the server for this request, or None."""
    try:
        c = json.loads((Path(base_dir) / CONFIRM_DIR / f"{rid}.json").read_text(encoding="utf-8"))
        return c if isinstance(c, dict) else None
    except (OSError, ValueError):
        return None


def confirm_command(rid):
    return f"./confirm_request.sh {rid}"


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


def pending(platform_data_dir, env=None, base_dir=None):
    """The requests not yet handled. With env (the pipeline's .env): each says whether it waits for confirmation on
    the server (weakens, confirm: the command), and with base_dir whether that confirmation was given."""
    d = req_dir(platform_data_dir)
    out = []
    for p in sorted(d.glob("*.json")) if d.exists() else []:
        try:
            req = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if isinstance(req, dict):
            row = public(req)
            if env is not None:
                w = weakens(req, env)
                if w:
                    row["weakens"], row["confirm"] = w, confirm_command(str(req.get("id") or ""))
                    row["confirmed"] = bool(base_dir and confirmation(base_dir, str(req.get("id") or "")))
            out.append(row)
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
            raw = p.read_bytes()
            req = json.loads(raw.decode("utf-8"))
        except (OSError, ValueError):
            raw, req = b"", {}
        req = req if isinstance(req, dict) else {}
        rid = str(req.get("id") or "")
        status, why, changed, confirmed_by = "refused", "", [], ""
        try:
            if not REQ_ID_RX.match(rid) or p.name != f"{rid}.json":
                raise ValueError("not a request made by the platform")
            env = read_env(env_file)
            kind = req.get("kind")
            bad = problems(req, env)         # malformed requests are refused at once, before any wait for confirmation
            if bad:
                raise ValueError("; ".join(bad))
            weak = weakens(req, env)
            if weak:                         # loosening the pipeline needs a person on the server, not only a file here
                c = confirmation(base_dir, rid)
                if not c:
                    made = dt.datetime.strptime(rid[:16], "%Y%m%dT%H%M%SZ").replace(tzinfo=dt.timezone.utc)
                    if dt.datetime.now(dt.timezone.utc) - made > dt.timedelta(days=CONFIRM_DAYS):
                        raise ValueError(f"not confirmed on the server within {CONFIRM_DAYS} days ({'; '.join(weak)})")
                    log.warning("Settings → Workers request %s (%s, by %s) waits for confirmation on the server: %s. "
                                "On the pipeline's account: %s", rid, clean(kind, 20), clean(req.get("by", "?"), 120),
                                "; ".join(weak), confirm_command(rid))
                    continue                 # stays in the folder; the platform shows it as waiting for confirmation
                if c.get("sha256") != hashlib.sha256(raw).hexdigest():
                    raise ValueError("changed after it was confirmed on the server: not applied")
                confirmed_by = clean(f"{c.get('by') or '?'} at {c.get('at') or '?'}", 120)
            if kind == "settings":
                provider = (env.get("MAIL_PROVIDER") or "imap").lower()
                ok_vals, errors = validate(req.get("values") or {}, provider)
                if errors:
                    raise ValueError("; ".join(errors))
                after = dict(env, **ok_vals)
                if after.get("REPORT_SOURCE") == "api" and not (after.get(API_KEYS[0]) and after.get(API_KEYS[1])):
                    raise ValueError("the API was chosen but no API key is saved")
                ch = {k: v for k, v in ok_vals.items() if env.get(k, SPEC[k][4]) != v}
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
                mail_auth.request_release(match[0], clean(req.get("by") or "?", 120))
                changed = [f"held-back report {qid} released"]
            else:
                raise ValueError(f"unknown request {kind!r}")
            status = "applied"
            applied += 1
        except Exception as exc:  # noqa: BLE001  (a bad request is refused, the run goes on)
            why = clean(exc, 300)
        result = dict(public(req), id=rid or p.stem, status=status, reason=why, changed=changed,
                      applied_at=dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"))
        if confirmed_by:
            result["confirmed_on_server"] = confirmed_by
        if REQ_ID_RX.match(rid):
            try:
                (Path(base_dir) / CONFIRM_DIR / f"{rid}.json").unlink()     # used once
            except OSError:
                pass
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
            "Settings → Workers request %s (%s, by %s%s): %s%s", clean(rid or p.name, 80), clean(req.get("kind", "?"), 20),
            clean(req.get("by", "?"), 120),
            f", confirmed on the server by {confirmed_by}" if confirmed_by else "",
            status, f": {why}" if why else (f": {'; '.join(changed)}" if changed else ": nothing changed"))
    return applied


# ------------------------------------------------------------------ confirming on the server (confirm_request.sh)
def _describe(req):
    """What the request changes, as printed (only shown for well-formed requests, and cleaned all the same)."""
    if req.get("kind") == "settings":
        return clean("; ".join(f"{k} = {v}" for k, v in (req.get("values") or {}).items()), 600)
    if req.get("kind") == "release":
        return clean(f"release held-back report {req.get('qid')}", 80)
    return clean(public(req).get("values") or req.get("kind"), 120)


def cli(argv=None):
    """./confirm_request.sh            list the requests waiting for confirmation
       ./confirm_request.sh <id>       show one and confirm it (asks y/N; --yes to skip the question)"""
    import argparse
    import getpass
    here = Path(__file__).resolve().parent
    ap = argparse.ArgumentParser(description="Confirm, on the server, a Looking Glass Settings → Workers request that "
                                             "makes the pipeline less strict.")
    ap.add_argument("id", nargs="?")
    ap.add_argument("--yes", action="store_true", help="confirm without asking")
    a = ap.parse_args(argv)
    env_file = here / ".env"
    env = read_env(env_file)
    base = Path(env.get("DATA_DIR") or here).expanduser().resolve()
    pdata = find_platform_data(here, env)
    if not pdata:
        print("The platform's data folder was not found (PLATFORM_DIR in .env).")
        return 2
    d = req_dir(pdata)
    waiting, malformed = [], []
    for p in sorted(d.glob("*.json")) if d.exists() else []:
        try:
            raw = p.read_bytes()             # read ONCE: what is shown is exactly what is hashed and confirmed
            req = json.loads(raw.decode("utf-8"))
        except (OSError, ValueError):
            continue
        if isinstance(req, dict) and REQ_ID_RX.match(str(req.get("id") or "")) and p.name == f"{req['id']}.json":
            bad = problems(req, env)
            if bad:                          # never shown as a change, never confirmable: the next run refuses it
                malformed.append((req["id"], bad))
                continue
            w = weakens(req, env)
            if w:
                waiting.append((raw, req, w))
    who = lambda r: f"{clean(r.get('by', '?'), 120)} at {clean(r.get('at', '?'), 40)}"
    if not a.id:
        if not waiting:
            print("Nothing waits for confirmation.")
        for raw, req, w in waiting:
            done = " (confirmed, applied at the next run)" if confirmation(base, req["id"]) else ""
            print(f"{req['id']}  by {who(req)}{done}\n    {_describe(req)}\n    weakens: {'; '.join(w)}")
        for rid, bad in malformed:
            print(f"{rid}  MALFORMED, cannot be confirmed; the next run refuses it: {clean('; '.join(bad), 300)}")
        return 0
    if any(rid == a.id for rid, _ in malformed):
        print(f"Request {a.id} is malformed and cannot be confirmed; the pipeline's next run refuses it.")
        return 1
    match = [x for x in waiting if x[1]["id"] == a.id]
    if not REQ_ID_RX.match(a.id) or not match:
        print(f"No request {clean(a.id, 60)!r} waits for confirmation (./confirm_request.sh lists them).")
        return 1
    raw, req, w = match[0]
    print(f"Request {req['id']}\n  asked by   {who(req)} (in Looking Glass)\n"
          f"  change     {_describe(req)}\n  weakens    {'; '.join(w)}")
    if not a.yes:
        try:
            if input("Confirm this change? Type yes: ").strip().lower() != "yes":
                print("Not confirmed.")
                return 1
        except EOFError:
            print("Not confirmed.")
            return 1
    cd = base / CONFIRM_DIR
    cd.mkdir(mode=0o700, parents=True, exist_ok=True)
    body = {"id": req["id"], "sha256": hashlib.sha256(raw).hexdigest(), "by": getpass.getuser(),
            "at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"), "weakens": w}
    fd, tmp = tempfile.mkstemp(dir=str(cd), prefix=".c.", suffix=".tmp")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(body, fh)
    os.chmod(tmp, 0o600)
    os.replace(tmp, cd / f"{req['id']}.json")
    print("Confirmed. The pipeline applies it at its next run (or run it now); the result shows in Settings → Workers.")
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(cli())
