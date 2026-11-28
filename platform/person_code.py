# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""An opaque code per account, so pages never hold a sign-in name.

A sign-in name is half of what signs someone in, so it stays on the server: the page attribute data-user (map pins
per account in the browser, "your note"), and the people a finding can be sent to (people-pick.js,
beacon-handover.js), carry this code instead. It is a keyed hash (HMAC-SHA256) of the sign-in name with this
installation's own random key, data/person_code.key (32 random bytes, owner-only, made once on first use and kept:
the same for every worker process and across restarts). The same account always gets the same code here; without the
key nobody can compute the code of a name they guess, and another installation gives other codes. The server turns a
code back into the account only among the accounts it offered (`user_of`).

If the key file is removed a new one is made: codes change, which only clears the map pins kept in browsers.

Nobody changes the key through Looking Glass: only someone with the server's files can (removing or replacing it, or
restoring data/ from an older backup). So a change is said (the user, 2026-11-25): data/person_code.made records that
this installation has had a key; a key made while that record exists is a NEW key, written to data/person_code_new.json,
in the audit log (person_code_key_new, through on_new) and in the administrators' bell (bell()). The very first key
(the update that brings this module) is silent. A damaged key file is in the bell too (pages that need it fail).
"""
import hashlib
import hmac
import json
import os
import secrets
import threading
import time

PREFIX = "p-"
LENGTH = 20                      # hex characters after the prefix (80 bits)
KEY_FILE = "person_code.key"
MADE_FILE = "person_code.made"           # "this installation has had a key", with when the first was made
NEW_FILE = "person_code_new.json"        # the last time a key was made again: the bell says it
MIN_KEY = 32
_lock = threading.Lock()
on_new = None                            # features.py: the audit entry when a key is made again
# LG_PERSON_CODE_DIR: tests keep their key in a temporary folder (tests/run_all_checks.sh), never in data/
_state = {"dir": os.environ.get("LG_PERSON_CODE_DIR") or os.path.join(os.path.dirname(os.path.abspath(__file__)), "data"),
          "key": None}


def configure(data_dir):
    """Where the key is kept (tests use a temporary folder)."""
    _state["dir"], _state["key"] = data_dir, None


def _key():
    if _state["key"] is not None:
        return _state["key"]
    with _lock:
        if _state["key"] is not None:
            return _state["key"]
        path = os.path.join(_state["dir"], KEY_FILE)
        if not os.path.exists(path):           # made once: written in full beside it, then linked into place, so two
            os.makedirs(_state["dir"], exist_ok=True)       # workers starting together agree on one whole key
            tmp = f"{path}.{os.getpid()}.{secrets.token_hex(4)}.tmp"
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as fh:
                fh.write(secrets.token_bytes(32))
                fh.flush()
                os.fsync(fh.fileno())
            made = False
            try:
                os.link(tmp, path)             # fails if another worker linked first: its key is used
                made = True
            except FileExistsError:
                pass
            finally:
                os.unlink(tmp)
            if made:
                _record_made()
        with open(path, "rb") as fh:
            key = fh.read()
        if len(key) < MIN_KEY:                 # an empty or cut file (a write cut short): never hash with a weak key
            raise RuntimeError(f"{path} is not a valid key: remove it and restart Looking Glass (map pins are cleared)")
        if not os.path.exists(os.path.join(_state["dir"], MADE_FILE)):
            _write_json(MADE_FILE, {"first": round(time.time(), 3)})   # a key from before the record existed
        _state["key"] = key
        return key


def _write_json(name, obj):
    path = os.path.join(_state["dir"], name)
    tmp = f"{path}.{os.getpid()}.{secrets.token_hex(4)}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(obj, fh)
    os.replace(tmp, path)


def _record_made():
    """This worker made the key: the first one here (silent), or a new one where one had been (said)."""
    made = os.path.join(_state["dir"], MADE_FILE)
    try:
        with open(made, encoding="utf-8") as fh:
            first = float((json.load(fh) or {}).get("first") or 0)
    except (OSError, ValueError, AttributeError):
        first = 0.0
    now = round(time.time(), 3)
    if not os.path.exists(made):
        _write_json(MADE_FILE, {"first": now})
        return
    _write_json(NEW_FILE, {"at": now, "first": first})
    if on_new:
        try:
            on_new(now)
        except Exception:                       # noqa: BLE001  the record is kept; the audit entry is best effort
            pass


def bell(base_dir, now=None):
    """The administrators' alerts: a key made again (codes changed) and a damaged key, for system_alerts.Alerts."""
    d = os.environ.get("LG_PERSON_CODE_DIR") or os.path.join(base_dir, "data")
    out = []
    try:
        with open(os.path.join(d, NEW_FILE), encoding="utf-8") as fh:
            at = float((json.load(fh) or {}).get("at") or 0)
    except (OSError, ValueError, AttributeError):
        at = 0.0
    if at:
        out.append({"key": f"person-code-new:{round(at)}", "problem": True,
                    "title": "A new key for the people codes was made",
                    "text": (f"On {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime(at))} Looking Glass made a new "
                             "data/person_code.key, because the one it had was removed or replaced, or data/ was restored "
                             "from an older backup. Nobody can do this from the website: only someone with the server's "
                             "files. Pins on the map were cleared once; nothing else is affected. If nobody on your team "
                             "did it, check who has access to the server (the audit log has the entry)."),
                    "at": at, "link": "/audit"})
    try:
        size = os.path.getsize(os.path.join(d, KEY_FILE))
    except OSError:
        size = None
    if size is not None and size < MIN_KEY:
        out.append({"key": "person-code-damaged", "problem": True, "title": "The key for the people codes is damaged",
                    "text": ("data/person_code.key is shorter than a key, so pages that name people (the map, Findings, "
                             "Notes) cannot open. On the server, remove that file and restart Looking Glass "
                             "(deploy/reload.sh): a new key is made and map pins are cleared once."),
                    "at": now or time.time(), "link": "/settings#monitor"})
    return out


def code(user):
    """The account's code, "" for no account."""
    user = str(user or "")
    if not user:
        return ""
    return PREFIX + hmac.new(_key(), b"lg-person:" + user.encode("utf-8"), hashlib.sha256).hexdigest()[:LENGTH]


def user_of(value, users):
    """The sign-in name among `users` whose code is `value`; None when it is none of them."""
    value = str(value or "").strip()
    if not value.startswith(PREFIX):
        return None
    # bytes: a value from the request that is not ASCII ("p-é") made compare_digest on text raise TypeError (a 500)
    want = value.encode("utf-8", "replace")
    return next((u for u in users if hmac.compare_digest(code(u).encode("ascii"), want)), None)
