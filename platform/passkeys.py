# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""Passkeys (WebAuthn / FIDO2), approved by the user 2026-11-24, with Duo Labs' py_webauthn.

A passkey is a key pair kept by the person's device (Windows Hello, Touch ID, a phone, a security key). Looking Glass
keeps only the public half and a counter. Signing in or confirming an action with it cannot be relayed by a look-alike
site: the browser ties it to the real site's address. That is why public installations (ACCESS_MODE=public) require
passkeys: at sign-in and before high-value actions (stepup.py). Internal installations use the authenticator code; a
person there may add passkeys when the site has a host name and a trusted certificate (browsers refuse passkeys on a
bare IP address or behind a certificate warning).

The store: data/passkeys.json (0600), {"users": {name: [{"id", "pk", "count", "name", "created", "last_used",
"transports"}]}}, ids and keys in base64url. Nothing secret is kept: a stolen copy lets nobody sign in.
"""
import json
import os
import re
import secrets
import threading
import time

from user_words import Said

from webauthn import (generate_authentication_options, generate_registration_options, options_to_json,
                      verify_authentication_response, verify_registration_response)
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url
from webauthn.helpers.structs import (AuthenticatorSelectionCriteria, PublicKeyCredentialDescriptor, ResidentKeyRequirement,
                                      UserVerificationRequirement)

MIN_PUBLIC = 2                       # passkeys each person registers on a public installation (the user, P2a)
MAX_PER_USER = 10
CHALLENGE_SECONDS = 300
NAME_RX = re.compile(r"[^\w .,'()\-]+")
_IP_RX = re.compile(r"^\[?[0-9a-f:.]+\]?$", re.I)


def _now():
    return time.time()


def is_ip(host):
    """True for an IP address (v4 or v6): browsers refuse passkeys on one."""
    h = (host or "").strip().lower()
    return bool(_IP_RX.match(h)) and any(c.isdigit() for c in h)


def rp_of(host_header, secure):
    """(rp_id, origin) for the host the person reached, or (None, why) when passkeys cannot work here: not HTTPS (or
    this computer's own address), or a bare IP address. The rp_id is the host name without the port."""
    host = (host_header or "").strip().lower()
    name = host.rsplit(":", 1)[0] if host.count(":") == 1 else host      # name:port; IPv6 literals stay whole
    if not name or is_ip(name):
        return None, "Passkeys need the site's host name, not an IP address."
    if not secure and name != "localhost":
        return None, "Passkeys need HTTPS with a trusted certificate."
    return name, f"{'https' if secure else 'http'}://{host}"


class Store:
    def __init__(self, path):
        self.path = path
        self.lock = threading.Lock()

    def _load(self):
        try:
            with open(self.path, encoding="utf-8") as f:
                d = json.load(f)
            return d if isinstance(d.get("users"), dict) else {"users": {}}
        except (OSError, ValueError, AttributeError):
            return {"users": {}}

    def _save(self, d):
        tmp = f"{self.path}.{os.getpid()}.tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(d, f, indent=1)
        os.replace(tmp, self.path)

    def of(self, user):
        return list(self._load()["users"].get(user) or [])

    def count(self, user):
        return len(self.of(user))

    def public_list(self, user):
        """What the person's own page shows: never the key itself."""
        return [{"id": c["id"][:16], "name": c.get("name") or "Passkey", "created": c.get("created"),
                 "last_used": c.get("last_used")} for c in self.of(user)]

    def add(self, user, cred_id, public_key, count, name, transports=()):
        with self.lock:
            d = self._load()
            lst = d["users"].setdefault(user, [])
            if len(lst) >= MAX_PER_USER:
                raise Said(f"At most {MAX_PER_USER} passkeys per person.")
            if any(c["id"] == cred_id for c in lst):
                raise Said("This passkey is already registered.")
            lst.append({"id": cred_id, "pk": public_key, "count": int(count), "created": int(_now()), "last_used": None,
                        "name": clean_name(name, len(lst) + 1), "transports": [str(t) for t in transports][:6]})
            self._save(d)

    def used(self, user, cred_id, count):
        with self.lock:
            d = self._load()
            for c in d["users"].get(user) or []:
                if c["id"] == cred_id:
                    c["count"], c["last_used"] = int(count), int(_now())
            self._save(d)

    def rename(self, user, short_id, name):
        with self.lock:
            d = self._load()
            hit = next((c for c in d["users"].get(user) or [] if c["id"][:16] == short_id), None)
            if not hit:
                return False
            hit["name"] = clean_name(name, 0)
            self._save(d)
            return True

    def remove(self, user, short_id, keep_at_least=0):
        """Remove one; refused when it would leave fewer than keep_at_least."""
        with self.lock:
            d = self._load()
            lst = d["users"].get(user) or []
            if len(lst) - 1 < keep_at_least:
                return False, f"Keep at least {keep_at_least} passkeys: add another one first."
            new = [c for c in lst if c["id"][:16] != short_id]
            if len(new) == len(lst):
                return False, "No such passkey."
            d["users"][user] = new
            self._save(d)
            return True, ""

    def reset(self, user):
        """Every passkey of a person removed (an administrator's reset): returns how many there were."""
        with self.lock:
            d = self._load()
            n = len(d["users"].pop(user, None) or [])
            self._save(d)
            return n


def clean_name(name, n):
    s = NAME_RX.sub("", str(name or "")).strip()[:40]
    return s or (f"Passkey {n}" if n else "Passkey")


class Challenges:
    """One-time challenges, kept for 5 minutes, bound to what asked for them (a session key or a sign-in step)."""

    def __init__(self):
        self.c, self.lock = {}, threading.Lock()

    def new(self, bound, purpose):
        ch = secrets.token_bytes(32)
        with self.lock:
            now = _now()
            for k in [k for k, v in self.c.items() if now - v[2] > CHALLENGE_SECONDS]:
                self.c.pop(k, None)
            self.c[(bound, purpose)] = (ch, purpose, now)
        return ch

    def take(self, bound, purpose):
        with self.lock:
            v = self.c.pop((bound, purpose), None)
        if not v or _now() - v[2] > CHALLENGE_SECONDS:
            return None
        return v[0]


def registration_options(store, challenges, bound, user, display, rp_id):
    opts = generate_registration_options(
        rp_id=rp_id, rp_name="Looking Glass", user_name=user, user_id=user.encode("utf-8"), user_display_name=display or user,
        challenge=challenges.new(bound, "register"),
        authenticator_selection=AuthenticatorSelectionCriteria(resident_key=ResidentKeyRequirement.PREFERRED,
                                                               user_verification=UserVerificationRequirement.REQUIRED),
        exclude_credentials=[PublicKeyCredentialDescriptor(id=base64url_to_bytes(c["id"])) for c in store.of(user)])
    return json.loads(options_to_json(opts))


def register(store, challenges, bound, user, credential, name, rp_id, origin):
    """Check a new passkey and keep it. Raises ValueError with a plain reason."""
    ch = challenges.take(bound, "register")
    if ch is None:
        raise Said("The passkey request expired. Try again.")
    try:
        v = verify_registration_response(credential=credential, expected_challenge=ch, expected_rp_id=rp_id,
                                         expected_origin=origin, require_user_verification=True)
    except Exception as e:  # noqa: BLE001  (the library's own errors: shown as one plain reason)
        raise Said("The passkey could not be checked. Try again, or use another passkey.", detail=str(e)[:160]) from None
    transports = []
    try:
        transports = list((credential.get("response") or {}).get("transports") or []) if isinstance(credential, dict) else []
    except AttributeError:
        pass
    store.add(user, bytes_to_base64url(v.credential_id), bytes_to_base64url(v.credential_public_key), v.sign_count, name,
              transports)


def authentication_options(store, challenges, bound, user, rp_id):
    opts = generate_authentication_options(
        rp_id=rp_id, challenge=challenges.new(bound, "auth"), user_verification=UserVerificationRequirement.REQUIRED,
        allow_credentials=[PublicKeyCredentialDescriptor(id=base64url_to_bytes(c["id"])) for c in store.of(user)])
    return json.loads(options_to_json(opts))


def authenticate(store, challenges, bound, user, credential, rp_id, origin):
    """True when the credential is one of this person's passkeys and signed this challenge. Raises ValueError."""
    ch = challenges.take(bound, "auth")
    if ch is None:
        raise Said("The passkey request expired. Try again.")
    cid = credential.get("id") if isinstance(credential, dict) else None
    hit = next((c for c in store.of(user) if c["id"] == cid), None)
    if not hit:
        raise Said("That passkey is not registered for this account.")
    try:
        v = verify_authentication_response(credential=credential, expected_challenge=ch, expected_rp_id=rp_id,
                                           expected_origin=origin, credential_public_key=base64url_to_bytes(hit["pk"]),
                                           credential_current_sign_count=int(hit.get("count") or 0),
                                           require_user_verification=True)
    except Exception as e:  # noqa: BLE001
        raise Said("The passkey could not be checked. Try again, or use another passkey.", detail=str(e)[:160]) from None
    store.used(user, hit["id"], v.new_sign_count)
    return True
