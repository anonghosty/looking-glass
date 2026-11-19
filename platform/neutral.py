"""What someone who is not signed in can learn about this server: as little as possible (the user's anti-fingerprinting
plan, 2026-11-18/19). Looking Glass is open source, so this is defence in depth: it stops scanners (Shodan, Censys and
the like) from naming the product, its framework or its libraries' versions from the outside. The most effective step
stays the operator's: keep the platform off the open internet (VPN, a firewall allowlist).

* Standard reason phrases ("302 Found", "404 Not Found"), not the framework's ("302 FOUND").
* Plain bodies for redirects and the framework's own error pages (Werkzeug's "Redirecting..." and "<title>404 Not
  Found</title>" texts are a signature).
* A neutral ETag on files (the framework's is "mtime-size-checksum"): a short hash of it, answered 304 as before.
* Before sign-in, a short Content-Security-Policy that names no outside library or version (the full one, with the map
  libraries, is sent to signed-in people only); the authenticator set-up keeps the QR-code library it needs.
* /healthz answers this computer only (the installer, deploy/reload.sh and monitoring on the server use it); anyone
  else gets the plain "not found".
* The sign-in pages' logo (the user's choice, 2026-11-19): the organisation's logo by default, none when the
  organisation has none; an administrator can choose the Looking Glass logo or no logo (Settings, audited). A
  product's logo is something scanners recognise.
The files the sign-in pages need are the only ones served without signing in (auth.PUBLIC_STATIC).
Installed from features.py: neutral.install(app, ctx).
"""
import hashlib
import json
import os
import re
import threading
from http import HTTPStatus

from flask import Response, g, jsonify, request

PRE_SIGNIN_CSP = ("default-src 'self'; script-src 'self' 'nonce-{nonce}'{extra}; style-src 'self' 'unsafe-inline' "
                  "https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com; img-src 'self' data:; "
                  "connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'")
QR = " https://cdnjs.cloudflare.com/ajax/libs/qrcode-generator/1.4.4/qrcode.min.js"   # the authenticator set-up
LOGO_CHOICES = ("organisation", "looking-glass", "none")
_FRAMEWORK_PAGE = re.compile(rb"^<!doctype html>\s*<html lang=en>\s*<title>", re.I)
PLAIN = {301: "Moved", 302: "Found", 303: "See other", 307: "Moved", 308: "Moved"}


def phrase(code):
    try:
        return HTTPStatus(code).phrase
    except ValueError:
        return "Error"


def neutral_etag(tag):
    return hashlib.sha256(tag.encode("utf-8", "replace")).hexdigest()[:24]


def plain_page(code):
    """The page a browser sees instead of the framework's own: the status in plain words, nothing else."""
    words = phrase(code)
    return (f"<!doctype html><meta charset=\"utf-8\"><title>{words}</title>"
            f"<p style=\"font-family:sans-serif\">{words}.</p>")


class Look:
    """data/signin_look.json: {"logo": one of LOGO_CHOICES, "by", "at"}."""

    def __init__(self, path):
        self.path, self.lock = path, threading.Lock()

    def get(self):
        try:
            with open(self.path, encoding="utf-8") as fh:
                d = json.load(fh)
            return d if d.get("logo") in LOGO_CHOICES else {"logo": "organisation"}
        except (OSError, ValueError, AttributeError):
            return {"logo": "organisation"}

    def set(self, logo, by, at):
        with self.lock:
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
            tmp = self.path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump({"logo": logo, "by": by, "at": at}, fh)
            os.replace(tmp, self.path)


def install(app, ctx):
    """ctx: base_dir, has_perm, csrf_ok, fresh, audit, org (organisation.Organisation)."""
    look = Look(os.path.join(ctx["base_dir"], "data", "signin_look.json"))
    hp, org = ctx["has_perm"], ctx.get("org")

    def signed_in():
        return bool(getattr(g, "user", None))

    def loopback():
        import ipaddress
        try:
            return ipaddress.ip_address(request.remote_addr or "").is_loopback
        except ValueError:
            return False

    @app.before_request
    def _healthz_local():
        if request.path == "/healthz" and not loopback():
            return Response(plain_page(404), status=404, mimetype="text/html")
        return None

    @app.context_processor
    def _signin_look():
        """For the sign-in pages: which logo, and the organisation's name (or nothing)."""
        choice = look.get()["logo"]
        o = org.get() if org is not None else {"name": "", "logo": None}
        if choice == "organisation":
            logo = "/login/logo" if o.get("logo") else ""
        else:
            logo = "lg" if choice == "looking-glass" else ""
        return {"signin_logo": logo, "signin_org": o.get("name") or ""}

    @app.route("/login/logo")
    def signin_logo():
        o = org.get() if org is not None else {}
        if look.get()["logo"] != "organisation" or not o.get("logo"):
            return Response(plain_page(404), status=404, mimetype="text/html")
        return Response(o["logo"], mimetype=o.get("logo_type") or "image/png", headers={"Cache-Control": "no-cache"})

    @app.route("/login/mark.svg")
    def signin_mark():
        """The Looking Glass logo for the sign-in pages, only when an administrator chose it (the file itself is not served
        signed out: it names the product)."""
        if look.get()["logo"] != "looking-glass":
            return Response(plain_page(404), status=404, mimetype="text/html")
        with open(os.path.join(ctx["base_dir"], "static", "img", "logo-mark.svg"), "rb") as fh:
            return Response(fh.read(), mimetype="image/svg+xml", headers={"Cache-Control": "no-cache"})

    @app.route("/api/settings/signin-look", methods=["GET", "POST"])
    def api_signin_look():
        if not hp("settings"):
            return jsonify(error="For administrators (permission 'settings')."), 403
        if request.method == "GET":
            d = look.get()
            o = org.get() if org is not None else {}
            return jsonify(logo=d["logo"], by=d.get("by", ""), at=d.get("at", ""), has_org_logo=bool(o.get("logo")),
                           choices=list(LOGO_CHOICES))
        if not ctx["csrf_ok"]():
            return jsonify(error="Refused (the request did not come from this page)."), 403
        if not ctx["fresh"]():
            return jsonify(error="Sign in again to make changes (your session is older than 12 hours)."), 403
        v = str((request.get_json(silent=True) or {}).get("logo") or "")
        if v not in LOGO_CHOICES:
            return jsonify(error="Choose the organisation's logo, the Looking Glass logo or no logo."), 400
        before = look.get()["logo"]
        import time
        who = (g.user or {}).get("user", "")
        look.set(v, who, time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
        if v != before:
            ctx["audit"].add("settings_changed", user=who, target="sign-in page logo", detail=f"{before} -> {v}")
        return jsonify(ok=True, logo=v)

    @app.after_request
    def _neutral(resp):
        try:
            code = resp.status_code
            resp.status = f"{code} {phrase(code)}"
            # the framework's own pages (redirects, errors): plain ones
            if 300 <= code < 400 and resp.mimetype == "text/html" and not resp.direct_passthrough:
                body = resp.get_data()
                if b"Redirecting..." in body[:400]:
                    resp.set_data(b"")
                    resp.headers.pop("Content-Type", None)
            elif code >= 400 and resp.mimetype == "text/html" and not resp.direct_passthrough:
                body = resp.get_data()
                if _FRAMEWORK_PAGE.match(body[:200]):
                    resp.set_data(plain_page(code).encode())
            # a neutral ETag on files (answered 304 when the browser has it)
            tag = resp.headers.get("ETag")
            if tag and request.path.startswith("/static/"):
                new = neutral_etag(tag)
                resp.headers["ETag"] = f'"{new}"'
                if code == 200 and new in (request.headers.get("If-None-Match") or ""):
                    resp = Response(status=304, headers={"ETag": f'"{new}"', "Cache-Control": resp.headers.get("Cache-Control", "")})
                    resp.status = "304 Not Modified"
            # before sign-in: a policy that names no outside library (the full one is for signed-in people)
            if not signed_in():
                # the QR-code library only for the page that draws one (the authenticator set-up), so the sign-in page
                # names no library and no version
                extra = QR if (resp.mimetype == "text/html" and not resp.direct_passthrough
                               and b"qrcode.min.js" in resp.get_data()) else ""
                resp.headers.setdefault("Content-Security-Policy", PRE_SIGNIN_CSP.format(nonce=getattr(g, "csp_nonce", ""), extra=extra))
        except Exception:                                   # noqa: BLE001  (never break an answer over a header)
            pass
        return resp

    return {"look": look, "org": org}
