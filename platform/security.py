"""Request guards and security headers for Looking Glass (see docs/SECURITY_REPORT.md).

* Who may connect (report #1): this machine only, by default. Other screens (a TV, a colleague's laptop) are allowed
  by address in VIEWER_NETWORKS (e.g. "192.168.1.50,10.0.0.0/24"); everyone else gets 403. For anything wider, put
  the app behind a reverse proxy with TLS and a login (the proxy connects from 127.0.0.1).
* Host header (report #2, DNS rebinding): only localhost names, plus ALLOWED_HOSTS (names or addresses other screens
  use to reach this machine) are served. A page on attacker.example that re-points its DNS to 127.0.0.1 gets 400.
* Cross-site writes (report #2, CSRF): every request that changes something (POST ...) must come from this site's
  own pages: a foreign Origin, or Sec-Fetch-Site "cross-site", gets 403.
* Security headers (report #8): Content-Security-Policy with a per-request nonce for the few inline scripts,
  frame-ancestors 'none' (no clickjacking; the one exception: /management?embed=1 may be framed by this same site, for
  the review page), nosniff, Referrer-Policy, COOP, Permissions-Policy.
* Request size (report #7): MAX_CONTENT_LENGTH 64 KB.
"""
import ipaddress
import os
import secrets
import time

NAMES_REFRESH = 60          # seconds between two looks at this machine's own addresses for an unknown host name
from urllib.parse import urlsplit

from flask import abort, g, request

LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "[::1]"}
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
_HERE = os.path.dirname(os.path.abspath(__file__)) + os.sep


def public_error(exc, fallback="That request could not be completed. Try again, or ask an administrator to check the log."):
    """The text of an error to show in the browser: only messages Looking Glass itself raised (written for users).
    An error raised inside a library or Python itself could carry internal details, so it gets a generic message."""
    tb = exc.__traceback__
    while tb is not None and tb.tb_next is not None:
        tb = tb.tb_next
    where = os.path.abspath(tb.tb_frame.f_code.co_filename) if tb is not None else ""
    ours = where.startswith(_HERE) and os.sep + "site-packages" + os.sep not in where and os.sep + ".venv" + os.sep not in where
    return str(exc)[:300] if ours else fallback


def _csv(v):
    return [x.strip() for x in (v or "").split(",") if x.strip()]


def _networks(spec):
    out = []
    for x in _csv(spec):
        try:
            out.append(ipaddress.ip_network(x, strict=False))
        except ValueError:
            pass
    return out


def _host_only(host):
    host = (host or "").strip().lower()
    if host.startswith("["):                       # [::1]:5000
        return host.split("]")[0] + "]"
    return host.rsplit(":", 1)[0] if host.count(":") == 1 else host


CSP = ("default-src 'self'; "
       # the outside scripts by their exact files, never a whole site (review 2026-11-13: unpkg and cdnjs serve any
       # package): Mapbox GL (its own folder: it loads its plug-ins from there), deck.gl and the QR-code library of the
       # authenticator set-up; each page tag also carries an integrity hash
       "script-src 'self' 'nonce-{nonce}' https://api.mapbox.com/mapbox-gl-js/ https://unpkg.com/deck.gl@9.1.14/dist.min.js "
       "https://cdnjs.cloudflare.com/ajax/libs/qrcode-generator/1.4.4/qrcode.min.js; "
       "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://api.mapbox.com; "
       "font-src 'self' data: https://fonts.gstatic.com; "
       "img-src 'self' data: blob: https://flagcdn.com https://api.mapbox.com https://*.tiles.mapbox.com; "
       "connect-src 'self' https://api.mapbox.com https://events.mapbox.com https://*.tiles.mapbox.com https://cdn.jsdelivr.net; "
       "worker-src 'self' blob:; child-src blob:; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'")


def _own_names():
    """This machine's host names and addresses (so http://<its-address>:5000 works without configuration)."""
    import socket
    names = set()
    try:
        hn = socket.gethostname()
        names |= {hn.lower(), socket.getfqdn().lower()}
        for info in socket.getaddrinfo(hn, None):
            names.add(info[4][0])
    except OSError:
        pass
    try:
        import subprocess
        names |= set(subprocess.run(["hostname", "-I"], capture_output=True, text=True, timeout=3).stdout.split())
    except Exception:
        pass
    return {n for n in names if n}


def access_mode():
    """local (this computer only), private (plus VIEWER_NETWORKS) or public (any address)."""
    spec = (os.environ.get("VIEWER_NETWORKS") or "").strip().lower()
    mode = (os.environ.get("ACCESS_MODE") or "").strip().lower()
    if spec in ("any", "*", "all", "0.0.0.0/0"):
        return "public"
    if mode in ("local", "private", "public"):
        return mode
    return "private" if spec else "local"


def install(app, logger=None):
    mode = access_mode()
    viewers = _networks(os.environ.get("VIEWER_NETWORKS"))
    any_host = (os.environ.get("ALLOWED_HOSTS") or "").strip() == "*"
    hosts = LOCAL_HOSTS | _own_names() | {h.lower() for h in _csv(os.environ.get("ALLOWED_HOSTS")) if h != "*"}
    app.config["MAX_CONTENT_LENGTH"] = 64 * 1024
    # behind a reverse proxy on this computer (Caddy / nginx doing HTTPS; docs/INSTALLATION.md): take the real client address,
    # scheme and host from its X-Forwarded-* headers, so address checks, session binding and Secure cookies still work.
    # Only with TRUST_PROXY=1, only from a proxy on this computer, and never without X-Forwarded-For (proxy_guard.py).
    import proxy_guard
    proxy_guard.install(app, os.environ.get("TRUST_PROXY") == "1")

    # this machine's own addresses change with the network (a laptop moving networks, DHCP): an unknown host name is checked
    # against them again, at most once a minute (2026-11-13: after a network change the new address was refused until a
    # restart). Only the machine's own names and addresses are added, never the name a request gives.
    own = {"at": time.monotonic(), "names": set()}

    def _refreshed_names():
        if time.monotonic() - own["at"] >= NAMES_REFRESH:
            own["at"] = time.monotonic()
            fresh = _own_names()
            if fresh - hosts and logger:
                logger.warning("This computer's addresses changed: now also answering on %s", ", ".join(sorted(fresh - hosts)))
            own["names"] = fresh
        return own["names"]

    def client_allowed():
        if mode == "public":
            return True
        try:
            addr = ipaddress.ip_address(request.remote_addr or "")
        except ValueError:
            return False
        return addr.is_loopback or (mode == "private" and any(addr in n for n in viewers))

    @app.before_request
    def _guard():
        g.csp_nonce = secrets.token_urlsafe(16)
        if not client_allowed():
            # visitors are not told how the server is configured (docs/INSTALLATION.md explains ACCESS_MODE to administrators)
            abort(403, description="Looking Glass is not available from your network. Contact the administrator.")
        if not any_host and _host_only(request.host) not in hosts and _host_only(request.host) not in _refreshed_names():
            abort(400, description="Unknown host name. Contact the administrator.")
        if request.method not in SAFE_METHODS:
            origin = request.headers.get("Origin")
            fetch_site = request.headers.get("Sec-Fetch-Site")
            if origin and origin != "null":
                o = urlsplit(origin)
                if (o.netloc or "").lower() != (request.host or "").lower():
                    abort(403, description="Cross-site requests are not accepted.")
            elif origin == "null" and fetch_site != "same-origin":
                # browsers send Origin: null for some same-site forms (pages with a no-referrer policy); they then
                # still say Sec-Fetch-Site: same-origin. Anything else with a null origin is refused.
                abort(403, description="Cross-site requests are not accepted.")
            if (fetch_site or "same-origin") not in ("same-origin", "none"):
                abort(403, description="Cross-site requests are not accepted.")
            # every route takes a JSON object: an array (or a bare value) is refused here, once, instead of failing
            # inside a route with a 500 (external review, 2026-11-12)
            # every JSON body, a chunked one too (it has no Content-Length: review 2026-11-13, a chunked array reached a
            # route and failed with a 500); the 64 KB limit still applies while it is read
            if request.mimetype == "application/json" and (request.content_length
                                                           or "chunked" in (request.headers.get("Transfer-Encoding") or "").lower()):
                body = request.get_json(silent=True)
                if body is not None and not isinstance(body, dict):
                    abort(400, description="Send the data as a JSON object.")

    @app.after_request
    def _headers(resp):
        h = resp.headers
        # a download named with letters outside Latin-1 (an organisation's name in an advisory, say) cannot go in the
        # header as it is and failed with a 500: an ASCII name for old browsers, the real one as filename* (RFC 6266,
        # external review, 2026-11-12)
        cd = h.get("Content-Disposition")
        if cd and not cd.isascii():
            import re as _re
            import unicodedata
            from urllib.parse import quote as _quote
            m = _re.match(r'\s*(\w+)\s*;\s*filename="([^"]*)"', cd)
            if m:
                disp, name = m.group(1), m.group(2)
                plain = unicodedata.normalize("NFKD", name).encode("ascii", "ignore").decode()
                plain = _re.sub(r'[^\w.\- ]+', "_", plain).strip() or "download"
                h["Content-Disposition"] = f'{disp}; filename="{plain}"; filename*=UTF-8\'\'{_quote(name, safe="")}'
        # CSP_REPORT_ONLY=1 (diagnostics): the browser reports what the policy would block instead of blocking it
        csp_header = "Content-Security-Policy-Report-Only" if os.environ.get("CSP_REPORT_ONLY") == "1" else "Content-Security-Policy"
        csp = CSP.format(nonce=getattr(g, "csp_nonce", ""))
        # one exception to "never framed": the Executive portal embedded in this site's own review page (combo_review.py),
        # framed by the same origin only; and the review page may frame this site, nothing else
        embed = request.path == "/management" and request.args.get("embed") == "1"
        if embed:
            csp = csp.replace("frame-ancestors 'none'", "frame-ancestors 'self'")
        if request.path.startswith("/review/"):
            csp = csp.replace("child-src blob:;", "child-src blob:; frame-src 'self';")
        h.setdefault(csp_header, csp)
        h.setdefault("X-Content-Type-Options", "nosniff")
        h.setdefault("X-Frame-Options", "SAMEORIGIN" if embed else "DENY")
        h.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")   # Mapbox URL-restricted tokens need the origin
        h.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        h.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")
        h["Server"] = "Looking Glass"
        return resp

    @app.context_processor
    def _nonce():
        return {"csp_nonce": getattr(g, "csp_nonce", "")}

    if logger:
        who = {"local": "this computer only", "public": "any address (public)",
               "private": f"this computer + {', '.join(map(str, viewers)) or '(no VIEWER_NETWORKS set)'}"}[mode]
        logger.warning("Access mode %s: %s; host names: %s", mode, who, "any" if any_host else ", ".join(sorted(hosts)))
