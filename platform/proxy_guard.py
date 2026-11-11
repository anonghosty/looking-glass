"""Behind a reverse proxy (TRUST_PROXY=1): which X-Forwarded-* headers are believed, and what happens without them.

With TRUST_PROXY=1 the visitor's address, scheme and host come from the proxy's X-Forwarded-* headers (werkzeug
ProxyFix). Two traps are closed here:

* The proxy must be on this computer: forwarded headers are believed only from a loopback peer. From any other peer
  they are removed before ProxyFix sees them, so a visitor who reaches the app port directly cannot claim to be
  127.0.0.1 by sending "X-Forwarded-For: 127.0.0.1".
* A proxy that does not send X-Forwarded-For would make every visitor look like 127.0.0.1 (the proxy's own address):
  "this computer" would let them past ACCESS_MODE=local, the HTTPS rule for sign-in, and the first-administrator page.
  So a request from the loopback peer without X-Forwarded-For is refused (400, with what to fix), except /healthz
  (no data; the service checks call it directly). Programs on this computer that call the app directly behind a proxy
  send "X-Forwarded-For: 127.0.0.1", as the check scripts do.
"""
import ipaddress

FORWARDED = ("HTTP_X_FORWARDED_FOR", "HTTP_X_FORWARDED_PROTO", "HTTP_X_FORWARDED_HOST", "HTTP_X_FORWARDED_PORT",
             "HTTP_X_FORWARDED_PREFIX", "HTTP_FORWARDED")
ALWAYS = ("/healthz",)
MESSAGE = (b"Looking Glass is set up behind a reverse proxy (TRUST_PROXY=1), but this request did not say who the "
           b"visitor is: the proxy must send X-Forwarded-For (see docs/INSTALLATION.md, 'HTTPS with a reverse proxy'). "
           b"Contact the administrator.\n")


def _loopback(addr):
    try:
        return ipaddress.ip_address((addr or "").split("%")[0]).is_loopback
    except ValueError:
        return False


class ForwardedGuard:
    def __init__(self, wsgi_app):
        self.inner = wsgi_app

    def __call__(self, environ, start_response):
        if not _loopback(environ.get("REMOTE_ADDR")):
            for h in FORWARDED:                       # not our proxy: its forwarded headers mean nothing
                environ.pop(h, None)
        elif not (environ.get("HTTP_X_FORWARDED_FOR") or "").strip() and environ.get("PATH_INFO", "") not in ALWAYS:
            start_response("400 Bad Request", [("Content-Type", "text/plain; charset=utf-8"),
                                               ("Content-Length", str(len(MESSAGE))), ("Cache-Control", "no-store")])
            return [MESSAGE]
        return self.inner(environ, start_response)


def install(app, enabled):
    """Wrap the app: ProxyFix (believe one proxy) inside the guard. Nothing changes when `enabled` is false."""
    if not enabled:
        return False
    from werkzeug.middleware.proxy_fix import ProxyFix
    app.wsgi_app = ForwardedGuard(ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1))
    return True
