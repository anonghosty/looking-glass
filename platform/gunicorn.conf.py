"""gunicorn reads this file automatically (it is in the service's working directory).

HTTPS: when data/tls/cert.pem and data/tls/key.pem exist, Looking Glass is served over HTTPS on the same port.
Create them with deploy/make_tls_cert.sh (self-signed, for a few screens on a local network) or copy in a certificate
from your organisation's CA. Other computers can only log in over HTTPS (auth.py), so passwords and session cookies are
never sent in clear over the network.

The bind address stays on the command line of the service (deploy/looking-glass.service.template); see docs/INSTALLATION.md.
"""
import os

_d = os.path.dirname(os.path.abspath(__file__))

# Settings → Configuration (config_page.py): .env, then the values kept on that page, before the app is loaded, so every
# module reads them (a value kept there takes precedence over .env). A problem here never stops the service.
try:
    import sys as _sys
    _sys.path.insert(0, _d)
    import config_page as _config_page
    _config_page.apply(_d)
except Exception as _e:                  # noqa: BLE001
    print(f"Settings → Configuration not applied: {_e}")
_cert, _key = os.path.join(_d, "data", "tls", "cert.pem"), os.path.join(_d, "data", "tls", "key.pem")
if os.path.exists(_cert) and os.path.exists(_key):
    certfile, keyfile = _cert, _key       # Python's defaults: TLS 1.2+ only

# gunicorn's own hardening
limit_request_line = 8190
limit_request_fields = 100
limit_request_field_size = 8190
forwarded_allow_ips = "127.0.0.1"     # only a reverse proxy on this computer may set X-Forwarded-* headers
# gunicorn 25.1+ opens a control socket (for its gunicornc tool) in ~/.gunicorn; Looking Glass does not use it, and the
# hardened service makes the home folder read-only, which would log "Control server error" at every start.
# Older gunicorn versions ignore this setting.
control_socket_disable = True
# The worker must report to gunicorn within `timeout` seconds or it is killed and restarted (losing the days in memory).
# Loading a day from MongoDB and a burst of heavy Executive requests can keep it busy for longer than the default 30 s
# (seen 2026-11-09: "WORKER TIMEOUT"), so allow 2 minutes; a worker that is truly stuck is still replaced.
timeout = 120
# The access log (the service's journal) keeps who asked for which page and how it went, never what was asked: no query
# string (it can hold host addresses, account names and searches), no referring page (its URL can too), no browser
# string. Views of host data are in the audit log instead, with hosts as opaque references (2026-11-14).
access_log_format = '%(h)s %(t)s "%(m)s %(U)s %(H)s" %(s)s %(b)s %(L)ss'


# No Server header (2026-11-14): gunicorn names itself ("Server: gunicorn") in every response, which tells a scanner
# what answers before anyone signs in. The header is dropped; nothing else in the response changes.
def _no_server_header():
    try:
        from gunicorn.http import wsgi as _wsgi
        if getattr(_wsgi.Response.default_headers, "_lg_no_server", False):
            return
        original = _wsgi.Response.default_headers

        def default_headers(self):
            return [h for h in original(self) if not h.lower().startswith("server:")]
        default_headers._lg_no_server = True
        _wsgi.Response.default_headers = default_headers
    except Exception:          # noqa: BLE001  (another gunicorn layout: the header stays, the service still starts)
        pass


_no_server_header()


# A neutral answer to a request too malformed to reach Looking Glass (the user, 2026-11-20, after a scan: nmap's garbled
# request got gunicorn's own error page, "Invalid Request Line '…'", which names the server to anyone who knows it, and
# it repeated what was sent). The same plain page as every other error (neutral.plain_page): the status in plain words,
# nothing echoed back, no template. The status code itself is unchanged (400, 431, …).
def _neutral_bad_request():
    try:
        from gunicorn import util as _util
        if getattr(_util.write_error, "_lg_neutral", False):
            return

        def write_error(sock, status_int, reason, mesg):
            words = " ".join(str(reason or "Bad Request").split())[:40] or "Bad Request"
            body = (f"<!doctype html><meta charset=\"utf-8\"><title>{words}</title>"
                    f"<p style=\"font-family:sans-serif\">{words}.</p>").encode("utf-8")
            head = (f"HTTP/1.1 {int(status_int)} {words}\r\nConnection: close\r\nContent-Type: text/html; charset=utf-8\r\n"
                    f"Content-Length: {len(body)}\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: DENY\r\n"
                    "Content-Security-Policy: default-src 'none'; frame-ancestors 'none'\r\nCache-Control: no-store\r\n\r\n")
            _util.write_nonblock(sock, head.encode("latin-1") + body)
        write_error._lg_neutral = True
        _util.write_error = write_error
    except Exception:          # noqa: BLE001  (another gunicorn layout: its page stays, the service still starts)
        pass


_neutral_bad_request()


# One worker process, always (review 2026-11-15). Sessions, the failed-sign-in counters, the sign-in steps and the days
# in memory live in that one process: with --workers 4 a session made in one worker is unknown to the other three, and
# people would be signed out at random. The service runs "--workers 1 --threads 8"; the command line overrides this
# file, so a setting here could not stop "--workers 4" - refusing to start does. For more load, raise --threads.
def on_starting(server):
    if server.cfg.workers != 1:
        msg = (f"Looking Glass runs in exactly one worker process (asked for {server.cfg.workers}): sessions and sign-in "
               "limits live in that process, so more workers would sign people out at random. Use --workers 1 and raise "
               "--threads for more load (gunicorn.conf.py).")
        server.log.error(msg)
        raise SystemExit(msg)
    # No recycling after a number of requests (review 2026-11-15): --max-requests replaces the worker after N requests,
    # and the request count is something anyone can drive, so a visitor could send requests until the worker is
    # replaced, which clears the failed-sign-in counters held in memory (their own lock included), and carry on
    # guessing. A recycle would also drop sign-ins in their second step, the kept answers and the loaded days.
    if getattr(server.cfg, "max_requests", 0):
        msg = (f"Looking Glass refuses --max-requests ({server.cfg.max_requests}): a worker replaced after a number of "
               "requests would clear the sign-in limits, and anyone can send requests. Leave it unset (gunicorn.conf.py).")
        server.log.error(msg)
        raise SystemExit(msg)
