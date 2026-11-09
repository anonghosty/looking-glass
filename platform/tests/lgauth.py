"""Lets the check scripts on this computer call the Looking Glass API now that every page needs a login.

`import lgauth` (first, before other urllib use):
* adds the automation key from data/automation.key to every request (X-LG-Automation). The server accepts it from
  this computer only (auth.py).
* requests written as http://127.0.0.1:5000 or http://localhost:5000 go to this installation's port (LG_PORT in
  .env, default 5000), and to https:// when HTTPS is on (data/tls/cert.pem, see gunicorn.conf.py), trusting the local
  certificate."""
import os
import ssl
import urllib.request

_D = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data")
try:
    with open(os.path.join(_D, "automation.key")) as _f:
        KEY = _f.read().strip()
except OSError:
    KEY = ""
HEADERS = {"X-LG-Automation": KEY} if KEY else {}
_CERT = os.path.join(_D, "tls", "cert.pem")


def _port():
    if os.environ.get("LG_PORT"):
        return os.environ["LG_PORT"].strip()
    try:
        for line in open(os.path.join(_D, "..", ".env"), encoding="utf-8"):
            if line.strip().startswith("LG_PORT="):
                return line.split("=", 1)[1].strip().strip("'\"") or "5000"
    except OSError:
        pass
    return "5000"


PORT = _port()
TLS = os.path.exists(_CERT)
_ctx = None
if TLS:
    _ctx = ssl.create_default_context(cafile=_CERT)
    _ctx.check_hostname = False          # the certificate may name the machine, not 127.0.0.1

_opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=_ctx)) if _ctx else urllib.request.build_opener()
_opener.addheaders = [(k, v) for k, v in HEADERS.items()] + [("User-Agent", "LookingGlass-checks")]
urllib.request.install_opener(_opener)

_orig = urllib.request.urlopen


BASE = ("https" if TLS else "http") + f"://127.0.0.1:{PORT}"


def _local_tls(url):
    for p in ("http://127.0.0.1:5000", "http://localhost:5000"):
        if url.startswith(p):
            return BASE + url[len(p):]
    return url


def urlopen(url, *a, **kw):
    if TLS or PORT != "5000":
        if isinstance(url, str):
            url = _local_tls(url)
        elif isinstance(url, urllib.request.Request) and _local_tls(url.full_url) != url.full_url:
            url.full_url = _local_tls(url.full_url)
    return _orig(url, *a, **kw)


urllib.request.urlopen = urlopen
