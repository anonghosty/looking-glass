#!/usr/bin/env python3
"""Nothing answers without signing in (the user, 2026-11-20, after reading a write-up on a hospital system whose
dashboard opened without a login and whose sign-in page carried activity figures: "add it" as a permanent check).

Against this installation's running service (its own address, this computer), signed out (no cookie):
1. Every route the platform declares, asked with GET, and with POST where the route takes it: only the public
   pages (auth.PUBLIC_PATHS: sign in, create an account, forgot password, log out, /healthz for this computer) may
   answer; everything else is refused (401 / 403 / 404 / 405) or sent to the sign-in page. A new route that forgets
   the sign-in fails here.
2. A route's id in the address changes nothing: the same routes with made-up ids, and with an identity in the query
   (user=, role=, seat=…), are refused the same way.
3. The sign-in page carries no data: no embedded figures or data objects, no session cookie before signing in, no
   product or server names in its headers, and it cannot be shown inside another site.
Skipped (exit 77) when the service is not running here. Only GET and POST with an empty body; signed out, so no
route handler runs.
"""
import glob
import os
import re
import ssl
import sys
import urllib.error
import urllib.request
from html.parser import HTMLParser

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if not os.path.isdir(os.path.join(ROOT, "static", "js")):      # run from a draft folder: the platform is the current one
    ROOT = os.getcwd()
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tests"))
checks, fails = 0, []


def ok(name, cond, detail=""):
    global checks
    checks += 1
    if cond:
        print(f"  ok   {name}")
    else:
        fails.append(name)
        print(f"  FAIL {name}  {str(detail)[:600]}")


try:
    from lgauth import PORT
except Exception:                                              # noqa: BLE001
    PORT = int(os.environ.get("LG_PORT", "5000") or 5000)
TLS = os.path.exists(os.path.join(ROOT, "data", "tls", "cert.pem"))
BASE = os.environ.get("LG_SIGNED_OUT_BASE") or (("https" if TLS else "http") + f"://127.0.0.1:{PORT}")
def tls_context():
    """A client context for this installation's own HTTPS: TLS 1.2 or newer only, as the service (set where it is made,
    so it is plain at every use: CodeQL py/insecure-protocol); the installation's own certificate trusted, its name not
    checked (the address is 127.0.0.1)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    if TLS:
        ctx.load_verify_locations(cafile=os.path.join(ROOT, "data", "tls", "cert.pem"))
    else:
        ctx.load_default_certs()
    ctx.check_hostname = False
    ctx.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN
    return ctx


CTX = tls_context() if BASE.startswith("https") else None


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


OPENER = urllib.request.build_opener(NoRedirect(), *([urllib.request.HTTPSHandler(context=CTX)] if CTX else []))
OPENER.addheaders = [("User-Agent", "LookingGlass-signed-out-check/1.0")]


def ask(path, method="GET"):
    """(status, headers, body) signed out; -1 when the service did not answer."""
    data = b"" if method == "POST" else None
    r = urllib.request.Request(BASE + path, data=data, method=method)
    try:
        with OPENER.open(r, timeout=30) as resp:                # nosec B310  this installation's own address
            return resp.status, dict(resp.headers), resp.read(400000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read(4000).decode("utf-8", "replace")
    except (urllib.error.URLError, OSError) as e:
        return -1, {}, str(e)


if ask("/login")[0] == -1:
    print(f"SKIPPED: the service does not answer at {BASE} (run on the server, with the service running)")
    sys.exit(77)

import auth  # noqa: E402
PUBLIC = tuple(auth.PUBLIC_PATHS)

# every route the platform declares (app.py and the feature modules), with its methods
ROUTE = re.compile(r"""\.route\(\s*["']([^"']+)["']\s*(?:,\s*methods\s*=\s*[\[(]([^\])]*)[\])])?""")
routes = {}
for f in sorted(glob.glob(os.path.join(ROOT, "*.py"))):
    for m in ROUTE.finditer(open(f, encoding="utf-8").read()):
        meths = set(re.findall(r"[A-Z]+", m.group(2) or "")) or {"GET"}
        routes.setdefault(m.group(1), set()).update(meths)


def concrete(rule, fill="1"):
    return re.sub(r"<[^>]+>", fill, rule)


def refused(code, headers):
    if code in (401, 403, 404, 405):
        return True
    if code in (301, 302, 303, 307, 308):
        loc = headers.get("Location", "")
        return loc.startswith("/login") or "/login" in loc.split("?")[0][-7:]
    return False


print(f"1. Every route, signed out ({len(routes)} declared, at {BASE})")
ok("the routes were found (the platform's sources were read)", len(routes) > 100, len(routes))
answered, posted = [], []
for rule, meths in sorted(routes.items()):
    path = concrete(rule)
    if path.startswith(PUBLIC):
        continue
    code, h, body = ask(path)
    if not refused(code, h):
        answered.append(f"GET {path}: {code}")
    if "POST" in meths:
        code, h, body = ask(path, "POST")
        if not refused(code, h):
            posted.append(f"POST {path}: {code}")
ok("every route but the public pages refuses a signed-out GET (or sends it to sign in)", not answered, answered[:12])
ok("…and a signed-out POST", not posted, posted[:12])

print("2. An id or an identity in the address changes nothing")
odd = []
for rule in sorted(routes):
    if "<" not in rule or rule.startswith(PUBLIC):
        continue
    for fill in ("0", "999999", "LG-A-00000000", "..%2F..%2Fdata%2Fusers.json"):
        code, h, _ = ask(concrete(rule, fill))
        if not refused(code, h):
            odd.append(f"{concrete(rule, fill)}: {code}")
ok("routes with made-up ids are refused the same way", not odd, odd[:10])
who = []
for path in ("/overview", "/api/me", "/api/stats", "/findings", "/api/findings", "/management", "/advisory", "/audit"):
    for q in ("?user=admin&role=admin", "?seatId=1&isGlobal=1&isPreview=1", "?automation=1", "?as=admin"):
        code, h, _ = ask(path + q)
        if not refused(code, h):
            who.append(f"{path}{q}: {code}")
ok("an identity or a role in the query string is ignored (who you are comes from the session only)", not who, who[:10])
code, h, _ = ask("/api/me")
ok("…even this computer's own requests need a session or the automation key", refused(code, h), code)

print("3. The sign-in page carries no data")
code, h, body = ask("/login")
ok("the sign-in page opens", code == 200, code)


class InlineScripts(HTMLParser):
    """The text of every inline <script> on a page, read by Python's HTML parser (not a pattern: CodeQL
    py/bad-tag-filter); a script with src= is a file, not inline."""
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.found, self._in = [], False

    def handle_starttag(self, tag, attrs):
        if tag == "script" and not any(k == "src" for k, _ in attrs):
            self._in = True
            self.found.append("")

    def handle_endtag(self, tag):
        if tag == "script":
            self._in = False

    def handle_data(self, data):
        if self._in:
            self.found[-1] += data


_ip = InlineScripts()
_ip.feed(body)
blobs = _ip.found
data_blobs = [b.strip()[:80] for b in blobs if re.search(r"[\[{]\s*\"[^\"]+\"\s*:|JSON\.parse|\b[A-Z_]{4,}\s*=", b)]
ok("no data in it (no embedded data objects or figures in its scripts)", not data_blobs, data_blobs[:3])
ok("…and no data scripts in its own files", not re.search(r'type=["\']application/(ld\+)?json', body))
# counts look like 58,516 or 1234 (the password rules' "123" hint and "12+ characters" are not figures)
figures = [n for n in re.findall(r">[^<]*?\b(\d{1,3}(?:,\d{3})+|\d{4,})\b[^<]*<", body)]
ok("no figures in its text (counts of four digits or more)", not figures, figures[:6])
cookies = [c for k, c in h.items() if k.lower() == "set-cookie"]
ok("no session cookie before signing in", not any(re.search(r"(lg_session|__Host-lg)=", c) for c in cookies), cookies)
ok("no product, framework or server name in its headers", not any(k.lower() in ("server", "x-powered-by") and re.search(r"werkzeug|gunicorn|flask|python|nginx", v, re.I)
                                                                    for k, v in h.items()), {k: v for k, v in h.items() if k.lower() in ("server", "x-powered-by")})
hl = {k.lower(): v for k, v in h.items()}
ok("it cannot be shown inside another site (frame-ancestors 'none' / DENY)", "frame-ancestors 'none'" in hl.get("content-security-policy", "")
   or hl.get("x-frame-options", "").upper() == "DENY", hl.get("x-frame-options"))
ok("passwords are checked on the server with a slow hash, nothing hashed in the browser",
   "generate_password_hash(" in open(os.path.join(ROOT, "auth.py"), encoding="utf-8").read()
   and not re.search(r"sha-?512|sha-?1\b|jsSHA", body, re.I))

print("4. A request too malformed to reach Looking Glass gets the same plain page (gunicorn.conf.py, 2026-11-20)")
import socket  # noqa: E402
from urllib.parse import urlsplit  # noqa: E402
host, port = urlsplit(BASE).hostname, urlsplit(BASE).port or (443 if BASE.startswith("https") else 80)


def raw(data):
    s = socket.create_connection((host, port), timeout=10)
    if BASE.startswith("https"):
        s = tls_context().wrap_socket(s, server_hostname=host)
    s.sendall(data)
    out = b""
    try:
        while len(out) < 20000:
            b = s.recv(4096)
            if not b:
                break
            out += b
    except (socket.timeout, OSError):
        pass
    s.close()
    return out.decode("latin-1")


# every kind the status sweep of 2026-11-20 found answered by the server's own page (10 of ~40 requests)
_H = b"Host: x\r\nConnection: close\r\n"
for name, data in (("a garbled request line", b"GARBAGE\r\n\r\n"), ("a broken header", b"GET / HTTP/1.1\r\n" + _H + b"Bad Header\r\n\r\n"),
                   ("a request line over the limit", b"GET /" + b"a" * 9000 + b" HTTP/1.1\r\n" + _H + b"\r\n"),
                   ("markup in a header", b"GET / HTTP/1.1\r\n" + _H + b"<script>alert(1)</script>\r\n\r\n"),
                   ("a method with odd characters", b"G@T / HTTP/1.1\r\n" + _H + b"\r\n"),
                   ("an unknown HTTP version", b"GET / HTTP/9.9\r\n" + _H + b"\r\n"),
                   ("an HTTP/2 opener on the HTTP/1 port", b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"),
                   ("a header with a NUL byte", b"GET / HTTP/1.1\r\n" + _H + b"X-A: a\x00b\r\n\r\n"),
                   ("101 headers (over the limit: 431)", b"GET / HTTP/1.1\r\n" + _H + b"".join(b"X-H%d: v\r\n" % i for i in range(101)) + b"\r\n"),
                   ("a 9,000-byte header (431)", b"GET / HTTP/1.1\r\n" + _H + b"X-Long: " + b"a" * 9000 + b"\r\n\r\n"),
                   ("chunked plus Content-Length (request smuggling: refused)",
                    b"POST /login HTTP/1.1\r\n" + _H + b"Content-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n")):
    r = raw(data)
    leaks = [w for w in ("Invalid", "gunicorn", "Request Line", "Bad Header", "<script>", "aaaaaaaa", "<h1><p>") if w in r]
    ok(f"{name}: a 4xx with the plain page, nothing of the server's own page, nothing echoed back",
       r.startswith("HTTP/1.1 4") and r.split("\r\n\r\n", 1)[-1].startswith("<!doctype html>") and not leaks, (r[:160], leaks))
src = open(os.path.join(ROOT, "gunicorn.conf.py"), encoding="utf-8").read()
ok("…set in gunicorn.conf.py (one place, at start)", "def _neutral_bad_request" in src and "_util.write_error = write_error" in src)

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {fails}" if fails else ""))
sys.exit(1 if fails else 0)
