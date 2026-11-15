#!/usr/bin/env python3
"""Addresses that come from .env are fetched over https only (static analysis, 2026-11-15): the report feed
(REPORT_MAP_FEED_URL, report_map.py) and Shadowserver's report API (SHADOWSERVER_API_URL, pipeline_settings.py). A
file: or plain http address is refused before anything is opened, so neither can read a local file or send the API key
in clear. Nothing is fetched: every address tried here is refused first. Run: .venv/bin/python tests/check_https_only.py"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import report_map, pipeline_settings  # noqa: E402

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond: fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info else ""), flush=True)


print("Report feed")
for url in ("file:///etc/passwd", "http://example.org/feed.json", "ftp://example.org/feed.json"):
    try:
        report_map._get(url); refused = False
    except ValueError as e:
        refused = "only https" in str(e)
    ok(f"refused: {url.split(':')[0]}:", refused)
print("Report API")
for url in ("file:///etc", "http://example.org/api2/"):
    ans, err = pipeline_settings._api("test/ping", "key-not-used", "secret-not-used", url=url)
    ok(f"refused: {url.split(':')[0]}:, and the key never leaves", ans is None and "https" in err, err)

print("Redirects (a local https server, throwaway certificate)")
import http.server, ssl, subprocess, tempfile, threading, urllib.request  # noqa: E402,E401
import https_only  # noqa: E402
with tempfile.TemporaryDirectory() as d:
    made = subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", f"{d}/k.pem", "-out",
                           f"{d}/c.pem", "-days", "1", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost"],
                          capture_output=True).returncode == 0
    if made:
        class _H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == "/ok":
                    self.send_response(200); self.end_headers(); self.wfile.write(b"fine"); return
                self.send_response(302)
                self.send_header("Location", {"/to-http": "http://localhost:1/x", "/to-file": "file:///etc/hostname"}.get(self.path, "/ok"))
                self.end_headers()

            def log_message(self, *a):
                pass
        srv = http.server.HTTPServer(("localhost", 0), _H)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(f"{d}/c.pem", f"{d}/k.pem")
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        port, real = srv.server_address[1], https_only._OPENER
        https_only._OPENER = urllib.request.build_opener(https_only._HttpsRedirectsOnly,
                                                         urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=f"{d}/c.pem")))
        try:
            for path in ("/to-http", "/to-file"):
                try:
                    https_only.open(f"https://localhost:{port}{path}", 5); refused = False
                except (https_only.NotHttps, urllib.error.HTTPError):   # urllib itself refuses file:, ours refuses http:
                    refused = True
                ok(f"a redirect from https to {path[4:]}: refused", refused)
            with https_only.open(f"https://localhost:{port}/stay", 5) as r:
                ok("a redirect that stays on https: followed", r.read() == b"fine")
        finally:
            https_only._OPENER = real
            srv.shutdown()
    else:
        print("  (openssl not available: redirect checks not run)")

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
