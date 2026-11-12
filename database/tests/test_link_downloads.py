#!/usr/bin/env python3
"""Shadowserver link downloads stop at ZIP_MAX_UNPACKED_MB and keep nothing past it (external review, 2026-11-12), and
Block mode fails closed when the sender check cannot run. No network: a fake session stands in for requests.
Run: .venv/bin/python tests/test_link_downloads.py"""
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import shadowserver_pipeline as P  # noqa: E402

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info else ""))


class Resp:
    def __init__(self, size, announce=True, name="2026-11-12-scan_x-report.csv"):
        self.status_code, self.size = 200, size
        self.headers = {"Content-Disposition": f'attachment; filename="{name}"'}
        if announce:
            self.headers["Content-Length"] = str(size)

    def iter_content(self, chunk_size):
        left = self.size
        while left > 0:
            n = min(chunk_size, left)
            left -= n
            yield b"x" * n

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class Session:
    def __init__(self, resp):
        self.resp = resp

    def get(self, url, **kw):
        return self.resp


MB = 2 ** 20
with tempfile.TemporaryDirectory() as d:
    dest = Path(d)
    st, text, name = P._download_link(Session(Resp(3 * MB)), "https://dl.shadowserver.org/a", dest, max_bytes=5 * MB)
    ok("a link under the limit is downloaded", st is True and (dest / name).stat().st_size == 3 * MB, text)
    st, text, _ = P._download_link(Session(Resp(9 * MB, name="big1.csv")), "https://dl.shadowserver.org/b", dest, max_bytes=5 * MB)
    ok("a link announcing more than the limit is refused before downloading", st is None and "larger than" in text
       and not (dest / "big1.csv").exists(), text)
    st, text, _ = P._download_link(Session(Resp(9 * MB, announce=False, name="big2.csv")), "https://dl.shadowserver.org/c", dest,
                                   max_bytes=5 * MB)
    ok("a link that does not announce its size is stopped at the limit, nothing kept (no .part left)",
       st is None and "download stopped" in text and not (dest / "big2.csv").exists()
       and not any(p.name.endswith(".part") for p in dest.iterdir()), text)
print("Block mode fails closed")
import types  # noqa: E402
from collections import Counter  # noqa: E402


class FakeSrc:
    listed = closed = False

    def list(self, days):
        FakeSrc.listed = True
        return []

    def close(self):
        FakeSrc.closed = True

    def describe(self):
        return "a fake mailbox"

    def fetch(self, items):
        return iter(())


def broken_log(*a, **k):
    raise OSError("database is locked")


real = (P.mail_sources.make_source, P.mail_auth.Log, os.environ.get("MAIL_AUTH"))
with tempfile.TemporaryDirectory() as d:
    s = types.SimpleNamespace(attachments_dir=Path(d) / "att", base_dir=Path(d), days=1)
    P.mail_sources.make_source, P.mail_auth.Log = (lambda env=None: FakeSrc()), broken_log
    try:
        os.environ["MAIL_AUTH"] = "enforce"
        try:
            P.pull_emails(s, Counter())
            raised = None
        except RuntimeError as exc:
            raised = str(exc)
        ok("Block on, the sender log cannot be opened: no e-mail is read this run (an error, not unchecked loading)",
           raised and "no e-mail is read" in raised and not FakeSrc.listed and FakeSrc.closed, raised or "went on")
        os.environ["MAIL_AUTH"] = "log"
        FakeSrc.listed = False
        P.pull_emails(s, Counter())
        ok("…Record only: the run goes on (nothing is held back then anyway)", FakeSrc.listed)
    finally:
        P.mail_sources.make_source, P.mail_auth.Log = real[0], real[1]
        if real[2] is None:
            os.environ.pop("MAIL_AUTH", None)
        else:
            os.environ["MAIL_AUTH"] = real[2]
print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
