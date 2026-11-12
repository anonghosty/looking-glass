#!/usr/bin/env python3
"""The sender check inside the real pull_emails(), with a fake mailbox, keys made here and DNS answered here
(nothing leaves the computer, nothing touches the real mailbox, folders or database):
- blocking off (MAIL_AUTH=log): every report is processed, each result recorded;
- blocking on (MAIL_AUTH=enforce): a signed report is processed; an unsigned one, a forged one and one signed by another
  domain are held back in quarantine/mail_auth/ (not in attachments_backup, their links not fetched); one whose DNS look-up
  did not answer is left for the next run;
- an administrator's release lets a held-back report through on the next run, and the record says so.
Run: .venv/bin/python tests/test_mail_auth_pipeline.py"""
import base64, hashlib, os, sys, tempfile
from collections import Counter
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import padding, rsa  # noqa: E402
import mail_auth  # noqa: E402
import shadowserver_pipeline as sp  # noqa: E402

fails, checks = [], 0


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info else ""), flush=True)


KEY, OTHER = (rsa.generate_private_key(public_exponent=65537, key_size=2048) for _ in range(2))
PUB = base64.b64encode(KEY.public_key().public_bytes(serialization.Encoding.DER,
                                                      serialization.PublicFormat.SubjectPublicKeyInfo)).decode()
DNS = {"mail._domainkey.shadowserver.org": f"v=DKIM1; k=rsa; p={PUB}", "mail._domainkey.example.net": f"v=DKIM1; k=rsa; p={PUB}"}


class Timeout(Exception):
    pass


class NXDOMAIN(Exception):
    pass


def resolver(name):
    if name.startswith("slow."):
        raise Timeout()
    if name not in DNS:
        raise NXDOMAIN()
    return DNS[name].encode()


def report(n, sign_with=KEY, d="shadowserver.org", s="mail", link=False):
    """A report e-mail with one zip attachment (or only a download link), signed like Shadowserver signs."""
    name = f"2026-11-12-scan_test{n}-example-geo.zip"
    head = [b"From: Shadowserver <autoreports@shadowserver.org>", b"To: csirt@example.org",
            f"Subject: Test report {n}".encode(), b"Date: Thu, 12 Nov 2026 08:34:14 +0000",
            f"Message-ID: <r{n}@shadowserver.org>".encode(), b"MIME-Version: 1.0",
            b'Content-Type: multipart/mixed; boundary="BB"']
    parts = [b"--BB", b"Content-Type: text/plain", b"",
             (f"Download: https://dl.shadowserver.org/test{n}" if link else "Your report is attached.").encode()]
    if not link:
        parts += [b"--BB", b"Content-Type: application/zip", f'Content-Disposition: attachment; filename="{name}"'.encode(),
                  b"Content-Transfer-Encoding: base64", b"", base64.b64encode(f"PK fake zip {n}".encode())]
    body = b"\r\n".join(parts + [b"--BB--", b""])
    if sign_with is None:
        return name, b"\r\n".join(head) + b"\r\n\r\n" + body
    bh = base64.b64encode(hashlib.sha256(mail_auth._canon_body(body, "simple")).digest()).decode()
    sig = f"DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/simple; d={d}; s={s}; h=From:To:Subject:Date:Message-ID; bh={bh}; b="
    data = b"".join(mail_auth._canon_header(next(f for f in head if f.startswith(h + b":")), "relaxed") + b"\r\n"
                    for h in (b"From", b"To", b"Subject", b"Date", b"Message-ID")) + mail_auth._canon_header(sig.encode(), "relaxed")
    b = sign_with.sign(data, padding.PKCS1v15(), hashes.SHA256())
    return name, (sig + base64.b64encode(b).decode()).encode() + b"\r\n" + b"\r\n".join(head) + b"\r\n\r\n" + body


class FakeBox:
    def __init__(self, msgs):
        self.msgs = msgs                                  # [(key, raw)]

    def describe(self):
        return "fake mailbox"

    def list(self, days):
        return [(k, k) for k, _ in self.msgs]

    def fetch(self, items):
        want = {k for k, _ in items}
        for k, raw in self.msgs:
            if k in want:
                yield k, raw

    def close(self):
        pass


fetched_links = []
sp._download_links = lambda links, d, threads, stats, **kw: [(u, fetched_links.append(u) or f"{abs(hash(u))}.zip") for u in links]
real_checker = mail_auth.Checker
sp.mail_auth.Checker = lambda domain="shadowserver.org": real_checker(domain, resolver=resolver)


def settings(base):
    return sp.Settings(env_file=base / ".env", imap_server="", imap_user="", imap_password="", imap_folder="inbox",
                       imap_verify_tls=True, mongo={}, mongo_db="t", mongo_cache_gb=1.0, base_dir=base, workers=1,
                       insert_chunk=100, download_threads=1, fetch_batch=10, days=3)


def run(base, msgs, mode):
    os.environ["MAIL_AUTH"] = mode
    sp.mail_sources.make_source = lambda env=None: FakeBox(msgs)
    sp.pull_emails(settings(base), Counter())


def records(base):
    log = mail_auth.Log(base / ".mail_state.sqlite")
    rows = {k: (r, a) for k, r, a in log.db.execute("SELECT key, result, action FROM mail_auth")}
    log.close()
    return rows


good, bad_none, bad_forged, bad_other, slow, linked = (report(1), report(2, sign_with=None), report(3, sign_with=OTHER),
                                                       report(4, d="example.net"), report(5, s="slow"), report(6, sign_with=None, link=True))
MSGS = [("k1", good[1]), ("k2", bad_none[1]), ("k3", bad_forged[1]), ("k4", bad_other[1]), ("k5", slow[1]), ("k6", linked[1])]

print("Blocking off (MAIL_AUTH=log): everything processed, every result recorded")
with tempfile.TemporaryDirectory() as d:
    base = Path(d)
    run(base, MSGS, "log")
    att = {p.name for p in (base / "attachments_backup").glob("*")}
    ok("every attachment saved as before", {good[0], bad_none[0], bad_forged[0], bad_other[0], slow[0]} <= att, f"{len(att)} saved")
    rec = records(base)
    ok("each message recorded with its result, all kept", {k: v[0] for k, v in rec.items()} == {"k1": "pass", "k2": "none",
       "k3": "fail", "k4": "other", "k5": "temperror", "k6": "none"} and {v[1] for v in rec.values()} == {"kept"}, str(rec))
    ok("nothing held back", not mail_auth.held(base))

print("Blocking on (MAIL_AUTH=enforce)")
fetched_links.clear()
with tempfile.TemporaryDirectory() as d:
    base = Path(d)
    run(base, MSGS, "enforce")
    att = {p.name for p in (base / "attachments_backup").glob("*")}
    ok("the signed report is processed", good[0] in att)
    ok("unsigned, forged and other-domain reports are NOT in attachments_backup",
       not ({bad_none[0], bad_forged[0], bad_other[0]} & att), str(sorted(att)))
    held = {m["key"]: (q, m) for q, m in mail_auth.held(base)}
    ok("…they are held in quarantine/mail_auth/, each with its files and reason",
       set(held) == {"k2", "k3", "k4", "k6"} and all((q / m["files"][0]).exists() for k, (q, m) in held.items() if m["files"]),
       str(sorted(held)))
    ok("a held-back report's download link is noted, not fetched",
       held["k6"][1]["links"] == ["https://dl.shadowserver.org/test6"] and not fetched_links, str(fetched_links))
    ok("a report whose DNS look-up did not answer is not saved now (tried again next run)", slow[0] not in att and "k5" not in held)
    rec = records(base)
    ok("the record says what happened to each", rec["k1"] == ("pass", "kept") and rec["k2"] == ("none", "quarantined")
       and rec["k3"] == ("fail", "quarantined") and rec["k4"] == ("other", "quarantined") and rec["k5"] == ("temperror", "retry"), str(rec))
    state = sp.mail_sources.MailState(base / ".mail_state.sqlite")
    done = state.done_messages(); state.close()
    ok("held-back messages are not fetched again; the DNS one is", {"k1", "k2", "k3", "k4", "k6"} <= done and "k5" not in done, str(sorted(done)))

    print("An administrator releases one")
    mail_auth.request_release(held["k2"][0], "lg-admin (after their password)")
    mail_auth.request_release(held["k6"][0], "lg-admin (after their password)")
    run(base, MSGS, "enforce")
    att = {p.name for p in (base / "attachments_backup").glob("*")}
    ok("the released report's attachment joins the others", bad_none[0] in att)
    ok("…the released link-only report's link is fetched", "https://dl.shadowserver.org/test6" in fetched_links, str(fetched_links))
    ok("…the others stay held", {m["key"] for _, m in mail_auth.held(base)} == {"k3", "k4"})
    ok("…the folder is kept under released/ as the record", (mail_auth.quarantine_root(base) / "released" / held["k2"][0].name / "meta.json").exists())
    rec = records(base)
    ok("…and the record says released", rec["k2"][1] == "released" and rec["k6"][1] == "released", str(rec))

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
