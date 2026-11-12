#!/usr/bin/env python3
"""The sender check (mail_auth.py), with keys made here and DNS answered here (nothing leaves the computer):
a correctly signed report passes; a changed body, a changed subject, a forged sender address, a signature by another
domain, no signature, a missing key, DNS that does not answer and plain garbage are each recorded for what they are;
nothing ever raises. (On real mail it was tried on the 80 newest Shadowserver e-mails, 2026-11-12: all passed.)
Run: .venv/bin/python tests/test_mail_auth.py"""
import base64, hashlib, os, re, sys, tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa  # noqa: E402
import mail_auth  # noqa: E402

fails, checks = [], 0


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info else ""), flush=True)


RSA = rsa.generate_private_key(public_exponent=65537, key_size=2048)
ED = ed25519.Ed25519PrivateKey.generate()
DNS = {
    "mail._domainkey.shadowserver.org": "v=DKIM1; k=rsa; p=" + base64.b64encode(RSA.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).decode(),
    "ed._domainkey.shadowserver.org": "v=DKIM1; k=ed25519; p=" + base64.b64encode(ED.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode(),
    "mail._domainkey.example.net": "v=DKIM1; k=rsa; p=" + base64.b64encode(RSA.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).decode(),
    "old._domainkey.shadowserver.org": "v=DKIM1; k=rsa; p=",
}


class NXDOMAIN(Exception):
    pass


class LifetimeTimeout(Exception):
    pass


def resolver(name):
    if name.startswith("slow."):
        raise LifetimeTimeout()
    if name not in DNS:
        raise NXDOMAIN()
    return DNS[name].encode()


BODY = (b"Hello,\r\n\r\nAttached is the Shadowserver report for your network.   \r\n\r\n"
        b"Shadowserver Foundation\r\n\r\n\r\n")
HEAD = [b"From: Shadowserver <autoreports@shadowserver.org>", b"To: csirt@example.org",
        b"Subject: [Example] Shadowserver Example Report: 2026-11-12", b"Date: Thu, 12 Nov 2026 08:34:14 +0000",
        b"Message-ID: <test-1@shadowserver.org>"]


def sign(head, body, d="shadowserver.org", s="mail", c="relaxed/simple", alg="rsa",
         hs=(b"From", b"To", b"Subject", b"Date", b"Message-ID")):
    """A DKIM-Signature made here, the way a sender makes one (RFC 6376 5)."""
    hc, bc = c.split("/")
    bh = base64.b64encode(hashlib.sha256(mail_auth._canon_body(body, bc)).digest()).decode()
    a = "ed25519-sha256" if alg == "ed" else "rsa-sha256"
    sig = f"DKIM-Signature: v=1; a={a}; c={c}; d={d}; s={s}; h={b':'.join(hs).decode()}; bh={bh}; b="
    data = b"".join(mail_auth._canon_header(f, hc) + b"\r\n"
                    for f in [next(x for x in head if x.lower().startswith(n.lower() + b":")) for n in hs])
    data += mail_auth._canon_header(sig.encode(), hc)
    b = ED.sign(hashlib.sha256(data).digest()) if alg == "ed" else RSA.sign(data, padding.PKCS1v15(), hashes.SHA256())
    return (sig + base64.b64encode(b).decode()).encode()


def message(head=HEAD, body=BODY, sig=None, **kw):
    sig = sig if sig is not None else sign(head, body, **kw)
    return b"\r\n".join(([sig] if sig else []) + list(head)) + b"\r\n\r\n" + body


C = mail_auth.Checker(resolver=resolver)
print("Genuine reports")
r = C.check(message())
ok("a report signed by shadowserver.org passes", r["result"] == "pass" and r["signer"] == "shadowserver.org", str(r))
r = C.check(message(c="simple/simple"))
ok("…in simple/simple canonicalisation too", r["result"] == "pass", r["reason"])
r = C.check(message(c="relaxed/relaxed"))
ok("…and relaxed/relaxed", r["result"] == "pass", r["reason"])
r = C.check(message(alg="ed", s="ed"))
ok("…and with an ed25519 key", r["result"] == "pass", r["reason"])
folded = message().replace(b"; bh=", b";\r\n\tbh=", 1)
r = C.check(folded.replace(b"\r\n", b"\n"))
ok("a folded signature and bare line ends (as some mailboxes store mail) still pass", r["result"] == "pass", r["reason"])
r = C.check(message(sig=sign(HEAD, BODY)).replace(b"Subject: [Example]", b"subject:   [Example]", 1)
            .replace(b"subject:   [Example]", b"Subject:  [Example]", 1))
ok("extra spaces a relay adds in a header still pass (relaxed headers)", r["result"] == "pass", r["reason"])

print("Changed or forged")
m = message()
r = C.check(m.replace(b"report for your network", b"report for YOUR network"))
ok("a body changed after signing fails (body hash)", r["result"] == "fail" and "body" in r["reason"], r["reason"])
r = C.check(m.replace(b"Example Report: 2026-11-12", b"Example Report: 2026-11-13"))
ok("a subject changed after signing fails (signature)", r["result"] == "fail" and "signature" in r["reason"], r["reason"])
r = C.check(m + b"Extra line added by a relay footer\r\n")
ok("a footer added on the way fails, so log-only comes first", r["result"] == "fail", r["reason"])
forged = [h.replace(b"autoreports@shadowserver.org", b"reports@attacker.example") if h.startswith(b"From") else h for h in HEAD]
r = C.check(message(head=forged, sig=b""))
ok("a forged sender without a signature is 'none'", r["result"] == "none" and r["from_domain"] == "attacker.example", str(r))
r = C.check(message(d="example.net"))
ok("a valid signature by another domain is 'other', not pass", r["result"] == "other" and r["signer"] == "example.net", r["reason"])
other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
real, RSA = RSA, other_key
fake = message()
RSA = real
r = C.check(fake)
ok("a signature made with someone else's key fails", r["result"] == "fail", r["reason"])

def sign_l(head, body, cut):
    """A signature with an l= tag covering only the first `cut` bytes of the canonical body."""
    cb = mail_auth._canon_body(body, "simple")[:cut]
    bh = base64.b64encode(hashlib.sha256(cb).digest()).decode()
    sig = f"DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/simple; d=shadowserver.org; s=mail; l={cut}; h=From:To:Subject:Date:Message-ID; bh={bh}; b="
    data = b"".join(mail_auth._canon_header(next(x for x in head if x.lower().startswith(n.lower() + b":")), "relaxed") + b"\r\n"
                    for n in (b"From", b"To", b"Subject", b"Date", b"Message-ID")) + mail_auth._canon_header(sig.encode(), "relaxed")
    return (sig + base64.b64encode(RSA.sign(data, padding.PKCS1v15(), hashes.SHA256())).decode()).encode()


full = len(mail_auth._canon_body(BODY, "simple"))
r = C.check(message(sig=sign_l(HEAD, BODY, full)))
ok("an l= tag covering the whole body still passes", r["result"] == "pass", r["reason"])
r = C.check(message(sig=sign_l(HEAD, BODY, full)) + b"Injected rows appended after signing\r\n")
ok("content appended after the l= length fails (the reviewer's attack)", r["result"] == "fail" and "l= tag" in r["reason"], r["reason"])
r = C.check(message(sig=sign_l(HEAD, BODY, 20)))
ok("a signature covering only part of the body fails", r["result"] == "fail" and "first 20" in r["reason"], r["reason"])

print("One reading of the message: lines added above a signed message's headers (external review, 2026-11-12)")
import email as _email  # noqa: E402
genuine = message()
ZIP = base64.b64encode(b"PK\x05\x06" + b"\x00" * 18)
attack = (b"Content-Type: multipart/mixed; boundary=\"XX\"\r\n"
          b"this line has no colon\r\n"
          b"--XX\r\nContent-Type: application/zip; name=forged.zip\r\n"
          b"Content-Disposition: attachment; filename=forged.zip\r\nContent-Transfer-Encoding: base64\r\n"
          + ZIP + b"\r\n--XX--\r\n" + genuine)
parsed = _email.message_from_bytes(attack)
ok("(the attack is real: Python's parser, as the pipeline uses it, finds forged.zip in it)",
   any(p.get_filename() == "forged.zip" for p in parsed.walk()))
r = C.check(attack)
ok("…and the check no longer passes it: the header block is ambiguous (permerror, held back in Block mode)",
   r["result"] == "permerror" and "ambiguous" in r["reason"] and r["result"] in mail_auth.BLOCK, r["reason"])
r = C.check(b"just a line\r\n" + genuine)
ok("a single line without a colon above the headers: permerror", r["result"] == "permerror", r["reason"])
r = C.check(genuine.replace(b"To: csirt@example.org", b"To: csirt@example.org\rX-Injected: 1", 1))
ok("a lone carriage return inside the headers (the parser splits there, a blank-line split does not): permerror",
   r["result"] == "permerror", r["reason"])
r = C.check(b" folded first line\r\n" + genuine)
ok("a header block that starts with a continuation line: permerror", r["result"] == "permerror", r["reason"])
r = C.check(genuine)
ok("…while the genuine message still passes", r["result"] == "pass", r["reason"])

print("A pass vouches for the sender: From signed, one From, from the signer's domain")
r = C.check(message(hs=(b"To", b"Subject", b"Date", b"Message-ID")))
ok("a valid shadowserver.org signature that does not sign From: not a pass ('other', held back in Block mode)",
   r["result"] == "other" and "not signed" in r["reason"], r["reason"])
other_from = [h.replace(b"autoreports@shadowserver.org", b"reports@attacker.example") if h.startswith(b"From") else h for h in HEAD]
r = C.check(message(head=other_from))
ok("a From of another domain under a shadowserver.org signature: 'other' (From and signer must match)",
   r["result"] == "other" and "does not match" in r["reason"], r["reason"])
two = message()
two = two.replace(b"\r\n\r\n", b"\r\nFrom: Someone <x@attacker.example>\r\n\r\n", 1)
r = C.check(two)
ok("a second From header added: not a pass", r["result"] != "pass", r["reason"])
sub = [h.replace(b"autoreports@shadowserver.org", b"autoreports@mail.shadowserver.org") if h.startswith(b"From") else h for h in HEAD]
r = C.check(message(head=sub))
ok("a From in a subdomain of the signer still passes (aligned)", r["result"] == "pass", r["reason"])

print("Keys and DNS")
r = C.check(message(s="missing"))
ok("no key published for the selector: permerror", r["result"] == "permerror" and "no key" in r["reason"], r["reason"])
r = C.check(message(s="old"))
ok("a revoked key (empty p=): permerror", r["result"] == "permerror" and "revoked" in r["reason"], r["reason"])
r = C.check(message(s="slow"))
ok("DNS that does not answer: temperror (not held against the message)", r["result"] == "temperror", r["reason"])
sig_sha1 = sign(HEAD, BODY).replace(b"a=rsa-sha256", b"a=rsa-sha1")
r = C.check(message(sig=sig_sha1))
ok("an old rsa-sha1 signature: permerror (unsupported)", r["result"] == "permerror" and "unsupported" in r["reason"], r["reason"])
calls = []
C2 = mail_auth.Checker(resolver=lambda n: (calls.append(n), resolver(n))[1])
for _ in range(5):
    C2.check(message())
ok("one DNS look-up per key and run, not per message", len(calls) == 1, str(calls))

print("Never stops the pipeline")
for junk in (b"", b"\x00\xff garbage", b"DKIM-Signature: v=1; d=; b=\r\n\r\n", b"DKIM-Signature: nonsense\r\n\r\nbody"):
    r = C.check(junk)
    ok(f"{junk[:20]!r}: a result, no exception", r["result"] in mail_auth.RESULTS, r["result"])

print("Recorded")
with tempfile.TemporaryDirectory() as d:
    log = mail_auth.Log(Path(d) / "state.sqlite")
    log.add("imap:1", C.check(message()), "Report A", ["a.zip"])
    log.add("imap:2", C.check(message(sig=b"")), "Report B", ["b.zip"])
    log.add("imap:2", C.check(message(sig=b"")), "Report B", ["b.zip"])          # fetched again: one record
    counts, odd = log.summary(7)
    ok("each message once, with its result; the ones that did not pass listed with their files",
       counts == {"pass": 1, "none": 1} and len(odd) == 1 and odd[0][3] == "none" and odd[0][6] == "b.zip", f"{counts} {odd}")
    log.close()
ok("MAIL_AUTH: off switches it off, enforce blocks, anything else (or nothing) only records",
   mail_auth.mode({"MAIL_AUTH": "off"}) == "off" and mail_auth.mode({}) == "log" and mail_auth.mode({"MAIL_AUTH": "enforce"}) == "enforce"
   and mail_auth.mode({"MAIL_AUTH": "typo"}) == "log")

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
