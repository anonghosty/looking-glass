"""Who really sent a report e-mail: its DKIM signature, checked here, recorded, never blocking (log only).

Reports reach the pipeline by e-mail, and anyone who knows the mailbox address can send one (external review,
2026-11-12). Shadowserver signs its report e-mails with DKIM (checked 2026-11-12: d=shadowserver.org, rsa-sha256), so
the signature tells a genuine report from a forged one. This module checks it on the message exactly as the pipeline
downloaded it, with the sender's public key from DNS (RFC 6376; rsa-sha256 and ed25519-sha256, relaxed and simple
canonicalisation). The pipeline's own mail server is not needed for this, and does not have to support DKIM.

For now it only records (MAIL_AUTH=log, the default): every message gets a result in .mail_state.sqlite (table
mail_auth) and a line in the run log; anything other than a valid signature by the expected domain is a WARNING. No
report is held back. Running it this way first shows whether every genuine report passes before anything is ever
blocked: a footer or a forwarding rule added on the way breaks a valid signature (Shadowserver signs the body in
"simple" mode). MAIL_AUTH=off switches it off. MAIL_AUTH_DOMAIN (default shadowserver.org) is the signer expected.

Results: pass (a valid signature by the expected domain that signs the one From header, and From is that domain or a
subdomain of it), other (valid, but signed by another domain only, or From unsigned, doubled or of another domain),
fail (a signature that does not verify: changed on the way, or forged), none (no signature at all), temperror (DNS did
not answer: not held against the message), permerror (a signature that cannot be checked: no key, unsupported
algorithm; or a header block that Python's email parser, which the pipeline uses, would read differently from this
check, such as a line without a colon or a lone carriage return: then nothing is vouched for).

Report: python3 mail_auth.py [days]   (counts per result, and the messages that did not pass)
"""
import base64
import datetime as dt
import email
import email.utils
import hashlib
import os
import re
import sqlite3
import sys
from pathlib import Path

RESULTS = ("pass", "other", "fail", "none", "temperror", "permerror")
# headers that decide who sent a report and how its parts are read: never more copies than the signature covers
GUARDED = ("from", "content-type", "content-transfer-encoding", "mime-version")


def _fields(head: bytes):
    """The header fields as they are (folded lines kept), in order."""
    out = []
    for line in head.split(b"\r\n"):
        if line[:1] in (b" ", b"\t") and out:
            out[-1] += b"\r\n" + line
        elif line:
            out.append(line)
    return out


_FIELD_NAME = re.compile(rb"^[\x21-\x39\x3b-\x7e]+:")    # RFC 5322 2.2: printable US-ASCII except ":", then ":"


def _head_problem(head: bytes):
    """Why this header block is not plainly a list of header fields (None: it is). The check and the pipeline's
    parser must see the same headers (external review, 2026-11-12: a line without a colon ends the headers for
    Python's email parser but not for a split at the first blank line, so a signed message with lines added above
    its headers passed the check while the pipeline read the added lines as the message)."""
    if re.search(rb"\r(?!\n)", head):
        return "a carriage return inside a header line"
    for i, line in enumerate(head.split(b"\r\n")):
        if line[:1] in (b" ", b"\t"):
            if i == 0:
                return "the first header line is a continuation"
            continue
        if not _FIELD_NAME.match(line):
            return f"header line {i + 1} is not a header field"
    return None


def _from_aligned(from_domain: str, signer: str) -> bool:
    """The From domain and the signing domain belong together (one is the other, or a subdomain of it)."""
    return bool(from_domain) and (from_domain == signer or from_domain.endswith("." + signer) or signer.endswith("." + from_domain))


def _tags(value: str) -> dict:
    out = {}
    for part in value.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            out[k.strip()] = re.sub(r"\s+", "", v)
    return out


def _canon_body(body: bytes, mode: str) -> bytes:
    if mode == "relaxed":
        body = b"\r\n".join(re.sub(rb"[ \t]+", b" ", ln).rstrip(b" \t") for ln in body.split(b"\r\n"))
    body = re.sub(rb"(\r\n)+$", b"", body)
    if mode == "relaxed" and not body:
        return b""
    return body + b"\r\n"


def _canon_header(field: bytes, mode: str) -> bytes:
    if mode == "simple":
        return field
    name, _, value = field.partition(b":")
    value = re.sub(rb"[ \t]+", b" ", value.replace(b"\r\n", b"")).strip(b" \t")
    return name.strip().lower() + b":" + value


def _without_b(field: bytes, mode: str) -> bytes:
    """The DKIM-Signature field itself, canonicalised, with the value of its b= tag left out (RFC 6376 3.7)."""
    return re.sub(rb"(?<=[;:])(\s*b\s*=)[^;]*", rb"\1", _canon_header(field, mode))


class Checker:
    def __init__(self, expect_domain: str = "shadowserver.org", resolver=None, timeout: float = 5.0):
        self.expect = expect_domain.strip().lower()
        self.keys = {}                                    # one DNS look-up per signing key and run
        self.timeout = timeout
        self._resolver = resolver

    def _key(self, selector: str, domain: str):
        """(public key or None, error result or None)."""
        name = f"{selector}._domainkey.{domain}"
        if name in self.keys:
            return self.keys[name]
        try:
            if self._resolver is not None:
                txt = self._resolver(name)
            else:
                import dns.resolver
                r = dns.resolver.Resolver()
                r.lifetime = self.timeout
                txt = b"".join(b"".join(x.strings) for x in r.resolve(name, "TXT"))
        except Exception as exc:                            # noqa: BLE001
            kind = type(exc).__name__
            out = (None, ("permerror", f"no key published at {name}") if kind in ("NXDOMAIN", "NoAnswer", "LookupError")
                   else ("temperror", f"DNS did not answer for {name} ({kind})"))
            self.keys[name] = out
            return out
        tags = _tags(txt.decode("ascii", "replace") if isinstance(txt, bytes) else txt)
        p = tags.get("p", "")
        if not p:
            out = (None, ("permerror", f"the key at {name} was revoked (empty p=)"))
        else:
            try:
                from cryptography.hazmat.primitives import serialization
                from cryptography.hazmat.primitives.asymmetric import ed25519
                raw = base64.b64decode(p)
                key = ed25519.Ed25519PublicKey.from_public_bytes(raw) if tags.get("k") == "ed25519" \
                    else serialization.load_der_public_key(raw)
                out = (key, None)
            except Exception as exc:                        # noqa: BLE001
                out = (None, ("permerror", f"the key at {name} cannot be read ({type(exc).__name__})"))
        self.keys[name] = out
        return out

    def _verify_one(self, field: bytes, fields, body: bytes):
        """(result, signing domain, selector, reason) for one DKIM-Signature field."""
        t = _tags(field.split(b":", 1)[1].decode("ascii", "replace"))
        d, s, a = t.get("d", "").lower(), t.get("s", ""), t.get("a", "").lower()
        if not (d and s and t.get("b") and t.get("bh") and t.get("h")):
            return "permerror", d, s, "the signature lacks a required tag"
        if a not in ("rsa-sha256", "ed25519-sha256"):
            return "permerror", d, s, f"unsupported algorithm {a or '(none)'}"
        hc, _, bc = (t.get("c") or "simple/simple").lower().partition("/")
        bc = bc or "simple"
        cb = _canon_body(body, bc)
        if "l" in t:
            # l= signs only the first l bytes of the body: anything appended after them would still pass. Such a
            # signature does not vouch for the whole report, so it counts as a fail (external review, 2026-11-12;
            # RFC 6376 8.2 warns about it). Shadowserver does not use l=.
            try:
                n = int(t["l"])
            except ValueError:
                return "permerror", d, s, "unreadable l= tag"
            if n < len(cb):
                return "fail", d, s, f"the signature covers only the first {n} of {len(cb)} body bytes (l= tag)"
            cb = cb[:n]
        if base64.b64encode(hashlib.sha256(cb).digest()).decode() != t["bh"]:
            return "fail", d, s, "the body was changed after it was signed (body hash differs)"
        data, used = b"", {}
        for h in t["h"].split(":"):
            h = h.strip().lower()
            if not h:
                continue
            cands = [f for f in fields if f.split(b":", 1)[0].strip().lower() == h.encode()]
            n = used.get(h, 0)
            if n < len(cands):
                data += _canon_header(cands[len(cands) - 1 - n], hc) + b"\r\n"      # bottom-up for repeated fields
            used[h] = n + 1
        data += _without_b(field, hc)
        key, err = self._key(s, d)
        if err:
            return err[0], d, s, err[1]
        try:
            sig = base64.b64decode(t["b"])
            if a == "ed25519-sha256":
                key.verify(sig, hashlib.sha256(data).digest())
            else:
                from cryptography.hazmat.primitives import hashes
                from cryptography.hazmat.primitives.asymmetric import padding
                key.verify(sig, data, padding.PKCS1v15(), hashes.SHA256())
        except Exception:                                   # noqa: BLE001
            return "fail", d, s, "the signature does not match the signed headers"
        self.last_key = (a, getattr(key, "key_size", 256 if a == "ed25519-sha256" else 0))
        return "ok", d, s, ""

    def check(self, raw: bytes) -> dict:
        """{result, signer, selector, from_domain, reason, alg, bits}. Never raises."""
        out = {"result": "permerror", "signer": "", "selector": "", "from_domain": "", "reason": "", "alg": "", "bits": 0}
        self.last_key = ("", 0)
        try:
            raw = raw.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")
            head, sep, body = raw.partition(b"\r\n\r\n")
            fields = _fields(head)
            msg = email.message_from_bytes(raw)
            out["from_domain"] = (email.utils.parseaddr(msg.get("From") or "")[1].rpartition("@")[2]).lower()
            # one reading of the message: the fields checked here must be exactly the headers the pipeline's parser
            # sees (same names, same order, nothing it read as a broken header), or nothing is vouched for
            problem = _head_problem(head) if sep else "no blank line between the headers and the body"
            if not problem and [k.lower() for k in msg.keys()] != \
                    [f.split(b":", 1)[0].strip().lower().decode("latin-1") for f in fields]:
                problem = "the headers read differently by the parser"
            if not problem and any(type(d).__name__ in ("MissingHeaderBodySeparatorDefect", "FirstHeaderLineIsContinuationDefect",
                                                        "MisplacedEnvelopeHeaderDefect", "InvalidHeaderDefect")
                                   for d in msg.defects):
                problem = "the parser found a broken header"
            if problem:
                out.update(result="permerror", reason=f"the message's header block is ambiguous ({problem}): not checked")
                return out
            sigs = [f for f in fields if f.split(b":", 1)[0].strip().lower() == b"dkim-signature"]
            if not sigs:
                out.update(result="none", reason="no DKIM signature")
                return out
            results = []                     # (result, domain, selector, reason, (alg, bits), From signed, extra copies)
            names = [f.split(b":", 1)[0].strip().lower().decode("latin-1") for f in fields]
            for f in sigs:
                r = self._verify_one(f, fields, body)
                h = [x.strip().lower() for x in _tags(f.split(b":", 1)[1].decode("ascii", "replace")).get("h", "").split(":")]
                # a header the parser reads first must be the signed one: a copy added above a signed header (an unsigned
                # Content-Type over the signed one, review 2026-11-13) passed while the parser read the attacker's. More
                # copies than the signature covers are refused; a header it does not cover may appear only once.
                extra = [g for g in GUARDED if names.count(g) > max(h.count(g), 1)]
                results.append(r + ((self.last_key if r[0] == "ok" else ("", 0)), "from" in h, extra))
            good = [r for r in results if r[0] == "ok"]
            mine = [r for r in good if r[1] == self.expect or r[1].endswith("." + self.expect)]
            # a pass vouches for who SENT it: exactly one From header, signed (in h=), from the signer's domain
            # (external review, 2026-11-12; RFC 6376 5.4 requires From to be signed; DMARC-style alignment)
            froms = msg.get_all("From") or []
            why_not = None
            if mine:
                ok_from = [r for r in mine if r[5] and len(froms) == 1 and _from_aligned(out["from_domain"], r[1])]
                if not ok_from:
                    why_not = ("the message has %d From headers" % len(froms) if len(froms) != 1 else
                               "the From header is not signed" if not any(r[5] for r in mine) else
                               f"From ({out['from_domain'] or 'none'}) does not match the signer ({mine[0][1]})")
                elif not [r for r in ok_from if not r[6]]:
                    why_not = ("it has more " + ", ".join(ok_from[0][6]) + " headers than the signature covers "
                               "(a header added on the way, which the pipeline would read first)")
                mine = [r for r in ok_from if not r[6]]
            if mine:
                out.update(result="pass", signer=mine[0][1], selector=mine[0][2], alg=mine[0][4][0], bits=mine[0][4][1])
            elif why_not:
                r = next(r for r in good if r[1] == self.expect or r[1].endswith("." + self.expect))
                out.update(result="other", signer=r[1], selector=r[2], alg=r[4][0], bits=r[4][1],
                           reason=f"a valid signature by {r[1]}, but {why_not}")
            elif good:
                out.update(result="other", signer=good[0][1], selector=good[0][2], alg=good[0][4][0], bits=good[0][4][1],
                           reason=f"signed by {good[0][1]}, not {self.expect}")
            else:
                worst = next((r for r in results if r[0] == "fail"), None) or next(
                    (r for r in results if r[0] == "temperror"), None) or results[0]
                out.update(result=worst[0], signer=worst[1], selector=worst[2], reason=worst[3])
        except Exception as exc:                            # noqa: BLE001  (a check never stops the pipeline)
            out.update(result="permerror", reason=f"could not be checked ({type(exc).__name__})")
        return out


class Log:
    """The results, kept with the pipeline's mail state (.mail_state.sqlite, table mail_auth)."""

    COLUMNS = (("key", "TEXT PRIMARY KEY"), ("at", "TEXT"), ("from_domain", "TEXT"), ("signer", "TEXT"), ("result", "TEXT"),
               ("reason", "TEXT"), ("subject", "TEXT"), ("files", "TEXT"), ("action", "TEXT"), ("alg", "TEXT"),
               ("bits", "INTEGER"), ("selector", "TEXT"))

    def __init__(self, path: Path):
        self.db = sqlite3.connect(str(path))
        self.db.execute("CREATE TABLE IF NOT EXISTS mail_auth (key TEXT PRIMARY KEY, at TEXT, from_domain TEXT, "
                        "signer TEXT, result TEXT, reason TEXT, subject TEXT, files TEXT)")
        have = {r[1] for r in self.db.execute("PRAGMA table_info(mail_auth)")}
        for name, kind in self.COLUMNS:                    # columns added after the first version
            if name not in have:
                self.db.execute(f"ALTER TABLE mail_auth ADD COLUMN {name} {kind}")
        self.db.commit()

    def add(self, key: str, res: dict, subject: str, files, action: str = "kept") -> None:
        """action: kept (log only, or passed), quarantined (blocking on), retry (DNS did not answer, blocking on),
        released (an administrator let a quarantined one through)."""
        now = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
        self.db.execute("INSERT OR REPLACE INTO mail_auth (key, at, from_domain, signer, result, reason, subject, files, "
                        "action, alg, bits, selector) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (key, now, res["from_domain"], res["signer"], res["result"], res["reason"],
                         (subject or "")[:200], ", ".join(files)[:2000], action, res.get("alg", ""), res.get("bits", 0),
                         res.get("selector", "")))
        self.db.commit()

    def set_action(self, key: str, action: str) -> None:
        self.db.execute("UPDATE mail_auth SET action = ? WHERE key = ?", (action, key))
        self.db.commit()

    def summary(self, days: int):
        cut = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=days)).isoformat(timespec="seconds")
        counts = dict(self.db.execute("SELECT result, COUNT(*) FROM mail_auth WHERE at >= ? GROUP BY result", (cut,)))
        odd = list(self.db.execute("SELECT at, from_domain, signer, result, reason, subject, files, action FROM mail_auth "
                                   "WHERE at >= ? AND result != 'pass' ORDER BY at DESC LIMIT 50", (cut,)))
        return counts, odd

    def forget_older_than(self, days: int) -> None:
        cut = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=days)).isoformat(timespec="seconds")
        self.db.execute("DELETE FROM mail_auth WHERE at < ?", (cut,))
        self.db.commit()

    def close(self) -> None:
        self.db.close()


def mode(env=None) -> str:
    """log (default: record only), enforce (a report that does not pass is quarantined) or off."""
    v = ((env if env is not None else os.environ).get("MAIL_AUTH") or "log").strip().lower()
    if v in ("off", "0", "false", "no"):
        return "off"
    return "enforce" if v in ("enforce", "block", "on") else "log"


# results that are quarantined when blocking is on; temperror (DNS did not answer) is tried again next run instead
BLOCK = ("fail", "none", "other", "permerror")


def quarantine_root(base: Path) -> Path:
    return Path(base) / "quarantine" / "mail_auth"


def quarantine_dir(base: Path, key: str) -> Path:
    """One folder per held-back message, named by a hash of its key (no address or subject in the name)."""
    return quarantine_root(base) / hashlib.sha256(key.encode()).hexdigest()[:20]


def write_meta(qdir: Path, key: str, res: dict, subject: str, files, links) -> None:
    import json
    qdir.mkdir(parents=True, exist_ok=True)
    meta = {"key": key, "at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"), "subject": (subject or "")[:200],
            "files": list(files), "links": sorted(links), **{k: res.get(k) for k in ("result", "reason", "signer", "selector",
                                                                                       "from_domain", "alg", "bits")}}
    tmp = qdir / "meta.json.tmp"
    tmp.write_text(json.dumps(meta, indent=1), encoding="utf-8")
    os.replace(tmp, qdir / "meta.json")


def held(base: Path):
    """[(folder, meta)] of the messages held back and not released yet."""
    import json
    root = quarantine_root(base)
    out = []
    for d in sorted(root.glob("*")) if root.exists() else []:
        if d.is_dir() and d.name != "released" and (d / "meta.json").exists():
            try:
                out.append((d, json.loads((d / "meta.json").read_text(encoding="utf-8"))))
            except (OSError, ValueError):
                continue
    return out


RELEASE_FILE = "RELEASE"


def request_release(qdir: Path, by: str) -> None:
    """Asked from the platform (an administrator, after their password) or the command line: the next pipeline run
    lets the message through."""
    import json
    (qdir / RELEASE_FILE).write_text(json.dumps({"by": by[:120], "at": dt.datetime.now(dt.timezone.utc)
                                                 .isoformat(timespec="seconds")}), encoding="utf-8")


def take_releases(base: Path, attach_dir: Path):
    """Move the attachments of every released message into attach_dir (never over an existing file). Returns
    [(key, links, files, by)]; the folder goes to quarantine/mail_auth/released/ with its meta, as the record."""
    import json
    import shutil
    out = []
    done = quarantine_root(base) / "released"
    for qdir, meta in held(base):
        rel = qdir / RELEASE_FILE
        if not rel.exists():
            continue
        try:
            who = json.loads(rel.read_text(encoding="utf-8")).get("by", "")
        except (OSError, ValueError):
            who = ""
        moved = []
        for name in meta.get("files") or []:
            src, dst = qdir / name, Path(attach_dir) / name
            if src.exists() and not dst.exists():
                shutil.move(str(src), str(dst))
                moved.append(name)
        done.mkdir(parents=True, exist_ok=True)
        shutil.move(str(qdir), str(done / qdir.name))
        out.append((meta["key"], set(meta.get("links") or []), moved, who))
    return out


def main(argv):
    base = Path(__file__).resolve().parent
    if len(argv) > 1 and argv[1] == "held":
        for qdir, meta in held(base):
            print(f"{qdir.name}  {meta.get('at')}  {meta.get('result'):<9} from {meta.get('from_domain') or '?'}  "
                  f"{meta.get('reason')}  | {(meta.get('subject') or '')[:60]}" + ("  (release asked)" if (qdir / RELEASE_FILE).exists() else ""))
        return 0
    if len(argv) > 2 and argv[1] == "release":
        match = [q for q, _ in held(base) if q.name.startswith(argv[2])]
        if len(match) != 1:
            print("give the start of one held folder's name (python3 mail_auth.py held)")
            return 1
        request_release(match[0], f"command line ({os.environ.get('USER', '?')})")
        print(f"{match[0].name}: released at the next pipeline run")
        return 0
    days = int(argv[1]) if len(argv) > 1 and argv[1].isdigit() else 7
    path = base / ".mail_state.sqlite"
    if not path.exists():
        print("no mail state yet: run the pipeline first")
        return 0
    log = Log(path)
    counts, odd = log.summary(days)
    log.close()
    total = sum(counts.values())
    print(f"Sender check (log only), last {days} day(s): {total} message(s)")
    for r in RESULTS:
        if counts.get(r):
            print(f"  {r:<10} {counts[r]}")
    if odd:
        print("Messages that did not pass (newest first):")
        for at, frm, signer, result, reason, subject, files, action in odd:
            print(f"  {at}  {result:<9} {action or 'kept':<11} from {frm or '?'}  {reason}  | {(subject or '')[:60]}"
                  + (f"  | files: {files[:80]}" if files else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
