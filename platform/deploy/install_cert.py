#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""A certificate bought for a domain: checked, then installed for Looking Glass (review follow-up item 5, 2026-11-15).

Used by the installer (install.sh, HTTPS "A certificate bought for a domain") and for renewals (manage/install_cert.sh).
Standard library and the openssl command only. Nothing is installed unless every check passes:

  key       the private key matches the certificate; RSA 2048 bits or more, or EC 256 or more; not protected by a
            passphrase (the service starts unattended)
  domain    the certificate names the domain (its subjectAltName; a wildcard covers one label)
  dates     it is valid now; fewer than 30 days left is said (a warning), expired or not yet valid is refused
  chain     it verifies against the trusted roots (the system's, or LG_CA_BUNDLE / --ca-bundle for a private CA), with
            the intermediate certificates from the certificate file itself or the chain file given
  DNS       where the domain points, compared with this computer's own addresses only (no outside service is asked:
            nothing about the installation leaves it). Elsewhere is a warning: a router may forward to here.

Installing writes data/tls/cert.pem (the certificate and its chain, as served) and data/tls/key.pem (owner-only),
keeps the previous pair in data/tls/previous-<time>/, notes the domain, expiry and fingerprint in data/tls/meta.json
(the bell warns 30, 14 and 3 days before it expires: system_alerts.py) and records the installation in the audit log.

    install_cert.py check   --domain D --cert C --key K [--chain I] [--ca-bundle B] [--json]
    install_cert.py install --domain D --cert C --key K [--chain I] [--ca-bundle B] [--by NAME]
    install_cert.py status  [--json]                     the installed certificate: domain, expiry, days left
"""
import argparse
import hashlib
import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
PROJECT = os.path.dirname(HERE)
PEM_RX = re.compile(r"-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\s]+?-----END CERTIFICATE-----")
WARN_DAYS = 30


def _openssl(*args, data=None):
    r = subprocess.run(["openssl", *args], input=data, capture_output=True, timeout=30)
    return r.returncode, r.stdout.decode("utf-8", "replace"), r.stderr.decode("utf-8", "replace")


def _read(path):
    with open(path, encoding="utf-8", errors="replace") as f:
        return f.read()


def _certs(text):
    return [m.group(0).strip() + "\n" for m in PEM_RX.finditer(text)]


def _date(s):
    """openssl's 'Nov 15 08:00:00 2027 GMT' as seconds since 1970 (UTC)."""
    import calendar
    return calendar.timegm(time.strptime(" ".join(s.split()), "%b %d %H:%M:%S %Y %Z"))


def _cert_facts(pem):
    rc, out, err = _openssl("x509", "-noout", "-subject", "-issuer", "-startdate", "-enddate", "-ext", "subjectAltName", data=pem.encode())
    if rc:
        return None
    facts = {"subject": "", "issuer": "", "sans": []}
    for line in out.splitlines():
        s = line.strip()
        if s.startswith("subject="):
            facts["subject"] = s[8:].strip()
        elif s.startswith("issuer="):
            facts["issuer"] = s[7:].strip()
        elif s.startswith("notBefore="):
            facts["not_before"] = _date(s[10:])
        elif s.startswith("notAfter="):
            facts["not_after"] = _date(s[9:])
        elif "DNS:" in s or "IP Address:" in s:
            facts["sans"] += [x.strip()[4:].lower() for x in s.split(",") if x.strip().startswith("DNS:")]
    der = subprocess.run(["openssl", "x509", "-outform", "DER"], input=pem.encode(), capture_output=True, timeout=30).stdout
    facts["fingerprint"] = "SHA256:" + hashlib.sha256(der).hexdigest().upper()
    return facts


def _covers(sans, domain):
    d = domain.lower().rstrip(".")
    for n in sans:
        n = n.rstrip(".")
        if n == d:
            return True
        if n.startswith("*.") and d.count(".") >= 2 and d.split(".", 1)[1] == n[2:] and d.split(".", 1)[0]:
            return True
    return False


def _local_addresses():
    out = set()
    try:
        r = subprocess.run(["hostname", "-I"], capture_output=True, text=True, timeout=10)
        out |= set(r.stdout.split())
    except (OSError, subprocess.SubprocessError):
        pass
    try:
        for fam, *_rest, sa in socket.getaddrinfo(socket.gethostname(), None):
            out.add(sa[0])
    except OSError:
        pass
    return out


def dns_note(domain):
    """Where the domain points, against this computer's addresses (no outside service asked). (ok, text)."""
    try:
        addrs = sorted({sa[0] for *_x, sa in socket.getaddrinfo(domain, 443, proto=socket.IPPROTO_TCP)})
    except OSError:
        return False, f"{domain} does not resolve (yet): set its DNS record to this server's public address"
    mine = _local_addresses()
    here = [a for a in addrs if a in mine]
    if here:
        return True, f"{domain} points to this computer ({', '.join(here)})"
    pub = [a for a in addrs if ipaddress.ip_address(a).is_global]
    return False, (f"{domain} points to {', '.join(addrs)}, not to an address of this computer: fine if a router or "
                   "firewall forwards that address to here" + ("" if pub else "; it is not a public address either"))


def check(domain, cert_path, key_path, chain_path=None, ca_bundle=None):
    """Every check; nothing is changed. {ok, problems, warnings, info, fullchain}."""
    problems, warnings, info = [], [], {"domain": domain}
    domain = (domain or "").strip().lower().rstrip(".")
    if not re.fullmatch(r"(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", domain):
        return {"ok": False, "problems": [f"'{domain}' is not a domain name (for example lookingglass.example.org)"],
                "warnings": [], "info": info, "fullchain": ""}
    for label, p in (("certificate", cert_path), ("key", key_path)) + ((("chain", chain_path),) if chain_path else ()):
        if not p or not os.path.isfile(p):
            problems.append(f"the {label} file {p or '(none given)'} does not exist")
    if problems:
        return {"ok": False, "problems": problems, "warnings": [], "info": info, "fullchain": ""}
    certs = _certs(_read(cert_path))
    chain = _certs(_read(chain_path)) if chain_path else []
    if not certs:
        return {"ok": False, "problems": ["the certificate file holds no PEM certificate (BEGIN CERTIFICATE)"], "warnings": [],
                "info": info, "fullchain": ""}
    leaf, inter = certs[0], []
    for c in certs[1:] + chain:                       # the intermediates, each once, in the order given
        if c not in inter and c != leaf:
            inter.append(c)
    facts = _cert_facts(leaf)
    if not facts:
        return {"ok": False, "problems": ["the certificate cannot be read"], "warnings": [], "info": info, "fullchain": ""}
    info.update({k: facts[k] for k in ("subject", "issuer", "sans", "fingerprint", "not_after")})
    # the key: readable without a passphrase, strong enough, and the certificate's own
    key_text = _read(key_path)
    if "ENCRYPTED" in key_text:
        problems.append("the key is protected by a passphrase: the service starts unattended, so it needs the key without one")
    else:
        rc, kt, _ = _openssl("pkey", "-in", key_path, "-noout", "-text")
        m = re.search(r"\((\d+) bit", kt or "")
        bits = int(m.group(1)) if m else 0
        is_ec = "ASN1 OID" in kt or "NIST CURVE" in kt.upper()
        info["key"] = f"{'EC' if is_ec else 'RSA'} {bits} bits" if bits else "unknown"
        if rc:
            problems.append("the key file cannot be read as a private key")
        elif (is_ec and bits < 256) or (not is_ec and bits < 2048):
            problems.append(f"the key is too weak ({info['key']}): RSA 2048 bits or more, or EC 256 bits or more")
        rc1, kp, _ = _openssl("pkey", "-in", key_path, "-pubout")
        rc2, cp, _ = _openssl("x509", "-noout", "-pubkey", data=leaf.encode())
        if rc1 == 0 and rc2 == 0 and kp.strip() != cp.strip():
            problems.append("the key does not belong to this certificate")
    # the domain
    if not _covers(facts["sans"], domain):
        problems.append(f"the certificate does not name {domain} (it names {', '.join(facts['sans']) or 'no DNS names'})")
    # the dates
    now = time.time()
    days = int((facts.get("not_after", 0) - now) // 86400)
    info["days_left"] = days
    if facts.get("not_before", 0) > now + 300:
        problems.append("the certificate is not valid yet")
    if facts.get("not_after", 0) <= now:
        problems.append("the certificate has expired")
    elif days < WARN_DAYS:
        warnings.append(f"the certificate expires in {days} day(s): renew it soon (manage/install_cert.sh)")
    # the chain, against the trusted roots
    ca = ca_bundle or os.environ.get("LG_CA_BUNDLE") or None
    with tempfile.TemporaryDirectory() as tmp:
        lf, uf = os.path.join(tmp, "leaf.pem"), os.path.join(tmp, "inter.pem")
        open(lf, "w").write(leaf)
        args = ["verify", "-purpose", "sslserver"]
        if ca:
            args += ["-CAfile", ca]
        if inter:
            open(uf, "w").write("".join(inter)); args += ["-untrusted", uf]
        rc, out, err = _openssl(*args, lf)
        if rc:
            why = (err or out).strip().splitlines()
            why = next((w for w in why if "error" in w.lower()), why[-1] if why else "it does not verify")
            problems.append("the chain does not verify against the trusted roots: " + why.split(":", 3)[-1].strip()
                            + ("" if inter else " (no intermediate certificate given: add the chain file your provider sent)"))
    ok_dns, note = dns_note(domain)
    info["dns"] = note
    if not ok_dns:
        warnings.append(note)
    return {"ok": not problems, "problems": problems, "warnings": warnings, "info": info, "fullchain": leaf + "".join(inter)}


def install(project, result, key_path, by="installer"):
    """Write data/tls (cert.pem with its chain, key.pem owner-only), keep the previous pair, note meta.json and audit it."""
    tls = os.path.join(project, "data", "tls")
    os.makedirs(tls, mode=0o700, exist_ok=True)
    os.chmod(tls, 0o700)
    kept = ""
    if os.path.exists(os.path.join(tls, "cert.pem")):
        stamp = os.path.join(tls, f"previous-{time.strftime('%Y%m%d-%H%M%S', time.gmtime())}")
        kept, n = stamp, 1
        while True:                    # two installs in the same second: the second keeps its own folder (-2, -3, ...)
            try:
                os.makedirs(kept, mode=0o700)
                break
            except FileExistsError:
                n += 1
                kept = f"{stamp}-{n}"
        for n in ("cert.pem", "key.pem", "meta.json"):
            if os.path.exists(os.path.join(tls, n)):
                shutil.move(os.path.join(tls, n), os.path.join(kept, n))
    old = os.umask(0o077)
    try:
        with open(os.path.join(tls, "key.pem.tmp"), "w") as f:
            f.write(_read(key_path))
        os.replace(os.path.join(tls, "key.pem.tmp"), os.path.join(tls, "key.pem"))
        os.chmod(os.path.join(tls, "key.pem"), 0o600)
        with open(os.path.join(tls, "cert.pem.tmp"), "w") as f:
            f.write(result["fullchain"])
        os.replace(os.path.join(tls, "cert.pem.tmp"), os.path.join(tls, "cert.pem"))
        os.chmod(os.path.join(tls, "cert.pem"), 0o644)
        i = result["info"]
        meta = {"domain": i["domain"], "not_after": i["not_after"], "fingerprint": i["fingerprint"], "issuer": i["issuer"],
                "installed_at": round(time.time()), "by": by, "kind": "bought"}
        with open(os.path.join(tls, "meta.json"), "w") as f:
            json.dump(meta, f)
    finally:
        os.umask(old)
    _audit(project, by, result["info"])
    return kept


def _audit(project, by, info):
    """The installation in the audit log, the same chain the service writes (audit_chain.py)."""
    try:
        sys.path.insert(0, project)
        import audit_chain
        chain = audit_chain.Chain(os.path.join(project, "data", "audit.log"))
        chain.append({"t": round(time.time(), 3), "event": "tls_certificate_installed", "user": by, "target": info["domain"],
                      "detail": f"certificate for {info['domain']} installed · expires "
                                f"{time.strftime('%Y-%m-%d', time.gmtime(info['not_after']))} · {info['fingerprint'][:23]}…"
                                f" · issuer {info['issuer'][:80]}", "ip": "", "location": "", "ua": ""})
    except Exception as e:  # noqa: BLE001  the certificate is installed either way; say so
        print(f"note: the audit log could not record it ({type(e).__name__})", file=sys.stderr)


def status(project):
    """The installed certificate: {domain, not_after, days_left, kind} from meta.json, else from cert.pem itself."""
    tls = os.path.join(project, "data", "tls")
    try:
        meta = json.load(open(os.path.join(tls, "meta.json")))
    except (OSError, ValueError):
        meta = {}
    try:
        certs = _certs(_read(os.path.join(tls, "cert.pem")))
    except OSError:
        return None
    facts = _cert_facts(certs[0]) if certs else None
    if not facts:
        return None
    na = facts.get("not_after", meta.get("not_after", 0))
    return {"domain": meta.get("domain") or (facts["sans"][0] if facts["sans"] else ""), "not_after": na,
            "days_left": int((na - time.time()) // 86400), "kind": meta.get("kind") or "self-made or other",
            "fingerprint": facts["fingerprint"]}


def _say(r):
    i = r["info"]
    if i.get("subject"):
        print(f"certificate:  {i.get('subject')}\n  issued by   {i.get('issuer')}\n  names       {', '.join(i.get('sans') or [])}")
        if i.get("not_after"):
            print(f"  expires     {time.strftime('%Y-%m-%d', time.gmtime(i['not_after']))} ({i.get('days_left')} days left)")
        print(f"  key         {i.get('key', '?')}\n  fingerprint {i.get('fingerprint')}")
    if i.get("dns"):
        print(f"DNS:          {i['dns']}")
    for p in r["problems"]:
        print(f"REFUSED:      {p}")
    for w in r["warnings"]:
        print(f"note:         {w}")
    print("RESULT: " + ("the certificate can be installed" if r["ok"] else "NOT installed"))


def main(argv):
    ap = argparse.ArgumentParser(description="Check and install a bought certificate for Looking Glass.")
    ap.add_argument("cmd", choices=("check", "install", "status"))
    ap.add_argument("--domain"); ap.add_argument("--cert"); ap.add_argument("--key"); ap.add_argument("--chain")
    ap.add_argument("--ca-bundle"); ap.add_argument("--by", default=os.environ.get("USER") or "installer")
    ap.add_argument("--project", default=PROJECT); ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    if a.cmd == "status":
        s = status(a.project)
        print(json.dumps(s) if a.json else (f"{s['domain']}: expires {time.strftime('%Y-%m-%d', time.gmtime(s['not_after']))} "
                                            f"({s['days_left']} days left), {s['kind']}" if s else "no certificate installed"))
        return 0 if s else 1
    if not (a.domain and a.cert and a.key):
        ap.error("--domain, --cert and --key are needed")
    r = check(a.domain, a.cert, a.key, a.chain, a.ca_bundle)
    if a.json:
        print(json.dumps({k: v for k, v in r.items() if k != "fullchain"}))
    else:
        _say(r)
    if not r["ok"]:
        return 1
    if a.cmd == "install":
        kept = install(a.project, r, a.key, a.by)
        print("installed in data/tls/" + (f" (the previous certificate kept in {os.path.relpath(kept, a.project)})" if kept else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
