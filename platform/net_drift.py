# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""When this computer's address changes (the user, 2026-11-19): what stops matching, and how to fix it.

Looking Glass itself follows its own addresses (security.py reads them again every minute). Two settings do not:
* the self-signed HTTPS certificate (deploy/make_tls_cert.sh) lists the computer's addresses as they were when it was
  made: other computers opening the new address get a name-mismatch warning on top of the self-signed one;
* MongoDB told to listen on a network address (MONGO_BIND in the pipeline's .env, a split installation: the pipeline on
  this computer, the platform on another): when that address is gone, MongoDB cannot start ("cannot assign requested
  address") and the platform cannot reach it.
drift(base_dir) -> [{"key", "title", "text"}], one per mismatch; [] when everything matches, or when it cannot be told
(a certificate from a CA, a name instead of addresses, this computer only). Read only; nothing is changed.
Used by system_alerts.py (the bell, administrators) and tests/check_addresses.py (the installation check).
"""
import ipaddress
import os
import socket
import subprocess


def own_addresses():
    """This computer's network addresses now (loopback left out)."""
    found = set()
    try:
        out = subprocess.run(["hostname", "-I"], capture_output=True, text=True, timeout=3).stdout
        found |= {a.strip() for a in out.split() if a.strip()}
    except (OSError, subprocess.SubprocessError):
        pass
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None):
            found.add(info[4][0])
    except OSError:
        pass
    keep = set()
    for a in found:
        try:
            ip = ipaddress.ip_address(a.split("%")[0])
        except ValueError:
            continue
        if not ip.is_loopback and not ip.is_link_local:
            keep.add(str(ip))
    return keep


def cert_addresses(path):
    """(self_signed, {IP addresses in the certificate}) or (None, set()) when it cannot be read. Read with the openssl
    command (deploy/make_tls_cert.sh makes the certificate with it; the platform's Python has no X.509 library)."""
    if not os.path.exists(path):
        return None, set()
    try:
        r = subprocess.run(["openssl", "x509", "-in", path, "-noout", "-subject", "-issuer", "-ext", "subjectAltName",
                            "-nameopt", "RFC2253"], capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.SubprocessError):
        return None, set()
    if r.returncode != 0:
        return None, set()
    subj = iss = ""
    ips = set()
    for ln in r.stdout.splitlines():
        ln = ln.strip()
        if ln.startswith("subject="):
            subj = ln[8:].strip()
        elif ln.startswith("issuer="):
            iss = ln[7:].strip()
        else:
            for part in ln.split(","):
                part = part.strip()
                if part.startswith("IP Address:"):
                    ips.add(part[len("IP Address:"):].strip())
    return bool(subj) and subj == iss, ips


def _pipeline_env(base_dir):
    try:
        import pipeline_link
        d = pipeline_link.find_dir(base_dir)
        return pipeline_link.read_env(os.path.join(d, ".env")) if d else {}
    except Exception:                                    # noqa: BLE001
        return {}


def drift(base_dir, mine=None, env=os.environ):
    mine = own_addresses() if mine is None else set(mine)
    out = []
    if not mine:
        return out
    # 1. the self-signed certificate, when other computers use it (not "this computer only")
    mode = (env.get("ACCESS_MODE") or "").strip().lower()
    cert = os.path.join(base_dir, "data", "tls", "cert.pem")
    self_signed, ips = cert_addresses(cert)
    ips = {i for i in ips if not ipaddress.ip_address(i).is_loopback}
    if self_signed and ips and mode != "local" and not (ips & mine):
        out.append({"key": "cert:" + ",".join(sorted(mine)),
                    "title": "The HTTPS certificate no longer matches this computer's address",
                    "text": (f"this computer's address is now {', '.join(sorted(mine))}; the self-signed certificate names "
                             f"{', '.join(sorted(ips))}. Other computers get a name warning. Make it again: "
                             "deploy/make_tls_cert.sh (each screen then trusts it once more), and give the server a fixed address "
                             "(a DHCP reservation) so it does not happen again.")})
    # 2. MongoDB listening on a network address that is gone (a split installation)
    penv = _pipeline_env(base_dir)
    bind = [b.strip() for b in str(penv.get("MONGO_BIND") or "").split(",") if b.strip()]
    gone = []
    for b in bind:
        try:
            ip = ipaddress.ip_address(b)
        except ValueError:
            continue
        if not ip.is_loopback and not ip.is_unspecified and str(ip) not in mine:
            gone.append(str(ip))
    if gone:
        out.append({"key": "mongo-bind:" + ",".join(gone) + ":" + ",".join(sorted(mine)),
                    "title": "MongoDB is set to listen on an address this computer no longer has",
                    "text": (f"MONGO_BIND in the pipeline's .env names {', '.join(gone)}; this computer's address is now "
                             f"{', '.join(sorted(mine))}. MongoDB cannot start on a missing address, and the platform on the "
                             "other computer cannot reach it. Give the server back its address (best: a DHCP reservation), or set "
                             "MONGO_BIND to the new one, run database/deploy.sh, and change MONGO_HOST in the platform's .env.")})
    return out
