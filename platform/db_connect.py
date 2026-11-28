# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""Where the reports database is, and how to reach it safely (2026-11-14).

Looking Glass reads (the platform) and fills (the pipeline) one MongoDB: by default on this same computer, reached on
127.0.0.1, or an existing MongoDB on another server. Settings, from .env:

    MONGO_HOST, MONGO_PORT          where it is (127.0.0.1, 27017)
    MONGO_TLS                       1: the connection is encrypted with TLS. Needed for a MongoDB on another computer.
    MONGO_TLS_CA_FILE               the CA certificate (PEM) that signed the database's certificate; empty: the
                                    system's trusted CAs
    MONGO_TLS_CERT_KEY_FILE         a client certificate and its key in one PEM file, when the database asks for one
    MONGO_ALLOW_PLAINTEXT           1: allow a MongoDB on another computer WITHOUT TLS (only on a link you trust,
                                    for example a private cable between two servers). Off by default.

The database is internal, never on the public internet (user, 2026-11-14): another computer is accepted only when
every address it has is a private one (10/8, 172.16/12, 192.168/16, 100.64/10, fc00::/7, link-local); a public
address is refused, and there is no switch to allow it. A MongoDB reachable from the internet is a target.

A MongoDB on another computer without TLS is refused unless MONGO_ALLOW_PLAINTEXT=1: the account's password and every
report record would cross the network readable by anyone on the way. With TLS the server's certificate and its name
are always checked (there is no switch to turn that off).

The same file is in the platform and in the database pipeline: kwargs(get) gives the MongoClient settings for either.
"""
import ipaddress
import os

LOOPBACK_NAMES = {"localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback"}


class Refused(ValueError):
    """The settings would send the database traffic over the network unencrypted, or point at a missing file."""


def _yes(v):
    return str(v or "").strip().lower() in ("1", "true", "yes", "on")


def is_local(host):
    """True for this computer only (a loopback name or address); a socket path counts as local too."""
    h = str(host or "").strip().strip("[]").lower()
    if not h or h in LOOPBACK_NAMES or h.startswith("/"):
        return True
    try:
        return ipaddress.ip_address(h).is_loopback
    except ValueError:
        return False


PRIVATE_NETS = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10",
                                                   "169.254.0.0/16", "fc00::/7", "fe80::/10")]


def is_internal_address(ip):
    a = ipaddress.ip_address(ip)
    if a.version == 6 and a.ipv4_mapped:
        a = a.ipv4_mapped
    return a.is_loopback or any(a in n for n in PRIVATE_NETS)


def addresses_of(host, port=27017):
    """Every address a name resolves to (an address: itself). [] when it does not resolve."""
    import socket
    h = str(host).strip().strip("[]")
    try:
        return [str(ipaddress.ip_address(h))]
    except ValueError:
        pass
    try:
        return sorted({i[4][0].split("%")[0] for i in socket.getaddrinfo(h, port, proto=socket.IPPROTO_TCP)})
    except OSError:
        return []


def check_internal(host, port=27017):
    """None when the database host is this computer or internal; else why it is refused."""
    if is_local(host):
        return None
    addrs = addresses_of(host, port)
    if not addrs:
        return f"MongoDB host {host} does not resolve to an address."
    public = [a for a in addrs if not is_internal_address(a)]
    if public:
        return (f"MongoDB at {host} has a public address ({', '.join(public[:3])}): the reports database must be "
                "internal (this computer or a private network address), never reachable from the internet.")
    return None


def port_of(value):
    """MONGO_PORT as a number (empty: 27017). Refused, saying why, when it is not a port from 1 to 65535: a reason,
    not a traceback (audit 4-11)."""
    s = str(value if value is not None else "").strip()
    if not s:
        return 27017
    if not (s.isascii() and s.isdigit()):
        raise Refused(f"MONGO_PORT {s[:40]!r} is not a number: set the database's port, from 1 to 65535 "
                      "(MongoDB's own is 27017).")
    port = int(s)
    if not 1 <= port <= 65535:
        raise Refused(f"MONGO_PORT {port} is not a port: set one from 1 to 65535 (MongoDB's own is 27017).")
    return port


def kwargs(get=None):
    """MongoClient keyword arguments for where the database is and how it is reached (no account: the caller adds it).
    get: a settings getter (os.environ.get, a dotenv dict's get). Raises Refused for an unsafe or broken setting."""
    get = get or os.environ.get
    host = (get("MONGO_HOST") or "127.0.0.1").strip()
    port = port_of(get("MONGO_PORT"))
    kw = {"host": host, "port": port}
    why = check_internal(host, port)
    if why:
        raise Refused(why)
    if _yes(get("MONGO_TLS")):
        kw["tls"] = True
        ca = (get("MONGO_TLS_CA_FILE") or "").strip()
        if ca:
            if not os.path.isfile(ca):
                raise Refused(f"MONGO_TLS_CA_FILE {ca} does not exist.")
            kw["tlsCAFile"] = ca
        cert = (get("MONGO_TLS_CERT_KEY_FILE") or "").strip()
        if cert:
            if not os.path.isfile(cert):
                raise Refused(f"MONGO_TLS_CERT_KEY_FILE {cert} does not exist.")
            kw["tlsCertificateKeyFile"] = cert
    elif not is_local(host) and not _yes(get("MONGO_ALLOW_PLAINTEXT")):
        raise Refused(f"MongoDB at {host} is on another computer and MONGO_TLS is off: the password and the reports would "
                      "cross the network unencrypted. Set MONGO_TLS=1 (and MONGO_TLS_CA_FILE when its certificate is from "
                      "your own CA), or, only on a link you trust, MONGO_ALLOW_PLAINTEXT=1.")
    return kw


def describe(get=None):
    """One line for checks and logs: where the database is and how it is reached (never a password)."""
    get = get or os.environ.get
    host, port = (get("MONGO_HOST") or "127.0.0.1").strip(), get("MONGO_PORT") or "27017"
    try:
        port_n = port_of(port)
    except Refused as why:
        return f"{host} (REFUSED: {why})"
    if check_internal(host, port_n):
        how = "REFUSED: not loopback or an internal network address"
    elif is_local(host):
        how = "this computer"
    elif _yes(get("MONGO_TLS")):
        how = "an internal server, over TLS"
    else:
        how = "an internal server, NOT encrypted (MONGO_ALLOW_PLAINTEXT=1)"
    return f"{host}:{port} ({how})"
