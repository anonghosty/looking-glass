# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""The connectors' way out (connectors.py, the user 2026-11-24): one HTTPS request to an OpenCTI or MISP the CSIRT
runs, and nothing else.

- HTTPS only: a key never travels in the clear, also on an internal network.
- The address is looked up once and the connection goes to exactly that address (no DNS rebinding between the check
  and the connection), with the host name still checked against the certificate (SNI + hostname check).
- Never this computer, link-local or cloud metadata addresses, multicast or unspecified ones: a target is another
  server (Looking Glass is standalone; the platforms run elsewhere). Private network addresses are allowed: CSIRTs run
  their platforms inside their own network.
- The certificate is always checked: the system's trusted authorities, plus the organisation's own authority when
  CONNECTOR_CA_FILE in .env names its certificate. A direct IP address works when the certificate lists that address.
- No redirect is followed; 20 seconds at most; an answer is read up to 1 MB.
Every failure comes back as plain words saying what to fix (Test connection shows them).
"""
import http.client
import ipaddress
import json
import os
import socket
import ssl
from urllib.parse import urlsplit

import user_words

TIMEOUT = 20
MAX_ANSWER = 1024 * 1024
METADATA = {ipaddress.ip_address("169.254.169.254"), ipaddress.ip_address("fd00:ec2::254"), ipaddress.ip_address("100.100.100.200")}


class Refused(Exception):
    """A request Looking Glass will not make, or one that failed: str(e) is the plain reason, e.step names the check."""

    def __init__(self, step, text):
        super().__init__(text)
        self.step = step
        user_words.register(self, text)      # written for the reader: Test connection may show them


def parse(address):
    """(host, port, path) of an https:// address, or Refused."""
    a = (address or "").strip()
    u = urlsplit(a)
    if u.scheme != "https":
        raise Refused("address", "Use an https:// address: the key must never travel unencrypted.")
    if not u.hostname or u.username or u.password or "\\" in a or any(c.isspace() for c in a):
        raise Refused("address", "That is not a valid https:// address.")
    try:
        port = u.port or 443
    except ValueError:
        raise Refused("address", "That address has an invalid port.") from None
    return u.hostname.lower(), port, (u.path or "/") + (f"?{u.query}" if u.query else "")


def allowed_ip(ip):
    """None when Looking Glass may connect to this address, else why not."""
    if ip in METADATA:
        return "a cloud metadata address"
    if ip.is_loopback:
        return "this computer (connectors send to another server)"
    if ip.is_link_local:
        return "a link-local address"
    if ip.is_multicast or ip.is_unspecified or ip.is_reserved:
        return "not a server address"
    return None


def resolve(host, port):
    """The one address to connect to: an IP as given, or the name looked up once; refused when it is not allowed."""
    try:
        ips = [ipaddress.ip_address(host)]
    except ValueError:
        try:
            ips = [ipaddress.ip_address(i[4][0].split("%")[0]) for i in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)]
        except (socket.gaierror, UnicodeError):
            raise Refused("dns", f"The server's name {host} could not be found: check the address and this server's DNS.") from None
    for ip in ips:
        why = allowed_ip(ip)
        if why:
            raise Refused("address", f"{host} leads to {ip}, {why}: Looking Glass does not send there.")
    return str(ips[0])


def context():
    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ca = (os.environ.get("CONNECTOR_CA_FILE") or "").strip()
    if ca:
        try:
            ctx.load_verify_locations(cafile=ca)
        except (OSError, ssl.SSLError):
            raise Refused("certificate", f"CONNECTOR_CA_FILE ({ca}) could not be read as a certificate.") from None
    return ctx


class _Pinned(http.client.HTTPSConnection):
    """HTTPS to one fixed address, with the certificate checked for the host name."""

    def __init__(self, host, port, ip, ctx):
        super().__init__(host, port, timeout=TIMEOUT, context=ctx)
        self._ip = ip

    def connect(self):
        sock = socket.create_connection((self._ip, self.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


def request(method, address, headers=None, body=None):
    """(status, answer bytes, response headers). Raises Refused with plain words."""
    host, port, path = parse(address)
    ip = resolve(host, port)
    conn = _Pinned(host, port, ip, context())
    data = json.dumps(body).encode() if isinstance(body, (dict, list)) else body
    try:
        conn.request(method, path, body=data, headers={"User-Agent": "Looking Glass connector", **(headers or {})})
        r = conn.getresponse()
        answer = r.read(MAX_ANSWER + 1)
        if len(answer) > MAX_ANSWER:
            answer = answer[:MAX_ANSWER]
        return r.status, answer, dict(r.getheaders())
    except ssl.SSLCertVerificationError as e:
        why = getattr(e, "verify_message", "") or str(e)
        if "mismatch" in why.lower() or "doesn't match" in why.lower() or "not valid for" in why.lower():
            raise Refused("certificate", f"The certificate is not for {host}: use the name the certificate was made for, or a "
                          "certificate that lists this address.") from None
        raise Refused("certificate", f"The certificate of {host} is not trusted ({why}). If it comes from your organisation's "
                      "own authority, set CONNECTOR_CA_FILE in .env to that authority's certificate.") from None
    except ssl.SSLError as e:
        raise Refused("tls", f"The secure connection to {host} failed ({e.reason or e}).") from None
    except (TimeoutError, socket.timeout):
        raise Refused("port", f"{host} did not answer on port {port} within {TIMEOUT} s: check the firewall or proxy.") from None
    except ConnectionRefusedError:
        raise Refused("port", f"{host} refused the connection on port {port}: is the platform running, and the port right?") from None
    except OSError as e:
        raise Refused("port", f"This server could not reach {host} on port {port} ({e.strerror or e}): check the firewall "
                      "or proxy.") from None
    finally:
        conn.close()
