"""The outside-connection guard for the checks (2026-11-18): while LG_NO_OUTSIDE names a file, every Python process the
checks start (PYTHONPATH includes this folder, so Python loads this file first) may connect only to this computer and
to the configured database (MONGO_HOST). Any other connection, and any name look-up (DNS) of a name that is not this
computer's, is refused (OSError / socket.gaierror) and written to that file, one JSON line each: so nothing a check
does can leave the computer, and tests/no_outside/report.py says what was tried and fails on what is not by design.

Before this, five checks guarded themselves and the others nothing; a check that loaded a day with a map key set sent
place names to the map geocoder (lg-test, 2026-11-18). Reserved names (.example, .invalid, .test) are refused without
being written down: they never belong to anyone. Not covered: programs that are not Python (curl, git), which the
checks do not start."""
import ipaddress
import json
import os
import socket
import sys

_LOG = os.environ.get("LG_NO_OUTSIDE", "")


def _db_hosts():
    """The database's address: MONGO_HOST, and LG_NO_OUTSIDE_DB (run_all_checks.sh reads it from .env)."""
    return {h.strip().lower() for h in (os.environ.get("MONGO_HOST", ""), os.environ.get("LG_NO_OUTSIDE_DB", "")) if h.strip()}


def _local_names():
    names = {"localhost", "localhost.localdomain", "ip6-localhost", ""}
    try:                                              # this computer's own name (the app lists its own addresses)
        names.add(socket.gethostname().lower())
    except OSError:
        pass
    return names | _db_hosts()


def _is_local_ip(host):
    try:
        ip = ipaddress.ip_address(str(host).split("%", 1)[0])
    except ValueError:
        return None                                   # not an address: a name
    return ip.is_loopback or ip.is_unspecified or str(ip) in _db_hosts()


def _reserved(name):
    n = str(name or "").lower().rstrip(".")
    return n.endswith((".example", ".invalid", ".test")) or n in ("example", "invalid", "test")


def _note(kind, dest):
    try:
        with open(_LOG, "a", encoding="utf-8") as fh:
            fh.write(json.dumps({"kind": kind, "dest": str(dest)[:200],
                                 "check": os.path.basename(sys.argv[0] if sys.argv else "") or "?"}) + "\n")
    except OSError:
        pass


def _install():
    real_connect, real_connect_ex = socket.socket.connect, socket.socket.connect_ex
    real_gai = socket.getaddrinfo

    def allowed(address):
        if not isinstance(address, tuple) or not address:
            return True                               # a Unix socket (a path): this computer
        host = address[0]
        local = _is_local_ip(host)
        return local if local is not None else str(host).lower() in _local_names()

    def connect(self, address):
        if self.family == getattr(socket, "AF_UNIX", -1) or allowed(address):
            return real_connect(self, address)
        _note("connect", f"{address[0]}:{address[1]}" if len(address) > 1 else address[0])
        raise OSError(f"refused by the checks' outside-connection guard: {address[0]} is not this computer")

    def connect_ex(self, address):
        if self.family == getattr(socket, "AF_UNIX", -1) or allowed(address):
            return real_connect_ex(self, address)
        _note("connect", f"{address[0]}:{address[1]}" if len(address) > 1 else address[0])
        return 111                                    # ECONNREFUSED

    def getaddrinfo(host, *a, **k):
        h = "" if host is None else (host.decode() if isinstance(host, bytes) else str(host))
        if _is_local_ip(h) is not None or h.lower() in _local_names() or h.lower().endswith(".localhost"):
            return real_gai(host, *a, **k)
        if not _reserved(h):
            _note("dns", h)
        raise socket.gaierror(socket.EAI_NONAME, f"refused by the checks' outside-connection guard: {h}")

    socket.socket.connect, socket.socket.connect_ex, socket.getaddrinfo = connect, connect_ex, getaddrinfo
    # create_connection and urllib resolve through getaddrinfo, and connect through socket.connect: both covered
    socket.gethostbyname = lambda h: getaddrinfo(h, None)[0][4][0]


if _LOG:
    _install()
