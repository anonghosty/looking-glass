# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""For the checks that call every route in-process: where no database answers (GitHub's unit job sets MONGO_PORT=1),
every database call fails at once instead of waiting for pymongo's server selection timeout on each route.
Where a database answers, nothing is changed. Returns True when the fast failure was put in place."""
import os
import socket


def _setting(name, default, base):
    if os.environ.get(name):
        return os.environ[name]
    try:
        for line in open(os.path.join(base, ".env"), encoding="utf-8"):
            if line.strip().startswith(name + "="):
                return line.split("=", 1)[1].strip().strip("'\"") or default
    except OSError:
        pass
    return default


def apply(base):
    host = _setting("MONGO_HOST", "127.0.0.1", base)
    try:
        port = int(_setting("MONGO_PORT", "27017", base))
    except ValueError:
        port = 27017
    try:
        socket.create_connection((host, port), timeout=1).close()
        return False
    except OSError:
        pass
    from pymongo.errors import ServerSelectionTimeoutError
    try:
        import pymongo.synchronous.topology as topology
    except ImportError:                                  # older pymongo
        import pymongo.topology as topology

    def fail(*a, **k):
        raise ServerSelectionTimeoutError("no database answers here (the check fails such calls at once)")
    topology.Topology._select_servers_loop = fail
    return True
