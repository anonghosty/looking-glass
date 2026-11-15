"""For checks that read the reports database: without a reachable MongoDB (a fresh clone, CI, a machine without the
database) they are SKIPPED (exit 77), not crashed with a connection error (review follow-up, 2026-11-12). With MongoDB
up, nothing changes: a database error later in the check is still a failure.

    import needs_db; needs_db.require()      # at the top of the check, before importing app
"""
import os
import sys

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def reachable(timeout_ms=3000):
    try:
        from dotenv import dotenv_values
        from pymongo import MongoClient
        e = {**dotenv_values(os.path.join(HERE, ".env")), **os.environ}
        MongoClient(host=e.get("MONGO_HOST") or "localhost", port=int(e.get("MONGO_PORT") or 27017),
                    username=e.get("MONGO_USER") or None, password=e.get("MONGO_PASSWORD") or None,
                    authSource=e.get("MONGO_AUTH_SOURCE") or "admin",
                    serverSelectionTimeoutMS=timeout_ms).admin.command("ping")
        return True, ""
    except Exception as exc:  # noqa: BLE001  any reason is "not reachable" here; the name says which
        return False, exc.__class__.__name__


def require():
    up, why = reachable()
    if not up:
        print(f"SKIPPED: needs MongoDB, which is not reachable ({why})")
        sys.exit(77)
