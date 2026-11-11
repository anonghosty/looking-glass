"""A MongoDB client that may create a throwaway database, for the tests that need one (test_new_collections.py,
test_new_service_collections.py), or None.

On a hardened installation no everyday account may: the platform's is read-only and the pipeline's may only write its
own database. So the candidates, in order: the platform's .env, the pipeline's .env, then the administrator account
the pipeline kept when it got its own (.env.before-pipeline-account, mode 600). The pipeline folder is ../database in
a release install, ../shadowserver in a development copy. The first account that can create and drop a database is
used; its password never leaves this process.
"""
import os

from dotenv import dotenv_values
from pymongo import MongoClient

HERE = os.path.dirname(os.path.abspath(__file__))
PLATFORM = os.path.dirname(HERE)


def _candidates():
    files = [os.path.join(PLATFORM, ".env")]
    for d in ("database", "shadowserver"):
        base = os.path.join(os.path.dirname(PLATFORM), d)
        files += [os.path.join(base, ".env"), os.path.join(base, ".env.before-pipeline-account")]
    for f in files:
        if os.path.isfile(f):
            e = dotenv_values(f)
            if e.get("MONGO_USER") and e.get("MONGO_PASSWORD"):
                yield dict(username=e["MONGO_USER"], password=e["MONGO_PASSWORD"], authSource=e.get("MONGO_AUTH_SOURCE") or "admin")


def client(host, port):
    for creds in _candidates():
        c = MongoClient(host=host, port=int(port), serverSelectionTimeoutMS=8000, **creds)
        try:
            c["lg_write_probe"]["probe"].insert_one({"probe": 1})
            c.drop_database("lg_write_probe")
            return c
        except Exception:  # noqa: BLE001  (not allowed, or not reachable: try the next one)
            c.close()
    return None
