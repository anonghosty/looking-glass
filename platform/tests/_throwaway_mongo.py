# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""A MongoDB client that may create a throwaway database, for the tests that need one (test_new_collections.py,
test_new_service_collections.py), or None.

On a hardened installation no everyday account may: the platform's is read-only and the pipeline's may only write its
own database, and the administrator account is in /etc/looking-glass/mongo-admin.env, readable only by root
(database/store_mongo_admin.sh). So the candidates, in order:
  1. the file named by LG_MONGO_ADMIN_FILE (tests/run_admin_db_tests.sh reads the root-only file with sudo once, asking
     for the password, and hands it over this way);
  2. the root-only file itself, when sudo works without a password;
  3. the platform's .env, the pipeline's .env, and an administrator copy left in the pipeline folder (older set-ups).
The pipeline folder is ../database in a release install, ../shadowserver in a development copy. The first account that
can create and drop a database is used; its password never leaves this process.
"""
import io
import os
import subprocess

from dotenv import dotenv_values
from pymongo import MongoClient

HERE = os.path.dirname(os.path.abspath(__file__))
PLATFORM = os.path.dirname(HERE)
ETC = "/etc/looking-glass/mongo-admin.env"


def _creds(e):
    if e.get("MONGO_USER") and e.get("MONGO_PASSWORD"):
        return dict(username=e["MONGO_USER"], password=e["MONGO_PASSWORD"], authSource=e.get("MONGO_AUTH_SOURCE") or "admin")
    return None


def _candidates():
    given = os.environ.get("LG_MONGO_ADMIN_FILE")
    if given and os.path.isfile(given):
        yield _creds(dotenv_values(given))
    try:
        r = subprocess.run(["sudo", "-n", "cat", ETC], capture_output=True, text=True, timeout=10)
        if r.returncode == 0:
            yield _creds(dotenv_values(stream=io.StringIO(r.stdout)))
    except (OSError, subprocess.SubprocessError):
        pass
    files = [os.path.join(PLATFORM, ".env")]
    for d in ("database", "shadowserver"):
        base = os.path.join(os.path.dirname(PLATFORM), d)
        files += [os.path.join(base, ".env"), os.path.join(base, ".env.before-pipeline-account")]
    for f in files:
        if os.path.isfile(f):
            yield _creds(dotenv_values(f))


def client(host, port):
    # LG_THROWAWAY_MONGO=host:port: a throwaway MongoDB started for these tests alone (its own port and folder, with its
    # administrator in LG_MONGO_ADMIN_FILE), so the tests run where no account of the installation's own server may
    # create a database, and that server is never asked (the local release suite, 2026-11-26: "we do not skip")
    given = os.environ.get("LG_THROWAWAY_MONGO", "")
    if given:
        host, _, port = given.rpartition(":")
    for creds in _candidates():
        if not creds:
            continue
        c = MongoClient(host=host, port=int(port), serverSelectionTimeoutMS=8000, **creds)
        try:
            c["lg_write_probe"]["probe"].insert_one({"probe": 1})
            c.drop_database("lg_write_probe")
            return c
        except Exception:  # noqa: BLE001  (not allowed, or not reachable: try the next one)
            c.close()
    return None
