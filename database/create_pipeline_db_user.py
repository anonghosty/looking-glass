#!/bin/sh
# runs itself with the project's own Python (.venv), from wherever it is called
''''exec "$(dirname -- "$0")/.venv/bin/python" "$0" "$@" # '''
"""Give the pipeline its own MongoDB account instead of the administrator (root) account.

The pipeline only needs to read and write its own database (MONGO_DB, default shadowserver): load reports, create
their indexes, keep the files_ and discovered_fields_ collections. With root it could also change or delete every
other database on the server, create accounts and change the server's settings. This account cannot.

The account `lookingglass_pipeline` (defined in the admin database, like the administrator) gets:
  readWrite      on MONGO_DB   everything the pipeline does with its reports
  clusterMonitor               read-only server status, for the `shadowserver check` cache check (optional: without
                               it that one check shows a warning)

Local MongoDB, administrator account in .env (what deploy.sh sets up):
  ./create_pipeline_db_user.py
    1. creates the account with a new random password (or resets it, if it exists);
    2. checks, without writing anything, that it has exactly those rights: read and write on MONGO_DB, nothing on any
       other database, no account management;
    3. keeps a copy of .env as .env.before-pipeline-account (mode 600: it holds the administrator password, and it is
       the way back) and puts the new account into .env.
  Way back: cp .env.before-pipeline-account .env

MongoDB on another server, run by someone else (MONGO_LOCAL=false):
  ./create_pipeline_db_user.py --print
    prints the commands for that server's administrator to run in mongosh (Looking Glass never needs their password).
    They choose the password and give it to you; put MONGO_USER, MONGO_PASSWORD and MONGO_AUTH_SOURCE=admin in .env.
"""
import json
import os
import re
import secrets
import shutil
import sys

from pymongo import MongoClient
from pymongo.errors import OperationFailure, PyMongoError

HERE = os.path.dirname(os.path.abspath(__file__))
ENV_PATH = os.path.join(HERE, ".env")
NEW_USER = "lookingglass_pipeline"
WRITE_ACTIONS = {"find", "insert", "update", "remove", "createIndex", "createCollection", "listCollections"}


def read_env(path):
    """KEY=VALUE lines, no shell expansion (the same rules as the pipeline's own loader)."""
    out = {}
    try:
        lines = open(path, encoding="utf-8").read().splitlines()
    except OSError:
        return out
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        k, v = k.strip(), v.strip()
        if len(v) >= 2 and v[0] == v[-1] and v[0] in "'\"":
            v = v[1:-1]
        out[k] = v
    return out


def roles(db):
    return [{"role": "readWrite", "db": db}, {"role": "clusterMonitor", "db": "admin"}]


def print_commands(db):
    r = json.dumps(roles(db))
    print(f"""For the administrator of the MongoDB server. In mongosh, signed in as an account that may create users:

  use admin
  db.createUser({{
    user: "{NEW_USER}",
    pwd: passwordPrompt(),          // asks for the password; it never appears on the screen or in the history
    roles: {r}
  }})

clusterMonitor only lets it read the server's status (for the cache check in `shadowserver check`); leave it out if
your policy does not allow it: that one check then shows a warning, everything else works.

Then, in this pipeline's .env:
  MONGO_USER={NEW_USER}
  MONGO_PASSWORD=<the password chosen above>
  MONGO_AUTH_SOURCE=admin
  MONGO_DB={db}""")


def client(e, user, pw, source):
    return MongoClient(host=e.get("MONGO_HOST") or "127.0.0.1", port=int(e.get("MONGO_PORT") or 27017), username=user,
                       password=pw, authSource=source, serverSelectionTimeoutMS=8000)


def rights(c):
    """The account's privileges as MongoDB reports them: {(db, collection): actions}, plus cluster-wide actions."""
    s = c.admin.command("connectionStatus", showPrivileges=True)["authInfo"]
    per, cluster = {}, set()
    for p in s.get("authenticatedUserPrivileges", []):
        res = p.get("resource", {})
        if res.get("cluster"):
            cluster |= set(p.get("actions", []))
        elif "db" in res:
            per.setdefault((res.get("db"), res.get("collection")), set()).update(p.get("actions", []))
    return per, cluster


def main():
    e = read_env(ENV_PATH)
    db = e.get("MONGO_DB") or "shadowserver"
    if "--print" in sys.argv[1:]:
        print_commands(db)
        return 0
    if e.get("MONGO_USER") == NEW_USER:
        sys.exit(f".env already uses {NEW_USER}.")
    if not e.get("MONGO_USER") or not e.get("MONGO_PASSWORD"):
        sys.exit("No administrator account in .env. For a MongoDB run by someone else, use --print.")
    admin = client(e, e["MONGO_USER"], e["MONGO_PASSWORD"], e.get("MONGO_AUTH_SOURCE") or "admin")
    pw = secrets.token_urlsafe(24)
    try:
        admin.admin.command("createUser", NEW_USER, pwd=pw, roles=roles(db))
        print(f"Created {NEW_USER}: read and write on {db}, server status (read only).")
    except OperationFailure as ex:
        if "already exists" not in str(ex):
            sys.exit(f"Could not create the account ({ex}). Is the account in .env an administrator? .env was not changed.")
        admin.admin.command("updateUser", NEW_USER, pwd=pw, roles=roles(db))
        print(f"{NEW_USER} existed: password reset, rights set again.")

    # check what the new account may do, from MongoDB's own answer (nothing is written to find out)
    try:
        per, cluster = rights(client(e, NEW_USER, pw, "admin"))
    except PyMongoError as ex:
        sys.exit(f"PROBLEM: the new account cannot sign in ({ex}). .env was not changed.")
    mine = per.get((db, ""), set())
    if not WRITE_ACTIONS <= mine:
        sys.exit(f"PROBLEM: missing rights on {db}: {', '.join(sorted(WRITE_ACTIONS - mine))}. .env was not changed.")
    # anywhere else: no change of any kind (clusterMonitor may read some server collections, such as system.profile)
    changes = {"insert", "update", "remove", "createCollection", "dropCollection", "createIndex", "dropIndex",
               "dropDatabase", "renameCollectionSameDB", "createUser", "dropUser", "grantRole", "changePassword"}
    elsewhere = sorted(f"{d or 'every database'}.{c or '*'}" for (d, c), acts in per.items() if d != db and acts & changes)
    if elsewhere or {"createUser", "dropUser", "grantRole", "shutdown", "setParameter"} & cluster:
        sys.exit(f"PROBLEM: the account may change more than {db} ({', '.join(elsewhere) or 'server'}). .env was not changed.")
    print(f"Rights check: read and write on {db}; cannot change any other database; cannot manage accounts"
          + ("; server status readable." if "serverStatus" in cluster else "."))

    shutil.copy2(ENV_PATH, ENV_PATH + ".before-pipeline-account")
    os.chmod(ENV_PATH + ".before-pipeline-account", 0o600)
    text = open(ENV_PATH, encoding="utf-8").read()
    for k, v in (("MONGO_USER", NEW_USER), ("MONGO_PASSWORD", pw), ("MONGO_AUTH_SOURCE", "admin")):
        if re.search(rf"^{k}=.*$", text, flags=re.M):
            text = re.sub(rf"^{k}=.*$", lambda _m, k=k, v=v: f"{k}={v}", text, flags=re.M)
        else:
            text += f"\n{k}={v}\n"
    with open(ENV_PATH, "w", encoding="utf-8") as f:
        f.write(text)
    os.chmod(ENV_PATH, 0o600)
    print(".env now uses the pipeline account. The administrator account is in .env.before-pipeline-account (mode 600):")
    print("keep that file (or its two MONGO_ lines) safe; it is the way back: cp .env.before-pipeline-account .env")
    return 0


if __name__ == "__main__":
    sys.exit(main())
