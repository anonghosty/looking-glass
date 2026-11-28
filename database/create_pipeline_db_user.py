#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
# runs itself with the project's own Python (.venv), from wherever it is called
''''exec "$(dirname -- "$0")/.venv/bin/python" "$0" "$@" # '''
"""Give the pipeline its own MongoDB account instead of the administrator (root) account.

The pipeline only needs to read and write its own database (MONGO_DB, default shadowserver): load reports, create
their indexes, keep the files_ and discovered_fields_ collections. With root it could also change or delete every
other database on the server, create accounts and change the server's settings. This account cannot.

The account `lookingglass_pipeline` (defined in the admin database, like the administrator) gets:
  lookingglass_pipeline_on_<MONGO_DB>   a role of its own on MONGO_DB: read, add, change and delete rows, create
                               collections and indexes, list them. NOT MongoDB's readWrite, which also lets an account
                               drop collections and indexes and rename them (audit 2026-11-27): code run through a
                               hostile e-mail could then wipe every report at once. The pipeline never drops anything
                               (the quarterly purge deletes rows).
  clusterMonitor               read-only server status, for the `shadowserver check` cache check (optional: without
                               it that one check shows a warning)

Running installations (their account has readWrite): give it the new role, without changing its password:
  sudo cat /etc/looking-glass/mongo-admin.env | ./create_pipeline_db_user.py --update-rights
    the administrator account is read from standard input (never from the command line); the role is created (or set
    again), the account gets it in place of readWrite, and its rights are checked with its own password from .env.
  MongoDB run by someone else: ./create_pipeline_db_user.py --print shows the commands for its administrator.

Local MongoDB, administrator account in .env (what deploy.sh sets up):
  ./create_pipeline_db_user.py
    1. creates the account with a new random password (or resets it, if it exists);
    2. checks, without writing anything, that it has exactly those rights: read and write on MONGO_DB, nothing on any
       other database, no account management;
    3. keeps a copy of .env as .env.before-pipeline-account and puts the new account into .env;
    4. moves the administrator account from that copy to /etc/looking-glass/mongo-admin.env, readable only by root
       (store_mongo_admin.sh, with sudo), and removes the copy. Without sudo, or with --keep-copy, the copy stays.
  Way back: sudo cat /etc/looking-glass/mongo-admin.env, and put its MONGO_ lines back into .env

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
# what the pipeline's own role allows on MONGO_DB: WRITE_ACTIONS and read-only listings and statistics; nothing that
# drops or renames (readWrite would also allow dropCollection, dropIndex and renameCollectionSameDB)
ROLE_ACTIONS = sorted(WRITE_ACTIONS | {"listIndexes", "collStats", "dbStats", "killCursors"})
NEVER = {"dropCollection", "dropDatabase", "dropIndex", "renameCollectionSameDB", "convertToCapped", "compact"}


def role_name(db):
    return f"lookingglass_pipeline_on_{db}"


def parse_env(text):
    """KEY=VALUE lines of a text, no shell expansion (the same rules as the pipeline's own loader)."""
    out = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        k, v = k.strip(), v.strip()
        if len(v) >= 2 and v[0] == v[-1] and v[0] in "'\"":
            v = v[1:-1]
        out.setdefault(k, v)                 # a key written twice: the first counts, as in the pipeline
    return out


def read_env(path):
    """KEY=VALUE lines, no shell expansion (the same rules as the pipeline's own loader)."""
    try:
        with open(path, encoding="utf-8") as fh:
            return parse_env(fh.read())
    except OSError:
        return {}


def privileges(db):
    return [{"resource": {"db": db, "collection": ""}, "actions": ROLE_ACTIONS}]


def roles(db):
    return [{"role": role_name(db), "db": "admin"}, {"role": "clusterMonitor", "db": "admin"}]


def ensure_role(admin, db):
    """Create the pipeline's role on db (in the admin database), or set its privileges again when it exists."""
    try:
        admin.admin.command("createRole", role_name(db), privileges=privileges(db), roles=[])
    except OperationFailure as ex:
        if "already exists" not in str(ex):
            raise
        admin.admin.command("updateRole", role_name(db), privileges=privileges(db), roles=[])


def print_commands(db):
    r = json.dumps(roles(db))
    p = json.dumps(privileges(db))
    print(f"""For the administrator of the MongoDB server. In mongosh, signed in as an account that may create users and roles:

  use admin
  db.createRole({{
    role: "{role_name(db)}",
    privileges: {p},
    roles: []
  }})
  db.createUser({{
    user: "{NEW_USER}",
    pwd: passwordPrompt(),          // asks for the password; it never appears on the screen or in the history
    roles: {r}
  }})

An account made earlier with readWrite: run the createRole above, then (its password stays as it is)
  db.updateUser("{NEW_USER}", {{ roles: {r} }})

The role lets the pipeline read, add, change and delete report rows and create collections and indexes on {db}, but not
drop or rename them (MongoDB's readWrite would). clusterMonitor only lets it read the server's status (for the cache
check in `shadowserver check`); leave it out if your policy does not allow it: that one check then shows a warning,
everything else works.

Then, in this pipeline's .env:
  MONGO_USER={NEW_USER}
  MONGO_PASSWORD=<the password chosen above>
  MONGO_AUTH_SOURCE=admin
  MONGO_DB={db}""")


def client(e, user, pw, source):
    import db_connect
    return MongoClient(**db_connect.kwargs(e.get), username=user,
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


def check_rights(per, cluster, db):
    """"" when the account has exactly the pipeline's rights (from MongoDB's own answer); else what is wrong."""
    mine = per.get((db, ""), set())
    if not WRITE_ACTIONS <= mine:
        return f"missing rights on {db}: {', '.join(sorted(WRITE_ACTIONS - mine))}"
    drops = set().union(*[acts & NEVER for (d, _c), acts in per.items() if d == db])
    if drops:
        return f"the account may still drop or rename on {db} ({', '.join(sorted(drops))})"
    # anywhere else: no change of any kind (clusterMonitor may read some server collections, such as system.profile)
    changes = {"insert", "update", "remove", "createCollection", "dropCollection", "createIndex", "dropIndex",
               "dropDatabase", "renameCollectionSameDB", "createUser", "dropUser", "grantRole", "changePassword"}
    elsewhere = sorted(f"{d or 'every database'}.{c or '*'}" for (d, c), acts in per.items() if d != db and acts & changes)
    if elsewhere or {"createUser", "dropUser", "grantRole", "createRole", "shutdown", "setParameter"} & cluster:
        return f"the account may change more than {db} ({', '.join(elsewhere) or 'server'})"
    return ""


def rights_line(db, cluster):
    return (f"Rights check: read, add, change and delete rows on {db}; cannot drop or rename there; cannot change any "
            "other database; cannot manage accounts" + ("; server status readable." if "serverStatus" in cluster else "."))


def update_rights(e, db, admin_text):
    """--update-rights: an installation made before 2026-11-27 (readWrite) gets the pipeline's own role, its password
    unchanged. admin_text: the administrator account's KEY=VALUE lines (standard input)."""
    a = parse_env(admin_text)
    if not a.get("MONGO_USER") or not a.get("MONGO_PASSWORD"):
        sys.exit("No administrator account on standard input (sudo cat /etc/looking-glass/mongo-admin.env | "
                 "./create_pipeline_db_user.py --update-rights). Nothing was changed.")
    if e.get("MONGO_USER") != NEW_USER or not e.get("MONGO_PASSWORD"):
        sys.exit(f".env does not use {NEW_USER}: run ./create_pipeline_db_user.py without --update-rights. Nothing was changed.")
    admin = client(e, a["MONGO_USER"], a["MONGO_PASSWORD"], a.get("MONGO_AUTH_SOURCE") or "admin")
    try:
        ensure_role(admin, db)
        admin.admin.command("updateUser", NEW_USER, roles=roles(db))
    except OperationFailure as ex:
        sys.exit(f"Could not set the rights ({ex}). Is that account an administrator? Nothing else was changed.")
    print(f"{NEW_USER}: now {role_name(db)} on {db} in place of readWrite (its password is unchanged).")
    try:
        per, cluster = rights(client(e, NEW_USER, e["MONGO_PASSWORD"], e.get("MONGO_AUTH_SOURCE") or "admin"))
    except PyMongoError as ex:
        sys.exit(f"PROBLEM: {NEW_USER} cannot sign in with the password in .env ({ex}).")
    why = check_rights(per, cluster, db)
    if why:
        sys.exit(f"PROBLEM: {why}.")
    print(rights_line(db, cluster))
    return 0


def main():
    e = read_env(ENV_PATH)
    db = e.get("MONGO_DB") or "shadowserver"
    if "--print" in sys.argv[1:]:
        print_commands(db)
        return 0
    if "--update-rights" in sys.argv[1:]:
        return update_rights(e, db, sys.stdin.read())
    if e.get("MONGO_USER") == NEW_USER:
        sys.exit(f".env already uses {NEW_USER}. To give it the rights of this version: "
                 "sudo cat /etc/looking-glass/mongo-admin.env | ./create_pipeline_db_user.py --update-rights")
    if not e.get("MONGO_USER") or not e.get("MONGO_PASSWORD"):
        sys.exit("No administrator account in .env. For a MongoDB run by someone else, use --print.")
    admin = client(e, e["MONGO_USER"], e["MONGO_PASSWORD"], e.get("MONGO_AUTH_SOURCE") or "admin")
    pw = secrets.token_urlsafe(24)
    try:
        ensure_role(admin, db)
    except OperationFailure as ex:
        sys.exit(f"Could not create the pipeline's role ({ex}). Is the account in .env an administrator? .env was not changed.")
    try:
        admin.admin.command("createUser", NEW_USER, pwd=pw, roles=roles(db))
        print(f"Created {NEW_USER}: read and write rows on {db} (no drop), server status (read only).")
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
    why = check_rights(per, cluster, db)
    if why:
        sys.exit(f"PROBLEM: {why}. .env was not changed.")
    print(rights_line(db, cluster))

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
    print(".env now uses the pipeline account.")
    # the administrator account must not stay where the pipeline's own user can read it: store_mongo_admin.sh moves it
    # to /etc/looking-glass/ (root only) and removes the copy; without sudo the copy stays (mode 600)
    if "--keep-copy" not in sys.argv[1:]:
        import subprocess
        r = subprocess.run([os.path.join(HERE, "store_mongo_admin.sh"), ENV_PATH + ".before-pipeline-account"])
        if r.returncode == 0:
            return 0
    print("The administrator account is in .env.before-pipeline-account (mode 600), readable by this user. Move it")
    print("where only root can read it: ./store_mongo_admin.sh   (or keep it in a password manager and delete the file)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
