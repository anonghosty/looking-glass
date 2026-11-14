#!/bin/sh
# runs itself with the project's own Python (.venv), from wherever it is called
''''exec "$(dirname -- "$0")/../.venv/bin/python" "$0" "$@" # '''
"""Give Looking Glass a read-only MongoDB account instead of the administrator account (docs/SECURITY.md).

Run it yourself on the server; it uses the administrator account currently in .env once:
  1. creates the user `lookingglass_ro` with only the `read` role on MONGO_DB (or resets its password),
     with a new random 32-character password;
  2. checks that the new account can read and cannot write;
  3. keeps a copy of .env as .env.before-readonly (mode 600) and puts the new account into .env;
  4. when the database pipeline is next to the platform: moves the administrator account from that copy to
     /etc/looking-glass/mongo-admin.env, readable only by root (its store_mongo_admin.sh, with sudo), and removes the
     copy. Otherwise (or with --keep-copy) the copy stays: move it off the server.
Then reload the service (deploy/reload.sh).

MongoDB on another server, run by someone else: --print shows the commands for its administrator to run instead
(Looking Glass never needs their password); they give you the password for .env.

Usage: .venv/bin/python deploy/create_readonly_db_user.py [--print] [--keep-copy]
"""
import os
import re
import secrets
import shutil
import sys

from dotenv import dotenv_values
from pymongo import MongoClient
from pymongo.errors import OperationFailure

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
ENV_PATH = os.path.join(ROOT, ".env")
E = dotenv_values(ENV_PATH)
DB = E.get("MONGO_DB") or "shadowserver"
NEW_USER = "lookingglass_ro"


def client(user, pw, source):
    return MongoClient(host=E.get("MONGO_HOST", "localhost"), port=int(E.get("MONGO_PORT") or 27017), username=user, password=pw,
                       authSource=source, serverSelectionTimeoutMS=8000)


if "--print" in sys.argv[1:]:
    print(f"""For the administrator of the MongoDB server. In mongosh, signed in as an account that may create users:

  use {DB}
  db.createUser({{
    user: "{NEW_USER}",
    pwd: passwordPrompt(),          // asks for the password; it never appears on the screen or in the history
    roles: [{{ role: "read", db: "{DB}" }}]
  }})

Then, in Looking Glass's .env:
  MONGO_USER={NEW_USER}
  MONGO_PASSWORD=<the password chosen above>
  MONGO_AUTH_SOURCE={DB}
  MONGO_DB={DB}
and reload: deploy/reload.sh""")
    sys.exit(0)

admin = client(E.get("MONGO_USER"), E.get("MONGO_PASSWORD"), E.get("MONGO_AUTH_SOURCE") or "admin")
if E.get("MONGO_USER") == NEW_USER:
    sys.exit(".env already uses the read-only account.")
pw = secrets.token_urlsafe(24)
try:
    admin[DB].command("createUser", NEW_USER, pwd=pw, roles=[{"role": "read", "db": DB}])
    print(f"Created {NEW_USER} with the read role on {DB}.")
except OperationFailure as e:
    if "already exists" not in str(e):
        raise
    admin[DB].command("updateUser", NEW_USER, pwd=pw, roles=[{"role": "read", "db": DB}])
    print(f"{NEW_USER} existed: password reset, roles set to read on {DB}.")

ro = client(NEW_USER, pw, DB)
names = ro[DB].list_collection_names()
print(f"Read check: {len(names)} collections visible.")
try:
    ro[DB]["lg_write_probe"].insert_one({"probe": 1})
    sys.exit("PROBLEM: the new account could write. .env was not changed.")
except OperationFailure:
    print("Write check: refused, as it should be.")

shutil.copy2(ENV_PATH, ENV_PATH + ".before-readonly")
os.chmod(ENV_PATH + ".before-readonly", 0o600)
text = open(ENV_PATH, encoding="utf-8").read()
for k, v in (("MONGO_USER", NEW_USER), ("MONGO_PASSWORD", pw), ("MONGO_AUTH_SOURCE", DB)):
    if re.search(rf"^{k}=.*$", text, flags=re.M):
        text = re.sub(rf"^{k}=.*$", f"{k}={v}", text, flags=re.M)
    else:
        text += f"\n{k}={v}\n"
with open(ENV_PATH, "w", encoding="utf-8") as f:
    f.write(text)
os.chmod(ENV_PATH, 0o600)
print(".env now uses the read-only account. Reload: bash deploy/reload.sh")
# the copy holds the administrator password: move it where only root can read it (the database pipeline's
# store_mongo_admin.sh, next to the platform), or say what to do with it
store = next((p for p in (os.path.join(ROOT, "..", d, "store_mongo_admin.sh") for d in ("database", "shadowserver"))
              if os.path.isfile(p)), None)
if store and "--keep-copy" not in sys.argv[1:]:
    import subprocess
    if subprocess.run([store, ENV_PATH + ".before-readonly"]).returncode == 0:
        sys.exit(0)
print("The old copy .env.before-readonly holds the administrator password. Move it off this server, or where only root")
print("can read it (database/store_mongo_admin.sh .../platform/.env.before-readonly), once everything works.")
