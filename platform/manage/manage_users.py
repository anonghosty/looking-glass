#!/bin/sh
# runs itself with the project's own Python (.venv), from wherever it is called
''''exec "$(dirname -- "$0")/../.venv/bin/python" "$0" "$@" # '''
HELP = """Looking Glass accounts (data/users.json). Run on the server; passwords are typed here, never on a web page.

  add NAME [--admin]      create an account (asks for the password), set up its authenticator app and recovery codes
  passwd NAME             change the password (ends the account's sessions)
  mfa NAME                set up (or replace) the authenticator app; new recovery codes (ends the account's sessions)
  role NAME ROLE        change the role (external, analyst, admin or a custom role)
  remove NAME             delete the account (ends its sessions)
  list                    accounts, roles, MFA status, recovery codes left

Usage: ./manage/manage_users.py add alice --admin
"""
import getpass
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from auth import LOWEST_ROLE, PASSWORD_RULES, NAME_RE, Users, new_recovery_codes, password_problem, totp_check, totp_new_secret, totp_uri  # noqa: E402

PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data", "users.json")
users = Users(PATH)


def ask_password(name):
    """The same rules as the web pages (auth.password_problem)."""
    print(PASSWORD_RULES)
    for _ in range(3):
        p1 = getpass.getpass(f"New password for {name}: ")
        problem = password_problem(name, p1)
        if problem:
            print(problem); continue
        if getpass.getpass("Repeat it: ") != p1:
            print("The two entries differ."); continue
        return p1
    sys.exit("No password set.")


def setup_mfa(name):
    secret = totp_new_secret()
    print("\nSet up the authenticator app (Google / Microsoft Authenticator, Aegis, FreeOTP...):")
    print("  Google Authenticator: + > Enter a setup key > Account: Looking Glass " + name + ", Key: the line below, Type: Time based")
    print("  Type the key exactly as shown: capital letters and digits, NO spaces. Keep it private (never paste it into chats or tickets).")
    print(f"\n     {secret}\n")
    print("  (for checking what you typed, the same key in groups of 4: " + " ".join(secret[i:i + 4] for i in range(0, len(secret), 4)) + ")")
    print("  Or open this link on the phone (it contains the key):")
    print(f"     {totp_uri(secret, name)}")
    for _ in range(3):
        code = input("\nType the 6-digit code the app now shows: ").strip()
        if totp_check(secret, code) is not None:
            break
        print("That code does not match: check the key and that the phone's clock is right.")
    else:
        sys.exit("Authenticator not confirmed; nothing changed.")
    codes, hashes = new_recovery_codes()
    users._load()
    u = users.data["users"][name]
    u.update(totp=secret, totp_last=None, recovery=hashes, changed=int(time.time()))
    users.save()
    print("\nRecovery codes (each works once if the phone is lost). Store them somewhere safe; they are not shown again:")
    for c in codes:
        print("   ", c)


def need(name, exists=True):
    if not NAME_RE.match(name or ""):
        sys.exit("Names: 2-40 letters, digits, dot, dash or underscore.")
    if exists and not users.get(name):
        sys.exit(f"No account {name}.")
    if not exists and users.get(name):
        sys.exit(f"Account {name} already exists.")


def main(a):
    if not a or a[0] in ("-h", "--help"):
        print(HELP); return
    cmd = a[0]
    if cmd == "list":
        for n, u in sorted(users.all().items()):
            print(f"  {n:20s} {u.get('role', LOWEST_ROLE):10s} MFA {'on ' if u.get('totp') else 'OFF'}  recovery codes left: {len(u.get('recovery', []))}")
        return
    name = a[1] if len(a) > 1 else ""
    if cmd == "add":
        need(name, exists=False)
        role = "admin" if "--admin" in a else LOWEST_ROLE   # "viewer" was renamed "external"
        users.set_password(name, ask_password(name), role)
        print(f"Account {name} ({role}) created.")
        try:
            setup_mfa(name)
        except (SystemExit, KeyboardInterrupt, EOFError):
            # no authenticator confirmed: the account goes again, never left with a password and no second factor
            # (external review, 2026-11-12)
            users._load(); users.data["users"].pop(name, None); users.save()
            sys.exit(f"Authenticator not confirmed: account {name} was not kept. Run add again.")
    elif cmd == "passwd":
        need(name); users.set_password(name, ask_password(name)); print("Password changed; the account's sessions have ended.")
    elif cmd == "mfa":
        need(name); setup_mfa(name); print("Authenticator set up; the account's sessions have ended.")
    elif cmd == "role":
        need(name)
        import json as _json
        rp = os.path.join(os.path.dirname(PATH), "roles.json")
        known = set(_json.load(open(rp))) if os.path.exists(rp) else {"external", "analyst", "researcher", "management", "admin"}
        if len(a) < 3 or a[2] not in known:
            sys.exit("role NAME " + "|".join(sorted(known)))
        users._load(); users.data["users"][name]["role"] = a[2]; users.save(); print(f"{name} is now {a[2]}.")
    elif cmd == "remove":
        need(name); users._load(); users.data["users"].pop(name, None); users.save(); print(f"Account {name} removed; its sessions have ended.")
    else:
        print(HELP)


if __name__ == "__main__":
    main(sys.argv[1:])
