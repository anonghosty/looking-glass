#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""Who gets through each route (privilege escalation through the API): every route and method of the app is called
in-process as an account with no permission at all, as one account per single permission, and as each built-in role.
Changes are sent as JSON with the session's own form token, so a refusal can only come from the permission check.

The result is the app's permission map: for each route and method, open to any signed-in account, opened by which
single permissions, and which built-in roles get through. It is compared with the reviewed map in
tests/role_access_map.json: a route that opens for a permission or role it did not open for before, or a new route, fails
until the map is reviewed and updated (LG_UPDATE_ROLE_MAP=1 writes the current map, for review in its diff).

Nothing is written: the account, session, counter, role and first-run stores are temporary files, the audit log is a
list, and while the routes run every file write outside the temporary folder, every database write, every new process
and every connection to another computer is refused. Answers that need the reports database are skipped where there is
none (as on GitHub): such a route counts by its refusal, which comes first.
Run: .venv/bin/python tests/check_role_refusals.py"""
import base64, builtins, json, os, re, shutil, socket, subprocess, sys, tempfile, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("LG_QUIET", "1")
os.environ.setdefault("THREATMAP_SCHEDULE", "0")
os.environ["TRUST_PROXY"] = "0"
HERE = os.path.dirname(os.path.abspath(__file__))
MAP_FILE = os.path.join(HERE, "role_access_map.json")
import app as A  # noqa: E402
import auth  # noqa: E402
from werkzeug.security import generate_password_hash  # noqa: E402

sys.path.insert(0, HERE)
import lg_no_db_fast  # noqa: E402

if lg_no_db_fast.apply(os.path.dirname(HERE)):
    print("no database answers here: database calls fail at once (the permission check comes first on every route)")

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{str(info)[:1500]}]" if info and not cond else ""), flush=True)


tmp = tempfile.mkdtemp(prefix="lg-role-refusals-")
AU = A.AUTH
users, sessions, throttle, audit, roles = AU["users"], AU["sessions"], AU["throttle"], AU["audit"], AU["roles"]
audit.add = lambda ev, **k: None
sessions.path, throttle.path, roles.path = (os.path.join(tmp, n) for n in ("sessions.json", "login_counters.json", "roles.json"))
AU["setup"].path = os.path.join(tmp, "setup_code")
sessions.s.clear(); throttle.fail.clear()
PERMS = sorted(auth.PERMS)
BUILTIN = sorted(set(auth.DEFAULT_ROLES) | set(auth.FIXED_ROLES))
# made-up roles: none, and one per permission
for p in PERMS:
    roles.roles["lgperm-" + p] = [p]
roles.roles["lgperm-none"] = []
H = generate_password_hash("Steady-Harbour-Lantern-63!")
WHO = {"none": "lgperm-none", **{"perm:" + p: "lgperm-" + p for p in PERMS}, **{"role:" + r: r for r in BUILTIN}}
ACC = {f"lgrr-{i}": {"hash": H, "role": role, "status": "active", "totp": base64.b32encode(os.urandom(20)).decode().rstrip("="),
                     "changed": 0, "created": 1, "pw_set_at": int(time.time()), "profile": {"full_name": f"Check {i}"}}
       for i, (who, role) in enumerate(WHO.items())}
with open(os.path.join(tmp, "users.json"), "w") as fh:
    json.dump({"users": ACC}, fh)
users.path, users.mtime = os.path.join(tmp, "users.json"), None
UA = "lg-check-role-refusals"
CL = {}
for (who, role), name in zip(WHO.items(), ACC):
    tok = sessions.create(name, "127.0.0.1", UA)
    c = A.app.test_client(); c.set_cookie("lg_session", tok)
    CL[who] = (c, sessions.s[auth._h(tok)]["csrf"])

# ------------------------------------------------------------------ nothing may be written or sent while the routes run
tmp_real, real_open, refused = os.path.realpath(tmp), builtins.open, []


def guarded_open(file, mode="r", *a, **k):
    if any(ch in str(mode) for ch in "wax+") and isinstance(file, (str, bytes, os.PathLike)):
        p = os.path.realpath(os.fsdecode(file))
        if not p.startswith(tmp_real + os.sep):
            refused.append("write")
            raise PermissionError("check_role_refusals: no writes")
    return real_open(file, mode, *a, **k)


def refuse(what):
    def f(*a, **k):
        refused.append(what)
        raise PermissionError("check_role_refusals: " + what)
    return f


builtins.open = guarded_open
real_makedirs = os.makedirs
for fn in ("replace", "rename", "remove", "unlink", "rmdir", "makedirs", "mkdir", "chmod"):
    setattr(os, fn, refuse("os." + fn))
# a folder that is already there is not a change (stores call makedirs(exist_ok=True) before every write)
os.makedirs = lambda p, *a, **k: None if os.path.isdir(p) else refuse("os.makedirs")()
shutil.rmtree, shutil.move, shutil.copy, shutil.copy2, shutil.copyfile = (refuse("shutil") for _ in range(5))
subprocess.Popen = refuse("a new process")
real_connect = socket.socket.connect


def local_only(self, addr, *a, **k):
    host = addr[0] if isinstance(addr, tuple) else addr
    if isinstance(host, str) and (host.startswith("127.") or host in ("::1", "localhost") or host.startswith("/")):
        return real_connect(self, addr, *a, **k)
    refused.append("a connection to another computer")
    raise PermissionError("check_role_refusals: no outside connections")


socket.socket.connect = local_only           # create_connection and every client library go through it
try:
    import pymongo.collection as PC
    for m in ("insert_one", "insert_many", "update_one", "update_many", "replace_one", "delete_one", "delete_many",
              "bulk_write", "drop", "create_index", "find_one_and_update", "find_one_and_delete", "find_one_and_replace"):
        setattr(PC.Collection, m, refuse("a database write"))
except ImportError:
    pass


def outcome(r):
    """'refused' or 'through' (anything the handler answered itself: 2xx, 400, 404 of a missing item, 409...)."""
    if r.status_code in (401, 403):
        return "refused"
    if r.status_code in (301, 302, 303, 307, 308) and "/login" in r.headers.get("Location", ""):
        return "refused"
    return "through"         # a redirect elsewhere is the page's own (/overview opens the start page)


# ------------------------------------------------------------------ the walk
rules = sorted(A.app.url_map.iter_rules(), key=lambda r: r.rule)
items = []
for r in rules:
    if r.rule.startswith("/static/") or r.rule.startswith(auth.PUBLIC_PATHS):
        continue
    path = re.sub(r"<(?:[^:>]+:)?[^>]+>", "1", r.rule)
    for m in sorted((r.methods or set()) - {"HEAD", "OPTIONS"}):
        items.append((m, r.rule, path))
print(f"{len(items)} route/method pairs x {len(CL)} accounts", flush=True)
MAP, errors, t_start = {}, [], time.time()
for m, rule, path in items:
    got = {}
    for who, (c, csrf) in CL.items():
        try:
            if m == "GET":
                resp = c.get(path, headers={"User-Agent": UA})
            else:
                resp = c.open(path, method=m, json={}, headers={"User-Agent": UA, "X-CSRF-Token": csrf})
            got[who] = outcome(resp)
        except Exception as e:                      # noqa: BLE001 (past the check: a refused write, no database)
            got[who] = "through"
            errors.append(f"{who} {m} {rule}: {type(e).__name__}")
    MAP[f"{m} {rule}"] = {"open_to_any_signed_in": got["none"] == "through",
                          "opened_by": sorted(k[5:] for k, v in got.items() if k.startswith("perm:") and v == "through"),
                          "roles": sorted(k[5:] for k, v in got.items() if k.startswith("role:") and v == "through")}
print(f"walk took {time.time() - t_start:.0f}s; errors past the check: {len(errors)}", flush=True)

# ------------------------------------------------------------------ the rules every map must keep
# a role's own quarterly report is that role's alone (admins have their own, quarterly.py)
ROLE_ONLY = {"GET /api/advisory/quarterly/<quarter>/<kind>": {"advisor"}, "GET /api/mgmt/quarterly/<quarter>/<kind>": {"management"}}
admin_missing = sorted(k for k, v in MAP.items() if "admin" not in v["roles"] and v["roles"] and set(v["roles"]) != ROLE_ONLY.get(k))
ok("admin gets through wherever any role does (apart from a role's own quarterly report)", not admin_missing, admin_missing[:10])
odd_only = sorted(f"{k}: {v['roles']}" for k, v in MAP.items() if k in ROLE_ONLY and set(v["roles"]) != ROLE_ONLY[k])
ok("…and those are opened for their own role only", not odd_only, odd_only)
ext_extra = sorted(k for k, v in MAP.items() if "external" in v["roles"] and not v["open_to_any_signed_in"]
                   and not set(v["opened_by"]) & {"view"})
ok("external gets through only where 'view' (its one permission) does", not ext_extra, ext_extra[:10])
# (a route may need two permissions together, as Findings does: unmasked AND export for analysts, so which role may
# open what is judged by the reviewed map below, not by single permissions)
admin_only = [k for k, v in MAP.items() if "users" in v["opened_by"] and len(v["opened_by"]) == 1]
bad_admin = [f"{k}: {v['roles']}" for k, v in MAP.items() if k in admin_only and set(v["roles"]) - {"admin"}]
ok("routes only 'users' opens (account management): admin only", not bad_admin, bad_admin[:10])

# ------------------------------------------------------------------ compared with the reviewed map
if os.environ.get("LG_UPDATE_ROLE_MAP") == "1":
    with real_open(MAP_FILE, "w", encoding="utf-8") as fh:
        json.dump(MAP, fh, indent=1, sort_keys=True); fh.write("\n")
    print(f"written: {MAP_FILE} ({len(MAP)} entries) - review its diff")
elif os.path.exists(MAP_FILE):
    with real_open(MAP_FILE, encoding="utf-8") as fh:
        ref = json.load(fh)
    wider = []
    for k, v in MAP.items():
        was = ref.get(k)
        if was is None:
            wider.append(f"new route {k}: open to any={v['open_to_any_signed_in']}, opened by {v['opened_by']}, roles {v['roles']}")
            continue
        if v["open_to_any_signed_in"] and not was["open_to_any_signed_in"]:
            wider.append(f"{k}: now open to any signed-in account")
        more = set(v["opened_by"]) - set(was["opened_by"])
        if more:
            wider.append(f"{k}: now also opened by {sorted(more)}")
        rm = set(v["roles"]) - set(was["roles"])
        if rm:
            wider.append(f"{k}: now also {sorted(rm)}")
    ok(f"no route opens wider than the reviewed map ({len(ref)} entries)", not wider, wider[:15])
else:
    ok("the reviewed map exists (tests/role_access_map.json)", False, "run with LG_UPDATE_ROLE_MAP=1 and review it")

print(f"\n{checks - len(fails)} of {checks} role refusal checks passed" + (f"; FAILED: {fails}" if fails else ""))
sys.stdout.flush(); sys.stderr.flush()
os._exit(1 if fails else 0)
