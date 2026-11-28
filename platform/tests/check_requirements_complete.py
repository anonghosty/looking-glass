# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
# runs itself with the project's own Python (.venv), from wherever it is called
''''exec "$(dirname -- "$0")/../.venv/bin/python" "$0" "$@" # '''
"""requirements.txt says exactly what the code uses (the production check of 2026-11-26), for every part that has one:
the platform, the database pipeline beside it and the docs site.

1. Every library the code imports is named in that part's requirements.txt, not only reached through another library
   (which could drop it in any version). Imports inside `try: ... except ImportError` are optional and listed apart.
2. Every library requirements.txt names is used: imported by the code, or one of the few named for another reason
   (KEPT below, each with its reason).
3. Every entry has an upper bound (the next major version, or one exact version), as requirements.txt explains.
4. Every library requirements.txt names is in that part's requirements.lock, at a version the entry allows.

Which library gives which module comes from each part's own environment (.venv), so the answer is the one the
installed platform really has. Needs no database and no network.
Run: .venv/bin/python tests/check_requirements_complete.py"""
import ast
import json
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
checks, fails = 0, []
SKIP_DIRS = {".venv", "venv", "node_modules", "__pycache__", ".git", "data", "backups", "site", "logs",
             "attachments_backup", "sorting_backup", "unzipped_backup", "tests"}
# named in requirements.txt but never imported, on purpose (each reason is checked where it can be)
KEPT = {
    "gunicorn": "the web server the service runs (the unit's ExecStart and gunicorn.conf.py), a command, not an import",
    "tzdata": "the time-zone data Python's zoneinfo reads when the server has no copy (timezones.py)",
    "typing-extensions": "named so the lock carries it for every Python (pyOpenSSL through webauthn needs it on 3.12)",
    "mkdocs-material": "the docs site's theme, named in mkdocs.yml (theme: material), not imported",
}


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info else ""), flush=True)


def norm(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def parse_reqs(path):
    """{name: spec} from a requirements.txt (comments and blank lines left out)."""
    out = {}
    for ln in open(path, encoding="utf-8"):
        ln = ln.split("#", 1)[0].strip()
        if not ln:
            continue
        m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?\s*(.*)$", ln)
        if m:
            out[norm(m.group(1))] = m.group(3).replace(" ", "")
    return out


def parse_lock(path):
    """{name: version} from a pip-compile style lock (name==version lines)."""
    out = {}
    for ln in open(path, encoding="utf-8"):
        m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([^\s\\;]+)", ln)
        if m:
            out[norm(m.group(1))] = m.group(2)
    return out


def allows(spec, version):
    """True when version satisfies a spec such as >=3.0,<4 or ==9.7.7 (numeric parts compared)."""
    def key(v):
        return tuple(int(x) for x in re.findall(r"\d+", v)[:4])
    for part in filter(None, spec.split(",")):
        m = re.match(r"(==|>=|<=|<|>|~=|!=)(.+)", part)
        if not m:
            return False
        op, v = m.groups()
        a, b = key(version), key(v)
        n = max(len(a), len(b))
        a, b = a + (0,) * (n - len(a)), b + (0,) * (n - len(b))
        if (op == "==" and a != b) or (op == ">=" and a < b) or (op == "<=" and a > b) or (op == "<" and a >= b) \
                or (op == ">" and a <= b) or (op == "!=" and a == b) or (op == "~=" and a < b):
            return False
    return True


def py_files(top, extra=()):
    for f in extra:
        if os.path.isfile(f):
            yield f
    for d, subs, files in os.walk(top):
        subs[:] = [s for s in subs if s not in SKIP_DIRS and not s.startswith(".")]
        for f in files:
            if f.endswith(".py"):
                yield os.path.join(d, f)


def optional_nodes(tree):
    """Import nodes inside a try whose handlers catch ImportError / ModuleNotFoundError (or everything)."""
    opt = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Try):
            names = set()
            for h in node.handlers:
                t = h.type
                if t is None:
                    names.add("Exception")
                for e in (t.elts if isinstance(t, ast.Tuple) else [t]) if t is not None else []:
                    names.add(getattr(e, "id", getattr(e, "attr", "")))
            if names & {"ImportError", "ModuleNotFoundError", "Exception", "BaseException"}:
                for sub in node.body:
                    for n in ast.walk(sub):
                        if isinstance(n, (ast.Import, ast.ImportFrom)):
                            opt.add(id(n))
    return opt


def imports_of(files):
    """{top-level module: [files]} for required and for optional imports (relative imports left out)."""
    need, opt = {}, {}
    for f in files:
        try:
            tree = ast.parse(open(f, encoding="utf-8").read(), filename=f)
        except (SyntaxError, UnicodeDecodeError, OSError):
            continue
        o = optional_nodes(tree)
        for n in ast.walk(tree):
            mods = []
            if isinstance(n, ast.Import):
                mods = [a.name for a in n.names]
            elif isinstance(n, ast.ImportFrom) and not n.level and n.module:
                mods = [n.module]
            for m in mods:
                (opt if id(n) in o else need).setdefault(m.split(".")[0], []).append(f)
    return need, opt


def local_names(top):
    names = set()
    for d, subs, files in os.walk(top):
        # the project's own code only: never a library folder of some environment (site-packages) taken for it
        subs[:] = [s for s in subs if s not in SKIP_DIRS - {"tests"} and not s.startswith(".")
                   and s not in ("site-packages", "dist-packages", "lib", "lib64")]
        names.update(f[:-3] for f in files if f.endswith(".py"))
        names.update(s for s in subs if os.path.isfile(os.path.join(d, s, "__init__.py")))
    return names


def dist_map(python):
    """{module: [distribution names]} and the installed versions, from that environment's own metadata."""
    code = ("import importlib.metadata as m, json, sys; "
            "print(json.dumps({'mods': m.packages_distributions(), 'stdlib': sorted(sys.stdlib_module_names), "
            "'vers': {d.metadata['Name']: d.version for d in m.distributions()}}))")
    r = subprocess.run([python, "-I", "-c", code], capture_output=True, text=True, timeout=120)
    if r.returncode:
        raise RuntimeError(r.stderr.strip()[-300:])
    data = json.loads(r.stdout)
    return ({k: [norm(x) for x in v] for k, v in data["mods"].items()}, set(data["stdlib"]),
            {norm(k): v for k, v in data["vers"].items()})


def shipped_db_files(top):
    """In the development tree the pipeline's folder also holds files that are not shipped (an old loader, tools):
    only the files tools/make_release.py ships are checked there (its DATABASE_FILES, read without running it).
    A release's database/ folder holds only shipped files, so there everything is checked."""
    mk = os.path.join(ROOT, "tools", "make_release.py")
    if not os.path.isfile(mk):
        return None
    for node in ast.walk(ast.parse(open(mk, encoding="utf-8").read())):
        if isinstance(node, ast.Assign) and any(getattr(t, "id", "") == "DATABASE_FILES" for t in node.targets):
            return [os.path.join(top, f) for f in ast.literal_eval(node.value) if f.endswith(".py")]
    return None


def part(name, top, python, extra_files=(), locals_from=None, only=None):
    print(f"\n{name} ({os.path.relpath(top, os.path.dirname(ROOT)) if top.startswith(os.path.dirname(ROOT)) else top})")
    req_p, lock_p = os.path.join(top, "requirements.txt"), os.path.join(top, "requirements.lock")
    ok(f"{name}: requirements.txt and requirements.lock are there", os.path.isfile(req_p) and os.path.isfile(lock_p))
    if not (os.path.isfile(req_p) and os.path.isfile(lock_p)):
        return
    reqs, lock = parse_reqs(req_p), parse_lock(lock_p)
    if not os.path.isfile(python):
        # no .venv of its own (the GitHub checks install the locks into the one Python that runs this): that Python
        python = sys.executable
    ok(f"{name}: its environment answers", os.path.isfile(python), python)
    mods, stdlib, vers = dist_map(python)
    code_top = locals_from or top
    files = [f for f in only if os.path.isfile(f)] if only else list(py_files(code_top, extra_files))
    need, opt = imports_of(files)
    opt = {m: v for m, v in opt.items() if m not in need}
    local = local_names(code_top) | {os.path.basename(f)[:-3] for f in extra_files}
    used = set()
    missing, unknown = [], []
    for mod in sorted(need):
        if mod in stdlib or mod in local or mod == "__future__":
            continue
        dists = mods.get(mod)
        if not dists:
            unknown.append(f"{mod} ({os.path.relpath(need[mod][0], code_top)})")
            continue
        named = [d for d in dists if d in reqs]
        used.update(dists)
        if not named:
            missing.append(f"{mod} from {'/'.join(dists)} ({os.path.relpath(need[mod][0], code_top)})")
    ok(f"{name}: every imported library is installed by the lock ({len(files)} files)", not unknown, "; ".join(unknown))
    ok(f"{name}: every imported library is named in requirements.txt", not missing, "; ".join(missing))
    for mod in sorted(opt):
        if mod not in stdlib and mod not in local:
            used.update(mods.get(mod, []))
            print(f"       optional (inside try/except ImportError): {mod}")
    unused = [r for r in reqs if r not in used and r not in KEPT]
    ok(f"{name}: every library requirements.txt names is used (or kept for a stated reason)", not unused, ", ".join(unused))
    for r in sorted(set(reqs) & set(KEPT)):
        print(f"       {r}: kept, {KEPT[r]}")
    uncapped = [f"{r}{s}" for r, s in reqs.items() if not re.search(r"(<[^=]|==)", s)]
    ok(f"{name}: every entry has an upper bound (next major version or one exact version)", not uncapped, ", ".join(uncapped))
    not_locked = [r for r in reqs if r not in lock]
    ok(f"{name}: every entry is in requirements.lock", not not_locked, ", ".join(not_locked))
    outside = [f"{r} {lock[r]} not in {reqs[r]}" for r in reqs if r in lock and not allows(reqs[r], lock[r])]
    ok(f"{name}: the lock's version of each entry is one requirements.txt allows", not outside, "; ".join(outside))
    drift = [f"{r} installed {vers.get(r)}, lock {lock[r]}" for r in reqs if r in lock and vers.get(r) and vers[r] != lock[r]]
    ok(f"{name}: the environment has the lock's versions", not drift, "; ".join(drift))


def find_db():
    for d in (os.environ.get("LG_DB_DIR", ""), os.path.join(ROOT, "..", "database"), os.path.join(ROOT, "..", "shadowserver"),
              os.path.expanduser("~/shadowserver")):
        if d and os.path.isfile(os.path.join(d, "zip_limits.py")):
            return os.path.abspath(d)
    return ""


part("platform", ROOT, os.path.join(ROOT, ".venv", "bin", "python"))
db = find_db()
ok("database pipeline: found beside the platform (database/ in a release, LG_DB_DIR otherwise)", bool(db))
if db:
    in_release = os.path.basename(db) == "database"
    part("database pipeline", db, os.path.join(db, ".venv", "bin", "python"),
         only=None if in_release else shipped_db_files(db))
# the docs site: docs/requirements.txt at the release's top (tools/release_root in the development tree), its code the
# MkDocs hooks file beside mkdocs.yml; built with its own environment where one exists, else the platform's metadata
# cannot answer for it, so its imports are checked against the docs lock by name
for rel in (os.path.join(ROOT, ".."), os.path.join(ROOT, "tools", "release_root")):
    if os.path.isfile(os.path.join(rel, "docs", "requirements.txt")) and os.path.isfile(os.path.join(rel, "mkdocs_hooks.py")):
        rel = os.path.abspath(rel)
        hooks = os.path.join(rel, "mkdocs_hooks.py")
        reqs = parse_reqs(os.path.join(rel, "docs", "requirements.txt"))
        lock = parse_lock(os.path.join(rel, "docs", "requirements.lock"))
        print(f"\ndocs site ({rel})")
        need, _ = imports_of([hooks])
        std = set(sys.stdlib_module_names)
        third = sorted(m for m in need if m not in std)
        # the hooks may use only what the docs lock brings (mkdocs and its own libraries)
        ok("docs site: the hooks import only what the docs lock installs", all(norm(m) in lock or m == "mkdocs" for m in third),
           ", ".join(third))
        ok("docs site: every entry has an upper bound", all(re.search(r"(<[^=]|==)", s) for s in reqs.values()),
           ", ".join(f"{r}{s}" for r, s in reqs.items()))
        ok("docs site: every entry is in its lock at an allowed version",
           all(r in lock and allows(s, lock[r]) for r, s in reqs.items()))
        break
else:
    ok("docs site: docs/requirements.txt and mkdocs_hooks.py found (release top or tools/release_root)", False)

print(f"\n{checks - len(fails)} of {checks} passed")
if fails:
    print("FAILED:\n  " + "\n  ".join(fails))
    sys.exit(1)
