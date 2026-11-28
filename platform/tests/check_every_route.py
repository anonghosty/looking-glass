#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""Every route survives bad input (a crash, a traceback, a reflected script or a stalled answer on any of them fails).

Every route of the app (all of app.url_map but `static`) is called in-process, signed out and as a made-up account of
each built-in role (temporary stores, tests/lg_inproc.py), with bad input:
- path parts: a made-up existing-looking value, an unknown one, an empty-ish one (a space), 5,000 characters (holding
  <script>x</script>), odd Unicode (right-to-left marks, an emoji, NUL as %00), a path-traversal attempt (..%2F..);
- query strings: none, and each query parameter name the code reads (found in the modules: args.get / getlist / _arg)
  with garbage: not a date, negative, huge, non-numeric, the name given twice, 5,000 characters, odd Unicode;
- write routes (POST/PUT/PATCH/DELETE), with the session's own form token so the request reaches the route: no body,
  JSON {}, JSON with every key the code reads given a string, a list, null or nested dicts, text that is not JSON with
  a JSON content type, a large but allowed body (about 60 KB) and a form body.
Sampling (keeps the run to a few minutes): per route, method and role every input KIND is sent at least once. Each path
kind is sent with no query string (and no body on writes); each query kind is sent twice with the made-up path: once
with every parameter name set to it, once with only one name set (the name rotates over routes and roles, so every
name meets every kind somewhere); each body kind is sent once with the made-up path. As admin (who opens the most),
every GET route that answers an HTML page also gets each parameter name on its own set to <script>x</script>, for the
reflected-input check.

For every answer: no 5xx; no Python traceback or exception text in the body; a 4xx under /api/ is JSON with an "error"
in words; every answer within 10 seconds (the slowest are listed); no HTML page carries the <script>x</script> input
back unescaped. A crash names the file:line that raised (caught in-process through got_request_exception).

Nothing is written and no database is used: MONGO_PORT=1 (database calls fail at once and answer 503 "the report
database cannot be read", which is counted, not failed), every write outside the temporary folder, new process, signal
and network connection is refused (a 500 that comes from such a refusal is counted as "stopped at a refused write",
not failed), and the modification times of every file in data/ are compared before and after.
Run: LG_STEPUP_TESTS_OFF=1 .venv/bin/python tests/check_every_route.py"""
import glob, json, os, re, sys, tempfile, time, traceback
from urllib.parse import quote, urlencode
BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)
os.environ["MONGO_PORT"] = "1"                       # never a database, live or not
os.environ["MONGO_HOST"] = "127.0.0.1"
os.environ.setdefault("LG_QUIET", "1")
os.environ.setdefault("THREATMAP_SCHEDULE", "0")
os.environ["TRUST_PROXY"] = "0"
import app as A  # noqa: E402
import auth  # noqa: E402
from flask import got_request_exception  # noqa: E402

sys.path.insert(0, os.path.join(BASE, "tests"))
import lg_inproc  # noqa: E402
import lg_no_db_fast  # noqa: E402

lg_no_db_fast.apply(BASE)
T0 = time.time()
UA = "lg-check-every-route"
tmp = tempfile.mkdtemp(prefix="lg-every-route-")
ROLES = lg_inproc.builtin_roles(auth)
CL = lg_inproc.accounts(A, auth, tmp, "lger", UA, ROLES)

# ------------------------------------------------------------------ the names the code reads (inputs, not assertions)
SRC = ""
for f in sorted(glob.glob(os.path.join(BASE, "*.py"))):
    with open(f, encoding="utf-8", errors="replace") as fh:
        SRC += fh.read()
PARAMS = sorted(set(re.findall(r"""args\.get(?:list)?\(\s*["']([A-Za-z_][\w-]*)["']""", SRC))
                | set(re.findall(r"""_arg\(\s*["']([A-Za-z_][\w-]*)["']""", SRC))
                | {"day", "at", "from", "to", "n", "page", "q", "code", "network", "region", "sector", "industry",
                   "report", "name", "fid", "id", "all", "reveal", "demo"})
KEYS = sorted(set(re.findall(r"""(?:body|data|payload|js|j|d|b|req|p|f|form|args|g_json|inp|obj)\.get\(\s*["']([A-Za-z_]\w*)["']""", SRC))
              | set(re.findall(r"""get_json\([^)]*\)\s*(?:or\s*\{\})?\)?\.get\(\s*["']([A-Za-z_]\w*)["']""", SRC)))[:400]

# ------------------------------------------------------------------ the bad inputs
XSS = "<script>x</script>"
LONG = XSS + "a" * (5000 - len(XSS))
MADE = {"quarter": "2026-Q3", "kind": "csv", "platform": "linux", "action": "view", "ref": "LG-2026-0001",
        "code": "accessible-rdp", "name": "made-up-name"}
PATH_KINDS = ("made-up", "unknown", "empty-ish", "5000 chars", "unicode", "traversal")


def path_value(name, kind):
    idlike = name in ("fid", "iid", "jid", "pid", "sid", "tid", "n") or name.endswith("id")
    return {"made-up": MADE.get(name, "1" if idlike else "made-up"),
            "unknown": "987654321" if idlike else "lg-no-such-" + name,
            "empty-ish": "%20",
            "5000 chars": quote(LONG, safe=""),
            "unicode": "%E2%80%8F%E2%80%AEab%F0%9F%A6%8A%00c",
            "traversal": "..%2F..%2F..%2Fetc%2Fpasswd"}[kind]


QUERY_KINDS = {"not a date": "2026-13-45T99", "negative": "-5", "huge": "9" * 40, "non-numeric": "abc",
               "given twice": ["1", "x"], "5000 chars": LONG, "unicode": "‏‮ab\U0001F98A\x00c"}
BODIES = {
    "no body": {},
    "JSON {}": {"json": {}},
    "JSON strings for every key": {"json": {k: "x" for k in KEYS}},
    "JSON lists for every key": {"json": {k: [1, "a"] for k in KEYS}},
    "JSON null for every key": {"json": dict.fromkeys(KEYS)},
    "JSON nested dicts for every key": {"json": {k: {"a": {"b": [None, {}]}} for k in KEYS}},
    "not JSON with a JSON type": {"data": "{not json" + XSS, "content_type": "application/json"},
    "large allowed body": {"json": {"note": XSS + "a" * 60000}},
    "form body": {"data": {k: XSS for k in KEYS[:200]}},
}

TRACE = [(re.compile(r"Traceback \(most recent call last\)"), "a Python traceback"),
         (re.compile(r'File "[^"]+", line \d+'), "a traceback line"),
         (re.compile(r"__debugger__|Werkzeug Debugger|werkzeug\.debug"), "the werkzeug debugger"),
         (re.compile(r"\b(?:[a-z_]\w*\.)+[A-Z]\w*(?:Error|Exception)\b"), "an exception with its module path"),
         (re.compile(r"\b[A-Z]\w*(?:Error|Exception): "), "exception text"),
         (re.compile(r"<class '[\w.]+'>"), "a Python class name")]

# ------------------------------------------------------------------ catch what raised, in-process
CAUGHT = []


def _caught(sender, exception, **k):
    CAUGHT.append(exception)


got_request_exception.connect(_caught, A.app, weak=False)
_real_http_exc = A.app.handle_http_exception


def _http_exc(e):                                    # an abort(4xx): where it was raised
    CAUGHT.append(e)
    return _real_http_exc(e)


A.app.handle_http_exception = _http_exc


def site(exc):
    """The file:line in the platform's own code that raised (the deepest such frame)."""
    frames = traceback.extract_tb(exc.__traceback__)
    own = [f for f in frames if f.filename.startswith(BASE) and "/.venv" not in f.filename and "/tests/" not in f.filename]
    f = (own or frames or [None])[-1]
    where = f"{os.path.relpath(f.filename, BASE)}:{f.lineno}" if f else "?"
    return f"{type(exc).__name__} at {where}: {str(exc)[:120]}"


def from_guard(exc, tag="check_every_route"):
    while exc is not None:
        if isinstance(exc, PermissionError) and tag in str(exc):
            return True
        exc = exc.__cause__ or exc.__context__
    return False


# ------------------------------------------------------------------ data/ before
def snapshot():
    return lg_inproc.data_snapshot(BASE)


before = snapshot()
G = lg_inproc.guard(tmp, "check_every_route")

# ------------------------------------------------------------------ the walk
rules = sorted((r for r in A.app.url_map.iter_rules() if r.endpoint != "static"), key=lambda r: r.rule)
PARAM_RX = re.compile(r"<(?:[^:>]+:)?([^>]+)>")
fails, seen_fail, stats, slow = [], set(), {"requests": 0, "db": 0, "write stop": 0, "pairs": 0}, []
STOPPED = set()                                      # routes that reached a refused write (not followed past it)
LAST = {"type": ""}                                  # the content type of the last answer


def fail(m, rule, who, label, status, what):
    key = (m, rule, who, what)
    fails.append((m, rule, who, label, status, what))
    if key not in seen_fail:
        seen_fail.add(key)
        print(f"FAIL {m} {rule} [{who}] {label} -> {status}: {what}", flush=True)


def call(c, m, url, csrf, body):
    h = {"User-Agent": UA}
    if csrf and m != "GET":
        h["X-CSRF-Token"] = csrf
    return c.open(url, method=m, headers=h, **body)


def check(m, rule, who, label, c, csrf, url, body, sent_xss):
    del CAUGHT[:]
    n_ref = len(G.refused)
    t = time.time()
    try:
        r = call(c, m, url, csrf, body)
    except KeyboardInterrupt:
        raise
    except BaseException as e:                       # noqa: BLE001 (propagated out of the app: always a failure)
        if from_guard(e):
            stats["write stop"] += 1
            STOPPED.add(f"{m} {rule}")
            return
        fail(m, rule, who, label, "raised", "raised out of the app: " + site(e))
        return
    dt = time.time() - t
    stats["requests"] += 1
    slow.append((dt, f"{m} {url[:90]} [{who}]"))
    if dt > 10:
        fail(m, rule, who, label, r.status_code, f"took {dt:.1f}s (over 10 s)")
    body_b = r.get_data()
    ctype = r.headers.get("Content-Type", "")
    LAST["type"] = ctype
    text = body_b.decode("utf-8", "replace") if ("text" in ctype or "json" in ctype or "javascript" in ctype) else ""
    if r.status_code >= 500:
        exc = CAUGHT[-1] if CAUGHT else None
        if r.status_code == 503 and "report database cannot be read" in text:
            stats["db"] += 1
        elif r.status_code == 503 and "json" in ctype and re.search(r'"error"\s*:\s*"[^"]*\bnot set up\b', text):
            # an outside service this installation was not given (2026-11-26, lg-test: no MALPEDIA_TOKEN): the route
            # says so in words, as designed; any other 503 still fails
            stats["not set up"] = stats.get("not set up", 0) + 1
        elif (exc is not None and from_guard(exc)) or (exc is None and len(G.refused) > n_ref):
            stats["write stop"] += 1
            STOPPED.add(f"{m} {rule}")
        else:
            fail(m, rule, who, label, r.status_code, site(exc) if exc else f"a {r.status_code} without an exception: {text[:100]!r}")
        return
    for rx, what in TRACE:
        hit = rx.search(text)
        if hit:
            fail(m, rule, who, label, r.status_code, f"{what} in the body: {hit.group(0)[:80]!r} "
                 f"(in {text[max(0, hit.start() - 160):hit.end() + 60]!r})")
            break
    if rule.startswith("/api/") and 400 <= r.status_code < 500:
        try:
            j = json.loads(text) if "json" in ctype else None
        except ValueError:
            j = None
        if not isinstance(j, dict):
            where = f" from {site(CAUGHT[-1]).split(': ')[0]}" if CAUGHT else ""
            fail(m, rule, who, label, r.status_code, f"a refusal under /api/ that is not JSON ({ctype.split(';')[0] or 'no type'}){where}")
        elif not (isinstance(j.get("error"), str) and re.search(r"[A-Za-z]{3,}", j["error"])):
            fail(m, rule, who, label, r.status_code, f"a JSON refusal without an error in words: {text[:100]!r}")
    if sent_xss and "html" in ctype and XSS in text:
        fail(m, rule, who, label, r.status_code, "the <script>x</script> input comes back unescaped in an HTML page")


def build(rule, kind_of):
    return PARAM_RX.sub(lambda mo: path_value(mo.group(1), kind_of(mo.group(1))), rule)


print(f"{len(rules)} routes ({sum(1 for r in rules if (r.methods or set()) & {'POST', 'PUT', 'PATCH', 'DELETE'})} take changes) "
      f"x {len(CL)} (signed out and {len(ROLES)} roles); {len(PARAMS)} query names, {len(KEYS)} body keys", flush=True)
inputs_checked = 0
for ri, r in enumerate(rules):
    has_params = bool(PARAM_RX.search(r.rule))
    made = build(r.rule, lambda n: "made-up")
    for m in sorted((r.methods or set()) - {"HEAD", "OPTIONS"}):
        for wi, (who, (c, csrf)) in enumerate(CL.items()):
            stats["pairs"] += 1
            for k in (PATH_KINDS if has_params else PATH_KINDS[:1]):
                url = build(r.rule, lambda n, k=k: k)
                inputs_checked += 1
                LAST["type"] = ""
                check(m, r.rule, who, f"path {k}", c, csrf, url, {}, k == "5000 chars")
                if k == "made-up":
                    plain_type = LAST["type"]
            if m == "GET":
                for qi, (qk, qv) in enumerate(QUERY_KINDS.items()):
                    qs_all = urlencode({p: qv for p in PARAMS}, doseq=True)
                    one = PARAMS[(ri * 7 + wi * 3 + qi) % len(PARAMS)]
                    qs_one = urlencode({one: qv}, doseq=True)
                    inputs_checked += 2
                    check(m, r.rule, who, f"query all names = {qk}", c, csrf, f"{made}?{qs_all}", {}, qk == "5000 chars")
                    check(m, r.rule, who, f"query {one} = {qk}", c, csrf, f"{made}?{qs_one}", {}, qk == "5000 chars")
                if who == "admin" and "html" in plain_type:   # the reflected-input check, every name on its own
                    for p in PARAMS:
                        inputs_checked += 1
                        check(m, r.rule, who, f"query {p} = {XSS}", c, csrf, f"{made}?{urlencode({p: XSS})}", {}, True)
            else:
                for bk, body in BODIES.items():
                    inputs_checked += 1
                    check(m, r.rule, who, f"body {bk}", c, csrf, made, body, True)
    if ri % 40 == 39:
        print(f"  ... {ri + 1} of {len(rules)} routes, {time.time() - T0:.0f}s", flush=True)

# ------------------------------------------------------------------ data/ after
after = snapshot()
changed = sorted(k for k in set(before) | set(after) if before.get(k) != after.get(k))
ours = sorted({w[6:] for w in G.refused if w.startswith("write ")})          # what this run tried (and was refused)
servers = lg_inproc.live_servers(BASE)               # the platform's own server, run from this folder, writes data/ too
for k in changed:
    tried = any(os.path.realpath(o) == os.path.realpath(os.path.join(BASE, k)) for o in ours)
    if servers and not tried:
        print(f"note: {k} changed during the run; this run tried no write there (and every write outside the temporary "
              f"folder is refused), and the platform's own server (pid {', '.join(servers)}) runs from this folder: its "
              "write, not this check's", flush=True)
    else:
        fail("-", "data/", "-", k, "-", "a file in data/ changed during the run" + ("" if k in after else " (removed)"))

# ------------------------------------------------------------------ summary
slow.sort(reverse=True)
groups = {}
for m, rule, who, label, status, what in fails:
    cause = re.sub(r": .*", "", what) if " at " in what else what.split(":")[0]
    groups.setdefault(cause, set()).add(f"{m} {rule}")
print("\nfailures grouped by cause:" if fails else "")
for cause, routes in sorted(groups.items(), key=lambda kv: -len(kv[1])):
    print(f"  {len(routes):4d} route(s): {cause}   e.g. {', '.join(sorted(routes)[:4])}")
print(f"\n{len(rules)} routes, {stats['pairs']} route/method/role pairs, {inputs_checked} inputs checked "
      f"({stats['requests']} answers; {stats['db']} answered 'no database', {stats.get('not set up', 0)} answered 'not set up', "
      f"{stats['write stop']} stopped at a refused write; "
      f"{len(set(G.refused))} distinct refused steps)")
print(f"stopped at a refused write (checked up to that step only), {len(STOPPED)} route(s): {', '.join(sorted(STOPPED))}")
print("refused steps: " + "; ".join(sorted({os.path.relpath(w[6:], BASE) if w.startswith("write /") else w for w in G.refused})))
print("slowest: " + "; ".join(f"{d:.2f}s {w}" for d, w in slow[:5]))
print(f"{len(fails)} failures ({len(seen_fail)} distinct) in {time.time() - T0:.0f}s" + ("" if fails else "; every route checks passed"))
sys.stdout.flush(); sys.stderr.flush()
G.real_exit(1 if fails else 0)                    # the guards stay on: background threads cannot write on the way out
