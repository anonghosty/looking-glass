#!/bin/sh
# runs itself with the project's own Python (.venv), from wherever it is called
''''exec "$(dirname -- "$0")/../.venv/bin/python" "$0" "$@" # '''
"""The Overview's greeting (greetings.py), in-process, on a throwaway file: the first time it says "Greetings, <first
name>! Welcome to Looking Glass", after that one of the 30 greetings; always the person's name, never their username
(no name entered: "there"); a name with markup is shown as text; every greeting is short enough to fit.
Usage: tests/check_greetings.py"""
import os, sys, tempfile
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
os.environ.setdefault("THREATMAP_SCHEDULE", "0")
import app as A  # noqa: E402
import greetings  # noqa: E402
from flask import g, render_template  # noqa: E402

fails, checks = [], 0


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond: fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info else ""), flush=True)


tmp = tempfile.mkdtemp(prefix="lg-greet-")
W = A.GREETED
real_path, real_name = W.path, A.people.name
W.path = os.path.join(tmp, "greetings.json")
NAMES = {"lg-g-ike": "Ike Owuraku Amponsah", "lg-g-noname": "", "lg-g-evil": "<script>x</script> Smith"}
A.people.name = lambda u, d="": NAMES.get(u, d) if u in NAMES else real_name(u, d)


def greet(user):
    with A.app.test_request_context("/overview"):
        g.user = {"user": user, "role": "researcher", "perms": {"definitions"}, "csrf": "t", "created": 1.0}
        return A.app.jinja_env.globals["lg_greeting"]()


try:
    first = greet("lg-g-ike")
    ok("the first time: Greetings, <first name>! Welcome to Looking Glass", first[3] and "".join(first[:3]) == "Greetings, Ike! Welcome to Looking Glass",
       "".join(first[:3]))
    seen = set()
    for _ in range(80):
        x = greet("lg-g-ike")
        seen.add(x[0] + "{name}" + x[2])
    ok("after that, the random greetings (by name, never the first-time one)", all(s in greetings.GREETINGS for s in seen) and len(seen) > 10,
       f"{len(seen)} different in 80 visits")
    ok("…always the first name", all(greet("lg-g-ike")[1] == "Ike" for _ in range(5)))
    x = greet("lg-g-noname")
    ok("no name entered: never the username", x[1] == "there" and "lg-g-noname" not in "".join(x[:3]), "".join(x[:3]))
    with A.app.test_request_context("/overview"):
        g.user = {"user": "lg-g-evil", "role": "researcher", "perms": {"definitions"}, "csrf": "t"}
        html = render_template("overview.html", lg_perms=["definitions"], lg_user="lg-g-evil", lg_role="researcher", lg_csrf="t", lg_peace=False)
    ok("a name with markup is shown as text", "<script>x</script>" not in html and "&lt;script&gt;" in html)
    ok("30 greetings, each with the name once", len(greetings.GREETINGS) == 30 and all(s.count("{name}") == 1 for s in greetings.GREETINGS))
    longest = max(len(s.replace("{name}", "Bartholomew")) for s in greetings.GREETINGS + [greetings.FIRST])
    ok("each short enough to fit the title (a long name in it: at most 52 characters)", longest <= 52, f"longest {longest}")
finally:
    W.path = real_path
    A.people.name = real_name
    import shutil; shutil.rmtree(tmp, ignore_errors=True)
print(f"\n{checks - len(fails)} of {checks} greeting checks passed" + (f"; FAILED: {fails}" if fails else ""))
sys.exit(1 if fails else 0)
