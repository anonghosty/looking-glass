#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""The insider package (insider.py, the user 2026-11-18), with made-up text, a scratch folder and a throwaway Flask app;
the installation's data/ is never read or written:
1. seals: keyed fingerprints of the whole, each line and each address; never the text; another key, other seals;
2. a copy is recorded BEFORE it happens: signed in, the page's CSRF token; the audit entry says what and how many, never
   the text; when it cannot be recorded, it is refused (the page then copies nothing); own recovery codes unsealed;
3. long copies and traced files may be larger than the platform's 64 KB, nothing else may;
4. every downloaded file sealed (its SHA-256, its lines and addresses; a ZIP's files); a list saved in the browser too;
5. Trace a leak: auditors and administrators, CSRF, at most 5 a minute; exact and partial matches, by file and by
   text; a CSV header in many people's downloads does not count; audited without what was searched; nothing kept;
5b. the external review (2026-11-19): guesses cannot be tested (a /16 compared as a whole only; 1,000 guesses holding
   the real addresses do not match; a real excerpt does), a daily trace limit, at most 30 copies recorded a minute per
   person, one person's repeated copies never make rows "common", seals pruned daily, the seals read line by line;
6. the pages: the full name in every header, lg-copy.js on every signed-in page, no other way to the clipboard,
   the Overview's notice, the copy address open to every role.
Run: .venv/bin/python tests/check_insider.py"""
import io
import json
import os
import re
import sys
import tempfile
import zipfile

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
os.environ.setdefault("LG_QUIET", "1")
os.environ.pop("COPY_SEAL_KEY", None)
import insider as I  # noqa: E402

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info else ""), flush=True)


tmp = tempfile.mkdtemp()
TEXT = "198.51.100.7\n203.0.113.9\nexample-c2.test beacon line\n"
print("1. Seals")
s1 = I.Sealer(b"k1" * 16, os.path.join(tmp, "a.jsonl"))
s2 = I.Sealer(b"k2" * 16, os.path.join(tmp, "b.jsonl"))
a, b = s1.seal_text(TEXT), s1.seal_text(TEXT.replace("\n", "\r\n") + "   ")
ok("the same text, the same seal (line ends and trailing spaces do not matter)", a["whole"] == b["whole"])
ok("…its lines and its addresses each fingerprinted", a["lines"] == 3 and a["addresses"] == 2 and len(a["items"]) == 5, str(a)[:120])
ok("another key: other fingerprints (cannot be tested without the key)", s2.seal_text(TEXT)["whole"] != a["whole"])
ok("no text and no address in a seal", "198.51.100" not in json.dumps(a) and "beacon" not in json.dumps(a))
key_dir = tempfile.mkdtemp()
k = I.load_key(key_dir)
kp = os.path.join(key_dir, "data", "copy_seal.key")
ok("the key is made once, owner-only, and kept", len(k) > 40 and oct(os.stat(kp).st_mode & 0o777) == "0o600" and I.load_key(key_dir) == k)
os.environ["COPY_SEAL_KEY"] = "from-the-env-file-test-only"
ok("COPY_SEAL_KEY in .env wins", I.load_key(key_dir) == b"from-the-env-file-test-only")
os.environ.pop("COPY_SEAL_KEY")

print("2. A copy, recorded first")
from flask import Flask, Response, g, render_template_string, request  # noqa: E402
app = Flask("insider-check")
app.config["MAX_CONTENT_LENGTH"] = 64 * 1024                 # as security.py sets it
who = {"user": "grace", "perms": {"view"}, "csrf": True}
audit = []


class Audit:
    def add(self, kind, **kw):
        audit.append((kind, kw))


@app.before_request
def _u():
    g.user = ({"user": who["user"], "automation": who.get("automation", False)}) if who["user"] else None


@app.route("/x/hosts.csv")
def _csv():
    body = "ip,asn,report\n198.51.100.7,64500,made-up\n203.0.113.9,64501,made-up\n"
    return Response(body, mimetype="text/csv", headers={"Content-Disposition": 'attachment; filename="hosts.csv"'})


@app.route("/x/other.csv")
def _csv2():
    return Response("ip,asn,report\n192.0.2.44,64502,made-up\n", mimetype="text/csv", headers={"Content-Disposition": 'attachment; filename="other.csv"'})


@app.route("/x/pack.zip")
def _zip():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("list.csv", "ip,asn,report\n192.0.2.200,64510,made-up\n")
    return Response(buf.getvalue(), mimetype="application/zip", headers={"Content-Disposition": 'attachment; filename="pack.zip"'})


@app.route("/x/drill")
def _drill():
    return {"hosts": [{"ip": "192.0.2.77"}]}


@app.route("/x/post", methods=["POST"])
def _post():
    return {"n": len(request.get_data())}


@app.route("/x/page")
def _page():
    return render_template_string("signed in as {{ lg_name }}")


base = tempfile.mkdtemp()
api = I.install(app, {"base_dir": base, "has_perm": lambda p: p in who["perms"], "csrf_ok": lambda: who["csrf"],
                      "audit": Audit(), "people_name": lambda u: {"grace": "Grace Mensah", "sarah": "Sarah Owusu"}.get(u, "")})
seals = os.path.join(base, "data", "copy_seals.jsonl")
c = app.test_client()
rec = lambda **b: c.post("/api/copy/record", json=b)  # noqa: E731
who["user"] = ""
ok("signed out: refused", rec(text=TEXT, kind="addresses").status_code == 401)
who["user"], who["csrf"] = "grace", False
ok("without the page's CSRF token: refused", rec(text=TEXT, kind="addresses").status_code == 403)
who["csrf"] = True
r = rec(text=TEXT, kind="addresses", what="the addresses of a combination (2)", page="Combination search")
e = audit[-1]
ok("recorded: the audit entry says who, what, how many and the seal", r.status_code == 200 and e[0] == "copied" and e[1]["user"] == "grace"
   and e[1]["target"] == "the addresses of a combination (2)" and "3 lines, 2 addresses" in e[1]["detail"] and r.get_json()["id"] in e[1]["detail"], str(e))
ok("…never the text: not in the audit entry, not in the seal", "198.51.100" not in json.dumps(audit) and "198.51.100" not in open(seals).read()
   and "beacon" not in open(seals).read())
ok("the seals file is owner-only", oct(os.stat(seals).st_mode & 0o777) == "0o600")
ok("nothing to copy: refused", rec(text="   ", kind="text").status_code == 400)
n = len(audit)
r = rec(kind="recovery", what="own recovery codes", text="abcd-ef01-2345")
ok("own recovery codes: recorded, never fingerprinted", r.status_code == 200 and len(audit) == n + 1 and "not fingerprinted" in audit[-1][1]["detail"]
   and "abcd" not in open(seals).read())
real = api["sealer"].path
blocker = os.path.join(tmp, "a-file"); open(blocker, "w").close()
api["sealer"].path = os.path.join(blocker, "copy_seals.jsonl")        # its folder is a file: cannot be written
n = len(audit)
r = rec(text=TEXT, kind="addresses")
ok("when the copy cannot be recorded: refused (503), nothing audited, so the page copies nothing", r.status_code == 503 and len(audit) == n)
api["sealer"].path = real
js = open(os.path.join(HERE, "static", "js", "lg-copy.js"), encoding="utf-8").read() if os.path.exists(os.path.join(HERE, "static", "js", "lg-copy.js")) else ""
S = os.environ.get("LG_HELD_DIR", "")
if S and os.path.exists(os.path.join(S, "lg-copy.js.new")):
    js = open(os.path.join(S, "lg-copy.js.new"), encoding="utf-8").read()
i_rec, i_write = js.find("/api/copy/record"), js.find("await write(text)")
ok("the page copies only after the record answers (fail closed)", 0 < i_rec < i_write and "if (!r.ok || !d || d.ok !== true) return { ok: false" in js)   # behaviour: check_copy_fail_closed.py

print("3. Request sizes")
big = "\n".join(f"198.51.{i // 250}.{i % 250}" for i in range(9000))     # about 120 KB
ok("a long list copied (over 64 KB) is taken", len(big) > 64 * 1024 and rec(text=big, kind="addresses").status_code == 200)
ok("…other addresses keep the 64 KB limit", c.post("/x/post", data="x" * 70000).status_code == 413
   and c.post("/x/post", data="x" * 1000).status_code == 200)
who["perms"] = {"view"}
ok("a large trace from someone without the 'audit' permission: refused", c.post("/api/audit/trace", json={"text": "y" * 70000}).status_code in (403, 413))

print("4. Every downloaded file sealed")
before = sum(1 for _ in open(seals))
c.get("/x/hosts.csv"); c.get("/x/other.csv"); c.get("/x/pack.zip"); c.get("/x/drill?download=1")
lines = [json.loads(x) for x in open(seals)][before:]
ok("each download sealed: its file name, its SHA-256, its lines and addresses", len(lines) == 4 and lines[0]["what"] == "hosts.csv"
   and len(lines[0]["sha256"]) == 64 and lines[0]["addresses"] == 2 and lines[0]["lines"] == 3, str(lines[:1])[:200])
ok("…a ZIP: each file in it too", lines[2]["files"] and lines[2]["files"][0]["name"] == "list.csv" and lines[2]["addresses"] == 1)
ok("…a list saved in the browser: its addresses", lines[3]["what"] == "a list saved in the browser" and lines[3]["addresses"] == 1)
ok("…never the content", "198.51.100" not in json.dumps(lines) and "made-up" not in json.dumps(lines))
n0 = sum(1 for _ in open(seals))
who["automation"] = True
c.get("/x/hosts.csv")
who["automation"] = False
ok("the local check scripts' downloads (automation key) are not sealed: people only", sum(1 for _ in open(seals)) == n0)
c.get("/x/hosts.csv"); c.get("/x/hosts.csv"); c.get("/x/other.csv")
for p in ("ama", "kofi", "esi", "yaw", "abena"):        # five more PEOPLE download it: the CSV header is common
    who["user"] = p; c.get("/x/other.csv")
who["user"] = "grace"

print("5. Trace a leak")
tr = lambda **b: c.post("/api/audit/trace", json=b)  # noqa: E731
ok("not an auditor or administrator: refused", tr(text=TEXT).status_code == 403)
who["perms"], who["user"] = {"audit"}, "sarah"
who["csrf"] = False
ok("without the page's CSRF token: refused", tr(text=TEXT).status_code == 403)
who["csrf"] = True
r = tr(text=TEXT).get_json()
m0 = r["matches"][0] if r.get("matches") else {}
ok("the exact text copied: found, with who and when", m0.get("exact") and m0.get("who") == "Grace Mensah" and m0.get("kind") == "copy" and m0.get("t"), str(m0))
r = tr(text="leaked:\n203.0.113.9\nsomething else\n").get_json()
ok("one address of it: found as a partial match (1 of its lines and addresses)",
   any(m["kind"] == "copy" and not m["exact"] and m["matched"] >= 1 for m in r["matches"]), str(r["matches"][:2])[:200])
r = c.post("/api/audit/trace", data={"file": (io.BytesIO(b"ip,asn,report\n198.51.100.7,64500,made-up\n203.0.113.9,64501,made-up\n"), "found.csv")},
           headers={"X-CSRF-Token": "x"}, content_type="multipart/form-data").get_json()
ok("the exact file downloaded: found by its fingerprint", any(m["kind"] == "download" and m["exact"] and m["what"] == "hosts.csv" for m in r["matches"]), str(r)[:200])
ok("…a CSV header in every download does not make the other list a match",
   not any(m["what"] == "other.csv" for m in r["matches"]) and r["common_left_out"] >= 1, str([m["what"] for m in r["matches"]]))
zbuf = io.BytesIO()
with zipfile.ZipFile(zbuf, "w") as z:
    z.writestr("renamed.csv", "ip,asn,report\n192.0.2.200,64510,made-up\n")
r = c.post("/api/audit/trace", data={"file": (io.BytesIO(zbuf.getvalue()), "x.zip")}, content_type="multipart/form-data").get_json()
ok("a file from a ZIP downloaded, renamed and zipped again: found", any(m["what"] == "pack.zip" for m in r["matches"]), str(r)[:200])
ok("nothing that was never copied or downloaded: no match", tr(text="192.0.2.250\nnot from here at all\n").get_json()["total"] == 0)
traced = [x for x in audit if x[0] == "leak_traced"]
ok("each trace audited: who, how many matches, never what was searched", traced and traced[-1][1]["user"] == "sarah"
   and re.fullmatch(r"\d+ match(es)?", traced[-1][1]["detail"]) and "192.0.2" not in json.dumps(traced))
ok("…what was given is not kept", "192.0.2.250" not in open(seals).read() and "not from here" not in open(seals).read())
codes = [tr(text="203.0.113.9").status_code for _ in range(3)]
ok("at most 5 a minute per person", 429 in codes, str(codes))

print("5b. The external review's findings (2026-11-19)")
import ipaddress  # noqa: E402
secret = ["198.18.37.201", "198.18.140.9", "198.18.200.77"]           # a test range (RFC 2544), made up
who["user"] = "analyst1"
r = rec(text="ip,network\n" + "\n".join(f"{ip},Example Net" for ip in secret), kind="addresses")
ok("(set-up) an analyst copies three addresses", r.status_code == 200)
who["user"], who["perms"] = "auditor1", {"audit"}
guess = lambda net: "\n".join(str(a) for a in ipaddress.ip_network(net))      # noqa: E731
r = tr(text=guess("198.18.0.0/16")).get_json()
ok("a whole /16 of guesses (65,536): compared as a whole only, nothing matches, and the answer says why",
   r.get("total") == 0 and r.get("exact_only") is True and r.get("max_items") == 1000, str({k: r.get(k) for k in ("total", "exact_only")}))
near = [f"198.18.37.{i}" for i in range(997)] + secret                          # 1,000 guesses holding the three real ones
r = tr(text="\n".join(near)).get_json()
ok("1,000 guesses that hold the real addresses: no match (they are not most of what was given)", r.get("total") == 0, str(r.get("matches"))[:160])
r = tr(text="\n".join(secret + ["198.18.1.1"])).get_json()
ok("…a real excerpt (3 of the 4 lines leaked): found", r.get("total") >= 1 and r["matches"][0]["matched"] >= 3 and r["matches"][0]["given"] == 8,
   str(r.get("matches"))[:200])
I.TRACE_PER_DAY, keep_day = 2, I.TRACE_PER_DAY
who["user"] = "auditor2"
codes = [tr(text="203.0.113.9").status_code for _ in range(3)]
I.TRACE_PER_DAY = keep_day
ok("a daily limit per person besides the minute's", codes[:2] == [200, 200] and codes[2] == 429, str(codes))
# small traces (at most 3 lines) watched: many in 24 hours put an alert in the administrators' bell (the user, 2026-11-20)
watch = os.path.join(base, "data", I.WATCH_FILE)
wd = json.load(open(watch)) if os.path.exists(watch) else {}
ok("small traces are noted: who and when only", wd.get("auditor2") and all(isinstance(t, int) for t in wd["auditor2"])
   and "203.0.113" not in open(watch).read(), str(wd)[:160])
ok("…the notes file is owner-only (0600)", (os.stat(watch).st_mode & 0o777) == 0o600)
ok("…a trace of more than 3 lines is not noted as small", "auditor1" not in wd or len(wd["auditor1"]) <= 1, str(wd.get("auditor1")))
# the external review of e6702c4 (2026-11-20): a guess sent as a file, a ZIP, or padded with filler lines was not counted


def trace_file(body, name):
    return c.post("/api/audit/trace", data={"file": (io.BytesIO(body), name)}, content_type="multipart/form-data")


def noted(user):
    return len((json.load(open(watch)) if os.path.exists(watch) else {}).get(user) or [])


zb = io.BytesIO()
with zipfile.ZipFile(zb, "w") as z:
    z.writestr("one.txt", "198.18.37.201\n")
small_cases = [("an uploaded file of one address", lambda: trace_file(b"198.18.37.201\n", "guess.txt")),
               ("a ZIP holding a one-line file", lambda: trace_file(zb.getvalue(), "guess.zip")),
               ("one address pasted with filler lines", lambda: tr(text="198.18.37.201\nfiller one\nfiller two\nfiller three\nfiller four"))]
for i, (label, send) in enumerate(small_cases):
    who["user"] = f"auditor3{i}"
    r = send()
    ok(f"…{label}: still answers, and is noted as small", r.status_code == 200 and r.get_json().get("total", 0) >= 1
       and noted(f"auditor3{i}") == 1, f"{r.status_code} {str(r.get_json())[:120]} noted={noted(f'auditor3{i}')}")
who["user"] = "auditor39"
r = trace_file(b"%PDF-1.7 made-up, no readable lines\n", "report.pdf")
ok("…a PDF (matched as the exact file only, so no guesses) is not noted as small",
   r.status_code == 200 and noted("auditor39") == 0, f"{r.status_code} noted={noted('auditor39')}")
wd = json.load(open(watch))
ok("…the notes still hold who and when only", "198.18.37" not in open(watch).read() and "filler" not in open(watch).read())
import system_alerts as SA  # noqa: E402
import time as _clock  # noqa: E402
now = _clock.time()
json.dump({"mallory": [round(now) - i for i in range(I.SMALL_TRACE_ALERT)], "old": [round(now) - 90000] * 50,
           "few": [round(now)] * (I.SMALL_TRACE_ALERT - 1)}, open(watch, "w"))
alerts = SA.Alerts(base)._small_traces(now)
ok(f"{I.SMALL_TRACE_ALERT} small traces by one person in 24 hours: an alert in the bell, linking to Audit",
   len(alerts) == 1 and alerts[0]["title"].startswith(__import__("people").person_label("mallory") + " ran ")
   and "mallory" not in alerts[0]["title"] and alerts[0]["link"] == "/audit" and alerts[0]["problem"], str(alerts))
ok("…older than 24 hours or fewer than the limit: no alert", not any(a["title"].startswith(("old ", "few ")) for a in alerts))
ok("…the alert says nothing of what was traced", "203.0.113" not in json.dumps(alerts))
json.dump({"mallory": [round(now) - i for i in range(2 * I.SMALL_TRACE_ALERT)]}, open(watch, "w"))
a2 = SA.Alerts(base)._small_traces(now)
ok("…a new alert (a new key) at each further limit", a2 and a2[0]["key"] != alerts[0]["key"], str([a["key"] for a in a2]))
os.remove(watch)
who["user"], who["perms"] = "external1", {"view"}
n_seals, n_audit = sum(1 for _ in open(seals)), len(audit)
codes = [rec(text=f"line {i} 192.0.2.{i % 250}", kind="text").status_code for i in range(32)]
ok("copies recorded: at most 30 a minute per person, the rest refused (429)", codes[:30] == [200] * 30 and codes[30:] == [429, 429], str(codes[28:]))
ok("…a refused one writes no seal and no audit entry", sum(1 for _ in open(seals)) == n_seals + 30 and len(audit) == n_audit + 30)
# one person copying the same rows many times cannot make them "common" (and so hidden from a trace)
who["user"] = "insider1"
rows = "192.0.2.201,Example Net\n192.0.2.202,Example Net\n"
for _ in range(25):
    rec(text=rows, kind="addresses")
who["user"], who["perms"] = "auditor3", {"audit"}
r = tr(text=rows).get_json()
ok("rows copied 25 times by one person are still found (common counts people, not copies)",
   any(m["user"] == "insider1" for m in r.get("matches") or []) and r.get("common_left_out") == 0, str({k: r.get(k) for k in ("total", "common_left_out")}))
old = {"id": "S-old", "t": 1.0, "user": "x", "kind": "copy", "items": ["aa"]}
api["sealer"].write(dict(old))
api["pruned"]["at"] = 0.0                                 # a day passed since the last prune
api["prune_daily"]()
import time as _t  # noqa: E402
for _ in range(50):
    if '"S-old"' not in open(seals).read():
        break
    _t.sleep(.1)
ok("seals past the retention are removed every day (not only at start)", '"S-old"' not in open(seals).read())
src = open(I.__file__, encoding="utf-8").read()
ok("a trace reads the seals one line at a time (no list of them all)", "list(self.all())" not in src)
who["perms"] = {"audit"}
who["user"] = "grace"
with app.test_request_context("/x/page"):
    _u()
    html = render_template_string("signed in as {{ lg_name }}")
ok("the header value lg_name is the registered full name", html == "signed in as Grace Mensah", html)

print("6. The pages")
held = lambda n, sub: os.path.join(S, n + ".new") if S and os.path.exists(os.path.join(S, n + ".new")) else os.path.join(HERE, sub, n)  # noqa: E731
tdir = os.path.join(HERE, "templates")
pages = [f for f in os.listdir(tdir) if f.endswith(".html") and not f.startswith("_") and f not in
         ("login.html", "enrol.html", "enrol_done.html", "forgot.html", "denied.html", "auth_base.html")]
username = [p for p in pages + ["_page_nav.html"] if "lg_user }} ({{ lg_role" in open(held(p, "templates"), encoding="utf-8").read()]
ok("no header or tooltip names the person by username (full name, lg_name)", not username, str(username))
nav = open(held("_page_nav.html", "templates"), encoding="utf-8").read()
no_copy = [p for p in pages if "lg-copy.js" not in open(held(p, "templates"), encoding="utf-8").read()
           and "_page_nav.html" not in open(held(p, "templates"), encoding="utf-8").read()]
ok("lg-copy.js on every signed-in page (the shared navigation or the page itself)", "lg-copy.js" in nav and not no_copy, str(no_copy))
jdir = os.path.join(HERE, "static", "js")
direct = []
for f in sorted(set(os.listdir(jdir)) | {n[:-4] for n in os.listdir(S) if n.endswith(".js.new")} if S else os.listdir(jdir)):
    if f.endswith(".js") and f not in ("lg-copy.js", "enrol.js"):
        src = open(held(f, "static/js"), encoding="utf-8").read()
        if re.search(r"clipboard\.writeText|execCommand\(\s*[\"']copy", src):
            direct.append(f)
ok("no page script writes to the clipboard except through LGCopy (the enrolment page aside: before sign-in)", not direct, str(direct))
said = "Everything you view, copy or export on Looking Glass is recorded under your name."
ok("the Overview says it, in the user's words: overview.html and the map's intro (the Overview of the roles that see the platforms)",
   all(said in open(held(n, "templates"), encoding="utf-8").read() for n in ("overview.html", "index.html")))
import auth  # noqa: E402
ok("every role with a fixed list of addresses may record a copy",
   all("/api/copy/" in L for L in (auth.AUDIT_PATHS, auth.ADVISORY_PATHS, auth.DEFINITIONS_PATHS, auth.MANAGEMENT_PATHS)))
import audit_portal as AP  # noqa: E402
ok("the Audit portal has a Copies tab, with every copy and every trace", ("copies", "Copies") in AP.TABS
   and AP.TAB_OF.get("copied") == "copies" and AP.TAB_OF.get("leak_traced") == "copies")

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {fails}" if fails else ""))
sys.exit(1 if fails else 0)
