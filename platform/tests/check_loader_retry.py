#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""Looking Glass could not be reached (static/js/loader.js, on every page; the held copy $LG_HELD_DIR/loader.js.new when
there is one): node runs loader.js's own fetch wrapper and LGLoader.errorText on a stand-in network. A READ (GET, HEAD)
that gets no answer, or a gateway page instead of Looking Glass's JSON, is tried again on its own after 2, 4, 8 and 15
seconds, saying so in plain words (a line at the foot of the page, or the caller's lgWait), and after the last try the
line offers Retry and the error reads in plain words. An ACTION (POST, PUT, PATCH, DELETE, in any case, also as a
Request) is sent exactly once: never again on its own, and its error says it may not have been done.
Run: .venv/bin/python tests/check_loader_retry.py"""
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import page_harness as H  # noqa: E402

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{str(info)[:500]}]" if info and not cond else ""))


if not H.NODE:
    print("SKIPPED: no node to run the page with"); sys.exit(77)

src = H.page_src("loader.js")
wrap = re.search(r"^  const nativeFetch = .*?^  \};\n", src, re.M | re.S)                  # the fetch wrapper, whole
err = re.search(r"^    errorText\(e, action\) \{.*?^    \},\n", src, re.M | re.S)
not_done = re.search(r"^    NOT_DONE: (\".*?\"),\n", src, re.M)
ok("loader.js has its fetch wrapper and errorText", bool(wrap and err and not_done))
if not (wrap and err and not_done):
    print(f"\n{checks - len(fails)}/{checks} checks passed; FAILED: {', '.join(fails)}"); sys.exit(1)

JS = r"""
const C = JSON.parse(process.argv[1]);
let waits = []; globalThis.setTimeout = (f, ms) => { waits.push(ms); return setImmediate(f); };
location.reload = () => {};
let calls = 0, plan = [];
const resp = (status, ct) => ({ ok: status < 400, status, headers: { get: (k) => (/content-type/i.test(k) ? ct : null) }, clone() { return this; }, json: async () => ({}) });
window.fetch = async (input, init) => { calls++; const step = plan.length ? plan.shift() : "ok";
  if (step === "net") throw new TypeError("Failed to fetch");
  if (step === "gw") return resp(502, "text/html");
  if (step === "gwjson") return resp(503, "application/json");
  if (step === "404") return resp(404, "application/json");
  return resp(200, "application/json"); };
""" + wrap.group(0) + r"""
window.LGLoader = { NOT_DONE: """ + not_done.group(1) + r""",
""" + err.group(0) + r"""};
const bar = () => document.body.querySelector(".lg-net-bar");
async function one(c) {
  calls = 0; waits = []; plan = c.plan.slice(); const seen = []; let barText = null;
  const init = { method: c.method, lgRetry: c.lgRetry, lgWait: c.lgWait ? (t) => seen.push(t) : undefined };
  if (!c.method) delete init.method; if (c.lgRetry === undefined) delete init.lgRetry; if (!c.lgWait) delete init.lgWait;
  const input = c.request ? new Request("http://localhost/api/made-up", { method: c.request }) : "/api/made-up";
  let status = null, error = null, words = null;
  const p = window.fetch(input, init).then((r) => { status = r.status; }, (e) => { error = String(e.message); words = window.LGLoader.errorText(e, c.action); });
  // the foot line while it waits (read between the tries)
  for (let i = 0; i < 50 && status === null && error === null; i++) { await new Promise((r) => setImmediate(r)); if (bar() && barText === null) barText = lines(bar()); }
  await p;
  return { calls, waits, status, error, words, seen, barText, barAfter: bar() ? lines(bar()) : null };
}
(async () => { const out = {}; for (const [k, c] of Object.entries(C)) { if (bar()) bar().remove(); out[k] = await one(c); } console.log(JSON.stringify(out)); })()
  .catch((e) => console.log(JSON.stringify({ fatal: String(e && e.stack) })));
"""
N4 = ["net"] * 4
CASES = {
    "get_back": {"plan": N4, "method": "GET"},
    "get_lost": {"plan": ["net"] * 9, "method": "GET"},
    "head_back": {"plan": ["net", "net"], "method": "HEAD"},
    "plain_back": {"plan": ["net"]},                              # no method given: a read
    "gateway": {"plan": ["gw", "gw"]},
    "gateway_json": {"plan": ["gwjson"]},                          # Looking Glass's own answer: not a gateway page
    "refused": {"plan": ["404"]},
    "no_retry": {"plan": ["net"], "lgRetry": False},
    "own_words": {"plan": ["net", "net"], "lgWait": True},
    "post": {"plan": ["net", "net"], "method": "POST", "action": True},
    "put": {"plan": ["net"], "method": "PUT", "action": True},
    "patch": {"plan": ["net"], "method": "PATCH", "action": True},
    "delete": {"plan": ["net"], "method": "DELETE", "action": True},
    "post_lower": {"plan": ["net"], "method": "post", "action": True},
    "post_request": {"plan": ["net"], "request": "POST", "action": True},
    "post_gateway": {"plan": ["gw", "gw"], "method": "POST", "action": True},
}
R, raw = H.run(JS, CASES)
R = R or {}
ok("the wrapper runs", R and "fatal" not in R, str(R.get("fatal")) if R else raw[-400:])
UNREACH = "Looking Glass could not be reached just now (it may be restarting)."
WAITING = f"{UNREACH} Trying again…"
NOT_DONE = eval(not_done.group(1))     # noqa: S307 - the page's own string literal, read back as the same text

print("A read is tried again on its own")
g = R.get("get_back") or {}
ok("a GET that gets no answer four times: tried again after 2, 4, 8 and 15 s, then it answers", g.get("waits") == [2000, 4000, 8000, 15000]
   and g.get("calls") == 5 and g.get("status") == 200, g)
ok("...saying so in plain words at the foot of the page meanwhile", g.get("barText") == [WAITING], g.get("barText"))
ok("...and the line goes once it answers", g.get("barAfter") is None, g.get("barAfter"))
g = R.get("get_lost") or {}
ok("no answer at all: five tries, then an error in plain words (never the browser's 'Failed to fetch')", g.get("calls") == 5
   and g.get("waits") == [2000, 4000, 8000, 15000] and g.get("error") == UNREACH and g.get("words") == UNREACH, g)
ok("...and the line at the foot of the page offers Retry", g.get("barAfter") == [UNREACH, "Retry"], g.get("barAfter"))
ok("HEAD is a read too", (R.get("head_back") or {}).get("calls") == 3 and (R.get("head_back") or {}).get("status") == 200, R.get("head_back"))
ok("no method given is a GET", (R.get("plain_back") or {}).get("calls") == 2 and (R.get("plain_back") or {}).get("waits") == [2000], R.get("plain_back"))
ok("a gateway page (502, not JSON) is tried again", (R.get("gateway") or {}).get("calls") == 3 and (R.get("gateway") or {}).get("status") == 200,
   R.get("gateway"))
ok("Looking Glass's own 503 (JSON) is its answer: not sent again", (R.get("gateway_json") or {}).get("calls") == 1
   and (R.get("gateway_json") or {}).get("status") == 503, R.get("gateway_json"))
ok("a refusal (404) is an answer: not sent again", (R.get("refused") or {}).get("calls") == 1, R.get("refused"))
ok("lgRetry: false: sent once", (R.get("no_retry") or {}).get("calls") == 1 and (R.get("no_retry") or {}).get("words") == UNREACH, R.get("no_retry"))
w = R.get("own_words") or {}
ok("lgWait: the caller says it in its own place (the words given), not the foot line", w.get("seen") == [WAITING, WAITING]
   and w.get("barText") is None and w.get("status") == 200, w)

print("An action is sent once, never again on its own")
for k, label in (("post", "POST"), ("put", "PUT"), ("patch", "PATCH"), ("delete", "DELETE"), ("post_lower", "post (lower case)"),
                 ("post_request", "a POST Request")):
    a = R.get(k) or {}
    ok(f"{label} that gets no answer: sent once, no waiting", a.get("calls") == 1 and a.get("waits") == [], a)
    ok("...and its words say it may not have been done", a.get("words") == NOT_DONE, a.get("words"))
a = R.get("post_gateway") or {}
ok("a POST answered by a gateway page: sent once, the answer handed back", a.get("calls") == 1 and a.get("status") == 502 and a.get("waits") == [], a)

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
