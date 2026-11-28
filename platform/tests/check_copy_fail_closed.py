#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""Copying fails CLOSED (static/js/lg-copy.js, insider.py; the held copy $LG_HELD_DIR/lg-copy.js.new when there is one):
node runs LGCopy.copy on a stand-in browser and clipboard. The text reaches the clipboard only after the server has
answered that the copy is recorded ({"ok": true}); refused, failed, no connection, or an answer that is not that
confirmation (a gateway or sign-in page that says 200) copies NOTHING and says so in plain words. Recovery codes and
invite links are recorded without their text. Copying the page's text by hand is blocked outside fields people type in.
Run: .venv/bin/python tests/check_copy_fail_closed.py"""
import os
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

JS = r"""
const clip = [], asked = []; let mode = "ok", execOk = true, execd = 0;
Object.defineProperty(globalThis, "navigator", { configurable: true, value: { clipboard: { writeText: async (t) => { if (mode === "noclip") throw new Error("not allowed"); clip.push(t); } } } });
Object.defineProperty(N.prototype, "nodeType", { get() { return this.tag === "#text" ? 3 : 1; } });
document.execCommand = () => { execd++; return execOk; };
document.title = "Looking Glass · Made-up page";
const meta = document.createElement("meta"); meta.setAttribute("name", "csrf-token"); meta.content = "tok-made-up"; document.body.append(meta);
const docOn = {}; document.addEventListener = (e, f) => { (docOn[e] = docOn[e] || []).push(f); };
N.prototype.select = function () {};
const answer = (status, body, json = true) => ({ ok: status >= 200 && status < 300, status,
  json: async () => { if (!json) throw new SyntaxError("Unexpected token '<'"); return body; } });
const myFetch = async (url, o) => { asked.push({ url, method: o.method, tok: o.headers["X-CSRF-Token"], body: JSON.parse(o.body) });
  if (mode === "down") throw new TypeError("Failed to fetch");
  if (mode === "refused") return answer(403, { error: "Refused (the request did not come from this page)." });
  if (mode === "limit") return answer(429, { error: "At most 30 copies a minute: wait a moment, or download the list instead." });
  if (mode === "unrecorded") return answer(503, { error: "The copy could not be recorded, so nothing was copied." });
  if (mode === "gateway") return answer(502, null, false);
  if (mode === "html200") return answer(200, null, false);           // a sign-in or gateway page that says 200
  if (mode === "notok") return answer(200, { ok: false });
  return answer(200, { ok: true, id: "S-made-up" }); };
((fetch) => {""" + H.page_src("lg-copy.js") + r"""})(myFetch);
(async () => {
  const R = {};
  for (const m of ["ok", "refused", "limit", "unrecorded", "gateway", "html200", "notok", "down", "noclip"]) {
    mode = m; clip.length = 0; asked.length = 0; execd = 0; execOk = m !== "noclip";
    const r = await LGCopy.copy({ text: "192.0.2.10\n192.0.2.11", what: "made-up addresses", kind: "addresses" });
    R[m] = { ok: r.ok, message: r.message, copied: clip.slice(), execd, asked: asked.length };
  }
  mode = "ok"; asked.length = 0; clip.length = 0;
  await LGCopy.copy({ text: "abcd-efgh", kind: "recovery" }); R.recovery = { sent: asked[0].body, copied: clip.slice() };
  R.first = (await (async () => { asked.length = 0; await LGCopy.copy({ text: "x", kind: "text", what: "w" }); return asked[0]; })());
  asked.length = 0; R.empty = await LGCopy.copy({ text: "   " }); R.emptyAsked = asked.length;
  // copying by hand: blocked outside fields people type in
  let prevented = 0; const ev = (target) => ({ target, preventDefault() { prevented++; } });
  const p = document.createElement("p"); document.body.append(p); const inp = document.createElement("input"); document.body.append(inp);
  for (const f of docOn.copy || []) f(ev(p)); R.blocked = prevented;
  document.activeElement = null; prevented = 0; for (const f of docOn.copy || []) f(ev(inp)); R.field = prevented;
  console.log(JSON.stringify(R));
})().catch((e) => console.log(JSON.stringify({ fatal: String(e && e.stack) })));
"""
R, raw = H.run(JS)
R = R or {}
ok("lg-copy.js runs", R and "fatal" not in R, str(R.get("fatal")) if R else raw[-400:])
o = R.get("ok") or {}
ok("recorded ({ok: true}): copied, and it says so", o.get("ok") is True and o.get("copied") == ["192.0.2.10\n192.0.2.11"]
   and o.get("message") == "Copied (recorded under your name)", o)
f = R.get("first") or {}
ok("...the record is asked FIRST, as a JSON POST with the CSRF token, naming the page", f.get("url") == "/api/copy/record" and f.get("method") == "POST"
   and f.get("tok") == "tok-made-up" and (f.get("body") or {}).get("page") == "Made-up page", f)
for m, words in (("refused", "Not copied: Refused (the request did not come from this page)."),
                 ("limit", "Not copied: At most 30 copies a minute: wait a moment, or download the list instead."),
                 ("unrecorded", "Not copied: The copy could not be recorded, so nothing was copied."),
                 ("gateway", "Not copied: the copy could not be recorded"),
                 ("html200", "Not copied: the copy could not be recorded"),
                 ("notok", "Not copied: the copy could not be recorded"),
                 ("down", "Not copied: the copy could not be recorded (no connection).")):
    x = R.get(m) or {}
    ok(f"{m}: nothing copied, and it says so in plain words", x.get("ok") is False and x.get("copied") == [] and x.get("execd") == 0
       and x.get("message") == words, x)
x = R.get("noclip") or {}
ok("recorded, but the browser refuses both ways of copying: it says so (never 'Copied')", x.get("ok") is False
   and x.get("message") == "Recorded, but the browser refused to copy.", x)
rc = R.get("recovery") or {}
ok("recovery codes: recorded without their text, then copied", "text" not in (rc.get("sent") or {"text": 1}) and rc.get("copied") == ["abcd-efgh"], rc)
ok("nothing to copy: nothing asked, nothing copied", (R.get("empty") or {}).get("ok") is False and R.get("emptyAsked") == 0, R.get("empty"))
ok("copying the page's text by hand is blocked", R.get("blocked") == 1, R.get("blocked"))
ok("...but not in a field people type in", R.get("field") == 0, R.get("field"))

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
