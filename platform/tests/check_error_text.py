#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""No page shows the browser's own error text (r90). No database needed.

1. loader.js has the one shared helper: LGLoader.errorText(e, action) keeps the server's own message and puts plain
   words in place of the browser's ("Failed to fetch", "NetworkError when attempting to fetch resource.", "Load
   failed", a JSON parse error, a gateway's status line); a read (GET, HEAD) that got no answer is tried again on its
   own after 2, 4, 8 and 15 s, then a Retry button shows; an action (POST, PUT, PATCH, DELETE) is never sent again on
   its own. The mapping is evaluated here with the loader's own regular expressions (no JavaScript engine needed).
2. No page script puts a caught error's .message (or the error itself) on the page: every catch goes through
   LGLoader.errorText. quarterly.js uses LGLoader.ask instead of a retry loop of its own.
3. Every page whose scripts use the helper loads loader.js (itself, through the shared header or the page that
   includes its card).
Run from the platform's folder: python3 tests/check_error_text.py   (LG_HELD_DIR=<folder> to check held page files)"""
import os
import re
import sys

PLAT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HELD = os.environ.get("LG_HELD_DIR", "")
JDIR, TDIR = os.path.join(PLAT, "static", "js"), os.path.join(PLAT, "templates")
checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{str(info)[:600]}]" if info and not cond else ""))


def page_files(folder, ext):
    """{name: text}: the held copy (<name>.new in LG_HELD_DIR) when there is one, else the live file."""
    out = {}
    for n in sorted(os.listdir(folder)):
        if n.endswith(ext):
            held = os.path.join(HELD, n + ".new") if HELD else ""
            out[n] = open(held if held and os.path.exists(held) else os.path.join(folder, n), encoding="utf-8").read()
    return out


JS, TPL = page_files(JDIR, ".js"), page_files(TDIR, ".html")
# a script no page or script names is not served to anyone: a leftover an update did not remove (an installation updated
# from an older release kept js/signin-look.js, dropped in r79) is not a page script
def _loaded(n):
    """Named by a template, or by another script (loader.js loads some), as js/<name> or "<name>"."""
    pat = re.compile(r"(?:js/|['\"])" + re.escape(n) + r"\b")
    return any(pat.search(t) for t in TPL.values()) or any(pat.search(t) for m, t in JS.items() if m != n)


_gone = sorted(n for n in JS if not _loaded(n))
if _gone:
    print(f"  (not loaded by any page, left out: {', '.join(_gone)})")
JS = {n: t for n, t in JS.items() if n not in _gone}
L = JS.get("loader.js", "")
UNREACH = "Looking Glass could not be reached just now (it may be restarting)."

print("1. The shared helper in loader.js")
ok("the page files were read", len(JS) > 20 and len(TPL) > 10 and L, f"{len(JS)} scripts, {len(TPL)} templates")
ok("LGLoader.errorText(e, action), lost(e), ask(url, opts, onWait) and the plain words are there",
   "errorText(e, action) {" in L and "    lost,\n" in L and "async ask(url, opts, onWait)" in L
   and f'const UNREACH = "{UNREACH}";' in L and "NOT_DONE:" in L and "Trying again…" in L)
ok("a read is tried again on its own after 2, 4, 8 and 15 s, then the line offers Retry",
   "const WAITS = [2000, 4000, 8000, 15000];" in L and "await sleep(WAITS[i]);" in L and 'b.textContent = "Retry";' in L
   and "netLine(UNREACH, true)" in L)
ok("…only a read (GET or HEAD): an action is never sent again on its own",
   'const again = (method === "GET" || method === "HEAD") && opts.lgRetry !== false;' in L
   and "if (!again || !lost(e) || opts.signal?.aborted) throw e;" in L)
ok("…a gateway page instead of Looking Glass's answer (502, 503, 504, not JSON) is tried again too",
   "[502, 503, 504].includes(r.status)" in L)
ok("the session-ended redirect (401) is kept", "r.status === 401 && !leaving" in L)
ok("downloads keep their one extra try, but not after a read already tried 2, 4, 8, 15 s",
   "attempt < 2" in L and "e.lgTried" in L)


def js_regex(name):
    """a regular-expression literal of loader.js (const NAME = /…/flags;) as a Python pattern"""
    m = re.search(r"const " + name + r" = /(.+?)/([a-z]*);\n", L)
    if not m:
        return None
    return re.compile(m.group(1), re.I if "i" in m.group(2) else 0)


NET_RE, JSON_RE, GATEWAY_RE = js_regex("NET_RE"), js_regex("JSON_RE"), js_regex("GATEWAY_RE")
ok("the loader's patterns for the browser's words were read", NET_RE and JSON_RE and GATEWAY_RE)
NOT_DONE = (re.search(r'NOT_DONE: "([^"]+)"', L) or [None, ""])[1]
ok("an action's words say it may not have been done and never that it is being tried again",
   "may not have been done" in NOT_DONE and "Trying again" not in NOT_DONE, NOT_DONE)
# errorText as written in loader.js, step by step (the test fails when the JavaScript changes shape)
body = L[L.find("errorText(e, action) {"):L.find("async ask(url")]
ok("errorText: no usable answer gives the plain words (UNREACHABLE for a read, NOT_DONE for an action)",
   "if (lost(e)) return action ? window.LGLoader.NOT_DONE : UNREACH;" in body)
ok("errorText: the server's own message (an Error the page made from its JSON) is kept; a script fault gets plain words",
   'const own = typeof e === "string" || !!e && (!e.name || e.name === "Error");' in body and "if (own && m) return m;" in body
   and not re.search(r"return [^;]*\be\.message", body))
lost_src = L[L.find("function lost(e) {"):L.find("const sleep")]
ok("lost(): flagged, SyntaxError (not JSON), TimeoutError, or the browser's words",
   'e.unreachable === true || e.name === "SyntaxError" || e.name === "TimeoutError"' in lost_src
   and "NET_RE.test(m) || JSON_RE.test(m) || GATEWAY_RE.test(m)" in lost_src)


def lost(name, msg, flag=False):
    return flag or name in ("SyntaxError", "TimeoutError") or any(p.search(msg) for p in (NET_RE, JSON_RE, GATEWAY_RE))


def error_text(name, msg, action=False):
    if lost(name, msg):
        return NOT_DONE if action else UNREACH
    if (not name or name == "Error") and msg.strip():
        return msg.strip()
    return "plain words"


if NET_RE and JSON_RE and GATEWAY_RE:
    RAW = [("TypeError", "Failed to fetch"), ("TypeError", "NetworkError when attempting to fetch resource."),
           ("TypeError", "Load failed"), ("SyntaxError", "Unexpected token '<', \"<!DOCTYPE \"... is not valid JSON"),
           ("SyntaxError", "JSON.parse: unexpected character at line 1 column 1 of the JSON data"),
           ("SyntaxError", "JSON Parse error: Unrecognized token '<'"), ("SyntaxError", "Unexpected end of JSON input"),
           ("Error", "Failed to fetch"), ("Error", "Unexpected token '<', \"<html>\" is not valid JSON"), ("Error", "502 Bad Gateway")]
    for n, m in RAW:
        ok(f"a read's {n} \"{m[:46]}\" shows the plain words", error_text(n, m) == UNREACH, error_text(n, m))
    ok("…an action's \"Failed to fetch\" shows the action's words", error_text("TypeError", "Failed to fetch", True) == NOT_DONE)
    for msg in ("That name is already taken.", "The upload is not JSON.", "Refused (403)", "HTTP 500"):
        ok(f"the server's own message \"{msg}\" is kept", error_text("Error", msg) == msg and error_text("Error", msg, True) == msg)
    ok("a fault in a page's script (TypeError \"Cannot read properties of undefined\") never shows its own words",
       error_text("TypeError", "Cannot read properties of undefined (reading 'x')") == "plain words")
    ok("an empty message (HTTP/2 has no status text) gets plain words", error_text("Error", "") == "plain words")

print("\n2. No page script shows a caught error's own words")
CATCH = re.compile(r"\bcatch\s*\(\s*(\w+)\s*\)\s*\{|\.catch\(\s*(?:async\s*)?\(?\s*(\w+)\s*\)?\s*=>|\.catch\(\s*function\s*\(\s*(\w+)\s*\)")
OPEN, CLOSE = "({[", ")}]"


def block_after(src, start):
    """the text of the block or call that starts at src[start] (an opening bracket), brackets in strings counted too"""
    depth = 0
    for i in range(start, min(len(src), start + 6000)):
        c = src[i]
        if c in OPEN:
            depth += 1
        elif c in CLOSE:
            depth -= 1
            if depth == 0:
                return src[start:i + 1]
    return src[start:start + 6000]


bad = []
for n, src in JS.items():
    if n == "loader.js":
        continue
    for m in CATCH.finditer(src):
        var = m.group(1) or m.group(2) or m.group(3)
        if m.group(1):
            start = m.end() - 1                                   # the "{" of catch (e) {
        else:
            start = src.rfind("(", m.start(), m.start() + 7)       # the "(" of .catch(
        blk = block_after(src, start)
        v = re.escape(var)
        for hit in re.finditer(r"(?<![\w.])" + v + r"\.message\b|String\(\s*" + v + r"\s*\)|\$\{\s*" + v + r"\s*\}", blk):
            line_start = blk.rfind("\n", 0, hit.start()) + 1
            line = blk[line_start:blk.find("\n", hit.start()) if blk.find("\n", hit.start()) != -1 else len(blk)]
            if "console." in line:
                continue
            lineno = src.count("\n", 0, start + hit.start()) + 1
            bad.append(f"{n}:{lineno} {hit.group(0)}")
bad = sorted(set(bad))
ok("no page script puts a caught error's .message (or the error itself) on the page: LGLoader.errorText instead",
   not bad, "; ".join(bad))
# the same over every line, whatever the catch looks like: e/err/x/error.message
loose = [f"{n}:{i}" for n, src in JS.items() if n != "loader.js"
         for i, ln in enumerate(src.split("\n"), 1)
         if re.search(r"(?<![\w.])(e|err|x|error|ex)\.message\b", ln) and "console." not in ln]
ok("…and no e.message / err.message / x.message / error.message anywhere in a page script", not loose, ", ".join(loose))
users = {n for n, t in JS.items() if n != "loader.js" and re.search(r"LGLoader\.(errorText|ask|lost)\(", t)}
count = sum(len(re.findall(r"LGLoader\.errorText\(", t)) for t in JS.values())
ok("the page scripts use the helper (at least 90 places in at least 30 scripts)", count >= 90 and len(users) >= 30,
   f"{count} places in {len(users)} scripts")
Q = JS.get("quarterly.js", "")
ok("quarterly.js: LGLoader.ask and LGLoader.errorText, no retry loop of its own (one shared function)",
   "window.LGLoader.ask(" in Q and "window.LGLoader.errorText(" in Q and "WAITS" not in Q and "Trying again…" in Q
   and '"Retry"' in Q)

print("\n3. Every page whose scripts use the helper loads loader.js")


def scripts(t):
    return set(re.findall(r"js/([\w.-]+\.js)", t))


INCL = {n: set(re.findall(r"""\{%\s*(?:include|extends)\s+["']([\w.-]+\.html)["']""", t)) for n, t in TPL.items()}


def all_text(n, seen=None):
    seen = seen or set()
    if n in seen or n not in TPL:
        return ""
    seen.add(n)
    return TPL[n] + "".join(all_text(i, seen) for i in INCL.get(n, ()))


no_loader = []
for n in TPL:
    if n.startswith("_"):
        continue                                               # a card: counted in the pages that include it
    t = all_text(n)
    used = sorted(scripts(t) & users)
    if used and "js/loader.js" not in t:
        no_loader.append(f"{n} ({', '.join(used)})")
ok("every page whose scripts show errors through the helper loads loader.js", not no_loader, "; ".join(no_loader))
lone = sorted(u for u in users if not any(u in scripts(all_text(n)) for n in TPL))
ok("every script that uses the helper is on a page", not lone, lone)

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
