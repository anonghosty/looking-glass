#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""Three leftovers of the 2026-11-27 whole-codebase audit, each kept fixed:
  3-13  shares.part(n, total): the one way a count's share is worded in the combination tables (combos.py) and PDFs
        (combo_pdf.py); the same words as before for normal values, never "0%" for a part with records, never "100%"
        for a part of the whole, and "0%" (not "100%" or "300%") for a total of 0, as LGShare.of says on the pages
  3-8   beacon-handover.js: a viewer who does not get the exact days (beacon_findings.py sends "days": [] and
        "day_count") reads ", on N day(s)"; a browser script with no JavaScript engine in the suite, so the check reads
        the held copy ($LG_HELD_DIR/beacon-handover.js.new when it is there, else static/js/beacon-handover.js)
  4-11  db_connect.py: a MONGO_PORT that is not a port gives a reason (db_connect.Refused), not a traceback; the
        platform's and the pipeline's db_connect.py stay byte-identical (the pipeline's copy: $LG_PIPELINE_DIR, else
        $LG_HELD_DIR/pipe_new, else ../database or ../shadowserver next to the platform)
LG_FIX_B15_ROOT points the Python checks at another copy of the platform (the old code, to see them fail).
No database, no live file, nothing outside this computer. Run: .venv/bin/python tests/check_fix_b15.py"""
import os
import re
import sys

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ROOT = os.path.abspath(os.environ.get("LG_FIX_B15_ROOT") or HERE)
HELD = os.environ.get("LG_HELD_DIR", "")
sys.path.insert(0, ROOT)
os.environ.setdefault("MAPBOX_TOKEN", "dummy-map-key-for-checks")

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{str(info)[:400]}]" if info and not cond else ""), flush=True)


def read(p):
    try:
        with open(p, "rb") as f:
            return f.read()
    except OSError:
        return None


def old_rule(n, total):
    """The words combos._share / combo_pdf._share gave before (audited copy), for a total above 0."""
    import shares
    return ("0%" if not n else "<0.1%" if n < .001 * total else shares.of(n, total, 1) if n < .1 * total
            else shares.of(n, total))


print("3-13 one way to word a share (shares.part)")
import shares  # noqa: E402

part = getattr(shares, "part", None)
ok("shares.part(n, total) exists", callable(part))
try:
    import combo_pdf  # noqa: E402
    import combos  # noqa: E402
    ok("combos.py words its shares with shares.part", getattr(combos, "_share", None) is part and part is not None,
       getattr(combos, "_share", None))
    ok("combo_pdf.py words its shares with shares.part", getattr(combo_pdf, "_share", None) is part and part is not None,
       getattr(combo_pdf, "_share", None))
except Exception as e:  # noqa: BLE001
    ok("combos.py / combo_pdf.py import", False, f"{type(e).__name__}: {e}")
if part:
    normal = [(5, 100), (1, 43281), (995, 1000), (999, 1000), (9, 9), (0, 9), (50, 100), (1, 1000), (99, 1000),
              (1, 3), (2, 3), (37, 412), (12, 4012), (4000, 4012)]
    got = {(n, t): part(n, t) for n, t in normal}
    ok("normal values: the same words as before", all(got[k] == old_rule(*k) for k in normal),
       {k: (got[k], old_rule(*k)) for k in normal if got[k] != old_rule(*k)})
    ok("examples: 5 of 100 '5.0%', 1 of 43,281 '<0.1%', 995 of 1,000 '>99%', 50 of 100 '50%', all '100%', none '0%'",
       (got[(5, 100)], got[(1, 43281)], got[(995, 1000)], got[(50, 100)], got[(9, 9)], got[(0, 9)])
       == ("5.0%", "<0.1%", ">99%", "50%", "100%", "0%"), got)
    zero = {(n, t): part(n, t) for n, t in ((3, 0), (1, 0), (0, 0), (None, None), (5, None))}
    ok("a total of 0 reads '0%' (as LGShare.of on the pages), never '100%' or '300%'",
       all(v == "0%" for v in zero.values()), zero)
    bad = []
    for t in list(range(1, 260)) + [999, 1000, 1001, 4012, 43281, 1_000_000]:
        for n in sorted({1, 2, t // 1000, t // 100, t // 10, t // 2, t - t // 100, t - 2, t - 1}):
            if 0 < n < t:
                w = part(n, t)
                if w in ("0%", "0.0%", "100%", "100.0%") or not re.fullmatch(r"[<>]?\d+(\.\d)?%", w):
                    bad.append((n, t, w))
    ok("a part with records is never '0%', a part of the whole never '100%' (every size of total)", not bad, bad[:8])

print("3-8 the beacon finding says on how many days, without the dates")
name = "beacon-handover.js"
held = os.path.join(HELD, name + ".new") if HELD else ""
page = held if held and os.path.isfile(held) else os.path.join(ROOT, "static", "js", name)
js = (read(page) or b"").decode("utf-8", "replace")
ok(f"the page file is there ({page})", bool(js))
facts = js[max(0, js.find('"bh-facts"') - 600): js.find('"bh-facts"') + 400] if '"bh-facts"' in js else ""
ok("the facts line uses the answer's day_count", "d.day_count" in facts, facts[:300])
ok("...worded ', on N day(s)' with the page's plural()", re.search(r',\s*on \$\{plural\(d\.day_count,\s*"day"\)\}', facts)
   is not None, facts[:300])
ok("...only when the exact days are not given (an analyst still sees the dates)",
   re.search(r'd\.days[^;]*\.length\s*\?\s*` \(\$\{d\.days\.join\(", "\)\}\)`\s*:\s*d\.day_count\s*\?', facts) is not None,
   facts[:300])
bf = (read(os.path.join(ROOT, "beacon_findings.py")) or b"").decode("utf-8", "replace")
ok("beacon_findings.py sends day_count and the days only to full viewers",
   '"day_count": len(days)' in bf and '"days": days if full else []' in bf)

print("4-11 MONGO_PORT that is not a port: a reason, not a traceback")
import db_connect as D  # noqa: E402


def kw(**env):
    try:
        return D.kwargs(lambda k: env.get(k)), None
    except D.Refused as e:
        return None, f"Refused: {e}"
    except Exception as e:  # noqa: BLE001
        return None, f"TRACEBACK {type(e).__name__}: {e}"


for v in ("abc", "27017x", "-1", "1e4", "27_017", "２７０１７"):
    k, e = kw(MONGO_PORT=v)
    ok(f"MONGO_PORT={v!r}: refused with the reason", k is None and (e or "").startswith("Refused") and "MONGO_PORT" in e,
       e or k)
for v in ("0", "65536", "99999"):
    k, e = kw(MONGO_PORT=v)
    ok(f"MONGO_PORT={v}: refused, not a port (1 to 65535)", k is None and (e or "").startswith("Refused") and "1 to 65535" in e,
       e or k)
for v, want in (("", 27017), (None, 27017), ("27018", 27018), (" 27019 ", 27019), ("65535", 65535)):
    k, e = kw(MONGO_PORT=v)
    ok(f"MONGO_PORT={v!r}: port {want}", k is not None and k.get("port") == want, e or k)
try:
    d = D.describe(lambda k: {"MONGO_PORT": "abc"}.get(k))
    ok("describe() with a bad MONGO_PORT says REFUSED, no traceback", "REFUSED" in d and "MONGO_PORT" in d, d)
except Exception as e:  # noqa: BLE001
    ok("describe() with a bad MONGO_PORT says REFUSED, no traceback", False, f"{type(e).__name__}: {e}")
ok("db_connect.port_of exists", callable(getattr(D, "port_of", None)))

plat = read(os.path.join(ROOT, "db_connect.py"))
pipe_dirs = [os.environ.get("LG_PIPELINE_DIR", "")] + ([os.path.join(HELD, "pipe_new")] if HELD else []) + \
    [os.path.join(ROOT, "..", "database"), os.path.join(ROOT, "..", "shadowserver")]
pipe = next((os.path.join(p, "db_connect.py") for p in pipe_dirs if p and os.path.isfile(os.path.join(p, "db_connect.py"))), "")
ok(f"the pipeline's db_connect.py is found ({pipe or 'none'})", bool(pipe))
if pipe:
    ok("the platform's and the pipeline's db_connect.py are byte-identical", read(pipe) == plat, pipe)

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
