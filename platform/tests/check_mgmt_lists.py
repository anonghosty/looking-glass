#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""The Executive page's capped lists and shares RUN under node (static/js/management.js, the held copy when there is
one), on a small stand-in for the page, with made-up rows (2026-11-26: every capped card read as complete, and a
share of a part with records read "0%"). Proved by running the page's own functions:

  1. bars(): a card that shows 8 of 23 networks says "Top 8 of 23 networks shown."; one that shows every row says
     nothing; the hover share of 1 of 43,281 reads "<0.1%", never "0.0%";
  2. ranking(): the top list shows 12 and says "Top 12 of 40 infections shown." (the services platform: its issues
     and the hosts' infections together);
  3. regionTree(): a region with 9 cities, 4 listed, says "and 5 more cities";
  4. hero(): a share is text from LGShare ("<1%" for 1 device of 2,000), never a rounded "0";
  5. the "Explain all" names are exactly the rows the list shows (12, never 25 explained and 12 opened).

Skips (77) where node is not installed. Run: .venv/bin/python tests/check_mgmt_lists.py"""
import glob
import json
import os
import re
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PF = os.path.dirname(HERE)
passed = failed = 0


def ok(name, cond, detail=""):
    global passed, failed
    if cond:
        passed += 1
        print(f"  ok   {name}")
    else:
        failed += 1
        print(f"  FAIL {name}" + (f": {str(detail)[:500]}" if detail else ""))


node = os.environ.get("LG_NODE") or shutil.which("node") or next(iter(sorted(glob.glob(os.path.expanduser("~/lg-node/*/bin/node")))), None)
if not node:
    print("SKIPPED: node is not installed here (CI runs this check)")
    sys.exit(77)
held = os.environ.get("LG_HELD_DIR", "")
pick = lambda name, sub: (os.path.join(held, name + ".new") if held and os.path.isfile(os.path.join(held, name + ".new"))
                          else os.path.join(PF, "static", sub, name))
js_path, ld_path = pick("management.js", "js"), pick("loader.js", "js")
src = open(js_path, encoding="utf-8").read()
ld_src = open(ld_path, encoding="utf-8").read()
# LGShare with the helpers just above it (from the comment that introduces it), in a block of its own
lm = re.search(r"^  // Shares and cut lists.*?^  window\.LGShare = \{.*?^  \};", ld_src, re.M | re.S) \
    or re.search(r"^  window\.LGShare = \{.*?^  \};", ld_src, re.M | re.S)


def fn(name):
    m = re.search(r"^  function " + name + r"\(.*?^  \}\n", src, re.M | re.S)
    return m.group(0) if m else f"function {name}() {{ throw new Error('{name} is not on the page'); }}\n"


def const(name):
    """The page's `const name = ...;` whole: up to the first line end where its brackets are balanced."""
    m = re.search(r"^  const " + re.escape(name) + r" = ", src, re.M)
    if not m:
        return ""
    depth, i = 0, m.start()
    while i < len(src):
        ch = src[i]
        depth += ch in "({[" and 1 or ch in ")}]" and -1 or 0
        if ch == "\n" and depth == 0 and src[i - 1] == ";":
            return src[m.start():i + 1]
        i += 1
    return ""


print(f"The Executive page's lists ({os.path.basename(js_path)}, {os.path.basename(ld_path)})")
ok("window.LGShare is found", bool(lm))
pieces = "".join(const(n) for n in ("pct", "cutNote", "RANK_N", "rankRows", "rankTotal")) + "".join(fn(n) for n in ("bars", "ranking", "regionTree", "hero"))

HARNESS = r"""
globalThis.window = {};
class E { constructor(tag, cls, text) { this.tag = tag; this.className = cls || ""; this.textContent = text == null ? "" : String(text);
    this.children = []; this.style = {}; this.attrs = {}; this.on = {}; this.disabled = false; this.title = "";
    this.classList = { add: (c) => { this.className += " " + c; }, toggle() {} }; this.dataset = {}; }
  append(...k) { for (const c of k) this.children.push(typeof c === "string" ? new E("#text", "", c) : c); }
  replaceChildren(...k) { this.children = []; this.append(...k); }
  addEventListener(ev, f) { this.on[ev] = f; } setAttribute(k, v) { this.attrs[k] = v; } }
const el = (tag, cls, text) => new E(tag, cls, text);
const fmt = (n) => Number(n || 0).toLocaleString("en-US"), empty = (box) => { box.empty = true; };
const requestAnimationFrame = () => {}, countUp = (b, v) => { b.textContent = fmt(v); };
const state = { plat: "comms", data: { baseline: null }, filters: { comms: {}, services: {} }, open: { comms: new Set(), services: new Set() },
  explained: { comms: {}, services: {} } };
const setFilter = () => {}, card = () => new E("div");
const all = (e) => [e.textContent, ...e.children.flatMap(all)];
{
""" + (lm.group(0) if lm else "") + "\n}\n" + pieces + r"""
const out = {};
const nets = Array.from({ length: 12 }, (_, i) => ({ label: `Network ${i}`, value: `n${i}`, hosts: 300 - i, count: 500 - i, share: i === 11 ? 1 / 43281 : 0.01 }));
let box = new E("div"); bars(box, nets, { key: "network", total: 23, noun: "networks" });
out.bars = { cut: box.children.filter((c) => c.className === "mg-cut").map((c) => c.textContent), n: box.children.filter((c) => c.tag === "button").length };
box = new E("div"); bars(box, nets.slice(0, 5), { key: "network", total: 5, noun: "networks" });
out.bars_all = box.children.filter((c) => c.className === "mg-cut").length;
box = new E("div"); bars(box, nets, { key: "network", n: 12, total: 23, noun: "networks" });
out.bars_title = box.children.filter((c) => c.tag === "button").map((b) => b.title)[11];
const infs = Array.from({ length: 15 }, (_, i) => ({ value: `bot${i}`, title: `Bot ${i}`, hosts: 100 - i, count: 200 - i }));
box = new E("div"); ranking(box, infs, "comms", 40);
out.rank = { items: box.children.filter((c) => c.className === "mg-rank-item").length, cut: box.children.filter((c) => c.className === "mg-cut").map((c) => c.textContent) };
const svc = { platform: "services", issues: Array.from({ length: 25 }, (_, i) => ({ value: `CVE-2099-${1000 + i}`, hosts: 50 - i, count: 60, exploited: false })),
  infections_on: [{ value: "examplebot", hosts: 49.5, infection: true }], totals: { issues: 33, infections_on: 1 } };
state.plat = "services";
box = new E("div"); ranking(box, rankRows(svc), "services", rankTotal(svc));
out.rank_svc = box.children.filter((c) => c.className === "mg-cut").map((c) => c.textContent);
out.explain = rankRows(svc).slice(0, RANK_N).filter((r) => !r.infection).map((r) => r.value);
state.plat = "comms";
const d = { platform: "comms", regions: [{ value: "Greater Accra", label: "Greater Accra", hosts: 40, count: 60 }],
  region_details: { "Greater Accra": { city_devices: [["Accra", 30], ["Tema", 8], ["Madina", 5], ["Kasoa", 4], ["Ashaiman", 3], ["Dodowa", 2]], city_devices_total: 9 } } };
box = new E("div"); regionTree(box, d);
out.tree = all(box).filter((t) => /more cit/.test(t));
box = new E("div"); hero(box, [[2000, "devices"], [pct(1 / 2000), "of the devices"]]);
out.hero = box.children.map((c) => c.children[0].textContent);
console.log(JSON.stringify(out));
"""
r = subprocess.run([node, "-e", HARNESS], capture_output=True, text=True, timeout=30)
try:
    out = json.loads(r.stdout)
except ValueError:
    ok("the page's functions run", False, (r.stdout + r.stderr)[:800])
    print(f"\n{passed}/{passed + failed} checks passed; {failed} FAILED")
    sys.exit(1)
ok("1. bars(): 8 of 23 networks drawn, and it says 'Top 8 of 23 networks shown.'", out["bars"] == {"cut": ["Top 8 of 23 networks shown."], "n": 8}, out["bars"])
ok("…a card that shows every row says nothing", out["bars_all"] == 0, out["bars_all"])
ok("…the hover share of 1 of 43,281 reads '<0.1%', never '0.0%'", "(<0.1% of the events)" in (out["bars_title"] or ""), out["bars_title"])
ok("2. ranking(): 12 shown, 'Top 12 of 40 infections shown.'", out["rank"]["items"] == 12 and len(out["rank"]["cut"]) == 1
   and out["rank"]["cut"][0].startswith("Top 12 of 40 infections shown."), out["rank"])
ok("…services: the issues and the hosts' infections together, 'Top 12 of 34 issues and infections shown.'",
   len(out["rank_svc"]) == 1 and out["rank_svc"][0].startswith("Top 12 of 34 issues and infections shown."), out["rank_svc"])
ok("3. regionTree(): 9 cities, 4 listed: 'and 5 more cities'", out["tree"] == ["and 5 more cities"], out["tree"])
ok("4. hero(): a share is LGShare text, 1 device of 2,000 reads '<1%'", out["hero"] == ["2,000", "<1%"], out["hero"])
ok("5. Explain all: exactly the issues the list shows (11 issues; the 12th row, the hosts' infection, explains under its row)",
   len(out["explain"]) == 11 and "examplebot" not in out["explain"], out["explain"])

print()
print(f"{passed}/{passed + failed} checks passed" + (f"; {failed} FAILED" if failed else ""))
sys.exit(1 if failed else 0)
