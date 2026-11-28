#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""The Executive page's ring charts (static/js/management.js donut, the held copy when there is one) RUN under node,
on a small stand-in for the page (2026-11-26: the Sectors card showed 7 sectors and "Other" of the services
platform's 11, and a sector with 4 of 43,281 events read "0%"). Proved by running it:

  1. the legend names EVERY part (all 11 sectors), each with its own name, never hidden in "Other";
  2. a part that has records never reads "0%", part of the whole never "100%";
  3. the ring draws the 7 biggest apart and the rest as one "Other" slice, and the legend's colours match: the first
     7 their slices' colours, the rest the grey of "Other";
  4. clicking a part filters by it (each legend button with a value is a working control).

Skips (77) where node is not installed. Run: .venv/bin/python tests/check_mgmt_charts.py"""
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
js_path = os.path.join(held, "management.js.new") if held and os.path.isfile(os.path.join(held, "management.js.new")) \
    else os.path.join(PF, "static", "js", "management.js")
src = open(js_path, encoding="utf-8").read()


def line_of(start):
    m = re.search(r"^  " + re.escape(start) + r".*$", src, re.M)
    return m.group(0) if m else ""


m = re.search(r"^  function donut\(.*?^  \}\n", src, re.M | re.S)
ok(f"the page's donut() is found ({os.path.basename(js_path)})", bool(m))
if not m:
    sys.exit(1)
pieces = "\n".join(line_of(x) for x in ("const pct = ", "const share = ", "const SEV_COLOURS = ", "const PALETTE = ")) + "\n" + m.group(0)
# the platform's one share rule (window.LGShare, loader.js; the held copy when there is one): the page uses it
ld_path = os.path.join(held, "loader.js.new") if held and os.path.isfile(os.path.join(held, "loader.js.new")) \
    else os.path.join(PF, "static", "js", "loader.js")
ld_src = open(ld_path, encoding="utf-8").read()
# LGShare with the helpers just above it (from the comment that introduces it), in a block of its own
lm = re.search(r"^  // Shares and cut lists.*?^  window\.LGShare = \{.*?^  \};", ld_src, re.M | re.S) \
    or re.search(r"^  window\.LGShare = \{.*?^  \};", ld_src, re.M | re.S)
ok(f"window.LGShare is found ({os.path.basename(ld_path)})", bool(lm))
LGSHARE = "globalThis.window = globalThis.window || {};\n{\n" + (lm.group(0) if lm else "") + "\n}\n"

HARNESS = r"""
class E { constructor(tag, cls, text) { this.tag = tag; this.className = cls || ""; this.textContent = text == null ? "" : String(text);
    this.children = []; this.style = { setProperty() {} }; this.attrs = {}; this.on = {}; this.disabled = false; this.title = "";
    this.classList = { add: (c) => { this.className += " " + c; }, toggle() {} }; }
  append(...k) { for (const c of k) this.children.push(typeof c === "string" ? new E("#text", "", c) : c); }
  replaceChildren(...k) { this.children = []; this.append(...k); }
  querySelector(sel) { return this.children.find((c) => c.tag === sel); }
  addEventListener(ev, f) { this.on[ev] = f; } setAttribute(k, v) { this.attrs[k] = v; } }
const el = (tag, cls, text) => new E(tag, cls, text);
const sv = (tag, attrs) => { const e = new E(tag); Object.assign(e.attrs, attrs || {}); if (attrs && attrs.class) e.className = attrs.class; return e; };
const fmt = (n) => String(n), empty = (box) => { box.empty = true; };
const state = { plat: "comms", filters: { comms: {} } }; const filtered = [];
const setFilter = (k, v) => filtered.push([k, v]);
""" + LGSHARE + pieces + r"""
const rows = JSON.parse(process.argv[1]), total = process.argv[2] ? Number(process.argv[2]) : undefined;
const box = new E("div"); donut(box, rows, "sector", "events", total);
const svg = box.children[0], legend = box.children[1];
const slices = svg.children.filter((c) => c.tag === "path");
const texts = svg.children.filter((c) => c.tag === "text").map((t) => t.textContent);
const items = legend.children.map((li) => { const b = li.children[0];
  return { label: b.children[1].textContent, share: b.children[2].textContent, colour: b.children[0].style.background, title: b.title,
           click: !!b.on.click, disabled: b.disabled }; });
if (items[2] && legend.children[2].children[0].on.click) legend.children[2].children[0].on.click();
console.log(JSON.stringify({ slices: slices.map((s) => s.attrs.fill), slice_titles: slices.map((s) => (s.children[0] || {}).textContent),
  items, filtered, texts, aria: svg.attrs["aria-label"] }));
"""

rows = [{"label": n, "value": v, "count": c} for n, v, c in (
    ("Telco / ISP", "isp", 31323), ("University / research", "education", 2760), ("Cloud / CDN", "cloud", 1133),
    ("Government", "government", 654), ("Hosting", "hosting", 538), ("Bank", "bank", 277), ("Enterprise", "enterprise", 154),
    ("Exchange (IXP)", "ixp", 37), ("Finance / insurance", "finance", 19), ("Unknown", "unknown", 2), ("Data centre", "datacentre", 1))]
r = subprocess.run([node, "-e", HARNESS, json.dumps(rows)], capture_output=True, text=True, timeout=30)
try:
    out = json.loads(r.stdout)
except ValueError:
    ok("the chart runs", False, (r.stdout + r.stderr)[:600])
    sys.exit(1)
items = out["items"]
ok("1. the legend names every sector (11 of 11), each by its own name",
   [i["label"] for i in items] == [x["label"] for x in rows], [i["label"] for i in items])
ok("…and none of them is called 'Other' (nothing hidden in a group)", all(i["label"] != "Other" for i in items))
zero = [i for i, x in zip(items, rows) if x["count"] and i["share"] == "0%"]
ok("2. a sector with records never reads '0%' (Data centre: 1 of 36,898 reads '<1%')", not zero and items[-1]["share"] == "<1%", zero or items[-1])
ok("…and the biggest part of the whole never reads '100%'", items[0]["share"] != "100%", items[0])
ok("…the exact figure is on each part (its title)", items[-1]["title"].startswith("Data centre: 1 events"), items[-1]["title"])
ok("3. the ring: the 7 biggest apart, the rest as one 'Other' slice (8 slices)", len(out["slices"]) == 8, out["slices"])
ok("…the legend's colours match the ring: the first 7 as their slices, the rest the grey of 'Other'",
   [i["colour"] for i in items[:7]] == out["slices"][:7] and all(i["colour"] == "#3a3f4d" for i in items[7:])
   and out["slices"][7] == "#3a3f4d", ([i["colour"] for i in items], out["slices"]))
ok("4. each part is a working control: clicking one filters by it", all(i["click"] and not i["disabled"] for i in items)
   and out["filtered"] == [["sector", "cloud"]], out["filtered"])
r2 = subprocess.run([node, "-e", HARNESS, json.dumps(rows[:3])], capture_output=True, text=True, timeout=30)
few = json.loads(r2.stdout)
ok("…with 3 parts: 3 slices, 3 names, no 'Other'", len(few["slices"]) == 3 and [i["label"] for i in few["items"]] == [x["label"] for x in rows[:3]])
ok("…the screen-reader name lists every sector with its share (Data centre '<1%'), never only 7 and 'Other'",
   all(x["label"] in out["aria"] for x in rows) and "Data centre <1%" in out["aria"] and "0%" not in out["aria"].replace("<1%", ""), out["aria"])

# 5. the real total (2026-11-26): the selection has 43,281 events, the rows sent hold 36,898
sent = sum(x["count"] for x in rows)
r3 = subprocess.run([node, "-e", HARNESS, json.dumps(rows), "43281"], capture_output=True, text=True, timeout=30)
tot = json.loads(r3.stdout) if r3.returncode == 0 else {}
ok("5. given the selection's total: the centre reads 43,281 events, not the 36,898 of the rows sent",
   tot.get("texts", [""])[0] == "43281" and "36898" not in tot.get("texts", []), tot.get("texts") or (r3.stdout + r3.stderr)[:300])
last = (tot.get("items") or [{}])[-1]
ok("…what the rows leave out (6,383 events) is an 'Other' line in the legend, its share of the total (15%)",
   last.get("label") == "Other" and last.get("share") == "15%" and last.get("disabled") is True and str(43281 - sent) in last.get("title", ""), last)
ok("…every hover share is of the total, with one decimal, never '0.0%' (Data centre: '<0.1%')",
   any(i["label"] == "Data centre" and "(<0.1%)" in i["title"] for i in tot.get("items", [])) and not any("(0.0%)" in t for t in tot.get("slice_titles", []) + [i["title"] for i in tot.get("items", [])]),
   [i["title"] for i in tot.get("items", [])][-3:])

print()
print(f"{passed}/{passed + failed} checks passed" + (f"; {failed} FAILED" if failed else ""))
sys.exit(1 if failed else 0)
