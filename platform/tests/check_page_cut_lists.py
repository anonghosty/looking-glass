#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""Cut lists and shares on the Audit portal, the Definitions page, the Services report window, the Task monitor, the
Connectors and Workers settings RUN under node, each page file on a small stand-in for the browser's page and made-up
data (2026-11-26: "nothing goes missing on the whole platform"). Proved by running each page:

  1. audit.js: the top 8 failure sources and exporters say "Top 8 of N" with a button to the log tab that holds every
     one; the recent privileged changes say "the newest 15 of N"; 1 failed sign-in of 43,281 reads "<0.1%", not "0.0 %";
  2. kb-settings.js: the infections table says "Showing 400 of 450" instead of stopping without a word; EPSS 0.04%
     reads "<0.1%"; another source's links are all listed, each in full;
  3. kb-services.js: the changes list, a report's products, and the window's Products, Versions (Top 12 of N), Issues
     (25 of N) and notes (5 of N) say when they are cut, and only then;
  4. kb-services-patterns.js: a field on 99.6% of the records is ">99%", on 0.04% "<0.1%";
  5. sender-audit.js: 43,280 valid of 43,281 reads ">99.9%", never "100.0 %"; 1,200 reports that did not pass read
     "1,200: the newest 300 are listed", not "300, newest 300";
  6. connectors-admin.js: the send log says "The newest 30 of 1,234 entries" and "Show all" lists every one;
  7. pipeline-settings.js: "Done by the pipeline" says "The newest 5 of 30" and "Show all" lists the rest;
  8. task-monitor.js: a user's share of the server time (a fraction from request_tracker.py) reads "<1%" / ">99%".

Each page is read from LG_HELD_DIR (<name>.new) when it holds one, else from static/js. Skips (77) without node.
Run: .venv/bin/python tests/check_page_cut_lists.py"""
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
        print(f"  FAIL {name}" + (f": {str(detail)[:600]}" if detail else ""))


node = os.environ.get("LG_NODE") or shutil.which("node") or next(iter(sorted(glob.glob(os.path.expanduser("~/lg-node/*/bin/node")))), None)
if not node:
    print("SKIPPED: node is not installed here (CI runs this check)")
    sys.exit(77)
held = os.environ.get("LG_HELD_DIR", "")


def page(name):
    p = os.path.join(held, name + ".new") if held else ""
    return p if p and os.path.isfile(p) else os.path.join(PF, "static", "js", name)


loader_src = open(page("loader.js"), encoding="utf-8").read()
# LGShare with the helpers just above it (from the comment that introduces it), in a block of its own
m = re.search(r"^  // Shares and cut lists.*?^  window\.LGShare = \{.*?^  \};", loader_src, re.M | re.S) \
    or re.search(r"^  window\.LGShare = \{.*?^  \};", loader_src, re.M | re.S)
LGSHARE = "{\n" + m.group(0) + "\n}" if m else ""

# a small stand-in for the browser: elements with children, text, attributes, listeners and simple selectors
SHIM = r"""
class E {
  constructor(tag) { this.tag = String(tag).toLowerCase(); this.tagName = this.tag.toUpperCase(); this.children = []; this.parentElement = null;
    this.className = ""; this.attrs = {}; this.dataset = {}; this.listeners = {}; this.hidden = false; this.value = ""; this.checked = false;
    this.disabled = false; this.title = ""; this.id = ""; this._text = ""; this.style = { setProperty() {}, cssText: "" };
    const self = this; this.classList = { add: (...c) => { for (const x of c) if (!self.cls().includes(x)) self.className = (self.className + " " + x).trim(); },
      remove: (...c) => { self.className = self.cls().filter((x) => !c.includes(x)).join(" "); },
      toggle: (c, on) => { const has = self.cls().includes(c); if (on === undefined ? !has : on) self.classList.add(c); else self.classList.remove(c); },
      contains: (c) => self.cls().includes(c) }; }
  cls() { return String(this.className || "").split(/\s+/).filter(Boolean); }
  get textContent() { return this.tag === "#text" ? this._text : this.children.map((c) => c.textContent).join(""); }
  set textContent(v) { if (this.tag === "#text") { this._text = String(v); return; } this.children = []; if (v != null && String(v) !== "") this.append(String(v)); }
  get innerHTML() { return ""; } set innerHTML(v) { this.children = []; }
  get childNodes() { return this.children; } get firstChild() { return this.children[0] || null; }
  get lastChild() { return this.children[this.children.length - 1] || null; }
  _adopt(k) { const n = typeof k === "string" || typeof k === "number" ? Object.assign(new E("#text"), { _text: String(k) }) : k;
    if (n.parentElement) n.parentElement.children = n.parentElement.children.filter((c) => c !== n); n.parentElement = this; return n; }
  append(...k) { for (const c of k) this.children.push(this._adopt(c)); }
  prepend(...k) { this.children.unshift(...k.map((c) => this._adopt(c))); }
  replaceChildren(...k) { for (const c of this.children) c.parentElement = null; this.children = []; this.append(...k); }
  before(...k) { const p = this.parentElement; if (!p) return; const i = p.children.indexOf(this); const n = k.map((c) => p._adopt(c)); p.children.splice(p.children.indexOf(this), 0, ...n); }
  after(...k) { const p = this.parentElement; if (!p) return; const n = k.map((c) => p._adopt(c)); p.children.splice(p.children.indexOf(this) + 1, 0, ...n); }
  remove() { const p = this.parentElement; if (p) p.children = p.children.filter((c) => c !== this); this.parentElement = null; }
  contains(x) { for (let n = x; n; n = n.parentElement) if (n === this) return true; return false; }
  setAttribute(k, v) { this.attrs[k] = String(v); if (k === "class") this.className = String(v); if (k === "id") this.id = String(v);
    if (k.startsWith("data-")) this.dataset[k.slice(5).replace(/-(.)/g, (_, c) => c.toUpperCase())] = String(v); }
  getAttribute(k) { return k in this.attrs ? this.attrs[k] : null; } removeAttribute(k) { delete this.attrs[k]; }
  addEventListener(t, f) { (this.listeners[t] = this.listeners[t] || []).push(f); } removeEventListener() {}
  dispatchEvent(ev) { for (const f of this.listeners[ev.type] || []) f(ev); return true; }
  click() { return this.dispatchEvent({ type: "click", target: this, preventDefault() {}, stopPropagation() {} }); }
  focus() {} blur() {} scrollIntoView() {} reset() {} closest() { return null; } getBoundingClientRect() { return { width: 0, height: 0, top: 0, left: 0 }; }
  _walk(f) { for (const c of this.children) { if (c.tag !== "#text") { f(c); c._walk(f); } } }
  matches(sel) { return sel.split(",").some((s) => one(this, s.trim().split(/\s+|>/).filter(Boolean).pop())); }
  querySelectorAll(sel) { const out = []; this._walk((c) => { if (c.matches(sel)) out.push(c); }); return out; }
  querySelector(sel) { const f = this.querySelectorAll(sel)[0]; if (f) return f;
    if (this._auto && /^[a-z]+$/.test(sel)) { const n = new E(sel); this.append(n); return n; } return null; }
}
function one(e, s) {
  const m = s.match(/^([a-z0-9]*)((?:[#.][\w-]+)*)((?:\[[^\]]+\])*)$/i); if (!m) return false;
  if (m[1] && e.tag !== m[1].toLowerCase()) return false;
  for (const p of (m[2].match(/[#.][\w-]+/g) || [])) { if (p[0] === "#" ? e.id !== p.slice(1) : !e.cls().includes(p.slice(1))) return false; }
  for (const a of (m[3].match(/\[[^\]]+\]/g) || [])) {
    const [, k, v] = a.match(/^\[([\w-]+)(?:="?([^"\]]*)"?)?\]$/) || [];
    const ds = k && k.startsWith("data-") ? e.dataset[k.slice(5).replace(/-(.)/g, (_, c) => c.toUpperCase())] : undefined;
    const have = ds !== undefined ? ds : e.attrs[k] !== undefined ? e.attrs[k] : (e[k] !== undefined && typeof e[k] !== "object" ? String(e[k]) : undefined);
    if (have === undefined || (v !== undefined && String(have) !== v)) return false;
  }
  return true;
}
globalThis.Node = E; globalThis.HTMLElement = E;
globalThis.Event = class { constructor(t, o) { this.type = t; Object.assign(this, o || {}); } preventDefault() {} };
globalThis.CustomEvent = class extends globalThis.Event {};
const body = new E("body"), ids = {};
const SC = JSON.parse(process.argv[1]);
const qsa = {};
for (const [sel, list] of Object.entries(SC.qsa || {})) qsa[sel] = list.map((x) => { const b = new E(x.tag || "button"); Object.assign(b.dataset, x.dataset || {}); if (x.text) b.textContent = x.text; body.append(b); return b; });
globalThis.document = { body, hidden: false, listeners: {},
  getElementById(id) { if (!ids[id]) { const e = new E("div"); e.id = id; e._auto = true; Object.assign(e, (SC.ids || {})[id] || {}); ids[id] = e; body.append(e); } return ids[id]; },
  createElement: (t) => new E(t), createElementNS: (_n, t) => new E(t), createTextNode: (t) => Object.assign(new E("#text"), { _text: String(t) }),
  querySelectorAll(sel) { return qsa[sel] ? [...qsa[sel]] : body.querySelectorAll(sel); },
  querySelector(sel) { return (qsa[sel] || [])[0] || body.querySelectorAll(sel)[0] || null; },
  addEventListener(t, f) { (this.listeners[t] = this.listeners[t] || []).push(f); },
  dispatchEvent(ev) { for (const f of this.listeners[ev.type] || []) f(ev); return true; } };
globalThis.window = globalThis;
globalThis.location = { pathname: "/page", hash: SC.hash || "", search: "" };
globalThis.history = { replaceState() {} };
globalThis.scrollTo = () => {};
globalThis.setInterval = () => 0; globalThis.clearInterval = () => {};
globalThis.confirm = () => true; globalThis.prompt = () => null;
globalThis.LGLoader = { wait: (p) => p, busy() {}, ready() {}, pane: (_p, _t, run) => run(), errorText: (e) => String((e && e.message) || e) };
const fetches = [];
globalThis.fetch = async (url) => { url = String(url); fetches.push(url);
  for (const [pre, data, status] of SC.routes || []) if (url.startsWith(pre)) {
    const d = typeof data === "string" && data.startsWith("js:") ? eval(data.slice(3))(url) : data;
    return { ok: (status || 200) < 400, status: status || 200, json: async () => JSON.parse(JSON.stringify(d)) }; }
  return { ok: false, status: 404, json: async () => ({ error: "not here" }) }; };
process.on("unhandledRejection", (e) => { console.error("unhandled:", e && e.stack || e); });
const $ = (id) => document.getElementById(id);
const txt = (n) => (n ? n.textContent : "");
const flush = async () => { for (let i = 0; i < 30; i++) await new Promise((r) => setImmediate(r)); };
const find = (root, f) => { const out = []; root._walk((c) => { if (f(c)) out.push(c); }); return out; };
const button = (root, re) => find(root, (c) => c.tag === "button" && re.test(c.textContent))[0];
"""


def run(js_file, scenario, steps, pre=""):
    src = open(js_file, encoding="utf-8").read()
    prog = SHIM + LGSHARE + "\n" + pre + "\n" + src + "\n(async () => { const out = {}; try {\n" + steps + \
        "\n} catch (e) { out.error = String(e && e.stack || e); } out.fetches = fetches; console.log(JSON.stringify(out)); })();"
    r = subprocess.run([node, "-e", prog, json.dumps(scenario)], capture_output=True, text=True, timeout=60)
    try:
        return json.loads(r.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        return {"error": (r.stdout + r.stderr)[-1500:]}


def no_error(label, out):
    ok(f"{label}: the page runs", not out.get("error"), out.get("error"))


# ---------------------------------------------------------------- 1. audit.js
print("1. Audit portal (audit.js)")
ov = {"kpis": {"events": 900, "signins": 43280, "people": 12, "failed": 1, "failure_rate": 0.0, "lockouts": 0, "privileged": 40,
               "exports": 30, "after_hours": 0},
      "checks": [], "integrity": {"ok": True, "entries": 900}, "period": {"from": "2026-10-28", "to": "2026-11-26"},
      "access_mode": "internal", "work_hours": [8, 18], "per_day": [], "hours": [0] * 24, "tabs": [],
      "fail_sources": [{"ip": f"192.0.2.{i}", "location": "Test", "n": 30 - i} for i in range(8)],
      "exports_by": [{"who": f"Person {i}", "n": 9 - i} for i in range(8)],
      "privileged_recent": [{"when": "2026-11-20 10:00", "label": "Role changed", "user": "a", "target": "b", "detail": ""}] * 15,
      "totals": {"fail_sources": 23, "exports_by": 14}}
events = {"rows": [], "total": 0, "counts": {}}
sc = {"qsa": {".au-tabs [data-tab]": [{"dataset": {"tab": "overview"}, "text": "Overview"}, {"dataset": {"tab": "auth"}, "text": "Sign-ins"},
                                     {"dataset": {"tab": "data"}, "text": "Data and exports"}]},
      "routes": [["/api/audit/overview", ov], ["/api/audit/events", events]]}
out = run(page("audit.js"), sc, """
  await flush(); out.ov = txt($("ovBody")); out.banner = txt($("banner"));
  const b = find($("ovBody"), (c) => c.tag === "button" && /Sign-ins tab/.test(c.textContent))[0];
  out.button = !!b; if (b) { b.click(); await flush(); }
""")
ok("audit: the page runs (no error shown)", not out.get("error") and not out.get("banner"), out.get("error") or out.get("banner"))
t = out.get("ov", "")
ok("the failure sources say 'Top 8 of 23 addresses' (the full count beside the top 8)", "Top 8 of 23 addresses" in t, t[-900:])
ok("...the exporters say 'Top 8 of 14 people'", "Top 8 of 14 people" in t, t[-900:])
ok("...each with a way to every one: the button opens the Sign-ins log tab", out.get("button")
   and any("tab=auth" in f for f in out.get("fetches", [])), out.get("fetches"))
ok("the privileged changes say 'The newest 15 of 40'", "The newest 15 of 40 privileged changes" in t, t[-600:])
ok("1 failed sign-in of 43,281 attempts reads '<0.1% of attempts', never '0.0 %'", "<0.1% of attempts" in t and "0.0 %" not in t
   and "0 % of attempts" not in t, re.findall(r".{12}of attempts", t))
ov2 = dict(ov, totals={"fail_sources": 3, "exports_by": 8}, fail_sources=ov["fail_sources"][:3], exports_by=ov["exports_by"][:8])
ov2["kpis"] = dict(ov["kpis"], privileged=15)
out = run(page("audit.js"), dict(sc, routes=[["/api/audit/overview", ov2], ["/api/audit/events", events]]), "await flush(); out.ov = txt($('ovBody'));")
ok("...and a list that holds every one says nothing more (3 addresses, 8 of 8 people, 15 of 15 changes)",
   not out.get("error") and "Exports by person" in out.get("ov", "") and "Top " not in out.get("ov", "")
   and "The newest" not in out.get("ov", ""), out.get("error") or out.get("ov", "")[-400:])

# ---------------------------------------------------------------- 2. kb-settings.js
print("2. Definitions page (kb-settings.js)")
names = [{"name": f"family{i:03d}", "references": [], "kinds": [], "sources": []} for i in range(450)]
long_url = "https://example.org/" + "a-very-long-path-segment/" * 6 + "end"
links = [f"https://example.org/ref{i}" for i in range(11)] + [long_url]
unres = {"unresolved": names, "unchecked": [], "defined": [], "all": names, "malpedia": True, "check": {},
         "issues": [{"name": "CVE-2024-0001", "cve": True, "epss": 0.0004, "cvss": 5.0, "hosts": 1, "records": 1, "found": True}]}
entry = {"references": [], "sources": [{"source_label": "MISP Galaxy", "name": "family000", "url": "https://example.org/main", "references": links}]}
sc = {"qsa": {"[data-iss]": [{"dataset": {"iss": "cves"}}]},
      "routes": [["/api/kb/unresolved", unres], ["/api/kb/entry", entry]]}
out = run(page("kb-settings.js"), sc, """
  await flush();
  const tb = $("infTable").querySelector("tbody"); out.rows = tb.children.length; out.inf = txt(tb).slice(-300);
  document.querySelectorAll("[data-iss]")[0].click(); out.iss = txt($("issTable").querySelector("tbody"));
  const d = button(tb, /^Define$/); if (d) { d.click(); await flush(); } out.others = txt($("kbOthers"));
  out.links = find($("kbOthers"), (c) => c.tag === "a").map((a) => a.textContent);
""")
no_error("kb-settings", out)
ok("450 names: the table draws 400 and says 'Showing 400 of 450: search to narrow the list.'",
   "Showing 400 of 450: search to narrow the list." in out.get("inf", ""), out.get("inf"))
ok("an EPSS of 0.04% reads 'EPSS <0.1%', never 'EPSS 0.0%'", "EPSS <0.1%" in out.get("iss", "") and "EPSS 0.0%" not in out.get("iss", ""),
   out.get("iss", "")[:300])
ok("another source's links: all 13 are listed (not the first 8)", len(out.get("links", [])) == 13, out.get("links"))
ok("...each in full (the long one is not cut at 80 characters)", long_url.replace("https://", "") in out.get("links", []), out.get("links"))

# ---------------------------------------------------------------- 3. kb-services.js
print("3. Services reports (kb-services.js)")
evs = [{"kind": "new_report", "text": f"Change {i}", "report": "scan_x", "at": "2026-11-01"} for i in range(30)]
rep = {"name": "scan_x", "names": ["scan_x"], "title": "Accessible X", "group": "Known vulnerability", "severity": "high", "hosts": 10,
       "records": 20, "products": ["Alpha", "Beta", "Gamma"], "ports": ["80/tcp"], "issues": [], "issues_total": 0, "infections": [],
       "totals": {"products": 14, "ports": 1}, "def": "", "names_v6": [], "notes": 0, "page": {}}
lst = {"groups": ["Known vulnerability"], "reports": [rep], "events": evs[:30], "totals": {"events": 30}, "status": {}}
pairs = lambda n, w: [[f"{w} {i}", 100 - i] for i in range(n)]
det = {"name": "scan_x", "names": ["scan_x"], "title": "Accessible X", "group": "Known vulnerability", "severity": "high",
       "classification": "x / y", "definition": {"def": "A definition."}, "shadowserver": {}, "url": "", "hosts": 10, "records": 20,
       "notes": [{"text": f"Note {i}", "role": "researcher", "by": "R", "date": "2026-11-01"} for i in range(7)],
       "issues": [{"name": f"CVE-2024-{1000 + i}", "cve": True, "hosts": 3, "epss": 0.0004 if i == 0 else 0.2} for i in range(60)],
       "issues_total": 140, "products": pairs(12, "Product"), "devices": pairs(3, "Device"), "versions": pairs(12, "Version"),
       "ports": pairs(2, "Port"), "tags": pairs(12, "Tag"),
       "totals": {"products": 40, "devices": 3, "versions": 25, "ports": 2, "tags": 12, "issues": 140}}
sc = {"routes": [["/api/kb/services", lst], ["/api/kb/service?", det]]}
out = run(page("kb-services.js"), sc, """
  await flush();
  out.asks = txt($("svcAskList")); out.table = txt($("svcTable"));
  const box = document.createElement("div"); await window.LGServices.overview(box, "scan_x"); await flush();
  out.blocks = Object.fromEntries(find(box, (c) => c.tag === "section").map((s) => [txt(s.children[0]), txt(s)]));
""")
no_error("kb-services", out)
ok("the changes list: 8 shown and 'The newest 8 of 30 changes' said", "The newest 8 of 30 changes" in out.get("asks", ""), out.get("asks", "")[-200:])
ok("a report's products in the list: 'Top 3 of 14 products'", "Top 3 of 14 products" in out.get("table", ""), out.get("table", "")[:300])
b = out.get("blocks", {})
ok("the window's Products: 'Top 12 of 40 products'", "Top 12 of 40 products" in b.get("Products", ""), b.get("Products", "")[:200])
ok("...Versions: 'Top 12 of 25 versions'", "Top 12 of 25 versions" in b.get("Versions", ""), b.get("Versions", "")[:200])
ok("...Devices, Ports and Tags hold every one: no notice", all("Top " not in b.get(k, "") for k in
   ("Devices (vendor and type)", "Ports", "Tags (not CVEs)")), {k: b.get(k, "")[:80] for k in ("Devices (vendor and type)", "Ports", "Tags (not CVEs)")})
iss = next((v for k, v in b.items() if k.startswith("Issues found")), "")
ok("...Issues: the heading gives 140 and the table says '25 of 140 issues'", "(140)" in iss and "25 of 140 issues" in iss, iss[-300:])
ok("...an EPSS of 0.04% reads 'EPSS <0.1%'", "EPSS <0.1%" in iss and "EPSS 0.0%" not in iss, iss[:200])
nts = next((v for k, v in b.items() if k.startswith("Researchers' notes")), "")
ok("...notes: 'The newest 5 of 7 notes'", "The newest 5 of 7 notes" in nts, nts[-200:])

# ---------------------------------------------------------------- 4. kb-services-patterns.js
print("4. Pattern fields (kb-services-patterns.js)")
sug = [{"field": f, "may": True, "kind": "exact", "present": p, "why": ""} for f, p in
       (("almost", 0.996), ("rare", 0.0004), ("every", 1.0), ("never", 0.0), ("half", 0.5))]
sc = {"routes": [["/api/kb/service/fields", {"records": 1000, "fields": [], "suggestions": sug, "min_hosts": 5}]]}
out = run(page("kb-services-patterns.js"), sc, """
  const pane = document.createElement("div"); await window.LGServicePatterns.fields(pane, "scan_x"); await flush();
  out.cells = find(pane, (c) => c.tag === "td" && c.cls().includes("svc-num")).map((c) => c.textContent);
""")
no_error("patterns", out)
ok("on 99.6% of the records: '>99%', not '100%'; on 0.04%: '<0.1%', not '0.0%'; the whole '100%', none '0.0%', half '50%'",
   out.get("cells") == [">99%", "<0.1%", "100%", "0.0%", "50%"], out.get("cells"))

# ---------------------------------------------------------------- 5. sender-audit.js
print("5. Sender check (sender-audit.js)")


def sender(checked, passed_n, odd_n, changes_n):
    return {"found": True, "mode": "enforce", "period": {"from": "2026-10-28", "to": "2026-11-26"}, "domain": "shadowserver.org",
            "kpis": {"checked": checked, "pass": passed_n, "fail": checked - passed_n, "none": 0, "other": 0, "temperror": 0, "permerror": 0,
                     "pass_rate": passed_n / checked, "held_back": 0, "released": 0, "held_now": 0},
            "api": {"files": 0}, "source": "email", "per_day": [], "keys": [], "types": {"new": [], "recorded": 0}, "standards": [],
            "odd": [{"at": "2026-11-20T10:00", "result": "fail", "meaning": "", "action_label": "", "from_domain": "x", "signer": "",
                     "reason": "", "subject": "", "files": ""}] * odd_n,
            "changes": [{"at": "2026-11-20", "event": "sender_release", "user": "a", "detail": ""}] * changes_n}


out = run(page("sender-audit.js"), {"routes": [["/api/audit/sender", sender(43281, 43280, 1, 2)]]},
          "await window.LGSender.load('from=a'); out.t = txt($('snBody'));")
no_error("sender", out)
ok("43,280 valid of 43,281: '>99.9%', never '100.0 %' while one failed", ">99.9%" in out.get("t", "") and "100.0" not in out.get("t", ""),
   re.findall(r"Valid, expected signer.{0,12}", out.get("t", "")))
out = run(page("sender-audit.js"), {"routes": [["/api/audit/sender", sender(1500, 300, 300, 100)]]},
          "await window.LGSender.load('from=a'); out.t = txt($('snBody'));")
ok("1,200 did not pass, the newest 300 sent: 'Reports that did not pass (1,200: the newest 300 are listed)'",
   "Reports that did not pass (1,200: the newest 300 are listed)" in out.get("t", ""), re.findall(r"Reports that did not pass.{0,50}", out.get("t", "")))
ok("...the changes at their cap of 100 say they are the newest 100", "the newest 100" in out.get("t", ""),
   re.findall(r"Settings and releases in the period.{0,60}", out.get("t", "")))

# ---------------------------------------------------------------- 6. connectors-admin.js
print("6. Connectors (connectors-admin.js)")
tgt = {"id": "t1", "name": "OpenCTI test", "kind_name": "OpenCTI", "address": "https://opencti.test", "tlp": "amber", "on": True,
       "key": ".env", "env_name": "X", "last": None, "scope": {}}
LOG = "js:(url) => { const m = url.match(/[?&]n=(\\d+)/), n = m ? +m[1] : 200; return { log: Array.from({ length: Math.min(n, 1234) }, (_, i) => ({ at: 1764000000 - i, day: '2026-11-20', status: 'sent', devices: 2 })), totals: { log: 1234 } }; }"
sc = {"hash": "#connectors", "routes": [["/api/connectors/t1/log", LOG], ["/api/connectors", {"vault_ready": True, "sender_installed": True,
                                                                                               "targets": [tgt], "tlps": ["amber"]}]]}
out = run(page("connectors-admin.js"), sc, """
  await flush(); const body = $("cnBody");
  button(body, /^Sends$/).click(); await flush();
  const log = () => find(body, (c) => c.tag === "ul" && c.cls().includes("cn-log"))[0];
  out.first = log().children.length; out.t1 = txt(log());
  const all = button(log(), /Show all/); out.all = !!all; if (all) { all.click(); await flush(); }
  out.second = log().children.length; out.t2 = txt(log()).slice(-200);
""")
no_error("connectors", out)
ok("1,234 sends: the newest 30 and 'The newest 30 of 1,234 entries.'", "The newest 30 of 1,234 entries." in out.get("t1", ""), out.get("t1", "")[-200:])
ok("...'Show all 1,234' lists every one (1,234 entries, no notice left)", out.get("all") and out.get("second") == 1234
   and "of 1,234" not in out.get("t2", ""), (out.get("all"), out.get("second"), out.get("t2")))

# ---------------------------------------------------------------- 7. pipeline-settings.js
print("7. Workers (pipeline-settings.js)")
res = [{"applied_at": f"2026-11-{20 - i // 3:02d}T10:00", "status": "applied", "by": "admin", "changed": [f"change {i}"]} for i in range(30)]
S = {"found": True, "unlocked": False, "provider": "imap", "groups": [], "fields": [], "pending": [], "results": res,
     "totals": {"results": 30}, "api": {}}
sc = {"hash": "#workers", "routes": [["/api/pipeline/settings", S]]}
out = run(page("pipeline-settings.js"), sc, """
  await flush(); const body = $("wkBody");
  const box = find(body, (c) => c.cls().includes("wk-requests"))[0]; out.t1 = txt(box);
  out.n1 = find(box, (c) => c.tag === "li").length;
  const b = button(box, /Show all/); out.all = !!b; if (b) { b.click(); }
  out.n2 = find(box, (c) => c.tag === "li").length; out.t2 = txt(box);
""")
no_error("pipeline", out)
ok("30 done requests: 5 listed and 'The newest 5 of 30.'", out.get("n1") == 5 and "The newest 5 of 30." in out.get("t1", ""), (out.get("n1"), out.get("t1", "")[-200:]))
ok("...'Show all 30' lists every one", out.get("all") and out.get("n2") == 30 and "The newest" not in out.get("t2", ""), (out.get("all"), out.get("n2")))

# ---------------------------------------------------------------- 8. task-monitor.js (its Users tab, on its own)
print("8. Task monitor, Users (task-monitor.js)")
src = open(page("task-monitor.js"), encoding="utf-8").read()
fn = lambda name: (re.search(r"^  function " + name + r"\(.*?^  \}\n", src, re.M | re.S) or [""])[0]
line = lambda start: (re.search(r"^  " + re.escape(start) + r".*$", src, re.M) or [""])[0]
pieces = "\n".join([line("const el = "), line("const fmt = "), "  const dur = (s) => `${s} s`;", "  const SORT = {}; let D = null; const drawTab = () => {};",
                    fn("table"), fn("drawUsers")])
tm_js = os.path.join(os.environ.get("TMPDIR", "/tmp"), f"lg_tm_users_{os.getpid()}.js")
with open(tm_js, "w", encoding="utf-8") as fh:
    fh.write(pieces)
users = [{"user": "p-0000000000000000heav", "user_label": "heavy", "role": "admin", "requests": 900, "seconds": 43280.0, "cpu_seconds": 1, "slowest": 1, "slowest_route": "/a",
          "running": 0, "last_route": "/a", "last_ago": 1, "errors": 0, "share": 43280 / 43281},
         {"user": "p-0000000000000000ligh", "user_label": "light", "role": "analyst", "requests": 1, "seconds": 1.0, "cpu_seconds": 0, "slowest": 1, "slowest_route": "/b",
          "running": 0, "last_route": "/b", "last_ago": 1, "errors": 0, "share": 1 / 43281}]
out = run(tm_js, {}, """
  drawUsers({ users: %s, users_window_min: 10 });
  out.lead = txt($("tmUsers").children[0]);
  out.shares = find($("tmUsers"), (c) => c.cls().includes("tm-share")).map((c) => c.textContent);
""" % json.dumps(users))
os.unlink(tm_js)
ok("the Users tab is found and runs", bool(fn("drawUsers")) and not out.get("error"), out.get("error"))
ok("a share of 1 in 43,281 reads '<1%', nearly all of it '>99%' (never '0%' or '100%')", out.get("shares") == [">99%", "<1%"], out.get("shares"))
ok("...and the lead names the heavy user with '>99%' of the server's time", "heavy used >99% of the server's time" in out.get("lead", ""), out.get("lead"))

print()
print(f"{passed}/{passed + failed} checks passed" + (f"; {failed} FAILED" if failed else ""))
sys.exit(1 if failed else 0)
