# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""Shared by the page behaviour checks (check_page_cuts_*.py): run a page script's own functions under node, on a small
stand-in for the browser's DOM, and read back the text they draw. Not a check itself.

  page_src(name)          the page file (the held copy $LG_HELD_DIR/<name>.new when there is one, else static/js)
  extract(src, names)     those top-level definitions of the page's IIFE (2-space indent): functions and consts
  run(js)                 node runs DOM_JS + LGSHARE_JS + js; returns (stdout parsed as JSON, raw output)
"""
import glob
import json
import os
import re
import shutil
import subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
PF = os.path.dirname(HERE)
NODE = os.environ.get("LG_NODE") or shutil.which("node") or next(iter(sorted(glob.glob(os.path.expanduser("~/lg-node/*/bin/node")))), None)
HELD = os.environ.get("LG_HELD_DIR", "")
# Running a page's own script under Node is a maintainer's check (tests/maintainer_rows.txt, 2026-11-26): in the
# maintainer's suite (LG_SUITE=all: the release checklist, the GitHub checks) a missing Node FAILS; on an installation,
# which has no Node, that part of a check is not run and not counted, and the check says so in one line.
MAINTAINER = os.environ.get("LG_SUITE") == "all"
NOT_HERE = "  (its page-script part runs under Node: a maintainer's check, run by LG_SUITE=all; not part of an installation's checks)"


def no_node(ok, label, *info):
    """Where a check needs Node and there is none: a failure in the maintainer's suite, one plain line elsewhere."""
    if MAINTAINER:
        ok(label, False, *(info or ("no node",)))
    else:
        print(NOT_HERE, flush=True)


def page_path(name):
    held = os.path.join(HELD, name + ".new") if HELD else ""
    return held if held and os.path.isfile(held) else os.path.join(PF, "static", "js", name)


def page_src(name):
    return open(page_path(name), encoding="utf-8").read()


def extract(src, names, optional=(), indent=2):
    """The definitions named, in the order given. A name in `optional` may be missing (a helper the old code lacks).
    indent: 2 for the page's own top level, 4 for a function inside one of its functions."""
    out = []
    sp = " " * indent
    for n in names:
        m = re.search(r"^" + sp + r"(?:async )?function " + re.escape(n) + r"\(.*?^" + sp + r"\}\n", src, re.M | re.S)
        if m:
            out.append(m.group(0))
            continue
        start = re.search(r"^" + sp + r"(?:const|let) " + re.escape(n) + r"(?![\w$])", src, re.M)
        if not start:
            if n in optional:
                continue
            raise KeyError(f"{n} is not in the page")
        # a const runs until its brackets close at the end of a line (strings and regexes skipped roughly)
        lines, depth = [], 0
        for line in src[start.start():].split("\n"):
            lines.append(line)
            bare = re.sub(r"\\.", "", line)
            bare = re.sub(r'"[^"]*"|\'[^\']*\'|`[^`]*`|/[^/\n*]+/[gimsuy]*(?=[.,;)\s])', "", bare)
            depth += sum(bare.count(c) for c in "({[") - sum(bare.count(c) for c in ")}]")
            if depth <= 0 and line.rstrip().endswith((";", ",")) or depth <= 0 and len(lines) > 1 and line.strip().startswith(("}", "]", ")")):
                break
        out.append("\n".join(lines))
    return "\n".join(out) + "\n"


def lgshare_js():
    """loader.js's LGShare with the helpers just above it (from its comment block on), in a block of its own."""
    rx = re.compile(r"^  // Shares and cut lists in words.*?^  window\.LGShare = \{.*?^  \};\n", re.M | re.S)
    m = rx.search(page_src("loader.js"))
    if not m:                       # the old loader: the shares the old pages worked out themselves are what is tested
        held = os.path.join(HELD, "loader.js.new") if HELD else ""
        m = rx.search(open(held, encoding="utf-8").read()) if held and os.path.isfile(held) else None
    return "{\n" + m.group(0) + "}\n" if m else ""


DOM_JS = r"""
const textNode = (s) => { const n = new N("#text"); n._text = String(s); return n; };
class N {
  constructor(tag) { this.tag = String(tag).toLowerCase(); this.tagName = this.tag.toUpperCase(); this.children = []; this.parent = null;
    this.attrs = {}; this.dataset = {}; this.on = {}; this.hidden = false; this._cls = new Set(); this._text = ""; this.type = ""; this.title = ""; this.value = "";
    this.style = { setProperty(k, v) { this[k] = v; }, cssText: "" }; const me = this;
    this.classList = { add: (...c) => c.forEach((x) => me._cls.add(x)), remove: (...c) => c.forEach((x) => me._cls.delete(x)),
      toggle: (c, f) => { if (f === undefined ? !me._cls.has(c) : f) me._cls.add(c); else me._cls.delete(c); }, contains: (c) => me._cls.has(c) }; }
  get className() { return [...this._cls].join(" "); } set className(v) { this._cls = new Set(String(v || "").split(/\s+/).filter(Boolean)); }
  get textContent() { return this.tag === "#text" ? this._text : this.children.map((c) => c.textContent).join(""); }
  set textContent(v) { if (this.tag === "#text") { this._text = String(v); return; } this.replaceChildren(); if (v != null && v !== "") this.append(String(v)); }
  get innerText() { return this.textContent; }
  get childNodes() { return this.children; } get firstElementChild() { return this.children.find((c) => c.tag !== "#text") || null; }
  get parentElement() { return this.parent; } get nextElementSibling() { const p = this.parent; if (!p) return null; const i = p.children.indexOf(this); return p.children.slice(i + 1).find((c) => c.tag !== "#text") || null; }
  _adopt(c) { if (c == null || c === false) return null; if (typeof c !== "object") c = textNode(c); if (c.parent) c.parent._rm(c); c.parent = this; return c; }
  append(...k) { for (const x of k) { const c = this._adopt(x); if (c) this.children.push(c); } }
  prepend(...k) { const cs = k.map((x) => this._adopt(x)).filter(Boolean); this.children.unshift(...cs); }
  appendChild(c) { this.append(c); return c; }
  _rm(c) { const i = this.children.indexOf(c); if (i >= 0) this.children.splice(i, 1); c.parent = null; }
  replaceChildren(...k) { for (const c of this.children) c.parent = null; this.children = []; this.append(...k); }
  remove() { if (this.parent) this.parent._rm(this); }
  before(...k) { const p = this.parent; if (!p) return; for (const x of k) { const c = p._adopt(x); if (c) p.children.splice(p.children.indexOf(this), 0, c); } }
  after(...k) { const p = this.parent; if (!p) return; let i = p.children.indexOf(this) + 1; for (const x of k) { const c = p._adopt(x); if (c) p.children.splice(i++, 0, c); } }
  setAttribute(k, v) { this.attrs[k] = String(v); if (k === "class") this.className = v; } getAttribute(k) { return k in this.attrs ? this.attrs[k] : null; }
  removeAttribute(k) { delete this.attrs[k]; } hasAttribute(k) { return k in this.attrs; }
  addEventListener(e, f) { (this.on[e] = this.on[e] || []).push(f); } removeEventListener() {}
  fire(e) { for (const f of this.on[e] || []) f({ type: e, key: "Enter", preventDefault() {}, stopPropagation() {}, clientX: 0, clientY: 0, target: this }); }
  click() { this.fire("click"); } dispatchEvent(ev) { this.fire(ev.type); return true; }
  focus() {} blur() {} scrollIntoView() {} getBBox() { return { x: 0, y: 0, width: 1, height: 1 }; }
  getBoundingClientRect() { return { left: 0, top: 0, width: 100, height: 100 }; } get offsetWidth() { return 0; } get offsetHeight() { return 0; }
  all() { const out = []; const walk = (n) => { for (const c of n.children) if (c.tag !== "#text") { out.push(c); walk(c); } }; walk(this); return out; }
  matches(sel) {
    return String(sel).split(",").some((all) => {
      const parts = all.trim().split(/\s+/);
      if (parts.length > 1) {                     // "a b": this matches b, an ancestor matches a (and so on)
        if (!this.matches(parts[parts.length - 1])) return false;
        let i = parts.length - 2, p = this.parent;
        while (p && i >= 0) { if (p.tag !== "#text" && p.matches(parts[i])) i--; p = p.parent; }
        return i < 0;
      }
      const one = parts[0];
      const m = /^([a-z0-9]*)((?:\.[\w-]+)*)((?:\[[^\]]+\])*)((?::not\([^)]*\))*)$/i.exec(one); if (!m) return false;
      if (m[1] && m[1].toLowerCase() !== this.tag) return false;
      for (const c of m[2].split(".").filter(Boolean)) if (!this._cls.has(c)) return false;
      for (const a of m[3].match(/\[[^\]]+\]/g) || []) { const [, k, v] = /^\[([\w-]+)(?:="?([^"\]]*)"?)?\]$/.exec(a) || [];
        const val = k && k.startsWith("data-") ? this.dataset[k.slice(5).replace(/-(\w)/g, (_, x) => x.toUpperCase())] : this.attrs[k];
        if (v === undefined ? val === undefined : String(val) !== v) return false; }
      for (const nt of m[4].match(/:not\(([^)]*)\)/g) || []) if (this.matches(nt.slice(5, -1))) return false;
      return true; });
  }
  querySelectorAll(sel) { return this.all().filter((n) => n.matches(sel)); } querySelector(sel) { return this.querySelectorAll(sel)[0] || null; }
  closest(sel) { let n = this; while (n) { if (n.tag !== "#text" && n.matches(sel)) return n; n = n.parent; } return null; }
}
const IDS = {};
const document = { body: new N("body"), documentElement: new N("html"), createElement: (t) => new N(t), createElementNS: (_, t) => new N(t),
  createTextNode: (s) => textNode(s), getElementById: (id) => (IDS[id] = IDS[id] || Object.assign(new N("div"), { id })),
  querySelector: (s) => document.body.querySelector(s), querySelectorAll: (s) => document.body.querySelectorAll(s), addEventListener() {} };
const window = globalThis; window.document = document; window.addEventListener = () => {}; window.innerWidth = 1200; window.innerHeight = 800;
window.matchMedia = () => ({ matches: false, addEventListener() {} });
window.LGLoader = { ready() {}, errorText: (e) => String(e), wait: (p) => p, busy() {}, saveBlob() {} };
const location = { search: "", hash: "", href: "http://localhost/", pathname: "/" };
const history = { replaceState() {}, pushState() {} };
// a page's own errors are kept (a check prints them when it fails), never a crash of the stand-in
const ERRS = []; const keep = (e) => ERRS.push(String((e && e.stack) || e).split("\n").slice(0, 3).join(" "));
process.on("uncaughtException", keep); process.on("unhandledRejection", keep);
class Option extends N { constructor(t, v) { super("option"); this.textContent = t; this.value = v; } }
class Event { constructor(type) { this.type = type; } } class MouseEvent extends Event {}
// fetch answers from ROUTES: [substring of the URL, status, JSON body]; the first that matches
const ROUTES = [];
const fetch = async (url) => { const r = ROUTES.find(([u]) => String(url).includes(u));
  if (!r) return { ok: false, status: 404, json: async () => ({ error: "not in the test" }) };
  return { ok: r[1] < 400, status: r[1], json: async () => JSON.parse(JSON.stringify(r[2])) }; };
window.fetch = fetch;
// every text drawn inside a node, one line per element that holds text of its own
const lines = (n) => { const out = []; const walk = (x) => { const own = x.children.filter((c) => c.tag === "#text").map((c) => c._text).join("").trim();
  if (own) out.push(own); for (const c of x.children) if (c.tag !== "#text") walk(c); }; walk(n); return out; };
"""


def run(js, data=None, timeout=60):
    """node runs the stand-in DOM, LGShare and js; `data` arrives as JSON in process.argv[1]. The last line printed is
    read as JSON: (that, every line printed)."""
    r = subprocess.run([NODE, "-e", DOM_JS + lgshare_js() + js, json.dumps(data)], capture_output=True, text=True, timeout=timeout)
    try:
        return json.loads(r.stdout.strip().splitlines()[-1]), r.stdout + r.stderr
    except (ValueError, IndexError):
        return None, r.stdout + r.stderr
