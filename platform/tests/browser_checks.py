#!/usr/bin/env python3
"""Every page, for every role, in a real browser (the user, 2026-11-18: "tests always to be done"). Signs in as each
test account on a RUNNING install and opens every page the role's Overview links to. On each page it checks:
1. keyboard: every visible control is reached by the Tab key, focus is never trapped, and nothing that looks
   clickable (pointer cursor) sits outside a control the keyboard can reach;
2. lists: a list (ul/ol) holds list items only, and no list item is itself made into a button (screen readers);
3. cut-off text: once the page has settled, no text is cut with "…"; and no MITRE ATT&CK technique or mitigation is
   shown twice in one box (a rule, 2026-11-19); a header button shows its hover label at once (header-tips.js);
4. errors: no script error and no server error (5xx) while the page opens;
5. loading: the loading logo shows at most once and draws itself at most once, loading lines do not come back after
   they have finished, and nothing is still loading after 30 s.
Needs Playwright with Chromium, a test system and its test accounts (never production, never real accounts):
    LG_BROWSER_BASE=http://127.0.0.1:5088 LG_BROWSER_ACCOUNTS=accounts.json python tests/browser_checks.py [role ...]
accounts.json: {"analyst": {"name": "...", "pw": "...", "secret": "<TOTP secret>"}, ...}. Without these the check is
skipped (exit 77, SKIPPED), so the suite runs anywhere. Exit 1 when a page has a problem."""
import base64
import hashlib
import hmac
import json
import os
import struct
import sys
import time
from urllib.parse import urljoin, urlparse

BASE = os.environ.get("LG_BROWSER_BASE", "")
ACC = os.environ.get("LG_BROWSER_ACCOUNTS", "")
try:
    from playwright.sync_api import sync_playwright
except ImportError:
    sync_playwright = None
if not (BASE and ACC and os.path.exists(ACC) and sync_playwright):
    print("SKIPPED: set LG_BROWSER_BASE and LG_BROWSER_ACCOUNTS (a test system's test accounts) and install Playwright "
          "with Chromium to run the browser checks")
    sys.exit(77)
ACCOUNTS = json.load(open(ACC, encoding="utf-8"))
ROLES = sys.argv[1:] or list(ACCOUNTS)
NEVER = ("logout", "/api/", "download", "export", ".csv", ".pdf", ".zip", "/static/")
MAX_PAGES = 14

# 5. loading (the user, 2026-11-18: "check the loading screens load properly and don't load twice"): watched from the
# first moment of every page. The centred logo (loader.js #lgTransition) is on screen at most once and draws itself at
# most once; the pages' loading lines (st-loading, i-loading, ...) do not come back once they have gone; and nothing
# is still loading once the page has settled (30 s at most).
LOAD_WATCH = """(() => {
  const ev = []; window.__lgLoad = ev; const t0 = performance.now(); const now = () => Math.round(performance.now() - t0);
  const SEL = '.i-loading, .st-loading, .lg-loading, .svc-loading, .kbn-loading, .mp-loading';
  let lineOn = false, ovOn = false;
  const tick = () => {
    const vis = [...document.querySelectorAll(SEL)].some(e => e.offsetParent !== null);
    if (vis !== lineOn) { lineOn = vis; ev.push(['line', vis, now()]); }
    const o = document.getElementById('lgTransition');
    const on = !!o && o.classList.contains('on') && !o.classList.contains('leaving');
    if (on !== ovOn) { ovOn = on; ev.push(['overlay', on, now()]); }
  };
  const go = () => {
    setInterval(tick, 40); tick();
    new MutationObserver(ms => { for (const m of ms) { const t = m.target;
      if (t.classList && t.classList.contains('lg-logo-wrap') && t.closest('#lgTransition') && t.classList.contains('drawing')
          && !String(m.oldValue || '').includes('drawing')) ev.push(['draw', true, now()]); } })
      .observe(document.documentElement, {subtree: true, attributes: true, attributeFilter: ['class'], attributeOldValue: true});
  };
  if (document.body) go(); else document.addEventListener('DOMContentLoaded', go);
})();"""


def loading_problems(ev, settled):
    """What the watch saw: [(kind, on, ms)] -> the problems a person would see."""
    probs = []
    shows = [e for e in ev if e[0] == "overlay" and e[1]]
    draws = [e for e in ev if e[0] == "draw"]
    lines = [e for e in ev if e[0] == "line"]
    if len(shows) > 1:
        probs.append(f"the loading logo came {len(shows)} times (at {[e[2] for e in shows]} ms)")
    if len(draws) > 1:
        probs.append(f"the loading logo drew itself {len(draws)} times (at {[e[2] for e in draws]} ms)")
    # a loading line that went away and came back more than a moment later: the page loaded twice
    for a, b in zip(lines, lines[1:]):
        if not a[1] and b[1] and b[2] - a[2] > 150:
            probs.append(f"loading lines came back at {b[2]} ms after finishing at {a[2]} ms")
            break
    if not settled:
        probs.append("still loading after 30 s")
    return probs


FOCUSABLE = "a[href], button, input:not([type=hidden]), select, textarea, summary, [tabindex]:not([tabindex='-1']), [contenteditable='true']"
PAGE_JS = """(sel) => {
  // what a person can see and use: rendered, not transparent (a native select under a custom one), not in a closed
  // <details>, not under an open modal panel (the controls behind it are out of reach on purpose)
  const modal = [...document.querySelectorAll('dialog[open], [aria-modal="true"]')].find(m => m.getBoundingClientRect().width > 0);
  const vis = (e) => { const r = e.getBoundingClientRect();
    const seen = e.checkVisibility ? e.checkVisibility({checkOpacity: true, checkVisibilityCSS: true, contentVisibilityAuto: true}) : true;
    return seen && r.width > 1 && r.height > 1 && !e.closest('[hidden],[inert]') && !e.disabled && (!modal || modal.contains(e))
      && !e.closest('details:not([open]) > :not(summary)') && parseFloat(getComputedStyle(e).opacity) > .05; };
  let n = 0; for (const e of document.querySelectorAll(sel)) { if (vis(e)) e.dataset.kb = String(++n); }
  const name = (e) => e.tagName.toLowerCase() + (e.id ? '#' + e.id : '') + ': ' + (e.getAttribute('aria-label') || e.textContent || '').trim().slice(0, 40);
  const pointer = [...document.querySelectorAll('body *')].filter(e => vis(e) && getComputedStyle(e).cursor === 'pointer'
      && !e.matches(sel) && !e.closest(sel) && !(e.tagName === 'LABEL' && e.control) && !e.closest('label')?.control && !(e.parentElement && getComputedStyle(e.parentElement).cursor === 'pointer')
      && !e.closest('canvas, svg, .maplibregl-canvas-container')).map(name).slice(0, 8);
  const lists = [...document.querySelectorAll('ul, ol')].filter(l => vis(l) && !l.getAttribute('role')).flatMap(l => [...l.children]
      .filter(c => !['LI', 'SCRIPT', 'TEMPLATE'].includes(c.tagName) || (c.tagName === 'LI' && c.getAttribute('role'))).map(c => name(l) + ' > ' + name(c))).slice(0, 8);
  const cut = [...document.querySelectorAll('body *')].filter(e => vis(e) && e.children.length <= 2 && e.textContent.trim()
      && getComputedStyle(e).textOverflow === 'ellipsis' && e.scrollWidth > e.clientWidth + 2).map(name).slice(0, 8);
  // RULE (the user, 2026-11-19): no MITRE ATT&CK technique or mitigation shown twice in one box (a card, the advisory's
  // list, a dialog); the advisor's review queues (suggested / removed mappings, one per source on purpose) left out
  const rx = /^\\s*((?:T\\d{4}(?:\\.\\d{3})?)|(?:M\\d{4}))\\b/, boxes = new Map(), dup = [];
  for (const e of document.querySelectorAll('body *')) {
    if (!vis(e) || e.closest('.av-tech-pending, .av-tech-removed, .av-tech-removedlist')) continue;
    if ([...e.children].some(c => rx.test(c.textContent || ''))) continue;
    const t = (e.textContent || '').trim(), m = rx.exec(t); if (!m || t.length > 160) continue;
    let b = e.closest('.av-tech-out, .av-attack, article, section, dialog, [role=dialog], .card, details, body');
    if (b && b.classList.contains('av-tech-out')) b = b.parentElement;
    let s = boxes.get(b); if (!s) boxes.set(b, s = new Map()); s.set(m[1], (s.get(m[1]) || 0) + 1);
  }
  for (const [b, s] of boxes) for (const [k, c] of s) if (c > 1) dup.push(k + ' x' + c + ' in ' + String(b.className || b.tagName).slice(0, 40));
  return {n, pointer, lists, cut, dup: dup.slice(0, 8)}; }"""


def totp(secret):
    key = base64.b32decode(secret + "=" * (-len(secret) % 8), casefold=True)
    if 30 - int(time.time()) % 30 < 6:
        time.sleep(7)
    d = hmac.new(key, struct.pack(">Q", int(time.time()) // 30), hashlib.sha1).digest()
    o = d[-1] & 0x0F
    return f"{(struct.unpack('>I', d[o:o + 4])[0] & 0x7FFFFFFF) % 1_000_000:06d}"


def sign_in(ctx, acc):
    pg = ctx.new_page()
    pg.goto(urljoin(BASE, "/login"))
    with pg.expect_navigation():
        pg.evaluate("([u, p]) => { const f = document.forms[0]; f.username.value = u; f.password.value = p; f.submit(); }", [acc["name"], acc["pw"]])
    if acc.get("secret"):
        with pg.expect_navigation():
            pg.evaluate("(c) => { const i = document.querySelector('input[name=code]'); i.value = c; i.form.submit(); }", totp(acc["secret"]))
    time.sleep(1.5)
    if "/login" in pg.url:
        raise RuntimeError(f"sign-in failed for {acc['name']}")
    return pg


def pages_of(pg):
    pg.goto(urljoin(BASE, "/overview")); time.sleep(3)
    hrefs = pg.eval_on_selector_all("a[href]", "as => as.map(a => a.getAttribute('href'))")
    out = ["/overview", "/"]                              # the map page is the home page: not always among the links
    for h in hrefs:
        u = urlparse(urljoin(BASE, h))
        if u.netloc != urlparse(BASE).netloc or any(w in u.path for w in NEVER) or u.path in out:
            continue
        out.append(u.path)
    return out[:MAX_PAGES]


def tour_walk(pg):
    """The guided tour on this page (tour.js, 2026-11-20): the Tutorial button in the header, every step of the page whose
    part is on it, each step spotlighting something visible with its card on the screen, walked by keyboard to the end;
    Escape ends it; the focus goes back to the button. Returns the problems found."""
    if not pg.evaluate("!!document.querySelector('.hud-right, .mg-top-actions')"):
        return []
    probs = []
    if not pg.evaluate("!!window.LGTour"):
        return ["the tour (tour.js) is not loaded"]
    btn = pg.query_selector(".lg-tour-btn")
    if not btn or not btn.is_visible():
        return ["no Tutorial button in the header"]
    want = pg.evaluate("""() => { const T = window.LGTour, own = T.STEPS[T.pageKey()] || [];
        const vis = (n) => { const r = n.getBoundingClientRect(); return r.width > 2 && r.height > 2 && getComputedStyle(n).visibility !== 'hidden'; };
        return own.filter(([sel]) => [...document.querySelectorAll(sel)].some(vis)).map(s => s[1]); }""")
    have = pg.evaluate("window.LGTour.steps().map(s => s.title)")
    lost = [t for t in want if t not in have]
    if lost:
        probs.append(f"tour steps left out though their part is on the page: {lost}")
    if not pg.evaluate("(window.LGTour.STEPS[window.LGTour.pageKey()] || []).length") and pg.evaluate("location.pathname") != "/":
        probs.append(f"no tour steps for this page ({pg.evaluate('window.LGTour.pageKey()')})")
    # pressed as a keyboard user does: the map's Overview dialog over the page would block a mouse click (the tour
    # explains that dialog then)
    btn.evaluate("b => { b.focus(); b.click(); }")    # focused first, as a click or Enter on it leaves it
    time.sleep(.4)
    seen, bad = 0, []
    for _ in range(len(have) + 2):
        st = pg.evaluate("""() => { const c = document.querySelector('.lg-tour-card'); if (!c) return null;
            const s = document.querySelector('.lg-tour-spot').getBoundingClientRect(), r = c.getBoundingClientRect();
            return {t: c.querySelector('.lg-tour-title').textContent, x: (c.querySelector('.lg-tour-text').textContent || '').length,
                    spot: s.width > 4 && s.height > 4, on: r.top >= 0 && r.left >= 0 && r.bottom <= innerHeight + 1 && r.right <= innerWidth + 1,
                    focus: c.contains(document.activeElement)}; }""")
        if st is None:
            break
        seen += 1
        if not (st["spot"] and st["on"] and st["x"] and st["focus"]):
            bad.append(st["t"])
        pg.keyboard.press("ArrowRight")
        time.sleep(.35)                      # as a person reads: the step settled (scrolled, placed) before it is measured
    if seen != len(have):
        probs.append(f"the tour showed {seen} of its {len(have)} steps")
    if pg.evaluate("!!document.querySelector('.lg-tour')"):
        probs.append("the tour did not end after its last step")
    if bad:
        probs.append(f"tour steps off screen, pointing at nothing or losing the focus: {bad[:4]}")
    if not pg.evaluate("document.activeElement && document.activeElement.classList.contains('lg-tour-btn')"):
        probs.append("the focus did not go back to the Tutorial button")
    btn.evaluate("b => { b.focus(); b.click(); }")
    time.sleep(.3)
    pg.keyboard.press("Escape")
    time.sleep(.2)
    if pg.evaluate("!!document.querySelector('.lg-tour')"):
        probs.append("Escape did not end the tour")
    return probs


# RULE (the user, 2026-11-20: "this has to be a check ... make sure everywhere that needs a loading screen is well done"):
# every link to another page opens with the loading animation. Each such link on the page is clicked (a mouse click
# event), the loader's go() is watched instead of leaving the page, and a link the loader does not take is a problem.
LOADER_LINKS = r"""() => {
  if (!window.LGLoader) return ['the loader (loader.js) is not on this page'];
  const real = window.LGLoader.go, went = [];
  window.LGLoader.go = (u) => { went.push(u); };
  // after every other listener: never leave the page during the check
  const stop = (e) => { e.preventDefault(); };
  window.addEventListener('click', stop);
  const skip = /^\/(api|static|login|logout|forgot|enrol|welcome|organisation\/logo)(\/|$)/;
  const files = /\.(pdf|csv|zip|json|txt|png|svg)$/i, dl = /\/(report|preview|export)(\/|$)/;
  const out = [], seen = new Set();
  try {
    for (const a of document.querySelectorAll('a[href]')) {
      const r = a.getBoundingClientRect();
      if (!r.width || !r.height || a.target === '_blank' || a.hasAttribute('download') || a.dataset.noLoader != null) continue;
      const href = a.getAttribute('href'); if (!href.startsWith('/') || href.startsWith('//')) continue;
      const u = new URL(href, location.href);
      if (skip.test(u.pathname) || files.test(u.pathname) || dl.test(u.pathname)) continue;
      if (u.pathname === location.pathname && u.search === location.search) continue;
      const key = u.pathname + u.search; if (seen.has(key)) continue; seen.add(key);
      const n = went.length;
      a.dispatchEvent(new MouseEvent('click', { bubbles: true, cancelable: true, button: 0, view: window }));
      if (went.length === n) out.push(`${(a.textContent || a.getAttribute('aria-label') || '').trim().slice(0, 30)} -> ${key}`);
    }
  } finally {
    window.removeEventListener('click', stop);
    window.LGLoader.go = real;
  }
  return out.length ? ['opens without the loading animation: ' + out.slice(0, 6).join('; ')] : [];
}"""


def loader_links(pg):
    if pg.evaluate("!document.querySelector('.hud-right, .mg-top-actions')"):
        return []                                    # not a signed-in page with a header
    try:
        return pg.evaluate(LOADER_LINKS)
    except Exception as e:  # noqa: BLE001  a page that navigated anyway is itself the problem
        return [f"the loader check could not finish: {str(e)[:120]}"]


fails = 0
with sync_playwright() as p:
    br = p.chromium.launch()
    for role in ROLES:
        ctx = br.new_context(ignore_https_errors=True, viewport={"width": 1400, "height": 900})
        ctx.add_init_script(LOAD_WATCH)                   # before the page's own scripts, on every page
        # the tour's first-visit offer (tour.js) is not shown, so it never covers what is checked; the tour itself is
        # walked below on every page
        ctx.add_init_script("try { localStorage.setItem('lg.tour.never', '1') } catch (e) {}")
        try:
            pg = sign_in(ctx, ACCOUNTS[role])
        except Exception as e:                          # noqa: BLE001
            print(f"  FAIL {role}: {e}"); fails += 1; ctx.close(); continue
        errs = []
        pg.on("pageerror", lambda e: errs.append(f"script error: {str(e)[:120]}"))
        pg.on("response", lambda r: errs.append(f"server error {r.status} {urlparse(r.url).path}") if r.status >= 500 else None)
        pg.evaluate("try { sessionStorage.setItem('lg.introSeen', '1') } catch (e) {}")
        for path in pages_of(pg):
            errs.clear()
            # arriving as a person does from a page button (LGLoader.go): the logo the last page drew carries on
            pg.evaluate("try { sessionStorage.setItem('lg.arrive', 'Opening') } catch (e) {}")
            pg.goto(urljoin(BASE, path), wait_until="domcontentloaded")
            t0, quiet, settled = time.time(), 0, False
            while time.time() - t0 < 30:                  # settled: nothing loading for 3 s in a row (not before 4 s)
                time.sleep(.5)
                busy = pg.evaluate("(() => { const e = window.__lgLoad || []; const last = (k) => { const x = e.filter(v => v[0] === k).pop(); return x ? x[1] : false; };"
                                   " return last('line') || last('overlay'); })()")
                quiet = 0 if busy else quiet + .5
                if quiet >= 3 and time.time() - t0 >= 4:
                    settled = True
                    break
            events = pg.evaluate("window.__lgLoad || []")
            load_probs = loading_problems(events, settled)
            if load_probs:                                # what was loading, for whoever reads the failure
                load_probs.append("loading timeline " + str(events[-8:]) + " still showing: " + str(pg.evaluate(
                    "[...document.querySelectorAll('.i-loading, .st-loading, .lg-loading, .svc-loading, .kbn-loading, .mp-loading')]"
                    ".filter(e => e.offsetParent !== null).map(e => e.textContent.trim().slice(0, 40)).slice(0, 3)")))
            info = pg.evaluate(PAGE_JS, FOCUSABLE)
            # hover labels (header-tips.js, 2026-11-19): a header button says what it is at once, on hover
            tip = pg.evaluate("""() => { const b = [...document.querySelectorAll('.nav-ic, .hud-right a, .hud-right button, .mg-top-actions a, .mg-top-actions button')]
                .find(e => e.getBoundingClientRect().width > 0); if (!b) return 'none';
              b.dispatchEvent(new MouseEvent('mouseover', {bubbles: true}));
              const t = document.querySelector('.lg-htip'), r = t && !t.hidden ? t.textContent.trim() : '';
              b.dispatchEvent(new MouseEvent('mouseout', {bubbles: true, relatedTarget: document.body})); return r; }""")
            info["tip"] = tip
            pg.evaluate("document.activeElement && document.activeElement.blur(); window.scrollTo(0, 0)")
            reached, prev, same = set(), None, 0
            for _ in range(min(4000, info["n"] * 4 + 80)):            # long pages: enough presses to reach the end
                pg.keyboard.press("Tab")
                # inside an embedded page (the review page's Executive views) focus moves within the frame: not a trap
                k = pg.evaluate("""(() => { const a = document.activeElement; if (!a) return '';
                    if (a.tagName === 'IFRAME') { try { const i = a.contentDocument.activeElement; return 'frame:' + (i ? i.tagName + (i.textContent || '').slice(0, 20) + i.className : ''); } catch (e) { return 'frame'; } }
                    // every element its own identity: several unlabelled inputs in a row are not one stuck element
                    window.__kbid = window.__kbid || new WeakMap(); window.__kbn = window.__kbn || 0;
                    if (!window.__kbid.has(a)) window.__kbid.set(a, 'u' + (++window.__kbn));
                    return a.dataset.kb || window.__kbid.get(a); })()""")
                reached.add(k)
                same = same + 1 if k == prev else 0
                prev = k
                if same > 5:
                    break
            missed = pg.evaluate("(got) => [...document.querySelectorAll('[data-kb]')].filter(e => !got.includes(e.dataset.kb) && e.isConnected"
                                 " && e.getBoundingClientRect().width > 0).map(e => e.tagName.toLowerCase() + ': ' + (e.getAttribute('aria-label') ||"
                                 " e.textContent || e.value || '').trim().slice(0, 40)).slice(0, 8)", sorted(reached))
            tour = tour_walk(pg) + loader_links(pg)
            probs = tour + ([f"not reached by Tab: {missed}"] if missed else []) + (["focus trapped"] if same > 5 else []) + \
                    ([f"clickable but not a control: {info['pointer']}"] if info["pointer"] else []) + \
                    ([f"list holds a non-item: {info['lists']}"] if info["lists"] else []) + \
                    ([f"cut off with '…': {info['cut']}"] if info["cut"] else []) + \
                    ([f"MITRE ATT&CK shown twice: {info['dup']}"] if info.get("dup") else []) + \
                    (["a header button shows no hover label"] if info.get("tip") == "" else []) + load_probs + errs[:4]
            if probs:
                fails += 1
                print(f"  FAIL {role} {path}: " + " | ".join(probs))
            else:
                print(f"  ok   {role} {path} ({len([r for r in reached if r.isdigit()])}/{info['n']} controls by keyboard)")
        ctx.close()
    br.close()
print(f"\n{'all pages passed' if not fails else f'{fails} page(s) with a problem'}")
sys.exit(1 if fails else 0)
