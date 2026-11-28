#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""The Findings page's wording and reply box (static/js/findings.js, the held copy $LG_HELD_DIR/findings.js.new when
there is one): node runs the page itself on made-up findings and the cards it draws are read back. A closed finding
takes no reply; a sub-finding takes none either (replies go on its case); only the researchers an analyst's code is for
see "Reply to the analyst"; sub-findings of other channels are explained as such, never as "closed before this case
was opened again". Run: .venv/bin/python tests/check_findings_ui.py"""
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
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info and not cond else ""))


if not H.NODE:
    print("SKIPPED: no node to run the page with"); sys.exit(77)


def finding(i, **kw):
    f = {"id": str(i), "number": f"F-{i:03d}", "title": f"Finding {i}", "name": "made_up_name", "display_name": "Made-up name",
         "text": "A made-up note.", "codes": [], "status": "new", "status_label": "New", "history": [], "open": True,
         "origin": "researcher", "parent": "", "kind": "", "children": [], "requests": [], "network": "", "review": None,
         "advisories": [], "channel": [], "role": "Researcher/TI", "by": "Rita Researcher", "created": "2026-01-02 10:00",
         "updated": "2026-01-02 10:00", "section": "infections", "assignee": "", "replies": 0}
    f.update(kw)
    return f


FINDINGS = [finding(1), finding(2, origin="analyst"), finding(3, open=False, status="closed", status_label="Closed"),
            finding(4, kind="case", children=["5", "98", "99"]),          # 98 and 99 are in another channel
            finding(5, parent="4", network="Made-up Org A")]

JS = r"""
N.prototype.contains = function (x) { while (x) { if (x === this) return true; x = x.parent; } return false; };
document.activeElement = null;
const D = JSON.parse(process.argv[1]);
ROUTES.push(["/api/findings?state=", 200, D]);
""" + H.page_src("findings.js") + r"""
setTimeout(() => {
  const cards = {};
  for (const c of IDS.fdList.all().filter((n) => n.tag === "article" && /^f\d+$/.test(n.id || ""))) {
    const rp = c.children.find((x) => x.tag === "details" && x._cls.has("fd-replybox"));
    cards[c.id.slice(1)] = { reply: rp ? rp.children[0].textContent : null };
  }
  console.log(JSON.stringify({ cards, text: lines(IDS.fdList), errs: ERRS }));
}, 300);
"""


def page(can_research):
    out, raw = H.run(JS, {"findings": FINDINGS, "statuses": [{"key": "new", "label": "New"}, {"key": "closed", "label": "Closed"}],
                          "can_research": can_research, "can_decide": False, "can_advise": False})
    return out or {"cards": {}, "text": [], "errs": [raw[-400:]]}


res = page(True)
C = res["cards"]
ok("the page draws every card without an error", set(C) == {"1", "2", "3", "4", "5"} and not res["errs"], f"{sorted(C)} {res['errs']}")
ok("an open finding takes a reply", (C.get("1") or {}).get("reply") == "Reply", str(C.get("1")))
ok("a closed finding shows no reply box", "3" in C and C["3"]["reply"] is None, str(C.get("3")))
ok("a sub-finding shows none (replies go on its case), its case does", "5" in C and C["5"]["reply"] is None
   and (C.get("4") or {}).get("reply") == "Reply", f"{C.get('4')} {C.get('5')}")
ok("'Reply to the analyst' for a researcher on an analyst's code", (C.get("2") or {}).get("reply") == "Reply to the analyst", str(C.get("2")))
ok("...and plainly 'Reply' on a researcher's own finding", (C.get("1") or {}).get("reply") == "Reply")
res2 = page(False)
ok("'Reply' (not 'to the analyst') for someone who is not a researcher", (res2["cards"].get("2") or {}).get("reply") == "Reply",
   str(res2["cards"].get("2")))
want = "2 other sub-findings of this case are not in your channel, so they are not shown here."
ok("hidden sub-findings are explained as other channels", want in res["text"], str([t for t in res["text"] if "sub-finding" in t]))
ok("...never as 'opened again'", not any("opened again" in t for t in res["text"]))

pdf = open(os.path.join(H.PF, "advisory_pdf.py"), encoding="utf-8").read()
front = pdf[pdf.index("def front("):pdf.index("def front(") + 1200]
ok("the advisory report shows no workflow status (no 'Draft')", '("Status"' not in front and "status_label" not in front)
print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
