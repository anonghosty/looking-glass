#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""Services page filters (static/js/services.js; the held copy $LG_HELD_DIR/services.js.new when there is one): node
runs the page's own withChosen, chips and checklist on made-up facets. A value the person chose stays in its menu even
when the new facets (after another filter changed) no longer have it: listed with 0, shown as chosen, so it can be seen
and taken off; once taken off it is gone. A value the facets do have is listed once (a number and its text are the same
value), with its own count. Run: .venv/bin/python tests/check_services_withchosen.py"""
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

JS = H.extract(H.page_src("services.js"), ["el", "withChosen", "chips", "checklist"]) + r"""
let changed = 0; const filtersChanged = () => { changed++; };
const fmt = (n) => Number(n || 0).toLocaleString("en-US");
const attachTip = () => {}; const defOf = () => null; const tipLine = (x) => x;
const state = { filters: { family: new Set(["Made-up family B"]), service: new Set(["Made-up report Z", "Made-up report A"]), issue: new Set(["443"]) } };
const R = {};
R.rows = withChosen([{ value: "Made-up family A", label: "Made-up family A", count: 12 }], "family");
R.none = withChosen([{ value: "Made-up family A", label: "Made-up family A", count: 12 }, { value: "Made-up family B", label: "Made-up family B", count: 3 }], "family");
R.num = withChosen([{ value: 443, label: "443", count: 7 }], "issue");
R.untouched = withChosen([{ value: "x", label: "x", count: 1 }], "family") && [...state.filters.family];
const box = document.createElement("div");
chips(box, "family", [{ value: "Made-up family A", label: "Made-up family A", count: 12 }], () => "#000");
R.chips = box.children.map((b) => [lines(b).join(" | "), b.getAttribute("aria-pressed")]);
box.children.find((b) => b.dataset.fv === "Made-up family B").click();
R.after = { changed, chosen: [...state.filters.family] };
chips(box, "family", [{ value: "Made-up family A", label: "Made-up family A", count: 12 }], () => "#000");
R.gone = box.children.map((b) => b.dataset.fv);
const ul = document.createElement("ul");
checklist(ul, "service", [{ value: "Made-up report A", label: "Made-up report A", count: 5 }], "", () => "#000");
R.list = ul.children.map((li) => [lines(li).join(" | "), li.querySelector("input").checked]);
checklist(ul, "service", [{ value: "Made-up report A", label: "Made-up report A", count: 5 }], "report z", () => "#000");
R.search = ul.children.map((li) => lines(li).join(" | "));
checklist(ul, "service", [], "nothing like it", () => "#000");
R.empty = lines(ul);
console.log(JSON.stringify(R));
"""
R, raw = H.run(JS)
R = R or {}
ok("the page's filter functions run", bool(R), raw[-400:])
ok("a chosen value the new facets lack stays listed, with 0", R.get("rows") == [{"value": "Made-up family A", "label": "Made-up family A", "count": 12},
   {"value": "Made-up family B", "label": "Made-up family B", "count": 0}], R.get("rows"))
ok("...one the facets have is listed once, with its own count", R.get("none") == [{"value": "Made-up family A", "label": "Made-up family A", "count": 12},
   {"value": "Made-up family B", "label": "Made-up family B", "count": 3}], R.get("none"))
ok("...a number and its text are the same value (listed once)", R.get("num") == [{"value": 443, "label": "443", "count": 7}], R.get("num"))
ok("...and listing it changes nothing that was chosen", R.get("untouched") == ["Made-up family B"], R.get("untouched"))
ok("the chips show it as chosen, with 0", R.get("chips") == [["Made-up family A | 12", "false"], ["Made-up family B | 0", "true"]], R.get("chips"))
ok("...so it can be taken off (the filters change)", R.get("after") == {"changed": 1, "chosen": []}, R.get("after"))
ok("...and once taken off it is no longer listed", R.get("gone") == ["Made-up family A"], R.get("gone"))
ok("the report checklist keeps both chosen reports, ticked, the missing one with 0",
   R.get("list") == [["Made-up report A | 5", True], ["Made-up report Z | 0", True]], R.get("list"))
ok("...its search finds a chosen report the facets lack", R.get("search") == ["Made-up report Z | 0"], R.get("search"))
ok("...a search that matches nothing says so", R.get("empty") == ["No match"], R.get("empty"))

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
