#!/usr/bin/env python3
"""The Findings page's wording and reply box (static/js/findings.js): a closed finding takes no reply; only the
researchers an analyst's code is for see "Reply to the analyst"; sub-findings of other channels are explained as
such, never as "closed before this case was opened again". Run: .venv/bin/python tests/check_findings_ui.py"""
import os, sys
js = open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "static", "js", "findings.js"), encoding="utf-8").read()
checks, fails = 0, []


def ok(label, cond):
    global checks
    checks += 1
    if not cond: fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}")


ok("a closed finding shows no reply box", "if (!f.parent && f.open) c.append(rp)" in js)
ok("'Reply to the analyst' only for researchers", 'f.origin === "analyst" && data.can_research ? "Reply to the analyst" : "Reply"' in js)
ok("hidden sub-findings are explained as other channels", "not in your channel" in js and "opened again" not in js)
print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
