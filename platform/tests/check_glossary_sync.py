#!/usr/bin/env python3
"""The documentation's glossary (docs/GLOSSARY.md) is generated from the in-app one (static/js/glossary.js) by
tools/glossary_md.py: this check regenerates it into a copy and fails when the two differ, so a term added in one place
only (by hand in GLOSSARY.md, or in the app without regenerating) is caught (2026-11-16: one was).
Run: .venv/bin/python tests/check_glossary_sync.py"""
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
JS = os.path.join(HERE, "static", "js", "glossary.js")
MD = next((p for p in (os.path.join(HERE, "..", "docs", "GLOSSARY.md"),                       # the published repository
                       os.path.join(HERE, "tools", "release_root", "docs", "GLOSSARY.md"))      # the development tree
           if os.path.exists(p)), None)
TOOL = next((p for p in (os.path.join(HERE, "tools", "glossary_md.py"), os.path.join(HERE, "..", "tools", "glossary_md.py"))
             if os.path.exists(p)), None)
if not (MD and TOOL and os.path.exists(JS)):
    print("SKIPPED: the glossary, its documentation page or the generator is not in this copy"); sys.exit(77)
tmp = tempfile.mkdtemp()
try:
    copy = os.path.join(tmp, "GLOSSARY.md")
    shutil.copy(MD, copy)
    r = subprocess.run([sys.executable, TOOL, JS, copy], capture_output=True, text=True, timeout=120)
    same = r.returncode == 0 and open(copy, encoding="utf-8").read() == open(MD, encoding="utf-8").read()
    print(f"  {'ok  ' if same else 'FAIL'} docs/GLOSSARY.md is exactly what the in-app glossary generates"
          + ("" if same else f"  [run: python3 tools/glossary_md.py; {r.stderr.strip()[:200]}]"))
    print(f"\n{1 if same else 0}/1 checks passed")
    sys.exit(0 if same else 1)
finally:
    shutil.rmtree(tmp, ignore_errors=True)
