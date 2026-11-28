#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""The whole-codebase review's server-side follow-ups (2026-11-27) that the page scripts rely on:
- Pipeline e-mail checks: each change row names who made it by full name, else person code, never the sign-in name;
- a combination's review sends every note (the page shows the first 12, says "The first 12 of N", and offers Show all);
- the Task monitor names each process and account by person code, with a shown name.
Run: .venv/bin/python tests/check_fix_lead.py"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("LG_PERSON_CODE_DIR", tempfile.mkdtemp(prefix="lg-pc-"))
ROOT = os.environ.get("LG_FIX_LEAD_ROOT") or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info and not cond else ""), flush=True)


def src(name):
    with open(os.path.join(ROOT, name), encoding="utf-8") as fh:
        return fh.read()


import people  # noqa: E402

SIGNIN = "lg-check-someone"

print("Pipeline e-mail checks (sender_audit.py)")
try:
    import sender_audit as SA
    shown = getattr(SA, "_shown", None)
    ok("a change's author is shown by person code when there is no full name", shown is not None and shown(SIGNIN) == people.person_label(SIGNIN)
       and shown(SIGNIN).startswith("p-"), shown(SIGNIN) if shown else "no _shown")
    ok("...and nobody named stays empty", shown is not None and shown("") == "")
    s = src("sender_audit.py")
    ok("the change rows send by_name, not the sign-in name", '"by_name": _shown(e.get("user", ""))' in s and '"user": e.get("user", "")' not in s)
except Exception as e:                                           # noqa: BLE001
    ok("sender_audit loads", False, repr(e))

print("A combination's review (combo_review.py)")
s = src("combo_review.py")
ok("every note is sent (no cut to 12 on the server)", "notes = notes[:12]" not in s and "notes_total = len(notes)" in s)

print("Task monitor (task_monitor.py)")
try:
    import task_monitor as TM
    rows = TM._named([{"user": SIGNIN, "route": "/x"}, {"user": "(signing in)", "route": "/y"}])
    ok("a process is named by person code, with a shown name", rows[0]["user"] == people.person_label(SIGNIN)
       and rows[0].get("user_label") and SIGNIN not in str(rows[0]), str(rows[0]))
    ok("...and a request still signing in stays as it is", rows[1]["user"] == "(signing in)", str(rows[1]))
except Exception as e:                                           # noqa: BLE001
    ok("task_monitor names its rows", False, repr(e))

print("The advisory editor keeps unsaved words across a redraw (advisory.js held copy; behaviour: scratchpad lead/pv_adv.py in Chromium)")
held = os.environ.get("LG_HELD_DIR", "")
adv_path = os.path.join(held, "advisory.js.new") if held and os.path.exists(os.path.join(held, "advisory.js.new")) \
    else os.path.join(ROOT, "static", "js", "advisory.js")
with open(adv_path, encoding="utf-8") as fh:
    ADV = fh.read()
dr = ADV.split("  function draw() {", 1)[1].split("\n  }\n", 1)[0] if "  function draw() {" in ADV else ""
ok("draw() reads what was typed before the redraw and puts it back after, for the same network only",
   "const keep = typedNow();" in dr and "typedBack(keep)" in dr and 'main.dataset.formFor = String(NET)' in ADV
   and all(f'"{k}"' in ADV.split("const TYPED = [", 1)[-1].split("]", 1)[0] for k in ("subject", "description", "actions", "recipients", "insights",
                                                                                      "look", "brand"))
   and 'look.dataset.fk = "look"' in ADV and 'brand.dataset.fk = "brand"' in ADV)
rn = ADV.split("const run = async (button, work) => {", 1)[-1].split("\n    };\n", 1)[0]
ok("...and after a save that went through, the form is drawn from what the server saved, not the words typed before it",
   "delete main.dataset.formFor;" in rn and rn.index("delete main.dataset.formFor;") < rn.rindex("draw();"))
held_svc = os.path.join(held, "services.js.new") if held and os.path.exists(os.path.join(held, "services.js.new")) \
    else os.path.join(ROOT, "static", "js", "services.js")
with open(held_svc, encoding="utf-8") as fh:
    SVC = fh.read()
esc = SVC.split('if (e.key === "Escape") {', 1)[-1].split("else if (e.target.matches", 1)[0]
ok("Services: one Escape closes one layer, and an Escape a drop-down used closes nothing more",
   "if (e.defaultPrevented) return;" in esc and "closeInsight(); closeModal(); closeGlossary();" not in SVC)

print("Sessions and sign-out (auth.py)")
s = src("auth.py")
ok("the sessions answer names each by shown name and person code (the Audit portal's 'Signed in now')",
   "user_label=people.signed_by(s[\"user\"])" in s and "person_code=people.person_label(s[\"user\"])" in s)
lo = s.split("def logout():", 1)[-1].split("\n    @app.route", 1)[0]
ok("signing out needs the session's own CSRF token, compared in constant time (behaviour: check_cov_auth_routes)",
   'request.form.get("csrf_token"' in lo and "hmac.compare_digest(" in lo and 'live.get("csrf")' in lo)

fg = s.split('return page("forgot.html", 401, mode=mode, username=', 1)[-1][:60]
ok("a failed password reset fills the typed name back in only when it is an account (a password typed there never returns)",
   fg.startswith("name if is_account(name) else"))

print("An advisory preview's watermark shows on both looks (combo_pdf.py; the user, 2026-11-27: gone on white pages)")
try:
    import combo_pdf as CP
    import test_tools
    PDFIUM = test_tools.find_pypdfium2()
    if PDFIUM is None:
        raise RuntimeError("pypdfium2 is needed to render the pages")

    def page_pixels(look, preview):
        adv = {"look": look, "tlp": "TLP:AMBER", "tlp_colour": "#FFC000"}
        if preview:
            adv["preview"] = {"who": "Ama Owusu", "at": "2026-11-27 20:00 UTC", "ref": "ADV-1"}
        d = CP.AnalystDoc({"advisory": adv, "header": "LG-C-1", "platform_label": "Services", "scope": "whole country"})
        d.new_page("Advisory")
        data = d.done()
        data = data if isinstance(data, (bytes, bytearray)) else d.buf.getvalue()
        img = PDFIUM.PdfDocument(data)[0].render(scale=1).to_pil().convert("L")
        w, h = img.size
        return img.crop((0, int(h * .15), w, int(h * .88)))       # the page's body: no header, no footer lines

    def changed(look):
        a, b = page_pixels(look, False), page_pixels(look, True)
        pa, pb = a.load(), b.load()
        return sum(1 for x in range(a.size[0]) for y in range(a.size[1]) if abs(pa[x, y] - pb[x, y]) >= 3)

    plain, dark = changed("plain"), changed("designed")
    ok("the white (plain) look: the diagonal watermark is visible on the page body", plain > 2000, f"{plain} pixels changed")
    ok("the designed (dark) look: still visible", dark > 2000, f"{dark} pixels changed")
except Exception as e:                                           # noqa: BLE001
    ok("the advisory preview renders", False, repr(e))

print()
print(f"{checks - len(fails)}/{checks} checks passed")
sys.exit(1 if fails else 0)
