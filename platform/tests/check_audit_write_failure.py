#!/usr/bin/env python3
"""An audit entry that cannot be written no longer vanishes (review 2026-11-15): while writes fail, the admins' bell says
so (system_alerts.py); once the log works again, the gap itself is the first entry written (audit_write_failed: how
many, between when and when, why), and the chain is still whole. A throwaway folder; no database, no service.
Run: .venv/bin/python tests/check_audit_write_failure.py"""
import errno, logging, os, sys, tempfile
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import auth, system_alerts as SA, audit_portal  # noqa: E402

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond: fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info else ""), flush=True)


class _Log(logging.Handler):
    def __init__(self): super().__init__(); self.errors = []
    def emit(self, r):
        if r.levelno >= logging.ERROR: self.errors.append(r.getMessage())


with tempfile.TemporaryDirectory() as tmp:
    plat = os.path.join(tmp, "platform"); os.makedirs(os.path.join(plat, "data"))
    log = logging.getLogger("lg-audit-write-test"); h = _Log(); log.addHandler(h); log.propagate = False
    a = auth.Audit(os.path.join(plat, "data", "audit.log"), logger=log)
    alerts = SA.Alerts(plat, env={})
    a.add("login", user="grace", ip="127.0.0.1", ua="t")
    print("While the disk is full")
    real = a.chain.append

    def full(rec):
        raise OSError(errno.ENOSPC, "No space left on device")
    a.chain.append = full
    for u in ("daniel", "sarah", "rachel"):
        a.add("login", user=u, ip="127.0.0.1", ua="t")
    keys = {x["key"].split(":")[0]: x for x in alerts.current()}
    ok("the bell says the audit log cannot be written", "audit-write" in keys and keys["audit-write"]["problem"])
    ok("…with how many entries and why", "3 audit entries" in keys.get("audit-write", {}).get("text", "")
       and "No space left" in keys.get("audit-write", {}).get("text", ""), keys.get("audit-write", {}).get("text", ""))
    ok("each failure is logged as an error, not a warning", len(h.errors) == 3 and "NOT written" in h.errors[0])
    print("Once it can be written again")
    a.chain.append = real
    a.add("logout", user="grace", ip="127.0.0.1", ua="t")
    recs = a.records()
    ev = [r["event"] for r in recs]
    ok("the gap is written first, then the new entry", ev[-2:] == ["audit_write_failed", "logout"], ev)
    ok("…saying how many entries, between when and when, and why",
       "3 audit entries could not be written between" in recs[-2]["detail"] and "No space left" in recs[-2]["detail"], recs[-2]["detail"])
    keys = {x["key"].split(":")[0]: x for x in alerts.current()}
    ok("the bell now says entries were lost (no longer 'cannot be written')", "audit-gap" in keys and "audit-write" not in keys)
    v = a.chain.verify()
    ok("the chain is still whole", v["ok"] and not v["break"], v.get("break"))
    ok("the Audit portal names the event and marks it as an alert",
       audit_portal.LABEL.get("audit_write_failed") and audit_portal.ALERT.search("audit_write_failed"))
    SA.note_audit_write(None)
    SA._AUDIT["recovered"] = None

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
