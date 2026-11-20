#!/usr/bin/env python3
"""The sender check's week and its hints (mail_auth.readiness, mail_auth.hint; 2026-11-15):
- each kind of failure gets a plain hint, and a changed body points at the mail gateway
- ready to block only when, on each of the last 7 days, e-mails passed and none failed
- an e-mail that could not be checked (DNS did not answer) never counts as passed, and when the newest day's e-mails
  could not be checked at all, the check is said to have stopped working
Throwaway mail states only. Run: .venv/bin/python tests/test_sender_readiness.py"""
import datetime as dt, sqlite3, sys, tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import mail_auth as MA  # noqa: E402

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info else ""), flush=True)


print("Hints")
h = MA.hint("fail", "the body was changed after it was signed (body hash differs)")
ok("a changed body: the mail gateway, and deliver Shadowserver's mail unmodified", "gateway" in h and "unmodified" in h, h)
ok("a changed signed header: subject tagging", "subject" in MA.hint("fail", "the signature does not match the signed headers").lower())
ok("no signature: a forward or a copy", "forward" in MA.hint("none", "no DKIM signature"))
ok("another signer: a forward or a mailing list", "mailing list" in MA.hint("other", "signed by lists.example.org, not shadowserver.org"))
ok("a DNS time-out: checked again next run", "next run" in MA.hint("temperror", "DNS did not answer for mail._domainkey.shadowserver.org (LifetimeTimeout)"))
ok("a doubled header: treat as suspicious", "suspicion" in MA.hint("permerror", "the message's header block is ambiguous (two From): not checked"))
ok("a pass has no hint", MA.hint("pass", "") == "")

NOW = dt.datetime(2026, 11, 15, 12, 0, tzinfo=dt.timezone.utc)


def state(rows):
    d = tempfile.mkdtemp(); p = Path(d) / ".mail_state.sqlite"
    log = MA.Log(p); log.close()
    con = sqlite3.connect(p)
    for i, (day_back, result, reason) in enumerate(rows):
        at = (NOW - dt.timedelta(days=day_back)).isoformat(timespec="seconds")
        con.execute("INSERT INTO mail_auth (key, at, result, reason) VALUES (?, ?, ?, ?)", (f"k{i}", at, result, reason))
    con.commit(); con.close()
    return p


print("The week")
week = MA.readiness(state([(b, "pass", "") for b in range(7) for _ in range(3)]), now=NOW)
ok("every day passed, none failed: ready", week["ready"] and week["days_passing"] == 7 and week["passed"] == 21 and not week["not_checking"])
week = MA.readiness(state([(b, "pass", "") for b in range(6)]), now=NOW)
ok("a day without mail: not ready yet", not week["ready"] and week["days_passing"] == 6)
week = MA.readiness(state([(b, "pass", "") for b in range(7)] + [(2, "fail", "the body was changed after it was signed (body hash differs)")]), now=NOW)
ok("one failure in the week: not ready, and the failure is listed with its hint",
   not week["ready"] and week["failed"] == 1 and week["failures"][0]["count"] == 1 and "gateway" in week["failures"][0]["hint"])
dns = "DNS did not answer for mail._domainkey.shadowserver.org (LifetimeTimeout)"
week = MA.readiness(state([(b, "pass", "") for b in (6, 5, 4, 3)] + [(b, "temperror", dns) for b in (2, 1, 0) for _ in range(5)]), now=NOW)
ok("days where nothing could be checked never count as passed", not week["ready"] and week["days_passing"] == 4 and week["unchecked"] == 15)
ok("…and the newest day all unchecked: the check has stopped working", week["not_checking"] and week["failed"] == 0)
week = MA.readiness(state([(b, "pass", "") for b in range(7)] + [(0, "temperror", dns)]), now=NOW)
ok("one DNS time-out among passes: still ready, and not 'stopped'", week["ready"] and not week["not_checking"] and week["unchecked"] == 1)
week = MA.readiness(state([(9, "pass", "")] + [(b, "pass", "") for b in range(7)]), now=NOW)
ok("only the last 7 days count", week["total"] == 7 and week["from"] == "2026-11-09")
ok("no mail state yet: nothing to say", MA.readiness(Path(tempfile.mkdtemp()) / ".mail_state.sqlite") == {})

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
