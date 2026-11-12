"""Audit portal → Sender check: who really sent the reports, as evidence for the auditor (read only).

The pipeline checks every report e-mail's DKIM signature (mail_auth.py) and records the result in its
.mail_state.sqlite (table mail_auth) and, when blocking is on, keeps held-back reports in quarantine/mail_auth/. This
module reads both, read-only, for the period chosen in the portal: figures, results per day, the signing keys seen
(domain, selector, algorithm, key size), every report that did not pass and what happened to it (kept, held back,
released, tried again), the settings and releases from the audit log, and what the current standards ask next to what
the evidence shows. Like the control checks, it gives evidence only, no verdict: the auditor decides.

Standards cited (current as of 2026-11): RFC 6376 (DKIM signatures), RFC 8301 (DKIM cryptographic algorithm and key
usage update), RFC 8463 (Ed25519 for DKIM), RFC 7489 (DMARC, identifier alignment), NIST SP 800-177 Rev. 1
(Trustworthy Email), NIST SP 800-53 Rev. 5 SI-7 (software, firmware and information integrity).
"""
import sqlite3
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

from flask import jsonify, request

import pipeline_link

RESULTS = ("pass", "other", "fail", "none", "temperror", "permerror")
MEANING = {"pass": "signed by the expected domain, signature valid", "other": "valid signature, but by another domain",
           "fail": "signature does not verify: changed on the way, or forged", "none": "not signed",
           "temperror": "DNS did not answer: not held against the report", "permerror": "signature cannot be checked"}
ACTIONS = {"kept": "processed", "quarantined": "held back", "released": "released by an administrator", "retry": "tried again next run"}


def _period():
    today = datetime.now(timezone.utc).date()

    def d(v, dflt):
        try:
            return datetime.strptime(str(v or "")[:10], "%Y-%m-%d").date()
        except ValueError:
            return dflt
    to = d(request.args.get("to"), today)
    fr = d(request.args.get("from"), to - timedelta(days=29))
    fr, to = min(fr, to), max(fr, to)
    fr = max(fr, to - timedelta(days=731))
    return fr, to


def standards(rows, mode_now):
    """[{ref, title, asks, shows}]: each standard's requirement next to this installation's evidence (no verdict)."""
    n = len(rows)
    algs = Counter(r["alg"] for r in rows if r["alg"])
    bits = Counter(r["bits"] for r in rows if r["bits"])
    signed = [r for r in rows if r["result"] in ("pass", "other")]
    aligned = sum(1 for r in signed if r["signer"] and r["from_domain"] and
                  (r["from_domain"] == r["signer"] or r["from_domain"].endswith("." + r["signer"])))
    fails = [r for r in rows if r["result"] in ("fail", "none", "other", "permerror")]
    handled = Counter(ACTIONS.get(r["action"] or "kept", r["action"]) for r in fails)
    pct = lambda a, b: f"{a / b:.0%}" if b else "–"
    return [
        {"ref": "RFC 6376 §6", "title": "DKIM: verifying a signature",
         "asks": "The verifier checks the signature with the public key the signing domain publishes in DNS, over the signed "
                 "headers and the body as received.",
         "shows": f"{n:,} report e-mails checked in the period, on the message exactly as downloaded, with the key from DNS; "
                  f"{sum(1 for r in rows if r['result'] == 'pass'):,} valid signatures by the expected domain ({pct(sum(1 for r in rows if r['result'] == 'pass'), n)})."},
        {"ref": "RFC 8301 §3.1", "title": "Algorithms",
         "asks": "rsa-sha1 MUST NOT be used for signing or verifying; rsa-sha256 is required.",
         "shows": (("Algorithms of the valid signatures: " + ", ".join(f"{a} ({c:,})" for a, c in algs.most_common()) + ".")
                   if algs else "No valid signature in the period.") + " rsa-sha1 is not accepted by this check (recorded as permerror)."},
        {"ref": "RFC 8301 §3.2", "title": "Key sizes",
         "asks": "Signers MUST use RSA keys of at least 1024 bits and SHOULD use at least 2048 bits; verifiers MUST be able to "
                 "validate keys of 1024 to 4096 bits.",
         "shows": ("Key sizes of the valid signatures: " + ", ".join(f"{b} bits ({c:,})" for b, c in sorted(bits.items()))) if bits
                  else "No valid signature in the period."},
        {"ref": "RFC 8463", "title": "Ed25519 signatures",
         "asks": "Verifiers should accept ed25519-sha256 signatures next to rsa-sha256.",
         "shows": "This check verifies ed25519-sha256 as well as rsa-sha256."},
        {"ref": "RFC 7489 §3.1", "title": "DMARC identifier alignment",
         "asks": "A DKIM pass counts for the author only when the signing domain matches the From domain (relaxed: same "
                 "organisational domain).",
         "shows": f"{aligned:,} of {len(signed):,} validly signed reports were signed by their From domain or its parent ({pct(aligned, len(signed))})."},
        {"ref": "NIST SP 800-177 Rev. 1", "title": "Trustworthy Email",
         "asks": "Receivers should verify DKIM signatures on incoming mail and use the result in deciding how to handle the message.",
         "shows": {"enforce": "Now: reports that do not pass are held back until an administrator releases them.",
                   "log": "Now: every result is recorded; reports that do not pass are still processed (record only).",
                   "off": "Now: the sender check is switched off."}.get(mode_now, "Now: unknown")},
        {"ref": "NIST SP 800-53 Rev. 5 SI-7", "title": "Information integrity",
         "asks": "Detect unauthorised changes to information, and take defined actions when one is found.",
         "shows": (f"{len(fails):,} reports in the period did not pass; what happened to them: "
                   + ", ".join(f"{a} {c:,}" for a, c in handled.most_common())) if fails else "Every report in the period passed."},
    ]


def install(app, ctx):
    """ctx: base_dir, has_perm, audit, report_entry(name) -> the report map's entry or None (optional)."""
    hp, audit = ctx["has_perm"], ctx["audit"]

    @app.route("/api/audit/sender")
    def api_audit_sender():
        if not hp("audit"):
            return jsonify(error="The Audit portal is for the auditor role and administrators (permission 'audit')."), 403
        fr, to = _period()
        d = pipeline_link.find_dir(ctx["base_dir"])
        if not d:
            return jsonify(found=False, message="The database pipeline is not on this computer, so its sender check cannot be read here.")
        env = pipeline_link.read_env(d / ".env")
        ma = pipeline_link.mail_auth(d)
        mode_now = ma.mode(env) if ma else "off"
        lo, hi = fr.isoformat(), (to + timedelta(days=1)).isoformat()
        rows, api_rows, type_rows = [], [], []
        db = d / ".mail_state.sqlite"
        if db.exists():
            con = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=5)
            con.row_factory = sqlite3.Row
            try:
                cols = {r[1] for r in con.execute("PRAGMA table_info(mail_auth)")}
                if cols:
                    sel = ", ".join(c if c in cols else f"'' AS {c}" for c in
                                    ("at", "from_domain", "signer", "result", "reason", "subject", "files", "action", "alg", "bits", "selector"))
                    rows = [dict(r) for r in con.execute(f"SELECT {sel} FROM mail_auth WHERE at >= ? AND at < ? ORDER BY at", (lo, hi))]
                # reports fetched through Shadowserver's report API (report_api.py): no e-mail, so no DKIM; the
                # requests are signed with the API secret (HMAC2) and the files come from Shadowserver over HTTPS
                if con.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='api_files'").fetchone():
                    api_rows = [dict(r) for r in con.execute("SELECT at, file, bytes FROM api_files WHERE at >= ? AND at < ?", (lo, hi))]
                # report types (report_types.py): every type that ever arrived, by e-mail or API; the starting point is
                # marked baseline, the others arrived for the first time later
                if con.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='report_types'").fetchone():
                    type_rows = [dict(r) for r in con.execute("SELECT name, first_seen, baseline FROM report_types ORDER BY first_seen DESC")]
            finally:
                con.close()
        for r in rows:
            r["bits"] = int(r["bits"] or 0)
            r["action"] = r["action"] or "kept"
        c = Counter(r["result"] for r in rows)
        acts = Counter(r["action"] for r in rows)
        per_day = defaultdict(Counter)
        for r in rows:
            per_day[r["at"][:10]][r["result"]] += 1
        for r in api_rows:
            per_day[r["at"][:10]]["api"] += 1
        days, cur = [], fr
        while cur <= to:
            k = cur.isoformat()
            days.append({"day": k, **{res: per_day[k][res] for res in RESULTS}, "api": per_day[k]["api"]})
            cur += timedelta(days=1)
        keys = Counter((r["signer"], r["selector"], r["alg"], r["bits"]) for r in rows if r["result"] in ("pass", "other"))
        held = ma.held(d) if ma else []
        odd = [{k: r[k] for k in ("at", "result", "action", "from_domain", "signer", "reason", "subject", "files")}
               | {"meaning": MEANING.get(r["result"], ""), "action_label": ACTIONS.get(r["action"], r["action"])}
               for r in rows if r["result"] != "pass"][-300:][::-1]
        t0 = datetime(fr.year, fr.month, fr.day, tzinfo=timezone.utc).timestamp()
        t1 = datetime(to.year, to.month, to.day, tzinfo=timezone.utc).timestamp() + 86400
        changes = [{"at": datetime.fromtimestamp(e.get("t") or 0, timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
                    "event": e.get("event"), "user": e.get("user", ""), "detail": e.get("detail", "")}
                   for e in audit.records() if t0 <= (e.get("t") or 0) < t1 and (
                       e.get("event") in ("sender_release", "pipeline_apikey_saved", "pipeline_unlock_failed")
                       or (e.get("event") == "pipeline_settings_saved" and "MAIL_AUTH" in (e.get("detail") or "")))]
        n = len(rows)
        source_now = "api" if (env.get("REPORT_SOURCE") or "").strip().lower() == "api" else "email"
        # new report types: arrived for the first time after the starting point; does the report map (definitions,
        # from Shadowserver's schema through the feed) know each one yet?
        entry = ctx.get("report_entry") or (lambda n: None)
        new_types = []
        for t in type_rows:
            if t["baseline"]:
                continue
            e = entry(t["name"]) or {}
            known = bool(e) and e.get("in_schema", True) is not False
            new_types.append({"name": t["name"], "first_seen": (t["first_seen"] or "").replace("T", " ")[:16] + " UTC",
                              "known": known, "title": e.get("title") or e.get("name") or "" if known else "",
                              "note": "in the report definitions" if known else "new report, no definition yet"})
        types = {"recorded": len(type_rows), "since": min((t["first_seen"] for t in type_rows), default="")[:10],
                 "new": new_types, "new_without_definition": sum(1 for t in new_types if not t["known"])}
        return jsonify(found=True, period={"from": fr.isoformat(), "to": to.isoformat()}, mode=mode_now, source=source_now,
                       types=types,
                       api={"files": len(api_rows), "bytes": sum(int(r["bytes"] or 0) for r in api_rows)},
                       domain=env.get("MAIL_AUTH_DOMAIN") or "shadowserver.org",
                       kpis={"checked": n, **{r: c[r] for r in RESULTS}, "pass_rate": (c["pass"] / n) if n else None,
                             "held_back": acts["quarantined"], "released": acts["released"], "retried": acts["retry"],
                             "held_now": len(held)},
                       meaning=MEANING, per_day=days,
                       keys=[{"signer": s, "selector": sel, "alg": a, "bits": b, "reports": k} for (s, sel, a, b), k in keys.most_common()],
                       odd=odd, changes=changes[-100:][::-1], standards=standards(rows, mode_now))

    return {}
