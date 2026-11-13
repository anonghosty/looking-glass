#!/usr/bin/env python3
"""worker_settings.weakens() judges a Settings → Workers change by what each value MEANS to the pipeline. Its eff_*
functions copy the rules of the modules that use the values (the platform loads worker_settings.py on its own, so it
cannot import them). This check keeps the copies honest: for many spellings, each eff_* must agree with mail_auth.mode,
mail_sources._truthy, report_api.source, zip_limits.Limits.from_env and the MAIL_AUTH_DOMAIN default.
Run: .venv/bin/python tests/test_worker_settings_effective.py"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import mail_auth  # noqa: E402
import mail_sources  # noqa: E402
import report_api  # noqa: E402
import worker_settings as WS  # noqa: E402
import zip_limits  # noqa: E402

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info else ""))


SPELLINGS = [None, "", "log", "LOG", " enforce ", "block", "Block", "on", "ON", "off", "0", "false", "no", "yes", "1",
             "true", "api", "API", " api", "email", "e-mail", "maybe", "-5", "0", "12", "2048", "3.5", "x"]
bad = [v for v in SPELLINGS if WS.eff_auth(v) != mail_auth.mode({} if v is None else {"MAIL_AUTH": v})]
ok("MAIL_AUTH: eff_auth agrees with mail_auth.mode", not bad, str(bad))
bad = [v for v in SPELLINGS if WS.eff_tls(v) != mail_sources._truthy("true" if v is None else v)]
ok("IMAP_VERIFY_TLS: eff_tls agrees with mail_sources (unset means on)", not bad, str(bad))
bad = [v for v in SPELLINGS if WS.eff_source(v) != report_api.source({} if v is None else {"REPORT_SOURCE": v})]
ok("REPORT_SOURCE: eff_source agrees with report_api.source", not bad, str(bad))
lim_attr = {"ZIP_MAX_UNPACKED_MB": ("max_unpacked", zip_limits.MB), "ZIP_MAX_RATIO": ("max_ratio", 1),
            "ZIP_MAX_FILES": ("max_files", 1), "ZIP_KEEP_FREE_MB": ("keep_free", zip_limits.MB)}
for name, (attr, unit) in lim_attr.items():
    bad = []
    for v in SPELLINGS:
        env = {} if v is None else {name: v}
        if WS.eff_zip(name, v) * unit != getattr(zip_limits.Limits.from_env(env.get), attr):
            bad.append(v)
    ok(f"{name}: eff_zip agrees with zip_limits.Limits.from_env", not bad, str(bad))
ok("MAIL_AUTH_DOMAIN: unset or empty means shadowserver.org, as the pipeline uses it",
   WS.eff_domain(None) == WS.eff_domain("") == "shadowserver.org" and WS.eff_domain(" Shadowserver.ORG ") == "shadowserver.org")

# confirm_request.sh on forged request files (review 2026-11-13: "values" as a list crashed it): every odd shape is
# listed as malformed or refused, never a crash, and never confirmed
import contextlib, io, json, pathlib, tempfile  # noqa: E401,E402
tmp = tempfile.mkdtemp(prefix="wsfuzz-")
pdata = pathlib.Path(tmp) / "data"
(pdata / "pipeline_requests").mkdir(parents=True)
real = (WS.find_platform_data, WS.read_env)
WS.find_platform_data = lambda *a, **k: pdata
WS.read_env = lambda p: {"DATA_DIR": tmp, "MAIL_AUTH": "enforce", "ZIP_MAX_UNPACKED_MB": "1024"}
RID = "20261113T070000Z-abcdefabcdef"
shapes = [{"kind": "settings", "values": ["MAIL_AUTH"]}, {"kind": "settings", "values": "MAIL_AUTH=off"},
          {"kind": "settings", "values": {"MAIL_AUTH": ["off"]}}, {"kind": "settings", "values": {"ZIP_MAX_UNPACKED_MB": {"a": 1}}},
          {"kind": "settings", "values": {"MAIL_AUTH": None}}, {"kind": "settings", "values": {"ZIP_MAX_UNPACKED_MB": "nan"}},
          {"kind": ["settings"]}, {"kind": {"a": 1}}, {"kind": "release", "qid": ["../../x"]}, {"kind": "apikey", "key": {"a": 1}}]
crashed, confirmed = [], []
try:
    for b in shapes:
        (pdata / "pipeline_requests" / f"{RID}.json").write_text(json.dumps(dict(b, id=RID)))
        for args in ([], [RID, "--yes"]):
            try:
                with contextlib.redirect_stdout(io.StringIO()):
                    rc = WS.cli(args)
                if args and rc == 0:
                    confirmed.append(b)
            except Exception as e:  # noqa: BLE001
                crashed.append((b, type(e).__name__))
finally:
    WS.find_platform_data, WS.read_env = real
ok(f"confirm_request.sh on {len(shapes)} forged request shapes: no crash", not crashed, str(crashed[:2]))
ok("…and none of them is confirmed", not confirmed, str(confirmed[:2]))
print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
