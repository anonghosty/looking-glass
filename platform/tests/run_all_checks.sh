#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
# Every automated check of both platforms, in one go. Read-only against the real database and service (the
# collection tests use throwaway databases that they drop). The end-to-end test (tests/e2e_test.py all) runs a
# separate copy of the app and is started on its own because it takes a few minutes.
# Usage: bash tests/run_all_checks.sh
cd "$(dirname "$0")/.." || exit 1
PY=.venv/bin/python
pass=0; fail=0; skip=0; failed=()
# the in-process checks sign in with throwaway sessions and test other things: the fresh check before high-value
# actions (stepup.py) is off for them; tests/check_stepup.py switches it on for itself and tests it. The running
# service never has this set (the security retest checks that a high-value request on it is refused without the check).
export LG_STEPUP_TESTS_OFF=1
# the per-account codes' key (person_code.py) for the tests: a temporary folder, never the installation's data/
LG_PERSON_CODE_DIR="$(mktemp -d)"; export LG_PERSON_CODE_DIR
# LG_NO_OUTSIDE=1: the outside-connection guard (tests/no_outside/sitecustomize.py) in every check, with a made-up map
# key so the paths that reach outside are switched on: only this computer and the database may be reached, every other
# attempt is refused and written down, and the last line below fails on any place not by design (2026-11-18)
if [ "${LG_NO_OUTSIDE:-}" = 1 ]; then LG_NO_OUTSIDE="$(mktemp)"; fi
if [ -n "${LG_NO_OUTSIDE:-}" ]; then
  LG_NO_OUTSIDE_DB="$(sed -n 's/^MONGO_HOST=//p' .env 2>/dev/null | tr -d "'\"" | head -1)"
  export LG_NO_OUTSIDE LG_NO_OUTSIDE_DB PYTHONPATH="$PWD/tests/no_outside${PYTHONPATH:+:$PYTHONPATH}" MAPBOX_TOKEN="dummy-map-key-for-checks"
  echo "Outside-connection guard on: nothing the checks do can leave this computer."
fi
# Is MongoDB reachable? Without it (a fresh clone, CI, a machine without the database) a check that needs the data is
# reported as skipped, not failed; with it, a database error is a failure like any other (external review, 2026-11-12)
DB_UP=1
$PY - <<'PY' >/dev/null 2>&1 || DB_UP=0
import os
from dotenv import dotenv_values
from pymongo import MongoClient
e = {**dotenv_values(".env"), **os.environ}
MongoClient(host=e.get("MONGO_HOST", "localhost"), port=int(e.get("MONGO_PORT") or 27017), username=e.get("MONGO_USER") or None,
            password=e.get("MONGO_PASSWORD") or None, authSource=e.get("MONGO_AUTH_SOURCE") or "admin",
            serverSelectionTimeoutMS=3000).admin.command("ping")
PY
[ $DB_UP = 1 ] || echo "MongoDB is not reachable: checks that need the data are reported as skipped."
# LG_NO_SKIP=1 (every release run: the development machine, the test systems; 2026-11-26, "we do not skip"): a check
# that would be skipped because something it needs is missing FAILS instead, with what is missing
[ "${LG_NO_SKIP:-}" = 1 ] && echo "No skipping: a check that cannot run here fails (LG_NO_SKIP=1)."
# Two suites (2026-11-26): an INSTALLATION runs the installation checks, the ones that tell whether this installation
# works and is safe, and need nothing it does not have. The MAINTAINER checks (tests/maintainer_rows.txt: the page
# scripts under Node, real browsers, rendered PDFs, the source tree, docs and release tooling, the installer and Caddy
# scripts in scratch folders, test systems and throwaway databases) are not part of an installation's suite: they are
# not run there and not counted. The maintainer's release checklist and the GitHub checks run both: LG_SUITE=all
# (or tests/maintainer_checks.sh).
LG_SUITE="${LG_SUITE:-installation}"
case "$LG_SUITE" in installation|all) ;; *) echo "LG_SUITE must be installation or all, not '$LG_SUITE'"; exit 2 ;; esac
MAINT=$(sed -e 's/#.*//' -e 's/[[:space:]]*$//' tests/maintainer_rows.txt 2>/dev/null | grep -v '^$')
[ -n "$MAINT" ] || { echo "tests/maintainer_rows.txt is missing or empty"; exit 2; }
if [ "$LG_SUITE" = all ]; then
  for f in $MAINT; do [ -f "tests/$f" ] || { echo "tests/maintainer_rows.txt names tests/$f, which does not exist"; exit 2; }; done
  echo "Suite: all (installation and maintainer checks)."
else
  echo "Suite: the installation's checks (the maintainer's checks run with LG_SUITE=all)."
fi
# The maintainer's release run splits the suite over two machines (2026-11-26): LG_ROWS_ELSEWHERE names a file of test
# files that run on the test system instead (the rows that check the running service, whose code must be the new
# build); LG_ROWS_ONLY names a file of test files and runs only those (that other machine's part). Both list one test
# file per line; the release checklist checks that the two parts together ran every row. LG_SCREENSHOTS_AT_END=1:
# the docs screenshot check runs at the screenshot stage, on the final build (the screenshots are retaken last).
list_of() { [ -n "${1:-}" ] && [ -f "$1" ] && sed -e 's/#.*//' -e 's/[[:space:]]*$//' "$1" | grep -v '^$'; }
ELSEWHERE=$(list_of "${LG_ROWS_ELSEWHERE:-}"); ONLY=$(list_of "${LG_ROWS_ONLY:-}")
[ -n "${LG_ROWS_ELSEWHERE:-}" ] && [ -z "$ELSEWHERE" ] && { echo "LG_ROWS_ELSEWHERE names an empty or missing file"; exit 2; }
[ -n "${LG_ROWS_ONLY:-}" ] && [ -z "$ONLY" ] && { echo "LG_ROWS_ONLY names an empty or missing file"; exit 2; }
elsewhere=0; at_end=0
row_file() { local a; for a in "$@"; do case "$a" in tests/*.py|tests/*.sh) echo "${a#tests/}"; return;; esac; done; }
maint=0
is_maint() {  # is this row's test file a maintainer check?
  local a f
  for a in "$@"; do
    case "$a" in tests/*.py|tests/*.sh) f=${a#tests/}; printf '%s\n' "$MAINT" | grep -qxF "$f" && return 0 ;; esac
  done
  return 1
}
run() {
  local name="$1"; shift
  if [ "$LG_SUITE" != all ] && is_maint "$@"; then maint=$((maint + 1)); return; fi
  local rf; rf=$(row_file "$@")
  if [ -n "$ONLY" ] && ! printf '%s\n' "$ONLY" | grep -qxF "$rf"; then return; fi
  if [ -n "$ELSEWHERE" ] && [ -n "$rf" ] && printf '%s\n' "$ELSEWHERE" | grep -qxF "$rf"; then elsewhere=$((elsewhere + 1)); return; fi
  if [ "${LG_SCREENSHOTS_AT_END:-}" = 1 ] && [ "$rf" = check_screenshots.py ]; then at_end=1; return; fi
  printf '%-34s ' "$name"
  out=$("$@" 2>&1); rc=$?
  if [ $rc != 0 ] && [ $rc != 77 ] && [ $DB_UP = 0 ] \
     && echo "$out" | grep -qE 'ServerSelectionTimeoutError|pymongo\.errors|Connection refused|No servers found'; then
    if [ "${LG_NO_SKIP:-}" = 1 ]; then
      echo "FAILED"; fail=$((fail + 1)); failed+=("$name"); echo "    NOT RUN (LG_NO_SKIP=1): needs MongoDB, which is not reachable"; return
    fi
    echo "skipped"; skip=$((skip + 1)); echo "    SKIPPED: needs MongoDB, which is not reachable"; return
  fi
  if [ $rc = 77 ] && [ "${LG_NO_SKIP:-}" = 1 ]; then
    echo "FAILED"; fail=$((fail + 1)); failed+=("$name")
    echo "    NOT RUN (LG_NO_SKIP=1): $(echo "$out" | grep -m1 SKIPPED | sed 's/^ *SKIPPED[^:]*: *//')"
  elif [ $rc = 0 ]; then echo "passed"; pass=$((pass + 1))
  elif [ $rc = 77 ]; then echo "skipped"; skip=$((skip + 1)); echo "$out" | grep -m1 SKIPPED | sed 's/^/    /'
  else echo "FAILED"; fail=$((fail + 1)); failed+=("$name"); echo "$out" | tail -15 | sed 's/^/    /'; fi
}
run "libraries (versions + behaviour)" $PY tests/check_libraries.py
run "requirements.txt names exactly what the code imports (platform, pipeline, docs site)" $PY tests/check_requirements_complete.py
run "Two suites: the installation's checks, the maintainer's apart; no part skipped in silence" $PY tests/check_suite_split.py
run "replay schedule"                 $PY tests/test_schedule.py
run "new communications collections"  $PY tests/test_new_collections.py
run "new services collections"        $PY tests/test_new_service_collections.py
run "services consistency"            $PY tests/check_services_consistency.py
run "services vs MongoDB"             $PY tests/verify_services.py
run "communications totals"           $PY tests/verify_totals.py
run "statistics + filters vs MongoDB" $PY tests/verify_stats.py
run "services statistics vs MongoDB"  $PY tests/verify_svc_stats.py
run "Executive + baseline vs MongoDB" $PY tests/verify_management.py
run "Abused or Compromised vs MongoDB" $PY tests/verify_intelligence.py
run "reports (PDF, ZIP, CSV)"         $PY tests/check_reports.py
run "CSV formula safety"              $PY tests/check_csv_safety.py
run "replayed counts"                 $PY tests/verify_replayed.py
# a machine whose own constituency must never be changed for a check (a development server) names a script that runs
# this check on a test system instead (LG_CONSTITUENCY_CHECK); a test system sets LG_TEST_SYSTEM=1 so the check sets a
# temporary constituency itself and restores the original byte for byte (tests/verify_constituency.py)
if [ -n "${LG_CONSTITUENCY_CHECK:-}" ]; then run "constituency" bash "$LG_CONSTITUENCY_CHECK"
else run "constituency"                    $PY tests/verify_constituency.py; fi
run "demo masking"                    $PY tests/test_demo.py
# the database pipeline beside the platform (database/ in a release install)
run "one address finder for every masker" $PY tests/check_ip_find.py
run "display time zones (every country)" $PY tests/check_timezones.py
run "world maps (every country)" $PY tests/check_world_maps.py
run "region matches (Settings)" $PY tests/check_region_matches.py
run "days kept while unchanged; settle" $PY tests/check_day_keep.py
run "warm-up after the days change" $PY tests/check_warmup.py
run "Strict-Transport-Security" $PY tests/check_hsts.py
run "heavy views per person" $PY tests/check_request_limits.py
run "encryption at rest (check)" $PY tests/check_at_rest.py
run "file modes (only scripts executable)" $PY tests/check_file_modes.py
run "licence and copyright lines in every source file (SPDX)" $PY tests/check_spdx_headers.py
run "special reports kept out of the replay" $PY tests/check_special_reports.py
run "views of host data in the audit log" $PY tests/check_data_access.py
run "CVE look-ups: KEV backoff, time budget" $PY tests/check_cve_backoff.py
run "constituency change beats a running day load" $PY tests/check_scope_reload.py
run "CSRF on every write route (real sign-in)" $PY tests/check_csrf_routes.py
run "uninstaller removes only its own parts" $PY tests/check_uninstall.py
run "sign-in, MFA, recovery, /forgot, role gates (offline)" $PY tests/check_auth_offline.py
run "grades and shares (offline)"     $PY tests/check_calc_offline.py
run "app routes: analysis, reports, look-ups, refusals (offline)" $PY tests/check_cov_app.py
run "auth building blocks: codes, stores, audit gap (offline)" $PY tests/check_cov_auth_units.py
run "auth routes: gate, sign-in steps, admin actions (offline)" $PY tests/check_cov_auth_routes.py
run "no API answer carries a secret, every role (in-process)" $PY tests/check_api_no_secrets.py
run "every route refuses the roles it should, the reviewed permission map (in-process)" $PY tests/check_role_refusals.py
run "Caddy in front of a public installation: its configuration, source and wiring (offline)" $PY tests/check_caddy_front.py
run "ATT&CK suggestions checked against Shadowserver's pages; revised ones reach existing mappings (offline)" $PY tests/check_attack_audit.py
run "Shadowserver's fields: readable labels, its own event mapping, certificate facts, exports (offline)" $PY tests/check_shadowserver_fields.py
run "The parts moved out of app.py still fit together (names, re-exports, routes)" $PY tests/check_moved_modules.py
run "Passkeys and the fresh check before high-value actions" $PY tests/check_stepup.py
run "Connectors: the way out, keys, test before save, scope, payload" $PY tests/check_connectors.py
run "Error words in answers: only words written for the reader"   $PY tests/check_user_words.py
run "Unusual activity: the normal, the summary, Confirm and Dismiss, who sees what" $PY tests/check_unusual.py
run "security headers, hosts, access modes (offline)" $PY tests/check_cov_security.py
run "organisation, notes, task monitor, Workers (offline)" $PY tests/check_cov_admin_tools.py
run "analyst codes: making, reading, channel rules (offline)" $PY tests/check_cov_acodes.py
run "Executive portal routes: refusals, errors (offline)" $PY tests/check_cov_mgmt.py
run "look-ups: CVE, KEV, EPSS, Malpedia, networks, places (faked answers)" $PY tests/check_cov_lookups.py
run "audit chain, checkpoints, the auditor's script (breaks found)" $PY tests/check_cov_audit.py
run "Audit portal routes: permission, tabs, CSV" $PY tests/check_cov_audit_portal.py
run "services for researchers: routes, patterns, no hosts (offline)" $PY tests/check_cov_services_kb.py
run "findings over time: rules, retries, loop (offline)" $PY tests/check_cov_finding_watch.py
run "report map: downloads, feed builder, command line (faked answers)" $PY tests/check_cov_report_map.py
run "PDF builders: analysis, Executive, combination, advisory front" $PY tests/check_cov_pdf.py
run "combination search: refusals, downloads kept, sweep (offline)" $PY tests/check_cov_combos.py
# LG_DB_DIR names the pipeline folder to test (the maintainer's run of the held pipeline before a release); else the
# one beside the platform
DBDIR=""; for d in ${LG_DB_DIR:+"$LG_DB_DIR"} ../database ../shadowserver; do [ -f "$d/zip_limits.py" ] && [ -x "$d/.venv/bin/python" ] && DBDIR=$d && break; done
if [ -n "$DBDIR" ]; then run "pipeline: unzip limits (zip bombs)" bash -c "cd '$DBDIR' && .venv/bin/python tests/test_zip_limits.py"
if [ -n "$DBDIR" ]; then run "pipeline: row hash limits and failed rows" bash -c "cd '$DBDIR' && .venv/bin/python tests/test_line_hash.py"; fi
if [ -n "$DBDIR" ] && [ -f "$DBDIR/tests/test_fix_b12.py" ]; then run "pipeline: the audit's batch 12 fixes stay fixed" bash -c "cd '$DBDIR' && .venv/bin/python tests/test_fix_b12.py"; fi
if [ -n "$DBDIR" ] && [ -f "$DBDIR/tests/test_fix_r2.py" ]; then run "pipeline: the review's fixes stay fixed (crashed files, the lock, UID keys)" bash -c "cd '$DBDIR' && .venv/bin/python tests/test_fix_r2.py"; fi
else run "pipeline: unzip limits (zip bombs)" bash -c 'echo "SKIPPED: database pipeline folder not found beside the platform"; exit 77'; fi
if [ -n "$DBDIR" ] && [ -f "$DBDIR/report_names.py" ]; then run "pipeline: report names (quarantine)" bash -c "cd '$DBDIR' && .venv/bin/python tests/test_report_names.py"
else run "pipeline: report names (quarantine)" bash -c 'echo "SKIPPED: database pipeline folder not found beside the platform"; exit 77'; fi
if [ -n "$DBDIR" ] && [ -f "$DBDIR/tests/test_no_ip_reports.py" ]; then run "pipeline: reports without an IP address" bash -c "cd '$DBDIR' && .venv/bin/python tests/test_no_ip_reports.py"; fi
if [ -n "$DBDIR" ] && [ -f "$DBDIR/mail_auth.py" ]; then run "pipeline: sender check (DKIM)" bash -c "cd '$DBDIR' && .venv/bin/python tests/test_mail_auth.py"
else run "pipeline: sender check (DKIM)" bash -c 'echo "SKIPPED: database pipeline folder not found beside the platform"; exit 77'; fi
if [ -n "$DBDIR" ] && [ -f "$DBDIR/tests/test_dns_https.py" ]; then run "pipeline: sender check key over HTTPS" bash -c "cd '$DBDIR' && .venv/bin/python tests/test_dns_https.py"
else run "pipeline: sender check key over HTTPS" bash -c 'echo "SKIPPED: database pipeline folder not found beside the platform"; exit 77'; fi
if [ -n "$DBDIR" ] && [ -f "$DBDIR/tests/test_mail_auth_pipeline.py" ]; then run "pipeline: sender check blocks and releases" bash -c "cd '$DBDIR' && .venv/bin/python tests/test_mail_auth_pipeline.py"
else run "pipeline: sender check blocks and releases" bash -c 'echo "SKIPPED: database pipeline folder not found beside the platform"; exit 77'; fi
if [ -n "$DBDIR" ] && [ -f "$DBDIR/tests/test_sender_readiness.py" ]; then run "pipeline: sender check week, hints, ready to block" bash -c "cd '$DBDIR' && .venv/bin/python tests/test_sender_readiness.py"
else run "pipeline: sender check week, hints, ready to block" bash -c 'echo "SKIPPED: database pipeline folder not found beside the platform"; exit 77'; fi
if [ -n "$DBDIR" ] && [ -f "$DBDIR/tests/test_link_downloads.py" ]; then run "pipeline: link size cap, Block fails closed" bash -c "cd '$DBDIR' && .venv/bin/python tests/test_link_downloads.py"
else run "pipeline: link size cap, Block fails closed" bash -c 'echo "SKIPPED: database pipeline folder not found beside the platform"; exit 77'; fi
if [ -n "$DBDIR" ] && [ -f "$DBDIR/tests/test_worker_settings_effective.py" ]; then run "pipeline: Workers rules read values as the pipeline does" bash -c "cd '$DBDIR' && .venv/bin/python tests/test_worker_settings_effective.py"
else run "pipeline: Workers rules read values as the pipeline does" bash -c 'echo "SKIPPED: database pipeline folder not found beside the platform"; exit 77'; fi
if [ -n "$DBDIR" ] && [ -f "$DBDIR/tests/test_quarterly_purge.py" ]; then run "pipeline: quarterly purge (permit, dates, report rows only)" bash -c "cd '$DBDIR' && .venv/bin/python tests/test_quarterly_purge.py"
else run "pipeline: quarterly purge (permit, dates, report rows only)" bash -c 'echo "SKIPPED: database pipeline folder not found beside the platform"; exit 77'; fi
if [ -n "$DBDIR" ] && [ -f "$DBDIR/report_api.py" ]; then run "pipeline: reports by Shadowserver API or e-mail" bash -c "cd '$DBDIR' && .venv/bin/python tests/test_report_api.py"
else run "pipeline: reports by Shadowserver API or e-mail" bash -c 'echo "SKIPPED: database pipeline folder not found beside the platform"; exit 77'; fi
if [ -n "$DBDIR" ] && [ -f "$DBDIR/report_types.py" ]; then run "pipeline: new report types noticed" bash -c "cd '$DBDIR' && .venv/bin/python tests/test_report_types.py"
else run "pipeline: new report types noticed" bash -c 'echo "SKIPPED: database pipeline folder not found beside the platform"; exit 77'; fi
run "settings Workers + audit Sender check" $PY tests/check_pipeline_settings.py
run "password expiry at sign-in (password policy)" $PY tests/check_password_policy.py
run "privacy + roles unit tests"      $PY tests/test_privacy_roles.py
run "masked viewers: report fields allowlist" $PY tests/check_masked_fields.py
run "masked viewers: banners, line hash, Spam URL hosts" $PY tests/check_banner_inbound.py
run "reverse proxy + first administrator" $PY tests/check_first_admin_proxy.py
run "settings: Settings permission only" $PY tests/check_settings_access.py
run "network list: every network in the reports" $PY tests/check_networks_list.py
run "values of the wrong kind: refused, never a 500" $PY tests/check_wrong_types.py
run "services report names are never malware names" $PY tests/check_kb_report_names.py
run "slow requests logged by route only; one name-index rebuild" $PY tests/check_slow_log.py
run "locked sign-ins: limits, admin list and unlock" $PY tests/check_lockouts.py
run "system alerts in the admins' bell" $PY tests/check_system_alerts.py
run "heavy answers cached safely (per role, afresh after changes)" $PY tests/check_response_cache.py
run "Settings → Task monitor (admins only, no address, actions audited)" $PY tests/check_task_monitor.py
run "analyst code page: how the selection came about" $PY tests/check_acode_chain.py
run "combinations: ticked infections and CVEs go into the report" $PY tests/check_ticked_names.py
run "Abused or Compromised: who sees what, counts, views, export" $PY tests/check_intelligence.py
run "combination codes never stand for two combinations" $PY tests/check_code_collisions.py
run "findings over time: reported day, repeats, time to act" $PY tests/check_finding_watch.py
run "a CVE ticked on an analyst code's page" $PY tests/check_acode_issue.py
run "the reports database: loopback or internal only, TLS" $PY tests/check_db_connect.py
run "the installer's database check: internal only, TLS, structure" $PY tests/check_install_db.py
run "Bought certificate: checks, install, bell" $PY tests/check_install_cert.py
run "the installer's animated logo" $PY tests/check_installer_anim.py
run "Libraries: only files that match the lock (every install path, every source)" $PY tests/check_installer_supply.py
run "update: old code files moved aside, nothing else touched" $PY tests/check_stale_files.py
run "the service reads its code, writes only data/ (unit + every write site)" $PY tests/check_code_readonly.py
run "code files against the release's fingerprints (verify command, daily check)" $PY tests/check_code_integrity.py
run "offline names: MISP Galaxy + ATT&CK, nothing sent" $PY tests/check_offline_names.py
run "ATT&CK mappings, versions, CVE links" $PY tests/check_attack_map.py
run "ATT&CK in advisories (reviewed only)" $PY tests/check_advisory_attack.py
run "ATT&CK Confirm all (Definitions, advisory)" $PY tests/check_confirm_all.py
run "ATT&CK on CVE and issue cards, CTID trust" $PY tests/check_cve_attack.py
run "failed-login counter (locks, clean-up)" $PY tests/check_login_throttle.py
run "one worker process (gunicorn refuses more)" $PY tests/check_single_worker.py
run "audit write failures: bell, then the gap in the log" $PY tests/check_audit_write_failure.py
run "the report feed's bell notices: a failed read, a stopped builder" $PY tests/check_feed_alerts.py
run "every downloaded CSV says who downloaded it and when" $PY tests/check_csv_stamp.py
run "the code review's bugs stay fixed (quarterly, Unknown network, breakdowns)" $PY tests/check_review_fixes.py
# the whole-codebase audit (2026-11-27): one check per batch, each failing on the code as audited
run "the audit's fixes stay fixed: acodes, advisory, ASN registry (01)" $PY tests/check_fix_b01.py
run "the audit's fixes stay fixed: audit log, sign-in, beacon decoder (02)" $PY tests/check_fix_b02.py
run "the audit's fixes stay fixed: connectors, combinations (03)" $PY tests/check_fix_b03.py
run "the audit's fixes stay fixed: counting keys to greetings (04)" $PY tests/check_fix_b04.py
run "the audit's fixes stay fixed: insider, intel, management (05)" $PY tests/check_fix_b05.py
run "the audit's fixes stay fixed: quarterly, privacy, passkeys (06)" $PY tests/check_fix_b06.py
run "the audit's fixes stay fixed: reports PDF, services, caches (07)" $PY tests/check_fix_b07.py
run "the audit's fixes stay fixed: services intel to warmup, tools (08)" $PY tests/check_fix_b08.py
run "the audit's fixes stay fixed: page scripts account to code-integrity (09)" $PY tests/check_fix_b09.py
run "the audit's fixes stay fixed: page scripts combos to logo-tool (10)" $PY tests/check_fix_b10.py
run "the audit's fixes stay fixed: page scripts management to welcome (11)" $PY tests/check_fix_b11.py
run "the audit's fixes stay fixed: stylesheets and templates (13)" $PY tests/check_fix_b13.py
run "the audit's fixes stay fixed: installer and scripts (14)" $PY tests/check_fix_b14.py
run "the audit's fixes stay fixed: shares, beacon handover days, the database port (15)" $PY tests/check_fix_b15.py
# the Ponytail review of the fixes (2026-11-28): one check per area, each failing on the code before its fixes
run "the review's fixes stay fixed: analyst-code labels masked, update rollback, connectors (r1)" $PY tests/check_fix_r1.py
run "the review's fixes stay fixed: installer values, rights, uninstall ownership (r3)" $PY tests/check_fix_r3.py
run "the review's fixes stay fixed: typed names never stored, dates in host names, JSON bodies (r4)" $PY tests/check_fix_r4.py
run "the audit's follow-ups stay fixed (names, notes, sign-out, the preview watermark)" $PY tests/check_fix_lead.py
run "CSP: exact outside files, no whole CDN; local globe map" $PY tests/check_csp_sources.py
run "reverse proxy: the right-most address, never a visitor's 127.0.0.1" $PY tests/check_proxy_chain.py
run "addresses from .env: https only (feed, report API)" $PY tests/check_https_only.py
run "request times in UTC (one day copy)" $PY tests/check_time_offsets.py
run "masked views: no host-name filter" $PY tests/check_masked_hostname.py
run "external accounts: three masked pages, every other route refused" $PY tests/check_external_masking.py
run "researchers: no code below 5 hosts" $PY tests/check_small_codes.py
run "masked text: every address labelled" $PY tests/check_host_label_text.py
run "self-test resets its own counters" $PY tests/check_retest_reset.py
run "intel gathered (researchers)"    $PY tests/check_intel.py
run "Explore a match (only its records)" $PY tests/check_intel_match.py
run "beacon decoder (who sees what)"   $PY tests/check_beacon_decode.py
run "beacons handed over (per role)"   $PY tests/check_beacon_findings.py
run "generic decode + undecoded families" $PY tests/check_beacon_unknown.py
run "beacon filter + decoded beacons"     $PY tests/check_beacon_stats.py
run "spike notice on the Overview"      $PY tests/check_spike_notice.py
run "AI attack frameworks are an issue"  $PY tests/check_ai_framework.py
run "masked viewers: file names and ids" $PY tests/check_masked_ids.py
run "glossary: docs page = in-app"      $PY tests/check_glossary_sync.py
run "every feature: tutorial, glossary, docs" $PY tests/check_feature_coverage.py
run "decoder on the latest day (counts)" $PY tests/verify_beacon_decode.py
run "researchers' notes"              $PY tests/check_notes.py
run "combination codes + search"      $PY tests/check_combos.py
run "Intel gathered: the report day"  $PY tests/check_report_day.py
run "Combinations: the report day"   $PY tests/check_combo_report_day.py
run "Drill-down counts behind the page" $PY tests/check_index_refresh.py
run "Day load: skipped fields unused"  $PY tests/check_day_skip.py
run "Beacon answers kept (restarts)"   $PY tests/check_beacon_keep.py
run "Settings: Configuration"          $PY tests/check_config_page.py
run "Findings pages keep up; roles played" $PY tests/check_findings_live.py
run "PDF tables: rows fit their text"  $PY tests/check_pdf_rows.py
run "PDF References by criticality; preview marks" $PY tests/check_pdf_refs.py
run "Severity map: who, ratings, PDFs" $PY tests/check_severity_map.py
run "Insider package: copies recorded, seals, Trace a leak" $PY tests/check_insider.py
run "Quarterly reports: who gets what, seals, CSRF, bell, calendar" $PY tests/check_quarterly_access.py
run "Heavy scheduled jobs never overlap (schedule, locks)" $PY tests/check_job_overlap.py
run "Every download in the audit log; one shared download helper on every page" $PY tests/check_downloads.py
run "No page shows the browser's own error text; reads tried again, actions never" $PY tests/check_error_text.py
run "Quarterly report: known answers, guards, permit (throwaway database)" $PY tests/check_quarterly.py
run "Quarterly purge end to end: permit, pipeline, audit, bell (throwaway database)" $PY tests/check_quarterly_purge_e2e.py
run "Anti-fingerprinting: what a signed-out visitor learns" tests/check_fingerprint.py
run "Network changes: certificate and MongoDB addresses" tests/check_addresses.py
run "Accounts: sign-up links, first administrator, sign-up bell" tests/check_accounts.py
run "Installer questions: Back, networks, ports, wording" tests/check_installer_questions.py
run "CVE titles from public records; tooltips on top" tests/check_cve_record_titles.py
run "CVE / issue codes; what a pattern's devices carry" tests/check_issue_codes.py
run "Every port per address; researcher follows the review; Impact in the analysts' PDF" tests/check_ports_impact_follow.py
run "Advisory options: References, insights, look, header; pipeline command copy" tests/check_advisory_options.py
run "Drop-down counts follow the other filters (facets)" tests/check_facet_counts.py
run "Settings: the constituency picker (networks, address blocks, other ranges)" tests/check_address_blocks.py
run "RULE: no ATT&CK technique or mitigation listed twice, anywhere" tests/check_attack_no_duplicates.py
run "Sign-in: the card turns, the dive after signing in, no logo before" tests/check_signin_motion.py
run "Hover labels on the header and portal buttons" tests/check_hover_labels.py
run "Settings: the logo's size and crop tool" tests/check_logo_tool.py
run "The guided tour on every platform and portal" $PY tests/check_tour.py
run "How sign-in is checked: a passkey or the authenticator code" $PY tests/check_signin_check.py
run "No page or answer holds a sign-in name (every role, every page)" $PY tests/check_no_signin_names.py
run "The documentation names only what the code has (statuses, codes, buttons, roles)" $PY tests/check_docs_vs_code.py
run "Caddy adopt run end to end on a made-up machine (rollback, checks first)" $PY tests/check_caddy_adopt_run.py
run "Executive ring charts: every part named, no 0% for something (node)" $PY tests/check_mgmt_charts.py
run "Shares in words: never 0% for a part, never 100% for a part; page = PDF; no share worked out alone" $PY tests/check_share_words.py
run "Analysis and services answers: Top N of M, Other and Not recorded rows, full CSVs, every facet" $PY tests/check_nothing_missing_api.py
run "Executive PDF and ZIP: real totals, Top N of M, the trend table goes on, ATT&CK and CISA actions once" $PY tests/check_exec_complete.py
run "Executive page lists: Top N of M, Explain all = the rows shown, more cities (node)" $PY tests/check_mgmt_lists.py
run "Quarterly, combination, intel, audit, beacon and unusual files hold every row; PDFs say N of M" $PY tests/check_cut_lists_data.py
run "Admin pages say when a list is cut (audit, definitions, services reports, sender, connectors, workers) (node)" $PY tests/check_page_cut_lists.py
run "Admin answers send the full count beside every cut list" $PY tests/check_cut_totals_server.py
run "Map and services pages: Top N of M, rings and bars of the real total, Other parts (node)" $PY tests/check_page_cuts_maps.py
run "Intel, Abused or Compromised, combinations, findings and advisory pages: Top N of M, shares (node)" $PY tests/check_page_cuts_portals.py
run "Pages show the counts kept apart: no network, no region, no address, rows counted once (node)" $PY tests/check_page_count_notes.py
run "One counting rule: the same host lands in the same sector, region and network on every page" $PY tests/check_count_keys.py
run "AS numbers and addresses match the constituency in every spelling (AS064500, ::ffff:)" $PY tests/check_scope_normalise.py
run "A report run's problems reach the bell and the Task monitor, each in words" $PY tests/check_pipeline_problems_shown.py
run "Caddy setup, sync, update, status, remove and make_tls_cert run offline: files written, rolled back on failure" $PY tests/check_caddy_paths_run.py
run "Installer: its own port behind Caddy, its service name, no endless 'not a Looking Glass database' loop" $PY tests/check_installer_caddy_db.py
run "Masking: an external account's services detail, a researcher's Intel gathered, pins cleared at sign-out" $PY tests/check_masked_detail_intel_signout.py
run "Accounts: an invite used once through the real sign-up, its role kept; Approve keeps the picked role" $PY tests/check_invite_signup_approve.py
run "Filter menus' counts equal a brute-force count of the records matching the other filters (both platforms)" $PY tests/check_facets_bruteforce.py
run "Advisory look refuses bad values and keeps its history; who researches; every saved network listed" $PY tests/check_advisory_look_research_scope.py
run "A host's ports named in full and in order; a review kept before 18 Nov opens with every figure" $PY tests/check_ports_index_old_review.py
run "The advisory page's ATT&CK boxes equal the PDF's for the same mappings (node vs Python)" $PY tests/check_attack_mergeout_parity.py
run "Copy buttons copy nothing unless the server confirms the copy was recorded (node)" $PY tests/check_copy_fail_closed.py
run "The welcome page goes on only to a path of this site; reduced motion goes straight there (node)" $PY tests/check_welcome_next.py
run "A failed read is tried again with plain words; an action is never sent twice (node)" $PY tests/check_loader_retry.py
run "A chosen filter value stays in its menu even when the new counts lack it (node)" $PY tests/check_services_withchosen.py
run "Every route, every role, bad input: no server error, no traceback, no hang; API refusals in words" $PY tests/check_every_route.py
run "Settings -> Update: signed release, backup, roll back (made-up repositories)" $PY tests/check_platform_update.py
run "Every PDF and CSV variation: the content checker" $PY tests/check_output_lint.py
run "RULE: every page opens with the loading animation" $PY tests/check_loader_everywhere.py
run "RULE: each destination offered once per page, per role" $PY tests/check_nav_once.py
run "Map filter: what else the devices carry; two ticked = carrying both" $PY tests/check_filter_overlap.py
run "Nothing answers without signing in (every route, malformed requests)" $PY tests/check_signed_out.py
run "Every page asking for the Looking Glass drop-downs loads lg-select.js" $PY tests/check_select_enhancer.py
run "Docs screenshots match the page files they show" $PY tests/check_screenshots.py
run "Sign-up links: the open limit, in fixed words; no error text in answers" $PY tests/check_invite_limit.py
run "PDF pages: no overlap, no cut-off" $PY tests/pdf_pages_check.py
run "analyst code counts: one lock per code" $PY tests/check_per_key_cache.py
run "older days kept for analyst codes" $PY tests/check_recent_days.py
run "Browser: keyboard, lists, cut text" $PY tests/browser_checks.py
run "findings (researcher → advisory)" $PY tests/check_findings.py
run "analyst codes (analyst → researcher)" $PY tests/check_acodes.py
run "report views, cases and advisories" $PY tests/check_combo_review.py
run "workflow: advisory saves, approve, sign-up look-ups" $PY tests/check_workflow_fixes.py
run "cached analysis and replayed counters = uncached" $PY tests/check_view_cache.py
run "notifications (per person, channel only)" $PY tests/check_notifications.py
run "overview of every role" $PY tests/check_overview.py
run "peace of mind (admins)" $PY tests/check_peace.py
run "Audit portal permission" $PY tests/check_audit_portal.py
run "Devices matched by IP note" $PY tests/check_device_note.py
run "CVE titles in full" $PY tests/check_cve_titles.py
run "CI stays pinned" $PY tests/check_ci_pins.py
run "SBOM exact from the locks (SPDX)" $PY tests/check_sbom.py
run "Audit checkpoints and signed backups" $PY tests/check_audit_checkpoint.py
run "Backup scripts: bound and signed" $PY tests/check_backup_scripts.py
run "auditor role + Audit portal (evidence)" $PY tests/check_auditor_portal.py
run "Findings page wording" $PY tests/check_findings_ui.py
run "greetings by name" $PY tests/check_greetings.py
run "several reports + filters"       $PY tests/check_cross_filters.py
run "management portal (no addresses)" $PY tests/check_management.py
run "report map (Shadowserver schema)" $PY tests/check_report_map.py
run "services for researchers (no hosts)" $PY tests/check_services_kb.py
run "Intel gathered privacy (no hosts)" $PY tests/check_intel_privacy.py
run "services patterns (no hosts)"     $PY tests/check_svc_patterns.py
[ -n "${LG_NO_OUTSIDE:-}" ] && run "nothing reached outside (guard)" $PY tests/no_outside/report.py "$LG_NO_OUTSIDE"
[ "$maint" -gt 0 ] && echo && echo "$maint maintainer checks are not part of an installation's checks (LG_SUITE=all runs them)."
[ "$elsewhere" -gt 0 ] && echo && echo "$elsewhere rows run on the test system instead (LG_ROWS_ELSEWHERE): the release checklist runs them there."
[ "$at_end" = 1 ] && echo && echo "The docs screenshot check runs at the screenshot stage, on the final build (LG_SCREENSHOTS_AT_END=1)."
[ -n "$ONLY" ] && echo && echo "Only the rows of LG_ROWS_ONLY ran here: $(printf '%s\n' "$ONLY" | wc -l) listed."
echo; echo "$pass passed, $fail failed${skip:+, $skip skipped}${failed:+: ${failed[*]}}"
[ "$fail" = 0 ]
