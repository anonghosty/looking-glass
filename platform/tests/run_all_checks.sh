#!/usr/bin/env bash
# Every automated check of both platforms, in one go. Read-only against the real database and service (the
# collection tests use throwaway databases that they drop). The end-to-end test (tests/e2e_test.py all) runs a
# separate copy of the app and is started on its own because it takes a few minutes.
# Usage: bash tests/run_all_checks.sh
cd "$(dirname "$0")/.." || exit 1
PY=.venv/bin/python
pass=0; fail=0; skip=0; failed=()
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
run() {
  local name="$1"; shift
  printf '%-34s ' "$name"
  out=$("$@" 2>&1); rc=$?
  if [ $rc != 0 ] && [ $rc != 77 ] && [ $DB_UP = 0 ] \
     && echo "$out" | grep -qE 'ServerSelectionTimeoutError|pymongo\.errors|Connection refused|No servers found'; then
    echo "skipped"; skip=$((skip + 1)); echo "    SKIPPED: needs MongoDB, which is not reachable"; return
  fi
  if [ $rc = 0 ]; then echo "passed"; pass=$((pass + 1))
  elif [ $rc = 77 ]; then echo "skipped"; skip=$((skip + 1)); echo "$out" | grep -m1 SKIPPED | sed 's/^/    /'
  else echo "FAILED"; fail=$((fail + 1)); failed+=("$name"); echo "$out" | tail -15 | sed 's/^/    /'; fi
}
run "libraries (versions + behaviour)" $PY tests/check_libraries.py
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
run "constituency"                    $PY tests/verify_constituency.py
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
run "special reports kept out of the replay" $PY tests/check_special_reports.py
run "views of host data in the audit log" $PY tests/check_data_access.py
run "CVE look-ups: KEV backoff, time budget" $PY tests/check_cve_backoff.py
run "constituency change beats a running day load" $PY tests/check_scope_reload.py
run "CSRF on every write route (real sign-in)" $PY tests/check_csrf_routes.py
run "uninstaller removes only its own parts" $PY tests/check_uninstall.py
run "sign-in, MFA, recovery, /forgot, role gates (offline)" $PY tests/check_auth_offline.py
run "grades and shares (offline)"     $PY tests/check_calc_offline.py
DBDIR=""; for d in ../database ../shadowserver; do [ -f "$d/zip_limits.py" ] && [ -x "$d/.venv/bin/python" ] && DBDIR=$d && break; done
if [ -n "$DBDIR" ]; then run "pipeline: unzip limits (zip bombs)" bash -c "cd '$DBDIR' && .venv/bin/python tests/test_zip_limits.py"
if [ -n "$DBDIR" ]; then run "pipeline: row hash limits and failed rows" bash -c "cd '$DBDIR' && .venv/bin/python tests/test_line_hash.py"; fi
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
run "offline names: MISP Galaxy + ATT&CK, nothing sent" $PY tests/check_offline_names.py
run "ATT&CK mappings, versions, CVE links" $PY tests/check_attack_map.py
run "ATT&CK in advisories (reviewed only)" $PY tests/check_advisory_attack.py
run "ATT&CK Confirm all (Definitions, advisory)" $PY tests/check_confirm_all.py
run "ATT&CK on CVE and issue cards, CTID trust" $PY tests/check_cve_attack.py
run "failed-login counter (locks, clean-up)" $PY tests/check_login_throttle.py
run "one worker process (gunicorn refuses more)" $PY tests/check_single_worker.py
run "audit write failures: bell, then the gap in the log" $PY tests/check_audit_write_failure.py
run "CSP: exact outside files, no whole CDN; local globe map" $PY tests/check_csp_sources.py
run "reverse proxy: the right-most address, never a visitor's 127.0.0.1" $PY tests/check_proxy_chain.py
run "addresses from .env: https only (feed, report API)" $PY tests/check_https_only.py
run "request times in UTC (one day copy)" $PY tests/check_time_offsets.py
run "masked views: no host-name filter" $PY tests/check_masked_hostname.py
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
run "Anti-fingerprinting: what a signed-out visitor learns" tests/check_fingerprint.py
run "Network changes: certificate and MongoDB addresses" tests/check_addresses.py
run "Accounts: sign-up links, first administrator, sign-up bell" tests/check_accounts.py
run "Installer questions: Back, networks, ports, wording" tests/check_installer_questions.py
run "CVE titles from public records; tooltips on top" tests/check_cve_record_titles.py
run "CVE / issue codes; what a pattern's devices carry" tests/check_issue_codes.py
run "Every port per address; researcher follows the review; Impact in the analysts' PDF" tests/check_ports_impact_follow.py
run "Advisory options: References, insights, look, header; pipeline command copy" tests/check_advisory_options.py
run "Drop-down counts follow the other filters (facets)" tests/check_facet_counts.py
run "Settings: pick address blocks from the reports" tests/check_address_blocks.py
run "RULE: no ATT&CK technique or mitigation listed twice, anywhere" tests/check_attack_no_duplicates.py
run "Sign-in: the card turns, the dive after signing in, no logo before" tests/check_signin_motion.py
run "Hover labels on the header and portal buttons" tests/check_hover_labels.py
run "Settings: the logo's size and crop tool" tests/check_logo_tool.py
run "The guided tour on every platform and portal" $PY tests/check_tour.py
run "Every PDF and CSV variation: the content checker" $PY tests/check_output_lint.py
run "RULE: every page opens with the loading animation" $PY tests/check_loader_everywhere.py
run "Map filter: what else the devices carry; two ticked = carrying both" $PY tests/check_filter_overlap.py
run "Nothing answers without signing in (every route, malformed requests)" $PY tests/check_signed_out.py
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
echo; echo "$pass passed, $fail failed${skip:+, $skip skipped}${failed:+: ${failed[*]}}"
[ "$fail" = 0 ]
