#!/usr/bin/env bash
# Every automated check of both platforms, in one go. Read-only against the real database and service (the
# collection tests use throwaway databases that they drop). The end-to-end test (tests/e2e_test.py all) runs a
# separate copy of the app and is started on its own because it takes a few minutes.
# Usage: bash tests/run_all_checks.sh
cd "$(dirname "$0")/.." || exit 1
PY=.venv/bin/python
pass=0; fail=0; skip=0; failed=()
run() {
  local name="$1"; shift
  printf '%-34s ' "$name"
  out=$("$@" 2>&1); rc=$?
  if [ $rc = 0 ]; then echo "passed"; pass=$((pass + 1))
  elif [ $rc = 77 ]; then echo "skipped"; skip=$((skip + 1)); echo "$out" | grep -m1 SKIPPED | sed 's/^/    /'
  else echo "FAILED"; fail=$((fail + 1)); failed+=("$name"); echo "$out" | tail -15 | sed 's/^/    /'; fi
}
run "replay schedule"                 $PY tests/test_schedule.py
run "new communications collections"  $PY tests/test_new_collections.py
run "new services collections"        $PY tests/test_new_service_collections.py
run "services consistency"            $PY tests/check_services_consistency.py
run "services vs MongoDB"             $PY tests/verify_services.py
run "communications totals"           $PY tests/verify_totals.py
run "statistics + filters vs MongoDB" $PY tests/verify_stats.py
run "services statistics vs MongoDB"  $PY tests/verify_svc_stats.py
run "Executive + baseline vs MongoDB" $PY tests/verify_management.py
run "reports (PDF, ZIP, CSV)"         $PY tests/check_reports.py
run "CSV formula safety"              $PY tests/check_csv_safety.py
run "replayed counts"                 $PY tests/verify_replayed.py
run "constituency"                    $PY tests/verify_constituency.py
run "demo masking"                    $PY tests/test_demo.py
run "privacy + roles unit tests"      $PY tests/test_privacy_roles.py
run "intel gathered (researchers)"    $PY tests/check_intel.py
run "researchers' notes"              $PY tests/check_notes.py
run "combination codes + search"      $PY tests/check_combos.py
run "findings (researcher → advisory)" $PY tests/check_findings.py
run "analyst codes (analyst → researcher)" $PY tests/check_acodes.py
run "report views, cases and advisories" $PY tests/check_combo_review.py
run "notifications (per person, channel only)" $PY tests/check_notifications.py
run "overview of every role" $PY tests/check_overview.py
run "peace of mind (admins)" $PY tests/check_peace.py
run "several reports + filters"       $PY tests/check_cross_filters.py
run "management portal (no addresses)" $PY tests/check_management.py
run "report map (Shadowserver schema)" $PY tests/check_report_map.py
run "services for researchers (no hosts)" $PY tests/check_services_kb.py
run "Intel gathered privacy (no hosts)" $PY tests/check_intel_privacy.py
run "services patterns (no hosts)"     $PY tests/check_svc_patterns.py
echo; echo "$pass passed, $fail failed${skip:+, $skip skipped}${failed:+: ${failed[*]}}"
[ "$fail" = 0 ]
