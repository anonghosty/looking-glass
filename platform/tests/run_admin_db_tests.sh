#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
# The tests that need a throwaway database, run with the MongoDB administrator account.
#
# The everyday accounts cannot create a database (the platform's is read-only, the pipeline's writes only its own), and
# the administrator account is in /etc/looking-glass/mongo-admin.env, readable only by root. So run_all_checks.sh
# skips these unless sudo works without a password. This script reads that file once with sudo (asking for the
# password), hands it to the tests through a private temporary file (LG_MONGO_ADMIN_FILE), and removes it afterwards.
#
#   tests/run_admin_db_tests.sh
set -uo pipefail
cd "$(dirname "$(readlink -f "$0")")/.." || exit 1
ETC=/etc/looking-glass/mongo-admin.env
tmp=$(umask 077; mktemp)
trap 'shred -u "$tmp" 2>/dev/null || rm -f "$tmp"' EXIT
# shellcheck disable=SC2024  # only reading needs root; the copy goes to this user's own 0600 temporary file
sudo cat "$ETC" > "$tmp" || { echo "Could not read $ETC with sudo."; exit 1; }
export LG_MONGO_ADMIN_FILE=$tmp
fail=0
for t in tests/test_new_collections.py tests/test_new_service_collections.py tests/check_quarterly.py tests/check_quarterly_purge_e2e.py; do
  printf '%-45s ' "$t"; out=$(.venv/bin/python "$t" 2>&1); rc=$?
  # 77 is a skip: WE DO NOT SKIP, so it fails here like any other exit code that is not 0
  if [ $rc = 0 ]; then echo passed
  elif [ $rc = 77 ]; then echo "FAILED (skipped, exit 77)"; echo "$out" | tail -5; fail=1
  else echo "FAILED ($rc)"; echo "$out" | tail -5; fail=1; fi
done
# the pipeline's own database tests: a skipped part, or no pipeline found to run them in, is a failure too (WE DO NOT
# SKIP; audit 2026-11-27: both passed with exit 0)
DB=""; for d in ../database ../shadowserver; do [ -f "$d/tests/test_report_names.py" ] && [ -x "$d/.venv/bin/python" ] && DB=$d && break; done
if [ -z "$DB" ]; then
  printf '%-45s %s\n' "pipeline: tests/test_report_names.py" "FAILED (not run: no ../database or ../shadowserver with tests/ and .venv)"; fail=1
else
  printf '%-45s ' "pipeline: tests/test_report_names.py"; out=$(cd "$DB" && .venv/bin/python tests/test_report_names.py 2>&1); rc=$?
  if [ $rc = 0 ] && ! echo "$out" | grep -q skipped; then echo passed
  elif [ $rc = 0 ] || [ $rc = 77 ]; then echo "FAILED (some tests skipped):"; echo "$out" | grep -i skip | head -3; fail=1
  else echo "FAILED ($rc)"; echo "$out" | tail -5; fail=1; fi
  if [ -f "$DB/tests/test_quarterly_purge.py" ]; then
    printf '%-45s ' "pipeline: tests/test_quarterly_purge.py"; out=$(cd "$DB" && .venv/bin/python tests/test_quarterly_purge.py 2>&1); rc=$?
    if [ $rc = 0 ] && ! echo "$out" | grep -q SKIPPED; then echo passed
    elif [ $rc = 0 ] || [ $rc = 77 ]; then echo "FAILED (the database part was skipped)"; fail=1
    else echo "FAILED ($rc)"; echo "$out" | tail -5; fail=1; fi
  fi
fi
exit $fail
