#!/usr/bin/env bash
# The three tests that need a throwaway database, run with the MongoDB administrator account.
#
# The everyday accounts cannot create a database (the platform's is read-only, the pipeline's writes only its own), and
# the administrator account is in /etc/looking-glass/mongo-admin.env, readable only by root. So run_all_checks.sh
# skips these three unless sudo works without a password. This script reads that file once with sudo (asking for the
# password), hands it to the tests through a private temporary file (LG_MONGO_ADMIN_FILE), and removes it afterwards.
#
#   tests/run_admin_db_tests.sh
set -uo pipefail
cd "$(dirname "$(readlink -f "$0")")/.."
ETC=/etc/looking-glass/mongo-admin.env
tmp=$(umask 077; mktemp)
trap 'shred -u "$tmp" 2>/dev/null || rm -f "$tmp"' EXIT
sudo cat "$ETC" > "$tmp" || { echo "Could not read $ETC with sudo."; exit 1; }
export LG_MONGO_ADMIN_FILE=$tmp
fail=0
for t in tests/test_new_collections.py tests/test_new_service_collections.py; do
  printf '%-45s ' "$t"; out=$(.venv/bin/python "$t" 2>&1); rc=$?
  [ $rc = 0 ] && echo passed || { echo "FAILED ($rc)"; echo "$out" | tail -5; fail=1; }
done
DB=""; for d in ../database ../shadowserver; do [ -f "$d/tests/test_report_names.py" ] && [ -x "$d/.venv/bin/python" ] && DB=$d && break; done
if [ -n "$DB" ]; then
  printf '%-45s ' "pipeline: tests/test_report_names.py"; out=$(cd "$DB" && .venv/bin/python tests/test_report_names.py 2>&1); rc=$?
  if [ $rc = 0 ] && ! echo "$out" | grep -q skipped; then echo passed
  elif [ $rc = 0 ]; then echo "passed, but some tests skipped:"; echo "$out" | grep -i skip | head -3
  else echo "FAILED ($rc)"; echo "$out" | tail -5; fail=1; fi
fi
exit $fail
