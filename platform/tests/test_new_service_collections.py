"""New publicly accessible / vulnerable services report types: detection, field check and what gets announced.
Uses a throwaway database (lg_svctest_<pid>) on the same MongoDB server and drops it afterwards; the real database
is only read (to copy sample rows).

Usage: .venv/bin/python tests/test_new_service_collections.py
"""
import os
import sys

from dotenv import load_dotenv

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from services import ServiceRegistry  # noqa: E402

load_dotenv(os.path.join(os.path.dirname(__file__), "..", ".env"))
# This test creates a throwaway database: an account that may (tests/_throwaway_mongo.py), or skip (exit 77).
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _throwaway_mongo  # noqa: E402
client = _throwaway_mongo.client(os.environ["MONGO_HOST"], os.environ.get("MONGO_PORT", 27017))
if client is None:
    print("SKIPPED: needs a MongoDB account that may create databases. The platform's and the pipeline's are limited, "
          "as they should be, and the administrator account is root-only: run tests/run_admin_db_tests.sh (asks for sudo once).")
    sys.exit(77)
real = client[os.environ["MONGO_DB"]]
name = f"lg_svctest_{os.getpid()}"
test = client[name]
fails = 0


def ok(label, cond, info=""):
    global fails
    fails += not cond
    print(("ok  " if cond else "FAIL") + " " + label + (f" · {info}" if info else ""))


try:
    sample = [{k: v for k, v in d.items() if k != "_id"} for d in real["scan_ssh"].find().limit(3)]
    test["scan_ssh"].insert_many([dict(d) for d in sample]); test["scan_ssh"].create_index("filename")
    reg = ServiceRegistry(test)
    ok("start: 1 report", [i["name"] for i in reg.get()] == ["scan_ssh"])

    # 1. a new, complete report type (e.g. Shadowserver starts sending scan_redis)
    test["scan_redis"].insert_many([dict(d) for d in sample]); test["scan_redis"].create_index("filename")
    reg.check()
    a = next((x for x in reg.added if x["name"] == "scan_redis"), None)
    ok("new complete report: loaded", "scan_redis" in [i["name"] for i in reg.items])
    ok("announced as compatible, with its score", a and a["compatible"] and a["required_ok"] == a["required_total"] == 4, str(a and (a["required_ok"], a["required_total"])))
    ok("official name used", a and a["label"] == "Open Redis", a and a["label"])

    # 2. a new report missing a required field (no geo) and with a recommended field missing (no tag)
    test["scan_vnc"].insert_many([{k: v for k, v in d.items() if k not in ("geo", "tag")} for d in sample]); test["scan_vnc"].create_index("filename")
    reg.check()
    b = next((x for x in reg.added if x["name"] == "scan_vnc"), None)
    ok("missing required field: not loaded", "scan_vnc" not in [i["name"] for i in reg.items])
    ok("listed as unsupported with what is missing", b and not b["compatible"] and b["missing"] == ["Country"], str(b and b["missing"]))
    ok("recommended field reported too", b and "Tags" in b["warnings"], str(b and b["warnings"]))

    # 3. all fields but no filename index
    test["scan_rdp"].insert_many([dict(d) for d in sample])
    reg.check()
    c = next((x for x in reg.added if x["name"] == "scan_rdp"), None)
    ok("no filename index: unsupported, says why", c and not c["compatible"] and any("no index" in m for m in c["missing"]), str(c and c["missing"]))

    # 4. a communications report (src_/dst_) is NOT a services report
    test["event4_new_thing"].insert_one({"src_ip": "1.2.3.4", "dst_ip": "5.6.7.8", "ip": "1.2.3.4", "extracted_date": sample[0]["extracted_date"], "filename": "x"})
    reg.check()
    ok("communication collections are left to the map platform", "event4_new_thing" not in [i["name"] for i in reg.items + reg.unsupported])
    # 5. no ip at all: ignored by both platforms (nothing to show)
    test["population_stats"].insert_one({"count": 5, "extracted_date": sample[0]["extracted_date"]})
    reg.check()
    ok("collection without ip: not a services report", "population_stats" not in [i["name"] for i in reg.items + reg.unsupported])
finally:
    client.drop_database(name)
    print(f"test database {name} dropped:", name not in client.list_database_names())
print("\nALL PASSED" if not fails else f"\n{fails} FAILED")
sys.exit(1 if fails else 0)
