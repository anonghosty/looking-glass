"""New-report detection test. Uses a throwaway database (lg_selftest_<pid>) on the same MongoDB server and
drops it afterwards; the real database is only read (to copy three sample rows).

Usage: .venv/bin/python tests/test_new_collections.py
"""
import os
import sys

from dotenv import load_dotenv

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from sources import Registry  # noqa: E402

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
name = f"lg_selftest_{os.getpid()}"
test = client[name]
fails = 0


def ok(label, cond):
    global fails
    fails += not cond
    print(("ok  " if cond else "FAIL") + " " + label)


try:
    sample = [{k: v for k, v in d.items() if k != "_id"} for d in real["event4_sinkhole_http"].find().limit(3)]
    test["event4_sinkhole_http"].insert_many([dict(d) for d in sample])
    test["event4_sinkhole_http"].create_index("filename")
    reg = Registry(test)
    ok("start: 1 report found", [i["name"] for i in reg.get()] == ["event4_sinkhole_http"])
    ok("nothing changed: no rebuild", reg.check() is False)

    test["event4_brand_new_report"].insert_many([dict(d) for d in sample])          # a new report type appears
    test["event4_brand_new_report"].create_index("filename")
    ok("new collection with rows: rebuilt at once", reg.check() is True)
    ok("it is now monitored", "event4_brand_new_report" in [i["name"] for i in reg.items])
    ok("and announced as new and compatible", [(a["name"], a["compatible"]) for a in reg.added] == [("event4_brand_new_report", True)])

    test.create_collection("event4_empty_for_now")                                  # created empty first
    reg.check()
    ok("empty new collection: not monitored yet", "event4_empty_for_now" not in [i["name"] for i in reg.items])
    test["event4_empty_for_now"].insert_many([dict(d) for d in sample])             # then filled
    test["event4_empty_for_now"].create_index("filename")
    ok("once it gets rows: rebuilt", reg.check() is True)
    ok("and monitored", "event4_empty_for_now" in [i["name"] for i in reg.items])

    # matches discovery (src_/dst_ fields) but lacks fields the platform needs: listed, not loaded
    partial = [{k: v for k, v in d.items() if k not in ("src_geo", "extracted_date")} for d in sample]
    test["event4_partial_fields"].insert_many(partial)
    test["event4_partial_fields"].create_index("filename")
    reg.check()
    un = {i["name"]: i["diagnostic"] for i in reg.unsupported}
    ok("missing fields: not loaded onto the map", "event4_partial_fields" not in [i["name"] for i in reg.items])
    ok("listed as unsupported", "event4_partial_fields" in un)
    ok("diagnostic names what is missing", un.get("event4_partial_fields", {}).get("missing") == ["Event time", "Source country"])
    ok("announced as not compatible", any(a["name"] == "event4_partial_fields" and a["compatible"] is False for a in reg.added))

    # all fields, but no filename index: rows cannot be loaded per day
    test["event4_no_index"].insert_many([dict(d) for d in sample])
    reg.check()
    un = {i["name"]: i["diagnostic"] for i in reg.unsupported}
    ok("no filename index: unsupported, with the reason",
       any("no index" in m for m in un.get("event4_no_index", {}).get("missing", [])))

    # destination-only: no src_* fields, but dst_ip + dst_geo: supported, drawn as points at the destination
    dst_only = [{k: v for k, v in d.items() if not k.startswith("src_")} for d in sample]
    test["event4_dst_only"].insert_many(dst_only)
    test["event4_dst_only"].create_index("filename")
    reg.check()
    item = next((i for i in reg.items if i["name"] == "event4_dst_only"), None)
    ok("destination-only report: loaded onto the map", item is not None and item["layout"] == "target")
    ok("its diagnostic notes the missing source", item is not None and "Source" in item["diagnostic"]["warnings"])

    # destination side without a country: not enough to place it
    test["event4_dst_no_geo"].insert_many([{k: v for k, v in d.items() if k != "dst_geo"} for d in dst_only])
    test["event4_dst_no_geo"].create_index("filename")
    reg.check()
    un = {i["name"]: i["diagnostic"] for i in reg.unsupported}
    ok("destination-only without country: unsupported", un.get("event4_dst_no_geo", {}).get("missing") == ["Destination country"])

    # unknown layout: has a src/dst-like field name, but none of the layouts the platform knows
    test["odd_report"].insert_one({"srcnet": "10.0.0.0/8", "extracted_date": sample[0].get("extracted_date"), "filename": "x"})
    reg.check()
    un = {i["name"]: i["diagnostic"] for i in reg.unsupported}
    ok("unrecognised layout: unsupported", un.get("odd_report", {}).get("layout") == "unrecognised")

    test.drop_collection("event4_brand_new_report")
    ok("dropped collection: rebuilt", reg.check() is True)
    ok("and no longer monitored", "event4_brand_new_report" not in [i["name"] for i in reg.items])
finally:
    client.drop_database(name)
    print(f"test database {name} dropped:", name not in client.list_database_names())

print("\nALL PASSED" if not fails else f"\n{fails} FAILED")
sys.exit(1 if fails else 0)
