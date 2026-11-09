"""Fast checks: connection, indexes, collection size, and one recent-window query with timing."""
import os
import sys
import time
from datetime import timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import app as tm  # noqa: E402

coll = tm.coll
print("ping:", tm.client.admin.command("ping"), flush=True)
print("indexes:", [list(ix["key"].items()) for ix in coll.list_indexes()], flush=True)
print("estimated docs:", coll.estimated_document_count(), flush=True)
w = tm.replay_now()
t = time.time()
n = coll.count_documents({"extracted_date": {"$gte": w - timedelta(seconds=60), "$lt": w}}, maxTimeMS=60000)
print(f"events in last 60s of replay clock ({w}): {n}  [{time.time() - t:.1f}s]", flush=True)
t = time.time()
plan = coll.find({"extracted_date": {"$gte": w - timedelta(seconds=10), "$lt": w}}).explain()
stage = plan.get("queryPlanner", {}).get("winningPlan", {})
print("plan:", str(stage)[:300], f"[{time.time() - t:.1f}s]", flush=True)
