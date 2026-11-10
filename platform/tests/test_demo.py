"""Demo mode and masked roles leak nothing: no real IP address, AS number, company name or host name in any answer of
both platforms, whether masking comes from the Demo button (demo=1) or from a role without the 'unmasked' permission.

The detector is proven first: the same check on the normal (unmasked) answers must find the real values, otherwise
the test could never fail. Exit 0 = passed, 1 = a leak (or a broken detector), 77 = no data loaded yet.
Usage: .venv/bin/python tests/test_demo.py      (the app in-process; no server needed, nothing is written)"""
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import app as tm  # noqa: E402
from flask import g  # noqa: E402

fails, checks = [], 0


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond: fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info else ""), flush=True)


now = tm.replay_now()
day = tm.store.get(now)
sday = tm.svc["store"].get(now)
if not day.events:
    print("SKIPPED: no events loaded for the replay day yet (run it again once the day's reports are in)")
    sys.exit(77)
AT = tm.iso(now)
TO = tm.iso(tm.day_start(now) + tm.timedelta(days=1) - tm.timedelta(seconds=1))   # the whole loaded day

# the real values that must never appear in a masked answer
REAL_IPS = {e[k] for e in day.events for k in ("src_ip", "dst_ip") if e.get(k)} | {e["ip"] for e in sday.events if e.get("ip")}
# the constituents' own host and machine names (a destination host name is the malware's C2 domain, shown on purpose
# as http_host)
REAL_HOSTS = {e[k] for e in day.events for k in ("src_hostname", "machine_name") if len(str(e.get(k) or "")) > 5}
# network (company) names; a name that is also a product vendor in the services data ("Microsoft") cannot be told apart
# from that vendor, which is shown on purpose
VENDORS = {str(e.get(k) or "") for e in sday.events for k in ("vendor", "product")}
REAL_NAMES = {v["name"] for v in tm.asn_registry.all().values() if len(v.get("name") or "") > 4} - VENDORS
ADDR = re.compile(r"(?<![\w.:])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])|(?<![\w:])(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}(?![\w:])")
RAW_ASN = re.compile(r'"(?:src_|dst_)?asn(?:_name)?": "?(?:AS)?\d+"?|\bAS\d{2,10}\b|"asns": \[\s*"?\d')


def leaks(body, typed=None):
    """What real values the answer holds (typed = the value the viewer sent, which an answer may repeat)."""
    found = [f"ip {x}" for x in set(ADDR.findall(body)) if x in REAL_IPS and x != typed][:3]
    found += [f"asn {m}" for m in RAW_ASN.findall(body)][:3]
    found += [f"name {n}" for n in REAL_NAMES if f'"{n}"' in body or f'"{n} (AS' in body or f": {n}" in body][:3]
    found += [f"host {h}" for h in REAL_HOSTS if f'"{h}"' in body][:3]
    return found


c = tm.app.test_client()
c.environ_base.update({"REMOTE_ADDR": "127.0.0.1",
                       "HTTP_X_LG_AUTOMATION": open(os.path.join(tm.BASE_DIR, "data", "automation.key")).read().strip()})


def get(path):
    r = c.get(path)
    return r.status_code, r.get_data(as_text=True)


def as_role(path, perms):
    """The answer for an account with these permissions (as the login would set it), without a session."""
    with tm.app.test_request_context(path):
        g.user = {"user": "lg-selftest-role", "role": "custom", "perms": set(perms), "csrf": None}
        ep = tm.app.url_map.bind("localhost").match(path.split("?")[0])
        r = tm.app.view_functions[ep[0]](**ep[1])
        r = r[0] if isinstance(r, tuple) else r
        return r.get_data(as_text=True)


# a real network (normal mode), its alias and an opaque host reference (demo mode), the day's top infection
st = json.loads(get(f"/api/stats?at={AT}")[1])
std = json.loads(get(f"/api/stats?at={AT}&demo=1")[1])
alias = std["src_network"][0]["value"] if std.get("src_network") else ""
ev_demo = json.loads(get(f"/api/events?latest=1&limit=50&to={TO}&demo=1")[1])["events"]
ref = ev_demo[-1]["src_ref"] if ev_demo else ""
inf = st["infection"][0]["value"] if st.get("infection") else ""
PATHS = [f"/api/events?latest=1&limit=1000&to={TO}", f"/api/stats?at={AT}", f"/api/facets?at={AT}", f"/api/overview?at={AT}",
         f"/api/geo?at={AT}", f"/api/insight?kind=src_asn&value={alias}&at={AT}", f"/api/insight?kind=src_ip&value={ref}&at={AT}",
         f"/api/insight?kind=infection&value={inf}&at={AT}", f"/api/insight/drill?kind=infection&value={inf}&metric=hosts&at={AT}",
         f"/api/svc/events?at={AT}&limit=1000", f"/api/svc/stats?at={AT}", f"/api/svc/facets?at={AT}", f"/api/svc/regions?at={AT}",
         f"/api/svc/drill?metric=hosts&at={AT}", f"/api/svc/drill?metric=vulnerable&at={AT}"]

print(f"Day {day.start.date()}: {len(REAL_IPS):,} real addresses, {len(REAL_NAMES)} company names, {len(REAL_HOSTS):,} host names to look for"
      f" ({len(VENDORS & {v['name'] for v in tm.asn_registry.all().values()})} names skipped: also a product vendor)")
print("\n1. The detector finds real values in normal (unmasked) answers (counts only: this output may be shared)")
normal = "".join(get(p)[1] for p in PATHS[:3] + PATHS[9:11])
found = leaks(normal)
ok("real addresses found in normal answers", any(x.startswith("ip ") for x in found), f"{sum(x.startswith('ip ') for x in found)} found")
ok("AS numbers or company names found in normal answers", any(x.startswith(("asn ", "name ")) for x in found))
_shown = leaks


def leaks(body, typed=None):                      # from here on: what leaked, by kind, without the value itself
    return [x.split(" ", 1)[0] + " (value withheld)" for x in _shown(body, typed)]

print("\n2. Demo button (demo=1): nothing real in any answer")
for p in PATHS:
    code, body = get(p + "&demo=1")
    lk = leaks(body)
    ok(f"{p.split('?')[0]:22s} {p.split('?')[1][:38]:38s} {len(body) // 1024:5d} KB", code == 200 and not lk, f"HTTP {code}" if code != 200 else ", ".join(lk))

print("\n3. A role without 'unmasked' (external), even with demo=0")
for p in PATHS[:2] + PATHS[9:11]:
    body = as_role(p + "&demo=0", {"view"})
    lk = leaks(body)
    ok(f"external {p.split('?')[0]:22s}", body and not lk, ", ".join(lk))

print("\n4. A demo viewer cannot test a raw address")
real_ip = next(iter(sorted(REAL_IPS)))
body = get(f"/api/insight?kind=src_ip&value={real_ip}&at={AT}&demo=1")[1]
d = json.loads(body) if body.strip().startswith("{") else {}
ok("a raw IP as host filter gives nothing in demo mode", d.get("total") == 0 and not leaks(body, typed=real_ip), f"total={d.get('total')}")

print("\n5. A demo viewer cannot test a real network name or AS number (only the aliases work)")
top = (st.get("src_network") or [{}])[0]
name, asn = top.get("value", ""), (top.get("asns") or [""])[0]
def total(path):
    code, body = get(path)
    return json.loads(body).get("total") if code == 200 and body.strip().startswith("{") else f"HTTP {code}"
n_real, n_alias = total(f"/api/insight?kind=src_asn&value={name}&at={AT}"), total(f"/api/insight?kind=src_asn&value={alias}&at={AT}&demo=1")
ok("normal mode: the real network name works", isinstance(n_real, int) and n_real > 0, f"total={n_real}")
ok("demo: its alias works", isinstance(n_alias, int) and n_alias > 0, f"total={n_alias}")
for label, v in (("real network name", name), ("real AS number", f"AS{asn}"), ("bare AS number", str(asn))):
    n = total(f"/api/insight?kind=src_asn&value={v}&at={AT}&demo=1")
    ok(f"demo: the {label} gives nothing", n == 0, f"total={n}")
for label, perms in (("external (no 'unmasked')", {"view"}),):
    body = as_role(f"/api/insight?kind=src_asn&value={name}&at={AT}&demo=0", perms)
    ok(f"{label}: the real network name gives nothing", json.loads(body).get("total") == 0, f"total={json.loads(body).get('total')}")
code, body = get(f"/api/svc/stats?at={AT}&asn={name}&demo=1")
sv = json.loads(body) if code == 200 else {}
ok("services, demo: a real network name as filter gives nothing", code == 200 and not (sv.get("total") or sv.get("hosts")),
   f"HTTP {code}, total={sv.get('total')}, hosts={sv.get('hosts')}")

print("\n6. Pinned events (full detail, kept in the browser) never outlive the account")
with tm.app.test_request_context("/"):
    pages = {}
    for role, perms in (("analyst", {"view", "unmasked", "export", "malpedia"}), ("external", {"view"})):
        g.user = {"user": f"lg-selftest-{role}", "role": role, "perms": perms, "csrf": None}
        r = tm.app.view_functions[tm.app.url_map.bind("localhost").match("/")[0]]()
        pages[role] = (r if isinstance(r, str) else r.get_data(as_text=True))
ok("the map page names its account (pins are stored per account)", 'data-user="lg-selftest-analyst"' in pages["analyst"])
ok("a masked account's page is marked masked (it stores no pins)", 'data-masked="1"' in pages["external"] and 'data-masked="1"' not in pages["analyst"])
js = open(os.path.join(tm.BASE_DIR, "static", "js", "app.js"), encoding="utf-8").read()
auth_js = open(os.path.join(tm.BASE_DIR, "static", "js", "auth-card.js"), encoding="utf-8").read()
ok("app.js: pins under the account's own key, only when unmasked; the old shared key removed",
   'const PIN_KEY = "tm.pins:" + (document.body.dataset.user' in js and "const PIN_STORE = !document.body.dataset.masked" in js
   and 'store.set("tm.pins"' not in js and 'store.get("tm.pins"' not in js and 'localStorage.removeItem("tm.pins")' in js)
ok("the login page (log out, expired session) removes every stored pin",
   'location.pathname.startsWith("/login")' in auth_js and 'k.startsWith("tm.pins:")' in auth_js)

print(f"\n{checks - len(fails)} of {checks} masking checks passed" + (f"; FAILED: {fails}" if fails else ""))
sys.exit(1 if fails else 0)
