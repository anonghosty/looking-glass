#!/bin/sh
# runs itself with the project's own Python (.venv), from wherever it is called
''''exec "$(dirname -- "$0")/../.venv/bin/python" "$0" "$@" # '''
"""Unit tests of the masking (privacy.py) and the roles (auth.Roles). No database, no server, no live files: the
AS-number registry and the roles file are temporary copies with invented values (documentation ranges and AS64500+).

Usage: tests/test_privacy_roles.py      exit 0 = all passed, 1 = a failure"""
import json
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import privacy as P  # noqa: E402
from auth import DEFAULT_ROLES, LOWEST_ROLE, MANAGEMENT_ONLY, PERMS, Roles  # noqa: E402

fails, checks = [], 0


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond: fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info else ""), flush=True)


tmp = tempfile.mkdtemp(prefix="lg-unit-")
try:
    print("1. IP masking")
    ok("IPv4: first and third parts hidden", P.mask_ip("198.51.100.23") == "x.51.x.23", P.mask_ip("198.51.100.23"))
    ok("IPv4: the network prefix is gone (no lookup possible)", not P.mask_ip("203.0.113.9").startswith("203.0"))
    m6 = P.mask_ip("2001:db8:abcd:12::1")
    ok("IPv6: only the 2nd and last groups kept", m6 == "x:0db8:x:x:x:x:x:0001", m6)
    ok("empty and None give an empty string", P.mask_ip("") == "" and P.mask_ip(None) == "")
    ok("a non-address is treated as text (IPs inside masked)", P.mask_ip("host 198.51.100.23") == "host x.51.x.23")
    t = P.mask_text("GET http://198.51.100.23:8080/a?b=203.0.113.9 from 2001:db8:abcd:12::1")
    ok("text: every IPv4 and IPv6 inside masked", "198.51.100.23" not in t and "203.0.113.9" not in t and "2001:db8:abcd" not in t, t)
    ok("text: non-strings and empty pass through", P.mask_text(None) is None and P.mask_text("") == "" and P.mask_text(5) == 5)
    ok("text without addresses unchanged", P.mask_text("RouterOS 6.49 (stable)") == "RouterOS 6.49 (stable)")

    print("\n2. AS-number registry (aliases)")
    reg_path = os.path.join(tmp, "asns.json")
    json.dump({"asns": {
        "64500": {"name": "Example Telecom", "demo_alias": "Telco 1", "events_last_check": 900},
        "64501": {"name": "Example Telecom", "demo_alias": "Telco 9", "events_last_check": 10},
        "64502": {"name": "Sample University", "demo_alias": "Institution 1", "events_last_check": 50},
        "64503": {"demo_alias": "Provider 2"}}}, open(reg_path, "w"))
    R = P.AsnRegistry(reg_path)
    ok("normal label: name and AS number", R.label("64500", False) == "Example Telecom (AS64500)", R.label("64500", False))
    ok("demo label: the alias only", R.label("64500", True) == "Telco 1")
    ok("one company, one alias (the busiest ASN's)", R.alias("64501") == "Telco 1", R.alias("64501"))
    ok("an ASN without a name: alias in demo, AS number otherwise", R.label("64503", True) == "Provider 2" and R.label("64503", False) == "AS64503")
    ok("an unlisted ASN: 'Unlisted network' in demo, never its number", R.label("64999", True) == "Unlisted network")
    ok("no ASN: empty label", R.label("", True) == "" and R.label(None, False) == "")
    ok("company grouping: alias in demo, name otherwise", R.company("64501", True) == "Telco 1" and R.company("64501", False) == "Example Telecom")
    ok("resolve an alias: every ASN of the company", R.resolve("Telco 1") == {"64500", "64501"}, str(R.resolve("Telco 1")))
    ok("resolve a name (normal mode)", R.resolve("Sample University") == {"64502"})
    ok("resolve an AS number", R.resolve("AS64502") == {"64502"} and R.resolve("64502") == {"64502"})
    R.strict = lambda: True                                  # a masked request (demo mode, or a role without 'unmasked')
    ok("masked: an alias still resolves", R.resolve("Telco 1") == {"64500", "64501"})
    ok("masked: a real company name matches no network", not R.resolve("Example Telecom") & {"64500", "64501", "64502", "64503"}, str(R.resolve("Example Telecom")))
    ok("masked: a real AS number matches no network", not (R.resolve("AS64502") | R.resolve("64502")) & {"64500", "64501", "64502", "64503"})
    def boom(): raise RuntimeError("outside a request")
    R.strict = boom
    ok("outside a request: not strict, no crash", R.resolve("Sample University") == {"64502"})
    R.strict = lambda: False

    print("\n3. Event masking")
    ev = {"src_ip": "198.51.100.23", "dst_ip": "203.0.113.9", "src_asn": "64500", "dst_asn": "64502", "src_asn_name": "Example Telecom",
          "dst_asn_name": "Sample University", "src_hostname": "pc-17.example.net", "dst_hostname": "srv.example.org", "machine_name": "DESKTOP-ABC",
          "http_url": "http://198.51.100.23/x", "http_host": "203.0.113.9", "http_referer": "", "http_agent": "curl 198.51.100.23",
          "ssl_servername": "", "detail": "seen from 203.0.113.9", "filename": "", "src_city": "Example City",
          "extras": {"banner": "login 198.51.100.23", "count": 3, "url_scheme": "http via gw.example.net"}}
    mv = P.mask_event(ev, R)
    blob = json.dumps(mv)
    ok("no real address anywhere in the masked event", "198.51.100.23" not in blob and "203.0.113.9" not in blob, blob[:120])
    ok("no company name or AS number", "Example Telecom" not in blob and "Sample University" not in blob and "6450" not in blob)
    ok("ASNs and names become aliases", mv["src_asn"] == mv["src_asn_name"] == "Telco 1" and mv["dst_asn"] == "Institution 1")
    ok("host and machine names hidden", mv["src_hostname"] == mv["dst_hostname"] == mv["machine_name"] == "hidden")
    ok("extras: a field not on the allowlist is hidden and counted", "banner" not in mv["extras"] and mv["extras_hidden"] == 1)
    ok("extras: allowed text masked for hosts, numbers kept", mv["extras"]["url_scheme"] == "http via <host>" and mv["extras"]["count"] == 3)
    ok("location kept, marked as demo", mv["src_city"] == "Example City" and mv["demo"] is True)
    ok("the original event is not changed", ev["src_ip"] == "198.51.100.23" and ev["extras"]["banner"] == "login 198.51.100.23")

    print("\n4. Host references")
    H = P.HostRefs("unit-test-secret")
    r1 = H.ref("198.51.100.23")
    ok("a reference is opaque (no part of the address) and stable", "198" not in r1 and "51.100" not in r1 and H.ref("198.51.100.23") == r1 and len(r1) == 12)
    ok("another server secret gives another reference", P.HostRefs("other").ref("198.51.100.23") != r1)
    ok("a reference this server issued resolves", H.resolve(r1) == "198.51.100.23")
    H.strict = lambda: True
    ok("strict (demo): a raw address is refused", H.resolve("203.0.113.9") == "\x00unknown-reference")
    ok("strict (demo): an issued reference still resolves", H.resolve(r1) == "198.51.100.23")
    H.strict = lambda: False
    ok("normal mode: a raw address is accepted", H.resolve("203.0.113.9") == "203.0.113.9")
    def boom(): raise RuntimeError("outside a request")
    H.strict = boom
    ok("outside a request: not strict, no crash", H.resolve("203.0.113.9") == "203.0.113.9")

    print("\n5. Roles")
    rp = os.path.join(tmp, "roles.json")
    roles = Roles(rp)                                        # no file yet: the defaults
    ok("defaults: external sees only, masked (no 'unmasked')", roles.perms("external") == {"view"})
    ok("defaults: analyst sees unmasked, exports, Malpedia", roles.perms("analyst") == {"view", "unmasked", "export", "malpedia"})
    ok("defaults: researcher has Definitions and networks, not the platforms", roles.perms("researcher") == {"definitions", "networks"})
    ok("defaults: management has only the portal", roles.perms("management") == {MANAGEMENT_ONLY})
    ok("admin always has every permission", roles.perms("admin") == set(PERMS))
    ok("an unknown role has no permission", roles.perms("nobody") == set())
    ok("the lowest role is external and cannot unmask or export", LOWEST_ROLE == "external" and not {"unmasked", "export"} & roles.perms(LOWEST_ROLE))
    roles.save({"analyst": ["view", "unmasked", "management", "made-up"], "custom-x": ["view", "management"], "management": ["view", "unmasked"],
                "admin": ["view"]})
    ok("save: the management permission is stripped from other roles", MANAGEMENT_ONLY not in roles.perms("analyst") | roles.perms("custom-x"))
    ok("save: unknown permissions dropped", "made-up" not in roles.roles["analyst"])
    ok("save: management stays exactly the portal (no unmasked data)", roles.roles["management"] == [MANAGEMENT_ONLY])
    ok("save: admin cannot be reduced", roles.perms("admin") == set(PERMS) and roles.roles["admin"] == list(PERMS))
    json.dump({"external": ["view"], "rogue": ["view", "management"], "management": ["view"], "admin": []}, open(rp, "w"))
    roles = Roles(rp)                                        # a hand-edited file is cleaned on load
    ok("load: a hand-edited file cannot give the portal to another role", MANAGEMENT_ONLY not in roles.perms("rogue"))
    ok("load: management reset to the portal, admin to everything", roles.roles["management"] == [MANAGEMENT_ONLY] and roles.perms("admin") == set(PERMS))
    ok("load: the researcher role is added when missing", roles.perms("researcher") >= set(DEFAULT_ROLES["researcher"]) - {"networks"})
    print("\n6. People's names (definitions and reports: full name; audit: Full Name (username))")
    from people import People

    class FakeUsers:
        data = {"a.mensah": {"profile": {"full_name": "Ama Mensah"}}, "kofi": {"profile": {}}, "same": {"profile": {"full_name": "same"}}}
        def get(self, n): return self.data.get(n)
    pp = People(FakeUsers())
    ok("a researcher's definition shows their registered full name", pp.name("a.mensah") == "Ama Mensah")
    ok("an account without a full name shows its username", pp.name("kofi") == "kofi")
    ok("a removed account shows the name saved with the record", pp.name("gone.user", "Former Researcher") == "Former Researcher")
    ok("a removed account without a saved name shows the username", pp.name("gone.user") == "gone.user")
    ok("non-account values stay as they are", pp.name("Looking Glass") == "Looking Glass" and pp.name("") == "")
    ok("audit: Full Name (username)", pp.audit("a.mensah") == "Ama Mensah (a.mensah)")
    ok("audit: the username alone when there is no full name (or it is the same)", pp.audit("kofi") == "kofi" and pp.audit("same") == "same")
    rows = pp.with_names([{"key": "x", "by": "a.mensah"}, {"key": "y", "by": ""}, {"key": "z"}])
    ok("lists: authors named, rows without an author untouched", [r.get("by") for r in rows] == ["Ama Mensah", "", None])

    class BrokenUsers:
        def get(self, n): raise OSError("being rewritten")
    ok("accounts file unreadable for a moment: the username, no crash", People(BrokenUsers()).name("a.mensah") == "a.mensah")
finally:
    shutil.rmtree(tmp, ignore_errors=True)

print(f"\n{checks - len(fails)} of {checks} privacy and role unit tests passed" + (f"; FAILED: {fails}" if fails else ""))
sys.exit(1 if fails else 0)
