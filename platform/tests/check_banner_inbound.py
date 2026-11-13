#!/usr/bin/env python3
"""What masked viewers and researchers get from banners, line hashes and Spam URL records (review 2026-11-13). Offline:
no server, no database.
- a masked event carries no line hash, event ID or record ID (a hash of the raw line confirms a guessed address)
- services: product, vendor, device type and version reach a masked viewer with host names and addresses masked; a
  masked viewer's filter on them matches the masked value only, so a guessed host name tells nothing; analysts
  (unmasked) keep the full text and filters
- the researchers' Definitions page (services_kb) counts banners masked
- Intel: a Spam URL record (the "inbound" layout: src is the spam relay, the constituent; ip / hostname / url are a link
  found in the spam) names its link host "Spam link host", never "C2 domain"; masked when the link points into the
  constituency, kept when it points abroad; a sinkhole record still names its C2 domain
Run: .venv/bin/python tests/check_banner_inbound.py"""
import json, os, sys
from types import SimpleNamespace
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import privacy as P  # noqa: E402
import services as S  # noqa: E402
import intel as I  # noqa: E402

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info and not cond else ""), flush=True)


print("Masked events: no line hash, event ID or record ID")
R = P.AsnRegistry(os.path.join(os.path.dirname(os.path.abspath(__file__)), "does-not-exist.json"))
ev = {"src_ip": "198.51.100.23", "dst_ip": "203.0.113.9", "src_asn": "", "dst_asn": "", "line_hash": "ab" * 32,
      "event_id": "e-1234567", "_id": "65f0c0ffee", "extras": {}}
mv = P.mask_event(ev, R)
ok("line_hash, event_id and _id are not sent", not any(k in mv for k in ("line_hash", "event_id", "_id")), str(sorted(mv)))
ok("…the unmasked event is untouched", ev["line_hash"] == "ab" * 32)

print("Services banners for masked viewers")
for raw, gone in (("Apache httpd on mail.example.org", "mail.example.org"), ("RouterOS 198.51.100.7 admin", "198.51.100.7"),
                  ("admin@example.org web panel", "admin@example.org")):
    m = S.banner_mask(raw)
    ok(f"{raw!r} -> {m!r}", gone not in m and m)
for raw, gone in (("Apache on 41-66-1-2.static.telco.com.gh", "41-66-1-2"), ("41-66-1-2.static.telco.com.gh", "telco"),
                  ("dsl-41-66-1-2.vodafone.com.gh", "vodafone"), ("1.static.example.org", "example")):
    m = S.banner_mask(raw)
    ok(f"a name whose first label is digits and dashes: {raw!r} -> {m!r}", gone not in m and "<" in m)
ok("plain software and versions stay", S.banner_mask("OpenSSH 8.9p1 Ubuntu-3ubuntu0.6") == "OpenSSH 8.9p1 Ubuntu-3ubuntu0.6",
   S.banner_mask("OpenSSH 8.9p1 Ubuntu-3ubuntu0.6"))
ok("an empty value stays empty", S.banner_mask("") == "")
e = {"product": "Apache httpd on mail.example.org", "vendor": "", "issues": [], "tags": []}
masked_flt = {"product": S.MaskedValues({"Apache httpd on mail.example.org"})}
ok("a masked viewer's filter with the real host name matches nothing", not S.matches(e, masked_flt))
ok("…the masked value it was shown matches", S.matches(e, {"product": S.MaskedValues({S.banner_mask(e["product"])})}))
ok("an analyst's filter with the full text still matches", S.matches(e, {"product": {"Apache httpd on mail.example.org"}}))


class Refs:
    def __init__(self, masked):
        self.masked = masked

    def strict(self):
        return self.masked

    def resolve(self, v):
        return v


from werkzeug.datastructures import MultiDict  # noqa: E402
f_masked = S.parse_filters(MultiDict([("product", "x")]), Refs(True), None)
f_plain = S.parse_filters(MultiDict([("product", "x")]), Refs(False), None)
ok("parse_filters: masked request -> compared masked; unmasked -> as typed",
   type(f_masked["product"]) is S.MaskedValues and type(f_plain["product"]) is not S.MaskedValues)

print("Definitions page (researchers): banners counted masked")
import services_kb as KB  # noqa: E402
day = SimpleNamespace(events=[{"report": "scan_http", "ip": f"192.0.2.{i}", "product": "Apache on host7.example.org",
                               "vendor": "Acme 198.51.100.7", "device_type": "", "version": "2.4", "port": 80,
                               "protocol": "tcp", "severity": "low", "issues": [], "tags": []} for i in range(6)])
KB._STATS.update(at=0, data=None)
st, _ = KB._stats(SimpleNamespace(days={"2026-11-13": day}))
blob = json.dumps(st)
ok("no host name or address in the products, devices or versions", "example.org" not in blob and "198.51.100.7" not in blob, blob[:200])
ok("…the software is still counted", any("Apache" in p for p, _ in st["scan_http"]["products"]))
KB._STATS.update(at=0, data=None)

print("Intel: Spam URL records")
I.INBOUND.clear(); I.INBOUND.add("spam_url"); I.COUNTRY["code"] = "GH"
base = {"source": "spam_url", "src_ip": "192.0.2.10", "infection": "spam_url", "tag": "", "family": "", "application": "",
        "http_agent": "", "ssl_servername": "", "extras": {}}
abroad = dict(base, dst_hostname="cheap-pills.example.net", http_host="", http_url="http://cheap-pills.example.net/buy", dst_geo="NL")
home = dict(base, dst_hostname="shop.example.gh", http_host="", http_url="http://shop.example.gh/promo", dst_geo="GH")


def kinds(e):
    fields, masked = I._comms(e)
    out = {}
    for k, f in fields:                    # two fields can give one kind (http_host and dst_hostname)
        out.setdefault(k, []).extend(I._values(e, f, k, svc=masked))
    return out


ka, kh = kinds(abroad), kinds(home)
ok("never a 'C2 domain' in a Spam URL record", "C2 domain" not in ka and "C2 domain" not in kh)
ok("a link abroad: 'Spam link host' cheap-pills.example.net", ka.get(I.SPAM_HOST) == ["cheap-pills.example.net"], str(ka.get(I.SPAM_HOST)))
ok("a link into the constituency: its host is masked out", not kh.get(I.SPAM_HOST) and "shop.example.gh" not in json.dumps(kh), json.dumps(kh)[:200])
ok("…and so is the URL", all("shop.example.gh" not in v for v in kh.get("URL", [])), str(kh.get("URL")))
spelled = dict(base, dst_hostname="41-66-1-2.static.telco.com.gh", http_host="", http_url="http://41.66.1.2/pharma", dst_geo="GH")
ks = kinds(spelled)
ok("a link into the constituency whose name spells an address: masked too", "telco" not in json.dumps(ks) and "41-66-1-2" not in json.dumps(ks),
   json.dumps(ks)[:200])
ok("record_items (combination codes) follows the same rule", "shop.example.gh" not in json.dumps(I.record_items("infections", home, "spam-url")))
sink = dict(base, source="event4_sinkhole_http", http_host="c2.example.com", dst_hostname="", http_url="", dst_geo="US")
ok("a sinkhole record still names its C2 domain", kinds(sink).get("C2 domain") == ["c2.example.com"], str(kinds(sink).get("C2 domain")))
I.INBOUND.clear(); I.COUNTRY["code"] = ""

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
