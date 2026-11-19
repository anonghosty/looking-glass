"""Address blocks to pick from in Settings → Constituency (the user, 2026-11-19: "i still cant select ip ranges in
settings"; answer: pick from a list).

Each loaded day counts its records per address block, before the constituency applies, like the networks' counts: an
IPv4 address in its /24, an IPv6 address in its /48. The Settings page lists the blocks of the days in memory on both
platforms, with their records and the network most of them belong to, and the administrator ticks the ones to add to
the extra address ranges (typing a range stays possible). Nothing is looked up outside: only what the reports hold.

tally(rows, sides, country) -> Counter{(block, asn): records}   (called by both day loaders)
API: GET /api/settings/address-blocks (administrators: the "settings" permission) -> {blocks: [{block, records, asn,
network, covered}], day, total, shown}
"""
import ipaddress
from collections import Counter

from flask import jsonify

MAX_LISTED = 5000           # the busiest blocks; a search on the page looks through these


def block_of(ip):
    """The /24 (IPv4) or /48 (IPv6) an address is in, as text; "" for anything that is not an address."""
    ip = str(ip or "").strip()
    if not ip:
        return ""
    if ip.count(".") == 3 and ":" not in ip:          # the common case, without building an address object
        a, b, c, d = ip.split(".")
        if all(x.isdigit() and int(x) < 256 for x in (a, b, c, d)):
            return f"{int(a)}.{int(b)}.{int(c)}.0/24"
        return ""
    try:
        return str(ipaddress.ip_network(f"{ip}/48", strict=False)) if ipaddress.ip_address(ip).version == 6 else ""
    except ValueError:
        return ""


def tally(rows, sides, country=""):
    """Records per (block, AS number). sides: (ip field, asn field, country field) per side of a record; a side is
    counted when its country is this installation's country (or not given), so a foreign sinkhole or attacker is not
    offered as part of the constituency."""
    out = Counter()
    country = (country or "").upper()
    for e in rows:
        for ipf, asf, geof in sides:
            ip = e.get(ipf)
            if not ip:
                continue
            g = str(e.get(geof) or "").upper() if geof else ""
            if country and g and g != country:
                continue
            blk = block_of(ip)
            if blk:
                out[(blk, str(e.get(asf) or ""))] += 1
    return out


def listing(days, company, covered, limit=MAX_LISTED):
    """The blocks of the given days (each with .block_raw), busiest first: records, the network most of them are in."""
    per, asn_of = Counter(), {}
    for d in days:
        for (blk, asn), n in (getattr(d, "block_raw", None) or {}).items():
            per[blk] += n
            asn_of.setdefault(blk, Counter())[asn] += n
    rows = []
    for blk, n in per.most_common(limit):
        asn = asn_of[blk].most_common(1)[0][0] if asn_of.get(blk) else ""
        rows.append({"block": blk, "records": n, "asn": asn, "network": company(asn) if asn else "",
                     "covered": covered(blk, asn)})
    return rows, len(per)


def install(app, ctx):
    """ctx: has_perm, days() -> the loaded days of both platforms for the replay day, company(asn), settings, day()."""
    hp = ctx["has_perm"]

    def covered(blk, asn):
        """Already in the constituency: its network is chosen, or an extra range holds the whole block."""
        st = ctx["settings"]
        if not st.restricted:
            return False
        if asn and asn in st.asns:
            return True
        try:
            net = ipaddress.ip_network(blk)
        except ValueError:
            return False
        return any(net.version == n.version and net.subnet_of(n) for n in st.nets)

    @app.route("/api/settings/address-blocks")
    def api_address_blocks():
        if not hp("settings"):                    # network names and address blocks: administrators only
            return jsonify(error="Settings are for admin accounts."), 403
        rows, total = listing(ctx["days"](), ctx["company"], covered)
        return jsonify(blocks=rows, total=total, shown=len(rows), day=ctx["day"]())

    return {"listing": listing, "covered": covered}
