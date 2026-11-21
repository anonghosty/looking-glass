"""Address blocks to choose from in Settings, in the Network names & types table's Constituent column ("Some address
blocks" opens a network's row with its blocks; the user's design, 2026-11-21).

Each loaded day counts its records per address block, before the constituency applies, like the networks' counts: an
IPv4 address in its /24, an IPv6 address in its /48. A block belongs to the network most of its records are in. The
Settings page lists one network's blocks, busiest first, and the administrator ticks the ones that are constituents;
they are saved as address ranges (CIDRs) with Apply settings, as before. Nothing is looked up outside: only what the
reports hold.

tally(rows, sides, country) -> Counter{(block, asn): records}   (called by both day loaders)
API (administrators: the "settings" permission):
  GET /api/settings/address-blocks            -> {blocks: [{block, records, asn, network, covered}], day, total, shown}
  GET /api/settings/address-blocks?asn=N      -> {asn, blocks: [{block, records}], total, shown, day}
  GET /api/settings/address-blocks?summary=1  -> {counts: {asn: blocks}, owners: {saved range: asn}, day}
"""
import ipaddress
from collections import Counter

from flask import jsonify, request

MAX_LISTED = 5000           # the busiest blocks; a search on the page looks through these
MAX_NETWORK = 20000         # one network's blocks ("Some address blocks" in the Constituent column)


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


def _gather(days):
    """Records per block and, per block, the records per AS number, over the given days (each with .block_raw)."""
    per, asn_of = Counter(), {}
    for d in days:
        for (blk, asn), n in (getattr(d, "block_raw", None) or {}).items():
            per[blk] += n
            asn_of.setdefault(blk, Counter())[asn] += n
    return per, asn_of


def _main_asn(asn_of, blk):
    """The network most of a block's records belong to ("" when not known)."""
    return asn_of[blk].most_common(1)[0][0] if asn_of.get(blk) else ""


def listing(days, company, covered, limit=MAX_LISTED):
    """The blocks of the given days (each with .block_raw), busiest first: records, the network most of them are in."""
    per, asn_of = _gather(days)
    rows = []
    for blk, n in per.most_common(limit):
        asn = _main_asn(asn_of, blk)
        rows.append({"block": blk, "records": n, "asn": asn, "network": company(asn) if asn else "",
                     "covered": covered(blk, asn)})
    return rows, len(per)


def of_network(days, asn, limit=MAX_NETWORK):
    """One network's blocks (those most of whose records are in it), busiest first, for the Constituent column's
    "Some address blocks": [{block, records}], and how many it has."""
    per, asn_of = _gather(days)
    mine = [(blk, n) for blk, n in per.items() if _main_asn(asn_of, blk) == asn]
    mine.sort(key=lambda x: (-x[1], x[0]))
    return [{"block": b, "records": n} for b, n in mine[:limit]], len(mine)


def summary(days, nets):
    """How many blocks each network has, and which network each saved range that is exactly one of those blocks
    belongs to (so the page shows it as that network's chosen block; any other range is an "other address range")."""
    per, asn_of = _gather(days)
    counts = Counter()
    for blk in per:
        a = _main_asn(asn_of, blk)
        if a:
            counts[a] += 1
    owners = {}
    for n in nets or []:
        k = str(n)
        if k in per:
            a = _main_asn(asn_of, k)
            if a:
                owners[k] = a
    return dict(counts), owners


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
        asn = request.args.get("asn", "").strip()
        if asn:                                   # one network's blocks (the Constituent column's "Some address blocks")
            if not asn.isdigit() or len(asn) > 10:
                return jsonify(error="An AS number is digits only."), 400
            rows, total = of_network(ctx["days"](), asn)
            return jsonify(asn=asn, blocks=rows, total=total, shown=len(rows), day=ctx["day"]())
        if request.args.get("summary"):           # blocks per network, and the saved ranges that are such blocks
            st = ctx["settings"]
            counts, owners = summary(ctx["days"](), getattr(st, "nets", None) or [])
            return jsonify(counts=counts, owners=owners, day=ctx["day"]())
        rows, total = listing(ctx["days"](), ctx["company"], covered)
        return jsonify(blocks=rows, total=total, shown=len(rows), day=ctx["day"]())

    return {"listing": listing, "covered": covered, "of_network": of_network, "summary": summary}
