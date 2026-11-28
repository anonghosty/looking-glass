# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""Address blocks to choose from in Settings, in the Network names & types table's Constituent column ("Some address
blocks" opens a network's row with its blocks; the user's design, 2026-11-21).

Each loaded day counts its records per address block and network, before the constituency applies, like the networks'
counts (both sides of a record): an IPv4 address in its /24, an IPv6 address in its /48. A network's row lists every
block it has records in, busiest first, with its own records there (a block two networks share is listed under both);
the administrator ticks the ones that are constituents; they are saved as address ranges (CIDRs) with Apply settings,
as before. Nothing is looked up outside: only what the reports hold.

tally(rows, sides) -> Counter{(block, asn): records}            (called by both day loaders)
network_records(days) -> Counter{asn: records} or None          (the network list's Records column, app.py)
API (administrators: the "settings" permission):
  GET /api/settings/address-blocks            -> {blocks: [{block, records, asn, network, covered}], day, total, shown}
  GET /api/settings/address-blocks?asn=N      -> {asn, blocks: [{block, records}], total, shown, day}
  GET /api/settings/address-blocks?summary=1  -> {counts: {asn: blocks}, owners: {saved range: asn},
                                                   info: {saved range: {asn, nets, part, exact, seen}}, day}
  GET /api/settings/address-blocks?add=R&for=N -> {range, info} or 400 {error}  (a network's row: "Add a block")
  GET /api/settings/address-blocks?check=R    -> {range} or 400 {error}          (Other address ranges: Add)
A saved range stays with its network on the page whether or not it has records: its network is the one it was chosen
under (data/constituency_blocks.json, written by Apply settings: remember()), else from yesterday's blocks, else from
every day in memory (all_days), else it is shown under Other address ranges. The settings themselves are unchanged.
"""
import ipaddress
import json
import os
import threading
from collections import Counter

from flask import jsonify, request

MAX_LISTED = 5000           # the busiest blocks; a search on the page looks through these
MAX_NETWORK = 20000         # one network's blocks ("Some address blocks" in the Constituent column)
CHOSEN_FILE = "constituency_blocks.json"   # beside settings.json: {range: AS number it was chosen under}
MAX_CHOSEN = 500            # as many as the saved ranges (settings.Settings.MAX_CIDRS)
_write_lock = threading.Lock()


# ---- which network each block was chosen under (r90, the user's "remember it"): a small file beside settings.json,
# written only when Apply settings saves (app.py, administrators). The settings themselves (AS numbers + ranges, what
# the platforms read) are unchanged; this file only tells the Settings page which row to show a range in. A missing,
# unreadable or edited file means no records: the page falls back to what the reports hold.
def chosen_path(settings):
    return os.path.join(os.path.dirname(os.path.abspath(settings.path)), CHOSEN_FILE)


def _clean_pairs(d):
    out = {}
    if not isinstance(d, dict):
        return out
    for k, v in list(d.items())[:MAX_CHOSEN]:
        net, a = _as_net(k) if isinstance(k, str) else None, str(v).strip() if isinstance(v, (str, int)) else ""
        if net is not None and a.isdigit() and len(a) <= 10:
            out[str(net)] = a
    return out


def load_chosen(path):
    """{range: AS number} from the file; {} when it is missing, unreadable or not what this module writes."""
    try:
        with open(path, encoding="utf-8") as fh:
            return _clean_pairs(json.load(fh))
    except (OSError, ValueError, TypeError):
        return {}


def remember(path, cidrs, sent):
    """After Apply settings saved the ranges (cidrs): record, for each saved range the page ticked or added in a
    network's row, that network (sent: {range: AS number}); a range no longer saved is dropped. sent not given (an
    older page, a script): the records of the ranges still saved are kept. Written atomically, readable by the service
    only (0600). Returns the number of records."""
    keep = {str(c) for c in cidrs or []}
    base = load_chosen(path) if not isinstance(sent, dict) else _clean_pairs(sent)
    out = {k: v for k, v in sorted(base.items()) if k in keep}
    with _write_lock:
        tmp = path + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(out, fh, indent=1)
        os.replace(tmp, path)
    return len(out)


def block_of(ip):
    """The /24 (IPv4) or /48 (IPv6) an address is in, as text; "" for anything that is not an address."""
    ip = str(ip or "").strip()
    if not ip:
        return ""
    if ip.count(".") == 3 and ":" not in ip:          # the common case, without building an address object
        a, b, c, d = ip.split(".")
        # ASCII digits only: "²" is a digit to isdigit() but not to int(), and broke a whole day's load (audit 2026-11-27, 1-10)
        if all(x.isascii() and x.isdigit() and int(x) < 256 for x in (a, b, c, d)):
            return f"{int(a)}.{int(b)}.{int(c)}.0/24"
        return ""
    try:
        return str(ipaddress.ip_network(f"{ip}/48", strict=False)) if ipaddress.ip_address(ip).version == 6 else ""
    except ValueError:
        return ""


def tally(rows, sides):
    """Records per (block, AS number). sides: (ip field, asn field) per side of a record; every side with an address
    counts, whatever its country, like the network list's Records column (asn_raw): a network with records always has
    the blocks they are in to choose from (r90; before, a side abroad was left out, so a network seen only on the other
    side of a communication had records but no blocks)."""
    out = Counter()
    for e in rows:
        for ipf, asf in sides:
            ip = e.get(ipf)
            if not ip:
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


def network_records(days):
    """Records per AS number on the given days (each with .asn_raw: a record counts for each network on either side,
    before the constituency), for the Network names & types table's Records column. None when no day is loaded, so
    the table shows "not known" rather than 0."""
    days = [d for d in days or [] if d is not None]
    if not days:
        return None
    out = Counter()
    for d in days:
        for a, n in (getattr(d, "asn_raw", None) or {}).items():
            out[str(a)] += n
    return out


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
    """One network's blocks for the Constituent column's "Some address blocks": every block in which it has records
    (on either side of a record), with its own records there, busiest first: [{block, records}], and how many it has.
    A block shared by two networks is listed under both, each with its own count (r90; before, only the blocks most
    of whose records were in it, so a network with a few records could have none to choose)."""
    per, asn_of = _gather(days)
    asn = str(asn)
    mine = [(blk, c[asn]) for blk, c in asn_of.items() if c.get(asn)]
    mine.sort(key=lambda x: (-x[1], x[0]))
    return [{"block": b, "records": n} for b, n in mine[:limit]], len(mine)


def blocks_in(net):
    """The blocks (/24 or /48) an address range touches, as text: the one block it sits in when it is a block or
    narrower, each block when it is wider (up to 256 blocks: a /16 or an IPv6 /40); a wider range: none (it is not
    one network's)."""
    size = 24 if net.version == 4 else 48
    if net.prefixlen >= size:
        return [str(net.supernet(new_prefix=size))]
    if size - net.prefixlen > 8:
        return []
    return [str(s) for s in net.subnets(new_prefix=size)]


def range_info(per, asn_of, net):
    """What the given days hold for one address range: the network it belongs to (asn: the one network most of the
    records of its blocks are in; "" when its blocks have no records or are mainly in different networks), the records
    each network has in it (nets: {asn: records}; for a range narrower than a block, those of the block it sits in:
    part=True), and whether it is exactly one block (exact: it is then listed under every network in nets)."""
    blks = [b for b in blocks_in(net) if b in per]
    owners = {_main_asn(asn_of, b) for b in blks} - {""}
    nets = Counter()
    for b in blks:
        for a, n in asn_of[b].items():
            if a:
                nets[a] += n
    size = 24 if net.version == 4 else 48
    return {"asn": owners.pop() if len(owners) == 1 else "", "nets": dict(nets), "part": net.prefixlen > size,
            "exact": net.prefixlen == size}


def _as_net(text):
    try:
        return ipaddress.ip_network(str(text).strip(), strict=False)
    except ValueError:
        return None


def _resolve(net, yday, every):
    """range_info on yesterday's blocks, with its network taken from every day in memory when yesterday does not
    tell (seen: "yesterday", "earlier" or "": not seen in the reports yet)."""
    i = range_info(*yday, net)
    i["seen"] = "yesterday" if i["asn"] else ""
    if not i["asn"] and every[0]:
        a = range_info(*every, net)["asn"]
        if a:
            i["asn"], i["seen"] = a, "earlier"
    return i


def summary(days, nets, all_days=None, chosen=None):
    """How many blocks each network has records in (on the given days: yesterday), and, for each saved range, the
    network it belongs to, so the page shows it in that network's row as a chosen block whether or not it has records:
    from yesterday's blocks; else from every day in memory (all_days); else not known, and the page keeps it under
    Other address ranges ("not seen in the reports yet"). chosen: {range: AS number} the network each range was
    chosen under (load_chosen), which comes first. info: {range: {asn, nets, part, exact, seen, remembered}}."""
    yday = _gather(days)
    counts = Counter()
    for c in yday[1].values():
        for a in c:
            if a:
                counts[a] += 1
    every = _gather(all_days) if all_days else ({}, {})
    owners, info = {}, {}
    for n in nets or []:
        net = n if isinstance(n, (ipaddress.IPv4Network, ipaddress.IPv6Network)) else _as_net(n)
        if net is None:
            continue
        i = _resolve(net, yday, every)
        i["remembered"] = bool((chosen or {}).get(str(net)))
        if i["remembered"]:
            i["asn"] = chosen[str(net)]
        info[str(net)] = i
        if i["asn"]:
            owners[str(net)] = i["asn"]
    return dict(counts), owners, info


def clean_range(text):
    """An address range as Other address ranges takes it (settings.Settings.validate: a range or a single address,
    written the standard way): (range, "") or (None, error)."""
    text = str(text or "").strip()
    if not text:
        return None, "Type an address range or a single address first."
    net = _as_net(text) if len(text) <= 64 else None
    return (str(net), "") if net is not None else (None, f"not an address range: {text[:64]}")


def check_add(text, asn, days, all_days=None, company=None):
    """The "Add a block" box in a network's open row: (clean range, info) or (None, error). Read like Other address
    ranges (clean_range), except that an address alone adds the block (/24 or /48) it is in; refused when the reports
    put the range in another network and this one has no records in it."""
    text = str(text or "").strip()
    if text and "/" not in text and block_of(text):
        text = block_of(text)
    rng, err = clean_range(text)
    if rng is None:
        return None, err
    net = ipaddress.ip_network(rng)
    i = _resolve(net, _gather(days), _gather(all_days) if all_days else ({}, {}))
    asn = str(asn)
    if i["asn"] and i["asn"] != asn and not i["nets"].get(asn):
        name = company(i["asn"]) if company else ""
        other = f"{name} (AS{i['asn']})" if name and name != f"AS{i['asn']}" else f"AS{i['asn']}"
        return None, (f"{rng} is in the reports as part of {other}, not of AS{asn}: choose it in that network's row, "
                      "or under Other address ranges.")
    if not i["asn"]:
        i["asn"] = asn                        # not seen in the reports yet: it is this network's, as the user says
    return rng, i


def install(app, ctx):
    """ctx: has_perm, days() -> the loaded days of both platforms for the replay day, company(asn), settings, day(),
    all_days() (optional) -> every day both platforms hold in memory (a saved range's network when yesterday has none)."""
    hp = ctx["has_perm"]

    def all_days():
        try:
            return list(ctx["all_days"]()) if ctx.get("all_days") else []
        except RuntimeError:                      # a day loaded or dropped meanwhile: yesterday's blocks only
            return []

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
        if request.args.get("summary"):           # blocks per network, and the network of each saved range
            st = ctx["settings"]
            chosen = load_chosen(chosen_path(st)) if getattr(st, "path", None) else {}
            counts, owners, info = summary(ctx["days"](), getattr(st, "nets", None) or [], all_days(), chosen)
            return jsonify(counts=counts, owners=owners, info=info, day=ctx["day"]())
        if "add" in request.args:                 # the open row's "Add a block": checked here as well as on the page
            asn = request.args.get("for", "").strip()
            if not asn.isdigit() or len(asn) > 10:
                return jsonify(error="An AS number is digits only."), 400
            rng, info = check_add(request.args.get("add", ""), asn, ctx["days"](), all_days(), ctx["company"])
            if rng is None:
                return jsonify(error=info), 400
            return jsonify(range=rng, info=info, day=ctx["day"]())
        if "check" in request.args:               # Other address ranges' Add: the range written the standard way
            rng, err = clean_range(request.args.get("check", ""))
            if rng is None:
                return jsonify(error=err), 400
            return jsonify(range=rng)
        rows, total = listing(ctx["days"](), ctx["company"], covered)
        return jsonify(blocks=rows, total=total, shown=len(rows), day=ctx["day"]())

    return {"listing": listing, "covered": covered, "of_network": of_network, "summary": summary, "check_add": check_add,
            "clean_range": clean_range}
