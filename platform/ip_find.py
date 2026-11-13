"""Every IP address inside a piece of text, found the same way by every masker (external review, 2026-11-12).

Before, the researchers' masker (hostmask.py) and the masked viewers' (host_label.py) each had their own patterns,
and each let different spellings through: v41.66.1.2 (a letter glued on), id_41.66.1.2, ip:2001:db8::1 (IPv6 after a
colon), 041.066.001.002 (leading zeros) and app.41.66.1.2.nip.io (an address inside a host name). Over-masking is
preferred to a leak, so here an address only has to stand clear of other DIGITS (and of a dotted number it is part of,
as in a version 1.2.3.4.5); letters, underscores, colons and dots around it do not protect it. The one exception: a
four-part number the text itself names as a version ("version 2.0.1.3", "Apache/2.0.1.3"), with nothing glued after it.

spans(text) -> [(start, end, address)]   the address normalised (leading zeros dropped), so 041.066.001.002 and
                                          41.66.1.2 are the same host to every masker.
sub(text, fn) -> text with fn(address) in place of each one.
"""
import bisect
import ipaddress
import re

# IPv4: four parts of up to three digits (after any leading zeros), not glued to another digit, not one piece of a
# longer dotted number (1.2.3.4.5)
_V4 = re.compile(r"(?<!\d)(?<!\d\.)((?:0*\d{1,3}\.){3}0*\d{1,3})(?!\d)(?!\.\d)")
# IPv6 candidates: runs of hex digits, colons and dots (dots for an IPv4 tail, ::ffff:41.66.1.2; review 2026-11-13: the
# run used to stop before the tail, so only "::ffff:41" was masked and ".66.1.2" was left); checked with ipaddress below
_V6 = re.compile(r"[0-9A-Fa-f:.]*:[0-9A-Fa-f:.]*")
# the longest IPv6 text there is (8 groups, or 6 groups and an IPv4 tail) is 45 characters, with at most 7 colons;
# nothing longer is tried, so the work grows with the length of the text, not its square (review 2026-11-13: 3,000
# colons took 6.9 s)
_V6_MAX = 45
_COLONS3 = re.compile(r":{3,}")
# A four-part version number is not an address when the text says so right before it (review follow-up, 2026-11-12):
#   a version word and a separator   "version 2.0.1.3", "Build: 1.2.3.4", "firmware=10.4.0.12"
#   a product name and a slash       "Apache/2.0.1.3", "RouterOS/6.49.10.1"  (not a path: "/api/41.66.1.2" stays masked)
# A bare "v" is NOT enough (v41.66.1.2 was one of the reviewer's leaks), nor is a word glued on with no separator.
_VERSION_BEFORE = re.compile(
    r"(?:(?<![A-Za-z0-9_])(?:version|ver|build|release|revision|rev|firmware|fw)\.?[ \t]*[:=][ \t]*"
    r"|(?<![A-Za-z0-9_])(?:version|ver|build|release|revision|rev|firmware|fw)\.?[ \t]+"
    r"|(?<![\w/.:-])[A-Za-z][A-Za-z_-]{1,40}/)$", re.I)


def _is_version(text, start, end):
    """True when the text names the dotted number as a version just before it, and nothing is glued on after it
    ("build 41.66.1.2a" stays masked)."""
    if end < len(text) and (text[end].isalnum() or text[end] == "_"):
        return False
    return bool(_VERSION_BEFORE.search(text[max(0, start - 60):start]))


def _v4(s):
    parts = s.split(".")
    try:
        nums = [int(p) for p in parts]
    except ValueError:
        return None
    if len(nums) != 4 or any(n > 255 for n in nums):
        return None
    return ".".join(str(n) for n in nums)


def _segments(run):
    """The run cut where three or more colons stand together (no address holds ':::'); each piece keeps two of those
    colons on either side, so 'a:::1' still offers 'a::' and '::1'. Yields (offset, piece)."""
    pos = 0
    for m in _COLONS3.finditer(run):
        yield pos, run[pos:m.start() + 2]
        pos = m.end() - 2
    yield pos, run[pos:]


def _shape(cand):
    """A cheap test before ipaddress: 2 to 7 colons, groups of at most 4 hex digits, dots only in a last IPv4 group,
    and '::' unless every group is there (7 colons, or 6 with an IPv4 tail)."""
    n = cand.count(":")
    if not 2 <= n <= 7:
        return False
    groups = cand.split(":")
    if any("." in g for g in groups[:-1]) or any(len(g) > 4 for g in groups[:-1]):
        return False
    last = groups[-1]
    if "." in last:
        if last.count(".") != 3 or n > 6:
            return False
    elif len(last) > 4:
        return False
    return "::" in cand or n == 7 or (n == 6 and "." in last)


def _v6_in(seg):
    """Every real IPv6 address inside one piece, left to right, the longest at each place (a prefix such as 'ip:' or a
    port suffix such as ':443' does not hide it), as [(offset, length, normalised)]."""
    if seg.count(":") < 2:
        return []
    starts = [0] + [i + 1 for i, ch in enumerate(seg) if ch in ":."]
    stops = sorted({len(seg)} | {i for i, ch in enumerate(seg) if ch in ":."})
    found, done = [], 0
    for a in starts:
        if a < done:
            continue
        best = None
        hi = bisect.bisect_right(stops, a + _V6_MAX)    # only ends within the 45 characters an address can have
        for b in reversed(stops[:hi][-24:]):            # longest first; at most 24 ends fit in 45 characters
            if b - a < 3:                               # not a bare '::'
                break
            cand = seg[a:b]
            if not _shape(cand):
                continue
            try:
                ip = ipaddress.IPv6Address(cand)
                # an IPv4-mapped address is that IPv4 host: the same label everywhere
                best = (a, b - a, str(ip.ipv4_mapped) if ip.ipv4_mapped else str(ip))
                break
            except ValueError:
                continue
        if best:
            found.append(best)
            done = a + best[1]
    return found


def spans(text):
    if not text or not isinstance(text, str):
        return []
    v4 = []
    for m in _V4.finditer(text):
        ip = _v4(m.group(1))
        if ip and not _is_version(text, m.start(1), m.end(1)):
            v4.append((m.start(1), m.end(1), ip))
    v6 = [(m.start() + off + o, m.start() + off + o + n, ip)
          for m in _V6.finditer(text) for off, seg in _segments(m.group(0)) for o, n, ip in _v6_in(seg)]
    # one sweep over both, left to right (both lists are in order): an IPv6 address that touches an IPv4 (an
    # IPv4-mapped tail) replaces it and covers all of it even where the two only partly overlap, so no digits of
    # either are left; overlapping hits are joined into one
    # (weight: which hit names a joined span; an IPv4 inside wins, then the longer address)
    out, i = [], 0
    for a, b, ip in v6:
        while i < len(v4) and v4[i][1] <= a:
            out.append(v4[i] + (1000,)); i += 1
        w = b - a
        over = []
        while i < len(v4) and v4[i][0] < b:
            over.append(v4[i]); i += 1
        if over:
            a, b = min(a, over[0][0]), max(b, over[-1][1])
            if len(over) == 1:                          # the IPv4 inside it is the host (::ffff:041.066.001.002)
                ip, w = over[0][2], 1000
        if out and out[-1][1] > a:
            pa, pb, pip, pw = out.pop()
            a, b = min(a, pa), max(b, pb)
            if pw >= w:
                ip, w = pip, pw
        out.append((a, b, ip, w))
    out += [s + (1000,) for s in v4[i:]]
    return [(a, b, ip) for a, b, ip, _ in out]


def sub(text, fn):
    if not text or not isinstance(text, str):
        return text
    parts, pos = [], 0
    for a, b, ip in spans(text):
        if a < pos:
            continue
        parts += [text[pos:a], fn(ip)]
        pos = b
    parts.append(text[pos:])
    return "".join(parts)
