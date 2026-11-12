"""Every IP address inside a piece of text, found the same way by every masker (external review, 2026-11-12).

Before, the researchers' masker (hostmask.py) and the masked viewers' (host_label.py) each had their own patterns,
and each let different spellings through: v41.66.1.2 (a letter glued on), id_41.66.1.2, ip:2001:db8::1 (IPv6 after a
colon), 041.066.001.002 (leading zeros) and app.41.66.1.2.nip.io (an address inside a host name). Over-masking is
preferred to a leak, so here an address only has to stand clear of other DIGITS (and of a dotted number it is part of,
as in a version 1.2.3.4.5); letters, underscores, colons and dots around it do not protect it.

spans(text) -> [(start, end, address)]   the address normalised (leading zeros dropped), so 041.066.001.002 and
                                          41.66.1.2 are the same host to every masker.
sub(text, fn) -> text with fn(address) in place of each one.
"""
import ipaddress
import re

# IPv4: four parts of up to three digits (after any leading zeros), not glued to another digit, not one piece of a
# longer dotted number (1.2.3.4.5)
_V4 = re.compile(r"(?<!\d)(?<!\d\.)((?:0*\d{1,3}\.){3}0*\d{1,3})(?!\d)(?!\.\d)")
# IPv6 candidates: runs of hex digits and colons (with an IPv4 tail allowed); checked with ipaddress below
_V6 = re.compile(r"[0-9A-Fa-f:]*:[0-9A-Fa-f:]*(?:\d{1,3}(?:\.\d{1,3}){3})?")


def _v4(s):
    parts = s.split(".")
    try:
        nums = [int(p) for p in parts]
    except ValueError:
        return None
    if len(nums) != 4 or any(n > 255 for n in nums):
        return None
    return ".".join(str(n) for n in nums)


def _v6(run):
    """The longest real IPv6 address inside a run of hex digits and colons (a prefix such as 'ip:' or a port suffix
    such as ':443' around it does not hide it), as (offset, length, normalised); None if there is none."""
    if run.count(":") < 2:
        return None
    cuts = [0] + [i + 1 for i, ch in enumerate(run) if ch == ":"]
    ends = [len(run)] + [i for i, ch in enumerate(run) if ch == ":"]
    best = None
    for a in cuts:
        for b in ends:
            if b - a < 3 or (best and b - a <= best[1]):
                continue
            cand = run[a:b]
            if cand.count(":") < 2:
                continue
            try:
                ip = ipaddress.IPv6Address(cand)
            except ValueError:
                continue
            best = (a, b - a, str(ip))
    return best


def spans(text):
    if not text or not isinstance(text, str):
        return []
    out = []
    for m in _V4.finditer(text):
        ip = _v4(m.group(1))
        if ip:
            out.append((m.start(1), m.end(1), ip))
    taken = [(a, b) for a, b, _ in out]
    for m in _V6.finditer(text):
        hit = _v6(m.group(0))
        if not hit:
            continue
        a, b = m.start() + hit[0], m.start() + hit[0] + hit[1]
        if any(a < y and x < b for x, y in taken):      # overlaps an IPv4 already found (an IPv4-mapped tail)
            taken_ip = [(x, y) for x, y in taken if a < y and x < b]
            out = [s for s in out if (s[0], s[1]) not in taken_ip]
        out.append((a, b, hit[2]))
        taken.append((a, b))
    return sorted(out)


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
