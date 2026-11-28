# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""What a masked viewer (the external role, demo mode, the Demo button) sees instead of an IP address: an opaque label.

Before, masking kept the 2nd and 4th parts of an address (x.161.x.34). A constituency sits in a handful of address
blocks, so those two parts left only a few hundred or thousand candidates, and the network alias, region and port
narrowed it further. Now no part of the address is shown: every address becomes "Host " + its opaque reference, an
HMAC of the address under the server's REF_SECRET (privacy.HostRefs). The same address always gets the same label on
one server (so a viewer can still follow one host across the screens, and the label works for "analyse this host"),
but nothing of the address can be read or computed back from it without the server's secret.

label(ip) -> "Host 3f9a2c41b07e"      label_text(text) -> every IPv4/IPv6 address inside the text replaced by its label
use(refs) is called by privacy.HostRefs, so labels are the app's own references (resolvable on the server only).
"""
PREFIX = "Host "
# (addresses inside text are found by ip_find.py, the one finder every masker shares: the patterns kept here were no
# longer used; removed in the audit of 2026-11-27)
_refs = None


def use(refs):
    global _refs
    _refs = refs


def _ref(ip):
    global _refs
    if _refs is None:                      # outside the app (a tool or a test): a private, random secret
        from privacy import HostRefs
        HostRefs()                         # registers itself through use()
    return _refs.ref(ip)


def label(ip):
    if not ip:
        return ""
    return PREFIX + _ref(str(ip).strip())


def label_text(s):
    """Every IPv4/IPv6 address inside the text as its label, found by ip_find (the one finder every masker shares:
    v41.66.1.2, id_41.66.1.2, ip:2001:db8::1, 041.066.001.002, app.41.66.1.2.nip.io are all addresses)."""
    if not s or not isinstance(s, str):
        return s
    import ip_find
    return ip_find.sub(s, label)
