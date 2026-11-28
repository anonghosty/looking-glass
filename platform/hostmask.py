# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""What researchers may not see of a constituent host, masked out of free text: host names (also wildcards such as
*.example.org), IP addresses, e-mail addresses, dates, times, and long numbers and IDs. The rest (software, versions,
wording) stays, so values from the same software still match: "220 mail.example.org ESMTP Postfix (Ubuntu)" becomes
"220 <host> ESMTP Postfix (Ubuntu)".

Used by intel.py for everything the services reports say about a constituent's own hosts (certificate names and
issuers, products, banners, tags), and by the services patterns. Over-masking is preferred to a leak: a dotted name
that only looks like a host name (index.html, node.js) is masked too.

mask(text) -> masked text.  looks_like_host(text) -> True when the whole value is a host name or an address.
"""
import re

_MON = r"(?:jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|june?|july?|aug(?:ust)?|sept?(?:ember)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?)\.?"
# one written-out date, "27 Nov 2026" or "Nov 27, 2026" (the two rules below, without their guards): for ranges
_WRITTEN = (r"(?:\d{1,2}(?:st|nd|rd|th)?[\s-]+" + _MON + r"[\s,-]+\d{4}|" + _MON
            + r"\s+\d{1,2}(?:st|nd|rd|th)?,?\s+(?:\d{1,2}:\d{2}(?::\d{2})?\s+)?\d{4})")
MASKS = [
    # an address starts where a run of its characters starts (the look-behind): starting at every word boundary inside a
    # long run (1.1.1.…) and scanning to its end for an "@" took time with the square of its length (2026-11-13)
    (re.compile(r"(?<![\w.+-])[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b"), "<email>"),
    # dates and times first: a time (10:22:31) must not be taken for an IPv6 address
    (re.compile(r"\b(?:mon|tue|wed|thu|fri|sat|sun)[a-z]*,?\s+\d{1,2}\s+[a-z]{3,9}\s+\d{2,4}(?:\s+\d{1,2}:\d{2}(?::\d{2})?)?"
                r"(?:\s*[+-]\d{4}|\s+[A-Z]{2,4})?", re.I), "<date>"),
    (re.compile(r"\b\d{4}-\d{2}-\d{2}(?:[ T]\d{2}:\d{2}(?::\d{2})?(?:\.\d+)?Z?)?\b"), "<date>"),
    # written-out and other numeric dates (audit 2026-11-27, 5-8): "27 Nov 2026", "Nov 27, 2026", a certificate's
    # "Nov 27 10:22:31 2026 GMT", "27/11/2026", "11/27/26", "27.11.2026", "2026/11/27". A numeric date stands on its
    # own (no dot, dash or slash glued to it), so a version (7.4.33) or a host name made of numbers is left to the rules below
    # the written-out ones stand on their own too (the guards of the numeric ones below): a date inside a host name
    # (srv-1-jan-2024.corp.example.gh) is left to the host rule, which masks the whole name (review 2026-11-28).
    # A range written without spaces ("1 Jan 2024-2 Feb 2025", "27 Nov 2026/28 Nov 2026") is two dates glued by "-" or
    # "/": masked first, as one, with the guards on its outer ends only
    (re.compile(r"(?<![\w./-])(" + _WRITTEN + r")([-/])(" + _WRITTEN + r")(?!\.?[\w/-])", re.I), r"<date>\2<date>"),
    (re.compile(r"(?<![\w./-])\d{1,2}(?:st|nd|rd|th)?[\s-]+" + _MON + r"[\s,-]+\d{4}(?!\.?[\w/-])", re.I), "<date>"),
    (re.compile(r"(?<![\w./-])" + _MON + r"\s+\d{1,2}(?:st|nd|rd|th)?,?\s+(?:\d{1,2}:\d{2}(?::\d{2})?\s+)?\d{4}(?!\.?[\w/-])"
                r"(?:\s+[A-Z]{2,4}\b)?", re.I), "<date>"),
    (re.compile(r"(?<![\w./-])\d{1,2}([/.-])\d{1,2}\1\d{4}(?!\.?[\w/-])"), "<date>"),
    (re.compile(r"(?<![\w./-])\d{1,2}/\d{1,2}/\d{2}(?!\.?[\w/-])"), "<date>"),
    (re.compile(r"(?<![\w./-])\d{4}([/.])\d{1,2}\1\d{1,2}(?!\.?[\w/-])"), "<date>"),
    (re.compile(r"\b\d{1,2}:\d{2}:\d{2}\b"), "<time>"),
    # (IPv4: only ip_find above, so both maskers follow one rule; a pattern here also masked the first four parts of a
    # version such as 1.2.3.4.5, which the masked viewers' masker left alone: external review, 2026-11-12)
    # IPv6 (and hardware addresses): with "::", or at least four groups (so a time or a ratio is not one)
    (re.compile(r"(?<![\w:])(?=[0-9a-f:]*::|(?:[0-9a-f]{1,4}:){4})[0-9a-f:]{3,}[0-9a-f](?![\w:])", re.I), "<ip>"),
    # host names: dotted labels ending in a letter-only top-level label (example.org, a.b.example.co). Any label may
    # be digits and dashes only: 41-66-1-2.static.telco.com.gh is a host name too (review 2026-11-13: a look-ahead
    # demanded a letter in the FIRST label, so names that begin with a spelled address were left as they were)
    (re.compile(r"(?<![\w.-])(?:\*\.)?[\w-]+(?:\.[\w-]+)*\.[a-z]{2,24}(?![\w-])", re.I), "<host>"),
    (re.compile(r"\b[0-9a-f]{12,}\b", re.I), "<id>"),
    (re.compile(r"(?<![\w.])\d{6,}(?![\w.])"), "<n>"),
]
_HOSTISH = re.compile(r"^\s*(?:<host>|<ip>|<email>)\s*$")


def mask(text):
    if text is None:
        return ""
    import ip_find
    # addresses first, by the finder every masker shares (ip_find.py); the patterns below still catch the rest
    # (hardware addresses, host names, e-mail addresses, dates, IDs)
    t = ip_find.sub(str(text), lambda ip: "<ip>")
    for rx, rep in MASKS:
        t = rx.sub(rep, t)
    return re.sub(r"\s+", " ", t).strip()


def looks_like_host(text):
    return bool(_HOSTISH.match(mask(text)))
