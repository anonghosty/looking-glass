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

MASKS = [
    (re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b"), "<email>"),
    # dates and times first: a time (10:22:31) must not be taken for an IPv6 address
    (re.compile(r"\b(?:mon|tue|wed|thu|fri|sat|sun)[a-z]*,?\s+\d{1,2}\s+[a-z]{3,9}\s+\d{2,4}(?:\s+\d{1,2}:\d{2}(?::\d{2})?)?"
                r"(?:\s*[+-]\d{4}|\s+[A-Z]{2,4})?", re.I), "<date>"),
    (re.compile(r"\b\d{4}-\d{2}-\d{2}(?:[ T]\d{2}:\d{2}(?::\d{2})?(?:\.\d+)?Z?)?\b"), "<date>"),
    (re.compile(r"\b\d{1,2}:\d{2}:\d{2}\b"), "<time>"),
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "<ip>"),
    # IPv6: with "::", or at least four groups (so a time or a ratio is not one)
    (re.compile(r"(?<![\w:])(?=[0-9a-f:]*::|(?:[0-9a-f]{1,4}:){4})[0-9a-f:]{3,}[0-9a-f](?![\w:])", re.I), "<ip>"),
    # host names: labels with at least one letter, ending in a letter-only top-level label (example.org, a.b.example.co)
    (re.compile(r"(?<![\w.-])(?:\*\.)?(?=[\w-]*[a-z])[\w-]+(?:\.[\w-]+)*\.[a-z]{2,24}(?![\w-])", re.I), "<host>"),
    (re.compile(r"\b[0-9a-f]{12,}\b", re.I), "<id>"),
    (re.compile(r"(?<![\w.])\d{6,}(?![\w.])"), "<n>"),
]
_HOSTISH = re.compile(r"^\s*(?:<host>|<ip>|<email>)\s*$")


def mask(text):
    if text is None:
        return ""
    t = str(text)
    for rx, rep in MASKS:
        t = rx.sub(rep, t)
    return re.sub(r"\s+", " ", t).strip()


def looks_like_host(text):
    return bool(_HOSTISH.match(mask(text)))
