"""Which Shadowserver tags are issues, and which only say what a device is.

A services record's tags mix two things: weaknesses (exposed-admin-panel, eol-vmware-esxi, device-implant …) and labels
of the product or protocol seen (vmware-esxi, mikrotik, iot, ssl, winbox, isakmp …). Only the first are issues; the
second are "what the devices are". The platform's own issue names (services.normalise_service) and the end-of-life tags
are the issues; CVEs are kept apart by the callers.

issue_of(tag) -> the issue's readable name, or "" for a tag that only names a product or protocol.
"""
import re

# the tags the services platform already counts as issues (services.normalise_service), with their readable names
NAMED = {"exposed-admin-panel": "Exposed admin panel", "device-implant": "Device implant", "badcandy": "Badcandy",
         "cpanel-compromised": "Cpanel compromised", "open-dir": "Open dir", "vulnerable": "Vulnerable",
         "expired-certificate": "Expired certificate", "ssl-poodle": "POODLE (SSLv3)", "poodle": "POODLE (SSLv3)", "freak": "FREAK"}
CVE_RX = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)


def issue_of(tag):
    """The issue a tag stands for ("End of life (vmware-esxi)", "Exposed admin panel"), or "" when it only names what
    the device is (a product, a vendor, a protocol)."""
    t = str(tag or "").strip().lower()
    if t.startswith("tag:"):
        t = t[4:].strip()
    if not t or CVE_RX.fullmatch(t):
        return ""
    if t in NAMED:
        return NAMED[t]
    if t == "eol":
        return "End of life"
    if t.startswith("eol-"):
        return f"End of life ({t[4:]})"
    return ""


def split(tags):
    """(issues, labels) of a list of tags: the issues by their names (a bare "End of life" dropped when a specific one is
    there), the product / protocol labels as they are. CVEs are left out of both."""
    issues, labels = [], []
    for t in tags or []:
        t = str(t).strip()
        if not t or CVE_RX.search(t):
            continue
        i = issue_of(t)
        if i:
            if i not in issues:
                issues.append(i)
        else:
            lb = t[4:].strip().lower() if t.lower().startswith("tag:") else t.lower()
            if lb and lb not in labels:
                labels.append(lb)
    if "End of life" in issues and any(i.startswith("End of life (") for i in issues):
        issues.remove("End of life")
    return issues, labels
