"""Control checks LG-01… → NIST SP 800-53 Rev. 5 → CIS Critical Security Controls v8.1, for the Audit portal and its report.

Every Looking Glass check names the NIST SP 800-53 Rev. 5 (Release 5.2.0, still the latest in NIST's OSCAL catalogue on
2026-11-12) controls it supports (audit_portal.py). The CIS safeguards here are NOT our own choice: they come from CIS's
official mapping, "CIS Controls v8.1 Mapping to NIST SP 800-53 Rev 5" (All Baselines workbook, last updated July 2026,
https://www.cisecurity.org/insights/white-papers/cis-controls-v8-1-mapping-to-nist-sp-800-53-rev-5), read on
2026-11-12 for exactly the NIST controls the checks use. Each safeguard keeps CIS's relationship (Equivalent, Subset,
Superset) and the NIST control it came through, so an auditor sees why it is listed. A NIST control CIS does not map
(AU-9, AC-2(7)) is said so, never filled in by us. CIS says its mappings lean "towards under-mapping".

CIS Controls content (the safeguard numbers and titles below, unchanged): CIS Critical Security Controls® v8.1
© Center for Internet Security, Inc., used under the Creative Commons Attribution-NonCommercial-NoDerivatives 4.0
International licence (https://creativecommons.org/licenses/by-nc-nd/4.0/). It is not covered by Looking Glass's AGPL
licence; commercial use of the CIS Controls needs CIS's prior approval. The current CIS Controls are at
https://www.cisecurity.org/controls/.
"""

CIS_RELEASE = "CIS Critical Security Controls v8.1"
CIS_SOURCE = "CIS Controls v8.1 Mapping to NIST SP 800-53 Rev 5 (CIS, July 2026)"
CIS_ATTRIBUTION = ("CIS Critical Security Controls® v8.1 © Center for Internet Security, Inc., used under CC BY-NC-ND 4.0 "
                   "(https://creativecommons.org/licenses/by-nc-nd/4.0/); the safeguards are those of CIS's official mapping to "
                   "NIST SP 800-53 Rev. 5. Current CIS Controls: https://www.cisecurity.org/controls/")

# safeguard titles exactly as in CIS's workbook ("All CIS Controls & Safeguards" sheet)
CIS_TITLES = {
    "3.1": "Establish and Maintain a Data Management Process",
    "3.3": "Configure Data Access Control Lists",
    "3.4": "Enforce Data Retention",
    "3.10": "Encrypt Sensitive Data in Transit",
    "3.11": "Encrypt Sensitive Data at Rest",
    "3.14": "Log Sensitive Data Access",
    "4.3": "Configure Automatic Session Locking on Enterprise Assets",
    "4.10": "Enforce Automatic Device Lockout on Portable End-User Devices",
    "5.1": "Establish and Maintain an Inventory of Accounts",
    "5.3": "Disable Dormant Accounts",
    "5.4": "Restrict Administrator Privileges to Dedicated Administrator Accounts",
    "5.5": "Establish and Maintain an Inventory of Service Accounts",
    "6.1": "Establish an Access Granting Process",
    "6.2": "Establish an Access Revoking Process",
    "6.3": "Require MFA for Externally-Exposed Applications",
    "6.4": "Require MFA for Remote Network Access",
    "6.5": "Require MFA for Administrative Access",
    "6.8": "Define and Maintain Role-Based Access Control",
    "8.1": "Establish and Maintain an Audit Log Management Process",
    "8.2": "Collect Audit Logs",
    "8.4": "Standardize Time Synchronization",
    "8.5": "Collect Detailed Audit Logs",
    "8.6": "Collect DNS Query Audit Logs",
    "8.7": "Collect URL Request Audit Logs",
    "8.8": "Collect Command-Line Audit Logs",
    "8.10": "Retain Audit Logs",
    "8.11": "Conduct Audit Log Reviews",
    "8.12": "Collect Service Provider Logs",
    "12.3": "Securely Manage Network Infrastructure",
    "12.6": "Use of Secure Network Management and Communication Protocols",
}

# CIS's mapping, for the NIST controls the checks use: NIST control -> [(safeguard, relationship)]
NIST_TO_CIS = {
    "AC-2": [("5.1", "Subset"), ("5.5", "Subset"), ("6.1", "Subset"), ("6.2", "Subset"), ("6.8", "Subset")],
    "AC-2(3)": [("5.3", "Subset")],
    "AC-2(7)": [],
    "AC-5": [("3.3", "Subset"), ("6.8", "Subset")],
    "AC-6(5)": [("5.4", "Superset")],
    "AC-6(9)": [("3.14", "Subset")],
    "AC-7": [("4.10", "Subset")],
    "AC-12": [("4.3", "Superset")],
    "AU-2": [("3.14", "Subset"), ("8.1", "Superset"), ("8.2", "Equivalent"), ("8.6", "Subset"), ("8.7", "Subset"),
             ("8.8", "Subset"), ("8.12", "Subset")],
    "AU-3": [("8.5", "Equivalent")],
    "AU-6": [("8.11", "Equivalent")],
    "AU-8": [("8.4", "Subset")],
    "AU-9": [],
    "AU-9(3)": [("3.11", "Superset")],
    "AU-9(4)": [("6.8", "Superset")],
    "AU-11": [("3.1", "Superset"), ("3.4", "Subset"), ("8.10", "Equivalent")],
    "AU-12": [("3.14", "Subset"), ("8.2", "Equivalent"), ("8.5", "Subset")],
    "IA-2(1)": [("6.3", "Subset"), ("6.4", "Subset"), ("6.5", "Equivalent")],
    "IA-2(2)": [("6.3", "Subset"), ("6.4", "Subset")],
    "SC-8": [("3.10", "Subset")],
    "SC-8(1)": [("3.10", "Subset")],
    "SC-23": [("12.3", "Subset"), ("12.6", "Subset")],
}
RELATION = {"Equivalent": "same scope", "Subset": "the CIS safeguard covers part of the NIST control",
            "Superset": "the CIS safeguard covers more than the NIST control"}
_ORDER = lambda s: tuple(int(x) for x in s.split("."))


def cis_for(nist_ids):
    """(safeguards, unmapped NIST ids) for a check's NIST controls, by CIS's own mapping. A safeguard reached through
    several NIST controls is listed once, with each of them and its relationship to each."""
    out, unmapped = {}, []
    for n in nist_ids:
        pairs = NIST_TO_CIS.get(n)
        if not pairs:
            unmapped.append(n)
            continue
        for sg, rel in pairs:
            e = out.setdefault(sg, {"id": sg, "title": CIS_TITLES[sg], "via": []})
            e["via"].append({"nist": n, "relation": rel})
    return [out[k] for k in sorted(out, key=_ORDER)], unmapped
