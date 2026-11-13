"""Control checks LG-01… → NIST SP 800-53 Rev. 5 → CIS Critical Security Controls v8.1, for the Audit portal and its report.

Every Looking Glass check names the NIST SP 800-53 Rev. 5 (Release 5.2.0, still the latest in NIST's OSCAL catalogue on
2026-11-12) controls it supports (audit_portal.py). The CIS safeguards here are NOT our own choice: they come from CIS's
official mapping, "CIS Controls v8.1 Mapping to NIST SP 800-53 Rev 5" (All Baselines workbook, last updated July 2026,
https://www.cisecurity.org/insights/white-papers/cis-controls-v8-1-mapping-to-nist-sp-800-53-rev-5), read on
2026-11-12 for exactly the NIST controls the checks use. Each safeguard keeps CIS's relationship (Equivalent, Subset,
Superset) and the NIST control it came through, so an auditor sees why it is listed. A NIST control CIS does not map
(AU-9, AC-2(7)) is said so, never filled in by us. CIS says its mappings lean "towards under-mapping".
Next to CIS's rows, and kept apart from them, Looking Glass's own reading of each (check, safeguard) pair: backed,
related or not backed (BACKED, NOT_BACKED, lg_reading). This is evidence for an organisation's own assessment of the
CIS Controls, not a certification: The CIS Controls are a map here, to guide security and help the auditor: voluntary best practice, with no CIS certificate for meeting them, and they apply to the whole environment.

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

# ---------------------------------------------------------------- Looking Glass's OWN reading (not CIS's)
# Everything above is CIS's, shown exactly as CIS publishes it (its licence allows no changes). What follows is Looking
# Glass's judgment, kept apart and always shown as ours ("Looking Glass: ..."), never mixed into CIS's text (review,
# 2026-11-12). The one place the portal, the PDF report and the tests read it from.
#
#   backed      the check produces evidence for the safeguard AS CIS WORDS IT (for Looking Glass itself), figures
#               included (45 days, weekly, 90 days...). Opt-in, conservative, and decided by the EVIDENCE: a pair listed
#               in BACKED is backed only while its condition holds on this system (review, 2026-11-13); otherwise it
#               is "related", with what differs from CIS's figure, as advice to the auditor.
#   not backed  the mapping reaches it, but the check does not look at its subject: NOT_BACKED says why.
#   related     everything else: CIS's mapping relates it to the check's NIST controls; Looking Glass claims no more.
# When in doubt: related. One overclaim would make an auditor distrust the rest. The CIS Controls are a map
# here, voluntary best practice with no CIS certificate: these checks are evidence for the organisation's own assessment.
# Each condition reads the facts the check worked out (audit_portal.py) and returns "" when the safeguard is met as
# CIS words it, else what differs (shown as "related: ..."). CIS's figures: 5.3 disable dormant accounts after 45 days;
# 8.10 keep audit logs at least 90 days; 8.11 review audit logs weekly or more often (CIS Controls v8.1).
def _mfa(f):
    if not f.get("mfa_required", True):
        return "MFA is not required on this system (MFA_REQUIRED=0)"
    return f"{f['accounts_without_mfa']} active account(s) have no authenticator" if f.get("accounts_without_mfa") else ""


def _dormant(f):
    days, active = f.get("dormant_days", 90), f.get("dormant_active", 0)
    if days > 45:
        return (f"Looking Glass lists accounts unused for {days} days (AUDIT_DORMANT_DAYS) and an administrator disables "
                f"them; CIS asks for 45 days")
    return f"{active} account(s) unused for {days} days are still active; CIS asks for them to be disabled" if active else ""


def _retention(f):
    d = f.get("retention_days")
    return "" if d is not None and d >= 90 else f"audit records are kept {d} days; CIS asks for at least 90"


def _review(f):
    days = f.get("review_days", 30)
    if days > 7:
        return f"Looking Glass looks for a review every {days} days (AUDIT_REVIEW_DAYS); CIS asks for weekly reviews"
    return "" if f.get("reviewed") else f"no review recorded in the last {days} days"


BACKED = {
    "LG-01": {"6.3": _mfa, "6.5": _mfa},     # sign-in to Looking Glass (an externally exposed application) needs MFA
    "LG-02": {"5.3": _dormant},              # dormant accounts: 45 days, and none left active
    "LG-04": {"6.1": lambda f: f"{f['not_approved']} active account(s) without a recorded approval" if f.get("not_approved") else ""},
    "LG-08": {"8.2": None},                  # the audit log is collected
    "LG-09": {"8.5": None},                  # audit records hold who, what, when, where
    "LG-11": {"8.10": _retention},           # at least 90 days
    "LG-13": {"8.11": _review},              # weekly reviews, and one recorded
    "LG-14": {"3.10": lambda f: "" if f.get("tls", True) else "HTTPS is off on this system"},
    "LG-15": {"8.2": None,                   # exports are logged
              # 3.14 Log Sensitive Data Access: exports AND views of host-level data are logged per person (data_access.py)
              "3.14": lambda f: "" if f.get("data_access_logged") else
                      "views of host-level data are not logged on this system (DATA_ACCESS_LOG=0)"},
}
# related, but worth saying why it is not more (advice for the auditor)
RELATED_NOTE = {
    ("LG-12", "8.4"): "the check reads whether the server's clock is synchronised; CIS asks for at least two synchronised "
                      "time sources (check the NTP configuration on the server)",
}
NOT_BACKED = {
    "3.11": "it protects the audit log's integrity but encrypts nothing: MongoDB and the data folder are plain files "
            "(use disk encryption)",
    "4.3": "it ends Looking Glass's own sessions; locking enterprise devices is outside Looking Glass",
    "4.10": "it limits sign-in attempts to Looking Glass; lockout on portable end-user devices is outside Looking Glass",
    "6.4": "it covers sign-in to Looking Glass; MFA for remote network access (VPN and the like) is outside Looking Glass",
    "8.6": "DNS query logs are outside Looking Glass",
    "8.7": "URL request logs (proxies, web gateways) are outside Looking Glass",
    "8.8": "command-line audit logs of the servers are outside Looking Glass",
    "8.12": "service provider logs are outside Looking Glass",
    "12.3": "managing network infrastructure is outside Looking Glass",
}
CERTIFICATION_NOTE = ("The CIS Controls are used here as a map, to guide Looking Glass's security and make the auditor's work easier. They are voluntary best practice, not a law or a requirement, and CIS issues no certificate for meeting them: organisations measure themselves with CIS's free Self Assessment Tool (CSAT) or with an auditor, and those that need a formal certificate usually go for ISO 27001 or SOC 2, with the CIS Controls as a guide.")


def lg_reading(check, safeguard, facts=None):
    """Looking Glass's own reading of one (check, safeguard) pair on this system: {"status": backed | not backed |
    related, "note"}. `facts`: what the check found (audit_portal.py); without them a conditional pair is "related"."""
    conds = BACKED.get(check, {})
    if safeguard in conds:
        cond = conds[safeguard]
        why = "" if cond is None else ("the evidence was not given" if facts is None else cond(facts))
        if not why:
            return {"status": "backed", "note": f"backed by {check}, which produces evidence for it"}
        return {"status": "related", "note": f"related to {check}, not backed on this system: {why}"}
    if safeguard in NOT_BACKED:
        return {"status": "not backed", "note": f"not backed by {check}: {NOT_BACKED[safeguard]}"}
    if (check, safeguard) in RELATED_NOTE:
        return {"status": "related", "note": f"related to {check}: {RELATED_NOTE[(check, safeguard)]}"}
    return {"status": "related", "note": f"related to {check} by CIS's mapping only"}
_ORDER = lambda s: tuple(int(x) for x in s.split("."))


def cis_for(nist_ids, check=None, facts=None):
    """(safeguards, unmapped NIST ids) for a check's NIST controls, by CIS's own mapping. A safeguard reached through
    several NIST controls is listed once, with each of them and its relationship to each. "id", "title" and "via" are
    CIS's, unchanged; "lg" is Looking Glass's own reading on this system (lg_reading with the check's facts), apart."""
    out, unmapped = {}, []
    for n in nist_ids:
        pairs = NIST_TO_CIS.get(n)
        if not pairs:
            unmapped.append(n)
            continue
        for sg, rel in pairs:
            e = out.setdefault(sg, {"id": sg, "title": CIS_TITLES[sg], "via": [], "lg": lg_reading(check, sg, facts)})
            e["via"].append({"nist": n, "relation": rel})
    return [out[k] for k in sorted(out, key=_ORDER)], unmapped
