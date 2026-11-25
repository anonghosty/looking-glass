# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""What the combination ZIPs carry beyond their fixed columns (approved 2026-11-23): the values the pattern analysis
groups devices by (intel.py COMMS_FIELDS / SVC_FIELDS: certificate fingerprints, JARM, HASSH, SSH and server software,
the page hash, brute-force usernames and passwords, the SSH client, the request pattern), Shadowserver's own ATT&CK and
CVE for the event (ss_attack.py) and the certificate and TLS facts (tls_facts.py). (The all-fields CSV of 2026-11-24 was
removed again at the user's request, 2026-11-24.)

These ZIPs go only to people allowed to see hosts and to export (analysts and administrators), often on to a network
provider in an advisory: the values are the provider's way to find the same devices in their own network. The column
names are stable snake_case, added after the existing ones, so tools that map the CSV (IntelMQ, Logstash) keep working.
"""
import ss_attack
import tls_facts

# (column, where): x:<field> is a record's extra field; _ss_attack and _tls are worked out per record
COMMS_PATTERN_COLS = [("request_pattern", "x:pattern"), ("brute_force_username", "x:username"),
                      ("brute_force_password", "x:password"), ("ssh_client", "x:client_version"),
                      ("shadowserver_attack", "_ss_attack")]
SVC_PATTERN_COLS = [("server_software", "x:server"), ("ssh_software", "x:serverid_software"), ("ssh_hassh", "x:hassh"),
                    ("tls_jarm", "x:jarm"), ("certificate_sha256", "x:sha256_fingerprint"),
                    ("certificate_subject", "x:subject_common_name"), ("certificate_issuer", "x:issuer_common_name"),
                    ("web_page_sha256", "x:page_sha256fp"), ("certificate_and_tls", "_tls")]


def computed(e, section):
    """The per-record values of the _ columns."""
    if section == "infections":
        return {"_ss_attack": ss_attack.summary(e.get("ss_attack"))}
    return {"_tls": tls_facts.summary(tls_facts.facts(e.get("extras"), e.get("timestamp") or e.get("extracted_date")))}
