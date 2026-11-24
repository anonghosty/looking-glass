# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""What the combination ZIPs carry beyond their fixed columns (approved 2026-11-23): the values the pattern analysis
groups devices by (intel.py COMMS_FIELDS / SVC_FIELDS: certificate fingerprints, JARM, HASSH, SSH and server software,
the page hash, brute-force usernames and passwords, the SSH client, the request pattern), Shadowserver's own ATT&CK and
CVE for the event (ss_attack.py), the certificate and TLS facts (tls_facts.py), and an all-fields file: every field of
every record, one line per field, with its readable label (field_labels.py).

These ZIPs go only to people allowed to see hosts and to export (analysts and administrators), often on to a network
provider in an advisory: the values are the provider's way to find the same devices in their own network. The column
names are stable snake_case, added after the existing ones, so tools that map the CSV (IntelMQ, Logstash) keep working.
"""
import os

import field_labels
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
ALL_FIELDS_HEAD = ["time", "ip", "port", "report", "field", "label", "value"]
# one line per field of every record: a big selection makes a big file, so it stops here (said in its last line)
ALL_FIELDS_MAX = int(os.environ.get("LG_ALL_FIELDS_MAX_LINES", "1000000") or 1000000)
SKIP = {"_t", "_id", "id", "_bc", "extras", "ss_attack", "line_hash", "event_id"}


def computed(e, section):
    """The per-record values of the _ columns."""
    if section == "infections":
        return {"_ss_attack": ss_attack.summary(e.get("ss_attack"))}
    return {"_tls": tls_facts.summary(tls_facts.facts(e.get("extras"), e.get("timestamp") or e.get("extracted_date")))}


def _text(v):
    if isinstance(v, (list, tuple, set)):
        return ", ".join(str(x) for x in v)
    return "" if v is None else str(v)


def all_fields_rows(records, section, report_of=None):
    """Every field of every record, one line each: time, ip, port, report, field, label, value. The record's own
    fields first, then its report's extra fields, as Shadowserver named them, each with its readable label. Empty values
    are left out. Returns (rows, cut): cut is True when ALL_FIELDS_MAX stopped it."""
    rows = []
    for e in records:
        ip = e.get("src_ip") if section == "infections" else e.get("ip")
        port = e.get("src_port") if section == "infections" else e.get("port")
        t = _text(e.get("timestamp") or e.get("extracted_date"))
        rep = report_of(e) if report_of else _text(e.get("source") or e.get("report"))
        # Looking Glass's own keys stay out: internal ones (_t, _id), record IDs and references (ip_ref, src_ref)
        fields = [(k, v) for k, v in e.items() if k not in SKIP and not k.startswith("_") and not k.endswith("_ref")]
        fields += sorted((e.get("extras") or {}).items())
        for k, v in fields:
            s = _text(v)
            if s == "":
                continue
            if len(rows) >= ALL_FIELDS_MAX:
                return rows, True
            rows.append([t, _text(ip), _text(port), rep, k, field_labels.label(k), s])
    return rows, False
