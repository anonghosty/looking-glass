# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""What a masked viewer (the external role, demo mode, any account without 'unmasked') sees of a report's own fields.

An allowlist, not a blocklist: a report field is shown only when it is named here (technical detail: protocol,
software, versions, ciphers, capability flags), and even then its value goes through hostmask.mask, so a host name,
IP address, e-mail address, date or long ID inside it is masked. Every other field is hidden: names (sysname,
workstation_name, dns_host_name...), MAC addresses, user names, descriptions, locations, keys, fingerprints, serials,
secrets, banners. A field a report adds tomorrow stays hidden until someone adds it here on purpose.

service_extras(extras) / event_extras(extras) -> (shown, hidden_count)
intelligence_row(row, fields, alias) -> the masked record of Abused or Compromised (external accounts)
"""
import re

import hostmask

# publicly accessible / vulnerable services reports (services.py extras)
SERVICES = frozenset("""
afp_versions algorithm allocator amplification anon_login anonymous_access auth_length auth_ssl_response
auth_tls_response authentication available_ciphers available_compression available_kex available_mac
badsecret_module badsecret_product badsecret_type bgp_version bit_rate bits browser_trusted build_date
cert_expired cert_length cert_valid cipher_suite code compiler content_type data_representation
domain_controller_functionality domain_functionality forest_functionality ecdsa_curve ecdsa_curve25519
ecdsa_public_key_length ed25519_curve25519 error_code error_code_text exchange_type features firmware format
freak_cipher_suite freak_vulnerable function function_text generator handshake has_password http_code http_reason
http_response_type is_global_catalog_ready is_synchronized javascriptengine key_algorithm language_tag leap
major major_error_code manufacturer md2_auth md5_auth mechanisms message_type message_type_text method
min_amplification minor minor_error_code mode modelfull modelshort multiplexing_api none_auth nts oem_auth opcode
os packet_type passkey_auth permessage_auth platform precision printer_make_and_model processor product
protocol_error_code rdp_protocol rsa_length self_signed selected_cipher selected_compression selected_kex
selected_mac server server_type serverid_software signature_algorithm software ssl_poodle ssl_version stability
status stratum supported_capabilities supported_ldap_version supported_protocols supported_sasl_mechanisms
tlsv13_cipher tlsv13_support transfer_encoding uams userauth_methods userlevel_auth validation_level vendor
version_major version_minor
""".split())
# families of harmless fields: MySQL capability flags (client_ssl, client_protocol_41...) and software versions
SERVICE_FAMILIES = re.compile(r"^(?:client_[a-z0-9_]+|[a-z0-9_]*_version)$")

# network communications reports (sources.py extras): the event's own technical detail and malware sample hashes
EVENTS = frozenset("""
client_version count duration end_time flags http_request_method max_pps maxdata query_type start_time
supported_protocols system_type threat_framework threat_tactic_id threat_technique_id url_scheme
md5 sha1 sha256 sha512 hash family malware malware_family threat botnet
""".split())
EVENT_FAMILIES = re.compile(r"^[a-z0-9_]*_hash$")
# a malware sample hash identifies the sample, not a host: kept whole so it can still be looked up on Malpedia
SAMPLE_HASH = re.compile(r"^(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64}|[0-9a-f]{128})$", re.I)
HASH_FIELDS = re.compile(r"^(?:md5|sha1|sha256|sha512|hash|[a-z0-9_]*_hash)$")


def _value(v, k=""):
    """The value as shown: anything that looks like a host, address, e-mail, date or ID is masked."""
    if isinstance(v, bool) or v is None:
        return v
    s = str(v)
    if HASH_FIELDS.match(k) and SAMPLE_HASH.match(s):
        return s
    m = hostmask.mask(s)
    return v if (m == s and isinstance(v, (int, float))) else m


def _keep(extras, names, families):
    shown, hidden = {}, 0
    for k, v in (extras or {}).items():
        if k in names or families.match(k):
            shown[k] = _value(v, k)
        else:
            hidden += 1
    return shown, hidden


def intelligence_row(row, fields, alias):
    """Abused or Compromised (intelligence.py) as external accounts see one record (the user, 2026-11-21), with the
    platforms' own masking: the address becomes its opaque label (privacy.mask_ip, "Host 3f9a2c41b07e", as on both
    platforms, so one host can still be followed), the network its demo alias (alias: privacy.AsnRegistry.alias), a
    host name "hidden" (as services_api.public), an organisation's name and a leaked account "hidden"; places,
    severity and the record's time stay (as on both platforms); the report's own fields (fields: intelligence.FIELDS)
    go through hostmask.mask (host names, addresses, e-mail addresses, dates and IDs inside them masked); every other
    field is left out, so a field a report adds tomorrow stays hidden. Returns the masked row."""
    import privacy
    out = {}
    if "entity_name" in fields:
        # a ransomware victim (the user, 2026-11-22: "Group only"): the group alone. Sector, place, website, published
        # date and network would, with the public leak-site trackers, point at one organisation; the record's time is
        # its day only (the page shows that day anyway). External accounts see how many victims and which groups.
        for k, v in (row or {}).items():
            if v in (None, "") or k in INTEL_INTERNAL:
                continue
            out[k] = (_value(v, k) if k in INTEL_VICTIM_KEPT else str(v)[:10] if k == "timestamp" else "hidden")
        return out
    for k, v in (row or {}).items():
        if v in (None, "") or k in INTEL_INTERNAL:
            continue
        if k == "ip":
            out[k] = privacy.mask_ip(str(v))
        elif k == "asn":
            out[k] = alias(v) or ""
        elif k in INTEL_HIDDEN or k in INTEL_FREE_TEXT:
            out[k] = "hidden"
        elif k == "timestamp":
            out[k] = v
        elif k in INTEL_KEPT:
            out[k] = _value(v, k)
        elif k in INTEL_DATES and isinstance(v, str) and DATE_ONLY.match(v.strip()):
            out[k] = v.strip()
        elif k in fields:
            out[k] = _value(v, k)
    return out


# Abused or Compromised: what each masked record keeps. Places and severity are kept as on both platforms (the
# region and city of a host, never its address); the time stamp is the record's own time
INTEL_KEPT = frozenset({"timestamp", "region", "city", "geo", "country", "severity", "sector"})
INTEL_HIDDEN = frozenset({"hostname", "email", "username", "entity_name"})   # a name: shown as "hidden"
# free text written by whoever reported it (a defacement's message, a blocklist's reason, a client's user agent): it
# can name a site or an organisation in plain words, which no address or e-mail masking catches, so it is "hidden"
# (security review of 9e51e5e). The short coded fields (tag, application, server, method...) stay.
INTEL_FREE_TEXT = frozenset({"detail", "reason", "user_agent"})
INTEL_VICTIM_KEPT = frozenset({"ransomware"})          # a ransomware victim's row: the group only (see intelligence_row)
INTEL_DATES = frozenset({"date_published"})                                     # a date only: kept as it is
INTEL_INTERNAL = frozenset({"_id", "line_hash", "filename", "category", "extracted_date", "logged_date"})
DATE_ONLY = re.compile(r"^\d{4}-\d{2}-\d{2}(?:[ T]\d{2}:\d{2}(?::\d{2})?)?Z?$")


def service_extras(extras):
    return _keep(extras, SERVICES, SERVICE_FAMILIES)


def event_extras(extras):
    return _keep(extras, EVENTS, EVENT_FAMILIES)
