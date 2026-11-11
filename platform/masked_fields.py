"""What a masked viewer (the external role, demo mode, any account without 'unmasked') sees of a report's own fields.

An allowlist, not a blocklist: a report field is shown only when it is named here (technical detail: protocol,
software, versions, ciphers, capability flags), and even then its value goes through hostmask.mask, so a host name,
IP address, e-mail address, date or long ID inside it is masked. Every other field is hidden: names (sysname,
workstation_name, dns_host_name...), MAC addresses, user names, descriptions, locations, keys, fingerprints, serials,
secrets, banners. A field a report adds tomorrow stays hidden until someone adds it here on purpose.

service_extras(extras) / event_extras(extras) -> (shown, hidden_count)
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


def service_extras(extras):
    return _keep(extras, SERVICES, SERVICE_FAMILIES)


def event_extras(extras):
    return _keep(extras, EVENTS, EVENT_FAMILIES)
