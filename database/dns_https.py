"""The sender check's key look-up over HTTPS (DNS over HTTPS), for networks that drop plain DNS TXT look-ups.

Some networks inspect DNS and block TXT queries on port 53 (a rule against DNS tunnelling): the sender check then can
not fetch Shadowserver's signing key and every report e-mail is "not checked" (the user's network, 2026-11-15: A
look-ups answered, TXT look-ups to the same public resolvers timed out over UDP and were reset over TCP; the same
question over HTTPS answered at once). mail_auth.Checker asks the system's resolver first, as before; only when that
does not answer does it ask these resolvers over HTTPS, by IP address (no name look-up needed to reach them), with the
certificate checked.

MAIL_AUTH_DNS_SERVERS (.env): the resolvers to ask over HTTPS, in order; default 1.1.1.1,1.0.0.1,8.8.8.8,8.8.4.4
(Cloudflare and Google). "none" turns the HTTPS look-up off. Only the name of the signing key is asked (for example
mail._domainkey.shadowserver.org), nothing about the reports or the constituency.

txt(name, timeout=5.0, servers=None) -> the TXT record as bytes; raises LookupError when the name has no TXT record,
OSError when no resolver answered.
"""
import json
import os
import re
import ssl
import urllib.parse
import urllib.request

DEFAULT = "1.1.1.1,1.0.0.1,8.8.8.8,8.8.4.4"
# each provider's JSON endpoint (Cloudflare: /dns-query, Google: /resolve); another resolver: /dns-query
PATHS = {"1.1.1.1": "/dns-query", "1.0.0.1": "/dns-query", "8.8.8.8": "/resolve", "8.8.4.4": "/resolve"}
_IP = re.compile(r"^(\d{1,3}(\.\d{1,3}){3}|[0-9a-fA-F:]+)$")
_QUOTED = re.compile(r'"((?:[^"\\]|\\.)*)"')
_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,253}$")


def servers(env=None):
    """The resolvers from MAIL_AUTH_DNS_SERVERS: IP addresses only, at most 8; [] when "none"."""
    raw = ((env if env is not None else os.environ).get("MAIL_AUTH_DNS_SERVERS") or DEFAULT).strip()
    if raw.lower() in ("none", "off", "no", "0"):
        return []
    out = [s.strip() for s in raw.split(",") if s.strip()]
    return [s for s in out if _IP.match(s)][:8]


def _data(record: str) -> str:
    """A TXT answer's text: Cloudflare quotes each string ("v=DKIM1; " "p=..."), Google does not."""
    parts = _QUOTED.findall(record)
    if parts:
        return "".join(re.sub(r"\\(.)", r"\1", p) for p in parts)
    return record


def txt(name: str, timeout: float = 5.0, servers_=None) -> bytes:
    if not _NAME.match(name or ""):
        raise LookupError(f"not a DNS name: {name!r}")
    ctx = ssl.create_default_context()                    # the resolver's certificate is checked (its IP is in it)
    last = None
    for ip in (servers_ if servers_ is not None else servers()):
        host = f"[{ip}]" if ":" in ip else ip
        url = f"https://{host}{PATHS.get(ip, '/dns-query')}?" + urllib.parse.urlencode({"name": name, "type": "TXT"})
        req = urllib.request.Request(url, headers={"accept": "application/dns-json", "User-Agent": "looking-glass-sender-check"})
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
                d = json.loads(r.read(65536).decode("utf-8", "replace"))
        except (OSError, ValueError) as exc:
            last = exc
            continue
        status = d.get("Status")
        if status == 3:                                   # NXDOMAIN: no key published under that name
            raise LookupError(f"{name} does not exist")
        if status != 0:
            last = OSError(f"{ip} answered status {status}")
            continue
        recs = [_data(str(a.get("data", ""))) for a in d.get("Answer") or [] if a.get("type") == 16]
        if not recs:
            raise LookupError(f"{name} has no TXT record")
        return "".join(recs[:1]).encode("ascii", "replace")
    raise OSError(f"no resolver answered over HTTPS ({type(last).__name__ if last else 'none set'})")
