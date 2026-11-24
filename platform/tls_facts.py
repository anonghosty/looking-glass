# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""Certificate and TLS facts of one services record, from the fields Shadowserver's scan reports carry (approved
2026-11-23): whether the certificate had expired when the host was scanned, is self-signed, passed Shadowserver's
validity check, is trusted by browsers (and the browser's reason when not), and whether SSLv3 is still on and TLS 1.3
is supported. Facts only, as Shadowserver gives them: no rating is added.

facts(extras, when, dates=True) -> [{key, label, value, flag}] in a fixed order, only the facts the record carries.
flag is True for the facts a reader would want to act on (expired, self-signed, not valid, not trusted, SSLv3 on).
dates=False is the masked view (researchers never see dates or host names): "Expired: yes/no" without the dates, and
no browser error text (it can name the host).
"""
import re
from datetime import datetime, timezone

YES = {"y", "yes", "true", "1", "t"}
NO = {"n", "no", "false", "0", "f"}
FORMATS = ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d", "%b %d %H:%M:%S %Y", "%b %d %H:%M:%S %Y %Z")


def yesno(v):
    s = str(v if v is not None else "").strip().lower()
    return True if s in YES else False if s in NO else None


def when_of(v):
    """A record's time or a certificate date -> aware datetime (UTC), else None."""
    if isinstance(v, datetime):
        return v if v.tzinfo else v.replace(tzinfo=timezone.utc)
    s = re.sub(r"\s+", " ", str(v or "").strip().replace("Z", "")).split("+")[0].split(".")[0]
    s = s.removesuffix(" GMT").removesuffix(" UTC")
    for f in FORMATS:
        try:
            return datetime.strptime(s, f).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def facts(extras, when=None, dates=True):
    ex = extras if isinstance(extras, dict) else {}
    out = []

    def add(key, label, value, flag=False):
        out.append({"key": key, "label": label, "value": value, "flag": bool(flag)})

    exp_raw = ex.get("cert_expiration_date")
    exp, seen = when_of(exp_raw), when_of(when)
    if exp:
        expired = bool(seen and exp < seen)
        day = exp.date().isoformat()
        if dates:
            add("expires", "Certificate expiry", f"Expired on {day}, before the scan" if expired else f"{day} (still valid when scanned)" if seen else day, expired)
        else:
            add("expires", "Certificate expired when scanned", "Yes" if expired else "No", expired)
    for key, field, label, bad in (("self_signed", "self_signed", "Self-signed certificate", True),
                                   ("valid", "cert_valid", "Certificate valid (Shadowserver's check)", False),
                                   ("trusted", "browser_trusted", "Trusted by browsers", False)):
        v = yesno(ex.get(field))
        if v is not None:
            add(key, label, "Yes" if v else "No", v if bad else not v)
    err = str(ex.get("browser_error") or "").strip()
    # never in the masked view: the error can name the host ("certificate is valid for a.example, not b.example")
    if dates and err and yesno(ex.get("browser_trusted")) is not True:
        add("browser_error", "Why browsers do not trust it", err[:200])
    v = yesno(ex.get("sslv3_supported"))
    if v is not None:
        add("sslv3", "SSLv3 (an old, broken protocol)", "Still on" if v else "Off", v)
    v = yesno(ex.get("tlsv13_support"))
    if v is not None:
        add("tlsv13", "TLS 1.3", "Supported" if v else "Not supported")
    return out


def summary(items):
    """One cell for CSVs and PDF rows: 'Certificate expiry: Expired on 2025-01-02, before the scan; Self-signed: Yes'."""
    return "; ".join(f"{i['label']}: {i['value']}" for i in items or [])
