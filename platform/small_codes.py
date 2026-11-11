"""No lasting code for a pattern fewer than MIN_HOSTS hosts carry, for viewers who never see hosts (external review,
2026-11-11, option 2 chosen by the CSIRT).

A combination (LG-C-…) or across-report pattern (LG-X-…) code is made from the pattern itself, so it stays the same
every day. When one or two devices carry the pattern, that code is in practice a name for those devices: a researcher
could follow it day after day without ever seeing an address. Researchers (any viewer without the "unmasked"
permission, and demo mode) still see the pattern and how many devices carry it, so a single device behind something
odd is still noticed; it simply comes without a code. The drill-down into that device is the analyst's, who sees the
devices and keeps every code. Patterns MIN_HOSTS or more hosts share keep their codes for everyone.
"""
from svc_patterns import MIN_HOSTS

HELD = f"Fewer than {MIN_HOSTS} devices carry this pattern: no lasting code. An analyst can drill into it."


def viewer_sees_hosts():
    """True for viewers who see the devices (the 'unmasked' permission, demo mode off); outside a request (tools,
    tests calling the functions directly) True."""
    try:
        from flask import g, has_request_context, request
        if not has_request_context():
            return True
        if request.args.get("demo") == "1":
            return False
        u = getattr(g, "user", None)
        return bool(u) and "unmasked" in (u.get("perms") or ())
    except Exception:                      # noqa: BLE001
        return True


def code_for(code, hosts, full=None):
    """The code, or None when fewer than MIN_HOSTS hosts carry the pattern and the viewer does not see hosts.
    full: viewer_sees_hosts() worked out once by the caller (it is the same for the whole answer)."""
    full = viewer_sees_hosts() if full is None else full
    return code if full or hosts >= MIN_HOSTS else None
