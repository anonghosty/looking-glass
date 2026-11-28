# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""Fetching over https only, redirects included (review 2026-11-15): an address that starts with https:// could still be
redirected to http:// or file:, and urllib follows redirects by itself. open() refuses a first address that is not https
and any redirect that leaves https, before anything is sent there. Used for the addresses that come from .env: the
report feed (report_map.py) and Shadowserver's report API (pipeline_settings.py)."""
import urllib.parse
import urllib.request


class NotHttps(ValueError):
    pass


class _HttpsRedirectsOnly(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not str(newurl).lower().startswith("https://"):
            raise NotHttps(f"refused a redirect away from https (to {str(newurl).split(':', 1)[0]}:)")
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        # a token or a cookie never follows a redirect to another host (urllib copies them; audit 2026-11-27, 5-6)
        if new is not None and (urllib.parse.urlsplit(str(newurl)).hostname or "").lower() != \
                (urllib.parse.urlsplit(req.full_url).hostname or "").lower():
            for h in [k for k in list(new.headers) + list(new.unredirected_hdrs)
                      if k.lower() in ("authorization", "proxy-authorization", "cookie")]:
                new.remove_header(h)
        return new


_OPENER = urllib.request.build_opener(_HttpsRedirectsOnly)


def open(req, timeout):  # noqa: A001  (named like urllib's)
    """urlopen for a Request or an address, https only, redirects included."""
    url = req.full_url if isinstance(req, urllib.request.Request) else str(req)
    if not url.lower().startswith("https://"):
        raise NotHttps(f"{url.split(':', 1)[0]}: only https:// addresses are fetched")
    return _OPENER.open(req, timeout=timeout)  # nosec B310  # https only, redirects included (checked above and in the handler)
