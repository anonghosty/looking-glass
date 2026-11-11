# Looking Glass — penetration test report

> **Remediation status (2026-11-07, same day).** All 12 findings are fixed in the application and re-tested:
> `security_testing/security_retest.py` passes (about 100 checks), plus targeted probes for cross-site sign-in and registration,
> markup injection and unauthenticated admin access. Since the test, the platform also gained a login with MFA,
> registration with approval, roles and permissions, an admin page with sessions and an audit log, and password reset.
> Remaining operator steps: install the hardened service unit, switch MongoDB to the read-only account, review the
> Windows firewall rules, restrict the Mapbox token. Details: `docs/SECURITY.md` (what changed, how it works) and
> `docs/INSTALLATION.md` (installing on Windows/WSL or Linux).

**Date:** 2026-11-07
**Target:** Looking Glass as first deployed on a development workstation (Windows with WSL 2). This covers the gunicorn service on port 5000, its host and network exposure, MongoDB, and the browser pages. Details that identify the test machine and its network have been left out of this published copy.
**Method:** grey box. The tester had the source code and ran live tests against the real service and against a separate copy.

The tests were non-destructive:
- **The only write to the real service** was a "settings save" with the current values, so only its timestamp changed.
- **Load and abuse tests** ran only on a throwaway copy (port 5055, test database `lg_e2e`, public demo mode forced), which was removed afterwards.
- **No denial-of-service flooding**, and no calls to third-party services.

## Summary

| # | Finding | Severity |
|---|---|---|
| 1 | The platform is reachable from the local network without any login, over plain HTTP | **High** |
| 2 | Settings can be changed by any web page open on this computer (cross-site request forgery, DNS rebinding) | **High** |
| 3 | The app connects to MongoDB as `root` | **Medium** |
| 4 | One request for a far-future day evicts the current day from memory, forcing reloads (denial of service) | **Medium** |
| 5 | Malpedia lookup: unvalidated input in the API path sent with your token; unbounded cache and quota use | **Medium** |
| 6 | Public demo mode: Settings shows network names; the `ip=` filter confirms whether an address is in the data | **Medium** (public screens only) |
| 7 | No limit on request size; country code not checked against the 54 countries | **Low** |
| 8 | No security headers (CSP, X-Frame-Options, nosniff, Referrer-Policy) | **Low** |
| 9 | Third-party scripts loaded without integrity hashes (SRI) | **Low** |
| 10 | Malpedia reference links are not limited to http(s) | **Low** |
| 11 | A JSON array as the settings body causes an error 500 | **Info** |
| 12 | The Mapbox token is visible in the page (expected for a public token) | **Info** |

**What held up:**
- **NoSQL injection:** no user input reaches a database query.
- **Cross-site scripting:** report data (banners, URLs, hostnames) is always inserted as text or escaped.
- **Path traversal:** blocked (12 attempts, all 404).
- **Secrets:** none appear in pages.
- **Spoofed proxy headers:** refused.
- **Settings writes from the network address:** refused (403).
- **Demo masking:** no real IP address or AS number leaked from any of 47 endpoints, even with `demo=0` override attempts.
- **Error handling:** no stack traces.
- **MongoDB:** bound to localhost, with authentication.
- **File permissions:** `.env` 600, backups 600 (folder 700).
- **Debug mode:** off.

---

## Findings

### 1. Reachable from the local network without login, over plain HTTP — High

**Evidence:**
- gunicorn binds to `0.0.0.0:5000` (the service unit at the time; now `deploy/looking-glass.service.template`).
- WSL runs in mirrored networking mode (`.wslconfig`), so it shares Windows' LAN address.
- A Windows firewall rule allows TCP 5000 inbound from the local subnet on the **Public** profile, and the network in use was classified as Public.
- A WSL (Hyper-V) firewall rule allows the same port from **any** address.
- The app has no login, and serves HTTP only.

**Impact:** anyone on the same Wi-Fi can very likely open the platform and download the unmasked lists of vulnerable hosts in the constituency:
- `/api/svc/hosts.csv`;
- the drill-down lists;
- the full event stream.

These lists are effectively a target list. Traffic is unencrypted, so it can also be read on the network. This could not be confirmed from a second device during the test; the configuration permits it.

**Fix:**
- Bind to `127.0.0.1:5000` unless other screens need access.
- If they do, put the app behind a reverse proxy with TLS and a login (or a VPN), and set `SETTINGS_TOKEN`. *(Later: every page now needs a login, and `SETTINGS_TOKEN` was removed on 2026-11-11; see the note under #2.)*
- Remove the Public-profile firewall rules for port 5000, or limit them to the specific display devices.
- Set the Wi-Fi network to Private.

### 2. Settings can be changed by any web page on this computer — High

**Evidence:** these live tests against the real service, using the current values, all returned **200, accepted**:
- `POST /api/settings` with `Content-Type: text/plain` and `Origin: https://evil.example`, which is a cross-site "simple" request that browsers send without asking the server first;
- the same as a form post with an empty body;
- the same with `Host: rebind.evil.example` (DNS rebinding).

Requests from a Windows browser to `localhost:5000` arrive as `127.0.0.1`, so they count as "this machine" (`writable: true`). The server never checks the `Origin` or `Host` header. An empty or unreadable body falls back to the defaults (the default country, whole country).

**Impact:** any website you visit in a browser on the same computer (Windows or WSL) can:
- silently change the constituency or country of both platforms, for example narrowing the view to one network so the rest of the country's incidents disappear from the screens;
- reset it.

DNS rebinding goes further: a malicious site can also read all the data through your browser.

**Fix:**
- Require `SETTINGS_TOKEN` always (the page already supports it). *(Done differently since: every page needs a
  login with two-factor authentication, and settings need an account with the Settings permission plus the page's
  CSRF token. `SETTINGS_TOKEN` was removed on 2026-11-11: behind the login it never let a script in on its own, and
  for a signed-in account without the permission it was a way around that permission.)*
- Accept only `Content-Type: application/json`; a cross-site page can't send that without the server's permission.
- Reject requests whose `Origin` doesn't match the server's own address.
- Accept only expected `Host` values (`localhost`, `127.0.0.1`, the configured name).
- Reject an empty body instead of falling back to the defaults.

### 3. MongoDB account has the `root` role — Medium

**Evidence:** the account in `.env` has the role `root@admin`. The platform only reads data.

**Impact:** any weakness in the app, or a leak of `.env` or a backup, gives full control of every database: delete, modify, or create users.

**Fix:** create a dedicated user with only the `read` role on the Shadowserver database, and use it in `.env`.

### 4. Far-future day evicts the current day (denial of service) — Medium

**Evidence:** on the test copy, `GET /api/svc/stats?at=2099-01-01T00:00:00Z` loads an empty day for 2099. In doing so it deletes from memory every day more than 2 days older (`DayStore.get` / `ServiceStore.get`), including the replay day. The next normal request had to reload the day:
- services: 1.26 s before → 3.35 s after;
- comms: 1.96 s after.

On the real data a reload means reading all the day's records from MongoDB again. Anyone who can reach the server can repeat this to keep both platforms reloading. No false "new report" notices were produced.

**Fix:**
- Only accept `at` within the replay day and the day before (clamp otherwise).
- Never evict the day the schedule is replaying.

### 5. Malpedia lookup — Medium

**Evidence** (code review; not sent to Malpedia):
- `/api/malpedia?field=md5&value=...`: with `field` set to `md5`, `sha1`, `sha256` or `hash`, the value is placed **unescaped** into the Malpedia API path (`get/sample/{value}/info`) and sent with your API token. So a caller can make the server request other Malpedia paths or add query parameters, with your token.
- Every distinct value is cached to `data/malpedia_cache.json` forever and costs API quota. Anyone who can reach the server can grow the file and use up the quota.

**Fix:**
- Validate hashes (hex, length 32/40/64) before using them, and URL-encode every value.
- Only look up values that exist in the loaded data.
- Bound the cache (size and age).
- Rate-limit the endpoint.

### 6. Public demo mode leaks — Medium (public screens only)

**Evidence** (test copy with `PUBLIC_DEMO=1`):
- **Network names:** `GET /api/settings` and the `/settings` page are open to every viewer and list network company names with record counts (company names of the constituency). Every other endpoint masks them.
- **Address oracle:** `GET /api/svc/insight?ip=<a real address>` returned 1 record; an unknown address returned 0. The filter accepts raw addresses, not just the opaque references, so a viewer can test whether a given address is listed as exposed or vulnerable.

**Fix:**
- With `PUBLIC_DEMO=1`, return 403 for `/settings` and `GET /api/settings` unless the request is local or carries the token.
- Accept only opaque host references (`ip_ref`) in `ip=` in demo mode.

### 7. No request-size limit; country not checked — Low

**Evidence:**
- A 5.9 MB settings body with 600,000 AS numbers was accepted (test copy). `MAX_CONTENT_LENGTH` is not set, and every record is then checked against the list.
- Country `ZZ` was accepted.

**Fix:**
- Set `MAX_CONTENT_LENGTH` (for example 64 KB).
- Cap the number of networks and address ranges.
- Only accept the 54 country codes.

### 8. Missing security headers — Low

**Evidence:** responses carry only `Server: gunicorn`. There is no `Content-Security-Policy`, `X-Frame-Options` / `frame-ancestors`, `X-Content-Type-Options` or `Referrer-Policy`.

**Impact:** the Settings page can be shown inside another site's frame and its **Apply settings** button clicked through a disguised page (clickjacking). There's also no second line of defence if a script injection were ever found.

**Fix:** add these headers in an `after_request` hook:
- a CSP listing the known sources (self, api.mapbox.com, unpkg.com, fonts, flagcdn);
- `frame-ancestors 'none'`;
- `nosniff`;
- `Referrer-Policy: same-origin`.

### 9. Third-party scripts without integrity hashes — Low

**Evidence:** `mapbox-gl.js` 3.8.0 and `deck.gl` 9.1.14 are pinned by version but loaded without `integrity=`.

**Impact:** a compromised CDN could run code in the page, with access to all data and the settings endpoint.

**Fix:** add Subresource Integrity hashes, or serve both files from `static/`.

### 10. Malpedia reference links not limited to http(s) — Low

**Evidence:** reference URLs returned by Malpedia are put into links as they are (`extLink` in `app.js`).

**Fix:** only create links for `http:` and `https:` URLs.

### 11. JSON array body causes an error 500 — Info

`POST /api/settings` with `[1,2]` raises an exception (500, generic page, no trace). Reject bodies that aren't JSON objects with 400.

### 12. Mapbox token visible in the page — Info

A public `pk.` token is expected in a web map. Restrict it to your hostnames in the Mapbox account so it can't be reused elsewhere.

---

## Recommended order

1. **Settings writes (#2):** set `SETTINGS_TOKEN`, and add the JSON-only, Origin and Host checks. *(Done: login, Settings permission and CSRF token instead; the token was later removed.)*
2. **Network exposure (#1):** bind to localhost, or put the app behind TLS + login; tighten the firewall rules.
3. **Database account (#3):** switch to a read-only MongoDB user.
4. **Input validation (#4, #5, #7):** clamp `at`, validate Malpedia hashes, limit body size and country codes.
5. **Public demo (#6):** lock Settings and raw `ip=` in public demo mode.
6. **Browser hardening (#8–#10):** security headers, SRI, link schemes.

## Test artefacts

- `tests/e2e_test.py` built the throwaway copy (port 5055, database `lg_e2e`); it was torn down afterwards.
- The real settings are unchanged; only their timestamp moved, because of the no-op write tests.
