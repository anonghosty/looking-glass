# Looking Glass — security

This document describes how Looking Glass is secured, what was changed after the penetration test of 2026-11-07
(`docs/SECURITY_REPORT.md`), and how to run it safely. To install it, see `docs/INSTALLATION.md`.

**Status: hardening is in progress.**
- **Done:** all application fixes, tested with `security_testing/security_retest.py` (about 120 checks, all passing).
- **Still to do by the operator, on each installation:**
  - install the hardened service unit;
  - switch MongoDB to the read-only account;
  - review the Windows firewall rules (on WSL installations);
  - create the real user accounts.

  These steps are listed under [Operator checklist](#5-operator-checklist).

---

## 1. What protects what

| Layer | Protection | Where |
|---|---|---|
| Network | `ACCESS_MODE`: `local` (this computer), `private` (+ `VIEWER_NETWORKS` allow list) or `public` (any address); other computers must use HTTPS to sign in | `deploy/looking-glass.service.template`, `security.py`, `gunicorn.conf.py` |
| Host names | Only `localhost`, `127.0.0.1`, `::1` and `ALLOWED_HOSTS` are served (stops DNS rebinding) | `security.py` |
| Login | Every page and API needs a login: password (scrypt) plus a code from an authenticator app (TOTP) | `auth.py`, `templates/login.html` |
| Accounts | Self-registration with approval, QR authenticator set-up, roles with permissions, admin page, audit log, password reset | `auth.py`, `templates/login.html`, `templates/admin.html` |
| Password guessing | 5 wrong attempts for an account from one address lock it for 15 minutes; 20 failures from one address in an hour lock the address. Failure records older than an hour are cleared out, so the counter cannot grow without end on a public install | `auth.py`, `throttle_prune.py` |
| Sessions | Server-side; the cookie is HttpOnly, SameSite=Strict, and Secure over HTTPS; bound to address and browser; idle and maximum timeouts | `auth.py` |
| Changes | Admin role, CSRF token, JSON only, and same-origin checks on `Origin` / `Sec-Fetch-Site` | `app.py`, `security.py` |
| Input | Times clamped to the replay days; Malpedia values validated; settings limited in size and content; 64 KB request limit | `app.py`, `malpedia.py`, `settings.py`, `security.py` |
| Browser | Content-Security-Policy with a per-request nonce; no inline handlers and no eval; frames refused; nosniff; Referrer-Policy; integrity hashes on CDN files | `security.py`, templates |
| Demo mode | Real addresses, AS numbers and network names are masked on the server; host filters accept only opaque references; report fields only from an allowlist; Settings is admin-only | `privacy.py`, `masked_fields.py`, `app.py` |
| Report zips | Unpacked within limits counted on the real bytes (unpacked size, compression ratio, files per zip, free disk); a zip bomb is quarantined with the reason and nothing of it is loaded; names inside a zip cannot leave its folder. Defaults suit a large country, changeable in `.env` | `database/zip_limits.py` |
| Database | Read-only MongoDB account for the platform (`lookingglass_ro`); the pipeline's own account (`lookingglass_pipeline`: read and write on its database only, no account management); the administrator account only in `/etc/looking-glass/mongo-admin.env` (root, mode 600), out of reach of the programs' own Linux user; MongoDB bound to localhost with authentication | `deploy/create_readonly_db_user.py`, `database/create_pipeline_db_user.py`, `database/store_mongo_admin.sh` |
| Operating system | systemd sandbox: no privilege gain, read-only system and home folder, writable only in `data/`, private files (umask 077) | `deploy/looking-glass.service.template` |
| Secrets | `.env` and `data/users.json`, `sessions.json`, `automation.key` and `tls/key.pem` are mode 600; backups are mode 600 in a 700 folder | file system |

## 2. Accounts, sign-in and administration

### First run
When no administrator exists, the sign-in page shows only **Let's get started**, and it asks for a **one-time setup
code** that only someone with access to the server can read: `cat data/setup_code` in the platform folder (mode 600,
written when the app starts without an administrator, never logged or shown in a page; the installer prints the
command). The first account created with that code becomes the **active administrator**, and the code is deleted.
Being on "this computer" is not enough on its own: a reverse proxy set up wrongly can make every visitor look local.
From another computer (through the reverse proxy) the first administrator is created over HTTPS only. Wrong codes
are in the audit log, and 10 wrong codes from one address block it for an hour (`first_run.py`, `auth.py`).

Behind a reverse proxy (`TRUST_PROXY=1`), the X-Forwarded-* headers are believed only from the proxy on this
computer, and a request from it without X-Forwarded-For is refused, except `/healthz` (`proxy_guard.py`). Without
this, a proxy that forgot the header would make every visitor look like 127.0.0.1.

### Creating an account (sign-in page → Create an account)
1. **Details:** full name, organisation, work email (unique), country, user name, and a password (asked twice; see
   [Password rules](#password-rules)). These details are stored with the account (`profile`), shown to administrators, and
   available for future features.
2. **Authenticator:** scan the QR code with Google Authenticator, Microsoft Authenticator or a similar app, and
   confirm with a code. The QR code is drawn in the browser, so the key never goes to an outside QR service. "Can't
   scan?" shows the key, to type in without spaces.
3. **Recovery codes:** 8 one-time codes are shown once (with a Copy button). Store them offline.

New accounts are **pending** until an administrator approves them and chooses their role. Registration accepts at
most 5 new accounts per address per hour and 100 pending accounts in total, and can be switched off with
`REGISTRATION=0` (accounts are then created by administrators only, or with `manage/manage_users.py`).

### Password rules
Enforced on the server for every password (create account, password reset, `manage/manage_users.py`), and shown
live on the page with a strength meter and a checklist; the form cannot be sent until they are met:
- at least 12 characters (at most 200);
- upper-case and lower-case letters, a number and a symbol;
- not containing the user name, the person's name, the email name or the organisation;
- no common password words or patterns (password, welcome, admin, qwerty, 123456, the platform's name, and others,
  also with digits standing in for letters);
- no character four times in a row.

Every password field has an eye button to show or hide what was typed.

### Signing in
The sign-in card opens on a choice: **Sign in** or **Create an account**, plus **Forgot password?**
1. User name and password.
2. The 6-digit code from the app (or a recovery code). Each code works once; codes from up to 30 seconds either side
   are accepted to allow for clock drift.
3. On success, a new session ID is issued.

- Wrong names and wrong passwords get the same answer and take the same time.
- The page says how many attempts are left before the 15-minute lock (5 per account and address; 20 per address an
  hour).
- Pending accounts are told they await approval; revoked accounts are told they have been revoked (only after the
  right password).

### Forgot password
- **Use my authenticator:** user name + a code from the app + **one recovery code** + a new password. Both are needed,
  so a stolen phone alone is not enough.
- **Ask an administrator:** the request appears in Admin → Users ("Password reset requested", with the address,
  location and browser it came from). The administrator clicks **Allow password reset**; for 24 hours the user can
  then set a new password with the authenticator code alone.
- The answers never reveal whether a name exists. Every reset ends the account's sessions, and is audited.

### Roles and permissions
Permissions are fixed; roles are sets of them, edited by an administrator in Admin → Roles & permissions (custom roles
can be added; roles in use cannot be removed; `admin` always has everything).

| Permission | Allows |
|---|---|
| `view` | see both platforms; real addresses, network and host names masked unless `unmasked` |
| `unmasked` | see real IP addresses, network names and host names |
| `export` | download CSV files and complete lists |
| `malpedia` | look up malware families and samples on Malpedia |
| `settings` | change Settings (country, constituency) |
| `users` | manage accounts, roles and sessions |
| `audit` | the Audit portal, read only: the audit log by tab, dashboard and control checks, access review, integrity, evidence exports |

Default roles (described on the admin page too):
- **external** (`view`): people outside the security team, such as partners or visitors. They see both platforms with IP
  addresses, network names and host names always masked, cannot switch masking off (no Demo buttons at all), and cannot
  export, use Malpedia or change anything. New accounts start here until an administrator chooses their role.
- **analyst** (`view`, `unmasked`, `export`, `malpedia`): CSIRT analysts. All data unmasked for analysis, exports,
  Malpedia, and the Demo switch for presentations. No Settings, no account management.
- **auditor** (`audit`, fixed): the Audit portal only, read only; never the platforms or host data. Its permission
  cannot be changed by anyone, so what an auditor may do never depends on the people being audited.
- **admin** (all): everything, including Settings, accounts, roles and permissions, sessions and the audit log.

Permanent roles (`auth.FIXED_ROLES`): management, researcher, advisor, auditor and external keep exactly their permissions and
cannot be removed; admin always has every permission. Exclusive permissions (`auth.EXCLUSIVE_PERMS`): *management*,
*definitions*, *advisory* and *users* belong to their own role (and admin) only. Both are enforced on the server when
roles are loaded and saved; the Roles page shows them locked.

(The lowest role was called "viewer" before 2026-11-07; existing roles and accounts were renamed automatically.)

**Masking** shows no part of an IP address: every address becomes an opaque label such as `Host 3f9a2c41b07e`, also
inside URLs and banners (`host_label.py`). The label is an HMAC of the address under the server's `REF_SECRET`: the
same address always gets the same label on one server, so a viewer can follow one host across the screens and
"analyse this host" still works, but the address cannot be read or computed back from the label without the
server's secret. (Earlier versions kept two of the four parts, `x.161.x.34`; in a constituency of a few address
blocks, with the network alias, region and port next to it, that left too few candidates.) Network names become
aliases (Telco 1, Bank 2...) and host names are removed. Set `REF_SECRET` in `.env` (the installer does) so labels
stay the same across restarts.
A report's own fields (the "specific fields" in a details window) are shown to masked viewers only when they are on an
allowlist of technical details (protocol, software, versions, ciphers, capability flags; `masked_fields.py`), and even
those values have host names, addresses, e-mail addresses, dates and long IDs masked. Every other field is hidden:
system and workstation names, DNS and LDAP names, MAC addresses, user names, descriptions, locations, keys,
fingerprints, serials and banners. A field a report adds later stays hidden until it is added to the allowlist.
Everything is enforced on the server: an external account gets masked data even if the address asks for `demo=0`, and exports,
Malpedia, Settings and the admin APIs answer 403 without the permission.

### Admin page (Admin button in the top bar)
- **Users:** user name, full name, organisation, email, country; status; role; MFA and recovery codes left; when, where
  (address and location) and with which browser the account registered and last signed in; open sessions. Actions:
  approve (with a role), change role, revoke, restore, allow password reset, reset authenticator (the user sets it up
  again at the next sign-in and needs approval again), kick (end all sessions), delete. An administrator cannot revoke,
  delete or reset their own account, and the last administrator cannot be removed or demoted.
- **Sessions:** every live session with user, address, location, browser, start and last activity; **End session**.
- **Audit log:** searchable; sign-ins and failures, lockouts, registrations, approvals, role and permission changes,
  revocations, kicks, session misuse, password resets, recovery-code use and Settings changes, each with time,
  account, address, location and browser. Stored in `data/audit.log` (mode 600). **Tamper evident:** each entry
  carries the SHA-256 of the entry before it (`audit_chain.py`); changing, inserting or removing an entry breaks the
  chain, and `data/audit.head` (newest link and entry count) catches entries cut from the end. **Retention:** at
  `AUDIT_ROTATE_MB` the file is compressed into `data/audit_archive/` and kept `AUDIT_RETENTION_DAYS` (default 400);
  the last link of every archive removed by the retention is noted, so the check still covers what is left. Read in the
  Audit portal (`audit_portal.py`): tabs per kind of event, dashboard, 15 control checks (evidence, no pass or fail),
  access review, Verify, and evidence exports (CSV, PDF report with the head), each check and export itself audited.
  The chain proves integrity against later editing of the file; someone with full control of the server could still
  rewrite the whole chain. Against that, the auditor takes the **proof package** (`audit_proof.py`): the log's files
  as stored, their SHA-256s and an independent verifier (`audit_verifier.py`, standard library only) to run on their
  own computer, and keeps its head (hash@entry) outside the server. At the next audit the earlier head must still be
  at its entry number (`--earlier`, or the portal's comparison); a rewrite cannot keep it there. The full logic:
  [How the audit log proves itself](AUDIT_LOG_PROOF.md).
  Entries written before the chain existed (older versions) are **sealed** once: their count, time span and SHA-256 go
  to `data/audit.seal`, and the seal is recorded in the chain. Changing them afterwards is detected; nothing can prove
  they were unchanged before the seal, and the evidence says so.
  The control checks (LG-01…LG-15) are mapped to NIST SP 800-53 Rev. 5, Release 5.2.0 (titles read from NIST's OSCAL
  catalog): IA-2(1), IA-2(2), AC-2, AC-2(3), AC-2(7), AC-5, AC-6(5), AC-6(9), AC-7, AC-12, SC-23, SC-8, SC-8(1), AU-2,
  AU-3, AU-6, AU-8, AU-9, AU-9(3), AU-9(4), AU-11, AU-12.
- **Roles & permissions:** the matrix above, editable.

**Location** is "This computer", "Local network" or "Internet". Addresses are never sent to an online service; to add
country and city, install the `maxminddb` package and put a GeoLite2-City database at `data/GeoLite2-City.mmdb`.

### Command line (server)
`manage/manage_users.py` creates and repairs accounts without the web pages (for example if every administrator is
locked out): `add NAME [--admin]`, `passwd`, `mfa`, `role`, `remove`, `list`. Accounts it creates are active at once.

### Why TOTP, and what about OAuth / single sign-on
TOTP is built in: it is free, works offline and no outside service sees your sign-ins. If your staff already have
central accounts, single sign-on through OpenID Connect is the next step: Microsoft Entra ID or Google Workspace (MFA
and leavers managed centrally), or a self-hosted Keycloak or Authentik. The login is a separate module (`auth.py`), so
an OpenID Connect provider can be added later.

## 3. Session hijacking defences

- **Server-side sessions.**
  - The browser holds only a random 256-bit ID.
  - The server stores its SHA-256 hash in `data/sessions.json` (mode 600), so a copy of that file can't be replayed.
  - Sessions survive a service restart.
- **New ID at every login**, so an attacker can't plant a known ID beforehand (session fixation).
- **Cookie flags:**
  - `HttpOnly`: scripts can't read the cookie.
  - `SameSite=Strict`: the cookie isn't sent on cross-site requests.
  - `Path=/`.
  - Over HTTPS: `Secure` and the `__Host-` prefix.
- **Bound to the device.** A session works only from the address and browser it was created on. Any other use ends the session for everyone holding it, and is logged as "Session of NAME ended: used from another …".
- **Timeouts:** a normal session is a browser-session cookie (gone when the browser closes) that ends after
  `SESSION_IDLE_MINUTES` without use (default 60) and after `SESSION_MAX_HOURS` (default 12).
- **Stay signed in for 5 days** (checkbox on the sign-in form): a 5-day cookie, capped at 5 days whatever the settings.
  It keeps every other protection (bound to address and browser, server-side, HttpOnly, Secure, SameSite=Strict),
  and adds two: the session ID is **replaced every 12 hours**, so a copied cookie stops working on its own; and once
  the sign-in is **older than 12 hours, changes need a fresh sign-in** (admin actions and Settings answer "sign in
  again"), while viewing continues. Admin → Sessions shows each session's type and expiry, and can end any of them.
- **Logout** is a button (`POST /logout`) and ends the session on the server. A link can't log you out.
- **Password changes and removed accounts** end that account's sessions immediately.
- **No plain-HTTP logins from other computers**, unless `ALLOW_INSECURE_REMOTE_LOGIN=1`, so passwords and cookies aren't sent in clear over the network.
- **Script injection, the main way cookies are stolen, is contained:** strict CSP (nonce, no eval, no inline handlers), all report data inserted as text, and `HttpOnly` cookies.
- **`Cache-Control: no-store`** on the API, the login page and Settings, so data doesn't stay in browser or proxy caches.

## 4. Changes made after the penetration test

| # | Finding | Fix | Verified by |
|---|---|---|---|
| 1 | Reachable from the network without login, plain HTTP | Login + MFA for everything. Local-only bind (unit) and an app-level guard: other computers get 403 unless listed in `VIEWER_NETWORKS`. HTTPS on the same port via `gunicorn.conf.py` + `deploy/make_tls_cert.sh`. Firewall steps in `docs/INSTALLATION.md` | retest: no-login pages redirect, APIs 401; the network address gets 403 |
| 2 | Settings changeable by any web page (CSRF, DNS rebinding) | Admin role; per-session CSRF token; JSON only (415 otherwise); a foreign `Origin` or `Sec-Fetch-Site: cross-site` gets 403; unknown `Host` gets 400; an empty body no longer means "defaults" | retest: text/plain 415, foreign Origin 403, cross-site 403, rebinding 400, no token 403, viewer 403 |
| 3 | MongoDB `root` account | `deploy/create_readonly_db_user.py` creates `lookingglass_ro` (read role only), checks that it can't write, and switches `.env` | **operator step** (needs the admin account once) |
| 4 | A far-future `at=` evicted the replay day | All request times are clamped to the replay day and the day before it | retest: `at=2099` gives the replay day; no reload |
| 5 | Malpedia path injection, quota and cache use | Allowed fields only; hashes must be hex of the right length; family IDs `platform.name`; values ≤ 100 characters and URL-encoded; 30 API calls a minute; cache capped at 3,000 entries | retest: bad hash, field and family ID all 400 |
| 6 | Public demo leaks (network names, IP oracle) | Settings admin-only; in demo mode host filters accept only the server's opaque references | retest: a raw IP in demo mode gives 0 records; the reference still works |
| 7 | No size limit; any country code | 64 KB request limit; at most 2,000 AS numbers and 500 ranges; country must be one of the 54 | retest: 2.9 MB refused, ZZ 400 |
| 8 | No security headers | CSP with nonce (no `unsafe-eval`; inline scripts carry the nonce; the old browser-age check no longer uses `new Function`), `frame-ancestors 'none'`, `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy`, `Cross-Origin-Opener-Policy`, `Permissions-Policy`; `Server: Looking Glass` | retest + browser: map, services and Settings work with no CSP violations |
| 9 | CDN scripts without SRI | sha384 integrity on `mapbox-gl.js`, `mapbox-gl.css`, `deck.gl` (pinned versions) | retest; browser loads them |
| 10 | Malpedia links not limited to http(s) | Only `http:` / `https:` links; anything else is shown as text | code |
| 11 | JSON array caused 500 | 400 with a message | retest |
| 12 | Mapbox token visible | Expected for a public `pk.` token | **operator step:** restrict it to your hostnames in the Mapbox account |

Changes after an external code review (2026-11-09):

| Finding | Fix | Verified by |
|---|---|---|
| CSV exports could carry spreadsheet formulas (vendor and product banners come from the scanned hosts) | One guard for every CSV (`csvsafe.py`, the same rule in the browser downloads): formula cells get a leading apostrophe | `tests/check_csv_safety.py`: planted values, the code, every cell of the real downloads |
| In masked views a real network name or AS number still worked as a filter (a network-presence oracle) | Masked requests accept only the aliases as network filters, as host filters already accepted only opaque references | `tests/test_demo.py`; the check fails with the fix removed |
| The masking test could never fail | It now fails on any leak, and first proves it detects real values in unmasked answers; unit tests for `privacy.py` and the roles | proven by breaking masking in a throwaway copy |
| Pinned events (full details) stayed in the browser after logout | Pins are per account, never kept for masked accounts, deleted on the sign-in page | `tests/test_demo.py` |
| The release was marked publishable before its scan; images and PDFs were not scanned | A separate marker is written only after a clean scan and is required to publish; binaries are scanned for paths, authors, EXIF, GPS and PNG text chunks | deliberate failures in the build |

Other hardening added:
- **systemd sandbox:** `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome=read-only`, writable only `data/`, `PrivateTmp`, `UMask=0077` and more. Check it with `systemd-analyze security threatmap`.
- **gunicorn request limits:** request line, number of header fields, and field size.
- **Geocoding cache moved to `data/geocache.json`,** so the sandbox only needs `data/` writable.

## 5. Operator checklist

Do this on every installation (details in `docs/INSTALLATION.md`):
- [ ] Install the hardened unit: `deploy/install.sh`, then copy `deploy/looking-glass.service` to `/etc/systemd/system/` (needs sudo; docs/INSTALLATION.md).
- [ ] Create the administrator account: open http://localhost:5000 on the server (or the proxy's HTTPS address), click **Let's get started**, and type the setup code from `cat data/setup_code`.
- [ ] Approve registered accounts in Admin → Users with the right role (external, analyst, admin or a custom role).
- [ ] Switch to the read-only MongoDB account: `deploy/create_readonly_db_user.py`, then move `.env.before-readonly` off the server.
- [ ] Give the pipeline its own account: `database/create_pipeline_db_user.py`. It moves the administrator account to `/etc/looking-glass/mongo-admin.env` (root only) with `database/store_mongo_admin.sh`; run that script yourself if it says sudo was not available. This only helps if the user running Looking Glass has no passwordless sudo.
- [ ] Now and then, run the three tests that need a throwaway database (they skip in the normal suite, because only root can read the administrator account): `tests/run_admin_db_tests.sh` (asks for sudo once).
- [ ] WSL only: remove the Windows / Hyper-V firewall rules that open port 5000 to the network, unless other screens need it.
- [ ] Other screens: choose `ACCESS_MODE` (`private` with `VIEWER_NETWORKS`, or `public`), switch on HTTPS, and open the firewall accordingly.
- [ ] Restrict the Mapbox token to your hostnames in the Mapbox account.
- [ ] Wall screens: an external account (always masked) with "Stay signed in for 5 days", and `PUBLIC_DEMO=1` for public displays.
- [ ] Run `security_testing/security_retest.py` and `tests/run_all_checks.sh`; both must pass.
- [ ] Take a backup (`manage/backup.sh`) and keep it off the server too.

## 6. Checking it

Every security protection:
```bash
.venv/bin/python security_testing/security_retest.py
```
- About 120 checks against the running service (login, MFA, sessions, registration, approval, roles and permissions, admin, audit, password reset, and every finding of the penetration test). It uses two temporary accounts with random secrets and removes them afterwards.
- It leaves about 10 failed logins from this computer in the lockout counter (one address may have 20 an hour). So don't run it twice in quick succession, or restart the service in between.

The platform checks:
```bash
bash tests/run_all_checks.sh
```

The end-to-end test, which runs on a separate copy:
```bash
.venv/bin/python tests/e2e_test.py all
```

The scripts reach the API with the local automation key (`data/automation.key`, mode 600, accepted from this computer only).

**Logs:**
```bash
journalctl -u looking-glass
```
They record:
- logins, failed logins and lockouts;
- sessions ended because they were used from another address or browser;
- recovery-code use;
- settings changes.

## 7. Reporting a problem

Report suspected vulnerabilities to the CSIRT team that runs this installation; don't open public issues for them. Include the steps to reproduce, and the logs if possible.
