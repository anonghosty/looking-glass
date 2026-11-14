# Looking Glass — security

How Looking Glass protects the data it holds, how to run it safely, and how to report a vulnerability. To install it,
see [INSTALLATION.md](INSTALLATION.md); for the parts, trust boundaries and threat model, see
[Architecture and threat model](ARCHITECTURE.md).

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
| Outbound downloads (name sources) | MISP Galaxy and MITRE ATT&CK are downloaded only by `manage/fetch_offline_names.py`, run by the weekly cron line, an administrator on the server, or the **Refresh sources** button (permission *settings*, CSRF token, fresh sign-in, at most once an hour, one at a time; every refresh in the audit log): plain HTTPS GETs of fixed public files on raw.githubusercontent.com (and one listing of MITRE CTID's public Mappings Explorer repository on api.github.com, to find its newest KEV mapping file) (no name, host or report in the request; redirects away from HTTPS refused; 200 MB per file; at most once a week unless `--force`; a download that is invalid or under 70% of the copy in use is refused and the old copy kept). Only compact indexes are kept (`data/names_misp_galaxy.json`, `data/names_attack.json`); a look-up only reads them and sends nothing. The text is third-party data: shown as text, links only `http(s)` | `offline_names.py`, `manage/fetch_offline_names.py` |
| ATT&CK in advisories | Only reviewed mappings go to recipients: generating an advisory's report is refused while a mapping is only suggested (the advisor confirms or removes it: advisors only, CSRF token, fresh sign-in, audited, part of the report's content fingerprint), and a report carrying an unreviewed mapping cannot be marked sent. The generated report keeps its techniques and texts; "why" lines use counts and products, never an address | `advisory_attack.py`, `advisory.py` |
| Trusting CTID's CVE mappings | CVE techniques (MITRE CTID, KEV mappings) in advisories are suggestions under the reviewed-only rule unless an administrator trusts CTID: `POST /api/attack/ctid-trust` needs permission *settings*, the CSRF token and a fresh sign-in, accepts only true or false, is off by default, and every change is in the audit log. CVE look-ups read the local copy only | `attack_map.py`, `advisory_attack.py` |
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

New accounts are **pending** until an administrator approves them and chooses their role; only a pending account can
be approved, so approving never changes an active account's role (Role does that, and keeps the last administrator).
Registration accepts at most 5 new accounts per address per hour and 100 pending accounts in total; the e-mail domain
of a sign-up is looked up in DNS at most 30 times per address per hour, failed attempts included. Registration can be
switched off with
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

### Password expiry (optional)
An administrator can make passwords expire (Settings → Password policy, `password_policy.py`): after N days, and
"every account now" at any time. Both need the administrator's own password and are in the audit log. An expired
password is replaced inside the sign-in, after the password AND the authenticator code and before any session exists:
the new one follows the rules above and cannot be the expired one; the session then opens, the account's other sessions
end, and the change is logged. Off by default. (NIST SP 800-63B advises against periodic changes without a sign of
compromise; the option exists for the audits and regulators that still require them.)

### Signing in
The sign-in card opens on a choice: **Sign in** or **Create an account**, plus **Forgot password?**
1. User name and password.
2. The 6-digit code from the app (or a recovery code). Each code works once; codes from up to 30 seconds either side
   are accepted to allow for clock drift.
3. On success, a new session ID is issued.

- Wrong names and wrong passwords get the same answer and take the same time.
- User names and e-mail addresses that differ only in letter case are one: "Grace" cannot register beside "grace".
- An authenticator code works once, checked again at the moment it is recorded, so two sign-ins with the same code at
  the same moment cannot both pass. The sign-in page shows no text from its address other than Looking Glass's own
  notices.
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

**What researchers see (a deliberate rule, decided 2026-11-12 after the external review).** Researchers study threats,
so they get the threat data itself; what they never get is who the constituents are.
- **Never a constituent's IP address.** Addresses are masked everywhere researchers look, also inside report values.
- **Report data as reported:** service banners and the product, vendor and version taken from them (with a host's own
  name, address or e-mail inside them masked, since 2026-11-13); bot URLs, user
  agents, DNS look-ups and SNI values in Intel gathered; patterns, including those only one or a few hosts carry. IP
  addresses inside these values are masked (in Intel gathered's threat values as `x.161.x.34`, found by the one
  address finder every masker shares, `ip_find.py`); nothing else in them is removed, because it is the intelligence
  the research depends on. **The one exception: the C2 host itself** (a sinkhole report's contacted host, `http_host`)
  is shown as reported, an IP address too, because researchers need the C2 servers for their analysis; a C2 server is
  the threat's side, never a constituent's host. (A Spam URL record has no C2: its constituent is the spam relay
  that sent the message, and the host of a link in the spam is a "Spam link host", masked when it is in the
  constituency.) Management sees no C2 host: it decides on numbers, so the
  Executive portal lists each C2 / sinkhole domain by its name, so the executive can tell what the devices call; a C2 host that is, or holds, an IP address is never shown and reads "IP address 1, 2…", also when the name spells the address (ec2-203-0-113-7.compute.amazonaws.com, an IPv6 address with dashes, a decimal or hex number) (decided 2026-11-13; before, every domain was numbered, which made no sense to the executives). A pattern fewer than 5 hosts carry is shown
  without a lasting code (`small_codes.py`), so it cannot be followed back to a host over time.
- **Team notes and free text** (what people write, not what reports contain) mask more: host names, IP addresses,
  e-mail addresses, dates and long IDs (`hostmask.py`).
The difference is intended: report data is threat intelligence, notes are analysts' own text and may name a
constituent. External viewers and demo mode get the same product, vendor and version lines as researchers; these are
software names (for example "nginx 1.18", "Cisco IOS 15.2"), and a device that puts its own host name there is rare.

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
  AU-3, AU-6, AU-8, AU-9, AU-9(3), AU-9(4), AU-11, AU-12. Through CIS's official mapping each check also lists the
  CIS Controls v8.1 safeguards related to those NIST controls, exactly as CIS publishes them, and beside each Looking
  Glass's own reading, labelled as ours: backed, related or not backed with the reason (for example LG-10 → 3.11
  encryption at rest: not backed, Looking Glass does not encrypt its data at rest). One table holds the reading
  (`control_map.py`: BACKED, NOT_BACKED). The CIS Controls are used here as a map, to guide Looking Glass's security and make the auditor's work easier. They are voluntary best practice, not a law or a requirement, and CIS issues no certificate for meeting them: organisations measure themselves with CIS's free Self Assessment Tool (CSAT) or with an auditor, and those that need a formal certificate usually go for ISO 27001 or SOC 2, with the CIS Controls as a guide.
- **Data access logging:** every export, and every view of host-level data (the map's events, the services page's
  records, one host's activity, the hosts behind a figure, a record's details, an analysis), is an audit entry with
  who, when, from where and what, every filter of the view included; hosts appear by their reference, never their
  address (`data_access.py`; `DATA_ACCESS_LOG=0` turns view logging off).
- **Roles & permissions:** the matrix above, editable.

**Location** is "This computer", "Local network" or "Internet". Addresses are never sent to an online service; to add
country and city, install the `maxminddb` package and put a GeoLite2-City database at `data/GeoLite2-City.mmdb`.

### Command line (server)
`manage/manage_users.py` creates and repairs accounts without the web pages (for example if every administrator is
locked out): `add NAME [--admin]`, `passwd`, `mfa`, `role`, `remove`, `list`. Accounts it creates are active at once.

### Pipeline settings from the web app (Settings → Workers)
The web app never writes the pipeline's files: a change is a request in its own `data/pipeline_requests/`, which the
pipeline checks again and applies at its next run. Requests may only make the pipeline **stricter** on their own. One
that weakens it (the sender check lowered or another expected signer, the mail server's certificate check off, the
API given up for the mailbox, an unzip limit loosened, a new Shadowserver API key, a held-back report released) is held
until someone confirms it on the server, on the pipeline's
account (`./confirm_request.sh <id>` in the pipeline's folder). The confirmation lives in the pipeline's folder, which
the hardened web service cannot write, and is bound to the request's SHA-256, so a request changed afterwards is
refused; unconfirmed ones are refused after 7 days. The confirmation screen and the pipeline's log print every field
of a request with its control characters removed, and a malformed request cannot be confirmed, so a forged request
cannot redraw the screen to look harmless; what is shown is read once and is exactly what is hashed. Nothing in the
web app's request folder is trusted: it and its `done/` are never followed through a symlink, a request must be a
plain file, results carry a fixed list of fields and are never named after an id a refused file claims (so a forged
"result" cannot become a confirmation), and each change is judged by what its value means to the pipeline. So a bug in the web app or a takeover of its account cannot use
this route to switch the pipeline's checks off or reach the mailbox password.

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

### Service hardening
- **systemd sandbox:** `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome=read-only`, writable only `data/`,
  `PrivateTmp`, `UMask=0077` and more. Check it with `systemd-analyze security looking-glass`.
- **Request limits:** request line, number of header fields and field size (gunicorn), and a 64 KB body limit.
- **Separate database accounts:** the platform reads with a read-only MongoDB account; the pipeline has its own
  account limited to its database; the administrator account is kept root-only in `/etc/looking-glass/`.
- **Report intake:** unpacking limits against oversized or malicious archives, report names checked before they become
  collections, and an optional DKIM check of every report e-mail, with blocking and quarantine.

## 4. Operator checklist

Do this on every installation (details in [INSTALLATION.md](INSTALLATION.md)):
- [ ] Install the hardened service unit (the installer does this; `deploy/install.sh` on a manual installation).
- [ ] Create the administrator account: open the sign-in page, click **Let's get started**, and type the setup code
      from `data/setup_code`.
- [ ] Approve registered accounts in Admin → Users with the right role.
- [ ] Use the read-only MongoDB account for the platform and the pipeline's own account (the installer does both;
      `deploy/create_readonly_db_user.py` and `database/create_pipeline_db_user.py` on a manual installation).
- [ ] Check the mail server's certificate (`IMAP_VERIFY_TLS=true`, the default) and, once genuine Shadowserver mail
      passes the sender check, block what fails it (`MAIL_AUTH=enforce`), or take the reports by Shadowserver's API.
- [ ] WSL only: remove Windows firewall rules that open the port to the network, unless other screens need it.
- [ ] Other screens: choose `ACCESS_MODE` (`private` with `VIEWER_NETWORKS`, or `public`), switch on HTTPS, and open
      the firewall accordingly.
- [ ] Restrict the Mapbox token to your host names in the Mapbox account.
- [ ] Wall screens: an external account (always masked) with "Stay signed in for 5 days", and `PUBLIC_DEMO=1` for
      public displays.
- [ ] Check the installation (below).
- [ ] Take a backup (`manage/backup.sh`) and keep a copy off the server.

## 5. Checking your installation

After installing or updating, check that every protection is in place on your own server:
```bash
.venv/bin/python security_testing/security_retest.py
bash tests/run_all_checks.sh
```
- The first checks the protections against the running service (sign-in, MFA, sessions, roles and permissions,
  administration, the audit log, password reset, request and browser protections). It uses two temporary accounts
  with random secrets and removes them afterwards. It leaves about 10 failed sign-ins from this computer in the
  lockout counter, so leave a few minutes before running it again.
- The second checks the configuration, the data and each part of the platform.
- Both reach the API with the local automation key (`data/automation.key`, mode 600, accepted from this computer only).
- The installer runs both at the end of an installation when you ask it to.

**Logs:**
```bash
journalctl -u looking-glass
```
They record sign-ins, failed sign-ins and lockouts; sessions ended because they were used from another address or
browser; recovery-code use; and settings changes. The audit log (Audit portal) records who did what, and how to prove
it was not changed is in [How the audit log proves itself](AUDIT_LOG_PROOF.md).

## 6. Supported versions and changes

Security fixes are made on the latest version (the `main` branch). Update with the steps in
[INSTALLATION.md](INSTALLATION.md#updating). What changed in each release, security changes included, is in the
[changelog](../CHANGELOG.md).

## 7. Reporting a vulnerability

- **In Looking Glass itself:** report it privately through the repository's Security tab (**Report a vulnerability**),
  not in a public issue. Include the steps to reproduce and the version (commit) you run.
- **In an installation:** report it to the CSIRT team that runs it.
