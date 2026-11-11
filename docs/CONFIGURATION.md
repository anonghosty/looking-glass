# Configuration

Looking Glass is configured in two places:

- **`.env`** in the platform folder: the database, tokens, security and advanced settings. It is created from
  `.env.example` by `deploy/install.sh`, must stay private (mode 600, never committed) and is read when the service
  starts: run `deploy/reload.sh` after changing it.
- **The Settings page** (administrators): the country and the constituency. It is stored in `data/settings.json`
  and applies at once, without a restart. `COUNTRY`, `CONSTITUENT_ASNS` and `CONSTITUENT_CIDRS` in `.env` are only
  the starting values until Settings is saved.

The database pipeline has its own `.env` in `../database` ([../../database/README.md](../database/README.md)).

## Database

| Setting | Default | Meaning |
|---|---|---|
| `MONGO_HOST`, `MONGO_PORT` | `127.0.0.1`, `27017` | where MongoDB runs |
| `MONGO_USER`, `MONGO_PASSWORD` | empty | the account Looking Glass uses. Use the read-only `lookingglass_ro` made by `deploy/create_readonly_db_user.py` |
| `MONGO_AUTH_SOURCE` | `admin` | the database the account is defined in |
| `MONGO_DB` | `shadowserver` | the database the pipeline fills |
| `MONGO_COLLECTIONS` | empty | empty = every compatible report found (recommended); otherwise a comma-separated list |
| `EXCLUDE_COLLECTIONS` | `outdated_dnssec_key` | reports never to use (comma separated) |

New report types that Shadowserver starts sending are picked up by themselves within about 15 seconds.

## Map and look-ups

| Setting | Default | Meaning |
|---|---|---|
| `MAPBOX_TOKEN` | empty | public Mapbox token (`pk.…`): map tiles in the browser and place look-ups on the server (each place once, cached in `data/geocache.json`). Restrict it to your site's address in the Mapbox account |
| `MALPEDIA_TOKEN` | empty | optional Malpedia API token for the **Look up on Malpedia** buttons. Stays on the server; answers are cached for a week |
| `NVD_API_KEY` | empty | optional NIST NVD API key (free, nvd.nist.gov/developers/request-an-api-key). CVE look-ups work without it at 5 per 30 seconds; with it, 50. CISA KEV and EPSS need no key |

## Replay

| Setting | Default | Meaning |
|---|---|---|
| `REPLAY_OFFSET_HOURS` | `24` | how far behind real time the replay runs: 24 = yesterday's events at today's clock time |
| `REPORT_SETTLE_SECONDS` | `600` | once a day's reports start arriving, how long without a new report before that day replays from 00:00 |
| `MAX_EVENTS_PER_POLL` | `400` | most events sent to a browser per poll (extra ones are sampled) |

Shadowserver delivers a day's reports during the next day. Looking Glass waits for them ("Waiting for the reports
of …"), then replays the whole day from 00:00 to 24:00. Details: [TECHNICAL_REFERENCE.md](TECHNICAL_REFERENCE.md).

## Country and constituency (also on the Settings page)

| Setting | Default | Meaning |
|---|---|---|
| `COUNTRY` | `GH` | the country your CSIRT covers: ISO 3166 two-letter code of any of the 54 African countries (`DZ`, `EG`, `KE`, `MA`, `NG`, `RW`, `SN`, `TZ`, `ZA`...). Sets the regions map and labels of the services platform |
| `CONSTITUENT_ASNS` | empty | AS numbers your CSIRT is responsible for, comma separated. Empty = the whole country |
| `CONSTITUENT_CIDRS` | empty | address ranges you are responsible for (for example a government network without its own AS number) |
| `SETTINGS_TOKEN` | (removed) | no longer used: it never let a script in without a signed-in session. Settings are changed by an account with the Settings permission; an old line in `.env` does nothing and can be deleted |

## Access and security

| Setting | Default | Meaning |
|---|---|---|
| `ACCESS_MODE` | `local` | who can reach the sign-in page: `local` (this computer), `private` (plus `VIEWER_NETWORKS`), `public` (anyone) |
| `VIEWER_NETWORKS` | empty | addresses and ranges allowed in `private` mode, comma separated (`10.20.0.0/24, 192.168.1.40`). `any` or `*` = public |
| `ALLOWED_HOSTS` | empty | extra host names people type to reach it (the computer's own names and addresses are always allowed). `*` = any |
| `MFA_REQUIRED` | `1` | authenticator code at every sign-in. `0` only in a closed lab |
| `REGISTRATION` | `1` | **Create an account** on the sign-in page (accounts wait for an administrator's approval). `0` = only administrators add people |
| `SESSION_IDLE_MINUTES` | `60` | a normal session ends after this many minutes without use |
| `SESSION_MAX_HOURS` | `12` | and after this many hours in any case. "Stay signed in" sessions last up to 5 days (fixed) |
| `TRUST_PROXY` | `0` | `1` when a reverse proxy on the same computer does HTTPS (Caddy, nginx): the client address and https come from its headers. The proxy must send `X-Forwarded-For`; direct requests without it are refused (except `/healthz`) |
| `ALLOW_INSECURE_REMOTE_LOGIN` | `0` | `1` lets other computers sign in over plain HTTP. Only in a closed lab: passwords cross the network readable |
| `PUBLIC_DEMO` | `0` | `1` masks everything for everyone (public screens): no IP addresses, network names or host names |
| `CSP_REPORT_ONLY` | `0` | diagnostics: `1` makes the browser report, not block, what the Content-Security-Policy forbids |

What each protection does: [../docs/SECURITY.md](SECURITY.md).

## Audit portal and the audit log

Set these to what your own audits and laws require; the defaults suit a yearly IT audit.

| Setting | Default | Meaning |
|---|---|---|
| `AUDIT_RETENTION_DAYS` | `400` | days archived audit entries are kept (compressed, `data/audit_archive/`) before they are deleted. The last link of each deleted archive is noted, so the integrity check still covers what is left |
| `AUDIT_ROTATE_MB` | `5` | size at which `data/audit.log` is archived and a new file started; the tamper-evident chain goes on across files |
| `AUDIT_DORMANT_DAYS` | `90` | control check LG-02 (NIST AC-2(3)): an active account unused this long is flagged as dormant |
| `AUDIT_MAX_ADMINS` | `3` | control check LG-03 (NIST AC-6(5)): more administrators (every permission) than this need attention |
| `AUDIT_PENDING_DAYS` | `7` | control check LG-04 (NIST AC-2): a registration waiting longer than this needs attention |
| `AUDIT_WORK_HOURS` | `07-19` | working hours in UTC: sign-ins outside them are counted on the dashboard |
| `AUDIT_FAIL_ALERT` | `10` | control check LG-06 (NIST AC-7): this many failed sign-ins from one address in one day, or any lockout, looks like password guessing. Fewer are treated as typing mistakes |
| `AUDIT_REVIEW_DAYS` | `30` | control check LG-13 (NIST AU-6): the log should be reviewed (integrity check or evidence export) at least this often |

## Advanced

| Setting | Default | Meaning |
|---|---|---|
| `REF_SECRET` | random at each start | secret for the short host references shown instead of addresses when masked. Set a long random value (`openssl rand -hex 32`) to keep references the same across restarts |
| `DAY_RELOAD_SECONDS` | `600` | how often the replay day is reloaded from MongoDB |
| `MGMT_PAST_RECORDS` | `3000000` | records of past days the Executive portal keeps in memory for its 7-day baselines (roughly 200 to 300 MB per million); above it, older days are loaded from MongoDB when needed |
| `REGISTRY_REFRESH_SECONDS` | `3600` | how often the list of reports is fully re-checked (new reports are found within 15 s anyway) |
| `FALLBACK_SCAN` | `0` | `1` loads reports without a `filename` index with a slower scan. Better: create the index ([OPERATIONS.md](OPERATIONS.md)) |
| `LG_PORT` | `5000` | the port the service listens on. Set by the installer or `deploy/install.sh --port`; the checks read it |
| `PORT` | `5000` | port for `python app.py` (development only) |

## Files in `data/`

Created and kept by the service; private to its user and never committed:

| File | Holds |
|---|---|
| `users.json`, `roles.json` | accounts (scrypt password hashes, authenticator keys, recovery code hashes), roles and permissions |
| `sessions.json`, `automation.key` | signed-in sessions (only hashes of the cookies), the key the local check scripts use |
| `audit.log`, `audit.head`, `audit_archive/` | sign-ins, account and settings changes, exports, findings and advisories; each entry chained to the one before by its SHA-256 (tamper evident). Archived at `AUDIT_ROTATE_MB`, kept for `AUDIT_RETENTION_DAYS`; `audit.head` holds the newest link and the number of entries |
| `settings.json`, `schedule.json` | Settings page values, replay schedule |
| `geocache.json`, `malpedia_cache.json` | look-up caches |
| `asns.json` | network names for AS numbers (built by `manage/asn_registry.py`, editable on the Definitions page) |
| `definitions.json` | definitions written on this site (take precedence over the shipped ones) |
| `notes.json` | researchers' notes on names, with author, date and combination codes |
| `combo_codes.json` | what each combination code shown to a researcher stands for (no address; the twenty thousand most recent are kept) |
| `acodes/` | the exact record IDs behind each analyst code (one owner-only file per code) |
| `findings.json` | findings: notes tracked from the first look to the advisory, with their status history |
| `seen_names.json` (+ `.done`) | where and when each name was last seen (30 days) |
| `tls/` | HTTPS certificate and key (`deploy/make_tls_cert.sh`) |

Shipped with the code (curated reference data, replaced by updates): `infections.json` (what each infection is and
what to do about it, with evidence), `issues.json` (the services issues that are not CVEs) and `service_reports.json`
(plain-language definitions of every Shadowserver report).
