# Configuration

Looking Glass is configured in two places:

- **`.env`** in the platform folder: the database, tokens, security and advanced settings. It is created from
  `.env.example` by `deploy/install.sh`, must stay private (mode 600, never committed) and is read when the service
  starts: run `deploy/reload.sh` after changing it.
- **The Settings page** (administrators): the country and the constituency. It is stored in `data/settings.json`
  and applies at once, without a restart. `COUNTRY`, `CONSTITUENT_ASNS` and `CONSTITUENT_CIDRS` in `.env` are only
  the starting values until Settings is saved.
- **Settings → Configuration** (administrators): every setting below in plain words, with the value in use, where it
  comes from (`.env`, this page or the default) and its default. The **tuning** settings (replay, loading and
  counting, memory and speed, findings, alerts: marked *page* below) can be changed there within a safe range. They are
  kept in `data/config.json`, take precedence over `.env`, and apply after a restart: **Restart now** on that tab
  (about a minute while the days are loaded again), or `deploy/reload.sh`. Changing them needs a recent sign-in, and
  every change and restart is in the audit log. The **security**, **audit** and **database** settings are shown only,
  with the exact `.env` line to change on the server, so a stolen administrator session cannot weaken them.
  Passwords and tokens are never shown, only whether one is set. To undo a value kept on the page, use **Use the
  default** there, or delete `data/config.json` and restart.

The database pipeline has its own `.env` in `../database` ([../../database/README.md](../database/README.md)).

## Database

| Setting | Default | Meaning |
|---|---|---|
| `MONGO_HOST`, `MONGO_PORT` | `127.0.0.1`, `27017` | where MongoDB runs: this computer, or an internal server of your network. A public address (or a name that resolves to one) is refused; the platform and the pipeline do not start |
| `MONGO_TLS` | `0` | `1`: TLS to the database. Needed for MongoDB on another server; its certificate and name are always checked |
| `MONGO_TLS_CA_FILE` | empty | the CA certificate (PEM) that signed the database's certificate; empty = the system's trusted CAs |
| `MONGO_TLS_CERT_KEY_FILE` | empty | a client certificate and key (one PEM file), when the database asks for one |
| `MONGO_ALLOW_PLAINTEXT` | `0` | `1`: allow an internal MongoDB on another server without TLS, only on a link you trust. Never allows a public address |
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
| `MALPEDIA_TOKEN` | empty | optional Malpedia API token: Malpedia then joins the sources behind the **Look up** buttons (the researchers' definitions, MISP Galaxy and MITRE ATT&CK answer without it). Stays on the server; answers are cached for a week |
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
| `COUNTRY` | `GH` | the country your CSIRT covers: ISO 3166-1 two-letter code of any country or territory in the world (`GH`, `KE`, `NG`, `BR`, `DE`, `IN`, `JM`...). Sets the regions map and labels of the services platform; a country without first-level regions in the open map data is drawn as one area |
| `TIMEZONE` | the country's usual zone | the time zone times are also shown in (IANA name, one of the country's own or `UTC`: `Africa/Nairobi`, `Africa/Lagos`, `Africa/Kinshasa` or `Africa/Lubumbashi` for DR Congo, `America/Sao_Paulo`, `Europe/Berlin`...). Display only: days and stored times stay UTC, as Shadowserver's. Settings > Country changes it and takes precedence |
| `CONSTITUENT_ASNS` | empty | AS numbers your CSIRT is responsible for, comma separated. Empty = the whole country |
| `CONSTITUENT_CIDRS` | empty | address ranges you are responsible for (for example a government network without its own AS number) |
| `SETTINGS_TOKEN` | (removed) | no longer used: it never let a script in without a signed-in session. Settings are changed by an account with the Settings permission; an old line in `.env` does nothing and can be deleted |

## Access and security

| Setting | Default | Meaning |
|---|---|---|
| `ACCESS_MODE` | `local` | who can reach the sign-in page: `local` (this computer), `private` (plus `VIEWER_NETWORKS`), `public` (anyone) |
| `VIEWER_NETWORKS` | empty | addresses and ranges allowed in `private` mode, comma separated (`10.20.0.0/24, 192.168.1.40`). `internal` = every private range (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, fc00::/7): any computer on the internal network, never the internet. `any` or `*` = public. Never `0.0.0.0` (that is one address no computer has: nobody gets in) |
| `ALLOWED_HOSTS` | empty | extra host names people type to reach it (the computer's own names and addresses are always allowed). `*` = any |
| `MFA_REQUIRED` | `1` | authenticator code at every sign-in. `0` only in a closed lab |
| `REGISTRATION` | `1` | **Create an account** on the sign-in page (accounts wait for an administrator's approval; the administrators are told in the bell). `0` = only people an administrator invites (Admin → Users → Add a person). The first administrator always signs up with the setup code, whatever this says |
| `INVITE_HOURS` | `72` | how long a sign-up link from Add a person works (1 to 720 hours); it works once either way |
| `SESSION_IDLE_MINUTES` | `60` | a normal session ends after this many minutes without use |
| `SESSION_MAX_HOURS` | `12` | and after this many hours in any case. "Stay signed in" sessions last up to 5 days (fixed) |
| `TRUST_PROXY` | `0` | `1` when a reverse proxy on the same computer does HTTPS (Caddy, nginx): the client address and https come from its headers. The proxy must send `X-Forwarded-For`; direct requests without it are refused (except `/healthz`) |
| `ALLOW_INSECURE_REMOTE_LOGIN` | `0` | `1` lets other computers sign in over plain HTTP. Only in a closed lab: passwords cross the network readable |
| `PUBLIC_DEMO` | `0` | `1` masks everything for everyone (public screens): no IP addresses, network names or host names |
| `CSP_REPORT_ONLY` | `0` | diagnostics: `1` makes the browser report, not block, what the Content-Security-Policy forbids |

What each protection does: [../docs/SECURITY.md](SECURITY.md).

## The database pipeline from the platform

Settings → Workers shows the pipeline's settings and the Audit portal's Sender check reads its results; both find the
pipeline beside the platform (`../database` or `../shadowserver`) and only read it. A change made in Settings → Workers
is a request in the platform's own `data/pipeline_requests/`; the pipeline checks it again and applies it to its own
`.env` at the start of its next run. The pipeline finds the platform beside it (`../platform` or `../threatmap`), or
by `PLATFORM_DIR` in the pipeline's `.env`.

| Setting | Default | Meaning |
|---|---|---|
| `PIPELINE_DIR` | empty | the pipeline's folder, when it is not beside the platform. On another computer: leave empty, its settings stay in its own `.env` |
| `SHADOWSERVER_API_URL` | `https://transform.shadowserver.org/api2/` | Shadowserver's report API, used to check an API key before it is saved. Must start with `https://`; a redirect away from https is refused |

The pipeline's sender check is set in the pipeline's `.env` (or Settings → Workers): `MAIL_AUTH` = `log` (record each
report e-mail's DKIM result, hold nothing back), `enforce` (hold back reports that do not pass until an administrator
releases them) or `off`; `MAIL_AUTH_DOMAIN` = the expected signer (`shadowserver.org`).

The check looks up the signer's public key in DNS (a TXT record, for example `mail._domainkey.shadowserver.org`). It
asks this server's own resolver first. Some networks drop DNS TXT look-ups (a rule against DNS tunnelling); when the
resolver does not answer, the key is asked over HTTPS (DNS over HTTPS) from `MAIL_AUTH_DNS_SERVERS`: IP addresses, in
order, default `1.1.1.1,1.0.0.1,8.8.8.8,8.8.4.4` (Cloudflare and Google), with their certificates checked. Only the
key's name is sent, nothing about the reports. `none` switches the HTTPS look-up off. A key that does not exist is
never asked again elsewhere.

**Recommended for production: `enforce`** (Block), or the report API instead of e-mail. Start with `log` for a week:
**Settings → Workers → Sender check, last 7 days** counts, day by day, the report e-mails that passed and those that did
not, with what each failure usually means. When every e-mail has passed on each of the 7 days (no footer, gateway or
forwarding rule breaks the signatures on the way), the card and the bell say blocking can be switched on, and the card's
button ticks it for you. With `log`, a forged report e-mail would be loaded
and only flagged. `REPORT_SOURCE=api` (Shadowserver's report API) does not use e-mail at all, so the question does not
arise; the e-mail path stays as a fallback.

## Executive portal: 7-day baseline

The Executive page compares each figure with the 7 days before; a selection seen for the first time builds that
baseline in the background.

| Setting | Default | Meaning |
|---|---|---|
| `EXEC_BASELINE_WORKERS` | `2` | baselines built at the same time (each reads up to 7 days of data) |
| `EXEC_BASELINE_QUEUE` | `20` | baselines waiting their turn beyond those; when the list is full the page shows "building" and asks again on its next refresh |

The Overview's spike notice compares the latest report day with the day before (counts only, from MongoDB).

| Setting | Default | Meaning |
|---|---|---|
| `SPIKE_RATIO` | `1.5` | a day is a spike at this many times the day before or more (a drop: the day before is this many times the day) |
| `SPIKE_MIN_EVENTS` | `500` | and the difference is at least this many records, so a small report doubling is not a spike |
| `SPIKE_CACHE_SECONDS` | `600` | how long the comparison is kept before it is counted again |

## Audit portal and the audit log

Set these to what your own audits and laws require; the defaults suit a yearly IT audit.

| Setting | Default | Meaning |
|---|---|---|
| `AUDIT_RETENTION_DAYS` | `400` | days archived audit entries are kept (compressed, `data/audit_archive/`) before they are deleted. The last link of each deleted archive is noted, so the integrity check still covers what is left |
| `AUDIT_GAP_DAYS` | `30` | a removed archive followed by this many days without any entry is reported for the auditor (an archive removed and its note's dates faked to look old leaves such a jump; real use writes more often) |
| `AUDIT_ROTATE_MB` | `5` | size at which `data/audit.log` is archived and a new file started; the tamper-evident chain goes on across files |
| `AUDIT_CHECKPOINT_HOURS` | `24` | how often a signed checkpoint of the log's head is written to `data/audit_checkpoints/` (`0` = never). See [OPERATIONS.md](OPERATIONS.md#audit-checkpoints) |
| `AUDIT_CHECKPOINT_COPY_DIR` | empty | a folder on another computer, mounted here, that gets a copy of every checkpoint (never replacing a file there). Empty: no copy; fetch `data/audit_checkpoints/` from another computer instead |
| `AUDIT_DORMANT_DAYS` | `45` | control check LG-02 (NIST AC-2(3)): an active account unused this long is listed as dormant. 45 is CIS's figure (safeguard 5.3); above it, 5.3 shows as "related", not backed |
| `AUDIT_MAX_ADMINS` | `3` | control check LG-03 (NIST AC-6(5)): the administrator limit the check names |
| `AUDIT_PENDING_DAYS` | `7` | control check LG-04 (NIST AC-2): registrations waiting longer than this are listed |
| `AUDIT_WORK_HOURS` | `07-19` | working hours in UTC: sign-ins outside them are counted on the dashboard |
| `AUDIT_FAIL_ALERT` | `10` | control check LG-06 (NIST AC-7): the evidence says whether this many failed sign-ins from one address in one day was reached |
| `FINDING_ACT_DAYS` | `30` | days after a finding's devices were last seen before a finding nobody is acting on closes on its own ("Time to act expired"); never one approved, with the advisor or with an advisory not yet sent; `0` never closes one |
| `FINDING_GRACE_DAYS` | `7` | a finding is never closed this way sooner than this many days after it was opened (a review of older records) |
| `DATA_ACCESS_LOG` | `1` | `0` stops logging views of host-level data (one host's activity, host lists, record details, analyses) in the audit log; exports are always logged. Off, CIS safeguard 3.14 shows as "related", not backed |
| `COPY_SEAL_KEY` | empty | the secret key that seals every copy and download (keyed fingerprints, for Trace a leak). Empty: Looking Glass makes one at the first start in `data/copy_seal.key` (owner-only) and uses it. Keep the key with your backups: seals made with a lost key can no longer be traced. Never shown anywhere |
| `AUDIT_REVIEW_DAYS` | `7` | control check LG-13 (NIST AU-6): the review interval the check names (integrity check or evidence export). 7 is CIS's figure (weekly, safeguard 8.11); above it, 8.11 shows as "related", not backed |

The control checks give evidence, not a pass or fail: the conclusion is the auditor's.

## Advanced

| Setting | Default | Meaning |
|---|---|---|
| `REF_SECRET` | random at each start | secret for the short host references shown instead of addresses when masked. Set a long random value (`openssl rand -hex 32`) to keep references the same across restarts |
| `DAY_RELOAD_SECONDS` | `600` | how often a loaded day is checked against MongoDB; it is kept, with every answer worked out from it, while the database holds the same rows |
| `DAY_MAX_AGE_SECONDS` | `3600` | a loaded day is read again in full at least this often, even with the same rows |
| `SETTLE_MAX_SECONDS` | `120` | new rows are loaded once their counts stop changing (two checks in a row), or at least this often while a pipeline run keeps adding them; only the reports that changed are read again |
| `COUNT_EVERY_SECONDS` | `600` | with the pipeline's marks (`lg_load_stamps`), the 15-second check counts every report's rows only when a mark moved, or at least this often |
| `MGMT_PAST_RECORDS` | `3000000` | records of past days the Executive portal keeps in memory for its 7-day baselines (roughly 200 to 300 MB per million); above it, older days are loaded from MongoDB when needed |
| `REGISTRY_REFRESH_SECONDS` | `3600` | how often the list of reports is fully re-checked (new reports are found within 15 s anyway) |
| `HEAVY_PER_USER` | `3` | heavy views (statistics, map, analysis, drill-down lists, regions, reports) one person may have worked on at once; more wait their turn. `0`: no limit |
| `HEAVY_PER_MINUTE` | `240` | heavy views one person may ask for in a minute; more get 429 with Retry-After. `0`: no limit |
| `HEAVY_WAIT_S` | `20` | how long a heavy view waits for its turn before 429 |
| `ANALYST_DAY_KEEP` | `1` | older days (not among the days in memory) kept for analyst codes, so a code's page, its records and its device counts share one load from the database instead of loading the day again each time. Each kept day costs about as much memory as a day in memory; `0` keeps none (every request loads the day again). A kept day is dropped as soon as the constituency or the stored data change, and a code spanning many days is still read one day at a time |
| `ANALYST_DAY_KEEP_S` | `300` | seconds such a day is kept (30 to 3600) |
| `NAME_LEVELS_DELAY_S` | `120` | seconds after a start before every report's records are read once (only their infection, issues, tags and severity, in batches with pauses) to learn each name's criticality for the PDFs' References section and every name for the severity map; it runs once per installation (`data/name_levels.done` marks it done), the day loads keep it current after that; `0` = never |
| `ANALYST_WARM_DELAY_S` | `30` | seconds after a start before the device counts of every open finding's analyst code are worked out in the background (both viewer levels, kept apart), so the Findings page does not wait for them; `0` = never ahead |
| `BEACON_KEEP_MAX` | `200000` | decoded beacon answers (format, operator, version, OS family only) kept in `data/beacon_summaries.json` so a restart does not decode the day's request lines again; about 170 bytes each in memory. Raise it for a country with many check-ins a day |
| `SLOW_REQUEST_S` | `2` | a request taking longer than this many seconds is listed in Settings → Task monitor |

Every setting in this table except `REF_SECRET`, `HSTS_*`, `BACKUP_PUBLIC_KEY` and `FALLBACK_SCAN`, and also
`REPLAY_OFFSET_HOURS`, `REPORT_SETTLE_SECONDS`, `MAX_EVENTS_PER_POLL`, `EXEC_BASELINE_*`, `SPIKE_*`, `FINDING_*` and
`PIPELINE_STALE_HOURS`, can be changed on **Settings → Configuration** too (the page allows at least 1 for the
`HEAVY_*` limits: "no limit" is set in `.env` only).
| `HSTS_MAX_AGE` | `31536000` | Strict-Transport-Security on answers over HTTPS, in seconds (`0` tells browsers to forget it); `HSTS_INCLUDE_SUBDOMAINS=1`, `HSTS_PRELOAD=1` only when every name under the domain is on HTTPS for good |
| `BACKUP_PUBLIC_KEY` | `data/backup_public_key` | the public key backups are encrypted to (an age recipient or a GnuPG public key; [OPERATIONS.md](OPERATIONS.md#backups)) |
| `FALLBACK_SCAN` | `0` | `1` loads reports without a `filename` index by `extracted_date`, which has no index: **every row of the report is read** for each day. Leave it off; create the `filename` index instead ([OPERATIONS.md](OPERATIONS.md)) |

**Memory.** Up to four days are held per platform (the day before, the replay day, the next, and the target). A full
reload builds the new copy beside the old one, so memory briefly rises by about one day's size; reloading only the
reports that changed keeps that small. Roughly 1 GB of web-service memory per million records held, plus the Executive
portal's past records above.
| `LG_PORT` | `5000` | the port the service listens on. Set by the installer or `deploy/install.sh --port`; the checks read it |
| `PORT` | `5000` | port for `python app.py` (development only) |

## Files in `data/`

Created and kept by the service; private to its user and never committed:

| File | Holds |
|---|---|
| `users.json`, `roles.json` | accounts (scrypt password hashes, authenticator keys, recovery code hashes), roles and permissions |
| `sessions.json`, `automation.key` | signed-in sessions (only hashes of the cookies), the key the local check scripts use |
| `login_counters.json` | failed sign-ins per address and account (the sign-in locks), kept across restarts; only failures within the longest lock window |
| `region_matches.json` | the administrator's region matches (Settings → Country) |
| `backup_public_key` | the public key backups are encrypted to (you put it there; [OPERATIONS.md](OPERATIONS.md#backups)) |
| `audit.log`, `audit.head`, `audit_archive/` | sign-ins, account and settings changes, exports, findings and advisories; each entry chained to the one before by its SHA-256 (tamper evident). Archived at `AUDIT_ROTATE_MB`, kept for `AUDIT_RETENTION_DAYS`; `audit.head` holds the newest link and the number of entries |
| `copy_seals.jsonl`, `copy_seal.key` | the seals of every copy made with a copy button and every file downloaded: who, when, what, and keyed fingerprints (never the text or an address); the key that makes them (when `COPY_SEAL_KEY` is not set). Owner-only; seals older than `AUDIT_RETENTION_DAYS` are removed |
| `name_kinds.json`, `name_ratings.json` | every name the reports carried with its kind, and the researchers' ratings of names no record rates (the severity map; names only) |
| `invites.json` | the open and recent sign-up links (Add a person): role, who made it, when; only each link's SHA-256, never a working link. Owner-only |
| `signin_look.json` | which logo the sign-in pages show: the organisation's (default), Looking Glass's or none; who chose it and when |
| `settings.json`, `schedule.json` | Settings page values, replay schedule |
| `config.json` | the tuning values kept on Settings → Configuration (they take precedence over `.env`; delete it and restart to go back to `.env`) |
| `beacon_summaries.json` | the beacon decoder's public answers kept across restarts (hashes of the request lines, never the lines; safe to delete) |
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
