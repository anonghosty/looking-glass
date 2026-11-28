# Looking Glass: technical reference

![Looking Glass](../platform/static/img/logo.svg)

How the platform works inside: data sources, replay schedule, both platforms, masking, the API and every script.
Installing: [INSTALLATION.md](INSTALLATION.md). Using it: [USER_GUIDE.md](USER_GUIDE.md). Settings:
[CONFIGURATION.md](CONFIGURATION.md). Day-to-day running: [OPERATIONS.md](OPERATIONS.md).
Figures, names and numbers in the examples below are invented illustrations.

**Looking Glass** is a live threat map built with Flask, Mapbox GL and deck.gl. It replays Shadowserver events from MongoDB with a 24-hour delay, so yesterday's events play out at the same time of day today.

It integrates **every Shadowserver collection that describes a source-to-destination communication**, discovered automatically. Each event carries its collection as its **source report**, plus an **attack type**.

## Data sources

At startup, and every 6 hours after that, `sources.py` scans the database. A collection qualifies when:
- its latest documents have field names containing `src` or `dst` (or the referer source fields);
- it has a `filename` index;
- it is not listed in `EXCLUDE_COLLECTIONS`.

Four layouts are normalized into one schema:

| Layout | Collections | Source → destination |
|---|---|---|
| standard | `event4_*`, `event6_*`, `microsoft_sinkhole_http` | `src_*` → `dst_*` |
| legacy | `darknet`, `ddos_amplification`, `hp_http_scan`, `hp_ics_scan`, `microsoft_sinkhole`, `sinkhole_http_drone` (2018–2021 reports) | `ip`/`geo`/`asn`/`city` → `dst_*` |
| referer | `event4_sinkhole_http_referer` | `http_referer_*` → `dst_*` |
| inbound | `spam_url` | `src_*` (spam sender) → `ip`/`geo` (local host) |

Attack types come from the collection name: Botnet C2 (sinkholes), Brute force, Scanning (honeypots and darknet), DDoS, Initial access, IP spoofing and Spam. Any field outside the common schema is kept per event as `extras` and shown in the detail view under "… specific fields" (for example brute-force usernames and passwords, the SSH client version, DNS queries, DDoS attack type and duration, raw honeypot requests).

Which collections have rows depends on the day and the country. Typically the sinkhole reports (`event4_sinkhole`,
`event4_sinkhole_http`, `event4_sinkhole_dns`) carry most of a day's events, the honeypot reports far fewer.
`outdated_dnssec_key` is excluded by default: it reports a misconfiguration, not an attack. `GET /api/sources` lists the live registry with today's row counts; `tools/discover.py` repeats the full survey of all collections.

## Infection knowledge base

`data/infections.json` holds one entry per infection name, as Shadowserver writes it, in lower case. Each entry has:
- `title` and `type`
- `description`: what it is
- `action`: the recommended response
- `confidence`: `high`, `medium` or `low`
- `status`: `reviewed` or `needs-review`
- `aliases`
- `updated`: the date of the last change
- `references`: the evidence (web links); `malpedia`: the Malpedia family id when Malpedia has it (its page is then the
  first reference)
- `curated_by`: who wrote it. Entries shipped with Looking Glass are signed `Looking Glass`; entries written on a site
  record the account's username, shown as the person's registered full name (`people.py`)

Every shipped entry carries evidence: a Malpedia family, or references to the Shadowserver report documentation and
vendor or CERT research. `data/issues.json` does the same for the services issues that are not CVEs.

**Shipped and site definitions never conflict.** `data/infections.json` and `data/issues.json` belong to Looking Glass
and are replaced by updates (`git pull`). What researchers write on a site goes to `data/definitions.json`, which is
not in the repository (`.gitignore` excludes `data/*` except the shipped files) and takes precedence over the shipped
entry of the same name. A site's own definitions and notes are therefore never overwritten and never block an update.

The detail and analysis views show the description and recommended action. Entries with low confidence or `needs-review` status are marked **Unverified**; infections with no entry say so. The server reloads the file whenever it changes and open pages fetch it again every 10 minutes: no restart is needed.

**Keeping it complete:**

```bash
.venv/bin/python manage/infections_missing.py 7      # check the last 7 days
```

This lists every infection seen in those days without an entry, plus entries still marked `needs-review`, with counts, reports, tags, families and sample C2 domains, and writes `data/infections_missing.json` with empty stub entries. Write the new entries (description, recommended action, confidence), then merge them into `data/infections.json`. While the service runs, `GET /api/infections/missing` gives the same check for the current replay day.

The base covers the infections and categories Shadowserver's event reports commonly use, including the honeypot, DDoS and access categories. Names with little public detail say so and carry `confidence: low` (for example `wd`, a family that looks up generated domains and is not publicly identified). Names seen only in the Sinkhole DNS report explain that the address is usually a DNS resolver, with the infected client behind it.

## Researchers: intel, notes and where a name was seen

The Definitions page (`/definitions`, permissions *definitions* / *networks*, admins too) is the researchers' page.
What each part shows and how it is used: [USER_GUIDE.md, Analysis and follow-up](USER_GUIDE.md#5-analysis-and-follow-up).
Its server side is in small modules called from `app.py`:

- **`intel.py`, Intel gathered.** Over the report day (`report_day.py`: the replayed day, else the newest in memory;
  the Executive portal passes its day; code look-ups and the combination search use every day in memory), per name and
  report: the records' indicators, and per value and **combination** (one record's exact tags and CVEs; for
  communications also C2 domain and user agent) records, share, hosts and repeating hosts. **Leads:** one indicator
  under two names, in two reports of one name, or an infection's domain that is a certificate name on a services host.
  Never returns a source address, host name or constituent address. `GET /api/intel?section=infections|issues&name=…`,
  `GET /api/intel/leads`, `GET /api/intel/summary` (the *Seen in* cards). Cached five minutes per set of days; with
  `services_intel.py`'s patterns, counted behind the page (`index_refresh.Gate`): stale counts are served while one
  thread counts again.
- **`intel_match.py`, Explore a match.** `GET /api/intel/match?kind=…&value=…` (Definitions permission), only for a
  match in the leads: per name and report, what `/api/intel` gives for only the records with the indicator, with the
  same masking, 5-device rule and codes. Devices are counted, never returned. Kept per set of days up to an hour;
  per-person limits.
- **`beacon_decode.py`, decoded beacons** (what analysts see:
  [USER_GUIDE.md](USER_GUIDE.md#3-reported-network-communications-the-map)). Pure functions (no network, no files)
  that decode encoded C2 check-ins in a record's `http_url`; cached by request line (4,096). A request line over
  16,384 characters or a query value over 8,192 is not looked at, values under 40 characters are not candidates, at
  most 4 values per line, and 0.25 s per line for all formats together. Formats are registered
  in `FORMATS`. The **CLogin check-in** (`clogin`, `GET /CLogin?key=…`): Base64 → repeating XOR with a 32-character
  hex key, new per check-in and recovered from the beacon → the JSON's Base64 text plus a trailer (46–52 hex
  characters, each XORed with 0x72). Every decode passes `recheck`; `instruction_like` adds `INJECTION_NOTE` to text
  that reads like instructions. Named, not decoded (`OPAQUE`, by C2 host, path and parameter): ttyunos and
  weatherlive (block cipher), adoverocean (hash), pixellog (device ID), clickby (campaign token), sustat (short binary
  values). `generic()` tries up to 3 layers of hex, Base64, zlib / gzip / deflate and one-byte XOR; `unknown()` lists
  the rest with `shape()`, never the value. States (`STATUS`): decoded, encrypted, hash, id, token, unknown, cut.
  `POST /api/beacon/decode` (`{url, name}` in the body; CSRF, *unmasked* permission, demo off) feeds the map's
  *Decoded beacon* block (`static/js/beacon.js`). `mask_url()` hides encoded values in masked views
  (`privacy.mask_event`) and Intel gathered. Researchers get only *Beacon format*, *Beacon operator*, *Beacon
  version* and *Beacon OS* (`public()`), each from 5 devices (`intel.held()`), and the lead *Beacon vs name*; never
  MAC, hardware UUID (`spare1`), `cpuid`, `cpumd5`, `mem` or the key. Tests: `tests/check_beacon_decode.py`,
  `tests/verify_beacon_decode.py` (the latest day, counts only).
- **`config_page.py`, Settings → Configuration.** Catalogue: `TUNING` (editable), `READ_ONLY` (shown with the `.env`
  line), `SECRETS` (only whether set). Values in `data/config.json` (mode 600); `load()` keeps only valid tuning
  values. `apply()` runs in `gunicorn.conf.py` before the app loads: `.env` first, then the kept values, which win.
  `GET/POST /api/admin/config`, `POST /api/admin/config/restart` (SIGTERM to the gunicorn master, which systemd
  restarts; one a minute). Settings permission, CSRF, a recent sign-in; audited `config_changed`,
  `service_restarted`. Test: `tests/check_config_page.py`.
- **`beacon_keep.py`, decoded answers kept across restarts.** Each request line's `beacon_decode.public` summary in
  `data/beacon_summaries.json` (mode 600), keyed by SHA-256 of request line and host, which are never written; ignored
  by a different `beacon_decode.py`. At most 200,000 answers (`BEACON_KEEP_MAX`), written at most once a minute and at
  exit. Deleting it is safe. Test: `tests/check_beacon_keep.py`.
- **`recent_days.py`, older days kept for analyst codes.** `app._day_for` gives an analyst code its day: the copy in
  memory, or a day loaded from MongoDB and kept by `RecentDays` for `ANALYST_DAY_KEEP_S` seconds, at most
  `ANALYST_DAY_KEEP` days (default 1; 0 keeps none), valid only for the constituency settings version and store
  generation it was loaded at. A many-day code is read a day at a time. Test: `tests/check_recent_days.py`.
- **`pdf_refs.py`, the PDFs' References section.** Orders every PDF's references: explained names by criticality (a
  CVE's CVSS severity, actively exploited first; an infection's or issue's highest record severity), then Shadowserver
  reports by Shadowserver's severity. Levels come from the PDF's records, the days in memory (`DAYS`) and
  `data/name_levels.json`. `reports_pdf.py` draws its own References with the same groups.
- **`name_levels_catchup.py`, every name's level learned once.** `NAME_LEVELS_DELAY_S` seconds after a start, one
  thread reads every report collection once, in batches, and keeps each name's highest level in
  `data/name_levels.json` and every name with its kind in `data/name_kinds.json`; `data/name_levels.done` marks it done
  (an installation updated from marker version 1 reads every report once more).
- **`invites.py`, Add a person** ([USER_GUIDE.md](USER_GUIDE.md#8-administration)). `data/invites.json` (owner-only),
  keyed by the SHA-256 of a 256-bit token; expiry `INVITE_HOURS` (72); at most 50 open; finished entries dropped
  after 90 days. `GET/POST /api/admin/invites`, `POST /api/admin/invites/<id>/revoke` (permission *users*, CSRF,
  recent sign-in; audited `invite_made`, `invite_revoked`, `invite_used`). `/register?invite=` works also when
  `REGISTRATION=0`, once, and makes an **active** account with the link's role, `approved_by` its maker. Page:
  `static/js/invites-admin.js`. Test: `tests/check_accounts.py`.
- **`net_drift.py`, network changes.** Compares this computer's addresses (`hostname -I`) with the IPs of a
  self-signed `data/tls/cert.pem` (not for a CA's certificate or `ACCESS_MODE=local`) and `MONGO_BIND` in the
  pipeline's `.env`, each mismatch with its fix, for `system_alerts.py` (the bell, at most every 5 minutes; it also
  announces people waiting for approval) and `tests/check_addresses.py` (a warning).
- **The mail server's certificate not checked (`system_alerts.Alerts.mail_tls_off`).** True when the pipeline's
  `.env` has an IMAP mailbox with `IMAP_VERIFY_TLS` off, read by the pipeline's own rule (`mail_sources._truthy`; Gmail
  API and Microsoft Graph always check). The administrators' bell says so every day (key `mail-tls-off:<day>`) and
  Settings → Task monitor shows it on the Report pipeline card (`pipeline.mail_tls_off`). When the mailbox cannot be
  read, the pipeline's status carries the reason (`email_error`, from `mail_sources.MailSourceError.reason`: no account
  or password), shown in the bell and on that card. Test: `tests/check_system_alerts.py`.
- **The pipeline's run problems (`run_problems` in `shadowserver_pipeline.py`).** Returns the run's errors and
  warnings, each `{"key", "count", "text"}`. Errors (a file, rows, a report, an attachment, a link, a zip or the API
  not loaded or not usable, a report name quarantined, a file that stopped its loader process even when loaded alone
  on 2 runs (`files_crashed`, moved to `quarantine/loader/<report>/` with a `.reason.txt`; the first time it is a
  `file_errors` and tried again; the load journal counts the runs in its `crashes` table and gives a quarantined file
  a fingerprint no file has, so that moved back it is loaded again, the rows already stored skipped), the mailbox not read) make the run
  fail: `run_errors` sums their counts and the run exits with 1. Warnings (CSV files not matched, an API fallback,
  unusable API list items, unreadable timestamps, rows that cannot be read as CSV, same row hash, rows without a
  timestamp, extra columns, bytes that are not UTF-8, files loaded again, and `emails_gone`: e-mails deleted or moved
  out of the reports folder between the listing and the fetch, missing from a UID FETCH the server answered OK) do not;
  a batch the server refuses stays an error (`emails_not_fetched`). `retention.status` writes them to
  `pipeline_status.json` beside `ok` and `finished`: `errors`, `warnings`, `not_matched` (the full `count` and up to 100
  `names`), `files_loaded`, `files_reloaded` and every row count (`rows_read`, `rows_inserted`, `rows_duplicates`,
  `rows_same_in_file`, `rows_same_hash`, `rows_bad_timestamp`, `rows_bad_csv`, `rows_failed`, `rows_no_time`), where
  `rows_read` is the sum of the stored, refused and failed parts. `rows_bad_csv` counts rows the CSV reader cannot read
  (a field over `CSV_FIELD_MAX`, 16 MB, or a broken line); the rows after one are loaded. A CSV column named `_id`
  (`RESERVED_COLUMNS`) is stored as `csv_id`. A file with no row to store is noted in the load journal (its size, time
  and SHA-256) and not read again until it changes. A zip encrypted with a password is refused by `zip_limits.py` and
  quarantined.
- **The pipeline's run lock (`hold_run_lock`).** `main()` takes `.pipeline.lock` (the lock `run.sh` and
  `bin/shadowserver` take with flock) itself, so a run started by cron or by hand cannot run beside another. The lock
  file is mode 0644 and opened read-only (flock needs no write access), so the platform, another Linux user, can open
  it, and a lock file owned by root does not stop later runs; a symbolic link is refused (`O_NOFOLLOW`). A run started
  by `run.sh` uses the descriptor it inherited: `run.sh` exports `LG_RUN_LOCK_FD=9`, and `/proc/self/fd` is looked
  through only when that is missing. A second run exits 1 with "Another pipeline run is in progress".
- **Block mode with the sender check down (`SenderCheckUnavailable`).** With `MAIL_AUTH=enforce` and a sender check
  that cannot start, no e-mail is read that run: a mail-source failure with its reason in `email_error`, not a stop of
  the whole run; the files on disk load, and the report API is used when it is set up.
  `system_alerts.py` shows the errors as "The last report run had problems" and the warnings as "The last report run
  has something to check" (keyed by each warning's key and count, so a cleared alert stays cleared until they change);
  an older pipeline's status without these fields still gets the counts-based alert. Settings → Task monitor shows
  "Rows read", "What went wrong" and "To check". A file already loaded is loaded again when its size or time changed
  and its content hash differs (`changed_since_load`, fingerprints in the load journal). Test:
  `tests/check_pipeline_problems_shown.py`.
- **`shares.py` and `LGShare`, shares in words.** One rule for every share on every page, PDF and CSV, the same in
  Python (`shares.py`) and in the browser (`window.LGShare` in `static/js/loader.js`). `pct(x, d=0)` takes a fraction,
  `of(part, total, d=0)` a count of a total (a total of 0 reads "0%"): a part that has records never reads "0%" but
  "<1%" (with `d=1`, "<0.1%"), a part of the whole never reads "100%" but ">99%" (">99.9%"). Both round half up
  (`of` exactly, in integers), so a page and its PDF give the same text. `part(n, total)` is the combinations' share
  of devices (one decimal under 10%, whole percents from 10%), used by both the combination pages and their PDF.
  `cut(shown, total, noun)` gives "Top 8 of 23
  networks" when a list is cut and "" when every row is shown; `other(rows, total)` is what the rows leave out of the
  total (an Other part), never below 0. Test: `tests/check_share_words.py`.
- **`api_errors.py`, refusals under `/api/` in words.** Any 4xx answer under `/api/` is JSON `{"error": ...}`: the
  message the route gave (`abort(403, "...")`) when it gave one, otherwise a plain sentence per status (403 "Your
  account does not have access to this.", 404 "Not found.", and so on). Pages keep their HTML answers. Test:
  `tests/check_every_route.py` calls every route as every role with bad input and fails on any server error,
  traceback, slow answer or HTML refusal under `/api/`.
- **`counting_keys.py`, one counting rule.** Every page, PDF and CSV buckets records with it (both platforms, the
  Executive portal, the quarterly report, combinations, Abused or Compromised and the masking in `privacy.py`).
  `sector_of(asn, reg_all, labels)` is the network type of the record's AS number in `data/asns.json` by its label, or
  Unknown (`Sectors` keeps it per AS number; `sector_now` for one record at a time); `industry_of` is Shadowserver's
  own `sector` column, shown as "Industry (Shadowserver)". `network_of(asn, registry, masked)` is the company (or its
  alias), "" for no network (none, 0, AS0), shown as "Unknown network" by `network_label` and counted apart.
  `norm_asn` writes "AS064500" as "64500"; `fold` is the grouping form of a name (trimmed, inner spaces collapsed,
  case-folded). `region_key(value, country)` is the region as every page spells it: the administrator's region matches,
  then the country's map, the country's own name as "Unknown region", else the value in title case.
  `row_key(collection, filename, line_hash)` is one row however many files of the same report day carry it (`Dedup`
  keeps the first copy and counts the others); `window(ed, start, end)` says whether a row is in the day, outside it or
  undated, and `load_note` is the sentence a page shows about them. `configure(...)` is called once by `app.py`.
- **`totals` beside capped lists.** An answer that sends only the top rows of a list also sends `totals`: for each
  list, how many values it has in all (on the map's statistics also `others`, the events outside the rows). The pages,
  PDFs and CSVs use it for "Top N of M" and for the Other part; a list that is not cut needs no `totals`.
- **`neutral.py`, what a signed-out visitor learns (anti-fingerprinting).** Standard status phrases, plain error and
  redirect bodies, hashed static ETags and, signed out, a short Content-Security-Policy. `/healthz` answers loopback
  only; `security.py` sends no `Server` header. `auth.PUBLIC_STATIC` lists the only files served signed out. The
  sign-in pages (`auth_base.html`, `login.html`, `forgot.html`) show the organisation's name only. After sign-in,
  `auth.start_session` redirects to `/welcome?next=…` (`signin_welcome.py`), then `next` (`auth._safe_next`).
  `deploy/make_tls_cert.sh` names the certificate after the first name given or the machine. Test:
  `tests/check_fingerprint.py`.
- **`insider.py`, copies recorded, seals and Trace a leak** ([USER_GUIDE.md](USER_GUIDE.md#the-audit-portal-audit)).
  `POST /api/copy/record` (CSRF, at most `COPY_PER_MINUTE` (30) a minute per person) seals the text (HMAC-SHA-256 with
  `COPY_SEAL_KEY` or `data/copy_seal.key`: the whole text, each line, each IP address) into `data/copy_seals.jsonl`
  (owner-only), then audits `copied`; a seal that cannot be written answers 503 and nothing is audited, and
  `static/js/lg-copy.js` copies only after a 200. Every download is sealed too (people only), after a CSV (or each CSV inside a ZIP) gets two columns on every row, `Downloaded by` (`stamp_who`: the full name and `person_code.code`, never the sign-in name; the quarterly CSVs name the person the same way) and `Downloaded at` (UTC) (`stamp_csv`, `stamp_zip`: read with `csv.reader`, written back through `csvsafe`, every other cell unchanged, every row as wide as the header; files stamped already and text that is not UTF-8 are left as they are; the seal's line fingerprints are taken without the two columns, `_unstamp`, so a copy with them deleted is still the exact file), and a list asked for with `download=1` gets `download_stamp` (`columns`, `cells`), which the page adds to every row. `POST /api/audit/trace` (permission *audit*, CSRF, 5 a minute and `TRACE_PER_DAY` (100) a day per
  person; text or a file) returns matching seals: exact, else, up to `TRACE_MAX_ITEMS` (1,000) items, seals holding
  at least `TRACE_MIN_SHARE` (half) of the lines or addresses; items held by more than 20 % of the people with seals
  are not counted, so one person's repeated copies cannot hide rows. Audited `leak_traced` (match count only). These
  two routes take bodies up to 12 MB and 26 MB; every other route keeps the 64 KB of `security.py`. Seals older
  than `AUDIT_RETENTION_DAYS` are removed. Also the template value `lg_name` (full name, `people.py`). Test:
  `tests/check_insider.py`.
- **`severity_map.py`, the severity map.** `GET /api/kb/severity-map`, `POST /api/kb/severity-map/rate` (`{name,
  level}`; level `""` takes a rating back; CSRF; audited `severity_rated`), *definitions* permission (researchers and
  administrators). Joins Shadowserver's levels (`pdf_refs.all_levels()`), every name (`pdf_refs.all_kinds()`) and the
  researchers' ratings (`data/name_ratings.json`); CVEs left out; a name Shadowserver rates is refused (409). PDFs use
  a researcher's level (`pdf_refs.researcher_level()`, flagged "Researcher/TI rating") only where no record rates the
  name. Page `static/js/severity-map.js`. Test: `tests/check_severity_map.py`.
- **`acode_warm.py`, analyst code counts after a start.** `ANALYST_WARM_DELAY_S` seconds after start, one thread works
  out the device counts (`/api/intel/acode/<code>/devices`) of every analyst code on open findings, at both viewer
  levels, into `acodes.PerKeyCache` (one lock per code). Tests: `tests/check_per_key_cache.py`,
  `tests/check_acodes.py`.
- **`beacon_findings.py`, decoded beacons handed over** ([USER_GUIDE.md](USER_GUIDE.md#findings-cases-and-who-holds-them)).
  `POST /api/beacon/finding` (`{name, format, operator, version, os_family, kind: analyst|management, to, comment,
  title}`; *definitions*, *settings* or *unmasked* permission, CSRF, a fresh sign-in) makes a finding holding the
  selection (name and threat-side parts), never a device; viewers who do not see hosts need 5 devices.
  `GET /api/beacon/finding/<id>` (the channel's people and admins) gives counts and parts; with `records=1`,
  analysts and admins only, up to 500 records (`data_access.SENSITIVE`). Page: `static/js/beacon-handover.js`.
  `GET /api/beacon/code?name=&format=&operator=&version=&os_family=` (same permissions) gives the selection's
  `LG-B-XXXXXXXX` code (code book kind `b`, no address). `attach()` also gives a beacon finding an `LG-A` selection of
  exactly its records for *Show in Executive*. Test: `tests/check_beacon_findings.py`.
- **`beacon_unknown.py`, requests Looking Glass could not decode**
  ([USER_GUIDE.md](USER_GUIDE.md#findings-cases-and-who-holds-them)). Groups `beacon_decode.unknown()` over the days in
  memory into families, each with up to 5 (infection name, request line) pairs; `request_line()` keeps only the
  undecoded value (`<value>` and `<address>` for the rest). `GET /api/beacon/unknown` (*unmasked* permission, demo
  off): the families, their state, request lines and the link to send them (`SEND_URL`: a private report on
  `anonghosty/http-requests-decoding`, never a public issue). `GET /api/beacon/unknown/<id>/request`: a JSON download
  of only the `{infection, request}` pairs (audit `data_exported`); 409 until approved.
  `POST /api/beacon/unknown/<id>/state` (CSRF; audit `beacon_family_state`), kept in `data/beacon_unknown.json` (0600):
  `asked` (analyst or admin), `approved` or `rejected` (an administrator), `sent`; waiting asks go to the
  administrators' bell. Page: `static/js/beacon-unknown.js`. Test: `tests/check_beacon_unknown.py`.
- **`features.py`, where new features install themselves.** app.py calls `features.install(app, core)` once, at the
  end, with the shared parts (`db`, `registry`, `svc`, `replay_now`, `day_start`, `AUTH`); each new feature has its
  own module and one entry there (among them `config_page.py`, `neutral.py`, `insider.py`, `severity_map.py`), so
  app.py does not grow.
- **Moved out of app.py (2026-11-24), behaviour unchanged:** `analytics_api.py`, `report_downloads.py`,
  `infection_kb.py`, `lookup_jobs.py`, `card_notes.py`, `name_definitions.py` and `intel_match_api.py`. Each reads its
  names from app.py at run time (`_A.name`); app.py keeps every moved name and its start-up wiring.
- **`spike_notice.py`, the spike notice on the Overview's buttons** ([USER_GUIDE.md](USER_GUIDE.md#2-the-intro-page)).
  Per platform, the latest report day against the day before (`count_documents` per report on `extracted_date`), and
  what moved most. Kept per day for `SPIKE_CACHE_SECONDS`. `GET /api/overview/spikes` ('view', 'management',
  'definitions' or 'settings'); `static/js/spike-notice.js` fills every `[data-spike]` line. Test:
  `tests/check_spike_notice.py` (no database; also in CI).
- **`beacon_stats.py`, beacons on the analyst's map.** `label(e)` is a record's *Beacon* filter label, kept as `_bc`.
  `ready(day)` labels a loaded day in one background thread (about 14 ms per check-in); until then the options read
  `beacon_pending`. Adds `beacon` to `FILTER_FIELDS` and `/api/facets`, `decoded_beacons` / `beacon_devices` to
  `/api/insight` and the `beacons` metric to `/api/insight/drill`. Masked viewers (`is_demo()`) get no options,
  figure or list, but the filter applies for all. Test: `tests/check_beacon_stats.py` (also in CI with
  `LG_UNIT_ONLY=1`).
- **`notes.py`, researchers' notes.** Per name in `data/notes.json` (run-time data, never shipped or overwritten),
  with author, role and date; `mp_resolve`, `issue_resolve` and `issues_resolve` attach them to every explanation
  card, on the pages and in the PDFs. `GET /api/notes`, `POST /api/notes` (optional `codes`, which must be in the code
  book, and `finding: {title}`), `POST /api/notes/delete` (author or admin); audit `note_added`, `note_removed`.
- **`combos.py`, combination codes and the combination search**
  ([USER_GUIDE.md](USER_GUIDE.md#combination-codes-the-combination-search-and-findings)). Each exact combination gets
  a code, `LG-C-?` / `LG-X-?` (no address). `intel.record_items` is the one matching rule, so Intel gathered's counts
  and the search agree. Codes shown to a researcher go to `data/combo_codes.json`. The search is one background
  thread per analyst over the report day (default), the days in memory, or up to 31 days read from MongoDB
  (`app._combo_fetch`, inside the constituency). Devices get that day's infections, issues, CVEs and open ports
  (`services_intel.host_flags`) and are followed into the name's other reports. The PDF's Impact section is
  `advisory.Impact.of_names` (`advisory_pdf.draw_impact`); a review keeps it (`combo_review.keep_search`). Result: a
  ZIP (PDF from `combo_pdf.py`, devices and records CSVs through `csvsafe`) kept in memory and in
  `data/combo_exports/` (0600, one hour). `export_fields.py` adds, before `combination_code` in both CSVs, the
  pattern analysis's values (communications `request_pattern`, `brute_force_username`, `brute_force_password`,
  `ssh_client`, `shadowserver_attack`; services `server_software`, `ssh_software`, `ssh_hassh`, `tls_jarm`,
  `certificate_sha256`, `certificate_subject`, `certificate_issuer`, `web_page_sha256`, `certificate_and_tls`; joined
  with ` | `). Readable field names: `field_labels.py` and `static/js/lg-fields.js`, from
  `static/data/field_labels.json`. Shadowserver's own event mapping: `ss_attack.py` (`GET /api/attack`'s `ss_seen`;
  tactics from `data/names_attack.json`). Certificate and TLS facts: `tls_facts.py` (`/api/svc/detail`'s `tls`).
  Routes: `GET /api/combo-codes/<code>` (researchers, management, analysts, admins), `POST /api/combo-codes/new`
  (researchers, admins), `POST /api/combos/search`, `GET /api/combos/search/<id>`,
  `POST /api/combos/search/<id>/stop`, `GET /api/combos/search/<id>/download` (`unmasked` + `export`, never in Demo
  mode, only the analyst who ran it), page `/combinations`. Audit `combo_code`, `combo_search` and `combo_export` (each
  ZIP download, and each call of a decided review's report, `/review/<id>/report`, which is not kept).
- **`finding_watch.py`, findings over time** ([USER_GUIDE.md](USER_GUIDE.md#findings-cases-and-who-holds-them)). Keeps
  a finding's reported days and how many of its devices the latest day shows again (one background worker). A finding
  nobody is acting on (`new`, `management`, `researcher`, `analyst`) whose devices were last seen over
  `FINDING_ACT_DAYS` (30) days ago, opened over `FINDING_GRACE_DAYS` (7) days ago, closes with "Time to act expired"
  (history kind `expired`, audit `finding_status` by `looking-glass`). `GET /api/findings/watch` (counts and days, never
  an address), `GET /api/findings/<id>/again` (the addresses; analysts, advisors and admins in the channel). The
  Executive portal loads a past day of the last week for a code (`/api/mgmt/<platform>?code=?&day=?`).
- **`acodes.py`, analyst codes.** `LG-A-?`, from an analysis window's selection. The exact record IDs are kept in
  `data/acodes/<code>.json` (0600), so masked roles see the same records; the code book holds what it stands for
  (kind `a`, no host addresses). `POST /api/analyst-codes` (analysts, admins; never in Demo mode) makes the code and a
  finding; `GET /api/analyst-codes` lists them; `GET /api/intel/acode/<code>` and page `/intel/<code>` show
  researchers, management and analysts those records' names, definitions, combinations and patterns. The Executive
  `code` filter and the Combinations search accept them (the code's day only). Audit `analyst_code`.
- **`findings.py`, findings.** Number, title, a copy of the note's text and codes, status and history in
  `data/findings.json`. Statuses `new`, `management`, `researcher`, `analyst`, `advisory`, `closed`.
  `GET /api/findings?state=open|all`, `POST /api/findings/<id>/status {status, comment}` (CSRF, recent sign-in), page
  `/findings` for researchers, management, analysts (`unmasked` + `export`) and admins. Audit `finding_created`,
  `finding_status`. A review or case on a code takes in the researchers whose reply to an analyst's request carried
  that code (`Findings._answerers`), and `request_links` links it to that request.
- **`seen_index.py`, last seen.** `data/seen_names.json`: per name, the last date seen in each report (no hosts). Each
  replay day is added as it passes; once per installation the last 14 days are read from MongoDB
  (`seen_names.json.done`). Kept 30 days.
- **`people.py`, names.** Definitions, notes and network corrections store the username and show the registered full
  name, looked up when displayed; the audit log shows *Full Name (username)*.

## Network names (ASN registry)

`data/asns.json` maps every AS number seen in the data to its operating company. The map shows company names instead of numbers ("Example Telecom (AS64500)" in the detail view, "Example Telecom" in lists). ASNs of one company are counted together: AS64500 and AS64501 of one operator appear as one network.

Each entry has:
- `name`: what is displayed
- `holder`: the registered holder from RIPEstat
- `type`: `isp`, `education`, `government`, `finance`, `hosting`, `ixp`, `private` or `unknown`
- `country` and `role`: whether the ASN appears as a source, a destination or both
- `reviewed`: `true` means the name was curated by hand
- `demo_alias`
- `events_last_check` (records noted when Identify networks last looked the network up; not shown on the pages, where
  the Records column counts the day the map shows)

**Updating it:**

```bash
.venv/bin/python manage/asn_registry.py 7     # add ASNs seen in the last 7 days
```

New ASNs are looked up automatically in the public RIPEstat registry (`stat.ripe.net`) and added with `reviewed: false`. To change a display name, edit `name` in `data/asns.json` and set `"reviewed": true`. Entries are never overwritten, and the server reloads the file whenever it changes.

Each CSIRT builds its own registry: the file is not shipped, and `manage/asn_registry.py` creates it from your data. Until then the map shows the registered holder names.

## Demo mode (public presentations)

The **Demo** button in the top bar conceals sensitive details while the data keeps playing live:
- Company names and AS numbers become stable aliases by type: "Telco 1", "Institution 3", "Provider 2", "Exchange 1".
- IP addresses (IPv4 and IPv6) become an opaque label, `Host 3f9a2c41b07e` (`host_label.py`): an HMAC of the address under `REF_SECRET`, the same for one address on one server, with no part of the address in it.
- Hostnames and machine names are hidden.
- IP addresses inside URLs, cookies and other text fields get the same label.
- A report's own fields (map and services details) pass an allowlist (`masked_fields.py`): only technical details
  (protocol, software, versions, ciphers, flags, malware sample hashes) are shown, with host names, addresses,
  e-mails, dates and IDs masked inside them; names, MAC addresses, user names, locations, keys, banners and any field
  not on the list are hidden, and the details window says how many.
- Locations stay visible.
- Pins and "Copy JSON" are hidden.

**The masking happens on the server** (`privacy.py`, `?demo=1`), so concealed values never reach the browser. Drill-downs still work through opaque host references (`src_ref`). While a request is masked (Demo, or a role without *unmasked*), filters accept only what the masked view shows: host filters only the opaque references, network filters only the aliases (`AsnRegistry.strict`); a real address, company name or AS number matches nothing, so a viewer cannot find out whether something is in the data.

Pinned events keep full details in the browser, so they are stored per account (`tm.pins:<username>`), never for masked accounts, and deleted on the sign-in page (log out, expired session). The aliases are fixed in `data/asns.json` (`demo_alias`), so "Telco 1" means the same network in every presentation.

For a public deployment where nobody may switch demo off, set `PUBLIC_DEMO=1` in `.env`: every request is masked, the button is locked on, and `/api/asns` is refused.

## Requirements and installation

See [INSTALLATION.md](INSTALLATION.md). In short: Ubuntu 24.04 or later (Desktop, Server or Ubuntu on WSL 2), Python
3.12, 3.13 or 3.14 on x86_64 or aarch64, MongoDB filled by the Shadowserver pipeline (`../database`), a Mapbox token,
and optionally a Malpedia token. Python packages: Flask, Werkzeug, pymongo, python-dotenv, gunicorn, ReportLab,
Pillow, webauthn, cbor2, cryptography, typing-extensions and tzdata. `requirements.txt` gives each a range below its
next major version (for example `flask>=3.0,<4`); `requirements.lock` fixes every version, dependencies included,
with each file's sha256. `tests/check_libraries.py` (no data needed; the installer runs it) checks the installed
versions against the ranges and tries the parts the platform uses. `tests/check_requirements_complete.py` checks that
each `requirements.txt` (platform, pipeline, docs site) names every library its code imports, and only those. To allow a new major version, raise its range, make the lock again
([OPERATIONS.md](OPERATIONS.md#updating-the-libraries-on-purpose)), and keep it only if `tests/run_all_checks.sh` and
`security_testing/security_retest.py` pass.

External services: **MongoDB** (database `shadowserver` by default; read only, never written); **Mapbox** (a public
`pk.` token for map tiles in the browser and the Geocoding v6 API on the server, each place looked up once and cached
in `data/geocache.json`); fonts from Google Fonts. Country flags come with Looking Glass (`static/img/flags/`, 252
public-domain flags, 40 pixels wide), so no flag is fetched from anywhere else.

For development, `.venv/bin/python app.py` runs it on `http://localhost:<PORT>` (`PORT` in `.env`). As a service, use
gunicorn with **one worker** (the day cache is in memory) and threads for viewers:

```bash
.venv/bin/gunicorn --workers 1 --threads 8 --bind 127.0.0.1:<your port> app:app
```

`deploy/install.sh` writes the hardened systemd unit `deploy/looking-glass.service` from
`deploy/looking-glass.service.template` for your user and folder ([INSTALLATION.md](INSTALLATION.md)):

```bash
sudo cp deploy/looking-glass.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now looking-glass
journalctl -u looking-glass -f
```

### How the libraries are installed (`deploy/safe_libraries.py`, `library_supply.py`)

Sources, refusals and the reports as an operator sees them:
[INSTALLATION.md, The libraries](INSTALLATION.md#the-libraries-only-files-that-match-the-lock). `deploy/safe_libraries.py`
uses Python's standard library only; the guided installer also uses it for its own answer checks, and a release copies
it unchanged beside the pipeline's `deploy.sh`. Its steps and exit codes:

1. **`check-machine`:** `ID=ubuntu` and `VERSION_ID` 24.04 or later in `/etc/os-release` (`ID_LIKE` does not count),
   the `python3` that will run Looking Glass at 3.12-3.14, `platform.machine()` x86_64 or aarch64. Else exit 2 with
   every reason, before anything is made.
2. **The lock** (from `tools/lock_requirements.sh`: pip-compile `--generate-hashes --allow-unsafe`): every line
   `name==version` with at least one `--hash=sha256:`. An option line (`--index-url`, `--extra-index-url`, `-e`...), a
   range, a missing hash or a duplicate: exit 4.
3. **`python3 -m venv .venvs/<name>-<time>`**; its own pip (never upgraded from outside) does the rest, with the
   user's pip settings and `PIP_*` variables set aside.
4. **Each file:** `pip download --no-deps --only-binary=:all:` for that Python and processor (`manylinux_2_28`,
   `manylinux2014`, `manylinux_2_17`, pure-Python) into a quarantine folder, from PyPI (`LG_PYPI_URL`), the release
   bundle (`LG_LIBRARIES_URL`; tarfile's `data` filter, wheels only, at most 2 GB), then the local copy
   (`LG_LIBRARIES_DIR`, default `~/looking-glass/libraries`, newest release first). No match in any source: exit 3,
   the new environment removed.
5. **Install:** `pip install --no-index --find-links <checked files> --require-hashes --only-binary=:all: -r
   requirements.lock`, then `pip check`, the required modules (`--import`), and the lock's sha256 in
   `lg-lock.sha256` (the same lock next time: nothing to do).
6. **Switch:** `.venv` becomes a relative link (an older real `.venv` folder moves into `.venvs/` first); the newest
   two environments are kept; the service keeps its loaded libraries until reloaded. The local copy is
   `<release>/<part>/` with `SHA256SUMS`, files 444, folders 555.
7. **Report:** refused files go to `suspected-packages.json` and `.txt` (in `LG_SUPPLY_REPORT_DIR`), each with an
   id, the lock and the outcome. Exit 10: installed, but something was refused. `library_supply.py` (via
   `features.py`) reads the reports of the platform's folder, the one above and the pipeline's, audits each event once
   (`library_suspected`, user `looking-glass`, a minute after start; ids in `data/suspected_packages_audited.json`)
   and raises one bell alert for the last 30 days' events.

`.release_files` (in `platform/` and `database/`) lists every file a release ships. During an update,
`deploy/stale_files.py` moves code files on `.release_files_history` (every file any release shipped there) but not on
`.release_files` to `backups/stale-<time>/`; with no history list it moves nothing. It refuses a list it cannot trust
and never follows links ([INSTALLATION.md, Updating](INSTALLATION.md#updating)).

`tools/build_wheelhouse.sh` makes the release bundle: every locked file for Python 3.12-3.14 on x86_64 and aarch64,
each checked against its lock, `SHA256SUMS`, the locks, and an offline `pip install --dry-run` per computer.
`tests/check_installer_supply.py` (in `run_all_checks.sh` and the GitHub checks) rehearses it all with a local package
index on 127.0.0.1 and made-up wheels, and fails if any install path runs pip without `--require-hashes`.

### Always on: a new day every day

**Each day is replayed in full, 00:00 to 24:00, once its report has arrived** (`schedule.py`), since Shadowserver
delivers a day's reports during the following day:

1. At 24:00 the next day starts at once if its report is in MongoDB.
2. If not, the platform shows **"Waiting for the reports of YYYY-MM-DD"**, holds at 00:00 and checks every 15 seconds.
3. Once no new report has arrived for `REPORT_SETTLE_SECONDS` (default 10 minutes; each new report restarts the
   wait), the day replays from 00:00; open pages switch within 15 seconds.
4. A replay more than a day behind (after downtime, say) skips to the newest day.

So the replay can be more than 24 hours behind; the top bar shows **Replay time (UTC)** (from `extracted_date`) and
**Current time (UTC)**. The schedule is saved in `data/schedule.json`, so a restart continues where it was, settle
time included. Only the server runs it; scripts that import `app.py` do not. At demo speeds the day loops.

**Late reports.** Every 15 seconds the server counts each report's rows for the replayed day (indexed filename
prefix); a new or grown report reloads the day at once, and open pages refresh within 15 seconds. The receive time
is the rows' MongoDB insert time (ObjectId). `/api/clock` lists the day's reports (`reports`) and recent arrivals
(`report_changes`); `tools/report_arrivals.py [day]` and `tools/check_reports.py [day]` (MongoDB against the running
service) check them.

**New collections.** Collections are listed every 15 seconds; a change rebuilds the report list at once, with a full
rebuild every `REGISTRY_REFRESH_SECONDS` (default 1 hour). A report has `src_*`/`dst_*` fields (or the referer
source fields) in a known layout (standard, legacy, referer, inbound), is not in `EXCLUDE_COLLECTIONS`, and is in
`MONGO_COLLECTIONS` when that is set (empty = all).

### Publicly accessible / vulnerable services (`/services`)

The platform for the single-host reports (what it shows:
[USER_GUIDE.md](USER_GUIDE.md#4-publicly-accessible--vulnerable-services)): collections with an `ip` but no source and
destination (`scan_*`, `scan6_*`, `population_*`, `device_id*`, `compromised_*`, `blocklist`). No map; the same
replay schedule and features as the map platform.

**Discovery.** `services.py` `ServiceRegistry` finds these collections every 15 seconds. **Required:**
`extracted_date` (a date), `ip`, `geo`, and `filename` with an index. **Recommended:** port, city or region, network,
severity, tag. Others are listed as "not processed yet", with what they lack.

**Fields.** `tools/analyze_services.py` measures the fields across the 86 collections. Records are normalised to
the common fields plus **service**, **family** (Exposed service, Service population, Identified device,
Compromised, Blocklisted), vendor, device type, product, version and **issues** (CVE tags, POODLE, FREAK, expired
certificate, exposed admin panel, device implant, compromise). Every other field is kept for the record details.

**Page.** `templates/services.html` uses the map platform's `app.css` and markup; `services.css` only adds the stage
that replaces the map. Region boundaries: `static/data/adm1/<country>.json` (geoBoundaries ADM1, CC BY 4.0). Demo
mode also hides identifying certificate fields.

**Official report names.** Shadowserver's names without "Report"; IPv6 reports carry "(IPv6)". Collections were
matched to reports by their file names and `category` and the "Filename" line of Shadowserver's report page.
`_verified` in `data/service_reports.json` records the exceptions: `population_bgp` ("Open BGP Service
(population)", the population variant of `scan_bgp`), MikroTik (spelled `scan_miktrotik_service`), NTRIP and Radmin
(no filename).

**Hosts in several reports (`cross`) and with multiple issues (`multi`).** Both compare the selected hosts against all
their reports of the day and show every one of their records. The filters set when the figure is switched on choose
the hosts and travel in the value (`cross=seed:family=Blocklisted`); later filters narrow the records; host filters
always apply. Old links with `cross=1` / `multi=1` let every filter choose the hosts. In the address: `multi`,
`cross`, `vulnerable=1`; a report: `/services?service=…`.

**Report definitions.** `data/service_reports.json`, written from Shadowserver's report pages
(https://www.shadowserver.org/what-we-do/network-reporting/): each report's official name, Shadowserver's severity,
what it means, why it matters and a link, for all 86 single-host and 12 communication reports. Glossaries, tooltips
and record details use it.

**API.** Under `/api/svc/`: `clock`, `events`, `detail`, `replayed`, `stats`, `facets`, `insight`, `hosts.csv`,
`glossary`, `diagnostics` and `summary`.

**The map's compatibility check** (`diagnose` in `sources.py`). Required: `extracted_date` (a date); source host
`src_ip`, `ip` or `http_referer_ip` and country `src_geo`, `geo` or `http_referer_geo`, by format; `filename` with
an index, or `FALLBACK_SCAN=1`. Recommended (the report still loads; the overview tooltip says what it lacks):
destination IP or country, source city/region, destination country, source network, severity, infection/category.
Source only (like Sinkhole DNS) shows points at the source. Destination only (the "target" format) needs `dst_ip`
and `dst_geo` and is left out of source-host figures. The older format (`ip`/`geo` the local host, `dst_*` the far
end) loads too. A report failing a required check is listed on the overview as "not supported yet".
`/api/diagnostics` gives the full check; `tools/diagnose_reports.py` runs it read-only. Rows load by filename prefix
(`YYYY-MM-DD-…`).

## Configuration (`.env`)

Every setting, with examples: [CONFIGURATION.md](CONFIGURATION.md). The main ones:

| Variable | Default | Meaning |
|---|---|---|
| `MONGO_HOST`, `MONGO_PORT` | `localhost`, `27017` | Mongo server; the port is a number from 1 to 65535, else the service refuses to start and says why |
| `MONGO_USER`, `MONGO_PASSWORD`, `MONGO_AUTH_SOURCE` | none, none, `admin` | credentials |
| `MONGO_DB` | `shadowserver` | source database |
| `MONGO_COLLECTIONS` | empty | empty means auto-discover every src/dst collection; otherwise a comma-separated list to use |
| `EXCLUDE_COLLECTIONS` | `outdated_dnssec_key` | comma-separated collections to skip |
| `MAPBOX_TOKEN` | none | Mapbox public token |
| `REPLAY_OFFSET_HOURS` | `24` | which day counts as "yesterday", and the schedule used on a fresh start when yesterday's report is already in |
| `REPORT_SETTLE_SECONDS` | `600` | after a day's report starts arriving, wait this long before replaying that day from 00:00 |
| `MAX_EVENTS_PER_POLL` | `400` | cap per poll window; any extra events are randomly sampled |
| `DAY_RELOAD_SECONDS` | `600` | how often an in-memory day is checked against Mongo; it is kept (with every cached answer) while the rows per report are the same, and read again in full at least every `DAY_MAX_AGE_SECONDS` (3600) |
| `SETTLE_MAX_SECONDS` | `120` | new rows load once the counts are the same on two checks in a row, or at least this often; only the changed reports are read again, the others taken over from the copy in memory |
| `COUNT_EVERY_SECONDS` | `600` | the 15-second check reads the pipeline's marks (`lg_load_stamps`, one small query) and counts every report's rows only when a mark moved, or this often |
| `FALLBACK_SCAN` | off | set to `1` to query by `extracted_date` when no `YYYY-MM-DD-*` file exists; this does a full collection scan unless that field is indexed |

## How it works

- **Data loading.** A collection can hold millions of documents with no index on `extracted_date`, so time-range queries would scan it whole. Instead the app loads the replay day into memory through the existing `filename` index (report files are named `YYYY-MM-DD-…csv`); a typical national day loads in a few seconds. If no file names match, the day stays empty and is retried every minute. `FALLBACK_SCAN=1` queries `extracted_date` instead.
- **Replay clock.** The browser keeps a clock running `REPLAY_OFFSET_HOURS` behind real time. Every 4 s it requests the next window from `/api/events` and launches each arc at the event's own time. The speed selector (1×, 5×, 15×, 60×) speeds this up; 1× snaps back to live. Each attack stays "active" for 75 s of replay time, its packet re-firing along the arc, so several attacks animate at once. On load, the stream is backfilled with the last 15 replay-minutes.
- **Coordinates.** Sources and destinations are geocoded by city and region, falling back to the country centroid. Events with only one known location show a pulse there instead of an arc.

### API

| Endpoint | Returns |
|---|---|
| `GET /api/clock` | server time, replay time, offset, number of integrated reports |
| `GET /api/overview` | whole-day summary for the intro page: totals, all monitored reports with row counts, attack-type mix, 15-minute timeline (contains no network names or IPs) |
| `GET /api/asns` | the ASN registry (refused in demo mode) |
| any endpoint `&demo=1` | the same response with network names, ASNs, IPs and hostnames concealed |
| `GET /api/sources?at=` | the collections being integrated (layout, attack type, label) with row counts for the replay day |
| `GET /api/events?from=&to=&infection=&severity=&tag=&src_city=&dst_geo=&dst_port=&protocol=` | events in the window, with every field plus `src_coords` and `dst_coords` |
| `GET /api/facets?at=` | filter values with counts for the replay day, plus the severity of each infection |
| `GET /api/stats?at=&…filters` | totals, unique hosts, families and C2 IPs, top infections / categories, affected cities, C2 / sinkhole domains and targets, and 15-minute timeline buckets |
| `GET /api/insight?kind=&value=&at=` | analytics for one entity (`kind` = `source`, `attack_class`, `infection`, `src_city`, `http_host`, `dst_geo`, `src_ip`, `src_asn` or `dst_ip`): connections, share, hosts, C2 domains, median beacon interval and how many hosts beacon regularly, multi-infected hosts, hourly profile, breakdowns, most active hosts and plain-language findings |
| `GET /api/insight/drill?kind=&value=&metric=&at=[&all=1]` | the list behind one figure of the analysis view (`metric` = `events`, `share`, `hosts`, `c2`, `dst_ips`, `interval`, `multi`, `reports`, `cross`, `beacons`: decoded beacons, analysts and admins). Host lists are ranked for follow-up (several kinds of activity, several reports, several infections, regular beaconing, critical). Returns the first 300 rows, or all with `all=1` (used by Download CSV). Demo mode masks IPs and networks |
| `GET /api/related?src_ip=&at=` | what one infected host did today: connection count, first and last seen, infections, contacted hosts |
| `GET /healthz` | liveness; this computer only (loopback), anyone else gets 404 |

## Intro page

The welcome page opens on the first visit in each browser session; refreshes go straight to the map. **Overview** in the top bar (or the logo) returns to it. It shows:
- the day being replayed;
- live totals: events, reports with data out of all monitored reports, source hosts, infections / categories, affected cities and hosts seen in several reports;
- the full-day activity strip and the attack-type mix;
- **every monitored report**, those with data that day first.

It has two buttons: **Explore the platform** and **Explore in demo mode**.

All figures come from `GET /api/overview`; the report list from the live collection registry. New collections with src/dst fields are discovered within `REGISTRY_REFRESH_SECONDS` (default 3600), so the count grows by itself beyond 30. The page refreshes every minute while open. The logo is animated (the arc draws in and flows, the impact ring pulses), except for users who prefer reduced motion.

### Animated logo: loading and page transitions (`static/js/loader.js`)

Shared by the map, the services platform and Settings:
- **While data loads**, the logo appears next to the loading message: the analysis and detail panels ("Analysing…", "Loading the details…"), the live stream while it waits for records, and Settings while it loads. Records scroll through the lens, the arc draws, and the hit pulses. Any element with the class `i-loading`, `st-loading` or `lg-loading` gets it automatically.
- **Between pages** (intro → services, services → overview, any page → Settings and back), the logo draws itself (rim, handle, then the arc) with "Opening …". The next page keeps it on screen until its first figures arrive (at least 0.7 s, at most 1.6 s), then it zooms and fades into the platform. **Explore the platform** on the intro shows the same logo over the intro before the map appears.
- In **Lite** display mode and for users who prefer reduced motion, the logo is still and pages switch without delay.

## Settings (both platforms): country and constituency

`/settings` opens from the gear at the top left of the intro page, the **Settings** button in both platforms' top bars, and the constituency label. What it sets applies to both platforms at once; the parts shown depend on where it was opened (what each setting does for users: [USER_GUIDE.md, Settings](USER_GUIDE.md#7-settings-administrators)):

| Opened from | Address | Shows |
|---|---|---|
| Network communications | `/settings?for=comms` | Constituency only (the map does not use a country) |
| Publicly accessible / vulnerable services | `/settings?for=services` | Country and constituency |
| Intro page | `/settings` | Both |

**Applying.** A bar fixed at the bottom of the page shows the state: **No changes** (with what is in force), **Unsaved changes** (with what Apply would set, plus Undo changes), or **Settings applied at HH:MM UTC**. **Apply settings** saves, and the server reloads both platforms' data at once (about 4 seconds); a green banner confirms what is in force. Open pages check for new settings every 10 seconds and refresh completely (figures, stream, map, analysis and, on the services platform, the country, its regions map and the "<country> regions" button), showing "Settings updated: …". Leaving the page with unapplied changes asks for confirmation.

**Wrong country.** If none of the regions in the reports are on the chosen country's map, the services platform still shows that country's map, with a note: "None of the N regions in these reports are on <country>'s map. Kindly select the right country in Settings to populate the regions", plus an **Open Settings** button. The settings page shows the same warning before applying.

- **Country.** Choose the continent, then the country: every country and territory in the world (ISO 3166-1, plus Kosovo). The services platform draws its first-level regions on the regions map and uses its name in labels; the view button reads "<country> regions", or "<country> map" for a country drawn as one area. Boundaries come from geoBoundaries (gbOpen ADM1, simplified; about 200 countries) and, for countries without first-level regions there, from geoBoundaries ADM0 or Natural Earth as one area. They live in `static/data/adm1/<ISO2>.json` with `index.json` listing continent, names, regions and licence per country; `manage/fetch_world_boundaries.py --out static/data/adm1` downloads them all again. Countries that cross the 180° line (Fiji, Russia, New Zealand, Kiribati) are drawn in one piece. The page previews the country's regions, checks yesterday's region names from the reports against the map and says how many it could draw; if none match, it warns that the reports do not seem to be for that country.
- **Region names and labels (every country).** The reports' region names come from IP geolocation, which follows ISO 3166-2. They are often in the local language ("Alger", "Al Qāhirah") or use newer subdivisions than the boundary files (Algeria's 58 provinces against 48 on the map; Kavango East / West in Namibia). `manage/region_aliases.py` adds to every region of every map:
  - its ISO 3166-2 codes;
  - aliases: the ISO name, sub-units whose ISO parent is that region (e.g. Burkina Faso's provinces), newer subdivisions mapped to the region they were carved from (Touggourt → Ouargla, In Salah → Tamanrasset), and English / local alternatives (Algiers ↔ Alger, Cairo ↔ Al Qāhirah, Brong-Ahafo → Bono);
  - repaired display names (Seychelles' truncated and garbled names, typos such as "Northen Red Sea");
  - a label point well inside the region.

  The script uses the ISO 3166-2 list of Ubuntu's `iso-codes` package. For the 54 African countries every ISO first-level subdivision lands on a map region, except where ISO's top level is above the map's units: the island groups of Cabo Verde and Equatorial Guinea (their municipalities and provinces match), and the uninhabited Cargados Carajos Shoals of Mauritius. Elsewhere the same step runs, and a name it cannot place is left for the administrator: the Settings page lists yesterday's report region names with a "Match" column, suggests the closest map region ("doesn't match, but this is what we found"), and an administrator confirms it, picks another region, or marks the name as the whole country. Choices are stored per country in `data/region_matches.json`, apply to the map, the Executive report and the "unknown region" checks, need a fresh sign-in, and are audited (region match set / removed). Matching ignores accents, letter case and words such as "Region" or "Governorate". `static/js/regions.js` does it in the browser for the services regions map and the Settings preview.

  Both maps label every region where the name fits without overlapping (regions with records first, then the largest); hovering names any region with its ISO code and records. Several report names on one region (a newer province inside the old one) are added up, and the tooltip lists them. Report regions on no region of the map are listed under the map. `manage/fetch_world_boundaries.py` runs the alias step after downloading.
- **Constituency.** Leave it on "Whole country", or choose the networks your CSIRT is responsible for. The card holds the mode and a live summary ("N networks, M address blocks, K other ranges"); the choice is made in the Constituent column of the network list (Network names & types, `net-editor.js`), one AS number at a time: **Not in**, **The whole network** (saved in the AS number list) or **Some address blocks** (an expansion row lists the network's /24 blocks with records, busiest first, from `GET /api/settings/address-blocks?asn=N` in `address_blocks.py`; a block belongs to the network most of its records are in; ticked blocks are saved as address ranges). **Other address ranges**, under the table, takes ranges of no listed network, such as a government network without its own AS number. On load, `GET /api/settings/address-blocks?summary=1` gives each network's block count and which saved ranges are exactly one of those blocks; those show as that network's chosen blocks, any other saved range under Other address ranges. Saving: `POST /api/settings` with `networks` (AS numbers) and `cidrs` (address ranges). Both platforms then keep only records whose host is in the constituency (the map platform: the source or destination side; the services platform: the host), and every figure, list, map, analysis and export follows. Saving reloads both platforms' data; open pages refresh by themselves and show **Constituency: N networks** in their top bars, as does the intro page.
- **Deployment.** The same settings can be given in `.env` as `COUNTRY`, `CONSTITUENT_ASNS` and `CONSTITUENT_CIDRS`. The page shows the lines for your current choice. Settings saved on the page are stored in `data/settings.json` and take precedence.
- **Who can change them.** Accounts with the Settings permission (administrators), from a recent sign-in. Accounts without the permission do not see Settings. (The old `SETTINGS_TOKEN` header was removed: settings have one rule.)
- **The replay schedule is unaffected.** It still waits for the reports themselves, so a narrow constituency with no records on a day is not mistaken for a missing report.

## Glossary and hover explanations

Each platform has a **Glossary** button in the top bar that covers **only that platform**:
- **Reported network communications** (the map): the general terms plus its reports.
- **Publicly accessible / vulnerable services**: its figures and terms, report families and its reports.

The intro page's **Glossary** tab covers **both platforms**. Every report is listed under its official Shadowserver name, with its Shadowserver rating, the number of records on the replayed day, and a **Shadowserver report page ↗** link to its page under https://www.shadowserver.org/what-we-do/network-reporting/ (links checked against that page). The links come from `data/service_reports.json`.

The general terms are plain-language definitions written for everyone, management included, grouped into The basics,
Who and where, Threats, Numbers and measures, Using the platform, Accounts, roles and permissions, Publicly accessible /
vulnerable services, and Security, audit and the pipeline, with a search box. Examples: what an event is, what
"median" and "median repeat interval" mean, sinkhole, honeypot, C2, demo mode, a finding, an advisory and TLP, the
audit log's hash chain, control checks, NIST SP 800-53, CIS Controls, the proof package, the sender check and
confirmation on the server.

The same definitions appear **on hover** across the platform. Labels with a dotted underline explain themselves: top-bar figures, the activity level, the replay clock, playback speed, filter headings, Intel chart titles, stream columns, and every number and chart title in the analysis view.

All text lives in `static/js/glossary.js`: a definition edited there changes in the Glossary tab and the tooltips.
`docs/GLOSSARY.md` is the same list for the documentation site, generated from it by `python3 tools/glossary_md.py`, so
edit the JavaScript file and regenerate rather than editing the Markdown (only its introduction and Related tools
section are written by hand). To explain a new label, add a term to `glossary.js`, then map the label's text to the
term's key in `LABEL_TERMS` in `static/js/app.js`.

## Devices and performance (smart TVs, older computers)

The look adapts to the device (phone, tablet, laptop, large screen). The top bar never squeezes its figures into each other: on wide screens (1440 px and up) they share one row and the least important ones (cross-report hosts, reports, source hosts) are hidden whole when they do not fit; from 701 to 1439 px they get their own row under the name and clocks; on phones the bar has three rows (name, replay time and buttons, figures) and the speed menu is hidden.

**Smart TVs and other short screens.** TV browsers report a small screen size (often 960 × 540 or 1280 × 720). On screens up to 820 px tall all six figures sit on a slim second row of the top bar (label and number side by side), and the event stream takes about a third of the height with compact rows (address and place; the network is in the details) and no column header. The stream has **Hide list / Show list** (or **L**): hidden, only its title bar stays. TVs start with the list hidden; the choice is remembered per device. The list can be focused with Tab or a TV remote: the arrow keys move between rows (scrolling the list) and Enter opens one. Map share at 960 × 540: 44 % with the list (3 rows visible), 72 % without; at 1280 × 720: 49 % (5 rows) and 79 %. Drawing cost is controlled by **Filters > Display**:

| Mode | What it does |
|---|---|
| **Auto** (default) | Full on capable devices. Lite on smart-TV browsers (Samsung Tizen, LG webOS, Android/Google TV, Fire TV, Chromecast and others), on very low-power devices (2 cores or 2 GB memory or less), and when the map keeps drawing below about 22 frames per second (checked after the first 10 seconds; remembered for that device). |
| **Full** | Every effect: 3D tilt, glowing arcs with trails, impact rings, camera drift, see-through blurred panels, sharp rendering on high-resolution screens. |
| **Lite** | Flat map, no glow, trails, fog or camera drift, solid panels (blurring over a moving map is the heaviest effect on weak graphics chips), no UI animations, at most 40 arcs and 4 popups at once, half the redraw rate, 120 stream rows, and 1 pixel per CSS pixel (a 4K TV otherwise draws four times the pixels). |

The data, counts and analysis are identical in every mode. A screen can also be set from the address: `http://host:<your port>/?perf=lite` (or `full`, `auto`); the choice is remembered on that device.

**Browser requirement:** the map needs WebGL 2 and a browser from about 2021 or later (current Chrome, Edge, Firefox, Safari; TVs roughly from 2021–2022 on). Older TV browsers get a clear message instead of a blank screen. For those TVs, use a computer or streaming stick with an up-to-date browser on the TV's HDMI input, or share a computer's screen to the TV.

## Malpedia lookups

With `MALPEDIA_TOKEN` set in `.env`, every infection description (in the event details and the analysis view) has a **Look up on Malpedia** button, as do the report's tag when it names something else and report fields holding a malware family or a sample hash (md5, sha1, sha256). The result shows the Malpedia family (linked), how it was matched (for example `modpack` matches win.misfox by its alternative name ModPack), the description, other names, attribution, YARA rule counts and references, with other possible matches to choose from.

- The token stays on the server (`/api/malpedia?field=&value=`) and never reaches a browser; `.env` is readable by its owner only.
- Answers are cached for a week in `data/malpedia_cache.json`.
- Shadowserver names are matched to Malpedia ids by trying the full name, then without platform prefixes (`android.`), helper words (`likely-rat-`, `avalanche-`, `-p2p`, `-beacon`, `-download`, `-stealer`, …), version digits (`badbox2` → `badbox`) and separators (`pseudomanuscrypt` = `win.pseudo_manuscrypt`).
- When no malware family matches, the name is tried as a **threat actor** (`find/actor/`, `get/actor/`; exact name or alias only, e.g. `tick` = Tick / BRONZE BUTLER): the card shows the group, its aliases, suspected origin, targets and the malware it uses. Definitions can point to an actor with `actor:<id>`.
- PDF reports: `GET /api/insight/report.pdf` and `GET /api/svc/report.pdf` take the same arguments as the drill-down (`kind`, `value` / filters, `metric`, `at`) plus `all=1` and an optional `label`; permission `export`. They run the analysis and drill-down views server-side and render with `reports_pdf.py` (reportlab; DejaVu fonts from `fonts-dejavu-core` when present, built-in fonts otherwise). Up to 60 infection names are explained per report (Malpedia answers are cached).
- Without `MALPEDIA_TOKEN`, `/api/malpedia/batch` and `/api/malpedia` (fields infection / tag) answer from the definitions and the knowledge base (`offline: true`); hash and family look-ups still need the token.
- Issues (services): `cves.py`. CVEs are explained in batches (measured 2026-11-08: NVD without a key answers 5 requests per 30 s as documented; the official CVE.org records, cvelistV5 on GitHub, answered 12 in 6.7 s; EPSS 12 in one 2-s request):
  CISA KEV one download a day; EPSS one request per 100 CVEs; CVE.org records four at a time (description, CNA or CISA-ADP CVSS, CWE, references; a cold batch of 24 CVEs takes about 2.5 s);
  NVD's own analysis only from the background thread (every 10 minutes, at NVD's pace, one worker process; `NVD_API_KEY` makes it 10 times faster). Cache `data/cve_cache.json` (NVD / CVE.org / EPSS 7 days, KEV 1 day), merged between worker processes.
  Non-CVE issues come from `data/issues.json` (shipped) and the `issues` of `data/definitions.json`, never looked up. `GET /api/issues/batch?values=` (permission `malpedia`).
  A CVE's title in lists (`CveIntel.known_titles` / `known_title`, cache only, never a request): CISA KEV's name, else the CNA's title, else the first whole sentence of the description (`short_title`). `app._defined_titles` (the code cards' definitions) and the Definitions list use it; a researcher's definition overrides it. Nothing is copied into `definitions.json`: the record is read from the cache each time, so it follows the weekly refresh.
  Codes for CVEs / issues and infections in `for_hosts` (since 2026-11-19 ONE per name, not per report: `issue_code(first, name, reports)` = `cross_code` of `[(report, []) for each report] + [("Issues found", ["Issue: name"])]`, `sink_code(first, name, reports)` likewise with `"Botnet sinkholes"`; a one-report code made before reads and resolves as it did), `small_codes.code_for` below 5 hosts, registered with `on_codes`; `Matcher` resolves them from `host_issues`. `ServicesIntel.carried(hosts)` gives a cross-report pattern's CVEs, issues and infections with counts; `intel.py` keeps the device sets of the 12 shown patterns per name (`xhosts`) for it and drops them before answering.
- Management portal: `management.py` (`/management`, `GET /api/mgmt/comms|services` with filters and `day`, `GET /api/mgmt/explain?kind=infection|issue&name=`, `GET /api/mgmt/report?platform=` executive PDF). Answers carry aggregates only (counts, shares, trends, facets) and never an address; other roles get 403. Permission `management` is exclusive (`auth.Roles` strips it from every role except `management` and `admin`; the `management` role is always exactly `["management"]`); management users are confined to `MANAGEMENT_PATHS`.
- Look-up jobs: `POST /api/lookups` {kind: issues | malpedia, values} (permission `malpedia`, CSRF; at most 400 names, two running jobs per user) starts a background job; `GET /api/lookups/<id>?since=n` returns progress, the new log lines and, when done, the results. The page shows them in a progress window (`static/js/pdf.js`, `LGLookup.run`). Malpedia jobs wait and continue when Malpedia's 30-a-minute limit is reached.
- Reports: `GET /api/insight/report` and `/api/svc/report` return a ZIP (PDF + complete list as CSV, formula-safe); `format=pdf` returns the PDF alone (then the list is printed).
- Network names: `GET /api/networks`, `POST /api/networks/entry`, `POST /api/networks/types` (permission `networks` or settings; CSRF; fresh sign-in). Types: `netypes.py` (built-in sectors, PeeringDB categories) plus `data/network_types.json`; demo aliases use each type's word. The built-in Researcher/TI (researcher or threat intelligence analyst) role has `definitions` and `networks` (added once to existing installs, marker `data/.roles_networks_added`). `GET /api/networks` gives each network's records on the replay day (`events`, null when that day is not loaded) and `events_day`.
- Administrator / researcher definitions (`data/infections.json`, written from Settings or `/definitions` via `POST /api/kb/entry`; permission `definitions`, or `settings`; the built-in `researcher` role has only `definitions` and is limited to `/definitions` and `/api/kb/*`): an optional `malpedia` family id is looked up directly instead of searching; otherwise `references` + `description` give a *Looking Glass definition* card. `GET /api/kb/unresolved` lists unmatched names, names not checked yet and defined names; `GET /api/kb/malpedia-search?q=` finds family ids; `POST /api/kb/check` checks new names now. The check state per name is in `data/malpedia_names.json` (run-time, not shipped); a background thread checks names new reports bring in every 30 minutes at most 20 per minute, one worker at a time (`data/.malpedia_check.lock`).
- `tools/malpedia_check.py` looks up every infection of the replay day and lists what matched (typically most of them; the rest are Shadowserver activity names such as `ssh-brute-force` or proxy networks that Malpedia does not list).

## The map: all connections plus the live replay

The map has two layers:
- **All of the day's connections** (always drawn, from `/api/geo`): every source place, destination and source → destination connection of the whole replayed day with the active filters, sized by event count and coloured by the main attack type. Filtering narrows it to exactly the matching places, zooming out if some are off screen. It can be switched off under **Filters > Display**.
- **The live replay** on top: bright animated arcs for the events playing at the current replay time (no popups).

**Everything drawn on the map explains itself on hover and can be clicked**, like the Intel lists ("Click to analyse"):
- a connection line opens a **Connection** analysis (for example Accra → The Hague): events, hosts, findings, charts and the click-through lists;
- a source place opens its **Affected city** analysis; a destination opens its **Destination place** analysis;
- a live arc or dot shows the event (infection, host, route, time) and opens its full details.

Events without a destination location (for example Sinkhole DNS, which records no destination) appear only as their source place.

## Unusual activity (`unusual.py`, `unusual_detect.py`, `unusual_worker.py`)

`unusual_worker.py` runs every hour from its own systemd timer (`deploy/unusual_timer.sh`) with the platform's
read-only database account. It counts each report day of the window that is new or changed into a summary (devices
per report, per network and report, and per report pair; counts only), then compares the latest days with each
thread's normal. `unusual_detect.py` holds the arithmetic: the median and median absolute deviation, the thresholds,
the lift of a pair, and each report's bar learned from the team's decisions. `unusual.py` serves the page
(`/unusual`, analysts and administrators), `/api/unusual` (also researchers, without devices), the devices behind a
card, Confirm, Dismiss and Stop watching (audited), and `/api/mgmt/unusual-week` for the Executive card.

## UI

Front-end libraries: Mapbox GL JS 3.8.0 (satellite style) and deck.gl 9.1.14 (3D arcs), both loaded from CDNs.

- **HUD (top bar):** events yesterday (whole-day total), replayed so far (exact count of the day's records up to the replay position, from `/api/replayed`; it stops while paused), source hosts, reports, cross-report hosts, critical count, an activity level (last 5 minutes vs the replayed day's average), "Replaying events of" with the replayed date (yesterday) and, separately, the current time (UTC). The analysis view and its findings refer to the replayed day as "Yesterday" with its date.
- **Map:** raised 3D arcs colored by infection, with packets that re-fire along each arc, impact rings and source pulses. Up to 10 popups appear at once, each showing the infection, IP and target. Pinned attacks stay drawn as dashed purple arcs. The camera slowly sways; turn this off with the ⟳ button.
- **Event stream (bottom):** a scrollable table with severity, infection / category with its report, source host (IP:port, city, ASN), destination (IP:port, city, ASN), protocol/port, and C2 domain plus request. Rows still animating on the map show a live dot.
  - If you scroll down, new rows wait behind a "↑ N new" button, so the list doesn't jump while you read.
  - **Pause** freezes the whole replay (clock, arcs, popups and stream); **Resume** continues from the same moment, so nothing is skipped. The replay then runs behind by the paused time; **Catch up** (or choosing a speed) jumps it forward to the normal replay time.
  - A hidden or minimised tab **pauses itself** (browsers stop animations in background tabs) and resumes from the same moment, so the stream has no gaps. An event that still arrives late is listed in the stream without its map animation, never dropped.
  - The map's zoom and compass buttons pause the slow cinema rotation while they animate, so they always work.
  - The 📌 button pins a row. Pinned rows sit above the live rows and are kept in the browser across reloads.
  - Clicking a row, arc or popup opens the **communication detail**: the raw HTTP request, infected host, destination, threat, TLS/device, "this host today" and provenance (report file, line hash), with Pin, Show on map and Copy JSON buttons.
  - Drag the top edge of the panel to resize it.
- **Filters (left):** attack type, source report, severity, infection / category (searchable, with severity dot and count), affected city, target country, tag, target port and protocol.
- **Intel charts (all with hover tooltips):**
  - **Attack types** donut: share per type, with a short explanation on hover.
  - **Events by hour and type**: stacked bars; hovering an hour shows its breakdown.
  - **Severity mix** bar: click a segment to filter by that severity.
  - **Source networks** and **destination networks**: company names, ASNs on hover.
- **Everything in an analysis is clickable for a further analysis:** every breakdown (reports, attack types, infections, cities, source and destination networks, C2 domains, destination IPs, target countries, target ports, user agents, request paths, severity, tags), the donuts, the severity bar and legend, the figures, the drill-down rows and the host table. The **hourly and 15-minute charts** are clickable too: a bar opens a **Time window** analysis (for example "18:00 to 19:00 UTC · android.badbox2") within the same selection.
- **Top-bar figures open the whole-day analysis** (with any active filters) at the matching list: Events yesterday → all events by infection and report; Replayed so far → the time window from 00:00 to the exact replay position (same count as the top bar); Source hosts → hosts ranked for follow-up; Reports → the reports; Cross-report hosts → hosts in several reports; Critical → critical events with their hosts.
- **Tooltips on touch screens** close by themselves after a few seconds, or at once on any new tap, scroll or opened panel.
- **Deep dive inside an analysis:** every click inside an analysis (a breakdown entry, a donut slice, the severity bar, a chart bar, a row of a Details list or of the host table) narrows it instead of jumping away. For example an infection (10,000 events) → one network (7,500) → port 80 (6,000) → one user agent (500) → 00:00 to 01:00 (15). The selection's parts show as chips under the title: click a part to open it on its own (for example a host with all of its reports), or × to remove it and widen again.
- **Filter map works for every analysis:** it sets the map, the stream and Intel to exactly that analysis' selection, every part of it, including networks, destination IPs, destination cities, user agents and request paths (also in demo mode, through concealed references). Only a time window is not applied: the replay itself is the time axis.
- **One filter model everywhere:** the map, stream, Intel, `/api/events`, `/api/stats`, `/api/geo` and the analyses all accept the same fields (`source, attack_class, infection, severity, protocol, tag, src_city, src_geo, src_asn, src_ip, dst_geo, dst_city, dst_asn, dst_ip, dst_port, http_host, http_agent, request`), so an analysis and the filtered map always show the same numbers.
- **Deep dive with filters:** Intel always reflects the active filters, and so does everything you click in it. With several filters (for example Botnet C2 + one city), an Intel entry opens a **Filtered selection** analysis combining them with what you clicked ("Attack type: Botnet C2 · Affected city: … · Source network: …", with the same number of events Intel shows), and an Intel hour or 15-minute bar opens that time window within all the filters. The figures, findings, charts and follow-up lists all work inside it, and its own bars go down to 15 minutes. In demo mode, concealed values (destination IPs, domains, user agents, paths) are sent as opaque references only the server can resolve, so they stay hidden but still open their analysis.
- **Accurate whole-day figures:** the top bar, Intel, the analysis view and its lists always count **every record of every report for the replayed day** (00:00 to 24:00 UTC). The replay drives only the map and the event stream; the numbers change only if late rows arrive in MongoDB (picked up by the 10-minute day reload).
- **Shared results, computed once per data change** (`respcache.py`): the statistics, filter lists, overview and whole-day map layer of the map platform and the services statistics are kept in memory under a key naming everything they depend on: the loaded day (its start, the moment it was loaded and its version, which changes whenever MongoDB has new or different rows), the filters, demo mode, the constituency and the network names. Other viewers of the same selection get the stored answer at once; when a report arrives the day is reloaded, the key changes and the next request recomputes. Simultaneous requests for the same key compute once (the others wait for that result). What depends on the replay moment (`as_of`, the current quarter and hour) is worked out per request.
- **Executive lookups:** network sector, company and region / city names are worked out once per distinct value per request.
- **Executive 7-day baseline from compact past days:** each of the 7 days before the report day is loaded once and kept in a compact form (only the 13 fields the Executive figures read, repeated text stored once), so any filter or clicked combination gets its baseline from memory in about a second instead of 14 MongoDB day loads. A day is loaded again when its row counts in MongoDB change or the constituency changes. `MGMT_PAST_RECORDS` (default 3,000,000) caps the records kept; above it the oldest days are loaded as before. The compact days give exactly the same complete Executive answers as the full days.
- **Intel (right):** 24-hour activity chart (real counts per 15 minutes from `extracted_date` for the whole day; hover any bar for its count; the white bar marks the replay position), attack types, source reports, top infections / categories, most affected cities, contacted C2 / sinkhole domains and target countries.
  - Click any item to open the **analysis** view. Every chart in it has hover tooltips, and clicking a segment or row drills further:
    - KPIs and key findings
    - beside the findings, two donuts:
      - a **composition donut** using the first breakdown that splits the selection: attack type, infection / category, report, target country or affected city
      - a **networks donut**: source networks, or destination networks when analysing a source network
    - **Events by hour and type** (stacked)
    - **Activity today** in 15-minute bars
    - **Severity mix**
    - breakdown lists and the most active source hosts
  - Every breakdown row and host row can be clicked to drill further (city → infection → C2 domain → host). **Back** returns to the previous view, and **Filter map** applies that entity as a filter.
- **Design:** neutral grey surfaces with one blue accent. Severity colors are used only for severity; infections use a separate palette with no red. Type is Inter for the UI (tabular numbers) and Geist Mono for IPs, hashes and timestamps.
- **Below 1440 px**, Intel moves into a tab in the left panel. **Below 1100 px**, the left panel becomes a ☰ drawer. **On phones**, the stream is a bottom sheet of cards (tap the grabber to expand), and the detail view opens full screen.

## The quarterly report and the purge (`quarterly.py`, `quarterly_pdf.py`)

**When.** A background check (every 10 minutes, in the running service only) makes the previous quarter's report the
first time it runs after 00:00 UTC on the next quarter's 3rd day (`make_due`, `MAKE_ON_DAY`; the quarter's last day's
reports arrive the day after it), if that quarter ended after the feature was first
installed (`data/quarterly/state.json`) and has no report yet. An administrator can make an ended quarter again
(`POST /api/admin/quarterly/make`, CSRF, in the background, one at a time, a lock file across processes). A quarter
whose rows the pipeline already purged is refused: it can no longer be counted.

**Counting.** Read only: `find`, `aggregate` and `count_documents`. The quarter is chosen by `filename` (it starts with
the report day and is indexed): from the first day, up to (not including) the next quarter's first day. Which field is
the constituent's host comes from the platforms' own registries: single-host reports (`services.ServiceRegistry`) use
`ip / asn / region / sector`; communications (`sources.Registry`) the first prefix of `sources.PREFIXES[layout]`
(`src_`, none for the legacy layout, `http_referer_`; `dst_` for destination-only reports). MongoDB groups the rows by
(month, network, host); Python counts the groups, so no document ever holds a network's addresses (an `$addToSet`
would hit MongoDB's 16 MB limit). Addresses are kept only in memory, as hashes, and never written. Readable names
come from `services.service_of` / `sources`, network names from the AS-number registry (`AsnRegistry.company`), regions
in title case like the platforms, infections from `data/infections.json`, CVE names from the CVE cache only
(`cves.CveIntel`, nothing downloaded): CISA's KEV name, else the issuer's title, else the name the description gives
("aka a Terrapin attack"), else its first sentence or subject when short, else the id alone; the full description is in
the advisor's issues CSV. Workflow figures come from `findings.Findings` and `advisory.Store` / `advisory.Impact`.
"Vs the previous quarter" uses the previous quarter's kept `summary.json` (made before its rows were purged), or counts
it from MongoDB when there is none.

**Accuracy checks (guards), every time.** 1 the months add up to the quarter for every report and network; 2 unique
addresses never exceed records, and the all-reports uniques lie between the largest report's and the sum; 3 an
independent `count_documents` recount equals every report's total and month; 4 nothing lost (records = with a network
+ unknown network); 5 the purge's dry count equals `count_documents` and the cutoff keeps the last 31 days; 6 the counts
of advisories and decisions equal the items listed, approved + rejected + waiting = decisions; 7 the first and last day
are in and the days either side out; 8 after writing, no output holds an address (any address of the data, by its
hash, or any address-shaped text that is not part of a published CVE text): every output is removed and the run fails.
A collection that cannot be read is listed, never skipped silently. Any failure: NOT VALID, on the first line of every
CSV and at the top of every PDF page.

**Kept** in `data/quarterly/<YYYYQn>/` (owner-only; built in a temporary folder and put in place in one step): the
two PDFs (`executive_pdf.Doc`'s look; every text whole, rows grow, tables carry on over pages), five CSVs (`csvsafe`),
`status.json`, `summary.json`, `purge_permit.json` (VALID, made before the purge day, and the purge turned on only) and
`purge_result.json`. `status.json` also records `purge_on` (the switch when it was made) and `no_permit_why`.

**The purge's switch** (`data/quarterly/purge_confirmed.json`, mode 600, written only by `quarterly.set_purge` through
the route below): `{enabled, by, by_name, at, at_ts, shown}`, where `shown` is what the page showed (quarter, rows,
purge day, cutoff). Missing, unreadable or anything but `"enabled": true` is off, and off is the default on every
installation. One rule decides a permit, `quarterly.permit_rule`: VALID, made on or before the purge day, the purge on,
the purge day not passed. Turning it on writes the permit for the newest kept quarter when that rule allows it;
turning it off removes every waiting permit; each kept quarter's `status.json` is updated with why it has none
(`WHY_OFF`, `WHY_ON_LATE`, ...). The switch is written first, so the pipeline refuses at once when it is turned off. It
never runs while a report is being made (the same `data/quarterly/.lock`). The PDFs' retention page, the advisor PDF's
"Keep your copy" and the admin CSV's head say whether the purge was on or off when they were made.

**Who gets what (one rule, `quarterly.may_see` / `quarterly.may_download`).** Each file has one audience (`FILES`):
the management PDF and summary CSV the management role; the advisor PDF and three CSVs the advisor role; the purge CSV
administrators. An audience needs its permission (`management`, `advisory`, `settings`), and for the two portals an
account whose role is not `admin`: admin accounts hold every permission (`auth.DEFAULT_ROLES["admin"]`) only to
preview the portals, and the `management` and `advisory` permissions are otherwise exclusive to their roles
(`auth.EXCLUSIVE_PERMS`). The lists and the download routes use the same rule: an admin's portal list carries no files
and a `note` ("Quarterly reports are for management only: ..."), and every management or advisor file route answers
403 to an admin. A file of another audience on a route is refused (403); an unknown kind or quarter is 404.

**Routes.** Downloads are attachments, so `insider.py` seals them; CSVs get a second line "Downloaded, <full name>
(<account>), <time UTC>"; each is in the audit log (`quarterly_download`). The page fetches each file
(`LGLoader.download` in `loader.js`, the one download helper of every page: fetch (POST with headers when needed),
blob, a temporary link (`saveBlob`) named from `Content-Disposition`, `filename*` first; one retry when there was no
answer; plain-words errors), never a plain link with a `download` attribute. A file the page builds itself (a
drill-down CSV) is fetched with `LGLoader.fetchForFile` and saved with `LGLoader.saveBlob`. `tests/check_downloads.py`
keeps every download route audited and every page on the helper.

| Route | Who | What |
|---|---|---|
| `GET /api/mgmt/quarterly`, `GET /api/mgmt/quarterly/<Q>/<kind>` | list: `management`; files: the management role (not an admin) | the management PDF and summary CSV |
| `GET /api/advisory/quarterly`, `GET /api/advisory/quarterly/<Q>/<kind>` | list: `advisory`; files: the advisor role (not an admin) | the advisor PDF and three CSVs |
| `GET /api/admin/quarterly`, `GET /api/admin/quarterly/<Q>/<kind>` | `settings` | the purge CSV only, the checks, the purge's status, the quarters that can be made again |
| `POST /api/admin/quarterly/make` `{quarter}` | `settings`, CSRF | make an ended quarter again (audit `quarterly_made`); only a quarter `can_make` offers (409 otherwise) |
| `POST /api/admin/quarterly/purge` `{enabled, password, shown}` | `settings`, CSRF, a session under 12 hours, the administrator's own password (`password_policy.check_own_password`, the same re-check as Settings → Workers and Password policy: a wrong one counts as a failed sign-in, audit `quarterly_purge_password_failed`) | turn the quarterly purge on or off (audit `quarterly_purge_on` / `quarterly_purge_off`: who, the rows it would delete then, the permits written or removed). Turning it on refuses (409) when `shown` is no longer what the purge would delete; the same state twice is refused (409) |

`GET /api/admin/quarterly` also returns `purge`: `{enabled, since, by, by_name, preview}`; `preview` is the newest VALID
report's quarter, dry count (`rows_purge_deletes`), purge day, cutoff, whether that day has passed and whether its
permit is waiting, and `next`, the rule's next purge day.

**The constituency (r89).** The reports count only the hosts in the constituency, with the platforms' own settings
object and rule (`settings.Settings.in_scope`, passed as `ctx["settings"]`; a communication is kept when its source or
destination host is in it, as the map's day loader does). `quarterly.keep_host` applies it to each stage-1 group (for a
communication the group key then also carries the other side's AS number and address); the rows outside it are counted
apart (`rep_out`), so guard 3 checks `count_documents` = counted + outside, and guards 1, 2 and 4 hold on the counted
figures. `quarterly.constituency` gives `{label, key}`: "the whole country" or "N networks and M address ranges (the
constituency set in Settings)", in `status.json` (`constituency`, `constituency_key`, `rows_outside_constituency`),
`summary.json`, every CSV's head ("Counted for") and the PDFs' Read me. A kept previous summary counted for another
key is flagged in "better or worse" ("counted for a different constituency"); reports made before r89 count as the
whole country. The purge is not scoped: `purge_all`, the admin CSV's stored rows and the PDFs' purge rows are the whole
database and say "all networks in the database, not only the constituency".

**What the cards say (true now).** Every list returns `now` (`quarterly.stands`: an ended quarter whose reports are not
made yet, then the quarter in progress, with the dates the role needs: management and advisors the day to download by
while the purge is on, administrators the purge day and the cutoff), `purge_state` (the switch today) and, per quarter,
`purge_text` (`quarterly.purge_fact`: purged, NOT VALID, made after its purge day, purge day passed, off, the permit's
dates), `rows` (`status.json`, or the kept `summary.json` for reports made before r89) and `empty_text`
(`quarterly.empty_text`, when the quarter has no report rows). The admin list also returns `can_make`
(`quarterly.can_make`: ended, the last four, from the oldest report day on, not purged), `can_make_note` and
`oldest_day`. The oldest report day (`quarterly.oldest_day`: one indexed `find_one` per report collection, sorted by
`filename`, never a scan) is cached in `data/quarterly/state.json` (`oldest_day`, `oldest_checked_ts`); the background
check refreshes it every `OLDEST_EVERY` (6 hours), and making a report or taking a purge's result refreshes it too. The
PDFs keep what was true when they were made ("when this report was made"); the CSVs are unchanged. A quarter with no
report rows: the sentence on every PDF page (`QDoc.new_page`) and as the CSVs' third line ("No report rows", ...).

**The bell** (`system_alerts.Alerts._quarterly` → `quarterly.bell`): an alert may name the permissions that see it
(`perms`) and where it leads for each (`links`); without them it is for administrators, as before. Ready: management,
advisors and administrators, until the purge day; with the purge off it says no report rows are deleted. While the
purge is off and a VALID report exists: "The quarterly purge is off" for administrators, once per quarter (its key names
the newest VALID quarter). NOT VALID, the purge done (7 days), and a purge the pipeline refused although the permit was
written: administrators.

**The purge** is the pipeline's (`quarterly_purge.py` beside `shadowserver_pipeline.py`, run after loading): it refuses
unless the platform's `data/quarterly/purge_confirmed.json` says `"enabled": true` (read like the permit: read-only,
never through a symbolic link, a plain file of 64 KB at most, untrusted; "the purge is not turned on in Settings →
Quarterly", logged once per quarter), reads the permit read-only (never through a symbolic link), works out the dates itself, deletes `filename` < cutoff (a report
day prefix) from the report collections only (`report_names.valid`, not `files_*` / `discovered_fields_*` / `lg_*`, with
the filename index), one at a time, records each collection's count in `<DATA_DIR>/quarterly_purge_status.json`, and
afterwards leaves out files dated before the cutoff when loading. The platform copies a done purge into the quarter's
`purge_result.json` once and writes the audit entry `quarterly_purge` (rows, collections, cutoff, when).

## Security, accounts and deployment

Every page needs a sign-in with a password and an authenticator code. People request accounts on the sign-in page
(full name, organisation, email, country) and administrators approve them with a role: external (masked data
only), analyst (all data, exports, Malpedia), Researcher/TI (the Definitions page), management (the Executive portal),
advisor (the Advisory portal), auditor (the Audit portal only, read only) or admin. "Stay signed in" keeps a session
for up to 5 days. Admins manage users, sessions, roles and permissions on the **Admin** page; the audit log is read in
the **Audit portal** (`/audit`). An optional password expiry policy is set in Settings (`password_policy.py`).

External accounts (permissions exactly "view"): `external_access.py` holds the allow-list of exact paths (the map, the
services platform, Abused or Compromised and what every account needs). The sign-in gate refuses every other page and
API before it runs. Abused or Compromised masks their rows with `masked_fields.intelligence_row`. Free text (`detail`,
`reason`, `user_agent`) is shown as "hidden" and never offered as a filter, and the ransomware victims report is left
out of their view entirely (`intelligence.EXTERNAL_LEFT_OUT`: the report list, the report and the group totals), with
the group-only row masking kept as a second guard (`INTEL_FREE_TEXT`, `INTEL_VICTIM_KEPT`); `tests/check_external_masking.py` checks both with made-up records that name
organisations in plain words.

The audit log and its evidence, module by module:
- `audit_chain.py`: the hash-chained audit log, its archives on rotation and the retention removals recorded in the chain.
- `audit_portal.py`: the Audit portal's pages and API, the control checks LG-01 to LG-15 and the access review.
- `control_map.py`: NIST SP 800-53 Rev. 5 controls → CIS Controls v8.1 safeguards, taken unchanged from CIS's
  official mapping (CC BY-NC-ND 4.0 content, not under AGPL).
- `audit_report.py`: the evidence report (PDF). `audit_proof.py`: the proof package (log files, `audit_log.csv`,
  manifest) and the continuity check. `audit_verifier.py`: the standalone verifier shipped in the package.
- `sender_audit.py`: the Audit portal's Sender check page (DKIM results, keys, new report types).

The pipeline from Settings → Workers: `pipeline_settings.py` (the page's API: unlock with the administrator's password,
requests, the API key check, held-back reports) and `pipeline_link.py` (finds the pipeline beside the platform). The
rules themselves live in the pipeline's `worker_settings.py`, which the platform loads read-only; a request that
weakens the pipeline also needs `./confirm_request.sh` on the pipeline's account. Held-back reports are listed by their
report files' Shadowserver names (`report_files.py`: day, report and readable report name; a name of any other shape
is flagged). `POST /api/pipeline/release` takes one id (`id`) or several chosen on the page (`ids`, up to 500); several
become one release request (`qids`), refused whole when any id is not a held-back report, so one confirmation on the
server releases them all.

Passkeys and the fresh check: `passkeys.py` (registration and sign-in with Duo Labs' py_webauthn: the store in
`data/passkeys.json`, single-use challenges of 5 minutes, the site's name taken from its host name; an IP address
is refused, since browsers refuse passkeys there) and `stepup.py` (the table of high-value actions, the check before
every request, the 10-minute window, the single-use confirmation for the every-time actions, Your account
(`/account`, `/api/passkeys`) and the administrators' passkey reset). The page asks through `static/js/lg-stepup.js`:
a request answered 403 with `stepup` opens the dialog, and is sent again with the one-time confirmation.

The sign-in check: `signin_check.py` answers one question for sign-in (`auth.py`) and the fresh check (`stepup.py`):
passkey or code. `SIGNIN_CHECK` in `.env` wins; then the administrators' choice (`data/signin_check.json`, mode 600,
read again when the file changes); then the default, passkey only for `ACCESS_MODE=public` with Caddy in front for a
domain (`/etc/caddy/Caddyfile` written by `deploy/caddy_front.sh`, not `--internal`). `GET` and `POST
/api/admin/signin-check` ('settings', CSRF, a recent sign-in, every-time confirmation) change it; passkeys are refused
without HTTPS and a host name, or before the administrator has two. Tested by `tests/check_signin_check.py`.

Settings → Update: `platform_update.py` (`GET` and `POST /api/admin/update`: 'settings', CSRF, a recent sign-in; an
update, not a check, asks for the every-time confirmation) only writes `data/update/request.json` (mode 600) and shows
`data/update/status.json` and `log.jsonl`. The work is `deploy/update_run.py`, started by the path unit
`deploy/looking-glass-update.path.template` as the installation's user (`deploy/update_helper.sh`; the service
template allows writing only the Looking Glass folder). It reuses `deploy/verify_install.py` for the release
repository, the signing key's fingerprint and the allowed-signers file. Tested by `tests/check_platform_update.py`
against a made-up repository with tags signed by a made-up key.

No sign-in names in pages: `person_code.py` gives each account an opaque code (HMAC-SHA256 of the sign-in name with
the installation's own random key, `data/person_code.key`: 32 bytes, mode 600, made once on first use and the same for
every worker; `p-` and 20 hex characters). Removing the key file only changes the codes (map pins in browsers are
cleared). Templates get it as `lg_me` (the `data-user` attribute: map pins per
account); `/api/findings/people` lists people by code and `findings.recipient()` turns a code back into the account
only among those offered; `notes.py` says `mine` instead of the author's sign-in name. Tested by
`tests/check_no_signin_names.py`, which walks every GET route as every role but admin.

Naming people (`people.py`): pages, answers, PDFs and downloads name a person by their registered full name, else by
the name saved with the record, else by their person code; never by the sign-in name, also for an account removed
since. `People.name()` does it for lists (findings history, the bell, severity ratings, the Task monitor, the Pipeline
e-mail checks, the quarterly purge switch, the password policy), and `people.signed_by()` gives
"Full Name (p-...)" or the code alone for every "Generated ... by" line of a PDF, the advisory's `generated_by` (when
no organisation name is set) and every CSV stamp. Only three places show sign-in names, because they identify accounts: the Audit portal's audit
trail, Trace a leak's user column and the Admin page's users table. A new passkey's WebAuthn user handle is the
person code (`passkeys.user_handle`); passkeys registered earlier keep the sign-in name as their handle and still sign
in, since a passkey is found by its credential id. Signing out (`POST /logout`) needs the session's own CSRF token
(every Log out form sends it); without it the session stays and the browser goes back to the home page, so another
site cannot sign someone out.

Connectors (the guide: [CONNECTORS.md](CONNECTORS.md)): `connectors.py` (Settings → Connectors: targets, the
encrypted key store, the test before saving, the API), `connector_net.py` (every outgoing connection: HTTPS only,
the address resolved once and refused when it is loopback, link-local, a cloud metadata address or reserved, the
certificate and name checked, no redirects, a size cap), `connector_payload.py` (what is sent: STIX 2.1 for OpenCTI,
a MISP event) and `connectors_worker.py` (the sender, run by its own systemd timer: `deploy/connectors_timer.sh`).

Error words in answers: `user_words.py`. An answer shows an error's text only when Looking Glass wrote it for the
reader (raised as `Said`, or registered, as the connectors' refusals are); any other error, a library's or Python's
own, gets a fixed message, and its detail goes to the audit or the service's log. The connectors and the passkey
checks answer this way (`tests/check_user_words.py`).

- **`docs/SECURITY.md`:** how Looking Glass is secured, the operator checklist, checking an installation and reporting a vulnerability.
- **`docs/INSTALLATION.md`:** installing on Windows with WSL or on a Linux server, HTTPS, firewall, updating, troubleshooting.

Every CSV the platform hands out (report ZIPs, the services host list, Executive tables, and the browser downloads) passes
through one guard (`csvsafe.py`, the same rule in `app.js` / `services.js`): a cell that a spreadsheet would run as a
formula (`=`, `+`, `-`, `@`, tab, line breaks, their full-width forms) gets a leading apostrophe; numbers and the `-`
placeholder are left as they are.

Security scripts:
- `security_testing/security_retest.py`: about 120 checks of every protection against the running service.
  Where passkeys are in force (the sign-in check, `signin_check.py`) its temporary accounts register two passkeys made by the test (in
  memory, removed with the accounts at the end) and sign in and confirm actions with them; it reaches the service as
  `localhost`, since passkeys need a host name.
- `manage/manage_users.py`: accounts on the command line (recovery when no administrator can sign in).
- `deploy/create_readonly_db_user.py`: a read-only MongoDB account for the app.
- `deploy/make_tls_cert.sh`: HTTPS for other screens.
- `python app.py` (development) listens on 127.0.0.1 unless `BIND_HOST` says otherwise; the service itself runs
  under gunicorn with its own bind setting.
- IP addresses inside text are found by one module, `ip_find.py`, for every masker (the researchers' `hostmask.py` and
  partial masking, and the masked viewers' `host_label.py`), so no spelling escapes one and not the other.
  It masks anything shaped like an address, letters glued on or not (`v41.66.1.2`, `id_41.66.1.2`), but keeps a
  four-part number the text itself names as a version, with nothing glued after it: after a version word and a
  separator (`version 2.0.1.3`, `Build: 1.2.3.4`, `firmware=10.4.0.12`) or after a product name and a slash
  (`Apache/2.0.1.3`; a path such as `/api/41.66.1.2` stays masked). A five-part number such as `1.2.3.4.5` is never
  an address, in either masker.
- Display time zone (`timezones.py`, Settings > Country, `TIMEZONE`): every time is UTC as Shadowserver writes it,
  and a day is 00:00 to 24:00 UTC; nothing is converted when loading or counting. `/api/clock`, `/api/svc/clock`,
  `/api/overview`, `/api/settings/public` and the Executive data carry `tz` ({zone, city, offset, same_as_utc}) for
  the replay day, and the pages show the same moment in that zone beside UTC with `static/js/localtime.js` (the
  browser's own time-zone database, so daylight saving is right). The Executive PDF does the same with `timezones.py`.
- CIS in the Audit portal (`control_map.py`): `NIST_TO_CIS` and `CIS_TITLES` are CIS's mapping, unchanged (CC BY-NC-ND
  4.0). Looking Glass's own reading is kept apart in the same file: `BACKED` (check → safeguard → condition on the
  check's facts, CIS's figures: 45 days dormant, 90 days retention, weekly reviews, MFA required), `NOT_BACKED`
  (safeguard → reason), `RELATED_NOTE`, `lg_reading(check, safeguard, facts)`; a pair whose condition fails, and
  every other pair, is "related". `audit_portal.py` passes the facts the checks computed. `cis_for(nist, check)`
  returns CIS's fields plus an `lg` field, which the portal shows as a separate badge and the PDF as a line marked
  "Looking Glass:". `CERTIFICATION_NOTE` ("The CIS Controls are used here as a map...") goes with the data.
- Data access logging (`data_access.py`, CIS 3.14): an `after_request` hook writes `data_viewed` for answered GETs of
  `/api/events`, `/api/svc/events`, `/api/related`, `/api/insight`, `/api/insight/drill`, `/api/svc/insight`,
  `/api/svc/drill`, `/api/svc/detail`, and `data_exported` for `/api/svc/hosts.csv`. The detail is every request
  parameter except display and time options (`IGNORE`: at, demo, from, to, limit, latest, since, time, n, format, page,
  sort), repeated parameters included, so a parameter added later is logged by default. Each value is cut to 120
  characters before the address finder reads it (a half address at the cut is dropped), and every address is replaced
  by its host reference (`HostRefs`); a view is one entry per person and selection per 10 minutes, a download is
  an entry every time (the same list twice included); not for the installation check;
  `DATA_ACCESS_LOG=0` turns the views off; `data_exported` (downloads) is always written.
- The address finder (`ip_find.py`) reads IPv6 candidates of at most 45 characters and 7 colons, split where three or
  more colons stand together, so its work grows with the text's length (thousands of colons: milliseconds). An
  IPv4-mapped address (`::ffff:41.66.1.2`) is that IPv4 host, masked whole, with the same label.
- Advisories: each generated report keeps a fingerprint of the heading, subject, TLP, Description and Recommended
  Actions (`advisory.content_sig`). When the advisory no longer matches it, the report is out of date
  (`report_stale` in the page's data), and drafted and sent are refused (409) until it is generated again.
- Dialogs (`static/js/dialog-focus.js`, loaded on every page by `loader.js`): any element marked `aria-modal="true"`
  counts as a dialog while it is shown. Focus moves into it, Tab and Shift+Tab stay inside the top-most one, closing
  returns focus to what opened it, and Escape with two or more open closes only the top-most. On a phone or tablet the
  filter drawer is marked as a dialog while it covers the page. Page scripts drop answers that arrive after the user
  moved on (sequence counters), say when a request failed instead of waiting forever, and disable a button while its
  request runs.
- The sign-in page shows only the notices Looking Glass sends (`auth.LOGIN_NOTICES`); user names and e-mail addresses
  that differ only in letter case are one; an authenticator code is checked again under the accounts lock, so two
  sign-ins with the same code at once cannot both pass.
- Executive PDF (`executive_pdf.py`): text is never cut. `fit()` keeps the whole text, smaller (to 80 %, never under
  6 pt) or on two lines; `wrap(max_lines=)` sets it smaller rather than cutting; Key findings take the largest size at
  which all of them fit, and continue on a page of their own if needed.
- The other PDFs cut no text either: `reports_pdf._cell` prints a table cell whole and lets a row split across pages
  (the report downloads' PDFs); `advisory_pdf.py` breaks a long word (a URL) onto the next line;
  `quarterly_pdf.py` continues the Read me notes on the next page.
- Special Reports (`special_reports.py`): Shadowserver's one-off datasets (`YYYY-MM-DD-special[-<name>]-...`, often a
  placeholder 00:00 time on every row). The pipeline loads each into its own `special_<name>` (`special` when it has
  no name): `report_names.special_name` cuts the name where the country part begins, learnt from the ordinary reports
  (whose names hold no hyphen), or else at the last word before `-geo`; both registries (`sources.py`, `services.py`)
  skip every `special*` collection, so they never enter the replay, totals or baselines; `/api/overview` carries
  `special`: per collection and shared date, rows and distinct hosts (counts only, cached 10 minutes and counted in a
  background thread: a page gets the last count at once, an expired one is refreshed behind it), shown on the
  intro page.
- Executive portal figures (`management.py`): lists are ranked by distinct devices (IP addresses) when they are known,
  records breaking ties; the 7-day baseline keeps every infection and issue of each past day (`item_count` reads a
  missing item in an old top-80 summary as unknown, never 0).
- Parts of the installation check that read the reports database are skipped when MongoDB cannot be reached: they
  report SKIPPED (exit 77) instead of a connection error.
- Scheduled jobs (`job_schedule.py`): one table lists every scheduled job of the platform and the pipeline, with its
  time, how long it may take, and the lock it takes. `tests/check_job_overlap.py` simulates the schedule minute by
  minute. It fails when two heavy jobs could overlap without a lock, when a lock in the table is not taken in the code,
  or when a heavy job falls in working hours.
- Code integrity: the release builder writes `.release_fingerprints` (SHA-256 of every shipped file) beside
  `.release_files`. `code_integrity.py` runs the daily check (`/api/admin/code-check`, plus `/approve` and
  `/quarantine`, both POST: the `settings` permission, the CSRF token, a session younger than 12 hours and the
  administrator's password again). `deploy/verify_install.py` compares with the local list or, with `--fetch`, with the
  list in the signed tag. The service file (`deploy/service_unit.py`) sets `ReadOnlyPaths` on the folder,
  `ReadWritePaths` and `NoExecPaths` on `data/`.
- Software bill of materials: `tools/make_sbom.py` writes `looking-glass-sbom.spdx.json` (SPDX 2.3) from the
  hash-locked requirements, with each library's exact version and hash. `tests/check_sbom.py` checks that it matches
  the locks.

## Scripts

### Checking everything

- **`bash tests/run_all_checks.sh`** runs the whole installation check in one go and prints one line per check. The checks are read-only against this installation's own database and service; the collection checks use throwaway databases that they drop. It runs the **installation's checks**: those that tell whether this installation works and is safe, and need nothing an installation does not have. The **maintainer's checks** (listed with their reasons in `tests/maintainer_rows.txt`: the pages' scripts run under Node, real browsers, rendered PDFs, the source tree, docs and release files, the installer and Caddy scripts in scratch folders, every route with bad input) are not part of an installation's checks: they are not run there and not counted. The release checklist and the GitHub checks run both: `bash tests/maintainer_checks.sh` (the same as `LG_SUITE=all bash tests/run_all_checks.sh`), which needs Node, Playwright with Chromium and pypdfium2, and fails rather than skips when one is missing (`LG_NO_SKIP=1`). Settings for those runs:
  - `LG_SUITE`: `installation` (the default) or `all`;
  - `LG_NO_SKIP=1`: a check that cannot run here fails, with what is missing, instead of being skipped;
  - `LG_TEST_SYSTEM=1` with `LG_TEST_SYSTEM_DB` (default `lg_demo`): on a test system with made-up data only, the
    constituency check sets a temporary constituency, checks it and restores `data/settings.json` byte for byte; it
    refuses anywhere else;
  - `LG_THROWAWAY_MONGO=host:port`: the checks that need a database account that may write ask only that throwaway
    server, never the installation's;
  - `LG_CONSTITUENCY_CHECK=<script>`: the constituency row runs that script instead (a development machine runs it on
    a test system);
  - `LG_DB_DIR`: the pipeline folder to test, instead of the one beside the platform;
  - `LG_ROWS_ELSEWHERE=<file>` and `LG_ROWS_ONLY=<file>` (one test file per line): a release run split over two
    machines. A development machine whose own service is not the new build leaves the rows that check the running
    service to a test system (`ELSEWHERE`, counted), and the test system runs exactly those (`ONLY`);
  - `LG_SCREENSHOTS_AT_END=1`: the docs screenshot check runs at the release's screenshot stage, on the final build,
    because the screenshots are retaken last.

  The checks are:
  - replay schedule;
  - new communications and services collections;
  - services consistency (28 filter combinations);
  - services and communications totals against MongoDB;
  - **statistics and filters**: every figure is worked out a second time straight in MongoDB, with aggregation pipelines that derive the fields on their own, and compared with the running service: the headline figures of the statistics and the overview, every top list, the 96 quarter-hour timeline, the hourly chart, the top networks per company, every filter on its own (its 3 most common values and the rarest) on the statistics, the map and the replayed count, combinations of filters, the *unknown* / *untagged* / *unrated* labels, and the edges (unknown filter names, values that do not exist, `at=` outside the two days served, the 30-minute window and the limits of `/api/events`). It also reports, without failing, how many filter values one request can carry (a web-server limit of about 8 KB) and how fast the statistics answer under load. Skipped when a constituency is set (the constituency check covers that) or when the day has no records yet;
  - **services statistics**: the services platform worked out a second time from the raw MongoDB documents with the check's own code (tags, issues, products, families): the headline figures, every whole-day breakdown with its host counts, every filter (3 most common values and the rarest), combinations, vulnerable only, the *unknown …* labels;
  - **Executive portal**: both portals' figures, hourly chart and lists, the filters, every day of the 7-day baseline and every grade (recomputed), and the clickable "Top findings" combinations (narrowed to one, the portal must count exactly its devices or hosts);
  - **reports**: analysis reports of both platforms and both Executive reports are downloaded (ZIP and PDF alone); every PDF opens, every CSV has as many rows as the on-screen list and as MongoDB, the combination CSVs add up to the portal's figures and the 7-day trend CSV matches the portal. Each download is an audit entry of the automation account;
  - **CSV formula safety**: planted formula values through the guard, the code (no CSV is
    written without it, the browser rule is run on the same values) and every cell of the real downloads;
  - replayed counts;
  - constituency;
  - **demo masking**: no real address, AS number, network name or host name in any masked answer
    of either platform (Demo button and roles without *unmasked*), raw addresses and real network names as filters find
    nothing, pins never outlive the account. It first proves it finds real values in unmasked answers, so it can fail;
  - **privacy and roles**: IP and text masking, aliases, host references,
    strict filters, role rules and people's names, on invented values;
  - **Intel gathered** and **researchers' notes** (on a throwaway notes file): researchers get them, other roles are refused, no constituent address in any answer, notes reach the cards
    and the PDF reports;
  - **several reports / multiple issues**: for every report family and the busiest reports, the figure, the analysis table, the filtered view, every bubble, what clicking a bubble shows and the regions map must agree with an independent count straight from MongoDB; it also checks that a filtered stream finds the latest records however long ago.
- While the intro page is open, it refreshes the services card within about 15 seconds of a new services collection, late services records or a field-check result. Communications changes refresh it straight from the map's clock.
- The "replay paused while this tab was in the background" notice appears only on the platforms, not over the intro page; the replay still pauses and resumes as before.
- Checks that need no database, among others:
  - `check_job_overlap.py`: no two heavy jobs overlap without a lock;
  - `check_code_readonly.py`: the service writes only in `data/`;
  - `check_code_integrity.py`: the daily code check, its findings and the administrator's choices;
  - `check_sbom.py`: the SBOM matches the locks;
  - `check_spdx_headers.py`: every shipped source file carries the SPDX licence and copyright lines within its first 10 lines; third-party files are listed with their own licences;
  - `check_cov_*.py`: tests that reach the branches the other checks do not. Statement and branch coverage is measured with `coverage.py`.
- **Proven count laws.** Before each release the maintainers also prove a set of counting laws, written in the Bend
  language, and compare each with the real code on 300 made-up datasets. The first four (a to d) are about the
  report-day rule for sinkholed devices: a device is counted only when its record and its call to a sinkhole fall on
  the same report day, a device that made no call counts as none, and each device counts once. Laws e to h prove that
  the Executive portal's sectors add up (e); that shares never read "0%" or "100%" wrongly and a page gives the same
  words as its PDF (f); that a cut list's rows and its Other part add up to the total (g); and that every page puts a
  record in the same sector, region and network (h). This lab is not part of the release.

- `tools/envcheck.sh` checks Python, venv and whether MongoDB (`MONGO_HOST`/`MONGO_PORT` from `.env`) is reachable.
- `tools/quickcheck.py` checks the connection, lists every report collection with its size and filename index, and times the replay day's count.
- `tools/daysize.py [YYYY-MM-DD]` (default yesterday) shows one day's rows and files per report, its time range, top tags and countries.
- `tools/list_infections.py [YYYY-MM-DD]` lists every infection of that day (any day, not only the replay day).
- `tools/discover.py` surveys every collection: size, indexes, src/dst fields, latest document and yesterday's row count. It writes `data/discovery.json` (mode 600, never into the code folder), every value taken from a record masked first (`hostmask.py`), and `tools/show_srcdst.py` prints the matching collections from it.
- `deploy/reload.sh` restarts the systemd service without sudo: it kills the main process and systemd starts it again (`sudo systemctl restart looking-glass` does the same).
- `manage/backup.sh [dest]` creates a timestamped archive of the project, including `.env` and everything in `data/` but not `.venv`, encrypted as it is written to the public key in `data/backup_public_key` (age or GnuPG; `manage/backup_crypt.sh`), saved as `~/backups/<project folder>-<UTC time>.tar.gz.age` (or `.gpg`) with a signed `.sha256` file and mode 600. Without a key it refuses; `--unencrypted` writes a plain `.tar.gz` on purpose.
