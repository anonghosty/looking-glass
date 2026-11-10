# Shadowserver Pipeline (Looking Glass database)

Pulls your CSIRT's Shadowserver report e-mails, unzips and sorts the reports by service, and loads them into MongoDB,
where the Looking Glass platform (`../platform`) reads them. It works for any country: Shadowserver names each report
file after your report profile (`...-ghana-geo.csv`, `...-kenya-geo.csv`, `...-south-africa-geo.csv`), and the pipeline
accepts them all.

It replaces the two original scripts with one faster, restartable pipeline that writes **exactly the same database structure**:

| Before | Now |
|---|---|
| `pull_emails_and_create_services.py` (step 1) | `shadowserver run --stage email` |
| `mongo_added_json.py` (step 2) | `shadowserver run --stage load` |
| both, one after the other | `shadowserver run` |

The original two scripts are still in the folder for reference. The new pipeline does not use them. Like the
pipeline, they take their mailbox and database settings from `.env`; no password is written in any script.

---

## Contents

1. [Quick start](#1-quick-start)
2. [How it works](#2-how-it-works)
3. [Command reference](#3-command-reference)
4. [Reading the output](#4-reading-the-output)
5. [Scheduling the runs](#5-scheduling-the-runs)
6. [Configuration (`.env`)](#6-configuration-env)
7. [MongoDB: install, layout and administration](#7-mongodb-install-layout-and-administration)
8. [Folders and files](#8-folders-and-files)
9. [Performance and memory](#9-performance-and-memory)
10. [Compatibility with the original scripts](#10-compatibility-with-the-original-scripts)
11. [Reliability](#11-reliability)
12. [Testing](#12-testing)
13. [Troubleshooting](#13-troubleshooting)
14. [Security notes](#14-security-notes)
15. [Uninstalling](#15-uninstalling)

---

## 1. Quick start

The simplest way is the installer at the top of the repository (`../install.sh`): it asks for the mailbox and
MongoDB settings, checks them, and runs everything below for you. By hand:

```bash
cd looking-glass/database      # this folder
cp .env.example .env && chmod 600 .env && nano .env   # mailbox (docs/MAIL_SETUP.md) and MongoDB (section 6)
./deploy.sh                     # first time: installs everything (asks for your sudo password)
shadowserver run                # pull e-mails, sort, load into MongoDB
shadowserver status             # how did it go?
```

Other things you will use often:

```bash
shadowserver run --days 8       # catch up on the last 8 days of e-mail
shadowserver run --stage load   # (re)load report files already on disk, no e-mail
shadowserver schedule every 30m # run automatically every 30 minutes (recommended)
shadowserver logs -f            # watch a run in progress
shadowserver check              # verify the whole setup
shadowserver help               # all commands     |  man shadowserver  for the full manual
```

Requirements: Ubuntu 24.04 or later, Desktop or Server, on the computer itself, in a virtual machine or as Ubuntu on WSL 2 on Windows (tested on 26.04), with systemd (on WSL:
`/etc/wsl.conf` → `[boot] systemd=true`), Python 3.12+, internet access, sudo rights for `deploy`, and a mailbox that
receives your Shadowserver reports (sign up for free at https://www.shadowserver.org/what-we-do/network-reporting/).

---

## 2. How it works

```
 IMAP mailbox (read-only)
        │  step 1: e-mail
        ▼
 attachments_backup/          ← attachments + files downloaded from dl.shadowserver.org links
        │  step 2: unzip + sort
        ├──────────────► unzipped_backup/<zip name>/     (non-report files from each zip)
        ▼
 sorting_backup/<service>/    ← report CSVs, one folder per service (scan_http, blocklist, ...)
        │  step 3: load
        ▼
 MongoDB  database "shadowserver"
        <service>                    one document per unique CSV row
        discovered_fields_<service>  one document per CSV column
        files_<service>              one document per file
```

**Step 1, e-mail.** The pipeline reads the mailbox **read-only** (messages stay unread) over IMAP, the Gmail API (Google Workspace) or Microsoft Graph (Microsoft 365): `MAIL_PROVIDER`, set up as described in [docs/MAIL_SETUP.md](../docs/MAIL_SETUP.md). E-mails and links already handled on an earlier run are skipped (`.mail_state.sqlite`), so a run with nothing new takes a second or two. It fetches all messages received in the last `N` days (default 1 = since yesterday), 25 per round trip. New attachments are saved to `attachments_backup/`; attachments that are already there are skipped. If an e-mail brought no new attachment, its `https://dl.shadowserver.org/...` links are downloaded instead, 4 at a time. This is the same rule as the original script.

**Step 2, unzip and sort.** Each zip is extracted once; a zip already extracted on an earlier run is skipped. Files whose name matches the report pattern

```
YYYY-MM-DD-<service>[-<number>]-<country>-geo[_asNNNN].csv
```

(`<number>` is Shadowserver's id for the receiving CSIRT, any number of digits, for example `123`; `<country>` is the country as Shadowserver names it, for example `cote-d-ivoire` or `south-africa`. If your reports are named differently,
set `REPORT_SUFFIX` in `.env`.)

go straight to `sorting_backup/<service>/`, replacing an older copy. Everything else in the zip goes to `unzipped_backup/<zip name>/`. Corrupt zips are deleted. Report CSVs that arrived unzipped are moved to their service folder the same way.

**Step 3, load.** For each service folder, one query finds which files are already in MongoDB. Only new files are loaded, by 6 worker processes in parallel, biggest files first. Each CSV row becomes one document; duplicate rows within a file are dropped, and the database's unique index rejects rows that are already stored.

If the e-mail step fails (mail server down, network), the pipeline logs the error and still sorts and loads what is already on disk.

---

## 3. Command reference

After `./deploy.sh`, the `shadowserver` command works from any folder and has tab completion: type `shadowserver <Tab>`. Inside the project folder the scripts `./run.sh`, `./check.sh` and `./deploy.sh` do the same jobs and take the same options.

### `shadowserver run [options]`: run the pipeline

| Option | Meaning | Default |
|---|---|---|
| `--stage all` | e-mail → unzip/sort → load | ✔ |
| `--stage email` | only e-mail and unzip/sort, no database | |
| `--stage load` | only load `sorting_backup/` into MongoDB, no e-mail | |
| `--days N` | pull e-mails from the last `N` days | `EMAIL_DAYS` = 1 |
| `--workers N` | parallel loader processes (~100–200 MB RAM each) | `WORKERS` = 6 |
| `-q`, `--quiet` | summary lines only (used by the daily schedule) | |
| `-v`, `--verbose` | also list attachments that were already saved, plus debug info | |
| `--check` | run the setup checks and exit | |
| `--env-file PATH` | use another settings file | `./.env` |
| `-h`, `--help` | short help | |
| `--man` | full manual | |

Options without a command mean `run`, so `shadowserver --days 8` is the same as `shadowserver run --days 8`.

Only one run can be active at a time. A second run (for example the scheduled one while you run it by hand) prints `Another pipeline run is in progress - exiting.` and stops.

**Exit codes:** `0` success · `1` a file failed to load, the e-mail step failed, a check failed, or another run was active · `130` stopped with Ctrl-C (unfinished files resume next run).

### `shadowserver status`: one-screen overview

```
MongoDB:       active (enabled at boot), memory 104 MB
Database:      shadowserver: 90 services, 750,000 rows
Files:         800 report CSV files in sorting_backup/
Running:       no
Last log:      /home/analyst/looking-glass/database/logs/pipeline-2026-11-06.log
               ... E-mail: 0 attachments saved, 1100 skipped | links: 1150 downloaded, 40 skipped, 0 failed (210.0s)
               ... Load: 800 files, 750,000 rows inserted, 0 duplicates skipped, ... (14.0s)
               ... Done in 225.0s
Schedule:      every day at 06:30 (shadowserver schedule off to remove)
```

(The numbers are invented for illustration.)

### `shadowserver check`: full setup check

Checks, and prints `OK` / `WARN` / `FAIL` for each:

- **MongoDB:** `mongod`, `mongosh` and the database tools are installed; the `mongod` service is running and starts with WSL; its memory limit, its current memory use, and `/etc/mongod.conf` (localhost only, login required).
- **Pipeline:** `.env` exists with mode 600 and all required settings; Python packages; the three data folders; free memory; MongoDB login; cache size.
- **Data:** every service collection has the unique index, a sample document has the expected structure, and the row total; service folders not yet loaded; interrupted loads waiting to resume.
- **E-mail:** a real IMAP login (read-only).
- **Schedule:** the daily run time.

Exit code 1 if any check fails. Needs no sudo.

### `shadowserver logs [-f] [N]`

Shows the last `N` lines (default 40) of the newest log. `-f` keeps following it live; Ctrl-C stops following, not the run.

### `shadowserver schedule [HH:MM | off | show]`

Sets, shows or removes the daily automatic run. See [section 5](#5-scheduling-the-runs).

### `shadowserver deploy [options]`: install or update everything

Safe to run as often as you like; it only changes what is out of date. It asks for sudo.

| Option | Meaning |
|---|---|
| *(none)* | install/update MongoDB, its config and memory limit, the MongoDB user, the Python environment, data folders, the global command, its man page and tab completion; then run `check` |
| `--schedule HH:MM` | also set the daily run (same as `shadowserver schedule HH:MM`) |
| `--unschedule` | remove the daily run (same as `shadowserver schedule off`) |
| `--remove-container` | delete the old Docker MongoDB container and its volume (only allowed after its data was migrated) |
| `--uninstall-commands` | remove the global command, man page and completion (project files stay) |
| `-h`, `--help` | show these options |

### `shadowserver help` · `shadowserver man` · `shadowserver version`

Short help, the full manual (also `man shadowserver`), and the version with the project folder.

---

## 4. Reading the output

By default every action gets a line, like the original scripts:

```
IMAP: 1200 message(s) in 'inbox' since 29-Oct-2026 (user@...)
[EMAIL 12/1200] Thu, 05 Nov 2026 03:12:44 +0000 | <subject> | 1 new attachment(s)
    [ATTACHMENT] saved 2026-11-05-scan_http-country-geo.zip (412.3 KB)
[EMAIL 13/1200] ... | 1 already saved, 1 new link(s)
-- progress: 100/1200 e-mails (8%) | attachments: 37 new, 60 already saved | links found: 12 | 4s
[LINK 3/53] downloaded 2026-10-30-scan_vnc-123-country-geo.csv (88.1 KB)
[LINK 4/53] already exists: 2026-10-30-scan_ssl-123-country-geo.csv
Unzip: 40 zip(s) in attachments_backup, 12 new to extract, 28 already extracted earlier
[UNZIP 2/12] 2026-11-05-scan_http-country-geo.zip -> 1 report CSV(s)
    [SORT] 2026-11-05-scan_http-country-geo.csv -> scan_http      (OVERWRITE = replaced an older copy)
[MOVE] 2026-10-30-scan_vnc-123-country-geo.csv -> scan_vnc      (report CSV that arrived unzipped)
Service folders populated: 90 (800 CSV files)
  - scan_http: 9 file(s)
[SCAN] scan_http                     9 file(s):     8 already in MongoDB,     1 to load
[LOAD 5/412] scan_http/2026-11-05-scan_http-country-geo.csv: 1,200 rows inserted (0.1s)
  120/412 files | 360,000 rows inserted | 98000 rows/s
Load: 412 files, ... rows inserted, ... duplicates skipped, ... (12.3s)
Done in 226.5s
```

(File names and counts in this sample are illustrative.)

- **WARNING / ERROR** lines name the file and the reason. Anything that failed is retried on the next run.
- `already in DB` on a `[LOAD]` line means rows rejected by the unique index; this is normal when a file is reloaded.
- `bad timestamp skipped` counts rows whose `timestamp` could not be read. The original script skipped these rows too.
- `--quiet` keeps only the summary lines; `-v` adds `[SKIP]` lines for attachments already saved.

Everything is also appended to `logs/pipeline-YYYY-MM-DD.log`.

---

## 5. Scheduling the runs

Shadowserver sends reports throughout the day, so run the pipeline often; every 30 minutes is recommended.

```bash
shadowserver schedule every 30m # every 30 minutes (minutes: 5 10 15 20 30; or every 1/2/3/4/6/8/12h)
shadowserver schedule 06:30     # or once a day at 06:30 (24-hour clock); a new schedule replaces the old
shadowserver schedule           # show the current schedule
shadowserver schedule off       # remove it
```

- It is a cron job for your own user: no sudo needed. You can see it with `crontab -l` (marked `# shadowserver-pipeline`). Other cron jobs you have are left alone.
- It runs `run.sh --quiet`: the e-mail of the last `EMAIL_DAYS` days (the installer asks for it, right after the schedule; 7 recommended — e-mails already fetched are skipped, so a run catches up by itself after the computer was off), then unzip/sort, then load. Output goes to `logs/pipeline-YYYY-MM-DD.log`; read it with `shadowserver logs` or `shadowserver status`.
- If a manual run is still going at that time, the scheduled run skips itself.

> **Important on WSL:** cron only fires while WSL is running. WSL shuts itself down when no terminal or app uses it. Keep a WSL terminal open at the scheduled time, or start WSL before it. If a day was missed, catch up with `shadowserver run --days N`.

---

## 6. Configuration (`.env`)

All settings live in `.env` in the project folder. Its permissions are `600`, so only your user can read it, because it holds the passwords. `.env.example` is the documented template.

- Values are read **literally**, with no shell expansion, so `$`, `#` and `@` in passwords are fine.
- Quotes around values are optional.
- Changes apply on the next run. MongoDB settings apply after `shadowserver deploy`.

| Setting | Meaning | Default |
|---|---|---|
| `MAIL_PROVIDER` | `imap`, `gmail_api` or `microsoft_graph` ([docs/MAIL_SETUP.md](../docs/MAIL_SETUP.md)) | `imap` |
| `GMAIL_SERVICE_ACCOUNT_FILE`, `GMAIL_USER`, `GMAIL_LABEL` | Gmail API: service account key, mailbox, label | –, –, `INBOX` |
| `MS_TENANT_ID`, `MS_CLIENT_ID`, `MS_CLIENT_SECRET`, `MS_MAILBOX`, `MS_FOLDER` | Microsoft Graph app registration and mailbox | –, –, –, –, `inbox` |
| `IMAP_SERVER` | mail server | – |
| `IMAP_USER` / `IMAP_PASSWORD` | mailbox login | – |
| `IMAP_FOLDER` | folder to read | `inbox` |
| `IMAP_VERIFY_TLS` | verify the mail server certificate (`false` only for a self-signed certificate) | `true` in `.env.example` |
| `EMAIL_DAYS` | default for `--days`: how many days back every run (also the scheduled ones) looks | `7` in `.env.example` (asked by the installer); `1` when unset |
| `MONGO_HOST` / `MONGO_PORT` | MongoDB address | `127.0.0.1` / `27017` |
| `MONGO_USER` / `MONGO_PASSWORD` | MongoDB login (created by `deploy` as a root user) | – |
| `MONGO_AUTH_SOURCE` | authentication database | `admin` |
| `MONGO_DB` | database name | `shadowserver` |
| `MONGO_LOCAL` | `true` = MongoDB on this computer (installed by `deploy`); `false` = on another server, nothing installed here | `true` |
| `MONGO_BIND` | addresses the local MongoDB listens on (add this server's address when the platform runs elsewhere; firewall it) | `127.0.0.1` |
| `MONGO_TAKE_OVER` | `true` lets `deploy` reconfigure a MongoDB that was installed before Looking Glass; otherwise it refuses, and such a MongoDB is used as it is with `MONGO_LOCAL=false` | `false` |
| `MONGO_SERIES` | MongoDB release installed by `deploy` | `8.0` |
| `MONGO_CACHE_GB` | WiredTiger cache size | `1.5` |
| `MONGO_MEMORY_LIMIT` | hard memory cap for the `mongod` service | `3g` |
| `DATA_DIR` | where the three data folders live (empty = project folder) | project folder |
| `WORKERS` | parallel loader processes | `6` |
| `INSERT_CHUNK` | rows per bulk insert | `2000` |
| `DOWNLOAD_THREADS` | parallel link downloads | `4` |
| `IMAP_FETCH_BATCH` | e-mails fetched per IMAP round trip | `25` |
| `REPORT_SUFFIX` | regular expression for the part of report file names after the service (`<country>-geo`) | any `<name>-geo` |

---

## 7. MongoDB: install, layout and administration

### How it is installed

`deploy` installs MongoDB **natively** (no Docker), following MongoDB's official guide
<https://www.mongodb.com/docs/v8.0/tutorial/install-mongodb-on-ubuntu/>:

- **Packages:** `mongodb-org` 8.0 from `repo.mongodb.org`. That gives `mongod` 8.0.34, `mongosh` 2.14.1, and `mongodump`/`mongorestore` 100.20.1. MongoDB does not publish packages for Ubuntu 26.04 yet, so `deploy` uses the official **Ubuntu 24.04 (noble)** build, which runs on 26.04. It switches to native 26.04 packages automatically once MongoDB publishes them.
- **Signing key:** `/usr/share/keyrings/mongodb-server-8.0.gpg`. **Source list:** `/etc/apt/sources.list.d/mongodb-org-8.0.list`.
- **Config:** `/etc/mongod.conf`, written by `deploy`; the original is kept as `/etc/mongod.conf.orig`. It sets:
  - listen on `127.0.0.1` only, port 27017
  - `authorization: enabled`
  - WiredTiger cache 1.5 GB
  - data in `/var/lib/mongodb`, log in `/var/log/mongodb/mongod.log`
- **Service:** systemd `mongod`, enabled so it starts with WSL. The drop-in `/etc/systemd/system/mongod.service.d/shadowserver.conf` adds `MemoryMax=3G`, `LimitNOFILE=64000` and restart-on-failure.
- **User:** `MONGO_USER` from `.env`, with the `root` role in `admin`. The pipeline logs in exactly like the original scripts did.

### Database layout (identical to the original scripts)

Database `shadowserver`:

| Collection | One document per | Fields |
|---|---|---|
| `<service>` (e.g. `scan_http`) | unique CSV row | all CSV columns (as text) + `filename`, `category` (= service), `line_hash` (SHA-256 of the row's values joined with `,`), and, when `timestamp` is `YYYY-MM-DD HH:MM:SS`: `logged_date` (text) and `extracted_date` (date) |
| `discovered_fields_<service>` | CSV column seen | `category`, `field_name` |
| `files_<service>` | file in the service folder | `filename`, `category`, `path` |

- **Index:** `<service>` has a unique index on `(filename, category, line_hash)`, the same as before.
- **JSON files:** a JSON file in a service folder becomes one document: `filename`, `category`, `line_hash` (of the whole file) plus the JSON fields, as before.

### Everyday administration

```bash
sudo systemctl status mongod                 # service state
sudo systemctl restart mongod                # restart
sudo tail -f /var/log/mongodb/mongod.log     # MongoDB's own log
mongosh -u <MONGO_USER> --authenticationDatabase admin shadowserver   # shell (asks for the password)
```

Example `mongosh` queries:

```javascript
show collections
db.scan_http.countDocuments()
db.scan_http.find({ ip: "192.0.2.10" }).limit(5)
db.scan_http.find({ extracted_date: { $gte: ISODate("2026-11-01") } }).count()
db.discovered_fields_scan_http.find({}, { field_name: 1, _id: 0 })
```

### Backup and restore

```bash
mkdir -p backups                 # in this folder
mongodump  -u <MONGO_USER> --authenticationDatabase admin --db shadowserver \
           --archive=backups/shadowserver-$(date +%F).archive.gz --gzip
mongorestore -u <MONGO_USER> --authenticationDatabase admin \
           --archive=backups/shadowserver-2026-11-06.archive.gz --gzip
```

Both ask for the password.

**Rebuilding without a backup:** the database can always be rebuilt from the report files on disk with `shadowserver run --stage load` (about 15 s for 800 files).

To bring over data from the **old server**, run `mongodump` there and `mongorestore` here. The structure is the same.

### The earlier Docker container

The very first setup ran MongoDB in a Docker container. `deploy` looks for that container (`shadowserver-mongo`). If it finds it, it:

1. exports its data to `backups/`,
2. restores the data into the native MongoDB,
3. checks that the document counts match,
4. stops the container.

`shadowserver deploy --remove-container` then deletes the container and its volume, and refuses to do so until that move has been verified. If the container no longer exists, nothing is done; reload from the files instead.

---

## 8. Folders and files

```
database/
├── shadowserver_pipeline.py      the pipeline (all three steps + --check, --test-mail)
├── mail_sources.py               reading the mailbox: IMAP, Gmail API, Microsoft Graph
├── docs/MAIL_SETUP.md            how to create the mailbox credentials (Google, Microsoft, IMAP)
├── run.sh                        runs the pipeline with a lock and a log file
├── check.sh                      setup checks (MongoDB service + pipeline --check)
├── deploy.sh                     installs/updates everything (sudo)
├── bin/
│   ├── shadowserver              the global command (linked from /usr/local/bin)
│   └── shadowserver-completion.bash   tab completion (linked from /etc/bash_completion.d)
├── docs/shadowserver.1           the manual (linked from /usr/local/share/man/man1)
├── .env                          settings + passwords (mode 600, never share)
├── .env.example                  documented template
├── requirements.txt              Python packages (pymongo, requests)
├── .venv/                        Python virtual environment (created by deploy)
├── tests/
│   ├── test_equivalence.py       old-vs-new document comparison (no MongoDB needed)
│   └── selftest_compare.py       end-to-end old-vs-new comparison in MongoDB + timings
├── attachments_backup/           saved attachments and downloaded link files
├── unzipped_backup/<zip>/        non-report files from each zip (a zip is extracted only once)
├── sorting_backup/<service>/     report CSVs by service - the input of the load step
├── logs/pipeline-YYYY-MM-DD.log  run logs (appended per day)
├── backups/                      database exports made by deploy
├── .pipeline_state.sqlite        files whose load was interrupted (resumed next run)
├── .pipeline.lock                prevents two runs at once
├── pull_emails_and_create_services.py   original script (reference only; settings from .env)
└── mongo_added_json.py                  original script (reference only; settings from .env)
```

Installed outside the project by `deploy`:

- **Global links:** `/usr/local/bin/shadowserver`, `/usr/local/share/man/man1/shadowserver.1`, `/etc/bash_completion.d/shadowserver`. They are links into the project, so changes to the project files show up immediately.
- **MongoDB:** `/etc/mongod.conf`, `/etc/systemd/system/mongod.service.d/shadowserver.conf`, `/etc/apt/sources.list.d/mongodb-org-8.0.list`, data in `/var/lib/mongodb`.
- **Schedule:** your user's crontab, only if you set a daily run.

---

## 9. Performance and memory

### Measured on this machine

| | Original scripts | New pipeline |
|---|---|---|
| Load 600k rows (120 files), same data | 21.2 s | **4.9 s (4.4× faster)**, ~123,000 rows/s |
| Re-run with nothing new | one query + one `files_` insert per file, every run | **0.0 s** |
| A full run, `--days 8` | – | loading takes seconds; most of the time (a few minutes) is spent downloading the report links |

The gap grows as the database grows, because the original did per-file lookups and re-inserted every `files_` entry on every run.

### Why it is faster

- **Parallel loading:** files load in 6 worker processes, biggest first, so the pool stays busy.
- **One query per service:** a single query finds the files already in MongoDB, instead of one query per file.
- **Bulk writes:** `files_` and `discovered_fields_` are written in bulk, and only for new entries.
- **Streaming:** CSVs are read line by line and inserted 2,000 rows at a time, so memory stays flat no matter how big a file is.
- **Faster timestamps:** timestamp parsing is about 4.6× faster (0.8 µs instead of 3.7 µs per row, measured), with exactly the same result as before.
- **Faster e-mail:** IMAP fetches 25 messages per round trip; link downloads and unzipping run in parallel threads.
- **Extract once:** each zip is extracted a single time, and report CSVs go straight to their service folder instead of being moved afterwards.

### Memory budget (WSL VM with ~11.5 GB)

| Part | Limit |
|---|---|
| MongoDB cache | 1.5 GB (`MONGO_CACHE_GB`) |
| MongoDB total | hard cap 3 GB (`MONGO_MEMORY_LIMIT`); idle about 100 MB |
| Loader workers | 6 × ~100–200 MB (`WORKERS`) |
| E-mail step | about 25 messages in memory at a time (`IMAP_FETCH_BATCH`) |

Everything together stays under about 5 GB, which leaves plenty for Windows and other work.

- **Tight on memory:** lower `WORKERS`, or `MONGO_CACHE_GB` together with `MONGO_MEMORY_LIMIT`.
- **Memory to spare:** raise them.
- After changing the MongoDB values, run `shadowserver deploy`.

---

## 10. Compatibility with the original scripts

**Unchanged:**

- Database name, collection names, document fields and field order, value types, `line_hash` values, the unique index, and the `discovered_fields_` / `files_` documents. This was proven by the tests in [section 12](#12-testing).
- How the service name is taken from a report's file name. (The pattern accepts any country.)
- Duplicate rows within a file are dropped. Rows with an unreadable `timestamp` are skipped. A file that already has rows in MongoDB is not loaded again.
- By default, e-mails since yesterday are pulled, and the mail server certificate is not verified.
- An e-mail without a new attachment falls back to its download links.
- Corrupt zips are deleted. A newer copy of a report replaces the older one in its service folder.

**Deliberate changes (improvements):**

| Original behaviour | Now |
|---|---|
| Fetching marked e-mails as **read** | Mailbox opened read-only; e-mails stay unread |
| `files_<service>` got a **duplicate entry for every file on every run** | One entry per file |
| A CSV row with more values than headers made the **bulk insert fail**, losing other rows sent with it | That row is stored with its header columns; a warning is logged |
| A file with non-UTF-8 bytes **crashed the whole run** | Loaded with the bad bytes replaced; a warning is logged |
| An interrupted load could leave a file **half-loaded forever** (it then counted as "already loaded") | Interrupted files are finished on the next run |
| A failed download could leave a **broken file** that blocked re-downloading | Files are downloaded to a temporary name and renamed when complete |
| Link files without a name got a **random** fallback name each run | Stable name derived from the URL |
| Attachment names containing `/` could write **outside the folder** | Names are cleaned |
| Passwords in the scripts | Passwords in `.env` (mode 600) |
| An unreachable mail server **stopped everything** | Error logged; files on disk are still sorted and loaded |

**Same limitation as before:** files that don't match the report pattern stay in `attachments_backup/` and are not loaded. Example: `...-gh_tld-rhost.csv`. Ask if you want such reports included.

---

## 11. Reliability

- **No overlapping runs:** `run.sh` takes a lock (`.pipeline.lock`). The lock is released automatically when the process ends, even after a crash, so it never needs cleaning up.
- **Resume after interruption:** files whose load started are recorded in `.pipeline_state.sqlite` until they finish. After Ctrl-C, a crash or a WSL shutdown, the next run completes them. The unique index prevents duplicate rows.
- **Retries:** a link download is retried 3 times. A dropped MongoDB connection is retried with back-off.
- **Partial work is invisible:** downloads and attachments are written to `.part` files, and zips are extracted into `.partial` folders, then renamed. An interrupted run never leaves a half-written file under its final name.
- **MongoDB restarts itself** if it crashes (systemd `Restart=on-failure`) and starts with WSL.

---

## 12. Testing

```bash
.venv/bin/python -m unittest discover -s tests -v      # in this folder
```

**Unit tests** (`tests/test_equivalence.py`, no MongoDB needed) run the original row-processing code and the new code on the same tricky files and compare the documents: keys, key order, values and types. Edge cases covered:

- byte-order mark and Windows line endings
- blank lines and duplicate rows
- bad and unusual timestamps
- missing columns, and files that already have `logged_date`/`extracted_date` columns
- quoted multi-line fields, odd line-break characters, duplicate headers
- a `filename` column inside the CSV
- empty files and header-only files
- JSON files

They also test that the fast timestamp parser matches `strptime`, and the service-name pattern.

**End-to-end comparison** (`tests/selftest_compare.py`) builds a test dataset and loads it with the **original** `mongo_added_json.py` and with the new pipeline, into two throw-away databases (`shadowserver_selftest_old` / `_new`). It then checks that every collection, document and index is identical, prints the timings, and drops both databases. It never touches the real `shadowserver` database or your data folders.

```bash
.venv/bin/pip install aiofiles async_lru          # only needed to run the original script
.venv/bin/python tests/selftest_compare.py        # default: 120 files x 5000 rows
.venv/bin/python tests/selftest_compare.py --files 10 --rows 2000 --keep   # smaller; keep the data to inspect
```

---

## 13. Troubleshooting

| Problem | What to do |
|---|---|
| `shadowserver: command not found` | Run `./deploy.sh` in the project folder, then open a new terminal |
| Tab completion doesn't work | Open a new terminal (completion loads at shell start) |
| `Permission denied` running a script | `chmod +x *.sh bin/shadowserver` in this folder |
| `Another pipeline run is in progress` | A run is going: `shadowserver status` / `shadowserver logs -f`. Wait, or stop it with Ctrl-C in its terminal |
| `check` shows `service mongod  inactive` | `sudo systemctl start mongod`; if it fails: `sudo tail -n 50 /var/log/mongodb/mongod.log` |
| `mongodb connection ... Authentication failed` | `MONGO_USER`/`MONGO_PASSWORD` in `.env` don't match the MongoDB user. Fix `.env` or reset the password in `mongosh` |
| `imap login FAIL` | Check `IMAP_*` in `.env`, the network/VPN, and that the mailbox password hasn't changed |
| `E-mail step failed ... (continuing with files already on disk)` | Same as above; the rest of the run still worked |
| `[LINK ...] FAILED ... HTTP 404/410` | Shadowserver links expire after a while. Run more often, or with a smaller `--days` |
| `[UNZIP] FAILED ...` | Logged with the reason; that zip is retried next run |
| Daily run didn't happen | Was WSL running at that time? (see [section 5](#5-scheduling-the-runs)). Check `shadowserver schedule` and `systemctl is-active cron`, then catch up with `shadowserver run --days N` |
| A service is missing in MongoDB | `shadowserver check` lists service folders not yet loaded. Run `shadowserver run --stage load` |
| A report file is never loaded | Its name doesn't match the report pattern ([section 10](#10-compatibility-with-the-original-scripts)) |
| WSL runs out of memory | Lower `WORKERS` and/or `MONGO_CACHE_GB` + `MONGO_MEMORY_LIMIT` in `.env`, then `shadowserver deploy` |
| `deploy` says `Ubuntu's 'mongodb' package is installed` | `sudo apt-get remove mongodb`, then deploy again (it conflicts with the official packages) |
| Database empty after reinstalling | `shadowserver run --stage load` rebuilds it from `sorting_backup/` |

For details on any run: `shadowserver logs 200`, or open `logs/pipeline-YYYY-MM-DD.log`.

---

## 14. Security notes

- `.env` holds the mailbox and database passwords. It is mode `600`, listed in `.gitignore`, and should never be shared or committed.
- MongoDB listens on `127.0.0.1` only (not reachable from the network) and requires a login.
- Passwords are never put on the command line by the scripts. `deploy` passes them through environment variables and temporary mode-600 files, so they don't show up in `ps`.
- The mail server certificate is **not** verified (`IMAP_VERIFY_TLS=false`), the same as the original script. Set it to `true` if the server has a valid certificate.
- The mailbox is opened read-only; the pipeline never changes, moves or deletes e-mails.
- The MongoDB user has the `root` role, matching the original setup. For extra safety you could create a user limited to `readWrite` on `shadowserver`.
- The Looking Glass platform does not use this account: `platform/deploy/create_readonly_db_user.py` gives it its own read-only account.

---

## 15. Uninstalling

```bash
shadowserver schedule off                    # stop the daily run
shadowserver deploy --uninstall-commands     # remove the global command, man page, completion
```

To remove MongoDB as well, as in MongoDB's guide. **This deletes all data:**

```bash
sudo systemctl stop mongod
sudo apt-get purge 'mongodb-org*'
sudo rm -r /var/log/mongodb /var/lib/mongodb
sudo rm -f /etc/apt/sources.list.d/mongodb-org-8.0.list /etc/systemd/system/mongod.service.d/shadowserver.conf
```

This folder is untouched by all of the above. Delete it yourself if you no longer need the reports.
