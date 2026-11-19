# Running Looking Glass day to day

Commands are run in the platform folder as the user the service runs as. Scripts marked ▶ start themselves with the
project's Python (`.venv`); run the others with `.venv/bin/python <script>`.

## Folders

| Folder | What is in it |
|---|---|
| `deploy/` | installing and running the service: `install.sh`, the service template, HTTPS certificate, reload, read-only database account |
| `manage/` | looking after a running installation: accounts, backups, network names, infection knowledge base, region maps |
| `security_testing/` | the security documentation and the installation's security check |
| `tests/` | the installation check: both platforms against the database |
| `tools/` | diagnostics for the database and the reports |
| `docs/` | these guides |

## The service

| Task | Command |
|---|---|
| Restart after a change (no sudo) | `deploy/reload.sh` |
| Status, start, stop | `systemctl status looking-glass`, `sudo systemctl start|stop|restart looking-glass` |
| Logs (live) | `journalctl -u looking-glass -f` |
| Health | `curl -s localhost:5000/healthz` (or `curl -sk https://localhost:5000/healthz` with HTTPS); on this computer only, others get "Not Found" |
| HTTPS certificate for other screens | `deploy/make_tls_cert.sh [extra names or addresses]` ▶ (no sudo; renews by running it again) |
| MongoDB's own log | `/var/log/mongodb/mongod.log`, rotated daily (or past 100 MB), 14 kept, by `/etc/logrotate.d/looking-glass-mongod`. Installed with MongoDB from 2026-11-17; an older installation adds it once: `sudo database/mongo_log_rotation.sh --now` |

The replay needs nothing from you: it waits for each day's reports, then replays the day. The intro page and the
top bar show "Waiting for the reports of …" while it waits.

### Watching it: Settings → Task monitor

Administrators can watch the service without a terminal on **Settings → Task monitor**, refreshed every five seconds
while the tab is open: the web service's memory, CPU, threads and uptime; requests running now and per minute over
the last hour; whether each background job is running; the slowest requests of the last day (every request slower
than `SLOW_REQUEST_S`, by route only); the kept answers; MongoDB's memory; the computer's load, memory, swap and disk;
the pipeline's last run and schedule; recent starts, sign-in locks and the admins' alerts.

Two actions are there, each needing a fresh sign-in and written to the audit log:

- **Keep heavy answers for** (off, 30 s … 30 min; default 3 min, or `CACHE_TTL_S`). The Definitions lists, Intel
  summary and leads and the ATT&CK panel take seconds to compute with a lot of data; Looking Glass keeps each answer for
  that time and computes it for one person at a time. A kept answer is exactly what was computed: always correct, only
  as recent as the time chosen. New reports show within it; anyone's change shows at once.
- **Clear kept answers now**: the next visit computes afresh.

From a terminal: `./manage/slow_requests.py [--days N]` (the slow requests) and `./tools/resource_check.py` (disk and
memory against the budgets in `.env`).

If Intel gathered or the services patterns could not be counted again (a record no rule expected, say), the earlier
counts stay on screen, it is tried again after 30 s, and an alert shows on the administrators' bell and here until it
works; the details are in the service log (`journalctl -u looking-glass`).

### Changing settings without a terminal: Settings → Configuration

Every setting in `.env` is listed there in plain words, with the value in use, where it comes from and its default
([CONFIGURATION.md](CONFIGURATION.md)). The tuning settings (replay, loading, memory and speed, findings, alerts) can
be changed within a safe range: **Save**, then **Restart now** when it suits (about a minute while the days are loaded
again; everyone's pages pause, then carry on). The security, audit and database settings are shown with the exact line
to change in `.env` on the server; passwords and tokens are never shown. Each save and restart needs a recent sign-in
and is in the audit log. A value kept there can be undone with **Use the default**, or by deleting `data/config.json`
and running `deploy/reload.sh`.

## Accounts

Normally done on the **Admin** page ([USER_GUIDE.md](USER_GUIDE.md)). On the command line, for recovery:

```bash
manage/manage_users.py list                 # accounts, roles, MFA, recovery codes left
manage/manage_users.py add NAME --admin     # new administrator (asks for the password, shows the QR key)
manage/manage_users.py help                 # every command: passwd, mfa, role, remove
```

## The HTTPS certificate

A certificate bought for a domain (INSTALLATION.md, B4a) is renewed with `manage/install_cert.sh`, run as Looking
Glass's user. It checks the new certificate first (key, domain, dates, chain) and changes nothing if a check fails;
otherwise it keeps the previous pair in `data/tls/previous-<time>/`, records the renewal in the audit log, reloads the
service and checks the site over HTTPS. The bell warns administrators 30, 14 and 3 days before expiry, and once it has
expired. `manage/install_cert.sh --status` shows the installed certificate and its days left.

## Backups

Run these as the service's own user (the owner of `data/`):

```bash
manage/backup.sh [folder]                                          # default ~/backups; encrypted, mode 600, a .sha256 file and its signature (a second one in the same second: -2)
manage/verify_backup.sh [--identity KEY] [archive] [key.pub]       # the signature and checksum; with your private key, .env and the files
manage/restore_check.sh --identity KEY [archive] [key.pub]         # rehearse a restore, without touching this installation
```
The archive holds the code, `.env` and all of `data/` (accounts, sessions, audit log, settings, certificates), not
`.venv`. Those are secrets, so the archive is **encrypted to your own key** and copied to safe storage off the computer,
with its `.sha256` and `.sha256.sig`.

> **Condition: no public key, no backup.** `manage/backup.sh` refuses to run until your public key is in
> `data/backup_public_key` (or `BACKUP_PUBLIC_KEY` in `.env`): it exits with "NOT BACKED UP" (exit code 3) and
> prints how to make one. Do this once, right after installing or updating. A scheduled backup made before
> 2026-11-15 also stops until the key is there: check its output.

**Encrypted.** The server keeps only a public key; the private key stays with you, off the server, so a backup that
leaves the server, or the server itself if it is broken into, cannot be read with what is on it. Make a key once, on
your own computer, with [age](https://age-encryption.org) or GnuPG (step by step below):

```bash
age-keygen -o looking-glass-backup-key.txt                         # keep this file safe: it opens every backup
age-keygen -y looking-glass-backup-key.txt > backup_public_key     # the public half, for the server
#   or, with GnuPG:  gpg --export --armor you@example.org > backup_public_key
```
Copy `backup_public_key` to `data/backup_public_key` on the server (or point `BACKUP_PUBLIC_KEY` in `.env` at it).

`backup.sh` then streams the archive straight into encryption (`.tar.gz.age` or `.tar.gz.gpg`): no readable copy is
ever written. Without a public key it refuses, and says how to make one; `manage/backup.sh --unencrypted` makes a
plain archive on purpose (not recommended). `age` is `sudo apt install age`; GnuPG is on most servers already. Keep the
private key where you keep other recovery secrets: without it the backups cannot be restored.

**Signed.** The checksum is signed with the installation's key (the same key as the
[audit checkpoints](#audit-checkpoints)) and each backup is recorded in the audit log ("Backup checksum signed", with
its SHA-256). The private key is **not** in the backup; its public key is (`data/audit_signing/signing_key.pub`) and in
the audit log. Keep a copy of `signing_key.pub` with your backups, and give it to `verify_backup.sh` or
`restore_check.sh` when you check a backup on another computer. Both check that the signed checksum is for the very
archive you give them (its name and its SHA-256), and both fail for a backup with no signature or no public key to
check it; for a backup made before backups were signed, add `--allow-unsigned` (first) and they say it was accepted.

The signature and checksum are over the encrypted file, so `verify_backup.sh` checks them without any private key;
give it `--identity <your private key>` to also open the archive, compare `.env` with the live one and count the files.

**Rehearse the restore.** `manage/restore_check.sh --identity <your private key>` checks the signature and checksum,
opens the archive straight into a temporary folder, and checks what a restore needs: `.env`, the accounts (at least one administrator), roles, settings,
the TLS certificate, and the audit log, with the same verifier an auditor runs (chain and signed checkpoints). It ends
with "RESULT: restorable" or says what is missing, and removes the temporary folder. Do it after each change to how
backups are made, and from time to time.

**Restore.**
1. Check the archive: `manage/verify_backup.sh --identity <your private key> <archive> <signing_key.pub>`.
2. Stop the service (`sudo systemctl stop looking-glass`) and move the current folder aside.
3. Open and unpack the archive in the parent folder: `age -d -i <your private key> <archive> | tar -xz` (or
   `gpg --decrypt <archive> | tar -xz`; an unencrypted one: `tar -xzf <archive>`).
4. Run `deploy/install.sh` (it recreates `.venv` and keeps `.env`) and start the service.
5. Sign in, open **Audit portal → Integrity and evidence** and verify the log. The restored installation makes a new
   signing key on first use, recorded in the audit log: note its fingerprint.

A restore brings the audit log back as it was when the backup was made: what was written after it is gone (the backup's
own "Backup checksum signed" entry is written just after the archive, so it is always one of those). Checkpoints and
heads noted after the backup then point beyond the end of the restored log, and the verifier says so. That is the
restore, not tampering: note the restore, the archive and the old and new key fingerprints with the audit papers.

MongoDB itself is backed up with the pipeline ([../../database/README.md](../database/README.md)).

### Making the backup key, step by step

You make the key **once**. It has two halves: the **private key**, which opens every backup and never goes on the
server, and the **public key**, which the server uses to lock each backup.

**On Linux or macOS**

1. Install age: `sudo apt install age` (Debian or Ubuntu) or `brew install age` (macOS).
2. On your own computer, not the server, make the key: `age-keygen -o looking-glass-backup-key.txt`.
3. Take out the public half: `age-keygen -y looking-glass-backup-key.txt > backup_public_key`. It is one line
   starting with `age1`.
4. Copy `backup_public_key` to the server as `data/backup_public_key` in the Looking Glass folder, owned by the
   service's user (for example `scp backup_public_key server:` and then `sudo -u <service user> cp ...`).
5. Run `manage/backup.sh` once and check that it ends with an `.age` file.
6. Put `looking-glass-backup-key.txt` somewhere safe and off the server: a password manager, or an encrypted USB stick
   kept with your other recovery secrets. Keep a second copy somewhere else. Without it the backups cannot be opened.
7. Rehearse a restore with it: `manage/restore_check.sh --identity /path/to/looking-glass-backup-key.txt`, which should
   end with "RESULT: restorable". Then take the key away again.

**On Windows, with Looking Glass in WSL**

1. In the WSL terminal, install age for the server: `sudo apt install age`.
2. In PowerShell on Windows, install age for yourself: `winget install FiloSottile.age` (open a new PowerShell
   afterwards so it is found).
3. In PowerShell, make the key in your own folder: `age-keygen -o looking-glass-backup-key.txt`.
4. Take out the public half: `age-keygen -y looking-glass-backup-key.txt | Out-File -Encoding ascii backup_public_key`.
5. Copy it into Looking Glass's `data` folder. From the WSL terminal, with your Windows folder under `/mnt/c/Users/...`:
   `cp /mnt/c/Users/<you>/backup_public_key ~/<looking glass folder>/data/backup_public_key`.
6. Run `manage/backup.sh` once in WSL and check that it ends with an `.age` file.
7. Rehearse a restore, reading the private key from Windows:
   `manage/restore_check.sh --identity /mnt/c/Users/<you>/looking-glass-backup-key.txt`. It should end with
   "RESULT: restorable".
8. Move `looking-glass-backup-key.txt` off the computer (a password manager or an encrypted USB stick, with a second
   copy elsewhere) and delete it from the Windows folder.

A key file saved on Windows works as it is: a byte-order mark, UTF-16 (what PowerShell's `>` writes) and Windows line
endings are all accepted, for the public key and for the private key given with `--identity`.

**With GnuPG instead:** export your public key with `gpg --export --armor you@example.org > backup_public_key` and copy
it the same way; to open a backup, export your secret key (`gpg --export-secret-keys --armor you@example.org`) to a
file you give with `--identity`.

**If the private key is lost:** the public key is safe to show; the private key is not. If you lose the private key, make a new
pair, replace `data/backup_public_key` and make a fresh backup at once: the older backups stay locked to the lost key.

## Encryption at rest

MongoDB Community does not encrypt its files, and neither do the pipeline's report copies or Looking Glass's `data/`
(accounts, sessions, audit log, settings). On a server they are protected at rest by an **encrypted volume**:

- **Linux:** put the database, the report copies and Looking Glass on a LUKS volume (the installer of Ubuntu and most
  distributions offers "encrypt the disk"; for an existing server, a new LUKS volume for `/var/lib/mongodb` and the
  install folder). An encrypted server needs its key to start: typed at boot, or unlocked by the machine's TPM or a key
  server on your network (Clevis and Tang) for unattended restarts.
- **Windows with WSL:** turn on BitLocker (or Device encryption) for the Windows drive that holds WSL: WSL's disk is a
  file on it.

**Settings → Task monitor → Encryption at rest** shows, for the database, the report copies, Looking Glass's data and
the backups, whether each is on an encrypted volume (looked at every 10 minutes; `at_rest.py`), and the guided
installer says so at the end. Inside WSL it cannot see BitLocker and says to check it in Windows. Backups are
encrypted on their own, to your key ([Backups](#backups)), wherever they are kept. NIST SP 800-53 SC-28 (protection of
information at rest) is met by these two together.

## Audit checkpoints

Every day (`AUDIT_CHECKPOINT_HOURS`, default 24) the service writes a signed checkpoint of the audit log's head to
`data/audit_checkpoints/`, and records it in the log. How it proves the log was not rewritten:
[AUDIT_LOG_PROOF.md](AUDIT_LOG_PROOF.md#between-audits-signed-checkpoints). The checkpoints only protect once a copy is
kept **away from this server**; choose one way:

- **A copy folder:** set `AUDIT_CHECKPOINT_COPY_DIR` to a folder on another computer, mounted here (a network share, a
  disk). Best is a share where the service's user can write new files but not change or delete them. The service may
  write only to `data/` unless told otherwise, so add the folder to its sandbox once:
  ```bash
  sudo systemctl edit looking-glass      # add the two lines below, save, then: sudo systemctl restart looking-glass
  [Service]
  ReadWritePaths=/mnt/lg-checkpoints
  ```
  A copy that fails (the share is not mounted, or not writable) is said in the audit log; the next checkpoint tries
  again.
- **Fetched by another computer:** from a computer of your own, copy the folder regularly with an account that can only
  read it, for example once a day:
  ```bash
  rsync -a --ignore-existing lgcopy@looking-glass-server:/path/to/platform/data/audit_checkpoints/ ~/lg-checkpoints/
  ```

To make one now, or to see the public key and its fingerprint:

```bash
.venv/bin/python audit_checkpoint.py now
.venv/bin/python audit_checkpoint.py key
```

Checkpoints need `ssh-keygen` (package `openssh-client`, on Ubuntu servers by default). Without it they are written
unsigned and the Audit portal says so.

## Reference data

### Network names (`data/asns.json`)
Turns AS numbers into company names ("AS64500" → the operator's name), and gives each network a type and a stable
demo alias. Built from your own data:
```bash
.venv/bin/python manage/asn_registry.py 7      # add the AS numbers seen in the last 7 days
```
New numbers are looked up in RIPEstat and added with `"reviewed": false`. To correct a name, edit `name` and set
`"reviewed": true`; the service picks the change up by itself.

### Infection knowledge base (`data/infections.json`)
What each infection is and the recommended action, shown in the details and analyses.
```bash
.venv/bin/python manage/infections_missing.py 7   # infections seen in 7 days with no entry yet
```
It writes stubs to `data/infections_missing.json`. Research and write the entries (title, type, description,
action, confidence), then add them to `data/infections.json`; open pages pick them up within 10 minutes.

Simpler: give a person the **researcher** role. The **Definitions** page lists the names Malpedia does not know (new
report names appear by themselves) and saves definitions with references to `data/definitions.json`. That file takes
precedence over `data/infections.json`, is never part of a release (so upgrades keep it) and is in the backups.

Updates replace `data/infections.json` and `data/issues.json` (the shipped definitions, signed *Looking Glass*) and
never touch what a site wrote: `data/definitions.json` (site definitions), `data/notes.json` (researchers' notes),
`data/combo_codes.json` (combination codes), `data/findings.json` (findings and their history) and
`data/seen_names.json` (where and when each name was last seen) are run-time files, all in the backups. A site
definition still overrides a shipped one of the same name after an update; to take the shipped one instead, delete the
site's entry from `data/definitions.json`.

### Researchers' notes (`data/notes.json`) and last seen (`data/seen_names.json`)
Notes are written on the Definitions page and shown on every card and in the PDF reports; the author or an
administrator removes them there. The last-seen record fills itself: once from the last 14 days (in the background
after the first start; `data/seen_names.json.done` marks it done, delete both files to rebuild it) and then from every
replay day. It keeps 30 days.

### Combination codes (`data/combo_codes.json`) and findings (`data/findings.json`)
Every code a researcher is shown is written to `data/combo_codes.json`, so an analyst can still resolve it after the days
that produced it have left memory (a code not found there is looked for in memory again). It keeps the twenty thousand most
recently shown. A history search reads at most 31 days, one day at a time, only the reports of that name, in a background
thread (two searches cannot run at once for one analyst); a finished search is held for an hour, in memory and in
`data/combo_exports/` (owner-only files, so a service restart before the download loses nothing), then deleted.
Findings are never deleted by the platform; a closed finding stays under *All*.

### Report definitions (`data/service_reports.json`)
Plain-language definitions of every Shadowserver report, with Shadowserver's severity and a link to its page. When
Shadowserver adds a report type, add an entry with the collection name as key.

### Region maps (`static/data/adm1/`)
A map for every country and territory in the world, grouped by continent in `index.json`. About 200 countries have
first-level regions (geoBoundaries ADM1); the rest are drawn as one area (geoBoundaries ADM0, or Natural Earth for the
few geoBoundaries lacks). Each file carries its own source licence. `manage/fetch_world_boundaries.py --out
static/data/adm1` downloads them all again, and `manage/region_aliases.py` re-links the region names found in reports
to the map regions (needs Ubuntu's `iso-codes` package). Where a report spells a region in a way the map does not
know, an administrator links it on the Settings page (Region names, "Match"); the choices are kept in
`data/region_matches.json`.

### Offline name sources (`data/names_misp_galaxy.json`, `data/names_attack.json`)
MISP Galaxy (Malpedia, Botnet and Tool clusters) and MITRE ATT&CK (malware and tools) explain names that neither the
researchers nor Malpedia explain, and appear under "Also described by" on every card (see the User Guide, Definitions).
`manage/fetch_offline_names.py` downloads them (at most once a week; `--force` now, `--status` to see what is installed).
The installer downloads the first copies (about a minute; an install without internet goes on without them and says so)
and schedules the refresh weekly (`--schedule`: Mondays 04:17 in the user's crontab, tagged `# looking-glass-name-sources`,
one line per installation folder; the uninstaller removes this folder's line;
`--unschedule` removes it). A download that is invalid, too small, or under 70% of the copy in use is refused and the old
copy kept; the reason is in `data/names_refresh.log` and `data/names_refresh.json`, and every refresh (with counts and the
ATT&CK version) is in the audit log. Administrators can also refresh from the Definitions page (**Refresh sources**,
at most once an hour). Look-ups only read these files. The same script downloads MITRE CTID's KEV → ATT&CK mappings
(`data/attack_kev.json`, `--only kev`), and when a new ATT&CK version arrives it compares it with the old one: the report
mappings it touches go back to "please check" (`data/attack_mappings.json`; the rule table that suggests them is the
shipped `data/attack_rules.json`), one notice appears on the Definitions page and one entry in the audit log.

## Checking your installation

| Command | What it checks | Time |
|---|---|---|
| `security_testing/security_retest.py` ▶ | about 120 checks of every security protection against the running service; must end with ALL PASSED | 2 min |
| `tests/run_all_checks.sh` | replay schedule, new reports on both platforms, consistency of every figure, totals against MongoDB, every statistic and filter of both platforms and the Executive portal against MongoDB, report downloads, CSV formula safety, masking (fails on any leak), privacy and roles, Intel gathered, researchers' notes, cross-report filters | 4 min |

The checks only read this installation's own database and service; checks that create reports use throwaway databases and drop them.
They reach the API with the local automation key (`data/automation.key`), accepted from this computer only.

## Diagnostics (`tools/`)

| Script | Shows |
|---|---|
| `tools/envcheck.sh` | Python, venv, and whether MongoDB is reachable |
| `tools/quickcheck.py` | connection, indexes, collection size, a timed sample query |
| `tools/diagnose_reports.py [collection...]` | which reports are used, and what the others lack |
| `tools/discover.py`, `tools/show_srcdst.py` | a survey of every collection (written to `tools/discovery.json`) |
| `tools/analyze_services.py` | the fields of the services reports |
| `tools/daysize.py YYYY-MM-DD` | the size of one day |
| `tools/report_arrivals.py [day]` | when each report of a day arrived in MongoDB |
| `tools/check_reports.py [day]` | MongoDB against what the running service has loaded |
| `tools/list_infections.py [day]` | every infection of a day with counts |
| `tools/malpedia_check.py` | which infections Malpedia knows |

### A report is listed as "not processed yet"
Usually it has no `filename` index. Create one (with an administrator account) in `mongosh`:
```js
use shadowserver
db.<collection>.createIndex({ filename: 1 })
```
The pipeline creates these indexes for every report it loads.
