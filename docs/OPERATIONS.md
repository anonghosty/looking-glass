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
| Health | `curl -s localhost:<your port>/healthz` (or `curl -sk https://localhost:<your port>/healthz` with HTTPS; `<your port>` is the port you selected, `LG_PORT` in `.env`); on this computer only, others get "Not Found" |
| HTTPS certificate for other screens | `deploy/make_tls_cert.sh [extra names or addresses]` ▶ (no sudo; renews by running it again) |
| Caddy in front (public installations) | `sudo deploy/caddy_front.sh status`; to update now: `sudo deploy/caddy_front.sh update` |
| MongoDB's own log | `/var/log/mongodb/mongod.log`, rotated daily (or past 100 MB), 14 kept, by `/etc/logrotate.d/looking-glass-mongod`. Installed with MongoDB from 2026-11-17; an older installation adds it once: `sudo database/mongo_log_rotation.sh --now` |

The replay needs nothing from you: it waits for each day's reports, then replays the day. The intro page and the
top bar show "Waiting for the reports of …" while it waits.

The service may read its code but not change it: its folder is read-only for it, and `data/` is the one place it
writes. If you see "Read-only file system" in its log, something tried to write outside `data/`. Please report it as an
issue.

### Watching it: Settings → Task monitor

Administrators can watch the service without a terminal on **Settings → Task monitor**, refreshed every five seconds
while the tab is open: the web service's memory, CPU, threads and uptime; requests running now and per minute over
the last hour; whether each background job is running; the slowest requests of the last day (every request slower
than `SLOW_REQUEST_S`, by route only); the kept answers; MongoDB's memory; the computer's load, memory, swap and disk;
the pipeline's last run and schedule; recent starts, sign-in locks and the admins' alerts; and **In front of Looking
Glass**: whether Caddy is in front, or, when Looking Glass answers the network itself, the one command that puts Caddy
in front of it (`sudo deploy/caddy_front.sh adopt`, [INSTALLATION.md, B4c](INSTALLATION.md#b4c-caddy-in-front-of-a-running-installation-security)).

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

Normally done on the **Admin** page ([USER_GUIDE.md](USER_GUIDE.md)): approve people who signed up (the bell tells
every administrator), or invite someone with **Users → Add a person** (a one-time sign-up link, 72 hours,
`INVITE_HOURS`). On the command line, for recovery:

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

**Caddy.** On a public installation Caddy updates itself through Ubuntu's automatic updates. The bell tells
administrators when a newer Caddy is available or when its updates do not install by themselves; then run
`sudo deploy/caddy_front.sh update`. It checks the repository's key against the pinned fingerprint first and changes
nothing if it differs, updates Caddy only, keeps Looking Glass's configuration, and checks the site through Caddy.

### When the server's address changes

Looking Glass follows its own addresses by itself (it reads them again every minute). Two settings do not, and the bell
warns administrators when they stop matching (the installation check, `tests/check_addresses.py`, says the same):

- **The self-signed certificate** names the server's addresses as they were when it was made, so other computers get a
  name warning. Make it again, then trust it once more on each screen:
  ```bash
  deploy/make_tls_cert.sh <the name or address people use>
  ```
  (A certificate made before 2026-11-19 also names the product; making it again replaces that too.)
- **MongoDB on a network address** (the pipeline here, the platform on another computer: `MONGO_BIND` in the
  pipeline's `.env`) cannot start on an address the server no longer has. Give the server its address back, or set
  `MONGO_BIND` to the new one, run `database/deploy.sh`, and change `MONGO_HOST` in the platform's `.env`.

Best: give the server a fixed address (a DHCP reservation on your DHCP server or router) or a name people use.

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

> **Caution: keep `data/person_code.key` with `data/`.** It is the installation's key for the per-account codes
> that pages use instead of sign-in names (map pins in the browser, Notes, the people a finding can be sent to).
> Never copy it to another installation, never put it in a ticket or a chat, and do not delete it: deleting it, or
> restoring `data/` from a backup made before this key existed, makes a new key, clears everyone's map pins once and
> puts a notice in the administrators' bell and the audit log ("A new key for the people codes was made"). If you
> see that notice and nobody on your team removed the key or restored a backup, treat it as someone having had the
> server's files: check who has access, the audit log and `deploy/verify_install.py --fetch`. A damaged key (an
> empty or cut file) is also in the bell; pages that name people do not open until it is removed and Looking Glass
> is restarted (`deploy/reload.sh`). Whoever can read the key can work out the code of a sign-in name they already
> know, so it is a secret like `.env`: backups hold it encrypted.

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
  ReadWritePaths=-/mnt/lg-checkpoints
  ```
  Keep the `-` in front of the folder: without it, Looking Glass does not start at all while the share is not mounted
  (after a restart, for example). With it, Looking Glass starts and the checkpoint says the copy failed. Use a folder
  outside `/tmp` and `/var/tmp`: the service has its own private ones, so a folder there is never the one it sees.
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

## The code check (Settings → Code check)

Every release lists the fingerprint (SHA-256) of every file it ships. Once a day, at 03:45 UTC, and a few minutes after
each start, Looking Glass compares its code files, and the database pipeline's if it is on the same computer, with that
list. It names:
- **Changed**: a file the release shipped whose content is now different;
- **Not in the release**: a file in a code folder that the release does not list.

Each finding is written to the audit log once, and administrators see one alert in the bell while any finding stands.
In Settings → Code check, an administrator confirms with their password and chooses, per file:
- **This is ours, keep it.** The file and its fingerprint are kept as approved. If it changes again, it is found again.
- **Not ours, move to quarantine.** The decision is recorded and the page gives the command to run on the server, as
  the account that owns the installation: `python3 deploy/verify_install.py --quarantine <path>`. The file is moved to
  `backups/quarantine-<time>/`, never deleted. Looking Glass cannot move it itself, because its code is read-only for
  it.

Then check the whole installation against the signed release (`deploy/verify_install.py --fetch`, see
[Checking a release's signature](INSTALLATION.md#checking-a-releases-signature)). A shipped file that was changed or
moved is put back with `git checkout <tag> -- platform/<path>`, followed by a restart. The daily check reads files only
and makes no outside connection.

## The quarterly report and the purge

Looking Glass counts every quarter once it has ended and keeps the result. **The quarterly purge is off on every
installation until an administrator turns it on** in Settings → Quarterly: while it is off, no report rows are deleted,
the reports and the bell say so, and the raw Shadowserver report rows are kept for good. Once it is on, the raw rows are
kept for about a quarter and a month, then deleted.

**Turning it on or off:** Settings → Quarterly, the card at the top (administrators with the Settings permission).
**Turn on the quarterly purge** shows what will be deleted and when (the purge day, the cutoff and the rows the newest
VALID report counted; the last 31 days are kept; findings, cases, advisories and the quarterly reports never), and asks
for your own password; a wrong one counts like a failed sign-in. It is done once: it then stays on for every quarter.
**Turn off the quarterly purge** is always there while it is on, with the same checks; turning it off removes any waiting
purge permit, so a purge that has not run yet does not run. Each change is in the audit log ("Quarterly purge turned
on" or "turned off": who, when, the rows it would delete then). The switch is kept in
`data/quarterly/purge_confirmed.json` (owner-only); do not edit it by hand. Turned on after a quarter's purge day,
nothing is deleted for that quarter: the next quarter's purge covers its rows.

The cycle, for every quarter once the purge is on (example: October to December 2026):

| When | What happens |
|---|---|
| The first check after 00:00 UTC on the next quarter's 3rd day (3 January 2027), when the quarter's last day's reports have arrived | The service makes the quarter's reports by itself: the management PDF and summary CSV, the advisor PDF and three CSVs, the purge CSV for administrators. Every accuracy check is run; the outputs say **VALID** or **NOT VALID** at the top, and whether the purge was on or off when they were made |
| At once | Management, advisors and administrators each get one alert in the bell: "2026Q4 reports ready; download before Thursday 21 January 2027; the raw report rows older than Tuesday 22 December 2026 are deleted on Friday 22 January 2027". With the purge off, it says instead that no report rows are deleted, and administrators get one more alert: "The quarterly purge is off: turn it on in Settings → Quarterly, or leave it off to keep every report row" |
| The 15 working days (Monday to Friday) after the quarter | People download their own copies: the management role its report and summary on the Executive portal, advisors theirs on the advisory portal, administrators only the purge CSV in Settings → Quarterly (administrators do not download the management or advisor reports; previewing a portal, they see the card with a note instead). Each download is sealed, its CSV stamped with who and when, and in the audit log |
| The next working day (the purge day, 22 January 2027) | The database pipeline's next run deletes the report rows dated before the cutoff (the purge day minus 31 days: the last 31 days stay). Older quarters' rows go too |
| After the purge | The administrators' bell says how many rows were deleted, from how many collections, before which day; the audit log has a "Quarterly purge" entry; Settings → Quarterly shows it |

The cycle is the same every quarter; public holidays are not counted. The quarter's report is made from the reports
loaded by then: the last day's reports usually arrive on the next morning, so if you want them in, use **Make it
again** in Settings → Quarterly once they are loaded (any time before the purge day).

**What is never deleted:** findings, cases, advisories, notes, the audit log, everything in the platform's `data/`
folder, and the quarterly reports themselves (`data/quarterly/<YYYYQn>/`, with `summary.json`, the counts the next
quarter compares against). Include `data/` in your backups ([Backups](#backups)): after the purge, these are the
quarter's record. Only the pipeline's report collections lose their old rows; `files_*` and `discovered_fields_*` stay.

**Who deletes:** the database pipeline, on its own account, never the web service. The service only writes a *purge
permit* into its own `data/quarterly/<YYYYQn>/purge_permit.json`, and only when the report is VALID and made before
the purge day **and** the purge is turned on. The pipeline reads it and `data/quarterly/purge_confirmed.json`, works
out the dates again itself and refuses anything else: the purge not turned on ("refused: the purge is not turned on in
Settings → Quarterly", logged once per quarter), no permit, a permit that is not VALID, dates that are not the rule's,
a cutoff within 31 days of today, or a quarter already purged. Its
result is in its `DATA_DIR`, `quarterly_purge_status.json`, and in its log (`[PURGE]` lines); a purge that cannot run
never stops the pipeline's run.

**When a report is NOT VALID:** the administrators' bell says so and names the checks that failed; no permit is written,
so nothing is deleted for that quarter. In Settings → Quarterly, open the report's **Accuracy checks** to see which
check failed and why:
- *collection could not be read*: MongoDB could not answer for that report (a broken view, a permissions change). Fix
  it, then **Make it again**;
- *3 independent recount*: rows arrived or were removed while it was counting (a pipeline run at the same moment). Make
  it again once the run has finished;
- *8 no address in any output*: a text carried an address (for example a decision's comment the masking missed): every
  output was removed. Tell the Looking Glass maintainers; do not copy the text anywhere.
A report made again and VALID before the purge day writes the permit (when the purge is on), and the purge runs on its day. Made after the
purge day, it writes no permit: the next quarter's purge covers those rows, so nothing is lost.

**Making a report again:** Settings → Quarterly → **Make it again** (administrators; in the audit log as "Quarterly
report made"). It replaces the kept report of an ended quarter. It offers only ended quarters of the last four that
have report rows: from the oldest report day in the database on (looked up with one indexed query per report
collection, kept in `data/quarterly/state.json`, refreshed every six hours, after a report is made and after a purge).
A quarter whose raw rows were already purged cannot be counted again: its kept report stays the record.

**The report, the purge and the pipeline never overlap.** A report waits for a pipeline load that is running and is
tried again 10 minutes later; while it is being made, no pipeline run starts. The purge is skipped while a report is
being made and is tried again at the next run. Make it again says "The database pipeline is loading reports now: try
again in a few minutes." while a load is running.

**What the cards say, and what the files say:** the cards on the Executive portal, the advisory portal and Settings →
Quarterly say what is true now: the purge's switch today, each quarter's purge as it stands (for example "No purge for
this quarter: its purge day (Thursday 22 October 2026) had passed when it was made"), where the quarter stands even
before any report exists, and a quarter with no report rows in plain words. The PDFs keep what was true when the
report was made and say so; the purge CSV keeps it too, unchanged. A quarter with no report rows says so on every PDF
page and on its CSVs' first lines.

**When the card says Looking Glass could not be reached:** the service was restarting or the connection dropped. The
card tries again a few times, then offers **Retry**; a download tries once more on its own. Nothing needs doing on the
server unless it keeps happening (then check the service: [The service](#the-service)).

**Checking the pipeline's side:** `cat <pipeline DATA_DIR>/quarterly_purge_status.json` shows the last check (`outcome`
done, refused or failed, with `why`) and every purge done, per collection.

## Updating from Settings (`deploy/update_helper.sh`)

Settings → Update writes a request, `data/update/request.json`; the update helper's path unit sees it and starts
`deploy/update_run.py` as the installation's user (`deploy/update_helper.sh install`, once, with sudo; `status` and
`remove` as for the other helpers). The run, in this order: the backup (`manage/backup.sh` into
`backups/before-update-<time>/`), the release tag fetched from GitHub and its signature checked against the
maintainer's key (the fingerprint in [Checking a release's signature](INSTALLATION.md#checking-a-releases-signature)),
the code moved to it (a fast-forward on the branch, so a later `git pull` still works), `deploy/update_libraries.sh`,
`deploy/reload.sh` and its health check. A failure before the code moved changes nothing; after it, the previous
commit, its libraries and a restart are put back. It refuses an older release, a tag that is not signed by that key,
a request older than 15 minutes, a folder not installed from a release (no `.release_fingerprints`), and shipped files
changed here (`git status`). One run at a time.

Every step and every line the commands print go to `data/update/log.jsonl` (the last 2,000 lines kept) and
`data/update/status.json`, which the page shows. The audit log gets `update_requested` or `update_check_requested`
from the page and `update_done`, `update_failed`, `update_rolled_back` or `update_checked` from the run. To look for
a release from the server: `deploy/update_helper.sh check`; the helper's own journal: `journalctl -u
<service>-update`.

## Updating the libraries on purpose

Installations take their Python libraries from the lock files only (`requirements.lock` of the platform and of the
database pipeline, `docs/requirements.lock` for the documentation site), every file checked against its sha256 value
([INSTALLATION.md, The libraries](INSTALLATION.md#the-libraries-only-files-that-match-the-lock)). A library therefore
changes only when someone makes the locks again, on purpose, with the one tool for it, and commits the result:

1. **Change the range, if needed,** in the `requirements.txt` beside the lock (each library up to its next major
   version). A raised cap is kept only once the new major version passes the full checklist (step 3).
2. **Make the locks again** (needs the internet; run from the platform folder):
   ```bash
   tools/lock_requirements.sh              # adds or removes what requirements.txt changed; other versions stay
   tools/lock_requirements.sh --upgrade    # the newest version of every library inside its range
   ```
   It writes the three locks, checks that every locked version is inside its range, and that every library's
   dependencies are in the lock for Python 3.12, 3.13 and 3.14 on x86_64 and aarch64. It installs its own tool
   (pip-tools) from `tools/lock_tools.lock`, with hashes too; `tools/lock_requirements.sh --tools` makes that lock again
   after a change in `tools/lock_tools.in`.
3. **Run the full release checklist**, `tests/run_all_checks.sh` among it (`tests/check_libraries.py` checks what the
   platform uses of each library; `tests/check_installer_supply.py` checks the locks against their ranges and every
   install path).
4. **Check the locked versions for known vulnerabilities:**
   ```bash
   pip-audit --require-hashes --disable-pip -r requirements.lock -r ../database/requirements.lock -r ../docs/requirements.lock
   ```
   (GitHub's checks run the same on every change.)
5. **Build the release's library bundle** for the library repository and for computers without internet:
   ```bash
   tools/build_wheelhouse.sh <release tag> <output folder>
   ```
   It downloads exactly the locked files for the six supported computers, checks each against its lock, writes
   `SHA256SUMS` and stops if a library has no ready-built file for one of them. The release attaches
   `looking-glass-libraries-<release>.tar.gz` to that release in the library repository.
6. **Installations then update** with `deploy/update_libraries.sh` (INSTALLATION.md, Updating). The update moves
   files the release no longer ships into a backup folder; see Updating.

Never install a library into `.venv` by hand: the next update replaces the environment from the lock anyway, and the
library would be in no lock. The environments in `.venvs/` (the one in use and the one before) are rebuilt from the locks
whenever needed and are not backed up.

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

Simpler: give a person the **Researcher/TI** (researcher or threat intelligence analyst) role. The **Definitions** page lists the names Malpedia does not know (new
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
