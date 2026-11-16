# Changelog

Notable changes to Looking Glass, newest first. Releases are named by date: the release of 2026-11-15 is tagged
`v2026.11.15`, a second one that day `v2026.11.15.2`, and each has its notes on GitHub's
[Releases](https://github.com/anonghosty/looking-glass/releases) page. To update an installation, follow
[Updating](docs/INSTALLATION.md#updating).

## 2026-11-16
### Fixed
- **The sender check works on networks that drop DNS TXT look-ups.** It looks up Shadowserver's signing key in DNS (a
  TXT record); some networks block TXT look-ups, and then every report e-mail was "not checked". When this server's
  own DNS does not answer, the key is now asked over HTTPS from Cloudflare and Google (`MAIL_AUTH_DNS_SERVERS`, default
  `1.1.1.1,1.0.0.1,8.8.8.8,8.8.4.4`, by IP address, certificates checked; only the key's name is sent). `none` turns it
  off. Nothing to change on update.
- Installing a bought certificate twice within the same second (or after the clock stepped back) stopped with an
  error, because the previous pair's folder name was already taken; the second one now gets its own folder.

### Changed
- **Held-back reports, chosen one by one or all.** Settings → Workers lists each report the sender check held back by
  its files' **Shadowserver names** (the day, the report and its readable name), and flags a file that is not named like
  a Shadowserver report. Tick the ones to process, or **Select all**, then **Process selected**: Looking Glass lists
  them and asks first. The chosen reports go to the pipeline as one request, so one confirmation on the server lets
  them all through at its next run. Before, each report had its own Release button and its own confirmation.

## 2026-11-15 (14)
### Fixed
- **The pipeline's marks are used from the start.** In the first 10 minutes after the computer started, the 15-second
  check did not look for the pipeline's marks and counted every report's rows each time, as before the marks existed.
  Harmless, but it did the work the marks are there to save; it also failed a check on GitHub's freshly started runners.
- **Explore follows each viewer's code rule.** Explore kept its finished answer for an hour, so a combination code on
  fewer than 5 devices, shown to someone who sees the devices, could reach a researcher who opened the same match
  after them (and the other way round, blank codes for the admin). It now keeps only what it read, and works out what
  each viewer may see on every request, as the rest of Intel gathered does. No address or host value was affected.

## 2026-11-15 (13)
### Security
- The audit verifier's `--key` now **fails closed**: a key file with no `ssh-ed25519` key in it (empty, a fingerprint,
  the wrong file) is refused with a message, instead of quietly falling back to the keys the log records. A key file
  saved on Windows (byte-order mark, Windows line endings) is read.
- Four code-scanning findings fixed: a region map is only read from the map folder for a known country code, and three
  test-only fixes (TLS 1.2 or newer, a safely made temporary file, a test route that answers JSON).

### Added
- **Explore shows exactly the match.** Explore on a "Looking Glass asks" match now opens every name and report of the
  match side by side, each worked out over only the records that carry the indicator: their tags, what comes with the
  indicator on the same record, and their other indicators. Two names sharing a domain show both names; one name in two
  reports shows both reports. Before, Explore opened the first name only, with the indicator typed into the search.

### Changed
- **Backup keys saved on Windows work as they are.** A public key or private key file with a byte-order mark, in UTF-16
  (what PowerShell's `>` writes) or with Windows line endings is cleaned before age or GnuPG reads it; before, age
  refused such a file.
- **Looking Glass asks:** when the detective finds something, the animation folds away and the results ease in, one
  after another, instead of appearing all at once (no motion when the system asks for reduced motion).

### Documentation
- OPERATIONS.md, Backups: **Making the backup key, step by step**, for Linux or macOS and for Windows with Looking
  Glass in WSL, including where to keep the private key and how to rehearse a restore with it.

## 2026-11-15 (12)
> **Before your next backup:** `manage/backup.sh` now refuses to run without your public key in
> `platform/data/backup_public_key` (see [OPERATIONS.md, Backups](docs/OPERATIONS.md#backups)). Make the key pair on
> your own computer and keep the private key off the server.

### Security
- **Encrypted backups.** `manage/backup.sh` encrypts each backup to your own public key (age or GnuPG, in
  `data/backup_public_key`), as it is written: no readable copy is ever on disk, and the private key stays with you,
  off the server. Without a key it refuses (`--unencrypted` makes a plain one on purpose). `verify_backup.sh` checks
  the signature and checksum without the private key; `--identity` opens the archive too, as `restore_check.sh` does.
- **Encryption at rest.** Settings → Task monitor shows whether the database, the report copies, Looking Glass's data
  and the backups are on an encrypted volume (LUKS; inside WSL it says to check BitLocker), and the guided installer
  says so at the end. OPERATIONS.md explains how to set it up.
- **Strict-Transport-Security** on every answer over HTTPS, from Looking Glass itself (Caddy and Looking Glass's own
  HTTPS sent none): one year; `includeSubDomains` and `preload` only when asked.
- **Heavy views per person.** At most 3 at once (the rest wait their turn) and 240 a minute, so one person can no longer
  hold every thread; tunable in `.env`, counted in the Task monitor.
- The audit verifier's `--key` now trusts **only** the key given, not also the keys the log records.
- Failed sign-ins are kept across a restart (`data/login_counters.json`), so restarting no longer lifts a lock.
- gunicorn 26.2 or newer (the version tested), still below 27.

### Changed
- **The pipeline marks what it loads** (`lg_load_stamps`), and the 15-second check counts every report's rows only when
  a mark moved, or every 10 minutes (`COUNT_EVERY_SECONDS`).
- **Kept answers stay right.** The heavy answers' cache now follows the days in memory (new report data is never
  answered from before it), is not emptied by look-ups, record views and other read-only requests, and does not keep an
  answer worked out while the database could not be read. The services filter lists also follow the network names,
  the report list and the administrator's region matches, and are worked out once for everyone asking together.
- More checks run on GitHub: a made-up week of reports (documentation addresses only) lets the combination, analyst
  code and Executive portal checks run there too.
- Python modules are no longer marked executable; a check keeps it so.

## 2026-11-15 (11)
### Changed
- **Faster while nothing changes.** A loaded day is checked against the database every 10 minutes and kept, with every
  answer already worked out from it, while its rows are the same; it is reloaded in full at most once an hour
  (`DAY_MAX_AGE_SECONDS`). Filtered views, the analysis and the summaries no longer start from scratch every 10 minutes.
- **Faster while reports arrive.** New rows are loaded once their counts stop changing (two checks in a row, or at
  least every two minutes during a long pipeline run, `SETTLE_MAX_SECONDS`), and only the reports that changed are read
  again; the rest of the day is kept as it is.
- **The Definitions page opens quickly.** Intel gathered, the services definitions, the sinkholes per report and the
  names seen are worked out in the background whenever the days in memory change, as are the first unfiltered views of
  both platforms (masked and not), so nobody waits for them. "Looking Glass asks" waits for the page's loading logo to
  go, however long the page takes, instead of playing underneath it.
- **Host look-up in Abused or Compromised.** The pipeline adds an index on address and day to the report collections
  (built once, on its next run), and the look-up asks for each day separately: from seconds per report to a few
  milliseconds.
- The README shows the Looking Glass mark at a readable size, with a dark rim on GitHub's light theme.

### Security
- Saving a region match accepts JSON only (415 otherwise), as the Settings save does.

## 2026-11-15 (10)
### Added
- **Every country in the world.** Settings → Country and the guided installer now ask for the continent first (Africa,
  Asia, Europe, North America, South America, Oceania, Antarctica), then the country: all 249 ISO 3166-1 countries
  and territories, and Kosovo. About 200 have a map of their first-level regions; the others are drawn as one area,
  where every record lands. Countries that cross the 180° line (Fiji, Russia, New Zealand, Kiribati) draw in one
  piece, and the communications map opens framed on the chosen country.
- **Region matches (Settings → Country).** Yesterday's region names from the reports are listed against the map with
  a "Match" column. A name the map does not know gets a suggestion ("doesn't match, but this is what we found");
  an administrator confirms it, picks another region, or marks the name as the whole country, and can undo it. The
  choices apply to the regions map, the Executive report and the unknown-region checks, need a fresh sign-in and are
  recorded in the audit trail.
- **Zoom on the regions map.** Scroll (or pinch) to zoom in where the pointer is, drag to move, and use the +, − and
  Fit buttons. The map is redrawn at each step, so names stay readable and more of them appear as you zoom in.
- **Maps open where the records are.** When the regions holding almost all the records (98%) cover clearly less than
  the whole country, as with islands far apart (Seychelles, Kiribati, the Bahamas), the services map, the Executive
  portal and the Executive PDF open framed on them, with a note. Fit (or the note's link on the Executive portal)
  shows the whole country.
- Regions too small to see at the map's scale get a dot that can be seen, hovered and clicked like the region.
- Time zones for every country, the capital's zone first where a country has several.
- `manage/fetch_world_boundaries.py` downloads every country's map again (geoBoundaries, Natural Earth for a few
  small territories), simplifies the largest ones and links the region names.

### Changed
- Executive portal cards show their notes in full instead of cutting them off.

### Fixed
- A region named like its country (Belize District, Djibouti, Guatemala, the State of México) now lands on that
  region instead of "Region unknown"; an administrator can still mark the name as the whole country.
- Regions listed twice in the open map data (two Latvian counties) are drawn as one, so their records show.
- An audit trail that cannot be written is still reported after the service restarts: the gap is kept on disk until
  writing works again, and the closing entry says how many restarts happened meanwhile.

### Security
- The service refuses to start with gunicorn's `--max-requests`, which would restart the worker and reset the sign-in
  and look-up limits held in memory.

## 2026-11-15 (9)
### Added
- Settings → Workers: **Sender check, last 7 days**. Day by day, the report e-mails that passed, did not pass or could
  not be checked, and each kind of failure with what it usually means. When every e-mail passed on each of the 7 days
  while blocking is off, it says blocking can be switched on safely (with a button that ticks it), and the bell says so
  once.
- The sender check explains its failures in plain words, in the run log, the held-back list and `mail_auth.py`'s
  report: a changed body usually means a mail gateway or forwarding rule, so deliver Shadowserver's mail unmodified.
- The installer's mailbox questions, Quick start and the mail set-up guide advise a folder (or Gmail label) only for
  Shadowserver's reports, filled by a mail rule.

### Fixed
- The sender check now says when it has stopped working: when the newest report e-mails could not be checked at all
  (the server's DNS does not answer the look-up of Shadowserver's signing key), Settings → Workers and the bell say so,
  and more urgently with blocking on, where those reports would wait at every run. Such e-mails never count as passed.
- With `DATA_DIR` set in the pipeline's `.env`, the platform read the sender check's results and the held-back reports
  from the wrong folder (and showed none); it now reads them where the pipeline keeps them.
- Shadowserver's report API is asked one day at a time with an explicit limit (`REPORT_API_LIST_LIMIT`, default 5000),
  and a day whose list reaches it is warned about, so no report is missed in silence; a report listed on two days is
  downloaded once.

### Security
- The pipeline's own report API calls now also use https only: an `http://` address is refused, an answer that
  redirects is not followed (the key is never sent on), and a report download that ends on plain http is refused.
- GitHub checks: the actions are pinned to their current releases on Node 24 (checkout v7.0.1, setup-python v7.1.0),
  replacing the Node 20 ones GitHub has deprecated.

## 2026-11-15 (8)
### Added
- Static code analysis on every push, pull request and release: Bandit for the Python code (no medium or high finding
  allowed) and ShellCheck for the shell scripts (no warning allowed), as a job in the GitHub checks. Each finding kept
  on purpose is marked in the code with its reason; CONTRIBUTING.md names both as the project's code standard.
- A security policy GitHub shows under Security → Policy, pointing to private vulnerability reporting.
- README and the documentation site's home page: the OpenSSF Best Practices badge.

### Fixed
- GitHub checks: the two checks that need a database now run against the empty database the checks start (made-up
  rows, documentation addresses only); before, they failed there because they expected a database with reports.
- Three maintenance scripts (the restore check, the administrator-database tests and the pipeline's set-up check) stop
  when they cannot change into their folder, instead of running on in the wrong one.

### Security
- The report API address and the report feed address (both settable in `.env`) are refused unless they use https, and
  a redirect away from https is refused too, so neither can read a local file or send the API key in clear.
- Two patterns in the code that held invisible text-direction characters are now written as visible escapes (same
  behaviour).

## 2026-11-15 (7)
### Added
- Guided installer: HTTPS with a certificate bought for a domain. The certificate is checked before anything is
  installed (its key, the domain, its dates and its chain), installed for port 443 with only the one capability that
  needs, the port opened in the firewall when ufw is on, and the site checked by its name over verified HTTPS.
  `manage/install_cert.sh` installs renewals the same way, and the bell warns 30, 14 and 3 days before expiry.
- An Explore button on each "Looking Glass asks" match: it opens Intel gathered on the name and report where the
  indicator is seen most, with the indicator already searched.
- README: Quick start step 6, "Before you hand it to anyone", with what the installer leaves to you and a link to
  the operator checklist; "Using it, step by step" now goes on to Definitions, combinations, findings, advisories,
  Abused or Compromised and the Audit portal.

### Fixed
- Executive portal and insight panels: a CVE's description is shown as its whole first sentence, never cut mid-word.
- The security retest and the checks accept a certificate bought for a domain (with its chain), not only a
  self-signed one; a service installed under another name than looking-glass is reloaded by its own name.
- Moving between pages, the loading logo draws itself once and carries on until the new page is ready (it drew twice).
- After a restart, the day before the replay day is loaded again at once, so "Looking Glass asks" and the
  across-reports figures compare the same days as before; when Looking Glass has nothing to ask, the card says how much
  it compared, day by day.
- Sign-in lock messages and the Audit portal's sign-in check (LG-06) give the lock times actually set in `.env`, and
  the time really left, instead of always "15 minutes".

### Changed
- The installer and the documentation recommend blocking reports that fail the sender check in production, once the
  Sender check shows every genuine report passing, or Shadowserver's report API, which does not use e-mail.

### Security
- An internet-facing installation always uses HTTPS: the installer no longer offers "No HTTPS" for it, and a
  self-signed certificate on a public site must be confirmed by typing it.
- GitHub checks: every action is pinned to a full commit, the checks that need a database run against MongoDB pinned by
  its image digest with a password made new in each run, and the libraries are checked for known vulnerabilities.
- Checking a backup says whether it is the newest one this installation signed, from the audit log, so an older
  genuine backup made to look newest by its file date is noticed.
- An audit entry that cannot be written (a full disk) no longer disappears silently: the administrators' bell says so
  while it lasts, and once the log can be written again the gap itself is recorded in it (how many entries, between
  when and when, and why), shown in the Audit portal as an alert.
- The service refuses to start with more than one gunicorn worker: sessions and sign-in limits live in one process,
  and more workers would sign people out at random.
- The sign-in page's globe reads its land map from Looking Glass itself; the content security policy no longer allows
  fetches from a whole public CDN.
- Behind a reverse proxy, the documentation says which address is believed (the last one, added by your proxy) and
  what to do with two proxies in a row; a new check confirms a visitor cannot pass as this computer.

## 2026-11-15 (6)

### Added
- Release notes: each release has a signed tag named by its date and its notes on GitHub's Releases page.

### Changed
- Every card that loads data as a page opens shows the loading animation until it has everything it needs, so no
  card shows "0", appears late, grows or is drawn twice; the platforms and the overview keep the logo until their
  figures, filters and lists are in, also after a reload. Windows and maps opened with a click (a record, an event, a
  definition, a country or region map, a log search) show it too, and the Executive portal's 7-day trends are drawn
  once, when the baseline is complete, instead of filling in piece by piece.
- "Looking Glass asks" shows Looking Glass thinking while it compares the reports: a detective looks through them, a
  light bulb when he finds matches, a shrug when Looking Glass has nothing to ask (still for reduced motion).
- The README points readers who want the global picture to ICHI, the Internet Cyber Health Index, with credit.
- The licence notes say that NIST SP 800-53, a work of the U.S. Government, may be adopted by anyone, and credit NIST.

### Fixed
- Combinations: the busiest devices' "Also seen in" names each report as people read it (for example "Device
  Identification") and shows the whole list, wrapped.
- Executive portal: in Top issues, rows without a Focus button line up with the others.

## 2026-11-15 (5)

### Security
- Checking a backup now ties the signed checksum to the archive being checked, and a backup without a signature fails
  unless `--allow-unsigned` is given.

## 2026-11-15 (4)

### Added
- Signed audit checkpoints: every day the audit log's head is signed with the installation's own key, recorded in the
  log, and copied to a folder on another computer if one is set. The verifier checks each checkpoint at its entry, so
  a copy kept away from the server shows if the log was rewritten later.
- Signed backups: each backup's checksum is signed and recorded in the audit log, and a new restore rehearsal checks a
  backup can be restored without touching the installation.

### Changed
- Where Looking Glass links reports by device (Across reports, the Executive portal's cross-report cards and the
  PDFs), a line says devices are matched by IP address and one address can sometimes be several devices.

## 2026-11-15 (3)

### Security
- An analyst code whose chain of parent codes cannot be followed to its end opens for administrators only.

## 2026-11-15 (2)

### Security
- A code made by ticking a CVE on an analyst code's page now opens only for the people of its parent's finding (and
  administrators), like the code it was made from.

## 2026-11-15

### Added
- Internal database on another server: the installer can use an existing MongoDB of your network, checks that it is
  a Looking Glass database, and otherwise offers a new database there or MongoDB on this computer.
- CVEs and issues can be ticked on an analyst code's page and sent with the reply.
- Guided installer: new start and progress screens.
- Community files: a code of conduct (Contributor Covenant 2.1), a contributing guide, an accessibility statement
  (WCAG 2.2 AA where feasible), issue forms (bug, feature, accessibility barrier) and a pull-request checklist.

### Changed
- Findings close on their own only when nobody is acting on them, counted from the day their devices were last seen,
  with a grace period after opening. Approved findings and findings with advisories in progress never expire.
- The Findings page no longer shows the list of steps at the top.
- Accessibility (checked against WCAG 2.2 AA on every page): lists, tabs, charts and the map's regions are named for
  screen readers, scrolling tables can be reached with the keyboard, small buttons are larger, and the red of
  Critical is easier to read. Text that was cut with "…" now shows in full.
- Documentation screenshots refreshed, with new ones for the features above.

### Fixed
- The Executive portal now shows management the Abused or Compromised totals (they were refused).
- A finding reported on the day being replayed is no longer counted as reported again.

### Security
- The reports database must be on this computer or an internal network address; a public address is refused.
  A database on another server is reached over TLS.
- Every automatic closing of a finding is recorded in the audit log.
- Advisors see a finding's repeated devices only once management has approved it, as on the advisory pages.

## 2026-11-14

### Added
- **Abused or Compromised** for analysts and administrators: Shadowserver's Intelligence reports by group, today
  against the usual, each report's records with filters, a host's view across reports, and CSV export.
- Findings show the day their records were reported, how many of their devices the latest report shows again, and
  when their time to act runs out; reviews, the Executive portal and searches open on that day.
- Analysts and advisors see devices reported again marked in their lists.
- Combinations: infections and CVEs/issues can be ticked for the report; reviews carry exactly the drilled-down
  devices, with the Executive figures of that selection.
- Every role lands on its own Overview, with greetings of its own.
- Settings → Task monitor for administrators; ATT&CK techniques on CVE and issue cards.

### Changed
- Advisories list each device's infections, define every infection and CVE they name, and show every value in full.
- Reply codes show how many devices they cover.

### Fixed
- Combination codes always stand for a single combination.
- Today's figures on Abused or Compromised count the reports received so far.

### Security
- Look-ups on Abused or Compromised send their filters in the request body, never in the address.
- The access log no longer records query strings or referring pages; responses carry no Server header.
- Pipeline runs with rows that could not be written are reported as failed and retried.

## 2026-11-13

### Added
- One-off special reports are loaded and listed apart from the daily replay.
- MISP Galaxy and MITRE ATT&CK beside Malpedia, with weekly local copies.
- Architecture and threat model page.

### Security
- Views of host-level data and every host-list download are recorded in the audit log.
- More address forms are masked for masked viewers.

## 2026-11-12

### Added
- Reports by Shadowserver's API or by e-mail, with automatic fallback, and a DKIM check of every report e-mail.
- Settings → Workers: the pipeline's settings from the web application.
- Local times beside UTC; audit evidence mapped to NIST SP 800-53 and CIS Controls; password expiry policy.
- Uninstaller.

### Security
- The database administrator account is kept root-only; the pipeline has its own limited account.
- Advisories are scoped to their organisation's networks.

## 2026-11-11

### Added
- Advisor role and advisories per organisation, with cases and TLP 2.0.
- Notifications, an Overview for every role, Peace of mind.
- Audit portal for auditors, with a tamper-evident audit log and a proof package.

### Security
- Masked viewers see report fields from an allowlist only.
- The first administrator needs a one-time setup code.

## 2026-11-10

### Added
- Combination codes, analyst codes and findings.
- The report map, kept current from Shadowserver's schema.
- Documentation site with the films.

## 2026-11-09

### Added
- First public release, for testing: Shadowserver reports replayed as two live platforms (network communications on
  a 3D map, and publicly accessible / vulnerable services), the Executive portal, Definitions, researchers' notes,
  roles with MFA, server-side masking and the audit log.
