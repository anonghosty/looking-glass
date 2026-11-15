# Changelog

Notable changes to Looking Glass, newest first. Releases are named by date: the release of 2026-11-15 is tagged
`v2026.11.15`, a second one that day `v2026.11.15.2`, and each has its notes on GitHub's
[Releases](https://github.com/anonghosty/looking-glass/releases) page. To update an installation, follow
[Updating](docs/INSTALLATION.md#updating).

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
