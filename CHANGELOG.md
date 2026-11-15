# Changelog

Notable changes to Looking Glass, newest first. Releases are named by date. To update an installation, follow
[Updating](docs/INSTALLATION.md#updating).

## Unreleased

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
- First public release: Shadowserver reports replayed as two live platforms (network communications on a 3D map, and
  publicly accessible / vulnerable services), the Executive portal, Definitions, researchers' notes, roles with MFA,
  server-side masking and the audit log.
