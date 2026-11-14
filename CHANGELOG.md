# Changelog

What changed in each release of Looking Glass. Releases are named by date; the newest is first. Update with the steps in
[docs/INSTALLATION.md](docs/INSTALLATION.md#updating).

## Unreleased

### Fixed
- Combination codes (LG-C, LG-X) can no longer stand for two different combinations. Codes keep their 8 characters;
  when a new combination's code is already taken, it gets a code of its own. Every existing code stays the same.
- Management's review now shows the figures of exactly what the analyst drilled down to (devices, records, networks,
  regions, per day, and the Executive portal filtered to that selection), not the whole combination's.
- Advisories: each affected device lists the infections it calls botnet sinkholes as in an Infections column of its
  own (page and PDF), including infections the analyst ticked on services findings.

### Added
- Combinations: under each organisation, the infections and CVEs/issues its own devices carry, with the ticked ones
  highlighted, and a button that ticks the organisations carrying them.
- Combinations: a researcher's reply code can be searched within the analyst's selection it answers, so the review,
  the report and the advisory carry only that selection's devices.

### Changed
- The Intelligence portal is now called Abused or Compromised, for analysts and administrators. A report's records are laid
  out like the platforms' analysis window: figures, key findings, a breakdown of each field (networks and regions
  too), and the record list with its download.
- Reviews: when the analyst drilled down (ticked patterns, infections or CVEs/issues), the report and the advisory
  cover exactly those devices, whichever view management approves; the researcher's view adds nothing to them, the
  analyst's view adds what was ticked. Decisions made earlier are unchanged.
- The installer's last step is called checking the installation.
- Documentation: a changelog; a shorter security policy (security model, operator checklist, checking an installation,
  reporting a vulnerability).
- Findings: the card head keeps the organisation and state labels on one line each, and long combination names wrap
  inside the card.

### Security
- Abused or Compromised: viewing a report's records is recorded in the data-access log; leaked accounts can be
  filtered or searched by e-mail or user name only after they are shown, which is recorded in the audit log.

## 2026-11-14

### Added
- Intelligence portal for analysts and administrators: Shadowserver's Intelligence reports by group (compromised
  systems and victims, malicious content, reputation, leaked accounts, attacker infrastructure), today against the
  median of the 7 days before, each report's records with filters on its own fields, CSV export, a host's view across
  reports, and analyst codes from a filtered view. Leaked accounts are masked until an analyst chooses to show them.
- Overview card for analysts and administrators, and Intelligence totals with their 7-day trend on the Executive portal
  (counts only).
- Combinations: infections and CVEs/issues can be ticked for the report, alongside the across-report patterns.
- Review: management can choose the analyst's view only (the report and advisory cover the devices behind what the
  analyst ticked).
- Analyst code pages show how the selection came about: the notes of the earlier codes it was made from.
- Settings → Task monitor for administrators: service, jobs, requests, cache, database, machine and pipeline, with
  performance graphs.
- ATT&CK techniques on CVE and issue cards (MITRE CTID's KEV mappings); Confirm all for reviewed mappings.
- Admin: locked sign-ins listed, and lifted by an administrator.
- The pipeline recognises report files from domain, ASN and netblock filters, so reports without an IP address
  (Compromised Account, Ransomware Victim, Sandbox-DNS) are loaded.

### Changed
- A short cache for the heaviest read-only answers, kept per role; faster host look-ups across reports.
- The advisory's own pages no longer carry the platform and scope line.

### Fixed
- The pipeline guide described the mail server certificate check wrongly; it is on by default.

## 2026-11-13

### Added
- Shadowserver's one-off special reports are loaded and listed apart, outside the replay and the daily totals.
- Views of host-level data and every host-list download are recorded in the audit log.
- Architecture and threat model page.
- Keyboard focus kept inside every dialog.
- MISP Galaxy and MITRE ATT&CK beside Malpedia (local copies, weekly refresh); advisories explain each ATT&CK
  technique and carry only reviewed mappings.
- Network names: one Look up all button, and Save all for reviewed names.

### Security
- More address forms are masked for masked viewers (dashed, zero-padded, decimal and hexadecimal forms, IPv4-mapped
  IPv6, host names made of an address).
- Masked viewers no longer receive record identifiers.
- Audit periods are kept within valid dates; Peace of mind also closes exports and complete lists.

## 2026-11-12

### Added
- Reports by Shadowserver's API or by e-mail, with automatic fallback either way.
- DKIM sender check of every report e-mail, with optional blocking, quarantine and release.
- Settings → Workers: the pipeline's settings from the web application, applied by the pipeline at its next run;
  changes that weaken it need a confirmation on the server.
- New report types are noticed and listed whatever way they arrive.
- Local times beside UTC (all 54 countries, daylight saving included).
- The network list sets the constituency.
- Audit evidence mapped to NIST SP 800-53 Rev. 5 and CIS Controls v8.1; password expiry policy.
- Uninstaller.

### Changed
- The MongoDB administrator account is kept root-only; the pipeline has its own limited account.
- Faster services analysis and replay counters.

### Security
- Audit log retention: every rotation and removal is recorded in the chain and checked.
- Advisory changes are refused when the advisory changed meanwhile; a finding closes only when every organisation's
  advisory is sent.
- Advisories are scoped to their organisation's networks and never widened.

## 2026-11-11

### Added
- Advisor role and advisories per organisation, with cases (one sub-finding per organisation) and TLP 2.0.
- Notifications, an Overview for every role, Peace of mind.
- Audit portal: the auditor role, the audit log by tab, control checks, access review, a tamper-evident log with
  retention, and a proof package with a standalone verifier.
- Loading animations on every page and tab.

### Changed
- Findings follow their flow step by step; only management or an administrator moves a finding by hand.
- Libraries may update within their major version.

### Security
- Masked viewers: report fields shown from an allowlist; addresses become opaque host labels.
- Reverse proxy: forwarded addresses are believed only from this computer; the first administrator needs a one-time
  setup code.
- Pipeline: unpacking limits against oversized archives, and report names checked before they become collections.
- Settings reachable only with the Settings permission; old failed sign-in records cleared.

## 2026-11-10

### Added
- Combination codes, analyst codes, findings and per-operator reports.
- The report map: where every Shadowserver report type belongs, kept current from Shadowserver's schema through one
  feed in this repository.
- Definitions → Services: each services report with its patterns, combinations and cross-report codes.
- Documentation site with the films.

### Security
- Intel gathered no longer shows researchers anything that identifies a constituent host.

## 2026-11-09

### Added
- First public release: Shadowserver reports replayed as two live platforms (network communications on a 3D map, and
  publicly accessible / vulnerable services), the Executive portal, Definitions, researchers' notes, roles with MFA,
  server-side masking and the audit log.
