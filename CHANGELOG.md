# Changelog

Notable changes to Looking Glass, newest first. Releases are named by date: the release of 2026-11-15 is tagged
`v2026.11.15`, a second one that day `v2026.11.15.2`, and each has its notes on GitHub's
[Releases](https://github.com/anonghosty/looking-glass/releases) page. To update an installation, follow
[Updating](docs/INSTALLATION.md#updating).

## Unreleased
### Fixed
- **Roles: every role names its ENISA skills profile.** The table in Roles has a new column for ENISA's European
  Cybersecurity Skills Framework (ECSF): Researcher/TI is the Cyber Threat Intelligence Specialist, as the text below
  the table already said (the table had said "Researcher"); Analyst the Cyber Incident Responder; Auditor the
  Cybersecurity Auditor; Administrator the Cybersecurity Implementer; Management the closest, the CISO.

## 2026-11-26
### Added
- **Settings → Update: update Looking Glass from the page.** Check for an update looks for a newer release; Update
  makes a backup, fetches the release, checks that the maintainer signed it, installs it with its libraries, restarts
  Looking Glass and checks that it answers. If a step after the code moved fails, the release you had is put back
  the same way. Every step shows on the page as it happens, also while Looking Glass restarts, and the run is in the
  audit log. Installing asks for a confirmation every time. Only a signed release newer than the installed one is ever
  installed. The web service still cannot change its own code: a small helper does the work as the installation's own
  user, never as root. Install it once on the server, in the platform folder: `deploy/update_helper.sh install` (it
  asks for sudo). Installations that are not from a release, such as a developer's working copy, are not updated from
  the page.
- **ATT&CK for nearly every report.** 175 of the 177 Shadowserver reports now have a suggested mapping checked against
  Shadowserver's own page for that report (80 more than before); each IPv4 and IPv6 pair that shares a page gets the
  same one. Researchers confirm them on the Definitions page as before; a mapping you have reviewed is never replaced.
- **Definitions → ATT&CK map → Please check: Use recommended for all.** Where MITRE retired a technique and names its
  replacement, one button takes the replacement for every such report, after a list of what will change. Reports
  without a named replacement are left for a person to choose.
- **Ten infections that arrived without a description now have one**: six named from published research
  (avalanche-marcher, avalanche-smart-app, emissary-panda, prometei, red october, vextrio-help-tds) and four explained
  with the family still unknown. Names that only match published research by spelling stay unknown.

### Security
- **No sign-in names in the pages.** A sign-in name is half of what signs someone in, so it now stays on the server.
  The page attribute that keeps map pins per account, the Notes window (which said whose each note was by sending its
  author's sign-in name to everyone who read it), and the lists of people a finding can be sent to now carry an
  opaque code per account instead; the account menu on the map shows your full name. A test signs in as every role,
  opens every page and answer, and fails on any sign-in name, your own or a colleague's (your own Account page and the
  auditor's audit trail aside). Pins kept under the old names are cleared once. The codes use the installation's own
  random key, `data/person_code.key`: keep it with `data/` and never copy it elsewhere. Nobody can change it from the
  website; if it is made again (removed, replaced, or `data/` restored from an older backup), the administrators'
  bell and the audit log say so, and a damaged key is in the bell too ([OPERATIONS.md](docs/OPERATIONS.md#backups)).
- **Settings → General → Sign-in check: a passkey or the authenticator code.** An administrator chooses how people
  sign in and confirm high-value actions. **Passkey** is recommended for a site on the internet; **Authenticator code**
  for an internal network. Changing it asks for a confirmation every time, so with passkeys in force, going back to
  codes needs a passkey. Passkeys can be chosen only by an administrator on the site's host name over HTTPS who has
  registered their own 2 passkeys, so nobody is locked out. `SIGNIN_CHECK=passkey` or `SIGNIN_CHECK=code` in the
  platform's `.env` wins over the page. Every change is in the audit log.
- **No lock-out after updating.** Before, every installation set to `ACCESS_MODE=public` asked everyone for passkeys,
  including ones that chose `public` for an office network before the installer offered "any computer on our internal
  network", where people reach Looking Glass by an IP address and no passkey can be registered. Now passkeys are the
  default only for a public installation with Caddy in front for a domain; every other installation keeps the
  authenticator code until an administrator chooses otherwise.
- **Caddy in front of a running installation, in one command.** `sudo deploy/caddy_front.sh adopt`, in the platform
  folder, reads the installation as it is (its `.env`, port and certificate), says what will change and asks once.
  Caddy then answers on the same port with the same certificate, so people keep the address they use and screens that
  trust the certificate go on trusting it; Looking Glass moves to `127.0.0.1` behind it. The service file and `.env`
  are copied first, and if a step fails everything is put back. Settings → Task monitor shows whether Caddy is in front
  and the command when it is not. The bell's daily reminder points to it, and now also comes to a public installation
  without Caddy.
- **After updating:** to update from Settings next time, install the update helper once: `deploy/update_helper.sh
  install` in the platform folder. An internal installation still set to `public` may also set
  `ACCESS_MODE=private` and `VIEWER_NETWORKS=internal` in `.env`; an installation without Caddy in front: `sudo
  deploy/caddy_front.sh adopt` ([Updating](docs/INSTALLATION.md#updating)).

### Fixed
- **Every form field has a name and a label.** The browser's Issues panel listed fields without an id or name, and
  fields without a label (searches, filters, table checkboxes, the Settings and Admin lists, replies on Findings).
  Each field now gets a name from what it is about and a label with the words shown beside it, also the fields pages
  add as they change, so screen readers and password managers can tell them apart. Nothing on the pages moves.
- **The unusual activity and connector timers run as the installation's user.** Installed with sudo, as the guided
  installer and these docs do, their service files named root as the user. They now always take the owner of the
  platform folder, and refuse a folder that belongs to root. If you installed either timer before this release, run
  its install again once, in the platform folder: `sudo deploy/unusual_timer.sh install` and, if you use connectors,
  `sudo deploy/connectors_timer.sh install`. `systemctl cat looking-glass-unusual.service` then shows your user.
- **A notification that points to the page you are on no longer hangs on the loading screen.** For example the
  bell's Caddy reminder while on Settings showed "Opening settings" for good; it now opens Settings again on the right
  tab (Task monitor).
- **Back no longer stops on the loading screen.** Going back to a page the browser kept showed the logo it had when
  you left it; the logo is now taken down.
- **The tutorial remembers its pages for every role.** For Researcher/TI, Executive, Advisor and Auditor accounts the
  tutorial's memory of the pages already shown was refused, so it could offer itself again. It now works for every
  role; it holds only each person's own seen pages.
- **The administrator routes' test passes on its own.** It now switches off the step-up confirmation for itself, as
  it tests what each route does with its input; the step-up confirmation is tested in its own test.

### Changed
- **Even buttons, fields and dropdowns on every page.** One height per size: 34 pixels for form buttons, text fields
  and dropdowns, 28 for buttons in lists and toolbars, and a button beside a field takes the field's height. Settings,
  Admin and Definitions no longer use the large welcome-page button for saving. On the Overview, each row of cards is
  as tall as its own cards, so a card alone in its row (Findings, Your account) is no longer stretched.
- **The researcher role is named Researcher/TI** (TI: threat intelligence), as the role studies threats and their
  patterns, which is threat intelligence work as much as research. The name shows in the header, on notes and
  findings, in the PDFs, on the severity map, in the glossary, on the Review page and on the Admin page (the role
  boxes and the Roles & permissions headings). Accounts, permissions and the
  audit log keep the role's key `researcher`, so nothing changes for existing accounts. The roles page maps it to
  ENISA's Cyber Threat Intelligence Specialist and to Saudi Arabia's cybersecurity workforce framework.
- **After updating:** nothing to do.

## 2026-11-25 (2)
### Security
- **Error messages show only what Looking Glass wrote for you.** On Settings → Connectors and in the passkey checks,
  an answer showed the text of any error, so a library's own message could reach the browser. Now an answer shows
  only messages written for the reader; anything else gets a fixed message, and the detail goes to the audit log or
  the service's log. A failed passkey check now says "The passkey could not be checked. Try again, or use another
  passkey."; the library's reason is in the audit.
- **Your bell says when a passkey is added to or removed from your account.** Adding or removing a passkey already
  asked you to confirm it's you every time; now your own bell also tells you, for 7 days, with the passkey's name and
  when, so one added from a session left signed in does not go unnoticed. Only you see it. The two passkeys
  registered right after your first sign-in do not ring.

## 2026-11-25
### Added
- **Connectors: send Looking Glass's analysis to your own OpenCTI or MISP.** On Settings → Connectors an
  administrator adds a target, its key and its TLP (AMBER unless chosen), and ticks what it receives: networks of
  the constituency, some of their address blocks, other ranges. A target is saved only after its test passed (the
  address, the certificate, the key and its rights, and one test object), and saved off. Turned on, it receives the
  last 30 days, then each report day once its reports have arrived: in OpenCTI a grouping per device with a note per
  report, linked to the platform's own MITRE ATT&CK entries; in MISP one event per day, shared with your
  organisation only and never published, with an event report. It sends only Looking Glass's own analysis, never
  Shadowserver's raw rows, findings, notes, names, time to act or combination codes, and the devices go as victims,
  never as indicators to block. A day whose data changes is updated in place; what is no longer true is revoked
  in OpenCTI. Every change to a target asks for your passkey or authenticator code, and every send is in the audit
  log. A paused target rings the administrators' bell, and the auditor sees every target and everything sent out on
  the Audit portal's new Data sent out tab. Works in every access mode, `local` included. Guide: [Connecting OpenCTI and MISP](docs/CONNECTORS.md).
- **After updating:** nothing to do unless you will use connectors. Then: `deploy/connectors_timer.sh install`
  (once), and if Settings → Connectors says keys cannot be stored, add `CONNECTOR_KEY_SECRET` to `.env`
  (`openssl rand -hex 32`) and run `deploy/reload.sh`.
- **Passkeys, and a fresh check before high-value actions.** On installations open to the internet
  (`ACCESS_MODE=public`) everyone signs in with a passkey (Windows Hello, Touch ID, a phone or a security key),
  which a look-alike site cannot relay; each person registers two on their first sign-in after the update. Before
  high-value actions (complete or unmasked downloads, unmasking, tracing, settings, the purge, advisories) every
  installation asks you to confirm it's you, with a passkey or a fresh authenticator code, for 10 minutes; changes to
  accounts, roles, sign-up links, connectors and passkeys ask every time. Your account (in the menu) lists your
  passkeys; administrators can reset a person's passkeys. An internal installation that sees sign-ins from the
  internet says so in the administrators' bell.
- **After updating:** on an installation open to the internet, tell your users before the update that their next
  sign-in asks them to register two passkeys, and that it needs the site's host name (not its IP address). Internal
  installations: nothing to do.
- **Unusual activity.** Every network and report, and every pair of reports, now has its own normal: the middle of its
  last 28 report days. Analysts see what is well above its normal on the latest report day on a new page, Unusual
  activity: each card in words, with its chart, the devices behind it and a link that filters the map or the services
  platform. Confirm makes it a thread your team watches every day; Dismiss keeps it quiet for 30 days. Each report
  learns from these decisions how readily to ask, and says why. Researchers see the suggestions, without devices, in
  Looking Glass asks; management sees Unusual this week on the Executive portal. Counted every hour by its own service;
  counts only, never an address.
- **After updating:** `sudo platform/deploy/unusual_timer.sh install` once (new installations do this by themselves).
  The first count reads the last weeks and takes a few minutes; the page is empty until then.

### Changed
- **Caddy in front of internal installations too.** A few deliberately slow connections from inside a network could
  hold Looking Glass up for everyone. The guided installer now puts Caddy in front of `private` installations as well,
  with their own self-signed certificate or one for a domain, and Looking Glass listens on this computer only. For
  `private`, "No HTTPS" and a reverse proxy of your own are no longer offered. An internal installation without Caddy
  in front is reminded in the administrators' bell every day.
- **After updating:** `local` and `public` installations: nothing to do. `private` installations: run the guided
  installer again with the same answers to put Caddy in front; until then the bell reminds you daily.
- **A shorter top bar on the map and services pages.** The line under the title no longer shows the report source,
  the number of reports or "replay of yesterday"; the page's name and who is signed in stay.
- **The security retest runs on public installations too.** There, its temporary accounts register two passkeys made
  by the test itself (kept in memory and removed at the end) and use them to sign in and to confirm high-value
  actions, so the passkey sign-in, a replayed passkey answer, another account's passkey and the confirmation are all
  checked. On an installation that listens on this computer only, the network address check says so instead of
  failing.

### Removed
- **The all-fields CSV is no longer part of combination downloads.** The ZIP keeps the PDF, the devices CSV and the
  records CSV, with the pattern values, Shadowserver's own ATT&CK and CVE and the certificate facts as before.
- **After updating:** nothing to do. `LG_ALL_FIELDS_MAX_LINES` is no longer read; you can delete it from `.env`.

### Fixed
- **ATT&CK suggestions checked again against Shadowserver's own pages.** Open IPP (IPv4 and IPv6) now suggests
  T1190 Exploit Public-Facing Application: Shadowserver names code execution found on printer models and access to
  print jobs, and never amplification. The general amplification rule now applies only to the reports it names; STUN,
  IPv6 STUN and GTP keep Reflection Amplification from their own pages. An IPv4 and an IPv6 report that share one
  Shadowserver page now get the same suggestion (CWMP, IMAP, MySQL, rsync and VNC differed).
- **After updating:** a researcher sees these reports marked *check* on the Definitions page, with the new suggestion
  offered and the earlier one kept; nothing changes until they confirm.
- The Overview greeting for an account with no name entered no longer starts a sentence with a lowercase "there";
  such accounts get only the greetings that open with a salutation, such as "Hello there".

## 2026-11-24 (2)
### Changed
- **app.py split into modules, behaviour unchanged.** The analysis panels, the PDF and ZIP reports of an analysis
  figure, the infection knowledge base, the look-up jobs, the researchers' notes on cards, the definitions for names
  Malpedia does not know and Explore a match now live in their own files (`analytics_api.py`, `report_downloads.py`,
  `infection_kb.py`, `lookup_jobs.py`, `card_notes.py`, `name_definitions.py`, `intel_match_api.py`). Every address,
  answer and permission is as before: the release's checks compare all 209 routes with the previous release's.
- **After updating:** nothing to do.

## 2026-11-24
### Added
- **Readable names for every report field.** The detail windows, Abused or Compromised and its CSV show each
  Shadowserver field by a short readable name, for example "IP header: URG flag" instead of `ip_header_urg`, for all
  746 fields the reports use.
- **Shadowserver's own ATT&CK and CVE for an event.** When Shadowserver tags an event with MITRE ATT&CK techniques and
  tactics, a CVE or the device it targeted (the honeypot scanner reports), the map's detail window shows them under
  "Shadowserver's mapping for this event". On the Definitions page, each report shows the techniques Shadowserver
  tagged its events with, beside Looking Glass's mapping. They never change a mapping.
- **Certificate and TLS facts.** When a scan carries them, the services detail window shows whether the certificate
  had expired when it was scanned, is self-signed, passed Shadowserver's check and is trusted by browsers, and whether
  SSLv3 is still on and TLS 1.3 supported. Researchers see them without dates.
- **Combination downloads carry what a network provider needs.** The devices CSV and the records CSV gain the values
  the pattern analysis groups devices by (certificate fingerprints and names, JARM, HASSH, SSH and server software,
  page hash, brute-force usernames and passwords, SSH client, request pattern), Shadowserver's own ATT&CK and CVE and
  the certificate facts, before `combination_code`. A new all-fields CSV lists every field of every record with its
  readable name. The PDF counts Shadowserver's tags and the certificate facts.
- **Caddy kept up to date.** `deploy/caddy_front.sh update` updates Caddy from its signed repository after checking its
  key against the pinned fingerprint, keeps Looking Glass's Caddyfile, hardening and firewall, and checks the site
  through Caddy afterwards. Setup makes sure Ubuntu's automatic updates are installed and says plainly when they are
  switched off. `status` shows the installed and newest version, and the administrators' bell warns when Caddy is
  behind or its updates do not install by themselves.

### Fixed
- **The figures stay in the top bar** on wide screens when the buttons need a second row (a long name, browser zoom);
  they no longer drop onto the map.
- **The detail window's connector** sits midway between the two places, drawn from one to the other with an arrow.
- **Every chart on the Executive portal shows its value on hover**, at once, also over a chart's labels and in the
  regions list.
- **CVE look-ups no longer fail after another process writes the CVE cache first** (a fresh installation started
  without the cache file; since 2026-11-23 (2)).
- **GitHub's checks no longer stop MongoDB while it starts** (the check for "is it up" wrote into MongoDB's data folder).

### Changed
- MITRE ATT&CK tactics are kept by ID from the next weekly refresh of the name sources. Until then a tactic shows its
  ID, linked to MITRE's page.

## 2026-11-23 (2)
### Changed
- **ATT&CK and impact checked against each report's own Shadowserver page.** Every report's suggested MITRE ATT&CK
  techniques and impact flags were compared with what Shadowserver's page says the report contains; 73 suggestions
  were corrected and 14 now say no technique fits (for example the Block List, which gathers third-party lists).
  Mappings a researcher already reviewed are not changed: they show "please check" with the new suggestion beside
  the old one. Impact flags were corrected for 68 reports.
- **Internal collections are no longer listed as reports.**
- **Looking Glass notices a file changed even within the same clock tick** (a check could fail on fast servers).
- **After updating:** researchers review the reports marked "please check" on the Definitions page.

## 2026-11-23
### Security
- **A public installation with a bought certificate has Caddy in front.** A few deliberately slow connections could
  hold up Looking Glass's own server when it faced the internet directly. Caddy now takes the public port, reads every
  request in full under time limits, and passes it on to Looking Glass, which listens on the server itself only. Caddy
  comes from its own signed repository (key pinned by fingerprint), fetches no certificate, has no admin endpoint and
  names itself in no answer, error answers included. Renewals update Caddy's copy of the certificate; the uninstaller
  removes only what Looking Glass wrote. Caddy's service runs locked down (systemd's exposure score 1.4 instead of the
  package's 8.8). It staples no OCSP answer, stays within memory and process limits, may send only to the server
  itself, and each address may hold at most 100 connections at once. Its security updates install by themselves, and its
  firewall rules are loaded again whenever the nftables service starts or reloads.
- **`public` offers one HTTPS choice only:** a certificate for the domain with Caddy in front. A self-signed certificate
  and a reverse proxy of your own are no longer offered for `public` (they still are for `private`).
- **After updating:** a public installation with a bought certificate runs the guided installer again with the same
  answers (see Updating). Others need nothing.

### Added
- **A check of Caddy's setup** (its configuration, package source and the installer's wiring), run on every release.

## 2026-11-22 (6)
### Changed
- **Trusting a self-signed certificate is the way, not clicking past the warning.** The installation guide shows how
  to trust the certificate on Windows, macOS and Ubuntu after checking its SHA-256 fingerprint; `make_tls_cert.sh`
  says so when it finishes, and the guided installer's summary shows the fingerprint with the same advice. A warning
  on a screen that already trusts it means stop and tell the administrator.
- **The user guide's sign-in section says Looking Glass never sends a link to sign in:** open it only from your own
  bookmark or the address your administrator gave you; any message with a sign-in link is phishing, so report it.

### Added
- **Three security tests.** A sign-up that adds fields such as `role=admin` by hand gets the lowest role. No API
  answer carries a secret, checked for every role. Every route refuses the roles it should, compared with a reviewed
  permission map.

## 2026-11-22 (5)
### Added
- The idea behind Looking Glass, the orb-weaver, on the documentation site's home page, with a short film of a real
  orb-weaver at work by the Butterfly Pavilion (1:37), which plays from the Butterfly Pavilion's own YouTube channel.
- **After updating:** nothing to do (documentation only).

## 2026-11-22 (4)
### Added
- The film **Teardown** (5:11, narrated, with captions) on the documentation site's home page under *How it works*,
  with its chapters.

## 2026-11-22 (3)
### Changed
- **External accounts no longer see ransomware victims.** The report is left out of their Abused or Compromised view:
  not listed, not counted in the group totals, and refused if asked for. Even a victim's ransomware group and day
  could be matched with public leak-site trackers, which list victims by group, date and country. Analysts,
  administrators and management see it as before.

## 2026-11-22 (2)
### Changed
- **External accounts see less in Abused or Compromised.** Free text a report writes in words (a defacement's message,
  a block list's reason, a user agent) is now shown as "hidden", because it can name a site or an organisation. A
  ransomware victim shows only the ransomware group: its sector, place, website and published date are hidden, since
  together with public leak-site trackers they could point at one organisation. Analysts and administrators see the
  records as before.

### Fixed
- Two of the repository's own tests were tightened: one checks each web address by its host rather than by a piece of
  its text, and one never prints the made-up secrets it works with, even when a check fails.

## 2026-11-22
### Changed
- **Heavy jobs never run at the same time.** A quarterly report is not started while the database pipeline is loading
  reports: it waits and is tried again 10 minutes later, and no pipeline run starts while a report is being made. The
  quarterly purge does not start while a report is being made; it is tried again at the next run. In Settings →
  Quarterly, Make it again says "The database pipeline is loading reports now: try again in a few minutes." when a load
  is running.
- **Nothing the service writes can be run.** The service could already write only in `data/`. The service file now
  also names its code folder as read-only outright, and nothing in `data/` may be run as a program. A new check makes
  sure every place the service writes is in `data/`. After updating, run the one step in
  [Updating](docs/INSTALLATION.md#updating) to install the new service file; the update says when it is needed.
- **Settings → Code check.** Once a day, and a few minutes after each start, Looking Glass compares its code files
  with the list of files the release shipped and names any file that was changed or added. Each finding is written to
  the audit log once, and administrators get one alert in the bell. An administrator marks a file "This is ours, keep
  it", or "Not ours, move to quarantine", which gives the command to run on the server: the file is moved aside, never
  deleted. `deploy/verify_install.py --fetch` checks every code file against the signed release on GitHub.
- **Every release carries its exact list of libraries** (an SPDX software bill of materials,
  `looking-glass-sbom.spdx.json`). It is in the release and attached to the release on GitHub, made from the same
  hash-locked lists the installer uses.
- **Every source file states its licence (AGPL-3.0-only) and copyright (the Looking Glass contributors)** in its first
  lines, in the standard SPDX form. Pages, scripts and the service file work exactly as before.

### Fixed
- Saving a CVE entry in the knowledge base with a note and no reference was refused with "Give at least one
  reference". A CVE needs only a note or a reference, as intended.
- Checking the audit log no longer stops on a line that is valid JSON but not an audit entry. The line is reported as
  damaged, like any other unreadable line.
- The services knowledge base no longer fails with an error when the list of values seen in reports cannot be read.
  The question that uses those values is simply left out.

## 2026-11-21 (6)
### Changed
- **Pages no longer show the browser's own error text.** When Looking Glass cannot be reached (for example while it
  restarts), pages say so in plain words. Reading data is tried again on its own after 2, 4, 8 and 15 seconds, then a
  Retry button appears. Saving, sending or approving is never repeated on its own: the page says the action may not
  have been done and leaves the button ready to try again. Messages from Looking Glass itself are shown as before.
- **Network names & types: the Records column** shows each network's records on the day the map shows, both
  platforms, before the constituency, and names that day; "not loaded" when that day is not loaded yet. It used to show a
  figure from the last network look-up, or 0.
- **Settings → Quarterly: the purge check says "Nothing to purge now"** when the latest quarter past its purge day had
  no report rows before its cutoff, and names the next quarter and its purge day; a refusal names them too.
- **Settings → Quarterly: with no quarter to make again,** only the sentence saying why is shown (no empty list or
  greyed button).

- **Updating tidies old files.** Files an earlier release shipped and the new one no longer uses are moved into a dated
  backup folder (`backups/stale-<date>-<time>/`), never deleted, and the update lists each one. Files Looking Glass
  never shipped, such as your own scripts, are never moved; the update names them and leaves them where they are. Your
  data, settings, logs and backups are never touched. To keep the former files where they are too, run the update with
  `LG_KEEP_STALE=1`.
- **Each page is offered once.** The Overview no longer repeats its pages as header buttons: the Your pages cards open
  them, and the header keeps the bell, Tutorial and Log out. The logo next to the Overview button is now only the logo.
  Settings no longer has an Open Definitions card: use the Definitions button in the header. On the advisory portal, a
  finding's number opens that finding on the Findings page.
- **Findings are for the team only.** The Findings page, its buttons and its cards are shown only to researchers,
  management, analysts, advisors and admins. Other accounts (external, auditor) are refused, since a finding is never
  handed to them.
- **External accounts open three pages only:** network communications (the map, with its Overview and glossary),
  publicly accessible / vulnerable services, and Abused or Compromised. Every other page and API is refused on the
  server. Abused or Compromised is now open to them in a masked view: IP addresses as host labels, networks by their
  alias, host names, organisations, accounts and e-mail addresses hidden; filters and search work on the masked values;
  no download, look-up or account reveal. They no longer get Copy JSON or Look up buttons, nor the names of the people
  who wrote a definition. A role whose only permission is "view" is treated the same way.
- **Settings, Network names & types:** every network with records lists every address block it has records in, on
  either side, with its own count; a block two networks share is listed under both. Chosen blocks are shown first and
  stay chosen until you untick them, with or without records, and Looking Glass remembers which network each was chosen
  under. A network's row has an Add a block box. Other address ranges is a list with a remove button on each range and
  a box to add one; ranges not seen in the reports yet are marked. What Apply settings saves for the platforms is
  unchanged.
- **Network communications and publicly accessible services:** when the day's reports are loaded and hold nothing, the
  list says "No records for your constituency on &lt;day&gt;." (or "No records reported on &lt;day&gt;." without a
  constituency) instead of waiting.

### Fixed
- **Quarterly reports: an infection row without a name** is named by what its tags stand for, a known tag's title, or
  the report's name, never by its raw tags.
- The tutorial on the platforms' Overview no longer points at buttons hidden behind it, and its Tutorial button sits
  beside the bell and Log out.
- "Back to the overview" on the Not allowed page opens your own Overview.
- The Audit portal describes settings changes in plain words again (country, time zone, constituency).
- **After updating:** nothing to do. External accounts that used to open other pages now get the Not allowed page.

## 2026-11-21 (5)
### Changed
- **The constituency is chosen in one place.** In Settings, the network list's **Constituent** column has a drop-down
  on every network: **Not in**, **The whole network**, or **Some address blocks**, which opens the network's row with
  its address blocks that had records, busiest first, with a search and **Show all N blocks**; folded, the row says
  for example "3 of 120 blocks chosen". **Other address ranges**, under the table, takes ranges that belong to no listed
  network. The Constituency card keeps the choice between the whole country and selected networks, with a live summary
  ("3 networks, 12 address blocks, 1 other range"); its own network list, Extra address ranges and Pick address
  blocks from the reports are gone. Saving is unchanged (AS numbers and address ranges, with Apply settings).
  **After updating:** nothing to do. A saved range that is exactly one of a network's blocks shows as that network's
  chosen block; any other saved range shows under Other address ranges.
- **Every download is in the audit log, once each time the file is saved:** combination reports (the whole report, one
  network's report, and one kept from before a restart), the report of a decided review, the services host list and
  the drill-down lists. A combination search is logged once as "Combination search run". The report of a decided
  review is no longer logged twice.
- **`DATA_ACCESS_LOG=0` now stops only the logging of views;** downloads are always logged.
- **Abused or Compromised downloads** are listed under "Data access and exports" in the Audit portal.
- **Every page downloads files the same way:** the button shows it is busy, the file keeps its name (including
  non-Latin names), Looking Glass tries once more when it could not be reached, and errors are in plain words.
- **Screenshots kept in step with the pages.** A new check names any documentation screenshot whose page has changed
  since it was taken. Retake or confirm it, then record it with `platform/tools/screens_manifest.py --update <name>`.
- **The PDF-only report addresses** (`/api/insight/report.pdf`, `/api/svc/report.pdf`) now count towards the
  per-person limits for heavy requests, like the other report addresses.

### Fixed
- **Quarterly downloads arrive on the first click.** The download buttons on the Executive portal, the advisory portal
  and Settings → Quarterly fetch the file through the page, show that they are downloading, and try once more on their
  own when Looking Glass could not be reached. Before, the browser's own download often failed with "Network error"
  on a self-signed certificate. A download that still fails says so in plain words. Every download is still sealed,
  stamped and in the audit log.
- **No more "Failed to fetch" on the quarterly cards.** While Looking Glass restarts, a card says "Looking Glass could
  not be reached just now (it may be restarting). Trying again…", tries a few more times, then offers **Retry**.
- **Each role downloads only its own quarterly files.** The management report and summary are for the management role
  only, the advisor report and its three CSVs for advisors only. Administrators get the purge CSV, the accuracy checks,
  the purge's switch and **Make it again**; previewing a portal, they see the card with a note instead of the
  downloads ("Quarterly reports are for management only").
- **The quarterly cards say what is true now.** Each card says whether the quarterly purge is on now and, for each
  quarter, its purge as things stand (for example "No purge for this quarter: its purge day (Thursday 22 October 2026)
  had passed when it was made"), and where the quarter stands even before any report exists ("2026Q4 is in progress:
  it ends Thursday 31 December 2026; its reports are made on Sunday 3 January 2027"). The PDFs keep what was true when
  the report was made and say so; the purge CSV is unchanged.
- **An empty quarter says so.** A quarter with no report rows says "No report rows were loaded for 2026Q3 (Looking
  Glass holds report rows from 21 September 2026 on)." on its card, on every page of its PDFs and on its CSVs' first
  lines.
- **Make it again offers only quarters with report rows:** ended quarters of the last four, from the oldest report day
  in the database on, not purged. With none, it says when the first report is made.
- **The quarterly reports follow the constituency.** Like the rest of Looking Glass, they count only the hosts in the
  constituency set in Settings → Constituency, and each report, CSV and card says what it was counted for ("Counted
  for: the whole country", or "Counted for: 3 networks and 1 address range (the constituency set in Settings)"). A
  comparison with a quarter counted for another constituency says so. The quarterly purge still clears old stored rows
  of all networks, and its figures say "all networks in the database, not only the constituency".
- **Open cases per organisation in the quarterly advisor report count only cases opened before the quarter ended.** A
  quarter made again later no longer counts newer cases.
- **An advisory's report file and its JSON export** download through the page and no longer leave the "Opening the
  advisory" screen on.
- **The services host list's file name** is quoted in its download header.
- **The Constituency card says where it applies:** every part of Looking Glass follows it, and only the quarterly
  purge works on the whole database.
- **After updating:** nothing to do. Reports made before this update counted every network (the whole country); if a
  constituency is set, use **Make it again** in Settings → Quarterly to count an ended quarter for it.

## 2026-11-21 (4)
### Changed
- **The documentation's screenshots show today's Looking Glass.** All 50 were taken again (made-up data), under the
  same names, so every page that shows one shows the current screens.
- **The quarterly purge is off until an administrator turns it on.** It no longer runs on its own: Settings →
  Quarterly shows at the top whether it is on or off and, while off, what it would delete once on (the purge day, the
  cutoff and the rows the newest VALID quarterly report counted). **Turn on the quarterly purge** shows exactly what
  will be deleted and when, and asks for the administrator's own password; a wrong one counts like a failed sign-in.
  It is done once and stays on for every quarter after; **Turn off the quarterly purge**, with the same checks, is
  always there and stops a purge that has not run yet. Each change is in the audit log (who, when, the rows it would
  delete then). Looking Glass writes a purge permit only while the purge is on, and the database pipeline refuses to
  purge unless the platform's `data/quarterly/purge_confirmed.json` says it is on. The timing has not changed and still
  has no setting. While the purge is off, the quarterly reports, the admin CSV and the bell say that no report rows are
  deleted, and administrators get one bell alert per quarter saying it is off.
- **After updating:** the quarterly purge is now off until an administrator turns it on in Settings → Quarterly; an
  installation that wants it should turn it on before Friday 22 January 2027 (the purge day for October to December
  2026). Update the database pipeline too (its `quarterly_purge.py` checks the same switch); nothing else to do.

## 2026-11-21 (3)
### Fixed
- **GitHub's checks run again.** One line of the checks workflow was not valid YAML (an unquoted value holding ": "),
  so GitHub started none of its jobs. It is quoted now, and `tests/check_ci_pins.py` reads every workflow as YAML.
- **After updating:** nothing to do.

## 2026-11-21 (2)
### Security
- **Libraries only from lock files, every file checked.** The platform, the database pipeline and the documentation
  site now install their Python libraries from `requirements.lock`: one exact version of every library (and of what it
  needs) with the sha256 value of every file. Every installation and update checks each file before using it: the guided
  installer, `deploy/install.sh`, the pipeline's `deploy.sh`, the new `deploy/update_libraries.sh` and GitHub's checks.
  A file that does not match is refused with a warning (library, version, source, expected and received sha256), the
  next source is tried (PyPI, then the release's files in the new library repository, then a read-only local copy of
  the last two releases in `~/looking-glass/libraries`), and it is reported in `suspected-packages.txt`, the installer's
  log, the audit log and the administrators' bell. With no matching file anywhere, the installation stops and nothing
  is changed. A library no lock lists is refused.
- **New environments beside the running one.** An installation or update builds the libraries in `.venvs/` and switches
  `.venv` to them only when everything matched and installed; the running installation is untouched until then, and
  the environment before is kept.
- **The computer is checked first.** Ubuntu 24.04 or later only, Python 3.12, 3.13 or 3.14, an x86_64 or aarch64
  processor; anything else is refused with the reason before anything is installed. **Debian is no longer accepted.**
- **Changing a library is deliberate:** `tools/lock_requirements.sh` makes the locks (and checks them for every
  supported Python and processor); `tools/build_wheelhouse.sh` builds a release's library bundle. pip-audit checks the
  locked versions. A new check, `tests/check_installer_supply.py`, rehearses every case with a local package index and
  fails if any install path skips the hashes.
- **After updating:** after `git pull`, run `deploy/update_libraries.sh` once in `platform/` (instead of
  `pip install -r requirements.txt`), then `deploy/reload.sh`. It needs Ubuntu 24.04 or later with Python 3.12-3.14 on
  x86_64 or aarch64, and the internet (or the release's library bundle unpacked into
  `~/looking-glass/libraries/<release>/`). `.venv` becomes a link into `.venvs/`; nothing else to configure. If it
  reports a refused file, keep `suspected-packages.txt` and report it ([When a library file does not
  match](docs/INSTALLATION.md#when-a-library-file-does-not-match)). Contributors: a change to a `requirements.txt` comes
  with its regenerated lock (CONTRIBUTING.md, "Changing the libraries").

## 2026-11-21
### Added
- **The quarterly report.** On the next quarter's 3rd day, once the quarter's last reports have arrived, Looking Glass
  counts the quarter and keeps the result: records and unique
  addresses per month, report, network, region and sector; infections and actively exploited CVEs; findings, cases and
  management's decisions; advisories and their follow-up. Counts only, never an address. **Management** downloads the
  management report (PDF) and its summary (CSV) on the Executive portal; **advisors** the advisor report (PDF) and three
  CSVs on the advisory portal; **administrators** everything, with the purge figures, in the new **Settings →
  Quarterly**, where they can also make a quarter's report again. Eight accuracy checks run every time; every report
  says **VALID** or **NOT VALID** at the top. Each download is sealed, its CSV stamped with who and when, and in the
  audit log. Researchers, analysts and external accounts do not get it. The bell tells management, advisors and
  administrators when a quarter's reports are ready, and until when to download them.
- **The quarterly purge.** On the working day after the 15th working day (Monday to Friday) after a quarter, the
  database pipeline deletes the raw report rows older than 31 days, so the reports database stops growing. It runs only
  when that quarter's report is VALID (Looking Glass then writes a purge permit), checks every date again itself, and
  deletes from the report collections only, once per quarter. Findings, cases, advisories and the quarterly reports
  are never deleted. The timing has no setting. The result is in the administrators' bell, Settings → Quarterly and
  the audit log.
- **Tutorials and glossary for the quarterly reports:** the Tutorial button on the Executive portal, the advisory
  portal and Settings explains them, and the glossary has "Quarterly report" and "Quarterly purge". A new check makes
  sure every feature ships with its tutorial steps, glossary terms and documentation.
- **A certificate check in the tests no longer fails at random.** It made certificates valid from that very second
  and checked them at once, so a clock that stepped back a moment made them "not yet valid". They now start a few
  minutes earlier (or the check waits briefly where OpenSSL cannot set the start).
- **Developer Certificate of Origin.** Every commit is signed off (`Signed-off-by:`, `git commit -s`): its author
  certifies the [DCO 1.1](https://developercertificate.org/). Pull requests are checked for it ("Commits signed off");
  see CONTRIBUTING.md, "Commits".
- **After updating:** update the platform **and** the database pipeline (it gets `quarterly_purge.py`). Nothing to
  configure. The first report made by itself is the one of the quarter that ends after the update; earlier quarters
  can be made in Settings → Quarterly, without a purge. Include `data/quarterly/` in your backups (all of `data/` is
  already): after a purge, those reports are the quarter's record. Tell management and advisors where their downloads
  are, and that they have 15 working days after each quarter to keep a copy. Contributors: sign off your commits
  (`git commit -s`).

## 2026-11-20 (9)
### Changed
- **The security assurance case.** [Architecture and threat model](docs/ARCHITECTURE.md) has a new section, "Why the
  security requirements are met": how secure design principles are applied (least privilege, fail-safe defaults,
  complete mediation, separation of privilege, economy of mechanism, open design, defence in depth) and how each of
  the OWASP Top 10 weaknesses is countered. With the threat model and the trust boundaries above it, it is the
  assurance case.
- **After updating:** nothing to do (documentation only).

## 2026-11-20 (8)
### Security
- **Small Trace a leak searches are counted however they are sent.** The administrators' bell warns when one person
  runs many traces of only a few items, since one or two addresses at a time can test guesses. Only pasted text was
  counted: an uploaded file, a ZIP holding one, or a single address padded with filler lines answered just the same
  without being counted. A trace now counts as small when it gives at most 3 lines **or** at most 3 addresses, pasted
  or in a file (a PDF can only match as the exact same file, so it never counts). Found by an external review.
- **After updating:** nothing to do.
### Fixed
- **The sign-in globe showed one country only.** Its attacks all aimed at a single fixed country, whatever country
  the installation serves. Looking Glass serves every country: the globe now marks three countries at a time, picked
  at random from cities on every continent and replaced one by one, and most attacks land on them. It never marks the
  installation's own country, so the sign-in page still says nothing about the installation. No slower to draw.
- **Two test-code alerts from GitHub code scanning (CodeQL):** the signed-out check now insists on TLS 1.2 or newer
  and reads a page's scripts with an HTML parser instead of a pattern.
- **A timing-sensitive check made reliable:** the pipeline settings check finds its own result by its request, not by
  the newest file, which two results written in the same instant could swap.

## 2026-11-20 (7)
### Changed
- **Governance: Community instead of Continuity.** The section now invites CSIRTs and people to collaborate, send fixes
  and improvements as pull requests and report security issues privately; the roadmap points to it.
- **After updating:** nothing to do (documentation only).

## 2026-11-20 (6)
### Changed
- **The guides use the port you selected.** The installer asks which port Looking Glass listens on, so the
  installation guide, operations, configuration, technical reference and both READMEs now write
  `http://localhost:<your port>` (and the same in the SSH tunnel, health check, firewall and reverse-proxy examples)
  instead of a fixed port. [Installation](docs/INSTALLATION.md) says once where your port comes from: the installer's
  **Port** question or `deploy/install.sh --port`, kept in `.env` as `LG_PORT`.
- **After updating:** nothing to do (documentation only).

## 2026-11-20 (5)
### Added
- **A second layout of the CLogin check-in decodes.** Some *android.badbox2* check-ins carry their data in Base64
  text that needs no padding, followed by `=` and a short trailer that is not XORed. The `=` was read as padding, so
  these were listed as *Unknown encoding*. They now decode like the first layout, and the Decoded beacon's note says
  where the trailer starts. Sent in through a decoding request.
### Changed
- **Every drop-down is in the Looking Glass design.** The 14 that still opened the browser's own list now use the
  platform's (search box on long lists, tick on the choice, full keyboard use): the organisation picker and the
  advisory's look and name, a finding's new status, the hand-over's recipient and person, the people picker, the
  combinations' report and device filter, the Abused or Compromised day, the definitions' note report, services sort,
  pattern kind and severity, the region match and the logo's background. Long names wrap in full; each keeps its size;
  an option's explanation stays as its tooltip.
- **Coding rules checked on every change** ([Ruff](https://docs.astral.sh/ruff/), `ruff.toml` at the top of the
  repository): undefined and unused names, bare `except:`, mutable or computed default arguments, late-bound loop
  variables and the like; CI fails on a change that breaks one. The code was brought in line (no behaviour changed).
- **After updating:** nothing to do.
### Security
- **No error's own text reaches an answer** (GitHub code scanning, CodeQL): an advisory stopped by the ATT&CK duplicate
  guard now tells the advisor in fixed words and writes the detail to the service's log; Add a person answers only its
  open-links limit in words, anything else gets the plain error page. Two test-code alerts were also tidied.
### Fixed
- **The advisory page's two new drop-downs** (the PDF's look, the name at the top of its pages) showed as plain white
  browser lists: the page did not load the drop-down script. A check now makes sure every page that asks for the
  Looking Glass drop-down loads it, and that no drop-down is left as the browser's list.

## 2026-11-20 (4)
### Added
- **The map's infection filter shows what else the devices carry.** With an infection ticked, the list counts devices:
  how many of its devices also carry each other infection (none: greyed, at the bottom). Ticking two or more shows
  only the devices carrying every one of them, everywhere on the map, in Intel, the figures and an analysis. Analyst
  codes and findings made before keep the devices they were made with.
- **Smooth filtering on the map:** counts roll to their new figures, list rows slide to their new places, and arcs
  the filters leave out fade away (off with reduced motion).
### Changed
- **Every page opens with the loading animation**, from any link, not only the header's buttons (Write the advisory,
  Open the review and an advisory's Open on the Findings page opened without it), and the Executive portal's Settings.
- **A request too malformed to reach Looking Glass** (a garbled request line, a broken header, an oversized one) gets
  the same plain page as every other error, with nothing of what was sent repeated back. Before, the web server's
  own page answered, which named it.
- **The Management role** (the Executive portal) is described as managers, executives or team leads, so decisions need
  not wait on management: in the roles guide and diagram, the user guide, the glossary and the Admin page.
- **After updating:** nothing to do.
### Security
- New checks on every release: every route refuses a signed-out request (GET and POST), an identity or id in the
  address changes nothing, the sign-in page carries no data, and malformed requests get the plain page.

## 2026-11-20 (3)
### Added
- **A guided tour on every platform and portal.** A Tutorial button in every page header shows a short tour of that
  page: one part at a time, spotlighted, with what it shows, then the header's buttons. Back, Next and Skip, or the
  arrow keys and Escape. The first time someone opens a page they are offered the tour (Take the tour, Skip, or
  Don't show again for every page); the answer is remembered for that person on the server, in every browser.
- **An alert for many small leak traces.** When one person runs many Trace a leak searches of at most 3 lines each
  within 24 hours (20 by default, `SMALL_TRACE_ALERT`), administrators get an alert in the bell, linking to Audit.
  Only the person and the times are kept, never what was traced.
### Changed
- **The advisory's look and the name on its pages are now the advisor's choice, per advisory**, on the advisory page
  beside Add insights: the designed (dark) or plain (white) look, and Looking Glass, the organisation's name or no
  name at the top of the pages. They left Settings → Organisation. An advisory saved before keeps the choice
  Settings held, so its PDF does not change.
- **The advisory's MITRE ATT&CK mitigations are grouped by technique:** one block per technique, in code order, with
  its mitigations and MITRE's advice for that technique. A mitigation that defends against several techniques appears
  under each of them, once in each. Generate an advisory's report again to get the new layout.
- **After updating:** nothing to do. Two new files appear in `data/` as they are used: `tour_seen.json` (who has seen
  or skipped which page's tour) and `trace_watch.json` (the times of small traces, kept 24 hours).

## 2026-11-20 (2)
### Added
- **Settings → Organisation: size and crop the logo.** Choosing a logo opens a sizing step: the picture in the
  advisory's 2:1 logo frame (its border highlighted), Trim empty margins, a size slider, drag or arrow keys to place
  it, a background for see-through pictures, previews of the card on the dark and the plain advisory, the recommended
  size (about 464 × 232 pixels) and the saved size. Pictures up to 5 MB; the saved logo stays within 40 KB, made in
  the browser.
### Fixed
- **An advisory's MITRE ATT&CK reasons are no longer repeated per report.** Reasons that differ only in a report's,
  a CVE's or an infection's name are one sentence naming them all ("the 8 reports … to this technique … For each,
  14 IP addresses …"), on the PDF and the advisory page. A CVE's technique that CTID maps in two roles is listed once
  with both ("T1059.001 PowerShell (what attackers gain first; how attackers exploit it)"), in the CVE cards and CSVs.
- **ATT&CK codes in code order everywhere:** the techniques (T1021 before T1071.001 before T1133), each technique's
  mitigation codes, each mitigation's techniques, the cards, the CSV text and the advisory page. Generate an
  advisory's report again to get the corrected PDF.
### Changed
- **After updating:** nothing to do.

## 2026-11-20
### Added
- **The sign-in moves.** The card turns over between Sign in, Create an account and Back, and every next step (the
  authenticator, the recovery codes, the sign-in code, a new password) turns in. After a successful sign-in the button
  fades, the view dives deep into the globe to black, the Looking Glass logo draws itself, and the Overview opens. Off
  for anyone whose computer is set to reduce motion.
- **Hover labels on the header and portal buttons:** each says what it is at once, on hover or keyboard focus.
### Changed
- **No logo or picture on the sign-in pages any more** (and no tab icon): the organisation's name only, so scanners
  have no image to recognise. The Settings choice *Sign-in page logo* is gone; `/login/logo` and `/login/mark.svg`
  answer "not found". The organisation's logo stays on advisories.
- **After updating:** nothing to do. `data/signin_look.json` is no longer read and may be deleted.

## 2026-11-19 (9)
### Added
- **Advisories: Add insights.** An advisory can go out on its own, without the analysis pages (INSIGHTS): tick **Add
  insights** to include them. A new advisory starts without them; one written before keeps them. The advisory pages,
  TECHNICAL DETAILS and REFERENCES always stay. Turning it on or off marks a generated report out of date.
- **The advisory PDF's look and the name on its pages** (Settings → Organisation → Advisory PDF): *Designed* (dark
  pages, as before) or *Plain* (white pages for printing; the TLP label unchanged), and at the top left of each page
  *Looking Glass* (as before), the organisation's name, or no name. Each change is in the audit log.
- **Settings → Workers: a Copy button for the confirmation command**, so the copy is recorded like every other copy.
- **Settings → Constituency: pick address blocks from the reports.** Every /24 in yesterday's reports on both
  platforms, with its records and network, searchable; tick one to add it to the extra address ranges. Typing a range
  still works, and nothing is looked up outside Looking Glass.
### Fixed
- **An advisory lists each MITRE ATT&CK technique once.** A technique that several reports, categories or CVEs map to
  was printed once for each of them. It is now one entry with every reason under "Why it is in this advisory", each
  CVE's mapping note once, and the strongest certainty (Observed before Possible). The advisor still reviews each
  mapping on its own. Generate an advisory's report again to get the corrected PDF.
- **MITRE mitigations in one section, grouped by code.** Instead of a "How to defend" list under every technique, the
  advisory has one section, *How to defend: MITRE ATT&CK mitigations*, with each mitigation once (M1016, M1031, …, in
  code order) and the techniques it defends against; each technique names its mitigation codes.
- **Each ATT&CK technique once everywhere else too:** the names' cards (Technical Details, Executive, the services
  and management pages) and the advisory page show a technique once with every report it came from. A guard stops a
  report from being made if a technique or mitigation would ever be listed twice, and the release checks look for
  repeats on every page and in every PDF.
- **An advisory's REFERENCES list every report it names**, also the reports its devices were also seen in (for
  example *Device Identification*), marked as such.
### Changed
- **The counts in the filters follow the other filters** (map and services platforms): each list counts the records
  matching every other filter, so drilling down shows what each choice would give instead of the whole day's figures.
  A list's own choice never hides its alternatives, and a chosen value with nothing left stays listed with 0.
- **After updating:** nothing to do. Advisories keep today's look and the Looking Glass name until an administrator
  chooses otherwise.

## 2026-11-19 (8)
### Security
- **Trace a leak can no longer be used to test guessed addresses** (external review): one trace of a whole range of
  guessed addresses said how many matched, and halving the range found an address in 17 traces. A trace now compares
  at most 1,000 lines and 1,000 addresses one by one (more: only the exact text or file is looked for, and the answer
  says so), and reports a copy or download only when it is exactly what was given or holds at least half of its lines
  or of its addresses. A real leaked excerpt is still found, also when it was reformatted. At most 100 traces a day
  per person, besides 5 a minute.
- **Copies recorded: at most 30 a minute per person.** A flood could fill the disk and the audit log, and copying the
  same rows over and over could make them "common", so that a trace left them out. A line now counts as common only
  when it is in many PEOPLE's copies and downloads. Old seals are removed every day (they were removed only when the
  service started), and a trace reads the seals one at a time.
- **A sign-up link never gives an administrator's or an auditor's role** (or any role with their rights): those
  accounts sign up on the sign-in page and are approved on Admin → Users. A link whose role was given those rights
  after it was made no longer works.
- **Only the researcher's answer to an analyst's request makes them follow management's review** (external review):
  any reply carrying codes, by anyone in the request's channel, did. Now it is the one reply that sent the request
  back to the analyst, made by a researcher; it alone also links a review to the request.
### Changed
- **Settings → Definitions → Issues says what each issue is, in full:** under each CVE's title, its whole public
  description (NVD's, else the CVE.org record's, with CISA's explanation added for an exploited CVE whose record says
  little); under any other issue, its definition.
- **A look-up window can be closed at any time, and closing it stops the look-up** ("Explain the names", "Explain
  issues", the Definitions look-ups and the others): the window opens at once, even while a long list is still being
  gathered, and closing it stops both the gathering and the search on the server. The button is ready again.
- **After updating:** nothing to do. A sign-up link made earlier for an administrator or an auditor stops working;
  make the account by sign-up and approval instead.

## 2026-11-19 (7)
### Added
- **Every port an IP address was seen open on, with the service**, in the devices CSV of the combination search, the
  analyst code package and the advisory (`all_ports_and_services`, for example `22/tcp Accessible SSH; 443/tcp
  Accessible SSL, Vulnerable HTTP`), beside the ports of the selection's own records.
- **The analysts' PDF has an Impact section**, as the advisory has: what the reports its devices were found in can lead
  to, the most severe first, with the reports behind each.
### Changed
- **A researcher who answers an analyst's request follows it on.** When the analyst sends the researcher's code to
  management (a review, or a case for several organisations), the researcher is in its channel: they see management's
  decision and the advisory's progress, and the review sits inside the request on the Findings page. Never an address.
  Requests answered before this update count too.
- **One code per infection, CVE and issue** in *In every other category* (Intel gathered) and on an analyst code's
  page, with one **Move to notes**: the name's devices in all the reports they were found in, which are listed under
  it. It was one code per report, which made the lists long. Codes handed out before keep working.
### Fixed
- **The Findings page's device counts could keep the wrong answers when the computer's clock was adjusted**: the
  count cache now times its answers with a clock that never jumps and drops the oldest one first.
- **Settings → Workers could list two pipeline results in the wrong order** when the pipeline wrote them within a few
  milliseconds of each other; each result now carries an exact time.
- **After updating:** nothing to do.

## 2026-11-19 (6)
### Added
- **CVEs and issues get codes and Move to notes in *In every other category*** (Intel gathered → Across reports), like
  infections: one code per report a CVE or issue was found in, for exactly the devices carrying it there. Fewer than 5
  devices: no lasting code for researchers, as for every other pattern.
- **Each *Combinations across reports* card says what its devices carry**: the CVEs, issues and infections on them,
  each with how many of the card's devices; a name opens its Intel gathered. Names and counts only.
### Fixed
- **A CVE read "No definition yet"** (on a code card) **or just "CVE"** (Settings → Definitions → Issues) although its
  public record had been looked up. It now takes its title from that record: CISA's name for it, else the title its
  issuer gave it, else the first sentence of its description. Only what is already looked up is used; a definition
  your researchers wrote still comes first.
- **The Overview's tooltips opened underneath it** and could not be seen; every tooltip now sits above every panel.
- **After updating:** nothing to do.

## 2026-11-19 (5)
### Added
- **The guided installer: a Back button on every question** (text mode: type `<`); earlier answers are kept, and
  passwords are never written down for it. Esc still stops the installation.
- **"Any computer on our internal network"** under *this computer and chosen networks* (`VIEWER_NETWORKS=internal`:
  every private range, never the internet), for a CSIRT's operations network. The allowed-networks list now refuses
  `0.0.0.0` (that let nobody in) and `0.0.0.0/0` (that is the whole internet), saying what to type instead.
- **Add a person** (Admin → Users): a one-time sign-up link with the person's role; they set their own password and
  authenticator, and the account works at once. Works once, for 72 hours (`INVITE_HOURS`), revocable, audited (never
  the link), also when sign-up on the sign-in page is closed.
- **The bell tells administrators when someone signs up**: one notice for everyone waiting, leading to Admin → Users.
- **Network changes are caught**: the bell (and the installation check) warns administrators when this computer's
  address no longer matches the self-signed HTTPS certificate or MongoDB's listening address, with the fix.
- **The installer offers to look up network names** (No by default; only AS numbers are sent) and says what No means:
  "Unlisted network" in demo mode and one check skipped.
### Fixed
- **The first administrator could not be made on the sign-in page when sign-up was closed** (`REGISTRATION=0`), while
  the installer said "Let's get started". The first administrator now always signs up with the setup code; closing
  sign-up closes it for everyone else.
- **The installer failed when Ubuntu's automatic updates held the package manager** ("Could not get lock"). It now
  waits, showing what for, and asks after 10 minutes without progress (stopping the update never hangs).
- **The installer accepted ports browsers refuse to open** (6000 gave *ERR_UNSAFE_PORT*): they are refused, and a safe
  free one is suggested.
- **A fresh installation's own checks failed** where nothing was wrong: the pipeline check read its bookkeeping
  collection as a report; the security retest needed a sign-in form before any administrator existed; every Python file
  was made executable; the demo masking test took "Unlisted network" for a network's alias.
- The Settings page's `.env` box says it is read only, and where to change the values.
- **After updating:** nothing to do. If the bell then warns that the certificate no longer matches this computer's
  address: `cd platform && deploy/make_tls_cert.sh <the name or address people use>`.

## 2026-11-19 (4)
### Changed
- **Someone who is not signed in can no longer tell what runs here.** The sign-in, account and reset pages name no
  product: they show the organisation's name and logo (Settings → Organisation → **Sign-in page logo**: the
  organisation's logo by default, the Looking Glass logo, or none; audited). Redirects and error pages are plain, with
  the standard status lines, file tags are neutral, there is no Server header, and the security policy sent before
  sign-in names no outside library or version. The platform's scripts and styles need a sign-in; only the files the
  sign-in pages use stay open. New HTTPS certificates are named after the machine (or the name given), never after
  the product. Looking Glass is open source, so this is defence in depth: keeping the platform off the open internet
  (a VPN, a firewall allowlist) stays the strongest step.
- **After updating:** `/healthz` answers this computer only: monitoring from another computer gets "Not Found" (run it
  on this computer, or through the reverse proxy here). The HTTPS certificate keeps its old name until you make a new
  one with `deploy/make_tls_cert.sh <the name people use>`; each screen then trusts it once more.

## 2026-11-19 (3)
### Added
- **Every copy is recorded before it happens.** Copying on the pages is only through the copy buttons; text cannot be
  selected, copied or dragged out except in the fields people type in. Each copy button asks the server to record the
  copy first (who, what, how many lines and addresses, which page, when) and copies only when that is done: when it
  cannot be recorded, nothing is copied. The copy buttons were not recorded before. The Audit portal has a new
  **Copies** tab. The copied text itself is never recorded.
- **Sealed copies and downloads, and Trace a leak.** Every copy and every downloaded file is sealed with keyed
  fingerprints (the whole, each line, each address; a file's SHA-256, and each file in a ZIP), never the text. In the
  Audit portal, **Trace a leak** (auditors and administrators) matches text or a file found outside against the seals:
  who copied or downloaded it, when, and how closely it matches. What is traced is not kept; each trace is audited
  (how many matches, never what was searched), at most 5 a minute per person.
- **Every page header names the person signed in by their full name**, and the Overview says: "Everything you view,
  copy or export on Looking Glass is recorded under your name."
- **After updating:** nothing to do. Looking Glass makes the sealing key at the first start (`data/copy_seal.key`,
  owner-only) unless `COPY_SEAL_KEY` is set in `.env`; keep it with your backups, since seals made with a lost key can
  no longer be traced. The seals (`data/copy_seals.jsonl`) are kept as long as the audit log (`AUDIT_RETENTION_DAYS`).

## 2026-11-19 (2)
### Added
- **The severity map, on the Definitions page (researchers and administrators only).** Every infection and issue the
  reports carried, with its criticality and where it comes from: rated by Shadowserver (the highest severity
  Shadowserver gave the records that carry it), not rated (no record rates it, listed first) or rated by a researcher.
  A researcher can give a not-rated name a level, or take it back; Shadowserver's own ratings are never changed, and
  when Shadowserver later rates a name, its level replaces the researcher's (shown as replaced). Every rating is in the
  audit log (`severity_rated`). The PDFs' References section uses a researcher's rating where no record rates a name,
  flagged "Researcher's rating". CVEs are rated by their CVSS score and are not on the map. The names are kept in
  `data/name_kinds.json` and the ratings in `data/name_ratings.json` (names only: no host, no address, no count).
- **After updating:** about two minutes after the service starts, Looking Glass reads every report's records once more
  in the background (infection, issues, tags and severity only, in batches with pauses), so the map also lists the
  names no record rates from before the update. Nothing to do; `NAME_LEVELS_DELAY_S=0` turns it off.

## 2026-11-19
### Changed
- **Documentation: for CSIRTs in every country.** The documentation site's home page, its title and description, its
  link-preview card and the guided installer's banner now say "built in Africa, for CSIRTs in every country", as the
  README does.
- **Documentation: memory and disk measured again on this version.** The installation guide adds a measurement of the
  current version (test installation, made-up data, about 67,000 records a day: about 2.3 GB for the platform and
  MongoDB together, within the 4 GB minimum). The README's requirements now give the same 4 GB minimum (it said
  about 2 GB), and the download and disk sizes are updated (about 70 MB to download, about 45 MB with `--depth 1`;
  the code itself about 6 MB). Nothing to do when updating.

## 2026-11-18 (8)
### Changed
- **Every PDF lists its references at the end, in a References section ordered by criticality.** The definition cards
  of the analysis, combination, Executive and advisory PDFs keep their explanation; their links now sit at the end,
  under one heading per name, then the Shadowserver reports the PDF draws on (the advisory's "Shadowserver Report
  References" page became this section). Each heading carries its criticality: a CVE its CVSS severity and score, and
  an actively exploited one (CISA KEV) also "Actively exploited", first within its level; an infection or an issue
  the highest severity Shadowserver gave the records that carry it; a Shadowserver report the severity Shadowserver
  gives that report type (INFO, Shadowserver's lowest level, as it says). A name with no severity at all is "not
  rated", listed last. The Executive PDF gains the section. A name whose days have left memory keeps the level it
  had: Looking Glass remembers each name's highest level in `data/name_levels.json` (names and levels only); after
  the update it learns them from the days it loads, so a name seen only before the update reads "not rated" until it
  appears again.
### Added
- **The advisory's preview names who opened it and when.** Every page of the preview carries "PREVIEW · NOT FOR
  DISTRIBUTION · name · date and time · reference" at the top and the foot, and a faint watermark behind the content
  (a picture, so it cannot be selected or removed as text). A screenshot of the preview therefore shows who took it.
  The report the advisor generates for the organisation carries none of it. Each preview was already in the data-access
  log.
  Nothing to do when updating; PDFs made after the update have the new layout.

## 2026-11-18 (7)
### Added
- **A check of Abused or Compromised against MongoDB** (`platform/tests/verify_intelligence.py`), like the checks the
  other pages have: every report's rows per day, its 7-day median, the group totals, "never received", "still
  arriving", each report's view and its CSV export, and management's counts, all recounted straight from the
  database. Read-only, counts only. It runs in the full suite on a running installation and skips itself where
  there is none. Its CSV comparison is recorded in the audit log as an export by the automation account.
- The suite's line for the page's other check now names it as people see it: "Abused or Compromised".
- **An outside-connection guard for the checks** (`platform/tests/no_outside/`). While the checks run with it, only
  the computer itself and the database can be reached: every other connection or name look-up is refused and
  listed, and the run fails on any place Looking Glass has no reason to reach. GitHub's checks run with it and a
  made-up map key, so a check that should send nothing is seen if it tries (an advisory had sent place names to the
  map geocoder, caught on a test installation only, 2026-11-18). GitHub's database job now also runs the advisory
  ATT&CK checks, where there is report data to load. On an installation: `LG_NO_OUTSIDE=1 tests/run_all_checks.sh`
  (see CONTRIBUTING).
  Nothing to do when updating.

## 2026-11-18 (6)
### Fixed
- **An advisory's Affected lists every infection, issue and CVE its devices show, from every report.** The devices
  table and the devices CSV named what each device showed in its other reports that day (for example "smb-scan;
  Compromised" from Compromised IoT), but Affected did not, when the finding's review was kept before 2026-11-17 (no
  device details were kept then). Affected and the table now read the same thing, worked out the same way.
- **The definitions in an advisory count the devices that have each issue,** for example "1 of the 148 devices in this
  advisory"; an issue could read as if every device of the combination had it.
  Nothing to do when updating; generate an advisory again to get the full Affected list and the counts.

## 2026-11-18 (5)
### Changed
- **The Findings page no longer waits for analyst codes' device counts after a restart.** Measured on a test
  installation, right after a restart, four codes' counts took 30 to 45 s together. Each one built the code's whole page,
  and that loaded the code's older day from the database twice, then again for every count (one large day loaded
  three times in 13 s). Three changes:
  - an analyst code's page loads its day once and uses it for its records too;
  - an older day loaded for an analyst code is kept a few minutes, so its page and its counts share it (**Older days
    kept for analyst codes**, default 1 day, and **How long such a day is kept**, default 300 s, on Settings →
    Configuration; 0 days keeps none, as before). A kept day costs about as much memory as a day in memory and is
    dropped as soon as the constituency or the stored data change. A code spanning many days is still read one day at
    a time, never two in memory together;
  - 30 s after a start, the device counts of every open finding's analyst code are worked out in the background, for
    people who see addresses and for those who do not, each kept apart (**Analyst code counts worked out after a
    start**, 0 = off).
  Nothing to do when updating; the defaults apply.
- **ATT&CK techniques in PDFs say only "Observed" or "Possible" again,** for example "T1071.001 Web Protocols · Command
  and Control · Observed". The line had grown to "Observed: this device was used for it". The analysis and Executive
  PDFs use the same form. The device's part is still in the cards and in the advisory's "Why it is in this advisory".
  In the advisory PDF, Observed and Possible have the cards' look (amber and teal, a faded outline); in the analysis
  PDFs the word is in the same colour.
- **"Why it is in this advisory" counts IP addresses for Observed techniques too, and says what they are linked to:**
  "3 IP addresses in this advisory have these affected devices (most often: …)". A technique linked to a botnet
  infection names the infections, one linked to an issue names the issues, one linked to a CVE names the CVE. Before,
  Observed techniques from a sinkhole had no figures, and Possible ones named the kinds of device.
  Nothing to do when updating; advisories generated again get the new wording.

## 2026-11-18 (4)
### Added
- **Two new checks of every page as people see it, run before every release.**
  - `platform/tests/pdf_pages_check.py` renders PDFs and finds text drawn over other text, the "…" cut-off and text
    off the page. It also runs in GitHub's checks.
  - `platform/tests/browser_checks.py` opens every page for every role in a browser and checks that every control is
    reached with the keyboard, focus is never trapped, lists are lists, no text is cut off and no page errors.
  - Both skip themselves where their tools are not installed (pypdfium2; Playwright with a test installation and its
    test accounts), so the suite runs anywhere.
### Changed
- **The advisory's own title is now the large title on its PDF.** The advisory page has one **Title** field (it
  starts as the finding's title); it is printed large at the top of the first page, with "*CSIRT* Security
  Advisory" in small letters above it. Before, the large title was always "*CSIRT* Security Advisory" and the
  advisor's words were the smaller line below. An advisory that already had a typed heading keeps it as the small
  line. A long title is no longer cut after three lines. Generate an advisory again to get the new layout.
- **The report page with the map is named "Geographic Location"** (it was "Where"), in the analysts' reports and in
  the advisory's insights.
- **The table of addresses says what it lists: "The IP addresses with the most records"** on a page named "IP
  addresses" (it said "The devices"), and page 1's preview is "The busiest IP addresses".
- **An advisory with more than 10 affected IP addresses points to its devices CSV instead of listing them.** The
  Affected IP addresses section gives their number and the name of the attached CSV; with 10 or fewer the table
  stays. The devices CSV now also has the **host_name** and **ports** columns (after ip), so nothing the table showed
  is lost; the analysts' devices CSV has them too.
- **Generate report always gives the advisory and its devices CSV together, never a PDF alone.** A finding that keeps
  no devices (made before devices were kept with findings) is refused with what to do: the analyst sends the
  combination to management again, and the new finding keeps its devices.
- **No page of an advisory prints the platform and scope line** ("Publicly accessible services · Ghana · whole
  country"). It was already gone from the advisory's own pages; the insights, Technical Details and references pages
  still had it. The analyst's own report keeps it.
- **An advisory's Technical Details pages are titled "Definitions"**: the badge beside the logo already says
  TECHNICAL DETAILS, so the title no longer repeats it.
### Fixed
- **An advisory's Affected section lists every infection its devices carry.** Its Categories showed only the infections
  from the devices' own sinkhole records, while the device table also showed those the search found on them that day
  (for example android.vo1d2 listed, avalanche-andromeda and m0yv only in the table). Categories, CVEs and Issues now
  list everything the device rows show. Generate an advisory again to get the corrected PDF.

- **The device counts beside analyst codes on the Findings page no longer wait for each other.** Every code was
  counted under one shared lock, so one code that takes long to count (about 16 s the first time, on a large
  selection) held every other code's count, and their loading placeholders could spin for over 30 s. Each code now
  has its own lock: a slow count only delays itself, and the same code is still counted once at a time.
- **Accessibility (found by an automated check of every page for every role, WCAG 2.2 AA):**
  - The top lists on the map and services pages, and the attack-type legend on the map page, made each list item a
    button, so screen readers met lists without list items. Each entry is now a real button inside its list item,
    at least 24 px tall (the touch-target minimum). They work the same with a mouse, Enter or Space.
  - The Executive portal's map was marked as a picture while holding a control (the whole-country switch); it is
    now a group.

Found by rendering every page of every kind of PDF the platform makes (110 pages) and checking each one:
- **Executive report, "Explained" pages:** a card's text stopped mid-sentence (the description after six lines, the
  researchers' notes and CISA's required action after three). Every line is now kept and the card grows to hold it.
- **Executive report, top infections and top issues:** a long name or a CVE's description was squeezed onto extra
  lines over the bar and the next row. The row now grows with its text, and the description goes under the name when
  it does not fit beside it.
- **Executive report, the bars beside them:** a long label ("Accessible GPRS Tunneling Protocol (GTP)") ran over
  the next row; it now wraps and its row grows.
- **Maps:** a region's name at the edge of the map ran into the list beside it; it now stays on the map.
- **Analysis report summary:** the list of actively exploited CVEs stopped after eight with "…"; it now names the
  rest as a count ("and 21 more, each explained under Issues explained").
- **Analysis report, the reports in the selection:** a report's name could end a page with its text on the next.
- **Audit evidence:** the method text showed "<i>backed</i>" as written; it now reads "backed". The seal's SHA-256
  is printed in full instead of shortened with "…".

## 2026-11-18 (3)
### Fixed
- **The advisory's table of affected IP addresses no longer leaves its heading alone on a page.** When the first row
  was too tall to fit under the report chips, it moved to the next page and left the section heading and the column
  names over half an empty page. The heading, the column names and the first row now always start on the same page.
- **Long names in the advisory and the analysts' report break at their hyphens.** A name too long for its column
  broke mid-word ("avalanche-androme" / "da"); it now breaks after a hyphen, dot, colon or slash ("avalanche-" /
  "andromeda"). In the analysts' report such a name used to run over the next column.
- **The advisory's Other days column is wider** (28 % of the table instead of 15 %), taken from the Reports and CVEs
  columns, so its rows are about half as tall and the table needs fewer pages. Generate an advisory again to get the
  corrected PDF.

## 2026-11-18 (2)
### Added
- **Findings pages keep up on their own.** A finding sent to you, decided or replied to shows on your open Findings
  page within about 15 seconds, no reload needed, and the cards that changed flash. While you type a comment or choose
  a person, a notice offers **Show the changes** instead of redrawing under your hands. The advisor's portal updates the
  same way; the review and advisory pages show the notice. This works for every role. The page only asks for a short
  fingerprint of the findings in your channels (no title, name or person), and only while the page is in front. Nothing
  to do when updating.
- **The review page shows the researcher and the analyst side by side**: *What the researcher is saying* (their
  finding and notes on the combination) and *What the analyst is saying* (the final comments and the analyst's
  replies).
### Changed
- **The Findings page groups a case as one: case → finding → sub-findings.** A researcher's finding and an analyst's
  request to management on the same combination used to be two separate cards, linked only by the code. The analyst's
  requests now sit inside the researcher's finding, which is marked *Case: the researcher's finding*, and the
  organisations' sub-findings stay inside each request. States, channels and decisions are unchanged, and the Open tab
  brings the whole case along while any part of it is open. Existing findings are grouped the same way. Nothing to do
  when updating.
- **An administrator's steps name the role they played.** Notes, findings and the review page said only
  "Administrator" when an administrator did a researcher's, analyst's or manager's work. They now say *Administrator
  acting as researcher*, *acting as analyst*, *acting as management* or *acting as advisor*. The role is worked out
  from the step itself (a note is research; a request from the analyst's tools is analysis; a decision is
  management's), so findings made before this update are labelled too.
### Fixed
- **Long text in the analysts' PDF tables no longer runs over the rows below.** A cell such as *Other days* stopped
  at three lines and squeezed the rest of its text into the third, which spilled over the next rows. Every line is now
  kept at the table's size and the row grows to hold it; the page breaks follow. Generate a report again to get the
  corrected PDF.

## 2026-11-18
### Added
- **Settings → Configuration: every setting in plain words, without a terminal.** A new tab lists every setting
  Looking Glass runs with: what it does, the value in use, where it comes from (`.env`, this page or the default) and
  its default, with a search box. The tuning settings (replay timing, loading and counting, memory and speed limits
  such as the decoded beacon answers kept, findings' deadlines, spike and pipeline alerts) can be changed within a safe
  range and are kept in `data/config.json`; they take precedence over `.env` and apply after **Restart now** (about a
  minute while the days are loaded again). The security switches, sign-in locks, the audit log's settings and the
  database connection are shown only, with the exact `.env` line to change on the server, so a stolen administrator
  session cannot weaken them; passwords and tokens are never shown, only whether one is set. Saving and restarting
  need a recent sign-in and are written to the audit log. Nothing to do when updating.
### Fixed
- **`SETTLE_MAX_SECONDS`, and `DAY_MAX_AGE_SECONDS` for the services platform, set in `.env` are now used.** They were
  read before `.env` was loaded, so their defaults always applied. `.env` is now read as the service starts, before
  anything else. If you set either one, check its value still suits you.

## 2026-11-17 (11)
### Changed
- **Intel gathered and the combination filters no longer make you wait for a recount.** The counts behind the
  Definitions page, the services patterns and the Executive portal's code filter used to be counted again while the
  page waited: about 22 s after a restart and 2 to 6 s after each new report or hourly refresh, all of it Python work,
  not the database. Now the counts already made are shown at once while one recount runs behind the page, and the
  Executive portal's day shares the report day's counts. The figures are the same; only the waiting changed.
  After a restart the first count is quicker too: most of it was the beacon decoder working through the day's request
  lines again, and its public answers (format, operator, version, OS family) are now kept in
  `data/beacon_summaries.json`, keyed by a hash, without any request line, host or device detail. They are thrown
  away whenever the decoder changes. A count that fails no longer shows an error page when earlier counts exist: those
  stay on screen, it is tried again after 30 s, and the administrators' bell and Settings → Task monitor show an
  alert until it succeeds.
- **Loading a day takes less memory.** The reports are read as they arrive from MongoDB instead of first being
  gathered whole, and without the few fields that were thrown away anyway: the largest report of a day needed 155 MB
  while loading, now 86 MB. Every record and every field shown is the same (checked record by record on a full day);
  a new check, `tests/check_day_skip.py`, fails if a later change starts using one of the fields left out.
- **The installation checks put far less load on MongoDB.** `tests/verify_stats.py` works out its figures in 9 queries
  instead of 91 (MongoDB time 53 s → 17 s), and `tests/verify_totals.py` reads only the report files around the day
  instead of whole collections (24 s → 1 s). They check exactly what they checked before.
- **MongoDB's own log is rotated.** `/var/log/mongodb/mongod.log` grew without end (hundreds of MB). A MongoDB
  installed by Looking Glass now gets a rotation rule: daily, or past 100 MB; 14 old logs kept, compressed. MongoDB is
  not restarted. **When updating:** if MongoDB was installed by Looking Glass, run once from the Looking Glass folder
  `sudo database/mongo_log_rotation.sh --now` (adds the rule and rotates the current log; running it again changes
  nothing). See *Updating* in the installation guide. The rest needs only the usual update steps.
- **The installation guide states the memory needed: minimum 4 GB.** It said about 2 GB, too little above about
  50,000 records a day. A new section, *How much memory*, gives figures measured with 50,000 to 300,000 records a day,
  explains that memory follows the reports and not the number of users (one process with 8 threads, shared by every
  role), and how to check and lower your own use. `ACCESSIBILITY.md` says what the keyboard check of 2026-11-17
  covered. The 2026-11-17 (9) entry now lists its two security-review fixes under **Security**, as the security policy
  asks. Nothing to do when updating.

## 2026-11-17 (10)
### Changed
- **Every page can be used with the keyboard alone.** On the map and the services platform, the chart legends (attack
  types, report families, severity levels) were mouse-only; they are buttons now (Tab, then Enter). The hourly and
  15-minute charts take the Left and Right arrows to choose a time and Enter to analyse it, with the time and its
  count written under the chart for screen readers. Every control shows a visible ring when it has keyboard focus
  (the map, the Executive portal's region map switch, sortable table headers included). See *With the keyboard only*
  in the user guide.
### Fixed
- **Two backups in the same second no longer write over each other.** `manage/backup.sh` names the second one `-2`
  (then `-3`...) instead of replacing the first archive and its checksum. Nothing to do when updating.

## 2026-11-17 (9)
### Security
Both found by the security review of 2026-11-17: work a single page request could make the server do, which repeated
requests could use to slow it for everyone (availability).
- **A record's details open at once for masked viewers.** On the services platform, opening a record looked for it by
  working out the masked id of every record of the day, up to about 2 seconds on a day of a million records. Each day
  now keeps a table of them, built on the first click.
- **Special Reports are counted in the background.** With a constituency set, the Overview's Special Reports list read
  every row of every Special Report while the page waited. A page now gets the last count at once and an expired one is
  refreshed behind it; just after a start or a change of the constituency the list appears on the next visit.
### Changed
- **The GitHub checks now test which devices an advisory carries** (`check_combo_review`, `check_ticked_names`), on a
  made-up week whose combinations span several organisations.
  Nothing to do when updating.

## 2026-11-17 (8)
### Fixed
- **The researcher's words appear once on a review.** Under *What the researcher is saying*, a finding made from a
  researcher's note was shown twice: as *Their finding* and again as the note itself. The note the finding was made from
  is now left out; the researcher's other notes still show. Nothing to do when updating.

## 2026-11-17 (7)
### Changed
- **The Combinations search counts the report day by default.** An analyst pasting a researcher's code now gets
  exactly the devices the researcher and the Executive portal counted (the report day), not every day in memory.
  The days in memory and the stored date range are still there, and every day is now matched on its own: a device
  counts on a day when it carried the whole combination that day.
- **Each device says what else it is, and what it did on the other days.** The device lists of the search (page,
  PDF, devices CSV) and of the advisory name each device's infections, issues and CVEs that day. On the report day
  an **Other days** column says, per device, whether it carried the same combination on the other days in memory, or
  changed and what it carried there instead. Reviews sent before this release keep their old device lists.
- **Intel gathered counts the report day only.** Patterns, exact combinations, **Across reports** and the sinkholes a
  report's devices call, on the infections and the services platforms, now count the report day (the day being
  replayed, or the newest day in memory), not every day in memory. Before, a device seen in one report on one day and
  calling a sinkhole on another could be counted together, so Across reports could show more devices than the Executive
  portal for the same day. The Executive portal's code filter matches on the day it shows; code look-ups still read
  every day in memory, so a code shown on an earlier day keeps its meaning.
  Nothing to do when updating.

## 2026-11-17 (6)
### Changed
- **sustat is named a campaign token, not "not decoded yet".** Its `p=` value is a few short random-looking values,
  each shared by many devices, with no text under XOR: a token, not device data. The request itself is a device check-in
  (`u.php`; `pic.php` with two more fields) whose device details travel in its other parameters, which are masked. It is
  no longer offered for a decoding request, since sending it could not give a decoder.
- **flyermobi's `/dzzb` request is named too:** the same ad SDK device ID as `/adbc` and `/adbsc` (hash-sized, not
  encoded).

### Fixed
- **A busy server no longer makes a check-in "did not decode".** The decoder's 0.25-second budget counted the clock, so
  on a busy server (the warm-up after a reload, several people at once) a decode waiting for others used it up, and the
  failure was kept for the life of the process: two CLogin check-ins that decode in 20 ms were listed under "Requests
  Looking Glass could not decode" and offered for a decoding request. The budget now counts the decode's own work, a
  decode cut short is never kept (it is tried again next time), and it is never reported as "did not decode".

## 2026-11-17 (5)
### Security
- **Masked viewers get less of each record.** External viewers and demo mode received two fields they never needed:
  the report's file name and the record's database id. A Shadowserver file name carries "details based on the
  organization and filters used to generate the report", so where reports are filtered per network it can name a
  constituent's organisation while the masked view shows that network as "Telco 3". Masked viewers now get the file
  name as its date and report type only (`2026-11-16-event4_sinkhole_http`) and a masked record id (`ev-…`, unique per
  record, under the same secret as the host labels). The services platform's record details accept the masked id.
  Analysts see both as before. Found in the security tests of 2026-11-17.
- **The security retest meets the 2026-11-17 security tests' probes on every release:** open-redirect tricks on the
  sign-in page (tab, newline, backslash, `javascript:`), sign-in and sign-out posted from another site, reflected
  `form=`/`mode=` values, researchers asking for host-level data, the 5-host value threshold lowered through the
  address, external viewers asking for exports or unmasking through the address, masked record ids and file names,
  and an SVG or disguised image as the organisation's logo.

## 2026-11-17 (4)
### Added
- **AI attack frameworks are an issue.** Since 2026-11-16 Shadowserver's Device Identification report also names hosts
  running agentic AI attack frameworks (ARTEX, CyberStrike, PentestCode, VXControl's tools and others), as device type
  `ai-attack-framework` with severity high, while the report's own default is info. Such a host now carries the issue
  **AI attack framework** on the services platform, so it is flagged, counted and filterable wherever issues are (the
  services platform, Findings, the Executive portal), instead of standing among the routers. The framework's name is
  the device's model, its maker the vendor. The issue has its definition, the report's description names the type,
  and the Glossary explains it.

### Fixed
- **The spike notice waits for a day's reports.** A day is compared with the one before only once it has at least
  80% of the reports the day before had (`SPIKE_COMPLETE_SHARE`); until then there is no notice. The morning's first
  report was read as a drop.
- The cache time chosen on Settings → Task monitor is read again whenever its file changes, also when two changes come
  within the same clock tick (a check failed now and then).

## 2026-11-17 (3)
### Fixed
- **The spike notice counts a day as the map does, without reading every record.** It found the two days by event
  time, which has no index, so each count read every record ever kept (about 7 seconds on a page request). It now
  reads each day through the platform's own day reader: the day's report files (indexed file name), the event time
  inside the day, and only the hosts inside the constituency when one is set, so its numbers match the map's. A day
  the platform already holds in memory is counted from there. It is worked out in the background, never while a
  page waits, and counted again only when a report's rows or the constituency changed.
- **The Special Reports list on the Overview follows the constituency.** With networks set in Settings, its rows and
  hosts count only the part inside them, as everything else does; a special report with nothing inside is not listed.
- Two live checks no longer read whole report histories: the decoder check finds its newest day by insertion order,
  and both read a day by its report files (`tests/verify_beacon_decode.py`, `tests/verify_replayed.py`).

## 2026-11-17 (2)
### Security
- **The path folding is stricter, and its limit is said plainly.** Path segments with digits or dashes, the usual
  machine and person names (`server01`, `finance-pc`, `kofi-mensah`), now fold to `<seg>`; so does a `;` parameter
  whose name is not a plain word (`;MINISTRY-PC01=1`), and a raw space in the path of a line approved earlier no longer
  stops the folding part-way. It stays best effort: a name that is itself a plain word (`jmensah`, `Administrator`)
  reads like a path word and is kept, which is why the administrator still approves the exact lines (security review
  of v2026.11.17).

## 2026-11-17
### Security
- **A decoding request carries only the path's shape.** The query was already masked, but the path left as it was, so a
  machine name, e-mail address or dashed address in it (`/u/MINISTRY-PC01/bot.php`) could reach the creator if the
  administrator missed it. Now plain path words and file names stay (`/api/v1/check`, `gate.php`); every other segment
  reads `<seg>`, `<n>`, `<long>`, `<address>` or `<email>`, and `;` parameters keep only their names. Lines approved
  before this release are folded the same way when downloaded (external review of v2026.11.16.10).

### Fixed
- `check_password_policy` no longer fails now and then when the suite runs under load: its throwaway administrator's
  password is dated a minute before the policy is switched on, not the same second.

## 2026-11-16 (14)
### Added
- **More CLogin check-ins decode.** Longer check-ins whose key the first recovery missed by a character are now read:
  the known start of their JSON fixes the first key characters exactly and the others are settled one by one, only
  after the normal reading fails (so nothing else is slower). When only the very end of the JSON was cut short in the
  request, the complete fields are kept with a note saying so.
- **Every decode is rechecked.** A decoded check-in is kept only when all its field names are the format's and the
  values with a fixed shape have it (the CPU hash, the MAC address, the bandwidth); a key that is not quite right never
  shows garbled data.
- **More families named:** flyermobi's ad SDK device ID (not encoded), weatherlive's other request paths (encrypted),
  the plugcallinfo terminal request (encrypted), and sustat's second host (not decoded yet).
- **A daily check of the decoder** (`tests/verify_beacon_decode.py`): on the installation's latest report day, how many
  CLogin check-ins decode, and that every one passes the recheck. Counts only.

### Security
- **Prompt injection in decoded data.** Encoded values are written by attackers. A decoded value that reads like
  instructions to a person or an AI tool is noted on the Decoded beacon as data, never an instruction, and a decoding
  request file opens with a line saying every value in it is untrusted data.
- A known family's value is offered for a decoding request only when it looks encoded, like unknown values: plain text
  at its place stays masked (security review of v2026.11.16.13, a point below the reporting bar).

## 2026-11-16 (13)
### Added
- **A spike notice on the Overview's buttons.** When the latest report day moved sharply against the day before,
  the cards say so and what is behind it: the infections that moved (with their report) for network communications,
  the reports for services. Analysts and admins see it on the two platform cards, management on the Executive
  portal's, researchers on Definitions'. A single report or infection that jumped is noticed even when the total is
  steady. Counts and names only. Settings: `SPIKE_RATIO`, `SPIKE_MIN_EVENTS`, `SPIKE_CACHE_SECONDS`.

- **The Glossary** (the in-app tab and the documentation's, generated from it) explains the new terms: Encoded
  request, Decoded beacon, Beacon status, Decoded beacons, Spike notice, Beacon code (LG-B) and Decoding request.

- **Known families not decoded yet can be asked for too.** *Requests Looking Glass could not decode* now also lists the
  requests of a known family that is not decoded yet (for example sustat) and of a known format whose value did not
  decode, with their known name, so an analyst can ask to send them for decoding automation and an administrator
  approves as for the others. An event's Decoded beacon and the Decoded beacons list point there. Encrypted values,
  hashes, IDs and tokens are still left out.

### Changed
- New features now install themselves from `features.py`, so `app.py` no longer grows with each one.

## 2026-11-16 (12)
### Added
- The film **Decoded beacons** (3:10, narrated, with captions) on the documentation site: on the home page and in the
  user guide beside the map's Decoded beacon, with its chapters.

### Fixed
- The user guide's *Playback* line on the map page shows as a list item again on the documentation site (it read
  "- Playback" as plain text).

## 2026-11-16 (11)
### Security
- Each step of a decoding request (asked, approved, sent) is checked again as it is saved, so two clicks at the same
  moment cannot both go through, and the request lines an administrator approved stay with the family once it is sent
  (security review of v2026.11.16.10, a point below the reporting bar).

## 2026-11-16 (10)
### Added
- **For reviewers.** A short box at the top of the README and a page, [For reviewers](docs/REVIEWERS.md), for
  anyone assessing the project: what it is and is not, how it is built, who sees what, its trust boundaries and how
  every release is checked (including the AI-assisted security review, whose every point is checked against the code), with the
  page to read for each.

### Security
- An administrator's approval of a decoding request is for exactly the request lines on their screen: they are kept
  with the approval and are what the download holds, and an approval is refused if the lines changed after the page
  was opened (security review of v2026.11.16.9, a point below the reporting bar).

## 2026-11-16 (9)
### Added
- **An administrator approves every decoding request.** On the Findings page, *Requests Looking Glass could not
  decode* now shows each family's exact request lines (*What would be sent*). An analyst asks to send a family, saying
  why; every administrator's bell says it waits; the administrator approves, or does not with a reason. Only then can
  the decoding request be downloaded and sent. Who asked, approved and sent it is shown and audited.
- **Each beacon family says what its value is.** In the Beacon filter, the Decoded beacons list (a new *Status*
  column), Intel gathered and an event's details: *decoded*, *encrypted* (encoded, cannot be decoded), *not decoded
  yet*, *did not decode* (a known format cut short), or *not encoded* (a one-way hash, a device ID, a campaign token).

### Fixed
- The backup scripts' check (`tests/check_backup_scripts.py`) no longer fails now and then: it takes the archive each
  run made, not the last name in order (a clock stepped back gave the first backup twice), and dates the "old archive
  made to look newest" past every other backup instead of "now".

### Security
- A decoding request keeps the undecoded value only up to the first raw space (what follows may name the device), and
  of a repeated parameter the copy holding the undecoded value; an analyst code's page no longer shows even the code
  of a beacon code held back for its viewer (security review of v2026.11.16.8, candidates below the reporting bar).

## 2026-11-16 (8)
### Security
- A beacon finding's beacon code (`LG-B-…`) and what it stands for reach only those who may see them: analysts and
  admins, and everyone else in the finding's channel while 5 or more devices carry the beacons. Below that, managers,
  researchers and advisors see the held analyst selection, as the title and summary already did, and an analyst code's
  page no longer names the beacon code it came from. The code book itself now gives a beacon code's meaning only to
  viewers who may see it (security review of v2026.11.16.7; threat-side values only, never an address).
- A decoding request masks every request shape: parameters split by `;`, raw spaces inside the query, a repeated
  parameter name (only the longest copy of the undecoded one is kept) and a target without a leading `/` (security
  review of v2026.11.16.7).

## 2026-11-16 (7)
### Security
- **A decoding request keeps only the value that could not be decoded.** A bot's own parameters can carry the
  device's address or machine name (`ip=…&host=…`): in the file sent to the Looking Glass creator every other
  parameter's value now reads `<value>` (names kept) and any address `<address>`, so it holds no host or address, as
  documented (reported by the external reviewer).
- A beacon selection's code page holds small patterns back in its *every other category* section too, for researchers:
  no code for a pattern fewer than 5 devices carry, as on the rest of the page and in Intel gathered (security review
  of v2026.11.16.6; codes and counts only, never an address). An analyst's handed-over selection keeps every code.

### Added
- **Beacons on the analyst's map.** A **Beacon** filter lists the day's decoded beacons by kind and system (for example
  *CLogin check-in, Windows*) and narrows the map, stream, Intel and figures to them. The analysis has a **Decoded
  beacons** figure whose list gives each kind's operators, versions, records, devices, the names it is filed under and
  its C2 domains; a row narrows the analysis to it. Analysts and admins only; each record is decoded once per loaded
  day.

### Fixed
- Opening a decoded beacon on the map no longer empties the cache of shared answers (decoding changes nothing).
- A beacon finding shows its beacon code (`LG-B-…`) and what it means, not the analyst selection behind *Show in
  Executive*, which keeps working as before. A beacon finding handed over before this release gets its beacon code
  the first time it is opened.
- The map's *Hand over these beacons* form and buttons use the Looking Glass styling.
- A services report's pattern fields taken back to the shipped ones (or a new product rule) show at once on every
  server. Where the file system keeps coarse modification times, a reset made right after a save could be missed until
  the next change (found by `tests/check_svc_patterns.py` on a server that installed the release).

## 2026-11-16 (6)
### Security
- The device counts behind an analyst code's page are kept per viewer level: what is worked out for an analyst is no
  longer served to a researcher who opens the same code within ten minutes, so a beacon selection's small patterns keep
  no code for researchers there either (security review of v2026.11.16.5; codes and counts only, never an address).

## 2026-11-16 (5)
### Security
- A beacon finding's analyst selection names no part of the beacons in its label while fewer than 5 devices carry
  them, as the finding's title already did; and a selection made from decoded beacons keeps the 5-device rule on its
  code's page for researchers (no code for a smaller pattern, no narrowing below 5 devices by ticking a CVE). Security
  review of v2026.11.16.4; threat-side values and counts only, never an address.

## 2026-11-16 (4)
### Security
- A beacon code (`LG-B-…`) worked out by hand now answers a researcher exactly like an unknown code, in the code look-up
  and when attached to a note, unless 5 or more devices carry its beacons, so it can't show that a held-back value
  exists (security review of v2026.11.16.3; threat-side values only, never device data).

### Changed
- **Management sees a beacon finding the normal way.** A finding about decoded beacons now carries an analyst code
  made of exactly its records, so **Show in Executive** opens the Executive portal on those devices: networks, regions,
  days and devices, counts only, like every other drill-down. Beacon findings made before this get it the first time
  they are opened.

## 2026-11-16 (3)
### Security
- A researcher handing over decoded beacons that fewer than 5 devices carry now gets the same answer as for beacons
  that don't exist, so guessing their parts can no longer show that a held-back value exists (security review of
  v2026.11.16.2; threat-side values only, never device data).

### Added
- **Governance and roadmap.** How decisions are made, who does what and what happens if the maintainer is not
  available ([Governance](docs/GOVERNANCE.md)); what is planned over the next year ([Roadmap](docs/ROADMAP.md)).
- **How vulnerability reports are handled:** acknowledged within 5 working days, assessed within 14 days, fixed within
  30 days (critical or high), 60 days (medium) or 90 days (low), disclosed with the release, and reporters credited unless they ask not to be
  ([Security, section 6](docs/SECURITY.md#6-reporting-a-vulnerability)).
- **Checking a release's signature**, with the signing key's fingerprint
  ([Installation](docs/INSTALLATION.md#checking-a-releases-signature)).

### Changed
- **Decoded beacons go to notes like every other pattern.** A *Beacon vs name* match, and each beacon operator under a
  report's cards, now has its own code (`LG-B-…`) and **Move to notes**, in place of the separate hand-over form. A
  note carrying it, tracked as a finding, takes exactly that drill-down to the Findings page, where analysts open its
  devices. Like every code it carries no address, and researchers get it once 5 or more devices carry the beacons.
- **A beacon finding's title says what it is.** Without a title typed, it reads like *BADBOX 2.0 beacons from Windows
  machines (android.badbox2)*: the family's readable name, what the beacons report and the infection name, so
  management and advisors see at a glance what they are deciding on.
- Beacon operating systems read as people write them (*Windows*, not `windows`) in *Looking Glass asks* and Explore,
  and the match's record count has its thousands separator.

### Fixed
- The analysts' hand-over form beside the map uses the same fields as the rest of Looking Glass, not the browser's
  bare controls.
- The "could not decode" section said the decoding request holds no infection name; it holds each request's infection
  name, and no host, address, user agent or count.

## 2026-11-16 (2)
### Security
- **Encoded beacons never reach a masked view.** An encoded check-in in a request decodes to the device's MAC address,
  hardware UUID and CPU id. In Demo mode, for the external role and in Intel gathered's URL values it now reads
  `<clogin beacon>`; the encrypted or opaque values of other request families read `<ttyunos value>` and the like,
  and any other long encoded value `<encoded value>`.

### Added
- **Decoded beacons.** Some bots pack what they know about the machine into one encoded query value of their check-in.
  Looking Glass now finds these in the HTTP request the sinkhole reports carry and decodes the formats it knows, starting
  with the **CLogin check-in** (`GET /CLogin?key=…`, filed under *android.badbox2*; operators zckypc, WT, PKS and HTM),
  recovering the XOR key from each check-in itself. Other request families seen in the reports (encrypted requests,
  hashes, opaque device IDs) are named, with what they are, but not decoded. Analysts and admins see a **Decoded
  beacon** block in the event details, under the HTTP request: the format, operator, version, operating system, XOR key,
  notes (the CPU id as text, what the MAC prefix means, a name the beacon contradicts) and the whole JSON. Researchers see
  only the threat-side parts in Intel gathered (*Beacon format*, *operator*, *version* and *OS*), each once 5 or more
  devices carry it, and a new **Beacon vs name** match in "Looking Glass asks" when decoded beacons name a different
  operating system than the infection they are filed under.
- **What the beacon says, not what to do.** When a decoded beacon names a different operating system than the
  infection it is filed under (a Windows 7 beacon under *android.badbox2*, for example), a note says so as a lead worth
  checking. The decoder adds no action of its own: the event keeps the name's recommended action, and what fits the
  record is the analyst's call.
- **Handing decoded beacons over.** A researcher (from Intel gathered or a *Beacon vs name* match) or an analyst (from
  the event details) sends decoded beacons to a named analyst or manager as a finding. On the Findings page everyone in
  the channel sees what was handed over and how many records and devices carry it; analysts and admins can also **Show
  the devices** (every record with its host and decoded JSON; recorded in the audit log). The beacons' parts are held
  back from the others while fewer than 5 devices carry them.
- **Generic fallback decoding.** A long encoded value no known format fits is tried with hex, Base64, zlib/gzip/deflate
  and a one-byte XOR, up to three layers deep. When the result reads as JSON, `key=value` pairs or words, analysts see
  it as a **Generic decode** with its layers. Real encryption is left alone.
- **Requests Looking Glass could not decode.** A section on the Findings page (analysts and admins) lists what still
  does not decode as families of one request shape, with the C2 hosts, names, reports and counts. Each can be sent to
  the Looking Glass creator for future automated decoding: a decoding request file holding only the HTTP requests (up
  to 5, each with its infection name; no host, address, user agent or count; confirmed against your TLP rules and
  recorded as an export), pasted into a private report on the separate HTTP Requests Decoding repository. A family that is not a beacon can be
  put away.

### Fixed
- Page files (scripts, styles and templates) are no longer marked executable; v2026.11.16 shipped some that were.
- The held-back reports list (Settings → Workers) no longer fails while the report database is unreachable: it lists the
  reports by their Shadowserver file names only, without the readable report names.
- The HTTPS look-up of the sender check's signing key only ever opens `https://` addresses (a code scanning finding).
- The checks on GitHub for v2026.11.16 failed on both of these; they pass again.
- A check of the services filters no longer fails early in the day, before the DNS Open Resolvers report has arrived:
  that part is skipped until there is something to check.
- **Architecture and threat model corrected.** The platform and the pipeline run as one Linux user (the page said the
  pipeline had its own): what keeps them apart is the web app's sandbox and their separate database accounts, and a
  shell as that user is now listed as a remaining risk. Also brought up to date: the lock time is a setting (5 to 240
  minutes), the audit log's signed daily checkpoints and their copy on another computer, the HTTPS look-up of the
  DKIM key, `pip-audit` on GitHub, encrypted backups, the per-person limits on heavy views, how the caches keep each
  role's answers apart, the decoded beacons and the decoding request.

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
