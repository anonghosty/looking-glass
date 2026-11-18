# Changelog

Notable changes to Looking Glass, newest first. Releases are named by date: the release of 2026-11-15 is tagged
`v2026.11.15`, a second one that day `v2026.11.15.2`, and each has its notes on GitHub's
[Releases](https://github.com/anonghosty/looking-glass/releases) page. To update an installation, follow
[Updating](docs/INSTALLATION.md#updating).

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
