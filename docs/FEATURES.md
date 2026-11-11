# What is new in Looking Glass

New features and notable changes, newest first, with the date they reached the platform. Each entry says where to
read more. Dates are UTC.

## Contents

- [2026-11-11: advisories, cases, an Overview for every role, the Audit portal](#2026-11-11-advisories-cases-an-overview-for-every-role-the-audit-portal)
- [2026-11-10: combination codes, the analyst's combination search and findings](#2026-11-10-combination-codes-the-analysts-combination-search-and-findings)
- [2026-11-09: researchers' intel, notes and a page of their own](#2026-11-09-researchers-intel-notes-and-a-page-of-their-own)
- [2026-11-09: security review fixes](#2026-11-09-security-review-fixes)
- [2026-11-09: faster platforms and a sharper Executive portal](#2026-11-09-faster-platforms-and-a-sharper-executive-portal)
- [2026-11-08: Executive portal, 7-day baseline, vulnerabilities and network types](#2026-11-08-executive-portal-7-day-baseline-vulnerabilities-and-network-types)
- [2026-11-07: definitions, the researcher role and PDF reports](#2026-11-07-definitions-the-researcher-role-and-pdf-reports)

## 2026-11-11: advisories, cases, an Overview for every role, the Audit portal

From a finding to the organisation that can act on it, with a name on every hand-over.

**New**

- **The advisor role and advisories.** One advisory per organisation (network), with that organisation's devices, the
  reports they appear in, what they are (*Seen as*), their weaknesses and the impact of each report. Never from a blank
  page: the advisor writes a short description and the actions, and the report carries the **insights** (the analysis
  behind the finding) and the **technical details** (every weakness and tag defined from the researchers' definitions,
  with references). The advisor chooses the TLP and generates the report.
  It is signed by the CSIRT (name and logo from Settings), never a person; the person is in the audit log. What goes
  to the organisation is two files: the PDF and the devices CSV, named `CSIRT_organisation_title_yyyymmdd`. No internal
  codes or notes travel with it. ([User guide](USER_GUIDE.md#advisories-the-advisor))
- **TLP 2.0.** Chosen per advisory (TLP:AMBER unless the advisor chooses), explained on the advisory page and on the
  Definitions page, printed in the header line and at the bottom right of every page.
  ([User guide](USER_GUIDE.md#tlp-how-far-an-advisory-may-travel))
- **Cases and sub-findings.** An analyst picks the networks before sending to management: several open a case with one
  sub-finding per organisation, each decided on its own. Management approves to a named advisor, or rejects with a
  reason. **Mark as drafted** on the advisory page and **Mark as sent** on the Findings page: the sub-finding closes,
  then the case when every sub-finding is closed, all logged. ([User guide](USER_GUIDE.md#findings-cases-and-who-holds-them))
- **The Findings page as a ticket tree**, folding at every level, with closed sub-findings in their own group and
  state pills that name who holds each one.
- **The advisor's dashboard:** waiting, drafts, drafted, sent, recipients, open and closed findings and cases, days to
  send, and the impacts carried.
- **Notifications.** A bell on every role's pages: what changed in your findings, one click to go there, clear your own.
- **An Overview for every role.** A greeting by first name (*Greetings, Name! Welcome to Looking Glass* the first time,
  then one of thirty at random), *Your pages* for that role in titled groups, and the Overview button in every header.
- **Peace of mind** for administrators: Admin, Audit, Settings and the Overview only, with no findings notifications.
- **The Audit portal** (`/audit`): the audit log and the sessions on a page of their own. The `audit` permission opens
  it; an auditor reads the sessions but only `users` can end one.
- **Loading animations** on every page and every tab that loads data.

**Changed**

- No general "move it on": every step is a decision by the person who holds the finding.
- Settings comes just before Log out, and Log out is always last in the header.

## 2026-11-10: combination codes, the analyst's combination search and findings

The team's workflow, end to end: a researcher finds something and names the exact combination, management weighs it
against the trends, an analyst pulls exactly those devices and writes the advisory.

**New**

- **Combination codes.** Every combination in Intel gathered has a short code: `LG-C-…` for one report, `LG-X-…` for a
  cross-report pattern. The same combination always gets the same code, and a code carries no address, so researchers
  and management can pass it on safely. ([User guide](USER_GUIDE.md#combination-codes-the-combination-search-and-findings))
- **A Notes window of its own.** Notes have their own **Notes** button on every row of both tables, apart from Define.
  A note can carry combination codes, picked from every combination of that name (grouped by report, with a filter),
  built by ticking the name's real indicators, or pasted (and checked). Nothing is typed by hand, so there are no
  typos. Notes and the PDF reports print the codes. For CVEs, the define button is now *Add context* / *Edit context*.
- **The analyst's combination search** (`/combinations`, for roles that see addresses and may export). Paste a code to
  see what it stands for and the researchers' notes. Then search the days in memory (exactly the counts the researcher
  saw) or up to 31 days of stored history, read one day at a time in the background. The results show the key figures,
  a map of the country's regions (hover a region for its devices, cities, networks and IP addresses), networks,
  cities, activity by hour, what the devices are, ports and the busiest devices. The download is a ZIP with a PDF in the
  Executive report's design (overview and key findings, the region map with each region's cities, the devices with
  their addresses, across reports, and the explanations of the name (each name, for an analyst code) and every CVE
  in the combination, each with its references and where it comes from, with the researchers' notes on those names;
  a chart with nothing to show is left out) and two CSV files (one row per device, one per record). A finished search survives a service
  restart for an hour; an expired one is run again by the download button. Off in Demo mode; every search is in the
  audit log.
- **Findings** (`/findings`). A note can be tracked as a finding: it gets a number and a status (*New → With
  management → Back with the researcher → With the analyst → Advisory sent → Closed*). Each move records who, when and
  a comment. Researchers, management, analysts and admins share the page; it never shows an address. Analysts get a
  **Search** button on every code.

- **Analyst codes (LG-A) and replies.** An analyst turns the selection of any analysis window (map or services
  platform), say a network and one host, into an analyst code and a finding, with a title and a note. Researchers open
  it at `/intel/LG-A-…`: the names in exactly those records, their definitions, and their combinations and
  cross-report patterns with codes, never an address. They tick codes and **reply on the finding**; every reply, with
  its codes, is in the finding's history. Management filters the Executive portal by the analyst code (that day, counts
  only). Analysts find every analyst code again in a searchable list on the Combinations page and download its PDF +
  CSV for the advisory. The code keeps the exact records of the selection, so every role sees the same ones.
- **A report per network provider.** On the Combinations page, **Report for** (or a click on a network) gives the PDF +
  CSV for one operator only, named after it, to attach to the advisory sent to that provider.
- **Management follows a finding in the Executive portal.** On the Findings page management gets **Show in Executive**
  for each code: the portal opens filtered to exactly that combination (a *Combination code* chip, counts only, never an
  address; the 7-day comparison is left out, as past days do not keep the indicators). The combination search with the
  addresses stays with the analysts.
- **Definitions tables: sorting and the Across reports flag.** Click a column heading to sort (↕, then ▲ / ▼): name,
  seen in / hosts, status, and the new **Across reports** column, which flags every name whose devices or hosts turn up
  in more than one of its reports (⇄ with the count); one click opens its cross-report view.

**Changed**

- **Network names stay editable.** A reviewed network can always be changed (a company renames or rebrands): the list
  opens on every network when none is left to review, the empty review queue offers *Show every network*, and the
  search looks through every network whatever the tab.
- **Overview:** the page buttons (Executive, Admin, Definitions, Combinations, Findings, Settings) are centred at the
  top; Log out and the scope stay on the right.
- **Day change:** loading a new day no longer holds up the pages. The reload runs after the replay schedule's lock is
  released, so the replay position and status answer at once while a day loads. Tested with a simulated day change and
  the real reload from the database.
- **Intel gathered:** Sinkhole DNS lookups (and TLS server names) are part of the combinations, so a DNS report no
  longer looks like "the name only". When a name's devices never share a report, the window explains why (IPv6 and IPv4
  reports, and DNS reports that see the resolver). Switching report keeps your place instead of jumping to the top.

## 2026-11-09: researchers' intel, notes and a page of their own

**New**

- **Intel gathered.** Every infection and issue on the Definitions page has an *Intel gathered* button: what the
  reports carry for it, organised as name › report › what comes with it there. C2 domains, DNS lookups, TLS server
  names, URLs, user agents, request patterns and brute-force usernames for infections; other CVEs on the same hosts,
  associated tags, products, certificate names and fingerprints for issues. Each value shows records, share and hosts,
  with *Copy* for other tools. Indicators only: hosts are never shown.
  ([User guide](USER_GUIDE.md#5-analysis-and-follow-up), [Technical reference](TECHNICAL_REFERENCE.md#researchers-intel-notes-and-where-a-name-was-seen))
- **Combinations and repeating hosts.** The exact sets of tags and CVEs (and for communications C2 domain and user
  agent) that occur together on one record, with records, share, hosts and ↻ the hosts that repeat them: why one
  indicator counts less than another, and which patterns are campaigns rather than one-offs.
- **Across reports.** For a name seen in several reports: the combinations each device carried in each report, the
  sets of reports that see the same devices, and the indicators that turn up in more than one report.
- **Looking Glass asks: can you look into this?** Matches the platform finds in the reports: the same indicator under
  two names, in two reports for one name, or on both platforms. It points out when one of the names has no definition
  yet. Values common to everything are never raised.
- **Researchers' notes.** Dated, signed notes on new findings, kept apart from the definitions and never replaced by an
  update; shown on every card and in the PDF reports as "Notes shared by Researcher: *full name* (*date*)".
- **Seen in, as report cards.** Each report a name appears in shows *intel · N kinds* or *name only*; one click opens
  that report's intel. Names not in today's reports show **Last seen in *report* on *date*** (30 days remembered).
- **The Definitions page stands on its own** (`/definitions`), with the Looking Glass loading animation; admins reach it
  from the intro page, the map, the services platform and Settings. Settings shows network names read-only.
- **Full names.** Definitions, notes, network corrections and reports name people by their registered full name; the
  audit log shows *Full Name (username)* and finds people by either. The audit table fits the page.
- **Knowledge base checked and completed.** Every infection now carries evidence (a Malpedia family or references to
  Shadowserver's report documentation and vendor or CERT research); three new names defined; the amplification-DDoS
  entry corrected (the report names the victim, not the attacker); Sinkhole DNS entries explain that the address is
  usually a resolver. Shipped entries are signed *Looking Glass*.
- **Documentation in one place.** Every guide is in `docs/`, including the security policy (`docs/SECURITY.md`); the
  glossary has the new terms.

## 2026-11-09: security review fixes

- **Safe CSV exports:** no cell can run as a spreadsheet formula (formula characters get a leading apostrophe).
- **Masked views accept only aliases:** a real network name or AS number no longer works as a filter in Demo mode or
  for roles without *unmasked*, so a viewer cannot test whether a network is in the data.
- **Pinned events** belong to the signed-in account and are deleted at log-out; masked accounts keep none.
- **A masking test that can fail**, plus unit tests for the masking and the roles.
- **Release builds:** publishable only after a clean scan, images and PDFs scanned for hidden metadata, curated data
  checked to reach the repository, documentation links checked.
- **Maintenance tools repaired** (`tools/daysize.py`, `tools/quickcheck.py`, `tools/list_infections.py`,
  `tests/test_sources.py`, `manage/manage_users.py`).

([SECURITY.md](SECURITY.md#4-changes-made-after-the-penetration-test))

## 2026-11-09: faster platforms and a sharper Executive portal

- **Shared results:** figures computed once and shared by everyone viewing the same day and filters, so busy days and
  many viewers answer quickly; new reports still appear as soon as they arrive.
- **Executive portal:** clickable "Top findings" combinations that filter the whole portal, full vulnerability names,
  and the 7-day baseline from compact past days (quicker, same results).
- **Event stream:** clear messages while a report waits for its replay time, and "IP address(es) or host(s)" wording.

## 2026-11-08: Executive portal, 7-day baseline, vulnerabilities and network types

- **Executive portal** for the management role: aggregated figures only, never an address, with executive PDF reports.
- **7-day baseline:** every figure compared with its own average over the previous 7 days, graded on a stated scale.
- **Vulnerabilities explained in batches** (CISA KEV, EPSS, CVE.org, NVD) with a progress window; reports as a ZIP of
  PDF plus CSV.
- **Network names and types** for researchers, with types (sectors) a site can add.
- **Licence:** GNU AGPL-3.0.

## 2026-11-07: definitions, the researcher role and PDF reports

- **Definitions** with references for names Malpedia does not know, and the **researcher** role that writes them.
- **PDF reports** on every list behind an analysis figure.
- **Penetration test** and its fixes ([SECURITY_REPORT.md](SECURITY_REPORT.md)).
