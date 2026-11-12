# Looking Glass: technical reference

![Looking Glass](../platform/static/img/logo.svg)

How the platform works inside: data sources, replay schedule, both platforms, masking, the API and every script.
Installing: [INSTALLATION.md](INSTALLATION.md). Using it: [USER_GUIDE.md](USER_GUIDE.md). Settings:
[CONFIGURATION.md](CONFIGURATION.md). Day-to-day running: [OPERATIONS.md](OPERATIONS.md).
Figures, names and numbers in the examples below are invented illustrations.

**Looking Glass** is a live threat map built with Flask, Mapbox GL and deck.gl. It replays Shadowserver events from MongoDB with a 24-hour delay, so yesterday's events play out at the same time of day today.

It integrates **every Shadowserver collection that describes a source-to-destination communication**, discovered automatically. Each event carries its collection as its **source report**, plus an **attack type**.

## Data sources

At startup, and every 6 hours after that, `sources.py` scans the database. A collection qualifies when:
- its latest documents have field names containing `src` or `dst` (or the referer source fields);
- it has a `filename` index;
- it is not listed in `EXCLUDE_COLLECTIONS`.

Four layouts are normalized into one schema:

| Layout | Collections | Source → destination |
|---|---|---|
| standard | `event4_*`, `event6_*`, `microsoft_sinkhole_http` | `src_*` → `dst_*` |
| legacy | `darknet`, `ddos_amplification`, `hp_http_scan`, `hp_ics_scan`, `microsoft_sinkhole`, `sinkhole_http_drone` (2018–2021 reports) | `ip`/`geo`/`asn`/`city` → `dst_*` |
| referer | `event4_sinkhole_http_referer` | `http_referer_*` → `dst_*` |
| inbound | `spam_url` | `src_*` (spam sender) → `ip`/`geo` (local host) |

Attack types come from the collection name: Botnet C2 (sinkholes), Brute force, Scanning (honeypots and darknet), DDoS, Initial access, IP spoofing and Spam. Any field outside the common schema is kept per event as `extras` and shown in the detail view under "… specific fields". For example, brute-force usernames and passwords, the SSH client version, DNS queries, DDoS attack type and duration, and raw honeypot requests.

Which collections have rows depends on the day and the country. Typically the sinkhole reports (`event4_sinkhole`,
`event4_sinkhole_http`, `event4_sinkhole_dns`) carry most of a day's events, and the honeypot reports far fewer.
`outdated_dnssec_key` is excluded by default, because it reports a misconfiguration rather than an attack. `GET /api/sources` lists the live registry with today's row counts, and `tools/discover.py` repeats the full survey of all collections.

## Infection knowledge base

`data/infections.json` holds one entry per infection name, as Shadowserver writes it, in lower case. Each entry has:
- `title` and `type`
- `description`: what it is
- `action`: the recommended response
- `confidence`: `high`, `medium` or `low`
- `status`: `reviewed` or `needs-review`
- `aliases`
- `updated`: the date of the last change
- `references`: the evidence (web links); `malpedia`: the Malpedia family id when Malpedia has it (its page is then the
  first reference)
- `curated_by`: who wrote it. Entries shipped with Looking Glass are signed `Looking Glass`; entries written on a site
  record the account's username, shown as the person's registered full name (`people.py`)

Every shipped entry carries evidence: a Malpedia family, or references to the Shadowserver report documentation and
vendor or CERT research. `data/issues.json` does the same for the services issues that are not CVEs.

**Shipped and site definitions never conflict.** `data/infections.json` and `data/issues.json` belong to Looking Glass
and are replaced by updates (`git pull`). What researchers write on a site goes to `data/definitions.json`, which is
not in the repository (`.gitignore` excludes `data/*` except the shipped files) and takes precedence over the shipped
entry of the same name. A site's own definitions and notes are therefore never overwritten, and never block an update.

The detail and analysis views show the description and recommended action. Entries with low confidence or `needs-review` status are marked **Unverified**, and infections with no entry say so. The server reloads the file whenever it changes, and open pages fetch it again every 10 minutes, so you never need a restart.

**Keeping it complete:**

```bash
.venv/bin/python manage/infections_missing.py 7      # check the last 7 days
```

This lists every infection seen in those days that has no entry, plus entries still marked `needs-review`, with counts, reports, tags, families and sample C2 domains. It also writes `data/infections_missing.json`, which includes empty stub entries. Research and write the new entries (description, recommended action, confidence), then merge them into `data/infections.json`. While the service is running, `GET /api/infections/missing` gives the same check for the current replay day.

The base covers the infections and categories that Shadowserver's event reports commonly use, including the honeypot, DDoS and access categories. Names with little public detail say so and carry `confidence: low` (for example `wd`, a family that looks up generated domains and is not publicly identified). Names seen only in the Sinkhole DNS report explain that the address is usually a DNS resolver, with the infected client behind it.

## Researchers: intel, notes and where a name was seen

The Definitions page (`/definitions`, permissions *definitions* / *networks*, admins too) is the researchers' page. Its
server side is in small modules called from `app.py`:

- **`intel.py`, Intel gathered.** From the days in memory it collects, per name and per report, the indicators the
  records carry: C2 domains, destination host names, TLS server names, DNS lookups, URLs, user agents, request patterns,
  brute-force usernames and passwords; for services issues the other CVEs on the same hosts, associated tags, products,
  certificate names and fingerprints (SHA-256, JARM, HASSH), server software and web page hashes. For each value and for
  each **combination** (the exact set on one record: tags and CVEs; for communications also C2 domain and user agent) it
  counts records, share, hosts and **repeating hosts** (hosts with more than one record). It also raises **leads**: the
  same indicator under two names, in two reports for one name, or an infection's domain that is a certificate name on a
  services host; values common to everything are filtered out. No source address, host name or constituent address is
  ever returned; addresses inside free text are masked. `GET /api/intel?section=infections|issues&name=…`,
  `GET /api/intel/leads`, `GET /api/intel/summary` (per name and report: how many kinds of indicator, for the
  *Seen in* cards). Cached for five minutes per set of days.
- **`notes.py`, researchers' notes.** New findings per name in `data/notes.json` (run-time data: never shipped, never
  overwritten by an update), each with author, role and date. The look-ups `mp_resolve`, `issue_resolve` and
  `issues_resolve` attach the notes to every explanation card, so the map, services, Executive and both PDF builders
  show them ("Notes shared by Researcher: *full name* (*date*)"). `GET /api/notes`, `POST /api/notes` (with
  optional `codes` and `finding: {title}`), `POST /api/notes/delete` (author or admin); audit events `note_added`,
  `note_removed`. A note's combination codes must be known to the code book; they are printed with the note.
- **`combos.py`, combination codes and the analysts' combination search.** `intel.combo_code` / `intel.cross_code` hash
  the section, name, report(s) and exact indicators into `LG-C-XXXXXXXX` / `LG-X-XXXXXXXX` (SHA-256, 8 hex digits; no
  address). `intel.record_items` is the one matching rule: Intel gathered counts with it and the search matches with it
  (`tests/check_combos.py` proves both agree for every name and report). Codes shown to a researcher go to
  `data/combo_codes.json` (the twenty thousand most recent kept); a code not there is looked for in memory. The search is a background thread per
  analyst (one at a time): over the days in memory together, or a date range (at most 31 days) read day by day from
  MongoDB with `app._combo_fetch` (only the name's reports, inside the constituency). For the devices found it also
  follows them into the name's other reports (cross-report patterns with their codes, sets of reports). The result is a
  ZIP (PDF from `combo_pdf.py`, drawn with `executive_pdf.Doc`'s parts: tiles, activity, findings, the region map and
  tree, bars, explanation cards for the name and every CVE in the combination, plus the devices table and note cards;
  `reports_pdf.build` only as a fallback; devices CSV, records CSV, both through `csvsafe`), kept in memory and in `data/combo_exports/` (0600, one hour) so a restart before the download loses
  nothing. Routes: `GET /api/combo-codes/<code>` (researchers, management, analysts, admins; no address),
  `POST /api/combo-codes/new` (researchers, admins: only the name's real indicators), `POST /api/combos/search`,
  `GET /api/combos/search/<id>`, `POST /api/combos/search/<id>/stop`, `GET /api/combos/search/<id>/download` (analysts,
  admins: `unmasked` + `export`, never in Demo mode, only the analyst who ran it), page `/combinations`. Audit events
  `combo_code`, `combo_export`.
- **`acodes.py`, analyst codes.** `LG-A-XXXXXXXX` (SHA-256 of platform, day and selection). Made from an analysis
  window's selection (`kind`/`value` on the map, the query arguments on the services platform; `app._slice_on` and
  `services_api.scope_events` apply them to any day). The exact record IDs of the selection are kept in
  `data/acodes/<code>.json` (0600), so masked roles (whose filters accept only aliases) see the same records; what
  the code stands for is in the code book (kind `a`, with the selection described without host addresses). Routes:
  `POST /api/analyst-codes` (analysts, admins; never in Demo mode) makes the code and a finding,
  `GET /api/analyst-codes` lists them for analysts, `GET /api/intel/acode/<code>` and page `/intel/<code>` show
  researchers, management and analysts the names, definitions, combinations and cross-report patterns of exactly
  those records. The Executive portal's `code` filter and the Combinations search accept analyst codes (the code's
  day only). Audit event `analyst_code`.
- **`findings.py`, findings.** A note tracked as a finding: number, title, the note's text and codes (a copy), status and
  history in `data/findings.json`. Statuses `new`, `management`, `researcher`, `analyst`, `advisory`, `closed`.
  `GET /api/findings?state=open|all`, `POST /api/findings/<id>/status {status, comment}` (CSRF, a recent sign-in),
  page `/findings` for researchers, management, analysts (`unmasked` + `export`) and admins; `/findings` and
  `/api/findings` are in the researcher and management roles' allowed paths. Audit events `finding_created`,
  `finding_status`.
- **`seen_index.py`, last seen.** `data/seen_names.json` remembers, for every name, the last date it was seen in each
  report (readable report names, no hosts). Every replay day is added as it passes; once per installation the last 14
  days are read from MongoDB in the background by one worker (`seen_names.json.done` marks it done). Kept 30 days.
- **`people.py`, names.** Definitions, notes and network corrections store the username and are shown with the
  registered full name, looked up when displayed (a corrected name appears everywhere at once); the audit log shows
  *Full Name (username)*.

## Network names (ASN registry)

`data/asns.json` maps every AS number seen in the data to its operating company. The map shows company names instead of numbers, for example "Example Telecom (AS64500)" in the detail view and "Example Telecom" in lists. ASNs of the same company are counted together: an operator's AS64500 and AS64501 appear as one network.

Each entry has:
- `name`: what is displayed
- `holder`: the registered holder from RIPEstat
- `type`: `isp`, `education`, `government`, `finance`, `hosting`, `ixp`, `private` or `unknown`
- `country` and `role`: whether the ASN appears as a source, a destination or both
- `reviewed`: `true` means the name was curated by hand
- `demo_alias`
- `events_last_check`

**Updating it:**

```bash
.venv/bin/python manage/asn_registry.py 7     # add ASNs seen in the last 7 days
```

New ASNs are looked up automatically in the public RIPEstat registry (`stat.ripe.net`) and added with `reviewed: false`. To change a display name, edit `name` in `data/asns.json` and set `"reviewed": true`. Entries are never overwritten, and the server reloads the file whenever it changes.

Each CSIRT builds its own registry: the file is not shipped, and `manage/asn_registry.py` creates it from your data. Until then the map shows the registered holder names.

## Demo mode (public presentations)

The **Demo** button in the top bar conceals sensitive details while the data keeps playing live:
- Company names and AS numbers become stable aliases by type: "Telco 1", "Institution 3", "Provider 2", "Exchange 1".
- IP addresses (IPv4 and IPv6) become an opaque label, `Host 3f9a2c41b07e` (`host_label.py`): an HMAC of the address under `REF_SECRET`, the same for one address on one server, with no part of the address in it.
- Hostnames and machine names are hidden.
- IP addresses inside URLs, cookies and other text fields get the same label.
- A report's own fields (map and services details) pass an allowlist (`masked_fields.py`): only technical details
  (protocol, software, versions, ciphers, flags, malware sample hashes) are shown, with host names, addresses,
  e-mails, dates and IDs masked inside them; names, MAC addresses, user names, locations, keys, banners and any field
  not on the list are hidden, and the details window says how many.
- Locations stay visible.
- Pins and "Copy JSON" are hidden.

**The masking happens on the server** (`privacy.py`, `?demo=1`), so concealed values are never sent to the browser. Drill-downs still work through opaque host references (`src_ref`). While a request is masked (Demo, or a role without *unmasked*), filters accept only what the masked view shows: host filters only the opaque references, network filters only the aliases (`AsnRegistry.strict`); a real address, company name or AS number matches nothing, so a viewer cannot test whether something is in the data.

Pinned events keep full details in the browser, so they are stored per account (`tm.pins:<username>`), never for masked accounts, and deleted on the sign-in page (log out, expired session). The aliases are fixed in `data/asns.json` (`demo_alias`), so "Telco 1" means the same network in every presentation.

For a public deployment where nobody may switch demo off, set `PUBLIC_DEMO=1` in `.env`. Every request is then masked, the button is locked on, and `/api/asns` is refused.

## Requirements and installation

See [INSTALLATION.md](INSTALLATION.md). In short: Ubuntu 24.04 or later, Desktop or Server (or Ubuntu on WSL 2), Python 3.12+ (tested on 3.14),
MongoDB filled by the Shadowserver pipeline (`../database`), a Mapbox token, and optionally a Malpedia token.
Python packages (from `requirements.txt`): Flask, Werkzeug, pymongo, python-dotenv, gunicorn and ReportLab. Each is
allowed up to, not including, its next major version (for example `flask>=3.0,<4`): bug and security fixes still
install, big changes do not. `tests/check_libraries.py` checks the installed versions against these limits and tries
the parts of each library the platform uses; it needs no data, and the installer runs it. To allow a new major
version, raise its limit, reinstall, and keep it only if `tests/run_all_checks.sh` and the security retest pass.

External services:
- **MongoDB** (database `shadowserver` by default). The app only reads; it never writes to the database.
- **Mapbox**: a public `pk.` token used for map tiles in the browser and the Geocoding v6 API on the server, which
  turns city/region/country into coordinates. Each place is looked up once and cached in `data/geocache.json`.
- Flag images come from `flagcdn.com`, and fonts come from Google Fonts.

For development, `.venv/bin/python app.py` runs it without the service on http://localhost:5000.

### Always on: a new day every day

**Each day is replayed in full, from 00:00 to 24:00, starting when its report has arrived** (`schedule.py`). Shadowserver delivers a day's reports during the following day, so a fixed "now − 24 h" clock would skip everything before the import. Instead:

1. When the replayed day reaches 24:00, the next day starts straight away if its report is already in MongoDB (no gap).
2. If it isn't, the platform shows **"Waiting for the reports of YYYY-MM-DD"**, holds at 00:00 (counters 0), and checks MongoDB every 15 seconds.
3. When reports appear, the stream lists which ones are in so far. Once **no new report has arrived for** `REPORT_SETTLE_SECONDS` (default 10 minutes; each new report restarts the wait), the day **replays from 00:00**. Open pages switch over by themselves within 15 seconds.
4. If the replay ever falls more than a day behind (for example after downtime), it skips to the newest available day.

**Reports arrive at different times.** Every 15 seconds the server counts each report's rows for the replayed day in MongoDB (indexed filename prefix, about 0.2 s). When a report is new or has grown, the day is reloaded at once, and open pages refresh their totals, filters, Intel, analysis and map within 15 seconds. They also announce it in a toast and at the top of the stream, for example *"New report data for 2026-11-06: Microsoft Sinkhole HTTP (78 events), received 07:31 UTC"*. The receive time is when the rows were inserted into MongoDB, taken from their ObjectId. `/api/clock` lists the day's reports with their receive times (`reports`) and recent arrivals (`report_changes`). `tools/report_arrivals.py [day]` shows when each report was inserted, and `tools/check_reports.py [day]` compares MongoDB with the running service.

**New report types (collections) are found automatically.** Every 15 seconds the server lists MongoDB's collections, which costs next to nothing. When one is created or dropped, or a collection that was still empty gets its first rows, the report list is rebuilt at once. A full rebuild also happens every `REGISTRY_REFRESH_SECONDS` (default 1 hour) as a safety net. A collection counts as a report when:
- its latest documents have `src_*`/`dst_*` fields (or the referer source fields), matching one of the known layouts (standard, legacy, referer, inbound);
- it is not excluded (`EXCLUDE_COLLECTIONS`);
- it is in `MONGO_COLLECTIONS`, when that is set (empty = all).

**Two tracks on the intro page.** Under the overview there are two cards, each with its own "Explore the platform" and "Explore in demo mode" buttons:
- **Reported network communications** (available): this platform. It shows how many reports are monitored and the day's event count.
- **Publicly accessible / vulnerable services** (available, opens `/services`): see the section below.

### Publicly accessible / vulnerable services (`/services`)

A second platform for the single-host reports: the collections with an `ip` but no source and destination (`scan_*`, `scan6_*`, `population_*`, `device_id*`, `compromised_*`, `blocklist`). It has no map. It shares the replay schedule with the map, so it shows the same day at the same replay time, and it has the same features.

**Discovery and compatibility check.** `services.py` `ServiceRegistry` finds these collections automatically, every 15 seconds, like the map's registry. Each one is checked against the fields the platform needs:
- **Required:** `extracted_date` (a date), `ip`, `geo`, and `filename` with an index.
- **Recommended:** port, city or region, network, severity, tag.

Compatible reports are loaded. Others are listed as "not processed yet", with what they lack.

**Common fields.** `tools/analyze_services.py` measured the fields across the 86 collections. These are in essentially all of them: ip, port, protocol, asn, geo, region, city, hostname, naics, sector, severity, tag, category, timestamp, extracted_date and filename. About a third add device details (`device_vendor`/`type`/`model`/`version`), product banners (`server`, `server_type`, `serverid_software`, `application`) or issue markers. Each record is normalised into the common fields plus:
- **service:** from the report, e.g. SSH, SSL/TLS, MikroTik service, with IPv6 reports marked;
- **family:** Exposed service, Service population, Identified device, Compromised or Blocklisted;
- **vendor, device type, product, version;**
- **issues:** CVE tags, POODLE, FREAK, expired certificate, exposed admin panel, device implant, compromise. A host with any issue counts as "with issues".

Every other field is kept and shown in the record details.

**Same look as the map platform.** `templates/services.html` uses the map platform's stylesheet (`app.css`) and markup: the top bar, the Filters drawer, the Intel column, the stream rows, the details dialog and the analysis dialog. `services.css` only adds the stage that replaces the map. The brand mark and **Overview** open the intro page (`/?intro=1`).

**What the page has**

| Area | What it does |
|---|---|
| Top bar | Records yesterday, Replayed so far, Exposed hosts, Reports, Hosts with issues, Critical. Every figure opens an analysis, with its list already open where that fits. |
| Filters | Only hosts with issues, report family, service report (searchable, with definitions on hover), severity, issue (searchable), region, city, network, port, vendor, device type. |
| Stage: Services constellation | One bubble per service, with area proportional to its records. A dot, coloured by severity, flies into the bubble as each record replays, and the bubble pulses. Click a bubble to analyse that service. |
| Stage: regions map | A heatmap of the chosen country's regions, coloured by records with the active filters. Regions flash as their records replay. Hovering shows what makes up a region (reports, issues, cities, networks, hosts with issues); clicking analyses it. Records whose region is unknown are counted separately. Boundaries: `static/data/adm1/<country>.json` (geoBoundaries ADM1, CC BY 4.0). |
| Intel | Activity yesterday (15-minute bars), a report-families donut, records by hour and family, severity mix, issues, services, networks, regions, cities, vendors, products, ports. Every line and bar is clickable. |
| Record stream | The same rows as the map platform: time, severity, service and family, host (address, place, network), device or product, protocol and port, issues and tags. Clicking one opens the record details: the report's definition, links to analyses for every value, and all report-specific fields. |

**In-depth analysis.** This has the same dialog and drill-downs as the map platform. Each figure tile has **Details ›**, which shows the list behind it with **Download CSV** (all rows):

| Figure | List behind it |
|---|---|
| Records / Exposed hosts | Hosts ranked for follow-up, with reasons such as "10 issues · critical · 5 reports" |
| Share of all records | By report family |
| Hosts with issues | Hosts with a concrete issue |
| Issues | Every issue, with records, hosts and services |
| Hosts with multiple issues | Hosts with more than one issue (the largest attack surface) |
| Reports | Every report, so you can look at one on its own or several together |
| Hosts in several reports | Cross-report hosts, the same idea as on the map platform |
| Networks | Networks of the hosts |
| Regions | Regions of the chosen country |

The dialog also shows key findings, a composition donut (families, or services), an issues donut, records by hour and family, activity by 15 minutes, severity mix, twelve clickable breakdowns and the hosts to follow up first. Every click narrows the analysis (for example SSH · Ashanti · CVE-2023-48795). Selection chips open a part on its own or widen it again, and **Filter the view** applies the selection to the page.

Speed, pause, Catch up, demo mode (IPs, host names, network names and identifying certificate fields hidden), Hide list (key **L**), dragging the stream edge to resize it, new-report alerts, and the TV and phone layouts all work as on the map.

**Official report names.** Every services report is shown under its official Shadowserver name without the word "Report", for example DNS Open Resolvers, Open mDNS, Accessible HTTP, Vulnerable ISAKMP, Accessible ISAKMP, Open HTTP Proxy and Accessible HTTP Proxy. IPv6 reports carry "(IPv6)", and `population_bgp` is "Open BGP Service (population)".

Each collection was matched to its report in two ways:
- in MongoDB, its file names and `category` field carry the collection name (for example `scan_dns` records are tagged `openresolver`);
- on Shadowserver's report page, the "Filename" line lists that same name.

`_verified` in `data/service_reports.json` records the exceptions:
- **BGP:** `population_bgp` is the population variant of `scan_bgp`.
- **MikroTik:** Shadowserver's page spells the filename `scan_miktrotik_service`.
- **NTRIP and Radmin:** their pages list no filename.

**Hosts in several reports / with multiple issues show all their reports.** Both host figures compare the selected hosts against all their reports of the day. The view then shows those hosts with every one of their records: bubbles, regions map, stream, figures, analysis and CSV.
- **Hosts in several reports** (`cross`): the selection's hosts that appear in more than one report. For example, DNS Open Resolvers + several reports = the resolvers that also appear in other reports, with all their records; Block List + several reports = the blocklisted hosts that also appear elsewhere (Device Identification, Accessible SSL, Accessible HTTP…), with all their records.
- **Hosts with multiple issues** (`multi`): the selection's hosts with more than one issue across all their reports. For example, Block List: 3 blocklisted hosts with an expired certificate and an exposed admin panel found in their Accessible SSL and Device Identification records (before, issues were counted only inside the selection, so Block List showed 0).
- **What chooses the hosts, and what narrows the view.** The filters set when the figure is switched on (checkbox, card, **Filter the view**) choose the hosts. They travel in the value: `cross=seed:family=Blocklisted`. Any filter added afterwards narrows the hosts' widened records. So Blocklisted → several reports → the Accessible HTTP bubble shows the 16 Accessible HTTP records of the 10 blocklisted hosts that have them: exactly what the bubble counted. Before, every filter chose the hosts, and no record is both Blocklisted and Accessible HTTP, so it showed 0.
- Old links with `cross=1` / `multi=1` keep their meaning: every filter in the link chooses the hosts.
- Host filters (region, city, network, host) always apply. The constellation outlines the starting report, and the hint under the view switch says what is shown, e.g. "hosts of Blocklisted that are in several reports · showing their Accessible HTTP records".
- In the analysis, the tables of these two figures list each host's issues and reports of the whole day, as they were compared. The figure, the table and the filtered view always give the same hosts.

**Record stream.** With or without filters, the record stream opens with the latest (matching) records of the day up to the replay time, however long ago, then adds new ones as they replay. Shadowserver's service reports arrive in bursts, so the last few minutes are often empty; the stream no longer shows "Waiting for records" in those gaps (or for Block List, whose records all arrive between 01:00 and 03:00). "Waiting for records" now only appears before the day's first record has replayed.

The figures, stream, Intel, regions map and analysis all follow this one rule. `tests/check_services_consistency.py` checks 28 combinations in normal and demo mode: stats, analysis, regions, replayed and the whole-day stream must all agree, and the host lists must match.

**Cards as filters.** Two analysis cards can be part of **Filter the view**: Hosts with multiple issues and Hosts in several reports, as well as Hosts with issues. With one of them open, the button reads "Filter the view · Hosts in several reports", and the page shows exactly the hosts of the card's table, with all their reports. They are also checkboxes under Filters (`multi`, `cross`, `vulnerable=1`; usable in the address too).

**Intro page.**
- **Badges:** each track shows **Available**. With no data for the day it shows **Currently unavailable** and "waiting for reports from Shadowserver".
- **Services report list:** a card lists all services reports with their official names and record counts. Hovering shows the definition; clicking opens the services platform filtered to that report (`/services?service=…`).
- **Glossary tab:** has a "Publicly accessible / vulnerable services" group with its terms and figures, plus the definitions of all communication and services reports.

**Report definitions.** `data/service_reports.json` defines every report in plain language. It is written from Shadowserver's report pages (https://www.shadowserver.org/what-we-do/network-reporting/) and holds each report's official name, Shadowserver's severity rating, what it means, why it matters and a link to its page. It covers all 86 single-host reports and the 12 communication reports. It is used by:
- the services glossary (button "Glossary");
- the tooltips on services, bubbles, filters and Intel;
- the record details;
- the map platform's glossary tab, which has new groups for both kinds of report;
- the map platform's overview report tooltips.

**API.** All endpoints are under `/api/svc/`: `clock`, `events`, `detail`, `replayed`, `stats`, `facets`, `insight`, `hosts.csv`, `glossary`, `diagnostics` and `summary`. `tests/verify_services.py [day]` checks records per report, the total and the hosts against MongoDB, and that demo mode masks every IP.

**Compatibility check.** Every discovered collection is checked against the fields the platform uses (`diagnose` in `sources.py`).

Required (the report is loaded onto the map only if all of these are present):

| Need | Field |
|---|---|
| Event time | `extracted_date`, which must be a date |
| Source host | `src_ip`, `ip` or `http_referer_ip`, depending on the format |
| Source country | `src_geo`, `geo` or `http_referer_geo` |
| Day loading | `filename` with an index, or `FALLBACK_SCAN=1` |

Recommended (the report still loads; the tooltip in the overview list says what it lacks): destination IP or country, source city/region, destination country, source network, severity, infection/category. A report without a destination shows each event as a point at the source with no arc; Sinkhole DNS is like that.

What happens in each case:
- **Source and destination:** loaded, with arcs.
- **Source only:** loaded, with points at the source (like Sinkhole DNS).
- **Destination only** (no `src_*` fields): loaded, with points at the destination. This is the "target" format, and it requires `dst_ip` and `dst_geo` instead of the source fields. The stream shows the source as "not reported", and such events are left out of source-host figures (hosts to follow up, rhythm, cross-report hosts). Destination analyses (target country, city, IP, network) include them.
- **Older format**, where `ip`/`geo` is the local host and `dst_*` the far end: loaded.

Reports that match discovery but fail a required check are not loaded. They are listed on the overview under "N more report types discovered, not supported yet", with what they lack and "Support will be added in a future update". A new report type is announced either way: "compatibility check passed … loaded onto the map", or "discovered but cannot be shown yet: missing …". `/api/diagnostics` gives the full check for every report, and `tools/diagnose_reports.py` runs it read-only from the command line.

Single-host scan, population, device and blocklist reports have no source and destination fields at all, so they are not candidates. Rows are loaded by filename prefix (`YYYY-MM-DD-…`), so a new collection needs a `filename` index, or `FALLBACK_SCAN=1`. When the report list changes, open pages update the overview ("N reports monitored"), filters and figures, and announce the new type. `tests/test_new_collections.py` checks this using a throwaway database.

So the replay time can be more than 24 hours behind the current time; the top bar shows both (**Replay time (UTC)** from `extracted_date`, and **Current time (UTC)**), and every stream row shows its own replay time. The schedule is saved in `data/schedule.json`, so a service restart continues where it was. A restart also keeps a running settle time, even before the day has been reloaded. Only the server runs the schedule; scripts that import `app.py` do not touch it. `tests/test_schedule.py` simulates several days (late imports, reports trickling in, restarts, outages). At faster speeds (demos) the day loops instead of running past 24:00.

Run it as a service with gunicorn. Use **one worker**, since the day cache is in memory, and threads for concurrent viewers:

```bash
.venv/bin/gunicorn --workers 1 --threads 8 --bind 127.0.0.1:5000 app:app
```

A hardened systemd unit is included: `deploy/install.sh` writes `deploy/looking-glass.service` from
`deploy/looking-glass.service.template` for your user and folder ([INSTALLATION.md](INSTALLATION.md)).

```bash
sudo cp deploy/looking-glass.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now looking-glass
journalctl -u looking-glass -f
```

## Configuration (`.env`)

Every setting, with examples: [CONFIGURATION.md](CONFIGURATION.md). The main ones:

| Variable | Default | Meaning |
|---|---|---|
| `MONGO_HOST`, `MONGO_PORT` | `localhost`, `27017` | Mongo server |
| `MONGO_USER`, `MONGO_PASSWORD`, `MONGO_AUTH_SOURCE` | — , — , `admin` | credentials |
| `MONGO_DB` | `shadowserver` | source database |
| `MONGO_COLLECTIONS` | empty | empty means auto-discover every src/dst collection; otherwise a comma-separated list to use |
| `EXCLUDE_COLLECTIONS` | `outdated_dnssec_key` | comma-separated collections to skip |
| `MAPBOX_TOKEN` | — | Mapbox public token |
| `REPLAY_OFFSET_HOURS` | `24` | which day counts as "yesterday", and the schedule used on a fresh start when yesterday's report is already in |
| `REPORT_SETTLE_SECONDS` | `600` | after a day's report starts arriving, wait this long before replaying that day from 00:00 |
| `MAX_EVENTS_PER_POLL` | `400` | cap per poll window; any extra events are randomly sampled |
| `DAY_RELOAD_SECONDS` | `600` | how often the in-memory day is reloaded from Mongo |
| `FALLBACK_SCAN` | off | set to `1` to query by `extracted_date` when no `YYYY-MM-DD-*` file exists; this does a full collection scan unless that field is indexed |

## How it works

- **Data loading.** A collection can hold millions of documents with no index on `extracted_date`, so time-range queries would scan the whole collection. Instead, the app loads the replay day into memory using the existing `filename` index: report files are named `YYYY-MM-DD-…csv`. A typical national day loads in a few seconds. If no file names match, the day stays empty and is retried every minute. Set `FALLBACK_SCAN=1` to query `extracted_date` instead.
- **Replay clock.** The browser keeps a clock running `REPLAY_OFFSET_HOURS` behind real time. Every 4 s it requests the next window from `/api/events` and launches each arc at the event's own time. The speed selector (1×, 5×, 15×, 60×) speeds this up, and choosing 1× snaps back to live. Each attack stays "active" on the map for 75 s of replay time. Its packet keeps re-firing along the arc during that time, so several attacks animate at once. On load, the stream is backfilled with the last 15 replay-minutes.
- **Coordinates.** Sources and destinations are geocoded by city and region, falling back to the country centroid. Events with only one known location show a pulse there instead of an arc.

### API

| Endpoint | Returns |
|---|---|
| `GET /api/clock` | server time, replay time, offset, number of integrated reports |
| `GET /api/overview` | whole-day summary for the intro page: totals, all monitored reports with row counts, attack-type mix, 15-minute timeline (contains no network names or IPs) |
| `GET /api/asns` | the ASN registry (refused in demo mode) |
| any endpoint `&demo=1` | the same response with network names, ASNs, IPs and hostnames concealed |
| `GET /api/sources?at=` | the collections being integrated (layout, attack type, label) with row counts for the replay day |
| `GET /api/events?from=&to=&infection=&severity=&tag=&src_city=&dst_geo=&dst_port=&protocol=` | events in the window, with every field plus `src_coords` and `dst_coords` |
| `GET /api/facets?at=` | filter values with counts for the replay day, plus the severity of each infection |
| `GET /api/stats?at=&…filters` | totals, unique hosts, families and C2 IPs, top infections / categories, affected cities, C2 / sinkhole domains and targets, and 15-minute timeline buckets |
| `GET /api/insight?kind=&value=&at=` | analytics for one entity (`kind` = `source`, `attack_class`, `infection`, `src_city`, `http_host`, `dst_geo`, `src_ip`, `src_asn` or `dst_ip`): connections, share, hosts, C2 domains, median beacon interval and how many hosts beacon regularly, multi-infected hosts, hourly profile, breakdowns, most active hosts and plain-language findings |
| `GET /api/insight/drill?kind=&value=&metric=&at=[&all=1]` | the list behind one figure of the analysis view (`metric` = `events`, `share`, `hosts`, `c2`, `dst_ips`, `interval`, `multi`, `reports`, `cross`). Host lists are ranked for follow-up (several kinds of activity, several reports, several infections, regular beaconing, critical). Returns the first 300 rows, or all with `all=1` (used by Download CSV). Demo mode masks IPs and networks |
| `GET /api/related?src_ip=&at=` | what one infected host did today: connection count, first and last seen, infections, contacted hosts |
| `GET /healthz` | liveness |

## Intro page

The welcome page opens on the first visit in each browser session. Refreshes go straight to the map. Click **Overview** in the top bar (or the logo) to return to it at any time. It shows:
- the day being replayed;
- live totals: events, reports with data out of all monitored reports, source hosts, infections / categories, affected cities and hosts seen in several reports;
- the full-day activity strip and the attack-type mix;
- **every monitored report**, with those that have data that day listed first.

It has two buttons: **Explore the platform** and **Explore in demo mode**.

All figures come from `GET /api/overview`, and the report list comes from the live collection registry. New collections with src/dst fields are discovered within `REGISTRY_REFRESH_SECONDS` (default 3600), so the count grows by itself beyond 30. The page refreshes every minute while it is open. The logo is animated: the arc draws in and then flows, and the impact ring pulses. Animations are off for users who prefer reduced motion.

### Animated logo: loading and page transitions (`static/js/loader.js`)

Shared by the map, the services platform and Settings:
- **While data loads**, the logo appears next to the loading message: the analysis and detail panels ("Analysing…", "Loading the details…"), the live stream while it waits for records, and Settings while it loads. Records scroll through the lens as if being searched, the arc draws, and the hit pulses. Any element with the class `i-loading`, `st-loading` or `lg-loading` gets it automatically.
- **Between pages** (intro → services, services → overview, any page → Settings and back), the logo draws itself (rim, handle, then the arc) with "Opening …". The next page keeps it on screen until its first figures arrive (at least 0.7 s, at most 1.6 s), then it zooms and fades into the platform. **Explore the platform** on the intro shows the same logo over the intro before the map appears.
- In **Lite** display mode and for users who prefer reduced motion, the logo is still and pages switch without delay.

## Settings (both platforms): country and constituency

`/settings` is opened from the gear at the top left of the intro page, from the **Settings** button in both platforms' top bars, and from the constituency label. What it sets applies to both platforms at once. Which parts are shown depends on where you opened it:

| Opened from | Address | Shows |
|---|---|---|
| Network communications | `/settings?for=comms` | Constituency only (the map does not use a country) |
| Publicly accessible / vulnerable services | `/settings?for=services` | Country and constituency |
| Intro page | `/settings` | Both |

**Applying.** A bar fixed at the bottom of the page always shows the state: **No changes** (with what is in force), **Unsaved changes** (with what Apply would set, plus Undo changes), or **Settings applied at HH:MM UTC**. **Apply settings** saves the settings, and the server immediately reloads both platforms' data (about 4 seconds). A green banner then confirms what is in force. Open pages check for new settings every 10 seconds and refresh completely: figures, stream, map, analysis and, on the services platform, the country, its regions map and the "<country> regions" button. They show "Settings updated: …". Leaving the page with unapplied changes asks for confirmation.

**Wrong country.** If none of the regions in the reports are on the chosen country's map, the services platform still shows that country's map, with a note: "None of the N regions in these reports are on <country>'s map. Kindly select the right country in Settings to populate the regions", plus an **Open Settings** button. The settings page shows the same warning before applying.

- **Country.** Choose from all 54 African countries. The services platform draws that country's first-level regions on its regions map, and uses the country's name in labels; the view button reads "<country> regions". Boundaries come from geoBoundaries (gbOpen ADM1, simplified, CC BY 4.0) and live in `static/data/adm1/<ISO2>.json`, about 4 MB for all 54; `manage/fetch_africa_boundaries.py` downloads them again. The page previews the country's regions and checks yesterday's region names from the reports against the map, and says how many of them it could draw. If none match (a country chosen that is not the one the reports are for), it warns that the reports do not seem to be for that country.
- **Region names and labels (all 54 countries).** The reports' region names come from IP geolocation, which follows ISO 3166-2. Those names are often in the local language ("Alger", "Al Qāhirah") or use newer subdivisions than the boundary files (Algeria's 58 provinces against 48 on the map; Kavango East / West in Namibia). `manage/region_aliases.py` adds to every region of every map:
  - its ISO 3166-2 codes;
  - aliases: the ISO name, sub-units whose ISO parent is that region (e.g. Burkina Faso's provinces), newer subdivisions mapped to the region they were carved from (Touggourt → Ouargla, In Salah → Tamanrasset), and English / local alternatives (Algiers ↔ Alger, Cairo ↔ Al Qāhirah, Brong-Ahafo → Bono);
  - repaired display names (Seychelles' truncated and garbled names, typos such as "Northen Red Sea");
  - a label point well inside the region.

  The script uses the ISO 3166-2 list of Ubuntu's `iso-codes` package. Every ISO first-level subdivision of the 54 countries now lands on a map region, apart from where ISO's top level is above the map's units: the island groups of Cabo Verde and Equatorial Guinea (their municipalities and provinces match), and the uninhabited Cargados Carajos Shoals of Mauritius. Matching ignores accents, letter case and words such as "Region" or "Governorate". `static/js/regions.js` does it in the browser for the services regions map and the Settings preview.

  Both maps label every region where the name fits without overlapping (regions with records first, then the largest), and hovering names any region with its ISO code and records. Several report names on one region (a newer province inside the old one) are added up, and the tooltip lists them. Report regions that are on no region of the map are listed under the map. `manage/fetch_africa_boundaries.py` runs the alias step after downloading.
- **Constituency.** Leave it on "Whole country", or choose the networks your CSIRT is responsible for. Networks are grouped by company, covering all their AS numbers, and can be searched and filtered by type. You can also add address ranges, such as a government network without its own AS number. Both platforms then keep only records whose host is in the constituency: on the map platform the source or destination side, on the services platform the host. Every figure, list, map, analysis and export follows. Saving reloads both platforms' data. Open pages refresh by themselves and show **Constituency: N networks** in their top bars; the intro page shows the same. `tests/verify_constituency.py` checks both platforms against MongoDB with the constituency that is set.
- **Deployment.** The same settings can be given in `.env` as `COUNTRY`, `CONSTITUENT_ASNS` and `CONSTITUENT_CIDRS`. The page shows the lines for your current choice. Settings saved on the page are stored in `data/settings.json` and take precedence.
- **Who can change them.** Accounts with the Settings permission (administrators), from a recent sign-in. Accounts without the permission do not see Settings. (The old `SETTINGS_TOKEN` header was removed: settings have one rule.)
- **The replay schedule is unaffected.** It still waits for the reports themselves, so a narrow constituency with no records on a day is not mistaken for a missing report.

## Glossary and hover explanations

Each platform has a **Glossary** button in the top bar that covers **only that platform**:
- **Reported network communications** (the map): the general terms plus its reports.
- **Publicly accessible / vulnerable services**: its figures and terms, report families and its reports.

The intro page's **Glossary** tab covers **both platforms**. Every report is listed under its official Shadowserver name, with its Shadowserver rating, the number of records on the replayed day, and a **Shadowserver report page ↗** link to its page under https://www.shadowserver.org/what-we-do/network-reporting/ (links checked against that page). The links come from `data/service_reports.json`.

The general terms are plain-language definitions written for everyone, management included, grouped into The basics,
Who and where, Threats, Numbers and measures, Using the platform, Accounts, roles and permissions, Publicly accessible /
vulnerable services, and Security, audit and the pipeline, with a search box. Examples: what an event is, what
"median" and "median repeat interval" mean, sinkhole, honeypot, C2, demo mode, a finding, an advisory and TLP, the
audit log's hash chain, control checks, NIST SP 800-53, CIS Controls, the proof package, the sender check and
confirmation on the server. `docs/GLOSSARY.md` is the same list for the documentation site; it is generated from
`static/js/glossary.js` by `python3 tools/glossary_md.py`, so edit the JavaScript file and regenerate it rather than
editing the Markdown (only its introduction and Related tools section are written by hand).

The same definitions appear **on hover** across the platform. Labels with a dotted underline explain themselves: top-bar figures, the activity level, the replay clock, playback speed, filter headings, Intel chart titles, stream columns, and every number and chart title in the analysis view.

All text lives in `static/js/glossary.js`. Edit a definition there and it changes in the Glossary tab and in the tooltips (and, once regenerated, in `docs/GLOSSARY.md`). To explain a new label, add a term to that file, then map the label's text to the term's key in `LABEL_TERMS` in `static/js/app.js`.

## Devices and performance (smart TVs, older computers)

The look adapts to the device (phone, tablet, laptop, large screen). The top bar never squeezes its figures into each other: on wide screens (1440 px and up) they share one row and the least important ones (cross-report hosts, reports, source hosts) are hidden whole when they do not fit; from 701 to 1439 px they get their own row under the name and clocks; on phones the bar has three rows (name, replay time and buttons, figures) and the speed menu is hidden.

**Smart TVs and other short screens.** TV browsers report a small screen size (often 960 × 540 or 1280 × 720), which used to leave the map about a fifth of the screen. On screens up to 820 px tall all six figures sit on a slim second row of the top bar (label and number side by side), and the event stream takes about a third of the height with compact rows (address and place; the network is in the details) and no column header. The stream also has **Hide list / Show list** (or press **L**): hidden, only its title bar stays and the map gets the screen. TVs start with the list hidden; the choice is remembered per device. The list can be focused with Tab or a TV remote: the arrow keys move between rows (scrolling the list) and Enter opens one. Map share at 960 × 540: 44 % with the list (3 rows visible), 72 % without; at 1280 × 720: 49 % (5 rows) and 79 %. Drawing cost is controlled by **Filters > Display**:

| Mode | What it does |
|---|---|
| **Auto** (default) | Full on capable devices. Lite on smart-TV browsers (Samsung Tizen, LG webOS, Android/Google TV, Fire TV, Chromecast and others), on very low-power devices (2 cores or 2 GB memory or less), and when the map keeps drawing below about 22 frames per second (checked after the first 10 seconds; remembered for that device). |
| **Full** | Every effect: 3D tilt, glowing arcs with trails, impact rings, camera drift, see-through blurred panels, sharp rendering on high-resolution screens. |
| **Lite** | Flat map, no glow, trails, fog or camera drift, solid panels (blurring over a moving map is the heaviest effect on weak graphics chips), no UI animations, at most 40 arcs and 4 popups at once, half the redraw rate, 120 stream rows, and 1 pixel per CSS pixel (a 4K TV otherwise draws four times the pixels). |

The data, counts and analysis are identical in every mode. A screen can also be set from the address: `http://host:5000/?perf=lite` (or `full`, `auto`); the choice is remembered on that device.

**Browser requirement:** the map needs WebGL 2 and a browser from about 2021 or later (current Chrome, Edge, Firefox, Safari; TVs roughly from 2021–2022 on). Older TV browsers get a clear message instead of a blank screen. For those TVs, use a computer or streaming stick with an up-to-date browser on the TV's HDMI input, or share a computer's screen to the TV.

## Malpedia lookups

With `MALPEDIA_TOKEN` set in `.env`, every infection description (in the event details and the analysis view) has a **Look up on Malpedia** button, and so does the report's tag when it names something else. Report fields holding a malware family or a sample hash (md5, sha1, sha256) get one too. The result shows the Malpedia family (linked), how it was matched (for example `modpack` matches win.misfox by its alternative name ModPack), the description, other names, attribution, YARA rule counts and references, with other possible matches to choose from.

- The token stays on the server (`/api/malpedia?field=&value=`) and never reaches a browser; `.env` is readable by its owner only.
- Answers are cached for a week in `data/malpedia_cache.json`.
- Shadowserver names are matched to Malpedia ids by trying the full name, then without platform prefixes (`android.`), helper words (`likely-rat-`, `avalanche-`, `-p2p`, `-beacon`, `-download`, `-stealer`, …), version digits (`badbox2` → `badbox`) and separators (`pseudomanuscrypt` = `win.pseudo_manuscrypt`).
- When no malware family matches, the name is tried as a **threat actor** (`find/actor/`, `get/actor/`; exact name or alias only, e.g. `tick` = Tick / BRONZE BUTLER): the card shows the group, its aliases, suspected origin, targets and the malware it uses. Definitions can point to an actor with `actor:<id>`.
- PDF reports: `GET /api/insight/report.pdf` and `GET /api/svc/report.pdf` take the same arguments as the drill-down (`kind`, `value` / filters, `metric`, `at`) plus `all=1` and an optional `label`; permission `export`. They run the analysis and drill-down views server-side and render with `reports_pdf.py` (reportlab; DejaVu fonts from `fonts-dejavu-core` when present, built-in fonts otherwise). Up to 60 infection names are explained per report (Malpedia answers are cached).
- Without `MALPEDIA_TOKEN`, `/api/malpedia/batch` and `/api/malpedia` (fields infection / tag) answer from the definitions and the knowledge base (`offline: true`); hash and family look-ups still need the token.
- Issues (services): `cves.py`. CVEs are explained in batches (measured 2026-11-08: NVD without a key answers 5 requests per 30 s as documented; the official CVE.org records, cvelistV5 on GitHub, answered 12 in 6.7 s; EPSS 12 in one 2-s request):
  CISA KEV one download a day; EPSS one request per 100 CVEs; CVE.org records four at a time (description, CNA or CISA-ADP CVSS, CWE, references; a cold batch of 24 CVEs takes about 2.5 s);
  NVD's own analysis only from the background thread (every 10 minutes, at NVD's pace, one worker process; `NVD_API_KEY` makes it 10 times faster). Cache `data/cve_cache.json` (NVD / CVE.org / EPSS 7 days, KEV 1 day), merged between worker processes.
  Non-CVE issues come from `data/issues.json` (shipped) and the `issues` of `data/definitions.json`, never looked up. `GET /api/issues/batch?values=` (permission `malpedia`).
- Management portal: `management.py` (`/management`, `GET /api/mgmt/comms|services` with filters and `day`, `GET /api/mgmt/explain?kind=infection|issue&name=`, `GET /api/mgmt/report?platform=` executive PDF). Answers carry aggregates only (counts, shares, trends, facets); `tests/check_management.py` asserts that no address of the loaded day appears in any answer and that other roles get 403. Permission `management` is exclusive (`auth.Roles` strips it from every role except `management` and `admin`; the `management` role is always exactly `["management"]`); management users are confined to `MANAGEMENT_PATHS`.
- Look-up jobs: `POST /api/lookups` {kind: issues | malpedia, values} (permission `malpedia`, CSRF; at most 400 names, two running jobs per user) starts a background job; `GET /api/lookups/<id>?since=n` returns progress, the new log lines and, when done, the results. The page shows them in a progress window (`static/js/pdf.js`, `LGLookup.run`). Malpedia jobs wait and continue when Malpedia's 30-a-minute limit is reached.
- Reports: `GET /api/insight/report` and `/api/svc/report` return a ZIP (PDF + complete list as CSV, formula-safe); `format=pdf` returns the PDF alone (then the list is printed).
- Network names: `GET /api/networks`, `POST /api/networks/entry`, `POST /api/networks/types` (permission `networks` or settings; CSRF; fresh sign-in). Types: `netypes.py` (built-in sectors, PeeringDB categories) plus `data/network_types.json`; demo aliases use each type's word. The built-in researcher role has `definitions` and `networks` (added once to existing installs, marker `data/.roles_networks_added`).
- Administrator / researcher definitions (`data/infections.json`, written from Settings or `/definitions` via `POST /api/kb/entry`; permission `definitions`, or `settings`; the built-in `researcher` role has only `definitions` and is limited to `/definitions` and `/api/kb/*`): an optional `malpedia` family id is looked up directly instead of searching; otherwise `references` + `description` give a *Looking Glass definition* card. `GET /api/kb/unresolved` lists unmatched names, names not checked yet and defined names; `GET /api/kb/malpedia-search?q=` finds family ids; `POST /api/kb/check` checks new names now. The check state per name is in `data/malpedia_names.json` (run-time, not shipped); a background thread checks names new reports bring in every 30 minutes at most 20 per minute, one worker at a time (`data/.malpedia_check.lock`).
- `tools/malpedia_check.py` looks up every infection of the replay day and lists what matched (typically most of them; the rest are Shadowserver activity names such as `ssh-brute-force` or proxy networks that Malpedia does not list).

## The map: all connections plus the live replay

The map has two layers:
- **All of the day's connections** (always drawn, from `/api/geo`): every source place, destination and source → destination connection of the whole replayed day with the active filters, sized by event count and coloured by the main attack type. Filtering narrows it to exactly the matching places, and if some are off screen the map zooms out to show them. It can be switched off under **Filters > Display**.
- **The live replay** on top: bright animated arcs for the events playing at the current replay time (no popups).

**Everything drawn on the map explains itself on hover and can be clicked**, like the Intel lists ("Click to analyse"):
- a connection line opens a **Connection** analysis (for example Accra → The Hague): events, hosts, findings, charts and the click-through lists;
- a source place opens its **Affected city** analysis; a destination opens its **Destination place** analysis;
- a live arc or dot shows the event (infection, host, route, time) and opens its full details.

Events without a destination location (for example Sinkhole DNS, which records no destination) appear only as their source place.

## UI

Front-end libraries: Mapbox GL JS 3.8.0 (satellite style) and deck.gl 9.1.14 (3D arcs), both loaded from CDNs.

- **HUD (top bar):** events yesterday (whole-day total), replayed so far (exact count of the day's records up to the replay position, from `/api/replayed`; it stops while paused), source hosts, reports, cross-report hosts, critical count, an activity level (last 5 minutes vs the replayed day's average), "Replaying events of" with the replayed date (yesterday) and, separately, the current time (UTC). The analysis view and its findings refer to the replayed day as "Yesterday" with its date.
- **Map:** raised 3D arcs colored by infection, with packets that re-fire along each arc, impact rings and source pulses. Up to 10 popups appear at once, each showing the infection, IP and target. Pinned attacks stay drawn as dashed purple arcs. The camera slowly sways; turn this off with the ⟳ button.
- **Event stream (bottom):** a scrollable table with severity, infection / category with its report, source host (IP:port, city, ASN), destination (IP:port, city, ASN), protocol/port, and C2 domain plus request. Rows still animating on the map show a live dot.
  - If you scroll down, new rows wait behind a "↑ N new" button, so the list doesn't jump while you read.
  - **Pause** freezes the whole replay: the replay clock, the arcs and popups on the map, and the stream. **Resume** continues from the same moment, so nothing is skipped. The replay then runs behind by the paused time, and a **Catch up** button jumps it forward to the normal replay time. Choosing a speed also catches up.
  - When the browser tab is hidden or minimised, the replay **pauses itself** (browsers stop animations in background tabs) and resumes from the same moment when you return, so the stream has no gaps; use **Catch up** to jump ahead. Any event that still arrives late is listed in the stream without its map animation, never dropped.
  - The map's zoom and compass buttons pause the slow cinema rotation while they animate, so they always work.
  - The 📌 button pins a row. Pinned rows sit above the live rows and are kept in the browser across reloads.
  - Clicking a row, arc or popup opens the **communication detail**: the raw HTTP request, infected host, destination, threat, TLS/device, "this host today" and provenance (report file, line hash). It also has Pin, Show on map and Copy JSON buttons.
  - Drag the top edge of the panel to resize it.
- **Filters (left):** attack type, source report, severity, infection / category (searchable, with severity dot and count), affected city, target country, tag, target port and protocol.
- **Intel charts (all with hover tooltips):**
  - **Attack types** donut: share per type, with a short explanation on hover.
  - **Events by hour and type**: stacked bars; hovering an hour shows its breakdown.
  - **Severity mix** bar: click a segment to filter by that severity.
  - **Source networks** and **destination networks**: company names, ASNs on hover.
- **Everything in an analysis is clickable for a further analysis:** every breakdown (reports, attack types, infections, cities, source and destination networks, C2 domains, destination IPs, target countries, target ports, user agents, request paths, severity, tags), the donuts, the severity bar and legend, the figures, the drill-down rows and the host table. The **hourly and 15-minute charts** are clickable too: a bar opens a **Time window** analysis (for example "18:00 to 19:00 UTC · android.badbox2") within the same selection.
- **Top-bar figures open the whole-day analysis** (with any active filters) at the matching list: Events yesterday → all events by infection and report; Replayed so far → the time window from 00:00 to the exact replay position (same count as the top bar); Source hosts → hosts ranked for follow-up; Reports → the reports; Cross-report hosts → hosts in several reports; Critical → critical events with their hosts.
- **Tooltips on touch screens** close by themselves after a few seconds, and any new tap, scroll or opened panel closes them at once (there is no mouse to move away).
- **Deep dive inside an analysis:** every click inside an analysis narrows it instead of jumping away: a breakdown entry, a donut slice, the severity bar, a chart bar, a row of a Details list or of the host table. For example an infection (10,000 events) → one network (7,500) → port 80 (6,000) → one user agent (500) → 00:00 to 01:00 (15). The parts of the selection are shown as chips under the title: click a part to open it on its own (for example a host with all of its reports), or × to remove it and widen again.
- **Filter map works for every analysis:** it sets the map, the stream and Intel to exactly that analysis' selection, every part of it, including networks, destination IPs, destination cities, user agents and request paths (also in demo mode, through concealed references). A time window is the one part that is not applied, because the replay itself is the time axis.
- **One filter model everywhere:** the map, stream, Intel, `/api/events`, `/api/stats`, `/api/geo` and the analyses all accept the same fields (`source, attack_class, infection, severity, protocol, tag, src_city, src_geo, src_asn, src_ip, dst_geo, dst_city, dst_asn, dst_ip, dst_port, http_host, http_agent, request`), so an analysis and the filtered map always show the same numbers.
- **Deep dive with filters:** Intel always reflects the active filters, and so does everything you click in it. With several filters (for example Botnet C2 + one city), an Intel entry opens a **Filtered selection** analysis that combines them with what you clicked ("Attack type: Botnet C2 · Affected city: … · Source network: …", with the same number of events Intel shows), and an Intel hour or 15-minute bar opens that time window within all the filters. The figures, findings, charts and follow-up lists all work inside it, and its own bars go down to 15 minutes. In demo mode, concealed values (destination IPs, domains, user agents, paths) are sent as opaque references that only the server can resolve, so they stay hidden but still open their analysis.
- **Accurate whole-day figures:** the top bar, Intel, the analysis view and its lists always count **every record of every report for the replayed day** (00:00 to 24:00 UTC). The replay only drives the map and the event stream and never changes these numbers; they change only if late rows arrive in MongoDB (picked up by the 10-minute day reload). `tests/verify_totals.py [YYYY-MM-DD]` compares them with direct MongoDB counts per report.
- **Shared results, computed once per data change** (`respcache.py`): the statistics, filter lists, overview and whole-day map layer of the map platform and the services statistics are kept in memory under a key naming everything they depend on: the loaded day (its start, the moment it was loaded and its version, which changes whenever MongoDB has new or different rows), the filters, demo mode, the constituency and the network names. Every other viewer of the same selection gets the stored answer at once; when a report arrives the day is reloaded, the key changes and the next request recomputes from the fresh data. Simultaneous requests for the same key compute once (the others wait for that result). What depends on the replay moment (`as_of`, the current quarter and hour) is always worked out per request. On a large synthetic test day, a repeated statistics request went from several seconds to under a millisecond, with identical answers.
- **Executive lookups:** network sector, company and region / city names are worked out once per distinct value per request (the sector lookup used to read the network-type list once per record).
- **Executive 7-day baseline from compact past days:** each of the 7 days before the report day is loaded once and kept in a compact form (only the 13 fields the Executive figures read, repeated text stored once), so any filter or clicked combination gets its baseline from memory in about a second instead of 14 MongoDB day loads. A day is loaded again when its row counts in MongoDB change or the constituency changes. `MGMT_PAST_RECORDS` (default 3,000,000) caps the records kept; above it the oldest days are loaded as before. `tests/check_past_days.py` proves the compact days give exactly the same complete Executive answers as the full days (7 days × both platforms × 11 selections).
- **Intel (right):** 24-hour activity chart (hover any 15-minute bar for its count) (real counts per 15 minutes from `extracted_date` for the whole day; the white bar marks the replay position), attack types, source reports, top infections / categories, most affected cities, contacted C2 / sinkhole domains and target countries.
  - Click any item to open the **analysis** view. Every chart in it has hover tooltips, and clicking a segment or row drills further:
    - KPIs and key findings
    - beside the findings, two donuts:
      - a **composition donut** using the first breakdown that splits the selection: attack type, infection / category, report, target country or affected city
      - a **networks donut**: source networks, or destination networks when analysing a source network
    - **Events by hour and type** (stacked)
    - **Activity today** in 15-minute bars
    - **Severity mix**
    - breakdown lists and the most active source hosts
  - Every breakdown row and host row can be clicked to drill further (city → infection → C2 domain → host). **Back** returns to the previous view, and **Filter map** applies that entity as a filter.
- **Design:** neutral grey surfaces with one blue accent. Severity colors are used only for severity, and infections use a separate palette with no red. Type is Inter for the UI (tabular numbers) and Geist Mono for IPs, hashes and timestamps.
- **Below 1440 px**, Intel moves into a tab in the left panel. **Below 1100 px**, the left panel becomes a ☰ drawer. **On phones**, the stream is a bottom sheet of cards (tap the grabber to expand), and the detail view opens full screen.

## Security, accounts and deployment

Every page needs a sign-in with a password and an authenticator code. People request accounts on the sign-in page
(full name, organisation, email, country) and administrators approve them with a role: external (masked data
only), analyst (all data, exports, Malpedia), researcher (the Definitions page), management (the Executive portal),
advisor (the Advisory portal), auditor (the Audit portal only, read only) or admin. "Stay signed in" keeps a session
for up to 5 days. Admins manage users, sessions, roles and permissions on the **Admin** page; the audit log is read in
the **Audit portal** (`/audit`). An optional password expiry policy is set in Settings (`password_policy.py`).

The audit log and its evidence, module by module:
- `audit_chain.py`: the hash-chained audit log, its archives on rotation and the retention removals recorded in the chain.
- `audit_portal.py`: the Audit portal's pages and API, the control checks LG-01 to LG-15 and the access review.
- `control_map.py`: NIST SP 800-53 Rev. 5 controls → CIS Controls v8.1 safeguards, taken unchanged from CIS's
  official mapping (CC BY-NC-ND 4.0 content, not under AGPL).
- `audit_report.py`: the evidence report (PDF). `audit_proof.py`: the proof package (log files, `audit_log.csv`,
  manifest) and the continuity check. `audit_verifier.py`: the standalone verifier shipped in the package.
- `sender_audit.py`: the Audit portal's Sender check page (DKIM results, keys, new report types).

The pipeline from Settings → Workers: `pipeline_settings.py` (the page's API: unlock with the administrator's password,
requests, the API key check, held-back reports) and `pipeline_link.py` (finds the pipeline beside the platform). The
rules themselves live in the pipeline's `worker_settings.py`, which the platform loads read-only; a request that
weakens the pipeline also needs `./confirm_request.sh` on the pipeline's account.

- **`docs/SECURITY.md`:** how Looking Glass is secured, the changes made after the penetration test, the operator checklist.
- **`docs/INSTALLATION.md`:** installing on Windows with WSL or on a Linux server, HTTPS, firewall, updating, troubleshooting.
- **`docs/SECURITY_REPORT.md`:** the penetration test of 2026-11-07 and its remediation status.

Every CSV the platform hands out (report ZIPs, the services host list, Executive tables, and the browser downloads) passes
through one guard (`csvsafe.py`, the same rule in `app.js` / `services.js`): a cell that a spreadsheet would run as a
formula (`=`, `+`, `-`, `@`, tab, line breaks, their full-width forms) gets a leading apostrophe; numbers and the `-`
placeholder are left as they are.

Security scripts:
- `security_testing/security_retest.py`: about 120 checks of every protection against the running service.
- `manage/manage_users.py`: accounts on the command line (recovery when no administrator can sign in).
- `deploy/create_readonly_db_user.py`: a read-only MongoDB account for the app.
- `deploy/make_tls_cert.sh`: HTTPS for other screens.
- `tests/lgauth.py`: lets the check scripts on this computer reach the API with the local automation key.
- `tests/e2e_test.py`: starts a copy of the app on port 5055 against a throwaway database. The copy holds reference
  data only (no accounts, sessions, keys, certificates, audit log, findings, notes or advisories), gets an automation
  key of its own, listens on 127.0.0.1 only, and is removed again even when the test fails.
- `python app.py` (tests, development) listens on 127.0.0.1 unless `BIND_HOST` says otherwise; the service itself runs
  under gunicorn with its own bind setting.
- IP addresses inside text are found by one module, `ip_find.py`, for every masker (the researchers' `hostmask.py` and
  partial masking, and the masked viewers' `host_label.py`), so no spelling escapes one and not the other.
  It masks anything shaped like an address, letters glued on or not (`v41.66.1.2`, `id_41.66.1.2`), but keeps a
  four-part number the text itself names as a version, with nothing glued after it: after a version word and a
  separator (`version 2.0.1.3`, `Build: 1.2.3.4`, `firmware=10.4.0.12`) or after a product name and a slash
  (`Apache/2.0.1.3`; a path such as `/api/41.66.1.2` stays masked). A five-part number such as `1.2.3.4.5` is never
  an address, in either masker.
- Checks that read the reports database call `tests/needs_db.py` first: without a reachable MongoDB they report
  SKIPPED (exit 77) instead of a connection error.

## Scripts

### Checking everything

- **`bash tests/run_all_checks.sh`** runs every automated check in one go and prints one line per check (about 2 minutes). The checks are read-only against the real database and service; the collection tests use throwaway databases that they drop. The checks are:
  - replay schedule;
  - new communications and services collections;
  - services consistency (28 filter combinations);
  - services and communications totals against MongoDB;
  - **statistics and filters** (`tests/verify_stats.py`): every figure is worked out a second time straight in MongoDB, with aggregation pipelines that derive the fields on their own, and compared with the running service: the headline figures of the statistics and the overview, every top list, the 96 quarter-hour timeline, the hourly chart, the top networks per company, every filter on its own (its 3 most common values and the rarest) on the statistics, the map and the replayed count, combinations of filters, the *unknown* / *untagged* / *unrated* labels, and the edges (unknown filter names, values that do not exist, `at=` outside the two days served, the 30-minute window and the limits of `/api/events`). It also reports, without failing, how many filter values one request can carry (a web-server limit of about 8 KB) and how fast the statistics answer under load. `tests/verify_stats.py -v` prints every comparison; a date checks the day before. Skipped when a constituency is set (the constituency check covers that) or when the day has no records yet;
  - **services statistics** (`tests/verify_svc_stats.py`): the services platform worked out a second time from the raw MongoDB documents with the check's own code (tags, issues, products, families): the headline figures, every whole-day breakdown with its host counts, every filter (3 most common values and the rarest), combinations, vulnerable only, the *unknown …* labels;
  - **Executive portal** (`tests/verify_management.py`): both portals' figures, hourly chart and lists, the filters, every day of the 7-day baseline and every grade (recomputed), and the clickable "Top findings" combinations (narrowed to one, the portal must count exactly its devices or hosts). The shared reading of MongoDB is `tests/mongo_derive.py`;
  - **reports** (`tests/check_reports.py`): analysis reports of both platforms and both Executive reports are downloaded (ZIP and PDF alone); every PDF opens, every CSV has as many rows as the on-screen list and as MongoDB, the combination CSVs add up to the portal's figures and the 7-day trend CSV matches the portal. Each download is an audit entry of the automation account;
  - **CSV formula safety** (`tests/check_csv_safety.py`): planted formula values through the guard, the code (no CSV is
    written without it, the browser rule is run on the same values) and every cell of the real downloads;
  - replayed counts;
  - constituency;
  - **demo masking** (`tests/test_demo.py`): no real address, AS number, network name or host name in any masked answer
    of either platform (Demo button and roles without *unmasked*), raw addresses and real network names as filters find
    nothing, pins never outlive the account. It first proves it finds real values in unmasked answers, so it can fail;
  - **privacy and roles unit tests** (`tests/test_privacy_roles.py`): IP and text masking, aliases, host references,
    strict filters, role rules and people's names, on invented values;
  - **Intel gathered** (`tests/check_intel.py`) and **researchers' notes** (`tests/check_notes.py`, on a throwaway notes
    file): researchers get them, other roles are refused, no constituent address in any answer, notes reach the cards
    and the PDF reports;
  - **several reports / multiple issues** (`tests/check_cross_filters.py`): for every report family and the busiest reports, the figure, the analysis table, the filtered view, every bubble, what clicking a bubble shows and the regions map must agree with an independent count straight from MongoDB; it also checks that a filtered stream finds the latest records however long ago.
- **`.venv/bin/python tests/e2e_test.py all`** is the end-to-end test of report arrivals (about 5 minutes). It copies the project to `~/lg_e2e_app` (its own data files) and the replay day's rows to a throwaway database `lg_e2e`, and starts the copy on port 5055. It then simulates Shadowserver and checks what both platforms and the intro page report, as the browser sees them:
  - late rows for reports already in;
  - a report's first rows of the day;
  - new compatible and incompatible collections on each platform (announced, field score, listed on the intro page, not picked up by the other platform);
  - a constituency change on both platforms;
  - dropped collections;
  - the replay schedule staying on its day.

  Afterwards the copy is stopped and the copy and the test database are deleted. `setup`, `check` and `teardown` can also be run one at a time, for example to watch the copy's pages at http://127.0.0.1:5055 while `check` runs.
- While the intro page is open, it refreshes the services card within about 15 seconds of a new services collection, late services records or a field-check result. Communications changes refresh it straight from the map's clock.
- The "replay paused while this tab was in the background" notice appears only on the platforms, not over the intro page; the replay still pauses and resumes as before.

- `tools/envcheck.sh` checks Python, venv and whether MongoDB (`MONGO_HOST`/`MONGO_PORT` from `.env`) is reachable.
- `tools/quickcheck.py` checks the connection, lists every report collection with its size and filename index, and times the replay day's count.
- `tools/daysize.py [YYYY-MM-DD]` (default yesterday) shows one day's rows and files per report, its time range, top tags and countries.
- `tools/list_infections.py [YYYY-MM-DD]` lists every infection of that day (any day, not only the replay day).
- `tools/discover.py` surveys every collection: size, indexes, src/dst fields, latest document and yesterday's row count. It writes `tools/discovery.json`, and `tools/show_srcdst.py` prints the matching collections from it.
- `tests/test_sources.py` is a smoke test: it builds the registry, loads the replay day from all collections and calls the APIs.
- `deploy/reload.sh` restarts the systemd service without sudo. It kills the main process and systemd starts it again; `sudo systemctl restart looking-glass` does the same.
- `manage/backup.sh [dest]` creates a timestamped archive of the project, including `.env` and everything in `data/` but not `.venv`, saved as `~/backups/<project folder>-<UTC time>.tar.gz` with a `.sha256` file and mode 600.
