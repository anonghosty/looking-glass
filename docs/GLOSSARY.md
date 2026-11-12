# Glossary

Every term, figure and report name used in Looking Glass, in plain language. The same definitions are built into
the platform: the **Glossary** tab on the overview page and the **Glossary** button on both platforms.

## Contents

- [The basics](#the-basics) (8 terms)
- [Who and where](#who-and-where) (10 terms)
- [Threats](#threats) (15 terms)
- [Numbers and measures](#numbers-and-measures) (12 terms)
- [Using the platform](#using-the-platform) (11 terms)
- [Accounts, roles and permissions](#accounts-roles-and-permissions) (34 terms)
- [Publicly accessible / vulnerable services](#publicly-accessible--vulnerable-services) (13 terms)
- [Security, audit and the pipeline](#security-audit-and-the-pipeline) (18 terms)
- [Related tools](#related-tools)
- [A–Z index](#az-index)

## The basics

**Event**  
One recorded communication or attack attempt in a Shadowserver report. For example: one infected device calling a sinkhole, or one password guess against a honeypot.

**Replay (minus 24 h)**  
Looking Glass plays yesterday's events at the same time of day today. Shadowserver delivers each day's reports the following day, so nothing on screen is live: it is a complete, verified day played back 24 hours later.

**Event time (UTC)**  
When the event actually happened, taken from the report's extracted_date field, in Coordinated Universal Time (UTC); add your country's offset for local time. Open any event to see it. It is never the current clock time.

**Replay time (UTC)**  
The event time (extracted_date) of the events being played right now, with its date: normally yesterday. It moves forward as the event stream plays, and each row in the stream shows its own replay time. Each day is replayed in full from 00:00 to 24:00, starting when Shadowserver's report for that day has arrived.

**Current time (UTC)**  
The real date and time now. It is separate from the replay time: the replay is at least a day behind, and more when a day's report arrived late (the replay then starts that day from 00:00 when the report arrives).

**Report**  
One Shadowserver data feed, stored as one database collection, for example Sinkhole HTTP or Honeypot Brute Force. Each report covers one kind of observation. Looking Glass finds every report that records a source and a destination automatically.

**Shadowserver**  
The Shadowserver Foundation, a non-profit that scans the internet, runs sinkholes and honeypots, and sends free daily reports to national CSIRTs and network owners.

**CSIRT**  
Computer Security Incident Response Team: the team that receives these reports and helps affected organisations clean up.

[↑ Back to contents](#contents)

## Who and where

**Source host**  
The unique IP address that started the communication. In botnet reports it is usually an infected device; in honeypot reports it is the machine doing the attacking.

**Destination**  
Where the communication went: a sinkhole server, a honeypot sensor or an attack target.

**Destination IPs**  
How many different destination addresses were contacted, for example distinct sinkhole servers or honeypot sensors.

**Affected city**  
The city of the source host, according to Shadowserver's geolocation of its IP address. It shows where in the country the problem is.

**Target country**  
The country of the destination. For botnet reports this is where the sinkhole runs, not a victim country.

**Network (ASN)**  
The company that operates the internet connection, such as an ISP, a university or a hosting provider. Each operator has an Autonomous System Number (ASN); Looking Glass shows the company name instead of the number.

**Target port**  
The network port (service) that was contacted, for example 80 for web, 22 for SSH, 23 for Telnet or 445 for Windows file sharing. It shows which service was being used or attacked.

**User agent**  
The name a program sends to identify itself in web requests, for example a browser or an Android device model. Malware often uses unusual or fixed user agents.

**Request path**  
The part of a web address the device asked for, such as /v4.php. Repeating paths often identify a malware family's check-in.

**IP address**  
The numeric internet address of a device or connection. Home connections often share one public IP between many devices (NAT).

[↑ Back to contents](#contents)

## Threats

**Infection / category**  
The malware family or type of activity Shadowserver assigned to the event, for example android.badbox2 (a TV-box botnet) or ssh-brute-force. Open any event for a description and a recommended action.

**Attack type**  
Looking Glass groups reports into broad types: Botnet C2, Brute force, Scanning, DDoS, Initial access, IP spoofing and Spam.

**Botnet C2**  
Infected devices trying to contact their botnet's command-and-control server, which has been taken over (sinkholed). Every such device is infected.

**Brute force**  
Repeated password guessing against a login service (for example SSH or Telnet) on a honeypot. The source is usually a compromised server or IoT device.

**Scanning**  
A host probing honeypots for vulnerable services or web pages. Often an infected device looking for new victims.

**DDoS**  
Distributed denial of service: flooding a target with traffic to knock it offline. Reports show local hosts taking part, or local networks being targeted.

**Botnet**  
A network of infected devices that criminals control remotely, for example to send spam, run proxies or attack websites.

**C2 (command and control)**  
The server a piece of malware contacts to receive instructions and report back.

**C2 / sinkhole domains**  
Distinct domain names the hosts tried to reach for command and control. Zero means the report records only IP addresses, not domain names (normal for some reports).

**Sinkhole**  
A server taken over by security researchers or law enforcement that receives the traffic meant for criminals' servers. Devices that contact it are infected, and nothing harmful is sent back.

**Honeypot**  
A decoy system set up to attract attackers and record what they do. Anything that attacks it is behaving maliciously.

**Severity**  
Shadowserver's rating of how serious an event is: critical, high, medium, low or info. Unrated means the report gives no rating.

**Critical**  
Events rated critical: usually confirmed infections or active attacks that need action.

**Tag**  
An extra label from the report, often a campaign name or an alternative family name.

**Residential proxy**  
Software that lets strangers route their internet traffic through a subscriber's connection, often hidden in free apps or cheap devices. Abuse then appears to come from that subscriber.

[↑ Back to contents](#contents)

## Numbers and measures

**Events yesterday**  
Every record Shadowserver reported for yesterday, across all reports, from 00:00 to 24:00 UTC. It is a fixed total for the day and does not grow as the map replays events. This includes infections calling sinkholes as well as attacks such as brute force and scanning.

**Replayed so far**  
How many of yesterday's events have been replayed in the event stream so far: every record with an event time up to the replay position, counted exactly from the database (with any active filters). It grows as the replay runs, stops while paused, and reaches the Events yesterday total at the end of the day.

**Reports**  
How many different reports contain these events yesterday.

**Cross-report hosts**  
Source hosts that appear in more than one report on the same day, for example a device that is infected and also scanning. They are strong candidates for follow-up.

**Hosts with multiple threats**  
Source hosts seen with more than one infection or category yesterday. One device can carry several pieces of malware.

**Share of all events**  
This selection's events as a percentage of all events of the replayed day. For example 42.9% means almost half of everything seen yesterday.

**Median**  
The middle value when all values are sorted from smallest to largest. Unlike an average, a few extreme values do not distort it, so it shows what is typical.

**Median repeat interval**  
For hosts seen at least three times, the typical time between their events (the median of the gaps). Short and regular intervals point to automated malware checking in, known as beaconing.

**Beaconing**  
Malware contacting its server at regular intervals to ask for instructions. Regular repeat intervals are a sign of it.

**Activity level**  
How busy the last 5 replayed minutes were compared with the whole day's average per minute. More filled bars means busier than usual; it says nothing about how dangerous the events are.

**Activity by 15 minutes**  
A bar for every 15 minutes of yesterday showing how many events happened in it, for the whole day. The white bar marks where the replay is now.

**Peak**  
The busiest hour or 15-minute period so far.

[↑ Back to contents](#contents)

## Using the platform

**Event stream**  
The table at the bottom listing each event as it plays. Click a row for full details, or pin it to keep it.

**Analysis view**  
Opens when you click any item in Intel, on the map or in a breakdown. It summarises that city, infection, network, report, host or time window with numbers, findings and charts. Clicking anything inside it narrows it further (a deep dive, for example an infection, then one network, then one port, then one hour). The parts are shown as chips under the title: click one to open it on its own, or × to remove it. Filter map applies the whole selection to the map, stream and Intel.

**Follow-up (details lists)**  
Click any figure in the analysis view to see the list behind it. Hosts are ranked for follow-up: several kinds of activity (for example botnet C2 and attacks) count most, then appearing in several reports or with several infections, then regular beaconing and critical events. Hosts marked Monitor show no strong signs beyond this selection. Each list can be downloaded as a CSV file.

**Key findings**  
Plain-language observations Looking Glass calculates from the data, such as what dominates or how many hosts appear in several reports.

**Filters**  
Narrow the map, stream and statistics to what you choose, for example one attack type or one city. The bar above the stream shows what is active.

**Intel**  
The right-hand panel of charts and top lists for all of yesterday's records (whole-day totals, not just what has been replayed). Click any entry to analyse it.

**Pin**  
Keeps an event at the top of the stream and on the map in this browser.

**Demo mode**  
For public presentations. Network names become aliases such as Telco 1, AS numbers and hostnames are hidden and IP addresses are shortened. Locations stay visible. The server applies it, so the hidden values never reach the screen.

**All of the day's connections (map)**  
Faint lines and circles on the map that stay drawn all the time: every source place (coloured, sized by events), every destination (white rings) and every source to destination connection of the whole day, thicker for more events. They follow the filters, so filtering narrows the map to just those places, and the map zooms out if some are off screen. The bright animated arcs on top are the events playing right now. Hover over anything on the map for details, and click it to analyse it: a line opens that connection (for example Accra to The Hague), a place opens that city or destination, and a live arc opens the event. Events without a destination location (for example Sinkhole DNS) show only their source place. Turn it off under Filters > Display.

**Display quality (Auto / Full / Lite)**  
Full shows every effect: 3D tilt, glowing arcs with trails, camera drift and see-through panels. Lite is for smart TVs and older computers: a flat map, fewer arcs at once, lighter effects and solid panels, so playback stays smooth. Auto (the default) uses Full on capable devices and switches to Lite on TV browsers, very low-power devices, or when the map draws slowly. The data and counts are the same in every mode. Set it on the intro page (top right) or under Filters on either platform, or add ?perf=lite to the address; the choice is remembered on this device and applies to every page.

**Playback speed**  
Speed 1x plays yesterday's events at their original pace, 24 hours later. Faster speeds compress time for demonstrations; choose Speed 1x to return to the normal replay.

[↑ Back to contents](#contents)

## Accounts, roles and permissions

**Role**  
What an account may see and do on Looking Glass. Each role is a set of permissions; administrators assign a role to every account (Admin → Users) and can create their own roles from the permissions (Admin → Roles).

**External (role)**  
People outside the security team, such as partners or visitors. They see both platforms with IP addresses, network names and host names always masked, cannot switch masking off, and cannot export, run look-ups or change anything.

**Analyst (role)**  
The security team's analysts. They see all data unmasked, analyse it, download lists, CSV files and reports (PDF + CSV), look up malware on Malpedia and vulnerabilities (CVEs), and switch Demo mode on for presentations. They cannot change Settings or manage accounts.

**Researcher (role)**  
The organisation's security researchers. They work on the Definitions page only: they research and define, with references, the malware names Malpedia does not know and the issues that are not CVEs, study the indicators the reports carry (Intel gathered) and the matches Looking Glass raises, share notes on new findings, and correct network names (AS numbers). Their definitions and notes are then shown to every user, signed with their full name. They do not see the platforms or host addresses.

**Management (role)**  
Managers and executives. They use the management portal only: a polished dashboard of aggregated figures for both platforms (affected devices, infections, exposed services, actively exploited vulnerabilities, regions, sectors, networks and trends), with filters, explanations of infections and vulnerabilities, and executive PDF reports of what they filtered. They never see individual addresses or host lists. This portal cannot be given to any other role; admins can open it to preview it.

**Management portal (Executive)**  
The dashboard of the management role at /management. Every figure is aggregated (counts, shares, trends): click any bar, slice or region to focus every chart on it, click an infection or a CVE to have it explained, and download an executive report (PDF) of exactly what is on screen.

**Advisor (role)**  
Writes the advisories. Their Advisory portal (/advisory) shows what waits for an advisory, what is in progress and what was sent, to whom. They open a finding management approved to them, write the description and recommended actions for one organisation, generate its report and mark it sent. They see the affected organisation's devices for that advisory, nothing else of the platforms.

**Auditor (role)**  
An internal or external auditor. They use the Audit portal (/audit) only, read only: the audit log by tab, the dashboard and control checks, the access review, the log's integrity, and evidence to take away. They never see the platforms or any host data, and no one can change what this role may do, so it never depends on the people being audited.

**Admin (role)**  
Administrators. Everything the other roles can do, plus Settings (country, constituency, the password policy, the pipeline's Workers settings), accounts, roles, sessions and the Audit portal. Peace of mind lets an administrator step out of the day-to-day findings.

**Permission**  
One thing a role allows: view (see the platforms), unmasked (real addresses and names), export (CSV files, complete lists and reports), malpedia (malware and vulnerability look-ups), settings, networks (correct network names), audit (the Audit portal), and four that belong to one role only: management (Executive portal), definitions (Researcher), advisory (Advisor) and users (Admin: accounts and roles).

**Looking Glass definition**  
A description of a malware name or an issue that Malpedia or the vulnerability databases do not cover, with references (evidence). The definitions that come with Looking Glass are signed Looking Glass; those written by a security researcher of the organisation carry the researcher's full name. It is shown to every user in look-ups, lists, CSV files and reports.

**Intel gathered**  
On the Definitions page: what the reports carry for an infection or an issue, report by report, as name › report › what comes with it there. For infections: the C2 domains contacted, DNS lookups, TLS server names, URLs, user agents and the usernames brute-force bots tried. For issues: the other CVEs on the same hosts, associated tags, products, certificate names and fingerprints. Indicators only: the hosts themselves are never shown.

**Indicator**  
A trace of a threat that can be searched for elsewhere: a C2 domain, a URL, a user agent, a file or certificate fingerprint, a username a bot tries. Looking Glass collects them from the reports for researchers (Intel gathered).

**Combination**  
The exact set of indicators that occur together on one record, for example iot + router-os + winbox, or a C2 domain with a particular user agent. Combinations explain why one indicator counts fewer records than another, and show which variants exist.

**Devices and repeating devices (↻)**  
In Intel gathered: how many distinct devices carry a value or a combination, and how many of them carry it in more than one record. A combination many devices keep repeating is a pattern (the same malware or campaign behaving the same way), not a one-off. Devices are counted, never shown.

**Looking Glass asks (lead)**  
A match the platform found in the reports and asks a researcher to look into: the same indicator under two names (possibly one family under two names, or shared infrastructure), in two reports for one name (a probable indicator of that name, worth putting in its notes), or an infection's C2 domain that is also a certificate name on a service in the constituency. Values common to everything (stock browser user agents, usernames such as root) are never raised.

**Note (researcher)**  
A new finding a researcher records on a name (the C2 moved, seen together with another family…), dated and signed. It appears on every card of that name and in the PDF reports as Notes shared by Researcher: full name (date). Notes are kept apart from the definitions and are never replaced by an update.

**Combination code (LG-C, LG-X)**  
A short code for one exact combination Intel gathered shows: LG-C-… for one report (the records that carry exactly these indicators), LG-X-… for a cross-report pattern (what a device carried in each of several reports). The same combination always has the same code, and a code carries no address, so researchers and management can pass it on in notes and reports; an analyst pastes it on the Combinations page to get exactly those devices.

**Combination search**  
The analysts' page (/combinations) that turns a combination code into the devices behind it, over the days in memory or up to 31 days of stored history, with a PDF summary (region map, across reports, each name and CVE explained with its references, and the researchers' notes on every name) and CSV files of the devices and records. A chart with nothing to show is left out of the PDF. It lists real addresses, so it is only for roles that see them and may export, and is off in Demo mode.

**Analyst code (LG-A)**  
A code for exactly the records of an analyst's selection on one day (for example a network and one host), made in an analysis window. It becomes a finding: researchers open it without any address and answer with their own codes, management filters the Executive portal by it, and analysts report on it again from the Combinations page.

**Needle through the haystack**  
The way Looking Glass is meant to be used: instead of forwarding a network operator thousands of reported addresses, narrow the day's reports step by step (actively exploited, seen by several reports, the same exact combination on many devices, repeating) to the few devices most likely to matter, send that operator a short explained report, then take the next. The numbers drop day by day.

**Report per network provider**  
On the Combinations page, the PDF and CSV files for one operator only (Report for, or a click on the network): every figure, the map and both CSV files cover just that provider's devices, ready to attach to the advisory sent to it.

**Reply (on a finding)**  
An answer added to a finding's history, with text and codes: a researcher answering an analyst's code with combination codes, or anyone in the loop adding what they found. The status stays as it is.

**Finding**  
Something the team follows up, with a number (#1, #2…): a researcher's note or an analyst's combination, sent by name to a manager, who approves it to a named analyst or advisor or rejects it with a reason. Every hand-over names a person, and only the people a finding has passed through (and administrators) see it. A case holds one sub-finding per organisation; it closes when every organisation's advisory is sent. Each step records who, when and a comment, and no address is shown on the Findings page.

**Advisory**  
The report an advisor sends one organisation about its affected devices: the advisory pages (devices, impact, description, recommended actions), then the insights behind it, technical details with every weakness defined, and the Shadowserver references. It is signed by the CSIRT (name and logo from Settings), never by a person, and carries its TLP on every page. It goes out as a PDF and a devices CSV.

**TLP (Traffic Light Protocol)**  
FIRST's TLP 2.0 labels how far an advisory may travel: RED (the named recipients only), AMBER+STRICT (the recipient's organisation only), AMBER (the organisation and its clients who need to know; the default, since an advisory lists the organisation's addresses), GREEN (the recipient's community, not published) and CLEAR (anyone).

**Seen in / Last seen**  
The reports a name appears in. Each report shows whether it carries intel for the name (intel · N kinds) or only the name. A name not in today's reports shows where and when it was last seen (the last 30 days are remembered).

**Malpedia**  
The malware encyclopedia of Fraunhofer FKIE (malpedia.caad.fkie.fraunhofer.de): malware families and threat actors with descriptions and references. Looking Glass looks infections up there when a Malpedia API token is set; otherwise the Looking Glass definitions answer.

**Threat actor**  
A group of attackers (for example Tick, also called BRONZE BUTLER) rather than a malware program. When a name is a group, the look-up shows the group, its aliases, suspected origin, targets and the malware it uses.

**CVE**  
Common Vulnerabilities and Exposures: the public identifier of a known security flaw, such as CVE-2023-48795. Issues that are CVEs are looked up automatically in NVD, CISA KEV and EPSS.

**CVSS score**  
The Common Vulnerability Scoring System rates how severe a flaw is, from 0 to 10: low, medium, high (7 or more) or critical (9 or more). From the US National Vulnerability Database (NVD).

**Actively exploited (CISA KEV)**  
The vulnerability is in the Known Exploited Vulnerabilities catalog of the US Cybersecurity and Infrastructure Security Agency (CISA): attackers are confirmed to be exploiting it. Hosts with these should be patched first. Not being in the catalog does not mean a flaw is safe.

**EPSS**  
The Exploit Prediction Scoring System (FIRST.org): the estimated probability that a vulnerability will be exploited in the next 30 days, for example 94% for CVE-2023-48795.

**Report (PDF + CSV)**  
The Download report button on every list behind an analysis figure gives a ZIP file with a PDF report (executive summary, key figures, priorities, the infections or issues explained, breakdowns, report definitions) and the complete list as a CSV file, which the PDF refers to.

[↑ Back to contents](#contents)

## Publicly accessible / vulnerable services

**Publicly accessible / vulnerable services**  
The second Looking Glass platform (/services). It replays the single-host Shadowserver reports: services in your constituency that anyone on the internet can reach (scans), devices Shadowserver fingerprinted, compromised hosts and blocklisted addresses. Same replay, filters, analysis and demo mode as the map; instead of a map it shows a services constellation or a Ghana regions heatmap.

**Record**  
One host and service seen in a single-host report, for example one open RDP server or one fingerprinted router. Records yesterday is the whole day's total.

**Exposed host**  
A distinct IP address with at least one internet-reachable service or finding in the reports.

**Issue**  
A concrete problem found on a host: a known vulnerability (CVE), weak encryption (POODLE, FREAK), an expired certificate, an exposed admin panel, a device implant or a compromise. Hosts with issues are the ones to follow up first.

**Hosts with multiple issues**  
Hosts of the selection carrying more than one issue across all their reports of the day, for example several CVEs, or a CVE plus an exposed admin panel in another report. They have the largest attack surface. Opening this card and pressing Filter the view shows these hosts with all their reports (bubbles, regions map, stream and figures); a filter added afterwards narrows to those reports.

**Hosts in several reports**  
Hosts that appear in more than one Shadowserver report on the same day, for example an exposed admin panel and an outdated SSH server on the same address. Opening this card and pressing Filter the view shows these hosts with all their reports (bubbles, regions map, stream and figures), e.g. the blocklisted hosts that are also seen in other reports; a filter added afterwards (a bubble, a report) narrows to those records.

**Report family**  
Exposed service (scan reports: a service reachable from the internet), Service population (every host answering a protocol), Identified device (devices fingerprinted by vendor, type and model), Compromised (devices or websites showing compromise) and Blocklisted (addresses on public abuse lists).

**DNS Open Resolvers**  
DNS servers that answer anyone's questions. Attackers use them to amplify denial-of-service attacks; recursion should be limited to your own users.

**Population report**  
A report listing every host that answers a protocol (for example Accessible ISAKMP or Open BGP Service (population)), whether or not it has a known problem. Useful as an inventory of what is exposed.

**Constituency (Settings)**  
The networks (AS numbers) and address ranges your CSIRT is responsible for, chosen on the Settings page. When set, both platforms show only records whose host is in the constituency; the top bar then shows 'Constituency: N networks'. Without it they show the whole country.

**Country (Settings)**  
The country your CSIRT covers, chosen on the Settings page from all 54 African countries. The publicly accessible / vulnerable services platform draws its regions map for it (boundaries from geoBoundaries, CC BY 4.0).

**Regions heatmap**  
The first-level regions of the country chosen in Settings (provinces, regions, states or counties), coloured by records with the active filters. Hover a region to see which reports, issues, cities and networks make it up; click it to analyse it. Records whose location is known only at country level are counted as Region unknown.

**Services constellation**  
One bubble per report, sized by its records for the day. A dot flies into a bubble each time one of its records replays, coloured by severity.

[↑ Back to contents](#contents)

## Security, audit and the pipeline

**Masking**  
What viewers without the unmasked permission see instead of real data: every IP address becomes an opaque label (Host 3f9a2c41b07e) that cannot be turned back into the address, network names become aliases (Telco 1) and host names are removed. Researchers never see a constituent's IP address; report data (banners, URLs, user agents, DNS and SNI values, patterns) is shown to them as reported with the addresses in it masked, while team notes and free text also mask host names, e-mail addresses and IDs.

**Authenticator code (two-step sign-in)**  
Every account signs in with its password and a six-digit code from an authenticator app (TOTP), which changes every 30 seconds. Each code works once. Recovery codes, shown once when the authenticator is set up, replace a lost phone.

**Password expiry**  
An optional policy an administrator sets in Settings: passwords expire after a number of days, and turning it on (or Every account now) makes every account choose a new password at its next sign-in. After the password and the authenticator code, the person sets a new password and goes straight in. Off by default, as NIST SP 800-63B advises against forced periodic changes.

**Audit portal**  
The auditor's page (/audit), read only: the audit log by tab (sign-ins, accounts, sessions, configuration, data access and exports, workflow, system), a dashboard of key figures, the control checks, the access review, the log's integrity, the sender check, and evidence to take away (CSV, the evidence report, the proof package).

**Audit log (hash chain)**  
The record of who did what, when and from where on Looking Glass. Each entry holds the hash of the entry before it, so changing, inserting or removing any entry breaks the chain from that point; archives and removals by the retention period are recorded in the chain too. The Audit portal checks it, and anyone can check it independently with the proof package.

**Control check (LG-01 … LG-15)**  
An automated check of one of Looking Glass's own controls (for example LG-01 multi-factor authentication, LG-06 failed sign-ins, LG-10 audit log protection), with the evidence from its records. Each is mapped to the NIST SP 800-53 controls it supports and, through them, to CIS Controls safeguards. They give evidence, not a pass or fail: the conclusion is the auditor's.

**NIST SP 800-53**  
The US National Institute of Standards and Technology's catalogue of security and privacy controls (Revision 5, release 5.2.0), for example IA-2(1) multi-factor authentication or AU-9 protection of audit information. The control checks cite the controls they support by their official titles.

**CIS Controls (safeguard)**  
The Center for Internet Security's Critical Security Controls v8.1: prioritised safeguards such as 8.5 Collect Detailed Audit Logs. Looking Glass lists, for each control check, the safeguards CIS's own official mapping relates to its NIST controls, with CIS's relationship (equivalent, subset or superset), so one chain reads LG → NIST → CIS. CIS Controls © Center for Internet Security, used under CC BY-NC-ND 4.0.

**Proof package**  
A ZIP the auditor downloads from the Audit portal: the audit log's files exactly as stored, the whole log as a spreadsheet (audit_log.csv, one row per entry, numbered as in the chain), a manifest with the SHA-256 of every file, and a short verifier in plain Python that recomputes the chain on the auditor's own computer, without trusting Looking Glass.

**Head (continuity check)**  
The hash of the newest entry in the audit log and its entry number. An auditor keeps it with the evidence; at the next audit, if that hash is still at that entry number, every entry up to it is unchanged, even against someone able to rewrite the whole log on the server.

**Evidence report (PDF)**  
The Audit portal's report for a period: scope and method, key figures, the integrity of the audit log, every control check with its NIST and CIS mapping and its evidence, the access review and the privileged changes.

**Database pipeline**  
The separate program that fetches Shadowserver's reports on a schedule (usually every 30 minutes), checks and unpacks them, and loads them into MongoDB for the platforms to read. It runs on its own account and keeps its own settings and passwords.

**Report source (e-mail or Shadowserver API)**  
How the pipeline gets the reports: from the mailbox they are e-mailed to, or straight from Shadowserver's report API with an API key. If the chosen way cannot be used on a run and the other is set up, that run uses the other and its log says why. Report types Shadowserver adds later are fetched like any other.

**Sender check (DKIM)**  
For reports that arrive by e-mail: the pipeline checks each message's DKIM signature with the sender's public key from DNS, to tell genuine Shadowserver reports from forged ones. Record only keeps every result for the Audit portal; Block also holds back a report that is not validly signed by the expected signer (shadowserver.org).

**Held-back report (quarantine)**  
A report e-mail the sender check stopped: kept apart and not loaded. An administrator who knows it is genuine releases it in Settings → Workers, and it is loaded at the pipeline's next run. Released reports stay on record.

**Workers (Settings)**  
The Settings tab for the pipeline's own settings: how reports are fetched, the sender check, mailbox folder and certificate check, loading performance, unzip limits, the Shadowserver API key and held-back reports. It is locked behind the administrator's own password; a change is a request the pipeline checks again and applies at its next run. Passwords are never shown or changed there.

**Confirmation on the server**  
A Workers change that makes the pipeline less strict (the sender check lowered or another signer, the certificate check off, the API given up for e-mail, a looser unzip limit, a new API key, a release) also needs someone on the server to run ./confirm_request.sh with its number on the pipeline's account. So a fault in, or break-in to, the web app cannot switch the pipeline's protections off by itself.

**New report type**  
A Shadowserver report arriving for the first time. The pipeline notices it however it arrives and logs it, and the Audit portal's sender check lists it with whether Looking Glass's report definitions know it yet.

[↑ Back to contents](#contents)

## Related tools

Tools that CSIRTs often use alongside Looking Glass (see the [comparison](COMPARISON.md)).

**Shadowserver Foundation**  
A non-profit that scans the internet, runs sinkholes and honeypots, and sends free daily reports to network owners and national CSIRTs about the threats seen in their networks.

**IntelMQ**  
A free, open-source tool from CERT.at for collecting, parsing, enriching and distributing security feeds, including Shadowserver's, and for notifying the owners of affected hosts automatically.

**Elastic Stack (Elasticsearch, Kibana, Logstash)**  
A search and analytics platform with a free self-managed tier. It stores and searches any data at scale; dashboards for Shadowserver reports are designed in Kibana by each team.

**Shadowserver Dashboard**  
Shadowserver's public website of country-level statistics (up to two years), with nothing to install.

**MongoDB**  
The database Looking Glass uses: one collection per Shadowserver report type, loaded by the database pipeline.

**Malpedia**  
Fraunhofer FKIE's reference library of malware families and threat actors, used to explain infections.

**geoBoundaries**  
Open (CC BY 4.0) boundaries of every country's first-level regions, used for the regions maps.

[↑ Back to contents](#contents)

## A–Z index

[Actively exploited (CISA KEV)](#accounts-roles-and-permissions) · 
[Activity by 15 minutes](#numbers-and-measures) · 
[Activity level](#numbers-and-measures) · 
[Admin (role)](#accounts-roles-and-permissions) · 
[Advisor (role)](#accounts-roles-and-permissions) · 
[Advisory](#accounts-roles-and-permissions) · 
[Affected city](#who-and-where) · 
[All of the day's connections (map)](#using-the-platform) · 
[Analysis view](#using-the-platform) · 
[Analyst (role)](#accounts-roles-and-permissions) · 
[Analyst code (LG-A)](#accounts-roles-and-permissions) · 
[Attack type](#threats) · 
[Audit log (hash chain)](#security-audit-and-the-pipeline) · 
[Audit portal](#security-audit-and-the-pipeline) · 
[Auditor (role)](#accounts-roles-and-permissions) · 
[Authenticator code (two-step sign-in)](#security-audit-and-the-pipeline) · 
[Beaconing](#numbers-and-measures) · 
[Botnet](#threats) · 
[Botnet C2](#threats) · 
[Brute force](#threats) · 
[C2 (command and control)](#threats) · 
[C2 / sinkhole domains](#threats) · 
[CIS Controls (safeguard)](#security-audit-and-the-pipeline) · 
[Combination](#accounts-roles-and-permissions) · 
[Combination code (LG-C, LG-X)](#accounts-roles-and-permissions) · 
[Combination search](#accounts-roles-and-permissions) · 
[Confirmation on the server](#security-audit-and-the-pipeline) · 
[Constituency (Settings)](#publicly-accessible--vulnerable-services) · 
[Control check (LG-01 … LG-15)](#security-audit-and-the-pipeline) · 
[Country (Settings)](#publicly-accessible--vulnerable-services) · 
[Critical](#threats) · 
[Cross-report hosts](#numbers-and-measures) · 
[CSIRT](#the-basics) · 
[Current time (UTC)](#the-basics) · 
[CVE](#accounts-roles-and-permissions) · 
[CVSS score](#accounts-roles-and-permissions) · 
[Database pipeline](#security-audit-and-the-pipeline) · 
[DDoS](#threats) · 
[Demo mode](#using-the-platform) · 
[Destination](#who-and-where) · 
[Destination IPs](#who-and-where) · 
[Devices and repeating devices (↻)](#accounts-roles-and-permissions) · 
[Display quality (Auto / Full / Lite)](#using-the-platform) · 
[DNS Open Resolvers](#publicly-accessible--vulnerable-services) · 
[EPSS](#accounts-roles-and-permissions) · 
[Event](#the-basics) · 
[Event stream](#using-the-platform) · 
[Event time (UTC)](#the-basics) · 
[Events yesterday](#numbers-and-measures) · 
[Evidence report (PDF)](#security-audit-and-the-pipeline) · 
[Exposed host](#publicly-accessible--vulnerable-services) · 
[External (role)](#accounts-roles-and-permissions) · 
[Filters](#using-the-platform) · 
[Finding](#accounts-roles-and-permissions) · 
[Follow-up (details lists)](#using-the-platform) · 
[Head (continuity check)](#security-audit-and-the-pipeline) · 
[Held-back report (quarantine)](#security-audit-and-the-pipeline) · 
[Honeypot](#threats) · 
[Hosts in several reports](#publicly-accessible--vulnerable-services) · 
[Hosts with multiple issues](#publicly-accessible--vulnerable-services) · 
[Hosts with multiple threats](#numbers-and-measures) · 
[Indicator](#accounts-roles-and-permissions) · 
[Infection / category](#threats) · 
[Intel](#using-the-platform) · 
[Intel gathered](#accounts-roles-and-permissions) · 
[IP address](#who-and-where) · 
[Issue](#publicly-accessible--vulnerable-services) · 
[Key findings](#using-the-platform) · 
[Looking Glass asks (lead)](#accounts-roles-and-permissions) · 
[Looking Glass definition](#accounts-roles-and-permissions) · 
[Malpedia](#accounts-roles-and-permissions) · 
[Management (role)](#accounts-roles-and-permissions) · 
[Management portal (Executive)](#accounts-roles-and-permissions) · 
[Masking](#security-audit-and-the-pipeline) · 
[Median](#numbers-and-measures) · 
[Median repeat interval](#numbers-and-measures) · 
[Needle through the haystack](#accounts-roles-and-permissions) · 
[Network (ASN)](#who-and-where) · 
[New report type](#security-audit-and-the-pipeline) · 
[NIST SP 800-53](#security-audit-and-the-pipeline) · 
[Note (researcher)](#accounts-roles-and-permissions) · 
[Password expiry](#security-audit-and-the-pipeline) · 
[Peak](#numbers-and-measures) · 
[Permission](#accounts-roles-and-permissions) · 
[Pin](#using-the-platform) · 
[Playback speed](#using-the-platform) · 
[Population report](#publicly-accessible--vulnerable-services) · 
[Proof package](#security-audit-and-the-pipeline) · 
[Publicly accessible / vulnerable services](#publicly-accessible--vulnerable-services) · 
[Record](#publicly-accessible--vulnerable-services) · 
[Regions heatmap](#publicly-accessible--vulnerable-services) · 
[Replay (minus 24 h)](#the-basics) · 
[Replay time (UTC)](#the-basics) · 
[Replayed so far](#numbers-and-measures) · 
[Reply (on a finding)](#accounts-roles-and-permissions) · 
[Report](#the-basics) · 
[Report (PDF + CSV)](#accounts-roles-and-permissions) · 
[Report family](#publicly-accessible--vulnerable-services) · 
[Report per network provider](#accounts-roles-and-permissions) · 
[Report source (e-mail or Shadowserver API)](#security-audit-and-the-pipeline) · 
[Reports](#numbers-and-measures) · 
[Request path](#who-and-where) · 
[Researcher (role)](#accounts-roles-and-permissions) · 
[Residential proxy](#threats) · 
[Role](#accounts-roles-and-permissions) · 
[Scanning](#threats) · 
[Seen in / Last seen](#accounts-roles-and-permissions) · 
[Sender check (DKIM)](#security-audit-and-the-pipeline) · 
[Services constellation](#publicly-accessible--vulnerable-services) · 
[Severity](#threats) · 
[Shadowserver](#the-basics) · 
[Share of all events](#numbers-and-measures) · 
[Sinkhole](#threats) · 
[Source host](#who-and-where) · 
[Tag](#threats) · 
[Target country](#who-and-where) · 
[Target port](#who-and-where) · 
[Threat actor](#accounts-roles-and-permissions) · 
[TLP (Traffic Light Protocol)](#accounts-roles-and-permissions) · 
[User agent](#who-and-where) · 
[Workers (Settings)](#security-audit-and-the-pipeline)
