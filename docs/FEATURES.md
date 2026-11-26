# What is new in Looking Glass

What Looking Glass does, grouped under the release that brought each part, newest first. Each entry describes the
feature as it works now and says where to read more. The [Changelog](../CHANGELOG.md) keeps the history. Dates are
UTC.

## Contents

- [2026-11-13: special reports, the Executive Reports card, CIS backing by the evidence](#2026-11-13-special-reports-the-executive-reports-card-cis-backing-by-the-evidence)
- [2026-11-12 (night): local times, Executive figures by devices, every report on the Overview](#2026-11-12-night-local-times-executive-figures-by-devices-every-report-on-the-overview)
- [2026-11-12 (evening): uninstaller](#2026-11-12-evening-uninstaller)
- [2026-11-12 (later): security fixes](#2026-11-12-later-security-fixes)
- [2026-11-12: audit evidence (NIST and CIS), report intake checks, the pipeline from Settings, password expiry](#2026-11-12-audit-evidence-nist-and-cis-report-intake-checks-the-pipeline-from-settings-password-expiry)
- [2026-11-11: advisories, cases, an Overview for every role, the Audit portal](#2026-11-11-advisories-cases-an-overview-for-every-role-the-audit-portal)
- [2026-11-10: combination codes, the analyst's combination search and findings](#2026-11-10-combination-codes-the-analysts-combination-search-and-findings)
- [2026-11-09: researchers' intel, notes and a page of their own](#2026-11-09-researchers-intel-notes-and-a-page-of-their-own)
- [2026-11-09: security fixes](#2026-11-09-security-fixes)
- [2026-11-09: faster platforms and a sharper Executive portal](#2026-11-09-faster-platforms-and-a-sharper-executive-portal)
- [2026-11-08: Executive portal, 7-day baseline, vulnerabilities and network types](#2026-11-08-executive-portal-7-day-baseline-vulnerabilities-and-network-types)
- [2026-11-07: definitions, the researcher role and PDF reports](#2026-11-07-definitions-the-researcher-role-and-pdf-reports)

## 2026-11-13: special reports, the Executive Reports card, CIS backing by the evidence

- **Special reports kept apart.** Shadowserver's one-off Special Reports are loaded but never replayed or counted in
  a day's totals or the 7-day comparison, so they cannot show as a false midnight spike. The intro page lists them.
- **Every report on the Executive portal.** A Reports card ranks the selection's reports by devices; click one to
  focus on it. The Executive report has a Reports page with all of them.
- **CIS backing follows the evidence.** A safeguard is "backed" only while the system meets CIS's own figure (MFA,
  90 days of audit records, dormant accounts after 45 days and none still active, weekly log reviews); otherwise it is "related", saying what
  differs. The defaults are CIS's figures. ([User guide](USER_GUIDE.md#the-audit-portal-audit))
- **tzdata** is a requirement, so local times never vanish on a server without its own time-zone data.
- **Views of host-level data are logged** (Data access and exports): who, when and what, with hosts by reference,
  never their address. LG-15 backs CIS 3.14, Log Sensitive Data Access.
- **Nothing cut in the Executive report.** Every label and key finding is printed in full; findings that do not fit
  the first page continue on the next.
- **The story film**, *The devices that kept calling* (4:54), on the documentation site's home page and in the README.

## 2026-11-12 (night): local times, Executive figures by devices, every report on the Overview

- **Time zone (Settings > Country).** Shadowserver's times stay UTC for days, storage and totals, and each time is
  also shown in your zone, daylight saving included. For a UTC zone such as Ghana's nothing changes.
- **Executive portal ranked by devices.** Networks, regions, reports, services, sectors, infections and issues are
  ranked by distinct devices (IP addresses), records breaking ties. The filter menus hold every item of the day.
- **7-day baseline complete.** Each past day keeps every infection and issue, so "New this week" is never shown for an
  item seen all week. A missing item in an older summary counts as unknown, never as zero.
- **Devices are counted by IP address**, as the Executive page and its report say.
- **Every report on the Overview**, in as many columns as fit.
- **CIS wording kept exact (Audit portal and report).** CIS's safeguards appear as CIS publishes them. Beside each, a
  badge marked as ours gives Looking Glass's own conservative reading: backed, related, or not backed with the reason
  (LG-10 → 3.11 encryption at rest, LG-15 → DNS, URL, command-line and service provider logs, LG-01 → 6.4 VPN MFA).
  The CIS Controls are a voluntary map, not a law or a certificate.

## 2026-11-12 (evening): uninstaller

- **`./uninstall.sh`** undoes what `./install.sh` set up: the service, the pipeline's schedule and the `shadowserver`
  command. It removes only what belongs to its own folder, keeps the database and files unless asked, and confirms
  each removal. `--dry-run` shows the plan. Details: docs/INSTALLATION.md, Uninstalling.

## 2026-11-12 (later): security fixes

- **Settings → Workers:** request files cannot forge a server confirmation (no symlinks followed, results built from a
  fixed list of fields). Each change is judged by what its value means to the pipeline.
- **Sender check (DKIM):** headers that can be read two ways are not trusted, and a pass needs a signed From in the
  signer's domain. Block mode fails closed. Report e-mails are keyed by the mailbox's own message number, not the
  sender's Message-ID. Link downloads stop at the unzip size limit.
- **Advisories:** chosen by the organisation's network numbers (ASNs), never widened to everyone. A closed finding's
  advisories cannot be changed or sent; regenerating a drafted report puts it back to draft.
- **Masking:** one address finder serves every masker, so unusual spellings of an address are masked everywhere.
  Lasting codes for patterns on fewer than 5 hosts are held back.
- **Audit log:** the portal and the auditor's verifier are one implementation; deleting or rewriting side files does
  not let a change pass. ([How the audit log proves itself](AUDIT_LOG_PROOF.md))
- **Accounts and workflow:** the forgot-password form tells nothing before identity is proven. Recovery codes, the
  authenticator and expired-password steps, restore and command-line account creation are hardened too. A review
  closed by hand is withdrawn instead of blocking the analyst.
- **Load:** cache keys ignore unknown parameters, CISA KEV backs off after a failure, look-ups keep their time budget,
  Executive baselines are bounded, and a constituency change wins over a day load already running.

## 2026-11-12: audit evidence (NIST and CIS), report intake checks, the pipeline from Settings, password expiry

Evidence an auditor can check without trusting Looking Glass, and reports that are checked before they are loaded.

- **LG → NIST → CIS.** Each control check (LG-01 to LG-15) names the NIST SP 800-53 Rev. 5 controls it supports and,
  through CIS's official mapping, the CIS v8.1 safeguards with CIS's relationship (equivalent, subset, superset).
  Evidence only: the conclusion is the auditor's. ([User guide](USER_GUIDE.md#the-audit-portal-audit))
- **The audit log as CSV in the proof package**, numbered as in the chain; the verifier reports a changed CSV.
  ([How the audit log proves itself](AUDIT_LOG_PROOF.md))
- **Sender check (DKIM).** Each report e-mail's signature is checked against Shadowserver's key in DNS: record only, or
  hold back what fails until an administrator releases it. The mail server's certificate is checked by default
  (`IMAP_VERIFY_TLS=true`).
- **Reports straight from Shadowserver's API**, as an alternative to the mailbox. If the chosen way fails on a run, the
  other is used and the log says why.
- **Settings → Workers:** the pipeline's settings from the web app, behind the administrator's own password. Changes
  are requests the pipeline checks and applies at its next run; a less strict one also needs `./confirm_request.sh` on
  the server. ([User guide](USER_GUIDE.md#workers-the-database-pipeline))
- **Password expiry (optional, off by default).** ([User guide](USER_GUIDE.md#password-policy))
- **The constituency from the network list:** each network has a *Constituent* tick box.
- The web app runs hardened (read-only system, only its own `data/` writable). Services figures and replay counts are
  cached per view, with masking in every cache key. An advisory saved in two tabs is
  refused, not overwritten. Only pending accounts can be approved.

## 2026-11-11: advisories, cases, an Overview for every role, the Audit portal

From a finding to the organisation that can act on it, with a name on every hand-over.

- **The advisor role and advisories.** One advisory per organisation (network). The advisor writes the description
  and the actions, chooses the TLP and generates the report; Looking Glass adds the insights and technical details. It
  is signed by the CSIRT, never a person, and carries no internal codes or notes.
  ([User guide](USER_GUIDE.md#advisories-the-advisor))
- **TLP 2.0**, chosen per advisory (TLP:AMBER unless the advisor chooses) and printed on every page.
  ([User guide](USER_GUIDE.md#tlp-how-far-an-advisory-may-travel))
- **Cases and sub-findings.** Several networks open a case with one sub-finding per organisation, each decided on its
  own. Management approves to a named advisor or rejects with a reason. A sub-finding closes when its advisory is
  marked as sent, and the case when every sub-finding is closed.
  ([User guide](USER_GUIDE.md#findings-cases-and-who-holds-them))
- **Case → finding → sub-findings in one card.** A researcher's finding tops its case, with the analyst's requests and
  their organisations inside. Each keeps its own state and channel. The Findings page folds at every level, with state
  pills that name who holds each one.
- **Findings pages keep up on their own**, within about 15 seconds, and never redraw while you type.
- **The role an administrator played** is named on each step (*Administrator acting as Researcher/TI* (researcher or threat intelligence analyst), and so on).
- **The advisor's dashboard**, **notifications** (a bell on every role's pages) and **loading animations** on every
  page and tab that loads data.
- **An Overview for every role**: a greeting by first name and *Your pages* for that role. Log out is always last in
  the header.
- **Peace of mind** for administrators: Admin, Audit, Settings and the Overview only, with no findings notifications.
- **The Audit portal** (`/audit`): the audit log and the sessions. An auditor reads the sessions but only `users` can
  end one.

## 2026-11-10: combination codes, the analyst's combination search and findings

The team's workflow, end to end: a researcher names the exact combination, management weighs it against the trends,
an analyst pulls exactly those devices and sends them to management for the advisory, and an advisor writes it.

- **Combination codes.** `LG-C-…` for one report, `LG-X-…` for a cross-report pattern. A code carries no address, so it
  can be passed on safely. ([User guide](USER_GUIDE.md#combination-codes-the-combination-search-and-findings))
- **A Notes window of its own**, with its own **Notes** button on every row. Codes in a note are picked, built from
  real indicators or pasted and checked, never typed by hand.
- **The analyst's combination search** (`/combinations`): paste a code, search the days in memory or up to 31 days of
  history, and download a ZIP with a PDF and two CSV files. A finished search survives a service restart for an hour.
  Off in Demo mode; every search is in the audit log.
- **Findings** (`/findings`). A note can be tracked as a finding with a number and a status (*With
  management → Back with the researcher → With the analyst → With the advisor → Closed*). Each move records who, when
  and a comment. Each person sees only the findings they take part in, and never an address.
- **Analyst codes (LG-A) and replies.** An analyst turns any analysis selection into an analyst code and a finding.
  Researchers open it at `/intel/LG-A-…`, never seeing an address, and reply on the finding with codes.
- **A report per network provider** (**Report for** on the Combinations page): the PDF + CSV for one operator only.
- **Show in Executive** opens the Executive portal filtered to a finding's combination, counts only.
- **Definitions tables** sort by any column, and **Across reports** flags names whose devices turn up in more than one
  of their reports.
- **Network names stay editable**, also after review; the empty review queue offers *Show every network*.
- **Day change:** loading a new day does not hold up the pages.

## 2026-11-09: researchers' intel, notes and a page of their own

- **Intel gathered.** For every infection and issue, what the reports carry for it (C2 domains, DNS lookups, URLs,
  user agents, CVEs, tags, products and more), with records, share and hosts. Indicators only: hosts are never shown.
  ([User guide](USER_GUIDE.md#5-analysis-and-follow-up), [Technical reference](TECHNICAL_REFERENCE.md#researchers-intel-notes-and-where-a-name-was-seen))
- **Combinations and repeating hosts**, and **Across reports** for a name seen in several reports.
- **Looking Glass asks: can you look into this?** The same indicator under two names, in two reports or on both
  platforms. Values common to everything are never raised.
- **Researchers' notes**: dated and signed, kept apart from the definitions, printed in the PDF reports.
- **Seen in, as report cards**, and **Last seen in *report* on *date*** for names not in today's reports.
- **Adding people**: sign-up on the sign-in page or a one-time link from Admin; the person sets their own password and
  authenticator.
- **A guided installer that lets you go back**, explains its choices and waits for Ubuntu's updates instead of failing.
- **Nothing to recognise from the outside.** Signed out, the pages name no product, framework or library version.
  ([Installation, Updating](INSTALLATION.md#updating))
- **A guided tour on every page**, offered on the first visit. ([User guide](USER_GUIDE.md#the-guided-tour))
- **Every copy recorded, every copy and download sealed, Trace a leak.** Copying works only through the copy buttons;
  a copy not recorded is not made. Auditors can trace a copy or file found outside back to who made it, and when.
  ([User guide](USER_GUIDE.md#everything-is-recorded-under-your-name))
- **The severity map**: each infection and issue with its criticality and source. Researchers rate only what no
  record rates, and Shadowserver's ratings are never changed. ([User guide](USER_GUIDE.md#5-analysis-and-follow-up))
- **The Definitions page stands on its own** (`/definitions`).
- **Full names** for people in definitions, notes, network corrections, reports and the audit log.
- **A checked knowledge base.** Every infection carries evidence. Sinkhole DNS entries explain that the address is
  usually a resolver. Shipped entries are signed *Looking Glass*.
- **Documentation in one place**: every guide is in `docs/`.

## 2026-11-09: security fixes

- **Safe CSV exports:** no cell can run as a spreadsheet formula.
- **Masked views accept only aliases**, so a viewer cannot find out whether a network is in the data.
- **Pinned events** belong to the signed-in account and are deleted at log-out.
- **Release builds** are publishable only after a clean scan, with images and PDFs scanned for hidden metadata, curated data
  checked to reach the repository, and documentation links checked.

([SECURITY.md](SECURITY.md#5-supported-versions-and-changes))

## 2026-11-09: faster platforms and a sharper Executive portal

- **Shared results:** figures are computed once for everyone viewing the same day and filters; new reports still
  appear as soon as they arrive.
- **Executive portal:** clickable "Top findings" combinations that filter the whole portal, and full vulnerability
  names.
- **Event stream:** clear messages while a report waits for its replay time.

## 2026-11-08: Executive portal, 7-day baseline, vulnerabilities and network types

- **Executive portal** for the management role: aggregated figures only, never an address, with executive PDF reports.
- **7-day baseline:** every figure compared with its own average over the previous 7 days, graded on a stated scale.
- **Vulnerabilities explained in batches** (CISA KEV, EPSS, CVE.org, NVD); reports as a ZIP of PDF plus CSV.
- **Network names and types** for researchers, with types (sectors) a site can add.
- **Licence:** GNU AGPL-3.0.

## 2026-11-07: definitions, the researcher role and PDF reports

- **Definitions** with references for names Malpedia does not know, and the **Researcher/TI** role that writes them.
- **PDF reports** on every list behind an analysis figure.
