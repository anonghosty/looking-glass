# For reviewers

This page is for anyone assessing Looking Glass: a security reviewer, an auditor, a partner CSIRT, or an AI tool asked
for its view of the project. It says what the project is and is not, how it is built, where its trust boundaries are
and how a release is checked, with a link to the detailed page for each.

---

## 1. What it is

Looking Glass is a free, open-source (AGPL-3.0) platform for **national CSIRTs** that receive the
[Shadowserver Foundation](https://www.shadowserver.org/what-we-do/network-reporting/)'s free daily reports. Those
reports arrive as many e-mails and CSV files a day, each report type with its own columns. Looking Glass loads them
and gives the team:

- **a replayed picture of the country:** yesterday's reports shown at the time of day they happened, on a map, with
  filters, statistics and drill-downs;
- **analysis:** hosts to follow up, patterns shared by many devices, combinations of issues, decoded beacons in HTTP
  requests;
- **follow-up:** findings handed from person to person (analyst, management, advisor), each hand-over naming who
  holds it next;
- **advisories:** one per affected organisation, with its TLP, written and sent by an advisor;
- **an audit trail:** a tamper-evident log an auditor can check on their own computer.

## 2. What it is not

| It is not | Because |
|---|---|
| A scanner | It never connects to a constituent's device. Everything it shows comes from Shadowserver's reports. |
| A SIEM or an IDS | It reads only Shadowserver's reports, not the CSIRT's own logs or traffic. |
| A mailer | Advisories are written and sent by people. Looking Glass makes the document and records that it was sent. |
| A data broker | No constituent address is sent to any outside service. Look-ups send only what each service needs (an AS number, a CVE ID, a malware name or hash, a place name). |
| A replacement for IntelMQ or Elastic | It does one job end to end for Shadowserver reports. See [Comparison](COMPARISON.md). |

## 3. How it is built

Two programs share one MongoDB database. By default all of it runs on one server.

| Part | Job | Its access |
|---|---|---|
| **Pipeline** (`database/`) | Fetches the reports (Shadowserver's report API or a mailbox), checks each e-mail's sender signature (DKIM), unzips within limits and loads one document per CSV row | Its own database account; runs on a schedule |
| **MongoDB** | Holds the reports | Bound to 127.0.0.1, or an internal server over TLS; never a public address |
| **Platform** (`platform/`) | The web app: map, services, analysis, findings, Executive portal, advisories, Audit portal | A sandboxed systemd service; a **read-only** database account; writes only its own `data/` folder |
| **Browser** | Shows the pages | All report data is inserted as text, under a strict Content-Security-Policy |

The full picture, with the data flow from a report to an advisory: [Architecture, sections 1 and 2](ARCHITECTURE.md#1-the-parts).

## 4. Who sees what

Every person has one role. Permissions are checked on the server, and the **masking is done on the server**, so a
hidden value never reaches the browser.

| Role | Sees |
|---|---|
| Analyst | Everything, with addresses |
| Researcher | The threat data, with every constituent address and host name masked; patterns carried by fewer than 5 devices get no lasting code |
| Management | Aggregates and C2 / sinkhole domains, never a constituent address |
| Advisor | The findings sent to them, to write advisories |
| Auditor | Only the audit log and its evidence, never host data |
| External | Everything masked |
| Admin | Everything, plus settings and accounts |

People talk about a selection without passing addresses around: a code stands for it (`LG-A-…` an analyst's
selection, `LG-C-…` a combination, `LG-B-…` decoded beacons), and the person opening it sees what their role allows.

## 5. Trust boundaries and threats

[Architecture and threat model, sections 3 to 6](ARCHITECTURE.md#3-trust-boundaries) names each boundary (internet to
pipeline, pipeline to database, database to platform, network to platform, user to data, platform to pipeline, outside
look-ups, the auditor, the decoding requests), what crosses it and what is checked there. It then lists what an
attacker would want, five kinds of attacker and what stops each, and the risks that remain.

Two boundaries reviewers often ask about:

- **The web app cannot weaken the pipeline.** A settings change that would make the intake less strict also needs
  someone to confirm it on the server.
- **Nothing goes out by itself.** A request that Looking Glass could not decode goes to its creator only after an
  administrator approves it, by hand, through a private report, holding only the request lines with every other value
  masked and the path reduced to its shape (a machine name, e-mail address or address in the path never leaves).

## 6. How a release is checked

Every release goes through the same steps before it is published:

1. **The full test suite** (over a hundred checks: privacy per role, CSRF on every write route, masking, caches,
   findings, the pipeline) on a test installation with made-up data.
2. **The same checks GitHub runs:** unit tests without a database, the database tests, a dependency audit and static
   analysis (Bandit, CodeQL).
3. **The installation's own security check** (`platform/security_testing/security_retest.py`) and a resource check.
4. **A scan of what is published:** no secret, key or private term may be in the code or the documents.
5. **A signed commit and a signed tag**, with the release notes on GitHub. How to check a signature yourself:
   [Checking a release's signature](INSTALLATION.md#checking-a-releases-signature).
6. **After publishing:** GitHub's checks must pass, and an **AI-assisted security review** of the release's changes
   is read. It is a second pair of eyes, not a verdict: every point it raises is checked against the code and,
   when it holds, fixed in the next release.

The project's [OpenSSF Best Practices](https://www.bestpractices.dev/projects/16699) entry records the practices it
follows.

## 7. Where to go next

| To check | Read |
|---|---|
| Each security control in detail | [Security](SECURITY.md) |
| How the audit log proves it was not changed | [How the audit log proves itself](AUDIT_LOG_PROOF.md) |
| Every setting | [Configuration](CONFIGURATION.md) |
| Every screen and button | [User guide](USER_GUIDE.md) |
| The code, module by module | [Technical reference](TECHNICAL_REFERENCE.md) |
| How decisions are made | [Governance](GOVERNANCE.md) |
| What changed, release by release | [Changelog](../CHANGELOG.md) |

**Reporting a problem:** a vulnerability privately, through GitHub's
[Report a vulnerability](https://github.com/anonghosty/looking-glass/security/advisories/new)
([Security, section 6](SECURITY.md#6-reporting-a-vulnerability)); anything else as a GitHub issue.
