# Looking Glass, IntelMQ and the Elastic Stack

An honest comparison of the free tools a CSIRT can use with its [Shadowserver](https://www.shadowserver.org/what-we-do/network-reporting/)
reports, why Looking Glass exists, and how the tools work **together**. Every figure below has its source linked.

## Contents

- [The problem](#the-problem)
- [The tools today](#the-tools-today)
- [Side by side](#side-by-side)
- [Why it matters for Africa](#why-it-matters-for-africa)
- [Using them together](#using-them-together)
- [Sources](#sources)

## The problem

The Shadowserver Foundation sends free daily reports to national CSIRTs and network owners: **201 national CSIRTs
covering 176 countries** ([Shadowserver, 2024 year in review][ss-2024]), in **more than 80 report types**
([Shadowserver report overview][ss-overview]). Each report runs every morning for the previous 24 hours.

That is an excellent service, and a heavy one to use by hand:

- **Volume.** A national CSIRT's mailbox can receive **well over a hundred report e-mails a day**, holding
  **tens of thousands of rows** across dozens of report types.
- **Many shapes.** Every report type has its own columns ([Shadowserver report schemas][ss-schema]).
- **Formats change.** Shadowserver has modified and extended report formats over time and acknowledged that this
  can confuse recipients ([Shadowserver, 2021 report restructuring notice][ss-2021]); parsers have to follow
  ([IntelMQ mailing list][imq-schema]).
- **No picture.** A ZIP of CSV files does not show what is happening in the country, where, or what to fix first.

## The tools today

### IntelMQ

A free, open-source solution from CERT.at and the CSIRT community for collecting and processing security feeds
([docs.intelmq.org][imq-docs]). It works as a pipeline of *bots*: **collectors** (mailbox, API) → **parsers**
(including Shadowserver CSV and JSON) → **experts** (enrichment, contact look-up) → **outputs** (files, databases,
e-mail). Around it: IntelMQ Manager (web interface), certbund-contact and Mailgen (route events to the right contact
and e-mail them, PGP-signed), Fody (contacts and sent tickets) and Tuency (constituency portal) ([IntelMQ universe][imq-universe]).

| Strengths | What it needs |
|---|---|
| Free, open source, mature; used by many national CERTs | **Resources**: a Linux server and several services to run and keep updated (Redis message queue, databases, bots) — minimum 4 GB RAM, 2 CPUs, 10 GB disk plus data ([hardware requirements][imq-hw]) |
| Automates notifying the owners of affected hosts | Staff to configure the bots and apply Shadowserver format updates |
| Handles many feeds, not only Shadowserver | Another tool to visualise the results (it moves and routes data; it is not a dashboard) |

### Elastic Stack (Elasticsearch, Kibana, Logstash)

A search and analytics platform. It has a **free self-managed tier**: Elastic says you can download it and use the
free features at no cost, and that the security features built into the stack are free ([Elastic pricing FAQ][es-faq]).
Since August 2024 the source is also available under the open-source AGPL licence ([Elastic announcement][es-agpl]).
Shadowserver publishes a script that loads its reports into Elasticsearch ([Shadowserver api_utils][ss-es]).

| Strengths | What it needs |
|---|---|
| Free self-managed tier, security features included | **Resources**: memory-hungry nodes (a common rule of thumb is 8 GB RAM and 4 cores per production node, [Opster][es-size]), storage, and a cluster to run, secure and upgrade |
| Very fast search across all reports and any other data | Every Shadowserver dashboard designed in Kibana and kept up to date by the team (each report has its own fields) |
| Scales to very large volumes; any visualisation you can build | Specialist skills to tune and maintain it |

### Shadowserver Dashboard

Shadowserver's public dashboard shows up to two years of **aggregated, country-level** statistics, with nothing to
install ([dashboard][ss-dash]). It is ideal for the big picture and for sharing; it does not show your constituency's
individual hosts or let you follow them up.

### Looking Glass

Free and open source (AGPL-3.0), built for one job: turning a CSIRT's own Shadowserver reports into a picture people can use.

| Strengths | Limits (honestly) |
|---|---|
| Ready-made views of every Shadowserver report: a live map, the services platform, analysis, host lists, PDF and CSV reports | Shadowserver reports only — not a general feed or log platform |
| Useful straight after the guided installer: mailbox, database, platform, accounts | Replays the previous day (as Shadowserver delivers it); not real-time ingestion of other feeds |
| Modest resources: about 2 GB RAM for the platform, one server ([installation guide](INSTALLATION.md)) | Does not e-mail constituents automatically (IntelMQ does) |
| Executive portal and reports with aggregates only; masked views for partners and public screens | No free-text search across arbitrary data (Elasticsearch does) |
| Secure by default: MFA for everyone, roles, audit log, penetration-tested | A young project: one maintainer team, single-server design |

## Side by side

| | IntelMQ | Elastic Stack | **Looking Glass** |
|---|:---:|:---:|:---:|
| Free to use | ✅ | ✅ | ✅ |
| Ready-made views of Shadowserver data | — | ◐ build them | ✅ |
| Useful straight after installing | ◐ configure bots | ◐ build dashboards | ✅ |
| Executive reports and dashboard | — | ◐ build them | ✅ |
| Automatic notification of constituents | ✅ | — | — |
| Many feeds besides Shadowserver | ✅ | ✅ | — |
| Search across any data, at scale | — | ✅ | — |

✅ built in · ◐ partly, or with work · — not its job

## Why it matters for Africa

The tools are free. **The resources to run them are not**: servers, storage, skilled staff and time.

- About **59 % of African states have a national CSIRT** ([UNIDIR policy brief, 2025][unidir]); many are young teams.
- Africa's cybersecurity workforce shortage is estimated at about **23 %** (BCG and the Global Cybersecurity Forum,
  2024, reported by [African Arguments][aa]).
- INTERPOL's 2025 assessment finds **capacity gaps are widespread** and threats are outpacing response capacity
  ([INTERPOL Africa Cyberthreat Assessment 2025][interpol]).

Looking Glass is built for that reality: one modest server, a guided installer that checks every answer, and views
that are useful on day one, so a small team can see and act on its Shadowserver reports while it grows into
IntelMQ and Elastic.

## Using them together

| | Job |
|---|---|
| **IntelMQ** | notifies the owners of affected hosts, across many feeds |
| **Elastic Stack** | searches everything you keep, for investigations and hunting |
| **Looking Glass** | shows the picture: what is happening in the country, where, and what to fix first — for analysts and executives |

Looking Glass reads the reports from the mailbox (or a MongoDB you already have) and changes nothing upstream, so it
runs happily next to an existing IntelMQ or Elastic set-up.

## Sources

Checked in November 2026.

[ss-2024]: https://www.shadowserver.org/news/shadowserver-2024-highlights-of-the-year-in-review/
[ss-overview]: https://www.shadowserver.org/wp-content/uploads/2022/06/Overview_of_Shadowserver_Reports_March_2022.pdf
[ss-schema]: https://github.com/The-Shadowserver-Foundation/report_schema
[ss-2021]: https://www.shadowserver.org/hp-rewrite/d1e0210d9617036984b6d00c24aff269
[imq-schema]: https://lists.cert.at/mailman3/hyperkitty/list/intelmq-users@lists.cert.at/thread/MWY3375RGHAGJLAMZ5AUWOG2VU7IT3Q5/
[imq-docs]: https://docs.intelmq.org/latest/admin/intro/
[imq-universe]: https://intelmq.readthedocs.io/en/latest/user/universe.html
[imq-hw]: https://intelmq.readthedocs.io/en/latest/user/hardware-requirements.html
[es-faq]: https://www.elastic.co/pricing/faq
[es-agpl]: https://www.businesswire.com/news/home/20240829537786/en
[ss-es]: https://github.com/The-Shadowserver-Foundation/api_utils/tree/main/elasticsearch
[es-size]: https://opster.com/faq/elasticsearch-minimum-requirements
[ss-dash]: https://www.shadowserver.org/statistics/
[unidir]: https://unidir.org/wp-content/uploads/2025/12/UNIDIR_Strengthening_National_CSIRT_Cooperation_Domestic_Setups_International_Networks.pdf
[aa]: https://africanarguments.org/2026/10/cybersecurity-is-the-infrastructure-africa-is-forgetting-to-build/
[interpol]: https://www.interpol.int/content/download/23094/file/INTERPOL_Africa_Cyberthreat_Assessment_Report_2025.pdf

- Shadowserver, *2024: highlights of the year in review* — [link][ss-2024]
- Shadowserver, *Overview of free public benefit network security reports* — [link][ss-overview]
- Shadowserver, report schemas — [link][ss-schema]; 2021 report restructuring notice — [link][ss-2021]; public dashboard — [link][ss-dash]; Elasticsearch loader — [link][ss-es]
- IntelMQ documentation: introduction — [link][imq-docs]; the IntelMQ universe — [link][imq-universe]; hardware requirements — [link][imq-hw]; schema update thread — [link][imq-schema]
- Elastic, pricing FAQ — [link][es-faq]; AGPL announcement — [link][es-agpl]; Opster, Elasticsearch minimum requirements — [link][es-size]
- UNIDIR, *Strengthening national CSIRT cooperation* (2025) — [link][unidir]
- African Arguments, *Cybersecurity is the infrastructure Africa is forgetting to build* (2026) — [link][aa]
- INTERPOL, *Africa Cyberthreat Assessment Report 2025* — [link][interpol]
