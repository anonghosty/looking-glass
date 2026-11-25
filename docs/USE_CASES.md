# Use case scenarios: a needle through the haystack

How a CSIRT team uses Looking Glass to turn a day of Shadowserver reports into a few advisories that a network operator
can act on, instead of forwarding a spreadsheet of thousands of addresses.

> All figures and network names on this page come from the **demonstration data** shipped with Looking Glass (fictional
> networks, documentation address ranges, real public CVEs). Your own figures will differ.

**Watch first:** the three stories on this page, told on screen in 11 minutes, narrated, with captions.

[![Watch the use case scenarios (11:24) on YouTube](media/films/use-cases.jpg)](https://www.youtube.com/watch?v=TyIG8su7vNQ) <!-- film: use-cases -->

## Contents

1. [The problem: a full dump is not an advisory](#1-the-problem-a-full-dump-is-not-an-advisory)
2. [The approach: most probable first, then the next](#2-the-approach-most-probable-first-then-the-next)
3. [Who does what](#3-who-does-what)
4. [Scenario one: the researcher finds the needle](#4-scenario-one-the-researcher-finds-the-needle)
5. [Scenario two: the analyst asks first](#5-scenario-two-the-analyst-asks-first)
6. [The next days: watching the numbers fall](#6-the-next-days-watching-the-numbers-fall)
7. [Writing the advisory](#7-writing-the-advisory)
8. [Checklists](#8-checklists)
9. [The codes at a glance](#9-the-codes-at-a-glance)

---

## 1. The problem: a full dump is not an advisory

One day of Shadowserver reports for a country is large. In the demonstration data, the publicly accessible services
alone are **tens of thousands of records on well over ten thousand hosts, in dozens of networks**; the sinkholes and
honeypots add tens of thousands of events more.

The usual reflex is to export each operator's share and send it: one network alone has **thousands of affected
addresses**.
The engineer who receives that file has no way to tell which ten addresses are tomorrow's ransomware incident and
which eight thousand are old, low-risk exposure. The file sits in a mailbox; nothing is fixed; next week another file
arrives. The constituency learns to ignore CSIRT mail.

**The cost of a dump**

| What the operator receives | What happens |
|---|---|
| Thousands of addresses, every report type mixed | No starting point, so no start |
| No explanation of what each finding means | The risk is not understood, so it is not prioritised |
| The same addresses again next week | The CSIRT's mail is filtered out |
| No way to see progress | Nobody knows whether anything improved |

## 2. The approach: most probable first, then the next

Looking Glass narrows the haystack in steps, each one dropping the numbers, until what is left is a short list the
operator can act on today:

```mermaid
%%{init: {"flowchart": {"curve": "basis", "nodeSpacing": 30, "rankSpacing": 34, "padding": 12}}}%%
flowchart TD
    A["<b>tens of thousands of records</b><br/>well over ten thousand hosts · the day's services reports"]:::wide
    B["<b>over a thousand hosts</b><br/>with a concrete issue"]:::step
    C["<b>82 hosts</b><br/>an actively exploited vulnerability (CISA KEV)"]:::step
    D["<b>46 hosts</b><br/>CVE-2025-22224 (VMware ESXi)"]:::step
    E["<b>42 hosts</b><br/>seen by two different reports"]:::step
    F["<b>21 hosts</b><br/>exactly the same five CVEs on end-of-life ESXi · code LG-C-1F7E2005"]:::step
    G(["<b>14 hosts at one operator</b><br/>one advisory, one PDF, one CSV"]):::goal
    A --> B --> C --> D --> E --> F --> G
    classDef wide fill:#475569,stroke:#334155,color:#fff
    classDef step fill:#4f46e5,stroke:#4338ca,color:#fff
    classDef goal fill:#0f766e,stroke:#115e59,color:#fff
    linkStyle default stroke:#94a3b8,stroke-width:2px
```

The signals that make a finding *probable* rather than noise:

| Signal | Where Looking Glass shows it | Why it matters |
|---|---|---|
| **Actively exploited** (CISA KEV), high CVSS, high EPSS | badges on every CVE; Definitions table; Executive | attackers are using it now |
| **Across reports** (⇄) | the Definitions tables' *Across reports* column; Intel gathered's *Across reports* view | two independent sensors see the same device: not a one-off |
| **Exact combinations** | Intel gathered's *Combinations* (with codes) | the same set of flaws or indicators on many devices is a pattern: one campaign, one product line, one fix |
| **Repeating devices** (↻) | combinations and values | a device that keeps carrying the set is not a scanning artefact |
| **Severity and peak hour** | the analysis windows, the Executive portal | what is critical, and when it is active |
| **Trend** (7-day baseline) | the Executive portal | rising problems first; a falling one shows the advisories work |

Handle the top of the list first. Next day, the next one. Each advisory is small, explained, and specific to one
operator, so it gets done, and the next day's numbers show it.

## 3. Who does what

| Role | Sees | Does |
|---|---|---|
| **Researcher** | names, definitions, indicators, combinations; **never an address** | finds patterns, writes notes, makes combination codes (LG-C, LG-X), tracks a note as a finding, answers analysts |
| **Analyst** | everything, with addresses | makes analyst codes (LG-A), pulls exactly the devices behind a code, sends the report to management for the advisory |
| **Management** | aggregated figures, trends, regions; **never an address** | weighs a finding against the trends, decides, names who takes it next |
| **Advisor** | the findings management approved for them, and their organisations | writes each organisation's advisory, generates the PDF, marks it as sent |

They meet on the **Findings** page (`/findings`). Every finding has a number, a status (*With management, Back with
the researcher, With the analyst, With the advisor, Closed*) and a history of every move and reply. Each hand-over
names the person it goes to, and only the people in a finding see it. The e-mails between them can stay; the state
lives in one place.

### The codes, and where they go

```mermaid
%%{init: {"flowchart": {"curve": "basis", "nodeSpacing": 38, "rankSpacing": 48, "padding": 14}}}%%
flowchart LR
    subgraph MADE["The codes · none carries an address"]
        direction TB
        CC["<b>LG-C</b> · one exact combination in one report<br/>researcher · Intel gathered"]:::research
        CX["<b>LG-X</b> · a pattern across several reports<br/>researcher · Intel gathered"]:::research
        CB["<b>LG-B</b> · decoded beacons that share a part<br/>researcher or analyst · under 5 devices, analysts only"]:::research
        CA["<b>LG-A</b> · exactly an analyst's selection, one day<br/>analyst · an analysis window"]:::analyst
    end
    N["<b>A note</b><br/>Track as a finding"]:::research
    F(["<b>The finding</b><br/>carries the codes"]):::mgmt
    E["<b>Show in Executive</b><br/>management · the figures behind a code"]:::mgmt
    S["<b>Search</b> on Combinations<br/>analyst · exactly the devices behind a code"]:::analyst
    R["<b>The review</b><br/>management decides the report's views"]:::mgmt
    P["<b>The advisory report</b><br/>PDF + CSV · one organisation's devices only"]:::advisor
    O(["<b>The organisation</b><br/>where it ends"]):::ext
    CC --> N
    CX --> N
    CB --> N
    CA -- "Make analyst code" --> F
    CC -. "or in a reply to an LG-A" .-> F
    N --> F
    F --> E
    F --> S
    S -- "Send to management" --> R
    R -- "an advisor named" --> P
    P -- "Mark as sent" --> O
    classDef research fill:#0369a1,stroke:#075985,color:#fff
    classDef analyst fill:#4f46e5,stroke:#4338ca,color:#fff
    classDef mgmt fill:#6d28d9,stroke:#5b21b6,color:#fff
    classDef advisor fill:#be185d,stroke:#9d174d,color:#fff
    classDef closed fill:#475569,stroke:#334155,color:#fff
    classDef ext fill:#b45309,stroke:#92400e,color:#fff
    linkStyle default stroke:#94a3b8,stroke-width:2px
    style MADE fill:transparent,stroke:#64748b,stroke-width:1.5px,stroke-dasharray:6 4,color:#64748b
```

A code names exactly a set of records and never an address, so researchers and management can pass it on; only the
analyst's **Search** turns it into devices, and only the advisory report sends devices out, to their own organisation.

### The life of a finding

```mermaid
%%{init: {"flowchart": {"curve": "basis", "nodeSpacing": 38, "rankSpacing": 48, "padding": 14}}}%%
flowchart LR
    RN(["<b>Researcher</b><br/>Track as a finding"]):::research
    AN(["<b>Analyst</b><br/>Make analyst code"]):::analyst
    M["<b>With management</b>"]:::mgmt
    R["<b>Back with the researcher</b>"]:::research
    A["<b>With the analyst</b>"]:::analyst
    V["<b>With the advisor</b>"]:::advisor
    O(["<b>The organisation</b><br/>its advisory"]):::ext
    C(["<b>Closed</b>"]):::closed
    T(["time to act runs out<br/>30 days after its devices were last seen"]):::closed
    RN -- "names a manager · LG-C, LG-X, LG-B" --> M
    AN -- "names a researcher · LG-A" --> R
    R -- "Reply to the analyst · LG-C, LG-X" --> A
    R -- "No combination of interest" --> C
    M -- "Decide: approve, names an analyst" --> A
    M -- "Decide: reject, with the reason" --> C
    A -- "Send to management, the ticked views or for the advisory" --> M
    M -- "decides the report's views, names an advisor" --> V
    V -- "Mark as sent" --> O
    O -- "every organisation's advisory sent" --> C
    T -. "Looking Glass closes it" .-> C
    classDef research fill:#0369a1,stroke:#075985,color:#fff
    classDef analyst fill:#4f46e5,stroke:#4338ca,color:#fff
    classDef mgmt fill:#6d28d9,stroke:#5b21b6,color:#fff
    classDef advisor fill:#be185d,stroke:#9d174d,color:#fff
    classDef closed fill:#475569,stroke:#334155,color:#fff
    classDef ext fill:#b45309,stroke:#92400e,color:#fff
    linkStyle default stroke:#94a3b8,stroke-width:2px
```

Management can also use **Move it on** to send any open finding to a manager, a researcher, an analyst or an advisor,
or close it. An administrator can do every role's work; the history shows which role they played.

### A researcher's view

```mermaid
%%{init: {"flowchart": {"curve": "basis", "nodeSpacing": 38, "rankSpacing": 48, "padding": 14}}}%%
flowchart TD
    S(["<b>Intel gathered</b> · Looking Glass asks<br/>names, definitions, indicators; never an address"]):::research
    N["<b>A note</b> with combination codes<br/>LG-C · LG-X · LG-B"]:::research
    T["<b>Track as a finding</b><br/>names a manager"]:::research
    M(["<b>With management</b>"]):::mgmt
    Q(["<b>An analyst's request</b><br/>Back with the researcher"]):::analyst
    O["<b>Open as researcher</b><br/>the intel of exactly those records"]:::research
    A(["<b>With the analyst</b><br/>the reply and its codes"]):::analyst
    C(["<b>Closed</b>"]):::closed
    S --> N --> T --> M
    Q --> O
    O -- "Reply to the analyst · LG-C, LG-X" --> A
    O -- "No combination of interest" --> C
    classDef research fill:#0369a1,stroke:#075985,color:#fff
    classDef analyst fill:#4f46e5,stroke:#4338ca,color:#fff
    classDef mgmt fill:#6d28d9,stroke:#5b21b6,color:#fff
    classDef advisor fill:#be185d,stroke:#9d174d,color:#fff
    classDef closed fill:#475569,stroke:#334155,color:#fff
    classDef ext fill:#b45309,stroke:#92400e,color:#fff
    linkStyle default stroke:#94a3b8,stroke-width:2px
```

### An analyst's view

```mermaid
%%{init: {"flowchart": {"curve": "basis", "nodeSpacing": 38, "rankSpacing": 48, "padding": 14}}}%%
flowchart TD
    W(["<b>The map or the services platform</b><br/>a selection of devices"]):::analyst
    K["<b>Make analyst code</b> · LG-A<br/>names a researcher"]:::analyst
    R(["<b>Back with the researcher</b>"]):::research
    D(["<b>With the analyst</b><br/>approved by management, with its directive"]):::mgmt
    Y(["<b>With the analyst</b><br/>the researcher's reply · LG-C, LG-X"]):::research
    S["<b>Search</b> on Combinations<br/>exactly the devices behind the code"]:::analyst
    V["<b>Tick the views</b> across reports<br/>drill down to what matters"]:::analyst
    G["<b>Send the ticked views to management</b><br/>or, with nothing ticked, Send to management for the advisory<br/>one organisation: a review · several: a case"]:::analyst
    M(["<b>With management</b>"]):::mgmt
    P(["<b>The advisory report</b><br/>exactly these devices, per organisation"]):::advisor
    W --> K --> R
    R -. "the researcher replies" .-> Y
    D -- "LG-C, LG-X or LG-B" --> S
    Y --> S
    S --> V --> G --> M
    M -. "approved: the advisor writes it" .-> P
    classDef research fill:#0369a1,stroke:#075985,color:#fff
    classDef analyst fill:#4f46e5,stroke:#4338ca,color:#fff
    classDef mgmt fill:#6d28d9,stroke:#5b21b6,color:#fff
    classDef advisor fill:#be185d,stroke:#9d174d,color:#fff
    classDef closed fill:#475569,stroke:#334155,color:#fff
    classDef ext fill:#b45309,stroke:#92400e,color:#fff
    linkStyle default stroke:#94a3b8,stroke-width:2px
```

Another way in: an analyst can ask management for analysis across reports on the devices of a code; it goes to the
manager they name.

### Management's view

```mermaid
%%{init: {"flowchart": {"curve": "basis", "nodeSpacing": 38, "rankSpacing": 48, "padding": 14}}}%%
flowchart TD
    I(["<b>With management</b><br/>a researcher's finding, or an analyst's request"]):::mgmt
    X["<b>Show in Executive</b><br/>the figures behind any of its codes, no addresses"]:::mgmt
    E{"<b>Decide</b>"}:::mgmt
    A(["<b>With the analyst</b><br/>the directive, an analyst named"]):::analyst
    C(["<b>Closed</b><br/>with the reason"]):::closed
    Q(["<b>A review or a case</b><br/>the analyst's report for the advisory"]):::analyst
    F{"<b>Decide the report's views</b><br/>each organisation of a case"}:::mgmt
    V(["<b>With the advisor</b><br/>an advisor named"]):::advisor
    I --> X --> E
    E -- "approve" --> A
    E -- "reject" --> C
    Q --> F
    F -- "the researcher's or the analyst's view" --> V
    F -- "reject" --> C
    classDef research fill:#0369a1,stroke:#075985,color:#fff
    classDef analyst fill:#4f46e5,stroke:#4338ca,color:#fff
    classDef mgmt fill:#6d28d9,stroke:#5b21b6,color:#fff
    classDef advisor fill:#be185d,stroke:#9d174d,color:#fff
    classDef closed fill:#475569,stroke:#334155,color:#fff
    classDef ext fill:#b45309,stroke:#92400e,color:#fff
    linkStyle default stroke:#94a3b8,stroke-width:2px
```

### An advisor's view

```mermaid
%%{init: {"flowchart": {"curve": "basis", "nodeSpacing": 38, "rankSpacing": 48, "padding": 14}}}%%
flowchart TD
    I(["<b>With the advisor</b><br/>only after management approved"]):::advisor
    W["<b>Write the advisory</b><br/>one per organisation, with its TLP"]:::advisor
    G["<b>Generate</b> the PDF<br/>after confirming it's you"]:::advisor
    S["<b>Mark as sent</b><br/>to its recipients"]:::advisor
    C(["<b>Closed</b><br/>once every organisation's advisory is sent"]):::closed
    O(["<b>The organisation</b><br/>fixes its devices"]):::ext
    I --> W --> G --> S --> C
    S -. "the advisory" .-> O
    classDef research fill:#0369a1,stroke:#075985,color:#fff
    classDef analyst fill:#4f46e5,stroke:#4338ca,color:#fff
    classDef mgmt fill:#6d28d9,stroke:#5b21b6,color:#fff
    classDef advisor fill:#be185d,stroke:#9d174d,color:#fff
    classDef closed fill:#475569,stroke:#334155,color:#fff
    classDef ext fill:#b45309,stroke:#92400e,color:#fff
    linkStyle default stroke:#94a3b8,stroke-width:2px
```

## 4. Scenario one: the researcher finds the needle

**1. Researcher: spot it.** On the **Definitions** page, sort the issues by **Hosts** (click the heading: ▲ ▼).
*Exposed admin panel* tops the list with thousands of records: real, but broad. Sort by **Across reports** instead:
**CVE-2025-22224** carries the ⇄ flag (42 hosts in two reports) and the badges *Actively exploited · CISA KEV*.

**2. Researcher: look closer.** **Intel gathered** on CVE-2025-22224 shows the combinations: 21 hosts carry exactly
*CVE-2024-22252 + CVE-2024-37085 + CVE-2025-41236 + CVE-2025-41237 + CVE-2025-41238 + end-of-life VMware ESXi*, 12 of
them in more than one record; the *Across reports* view shows 19 hosts with the same set in both reports
(`LG-X-C5CDB416`). Five flaws on unsupported hypervisors: one door to every server behind it.

**3. Researcher: write it down.** Open **Notes** on the row. In *Combinations for this note*, pick the combination
from *Seen in the reports* (nothing to type, so no typos): `LG-C-1F7E2005`. Write what it means, tick **Track as a
finding**, give it a title (*Exploited ESXi hypervisors, end of life*), and name the manager it goes to. It becomes
**Finding #1**, *With management*.

**4. Management: weigh it.** On the Findings page, **Show in Executive**: the portal filters itself to the code:
21 hosts, Nairobi and Mombasa, the networks, the severity. Management uses **Decide**: approve, with the directive
(*Prioritise: ransomware exposure*), and names the analyst. It is now *With the analyst*.

**5. Analyst: pull the devices.** **Search** on the finding opens the **Combinations** page with the code: the
devices, records, the region map (hover a region for its addresses), networks, ports, the busiest hosts. In
**Report for**, choose the operator with most of them: **Tsavo Wireless, 14 hosts**. Download the PDF + CSV.

**6. Analyst: send it for the advisory.** Tick the views that matter and **Send the ticked views to management**: a
review of exactly those 14 hosts.

**7. Management: decide the report.** On the review, keep the analyst's view and name an advisor. It is now *With the
advisor*.

**8. Advisor: write and send.** **Write the advisory** for Tsavo Wireless, **Generate the report** and **Mark as
sent**: 14 hosts, not thousands. The finding closes once every organisation's advisory is sent; the other operators
get theirs the same way.

## 5. Scenario two: the analyst asks first

**1. Analyst: notice something.** On the map, an analysis of one network and one infection (*Lakeside Broadband ·
android.badbox2*) shows devices calling several sinkholes. Before sending anything, the analyst wants a researcher's
view.

**2. Analyst: ask with a code.** **Make analyst code** in the analysis window. Title and question (*Which of these
call the same sinkholed C2 domains? Check before I send*). Looking Glass keeps exactly those records and makes `LG-A-…` and **Finding #2**.

**3. Researcher: answer without seeing an address.** **Open as researcher** on the finding: the selection in words
(the host is "1 host, address held back"), the names in it, their definitions, combinations and cross-report patterns
with their codes. Tick the codes that answer the question and **Send the reply**: it lands in the finding's history.

**4. Management: read both sides.** **Show in Executive** works with the analyst's code too (that day, counts only).

**5. Analyst: send it on.** Search the researcher's code from the reply for exactly the devices that call the same
sinkholed domain, then send it to management for the advisory, as in scenario one.

## 6. The next days: watching the numbers fall

- Search a code again over **a date range of the stored history** (up to 31 days) on the Combinations page: devices
  per day show whether the operator has fixed them.
- The **Executive portal** compares every figure with its own 7-day average; filtered by the code, the drop is visible
  to management.
- A finding closes when every organisation's advisory is sent, or by itself when its time to act runs out (30 days
  after its devices were last seen).

## 7. Writing the advisory

The advisor writes it on the finding's advisory page (`/advisory/<number>`), once management has approved the finding,
one organisation at a time:

1. **Pick the organisation**: a network in the finding's search, with how many of its devices and records are in it.
2. **See its data**: its addresses with their ports, reports, CVEs and issues, and the impact of those reports, so the
   advisory is written from what the PDF will carry.
3. **Write** the subject, the **Description** (the impact) and the **Recommended Actions**: what the organisation
   should do (patch, isolate, replace end-of-life systems) and by when. Bold, bullets and numbering are kept in the PDF.
4. **Generate the report**, after confirming it's you. It holds:
    - the advisory's pages: your organisation's name and logo, the organisation's affected addresses, CVEs and issues,
      the reports with their impact, and your Description and Recommended Actions;
    - the analyst's report on that organisation's devices only, with the definitions under Technical Details;
    - the Shadowserver report references.

    Every generated report is kept, with its download.
5. **Mark as sent** to its recipients, and go on to the next organisation. The finding closes once every
   organisation's advisory is sent.

## 8. Checklists

**Researcher, every day**
- [ ] Sort by *Across reports* and by *Hosts*; read the *Looking Glass asks* card
- [ ] Open Intel gathered on the top names; note exact combinations that repeat
- [ ] Write a note with the combination's code; track the strongest as a finding
- [ ] Answer analysts' codes on the Findings page

**Management**
- [ ] Open new findings; **Show in Executive**; check the trend and the regions
- [ ] Move each finding on with a short comment

**Analyst**
- [ ] Search the code; report per operator; send short advisories
- [ ] Make an analyst code when a selection needs a researcher's eye
- [ ] Re-search after a few days; close what is fixed

## 9. The codes at a glance

| Code | Made by | Stands for | Carries an address? |
|---|---|---|---|
| `LG-C-…` | researcher (Intel gathered, Notes) | one exact combination in one report | no |
| `LG-X-…` | researcher | one exact pattern across reports | no |
| `LG-A-…` | analyst (analysis window) | exactly the records of an analysis selection on one day | no |

See also: [User guide](USER_GUIDE.md#combination-codes-the-combination-search-and-findings) ·
[What is new](FEATURES.md) · [Glossary](GLOSSARY.md)
