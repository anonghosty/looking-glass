---
title: Looking Glass
hide:
  - navigation
  - toc
---

<div class="lg-hero" markdown>

<img class="lg-hero-mark" src="assets/logo-mark.svg" alt="" width="84" height="84">

<p class="lg-eyebrow">Free and open source · built in Africa, for African CSIRTs</p>

# Your Shadowserver reports, replayed as a living picture of your country

<p class="lg-lede">Looking Glass turns the daily Shadowserver reports into two live platforms, analysis that finds
the few devices that matter, and reports you can send. One modest server and a guided installer: useful on day one.</p>

[Install it](INSTALLATION.md){ .md-button .md-button--primary }
[Read the user guide](USER_GUIDE.md){ .md-button }
[See it used](USE_CASES.md){ .md-button }

</div>

<div class="lg-hero-film" markdown>
<!-- film: overview compact -->
</div>

## Where to start

<div class="grid cards" markdown>

-   :material-download-circle-outline:{ .lg-ic .blue } **Install**

    ---

    Ubuntu 24.04 or later, on a server, a virtual machine or WSL 2. The installer asks, checks every answer on the
    spot, and installs everything.

    [Installation](INSTALLATION.md) · [Connecting the mailbox](MAIL_SETUP.md)

-   :material-radar:{ .lg-ic .violet } **Analysts**

    ---

    The two platforms, one-click analysis, the hosts to follow up first, and a report per network provider to
    attach to an advisory.

    [User guide](USER_GUIDE.md) · [Use cases](USE_CASES.md)

-   :material-flask-outline:{ .lg-ic .amber } **Researchers**

    ---

    The Definitions page: what the reports carry for every name, the exact combinations, notes with codes, and
    what Looking Glass asks you to look into.

    [Use cases](USE_CASES.md) · [Glossary](GLOSSARY.md)

-   :material-chart-box-outline:{ .lg-ic .teal } **Management**

    ---

    The Executive portal: aggregated figures only, never an address, compared with a 7-day baseline, with a
    one-click executive report.

    [User guide](USER_GUIDE.md) · [Features](FEATURES.md)

-   :material-shield-lock-outline:{ .lg-ic .red } **Administrators**

    ---

    Accounts, roles, two-factor sign-in, sessions, the audit log, backups and the checks that prove each
    protection on your own installation.

    [Operations](OPERATIONS.md) · [Security](SECURITY.md)

-   :material-scale-balance:{ .lg-ic .slate } **Comparing tools**

    ---

    Looking Glass complements IntelMQ and the Elastic Stack: IntelMQ notifies, Elastic searches, Looking Glass
    shows.

    [The honest comparison](COMPARISON.md)

</div>

## See it working

<div class="lg-films" markdown>
<!-- film: live-demo compact -->
<!-- film: use-cases compact -->
</div>

The chapters of each film are on its page: the live demo at the top of the [user guide](USER_GUIDE.md), the use cases
at the top of [Use cases](USE_CASES.md).

## How it works

<div class="lg-steps" markdown>

1. **Collect.** The database pipeline reads the mailbox that receives your Shadowserver reports (Gmail / Google
   Workspace, Microsoft 365 or any IMAP server), saves every attachment and download link, and skips what it
   already has.
2. **Load.** Each report goes into MongoDB, one collection per report type, without duplicates.
3. **Replay.** Shadowserver sends a day's reports during the next day; Looking Glass replays that day in full, at
   the same time of day, so a wall screen always shows a living picture.
4. **Analyse and share.** Analysts drill down and export; researchers define and explain; executives get
   aggregates; partners see masked views.

</div>

## A needle through the haystack

Instead of forwarding a network operator thousands of reported addresses, narrow the day's reports step by step
(actively exploited, seen by several reports, the same exact combination on many devices, repeating) to the few
devices most likely to matter, send that operator a short, explained report, then take the next.

<div class="lg-pair" markdown>
![Looking Glass asks: the matches worth a researcher's eye](media/screens/62-definitions-leads.png)
![Combinations: the devices behind a code](media/screens/68-combinations.png)
</div>

[Follow the use cases step by step](USE_CASES.md){ .md-button .md-button--primary }

<p class="lg-fine">Every screenshot uses dummy data: documentation IP ranges (RFC 5737 / RFC 2544 / RFC 3849), private AS
numbers and fictional network names. Looking Glass is free software under the
<a href="https://github.com/anonghosty/looking-glass/blob/main/LICENSE">GNU AGPL-3.0</a>.</p>
