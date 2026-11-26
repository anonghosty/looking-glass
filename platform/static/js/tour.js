/* SPDX-License-Identifier: AGPL-3.0-only
   SPDX-FileCopyrightText: the Looking Glass contributors */
/* Looking Glass · the guided tour (the user, 2026-11-19: "a tutorial button on each platform so it shows what the
   sections, buttons and charts show, so anytime someone is lost they can click it ... new users should have a pop up
   asking whether to be taken through the tutorial or skip").
   * A Tutorial button in every page header starts the tour of that page, any time.
   * The tour spotlights one part at a time (the rest dimmed) with what it is: the page's own steps (STEPS below,
     by page) first, then every header button, explained from its own description (title), so a new button is covered
     without writing a step for it. Back, Next, Skip; arrow keys, Enter, Escape; the focus stays in the tour's card.
   * The first time a person opens a page with a tour: a small offer, "Take the tour" or "Skip" ("Don't show again"
     for every page). Remembered per person (PREF: the server's preference when the page has one, else this browser).
   Nothing is fetched to explain a part: the words are on the page or below. */
(() => {
  "use strict";
  if (window.LGTour) return;
  const KEY = "lg.tour.";
  // [selector, title, text] per page (r81/TOUR_STEPS_SOURCE.txt: read from the pages). A step whose part is not on the
  // page (another role, a hidden tab, nothing to show yet) is left out, never shown pointing at nothing.
  const STEPS = {
    "/overview": [
      [".ov-hero", "Where you start", "Your Overview: who you are signed in as, and the pages your role opens."],
      [".ov-record", "Everything is recorded", "What you view, copy or export is recorded under your name."],
      [".ov-yours", "Your pages", "The pages your role opens. Click one to go there."],
    ],
    "/#intro": [
      ["#introStats", "Yesterday in figures", "The headline figures of yesterday's reports."],
      ["#introTimeline", "Yesterday at a glance", "Events per hour of the report day; the bar under it splits them by attack type."],
      ["#introReports", "Reports monitored", "The network-communications reports Looking Glass replays, and the services reports."],
      [".intro-tabs", "Overview and Glossary", "Switch to the Glossary: every report, figure and term of both platforms, with a search box."],
      ["#btnExplore", "Open the map", "The replay of yesterday's infected devices and attacks, one day late, on the map."],
      [".intro-yours .portal-cards:not(.pc-platforms)", "Your pages", "The other pages your role opens."],
    ],
    "/": [
      ["#kpis", "Key figures", "Events yesterday, how many are replayed so far, source hosts, reports, hosts in several reports and critical ones."],
      ["#map", "The map", "Each event is replayed as an arc from its source to its destination at the replay clock's time. Hover one to see it, click to analyse it."],
      ["#speed", "Replay speed", "How fast the day is replayed, from 1x to 60x."],
      ["#drawer, #btnDrawer", "Filters", "Attack type, report, severity, infection, city or country, networks, tag, port and protocol. The counts follow the other filters."],
      ["#intelCol", "Threat intel", "The activity over the day, attack types, severity and the top networks, reports, infections, cities and domains. Click an entry to analyse it."],
      ["#stream", "Event stream", "The replayed events as a list. Click a row for its details, with Shadowserver's own ATT&CK and CVE when the report gives them; Pause and Catch up are at its top."],
    ],
    "/services": [
      ["#stage", "The view", "One bubble per service, sized by its records, pulsing as records are replayed. Click a bubble to analyse it."],
      ["#viewSeg", "Bubbles or regions", "Switch between the bubbles and the map of regions."],
      ["#kpis", "Key figures", "Records, replayed, exposed hosts, reports, hosts with issues and critical ones. Click a tile for its breakdown."],
      ["#drawer, #btnDrawer", "Filters", "Only hosts with issues, several issues or several reports; report family, service, severity, issue, region, city, network, port, vendor and device type."],
      ["#intelCol", "Intel", "The day's activity, report families, severity and the top issues, services, networks, regions, vendors, products and ports."],
      ["#stream", "Record stream", "The replayed records. Click one for its details, with the certificate and TLS facts when the scan has them, to analyse the host or service, or to filter the view."],
    ],
    "/management": [
      [".mg-switch", "Platform", "Infections and attacks (network communications) or exposure and vulnerabilities (services)."],
      ["#mgDay", "Report day", "The day shown."],
      ["#mgReport", "Executive report", "A PDF and CSV of what is shown, as filtered."],
      ["#cUnusual", "Unusual this week", "How many networks and reports were well above their normal each day of the week, and the strongest in words. The analysts confirm or dismiss them."],
      ["#mgKpis", "Key figures", "The day's main counts for the selection."],
      ["#cBase", "7-day baseline", "Each figure over the 7 days before the report day; the dashed line is their average."],
      ["#cMap", "Regions", "Regions coloured by activity. Hover for the figures, click to focus on a region."],
      ["#cTop", "Top names", "Devices per infection or vulnerability. Click a name, or Explain all, for what it is in plain words."],
      ["#cReports", "Reports", "Every report in the selection, ranked by devices. Click one to focus on it."],
      ["#cCross", "Across reports", "Devices seen in several reports, and the report pairs they share most."],
      ["#lgQuarterly", "Quarterly reports", "Each ended quarter's management report (PDF) and summary (CSV), made on the next quarter's 3rd day, for the management role only. The card says where the quarter stands and whether the quarterly purge is on now; when it is, download before the date shown: the raw report rows are deleted after it."],
    ],
    "/findings": [
      [".fd-hero", "Where every finding stands", "A finding's path: a note or an analysis, management's decision, the advisory sent, closed."],
      [".fd-tabs", "Open or all", "Only the open findings, or every finding you take part in."],
      ["#fdQ", "Search", "Find a finding by its name, title or code."],
      ["#fdList .fd-card", "A finding", "Its number, title, state and who holds it. Open it for its history, and reply when it waits for you."],
      ["#beaconUnknown", "Undecoded requests", "Requests nothing decodes yet, to send to the Looking Glass creator once an administrator agrees."],
    ],
    "/advisory": [
      ["#apMain .ap-hero", "Advisory portal", "How many findings wait for an advisory."],
      ["#apMain .ap-kpis", "Figures", "Waiting, drafts, drafted and sent advisories, recipients, open findings and the average days to send."],
      ["#apMain .ap-kpis + .av-card", "Waiting for an advisory", "Findings management decided and sent to you. Open one to write its advisory."],
      ["#apMain .ap-grid", "Charts", "Advisories per recipient, sent per month, the impacts and the reports they named."],
      ["#apMain .ap-grid + .av-card", "Advisories", "Every advisory with its reference, TLP, organisation, state and recipients."],
      ["#lgQuarterly", "Quarterly reports", "Each ended quarter's advisor report (PDF) and CSVs: networks, organisations with the follow-up of their advisories, and issues per network, for advisors only. The card says where the quarter stands and whether the quarterly purge is on now; when it is, download them before the date shown."],
    ],
    "/advisory/": [
      ["#avMain .av-hero", "The advisory", "The finding it is for, and the organisation's name and logo from Settings."],
      ["#avMain .av-netsel", "1 · The organisation", "Each organisation gets its own advisory and report."],
      ["#avMain .av-aff", "2 · Its data", "The IP addresses and records, with ports, reports, CVEs, issues and impact, as the PDF carries them."],
      ["#advLook, #avMain .av-pdfopts", "The PDF's look", "Designed (dark) or plain white, and the name at the top of its pages: your choice for this advisory."],
      ["#advInsights", "Add insights", "The analysis pages after the advisory, or the advisory alone."],
      ["#avMain .av-acts", "Save and the report", "Save, generate the report, then mark it drafted and sent. A sent report is kept unchanged."],
    ],
    "/definitions": [
      ["#cardLeads", "Looking Glass asks", "Matches between names and reports for researchers to look into, and unusual activity: what is well above its own normal today."],
      ["#cardAttack", "MITRE ATT&CK", "Each report's suggested ATT&CK techniques, to confirm or change, beside the techniques Shadowserver tagged its events with."],
      ["#cardInf", "Infections and categories", "Names from the sinkhole and honeypot reports, looked up in Malpedia, MISP Galaxy and ATT&CK; define one with references."],
      ["#cardIss", "Issues", "CVEs are looked up (CISA KEV, EPSS, CVE.org, NVD); other issues need a definition with references."],
      ["#cardSev", "Severity map", "Each name with its criticality and where it comes from."],
      ["#cardNets", "Network names and types", "AS numbers with the company's name and type, to review and correct."],
    ],
    "/combinations": [
      [".cb-hero", "Combination search", "Paste a combination code (LG-C-… one report, LG-X-… across reports) to get exactly the devices carrying it."],
      ["#cbCodeForm", "1 · The combination", "The code, then Look up."],
      ["#cbStep2Box", "2 · Where to look", "The report day, the days in memory, or a range of stored days; then Search."],
      ["#cbStep3Box", "3 · The devices", "The devices found, a map of them per region and a breakdown per day."],
      ["#cbDownload", "Download", "A PDF summary and CSV files of the devices, the records and every field of every record, as a ZIP."],
    ],
    "/intelligence": [
      ["#itMain .it-hero", "Abused or Compromised", "What Shadowserver's Intelligence reports say about the constituency: yesterday against the 7 days before."],
      ["#itMain .it-tiles", "Groups", "One tile per group of reports with today's count and the week's bar. Click to jump to it."],
      ["#itMain .it-group .it-card", "A report", "What it means, today's count and the trend. Open the records to see them."],
      ["#itMain .it-nr", "Not received", "Reports that did not reach Looking Glass in the last 8 days, and why."],
    ],
    "/audit": [
      [".au-period", "Period", "7, 30 or 90 days, 12 months or chosen dates (UTC); every tab uses it."],
      [".au-tabs", "Tabs", "The overview, the audit log by kind, access review, who is signed in, the sender check, data sent out, integrity and evidence, Trace a leak."],
      ["#pane-sent", "Data sent out", "What went to the CSIRT's own OpenCTI and MISP in the period: each target as set up, then every send, retry, revocation and failure. Never raw rows, findings, notes, names or keys."],
      ["#ovBody", "Overview", "The figures and the control checks, mapped to NIST and CIS."],
      ["#pane-trace", "Trace a leak", "Paste text or choose a file found outside: it is matched against the recorded copies and downloads."],
    ],
    "/admin": [
      ["#peaceCard", "Peace of mind", "Closes the day-to-day pages and the findings notifications for your own account; recorded."],
      [".adm-tabs", "Tabs", "Users, roles and permissions, and locked sign-ins."],
      ["#usersTable", "Users", "The accounts and their roles; approve people who signed up; Reset passkeys when someone lost their devices."],
      ["#invBox", "Add a person", "A one-time sign-up link with a role, for a limited time."],
    ],
    "/unusual": [
      ["#ptToday", "Unusual on the latest report day", "Each network and report, or two reports together, well above its own normal: in words, with its chart. Show the devices, open it on the map, then Confirm or Dismiss."],
      ["#ptStatus", "The status line", "The report day, how the normal is worked out, and how many dismissed threads are kept quiet."],
      ["#ptMine", "Watched by your team", "The threads your team confirmed, followed every day against their own normal; Growing again today when one jumps."],
    ],
    "/account": [
      ["#pkCard", "Passkeys", "Your passkeys: the devices that confirm it's you. On an installation open to the internet you sign in with one and need at least two; elsewhere you may add one to use instead of the authenticator code."],
      ["#pkList", "Your passkeys", "Each passkey with its name, when it was added and last used. Rename it so you know which device it is; Remove one you no longer have."],
      ["#pkAdd", "Add a passkey", "Name it (for example \"Office laptop\"), then follow your browser: it asks your device to create the passkey. Looking Glass asks you to confirm it's you first."],
    ],
    "/settings": [
      [".st-tabs", "Tabs", "General, Workers (the report pipeline), Configuration, Connectors, the Task monitor and Quarterly. The Task monitor also shows whether Caddy is in front of Looking Glass, and the command when it is not."],
      ["[data-st-tab=\"connectors\"]", "Connectors", "Send Looking Glass's own analysis to your CSIRT's OpenCTI or MISP. Add a target follows the platform's own setup steps, then Test: a target is saved only after its test passed, and saved off. Tick what it receives, then turn it on. Every change asks you to confirm it."],
      ["[data-st-tab=\"update\"]", "Update", "Check for an update looks for a newer release. Update makes a backup, checks the maintainer's signature, installs the release with its libraries, restarts and checks that Looking Glass answers; if a step fails, the release you have now is put back. Every step shows as it happens. It asks you to confirm it's you every time."],
      ["[data-st-tab=\"quarterly\"]", "Quarterly and the purge", "The quarterly purge is off until you turn it on here, at the top: it shows what it would delete and when, and asks for your password; turn it off the same way. Below: where the quarter stands, Make it again, and every quarter with its purge figures (CSV) and accuracy checks. The management and advisor reports are downloaded by those roles only, on their portals."],
      ["#cardCountry", "Country", "The country and time zone; region names in the reports are matched to the map here."],
      ["#cardScope", "Constituency", "The whole country, or only chosen networks and address ranges, with a live count: networks, address blocks, other ranges. Every part of Looking Glass follows it."],
      ["#cardOrg", "Organisation", "The name and logo every advisory carries."],
      ["#cardSigninCheck", "Sign-in check", "A passkey (for a site on the internet) or the authenticator code (for an internal network), at sign-in and before high-value actions."],
      ["#cardPwPolicy", "Password policy", "Password expiry, and making every account change its password."],
      ["#cardCode", "Code check", "Once a day the installed code files are compared with the fingerprints their release shipped. A changed or added file is listed here and in your bell: keep it if it is yours, or mark it as not yours and run the command shown, which moves it to a quarantine folder on the server; both ask for your password. The command at the bottom checks the whole installation against the signed release."],
      ["#cardNets", "Choosing the constituency", "In the Constituent column, choose Not in, The whole network, or Some address blocks for each network. Some address blocks opens the row with its blocks, busiest first: tick yours, or add one that is not listed. A choice stays until you untick it."],
      ["#cidrs", "Other address ranges", "Ranges or single addresses that belong to no listed network, one row each: add one in the box, remove one with its × button."],
      ["#save", "Apply settings", "Applies the country and constituency."],
    ],
    "/review/": [
      ["#rvMain .rv-hero", "The request", "The finding, its state, the report day, the organisation and the channel."],
      ["#rvMain .rv-researcher", "The researcher", "The researcher's notes on the combination."],
      ["#rvMain .rv-analyst", "The analyst", "The analyst's request: the devices drilled down to."],
      ["#rvMain .rv-views", "The views", "The Executive portal's counts for each view."],
      ["#rvMain .rv-decide", "The decision", "Your comment, the advisor, and which view to approve, or reject."],
    ],
    "/intel/": [
      ["#axMain .ax-hero", "The analyst's selection", "The code, the day, the selection in words and its figures. Addresses are never shown."],
      ["#axMain .ax-src", "Where these hosts were seen", "Every report the hosts appear in, with host counts."],
      ["#axMain .ax-sec-inf", "Infections", "The infections in the selection, with their combination codes to tick."],
      ["#axMain .ax-sec-cve", "CVEs and issues", "The CVEs and issues found on these hosts."],
      ["#axMain .ax-sec-svc", "Services", "The services reports these hosts are in, with their pattern combinations."],
      ["#axMain .ax-sec-x", "Across reports", "Each name's hosts followed into their other reports that day."],
      ["#axMain .ax-reply", "Reply", "Reply on the finding with the codes you ticked."],
    ],
  };
  const el = (t, c, x) => { const n = document.createElement(t); if (c) n.className = c; if (x != null) n.textContent = x; return n; };
  const vis = (n) => { if (!n) return false; const r = n.getBoundingClientRect(); return r.width > 2 && r.height > 2 && getComputedStyle(n).visibility !== "hidden"; };
  // r90: a part another layer covers (the map's header behind its Overview dialog) is not on screen for the person:
  // what is drawn at its centre must be the part itself (or inside it). A part scrolled out of view is scrolled to.
  const uncovered = (n) => {
    const r = n.getBoundingClientRect(), x = r.left + r.width / 2, y = r.top + r.height / 2;
    if (x < 0 || y < 0 || x >= innerWidth || y >= innerHeight) return true;
    const top = document.elementFromPoint(x, y);
    return !top || top === n || n.contains(top) || !!top.closest(".lg-tour, .lg-tour-offer, .lg-htip");
  };
  // a part under an open modal dialog it is not in (the map's Overview dialog over the map) is left out too
  const underDialog = (n) => [...document.querySelectorAll('[aria-modal="true"]')].some((d) => d !== n && !d.contains(n) && !d.hidden && vis(d) && !d.closest(".lg-tour"));
  const shown = (n) => vis(n) && !underDialog(n) && uncovered(n);
  // the page: /advisory/12 -> /advisory/, /intel/LG-A-… -> /intel/; the map with its Overview dialog open -> /#intro
  const pageKey = () => {
    const p = location.pathname;
    if (p === "/") { const i = document.getElementById("intro"); return i && vis(i) && !i.hidden ? "/#intro" : "/"; }
    if (/^\/(advisory|review|intel)\/./.test(p)) return p.replace(/^(\/[a-z]+\/).*$/, "$1");
    return p;
  };
  // what this person has seen or skipped: the server's memory (tour_prefs.py, per person, every browser) and this
  // browser's, either one enough to stop the offer
  const server = { pages: [], never: false };
  const csrf = document.querySelector('meta[name="csrf-token"]')?.content || "";
  const tell = (body) => fetch("/api/tour", { method: "POST", credentials: "same-origin",
    headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf }, body: JSON.stringify(body) }).catch(() => {});
  const store = {
    get(k) {
      if (k === "never" && server.never) return "1";
      if (k.startsWith("seen:") && server.pages.includes(k.slice(5))) return "1";
      try { return localStorage.getItem(KEY + k); } catch { return null; }
    },
    set(k, v) {
      try { localStorage.setItem(KEY + k, v); } catch { /* private mode */ }
      if (k === "never") { server.never = true; tell({ never: true }); }
      else if (k.startsWith("seen:")) { server.pages.push(k.slice(5)); tell({ page: k.slice(5) }); }
    },
  };

  // the page's own steps: by its address, else by what is on it (the Overview's welcome, the map, the services stage)
  const MARKS = [[".ov-hero", "/overview"], ["#map", "/"], ["#stage", "/services"]];
  function pageSteps() {
    if (STEPS[pageKey()]) return STEPS[pageKey()];
    const m = MARKS.find(([sel]) => document.querySelector(sel));
    return m ? STEPS[m[1]] : [];
  }
  function steps() {
    const out = [];
    for (const [sel, title, text] of pageSteps()) {
      const n = [...document.querySelectorAll(sel)].find((m) => vis(m) && !underDialog(m));
      if (n) out.push({ n, sel, title, text });
    }
    // the header buttons, each from its own description: only those the person can see and reach now (r90)
    const heads = [...document.querySelectorAll(".hud-right .nav-ic, .hud-right .demo-btn, .hud-right .lg-bell, .intro-gear-row .lg-bell, .intro-gear-row .account-btn, .mg-top-actions a, .mg-top-actions button")]
      .filter((n) => shown(n) && !n.classList.contains("lg-tour-btn"));
    for (const n of heads) {
      const name = (n.getAttribute("aria-label") || n.textContent || "").trim();
      const tip = (n.getAttribute("title") || n.dataset.lgTitle || "").trim();
      if (name) out.push({ n, title: name, text: tip && tip !== name ? tip : "A button in the header." });
    }
    const t = document.querySelector(".lg-tour-btn");
    if (t && shown(t)) out.push({ n: t, title: "Lost? Start the tour again", text: "The Tutorial button shows this tour of the page, any time." });
    return out;
  }

  let ui = null;
  function end(done) {
    if (!ui) return;
    ui.root.remove(); document.removeEventListener("keydown", ui.keys, true); removeEventListener("resize", ui.place); removeEventListener("scroll", ui.place, true);
    if (done) store.set("seen:" + pageKey(), "1");
    if (ui.back && ui.back.focus) ui.back.focus();
    ui = null;
  }
  function start() {
    end(false);
    const list = steps();
    if (!list.length) return;
    const root = el("div", "lg-tour"), spot = el("div", "lg-tour-spot"), card = el("div", "lg-tour-card");
    card.setAttribute("role", "dialog"); card.setAttribute("aria-modal", "true"); card.setAttribute("aria-labelledby", "lgTourTitle");
    const count = el("div", "lg-tour-count"), h = el("h2", "lg-tour-title"), p = el("p", "lg-tour-text");
    h.id = "lgTourTitle";
    const acts = el("div", "lg-tour-acts"), skip = el("button", "lg-tour-skip", "Skip the tour"), prev = el("button", "lg-tour-prev", "Back"), next = el("button", "lg-tour-next", "Next");
    for (const b of [skip, prev, next]) b.type = "button";
    acts.append(skip, prev, next); card.append(count, h, p, acts); root.append(spot, card); document.body.append(root);
    let i = 0;
    const place = () => {
      const s = list[i], r = s.n.getBoundingClientRect(), pad = 6;
      Object.assign(spot.style, { left: `${r.left - pad}px`, top: `${r.top - pad}px`, width: `${r.width + 2 * pad}px`, height: `${r.height + 2 * pad}px` });
      // its width first, then its height: measured at the old width the text wrapped less, and the card ended below
      // the screen (the services platform's first step, 2026-11-20)
      const cw = Math.min(340, innerWidth - 24);
      card.style.width = `${cw}px`;
      const ch = card.offsetHeight || 160;
      let top = r.bottom + 14, left = Math.min(Math.max(12, r.left), innerWidth - cw - 12);
      if (top + ch > innerHeight - 12) top = Math.max(12, r.top - ch - 14);
      if (top < 12 || r.height > innerHeight * 0.6) { top = Math.max(12, innerHeight - ch - 24); left = Math.max(12, innerWidth - cw - 24); }
      Object.assign(card.style, { left: `${left}px`, top: `${top}px`, width: `${cw}px` });
    };
    // a part the page drew again since the tour began (a list that finished loading, a live update): found again
    const fresh = (s) => {
      if (s.sel && (!s.n.isConnected || !vis(s.n))) s.n = [...document.querySelectorAll(s.sel)].find(vis) || s.n;
      return s;
    };
    const show = () => {
      const s = fresh(list[i]);
      // at once, not the page's smooth scrolling: the card is placed where the part ends up, not where it was mid-scroll
      s.n.scrollIntoView({ block: "nearest", inline: "nearest", behavior: "instant" });
      count.textContent = `${i + 1} of ${list.length}`; h.textContent = s.title; p.textContent = s.text;
      prev.disabled = i === 0; next.textContent = i === list.length - 1 ? "Done" : "Next";
      place(); next.focus();
    };
    const go = (d) => { if (i + d < 0) return; if (i + d >= list.length) { end(true); return; } i += d; show(); };
    prev.addEventListener("click", () => go(-1)); next.addEventListener("click", () => go(1)); skip.addEventListener("click", () => end(true));
    const keys = (e) => {
      if (e.key === "Escape") { e.preventDefault(); end(true); }
      else if (e.key === "ArrowRight") { e.preventDefault(); go(1); }
      else if (e.key === "ArrowLeft") { e.preventDefault(); go(-1); }
      else if (e.key === "Tab") {             // the focus stays in the tour's card
        const f = [skip, prev, next].filter((b) => !b.disabled), k = f.indexOf(document.activeElement);
        e.preventDefault(); f[(k + (e.shiftKey ? f.length - 1 : 1)) % f.length].focus();
      }
    };
    ui = { root, keys, place, back: document.activeElement };
    document.addEventListener("keydown", keys, true); addEventListener("resize", place); addEventListener("scroll", place, true);
    show();
  }

  // the Tutorial button in the header (before the bell / Settings / Log out, like the other icons). One button per page:
  // on the map it sits in the header of the screen that is open, the Overview dialog's own group (beside its bell and
  // Log out, styled like its bell) while the dialog is open, the map's header once it closes (r90: it stayed behind
  // the dialog, unreachable)
  let tourBtn = null;
  const introOpen = () => { const i = document.getElementById("intro"); return !!(i && !i.hidden && vis(i)); };
  function placeButton() {
    if (!tourBtn) return;
    const intro = introOpen() && document.querySelector(".intro-gear-row");
    const host = intro || document.querySelector(".hud-right, .mg-top-actions");
    if (!host) return;
    const logout = host.querySelector(":scope > .account-form, :scope > .account-btn, .account-form, .account-btn");
    const before = logout ? (logout.closest(".account-form") || logout) : null;
    if (tourBtn.parentElement === host && tourBtn.nextElementSibling === before) return;
    const had = document.activeElement === tourBtn;
    host.insertBefore(tourBtn, before);
    if (had) tourBtn.focus({ preventScroll: true });
  }
  function addButton() {
    if (tourBtn || !document.querySelector(".hud-right, .mg-top-actions")) return;
    const b = el("button", "demo-btn nav-ic lg-tour-btn"); b.type = "button";
    b.title = "Tutorial: a short tour of this page, what its sections, buttons and charts show"; b.setAttribute("aria-label", "Tutorial");
    b.innerHTML = '<svg viewBox="0 0 24 24" width="16" height="16" aria-hidden="true"><path fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" d="M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18zM9.6 9.2a2.5 2.5 0 1 1 3.4 2.4c-.6.3-1 .8-1 1.5v.6M12 17h.01"/></svg><span>Tutorial</span>';
    b.addEventListener("click", start);
    tourBtn = b;
    placeButton();
    // the map's Overview dialog opens and closes in place (app.js openIntro / closeIntro): the button follows it
    const intro = document.getElementById("intro");
    if (intro) new MutationObserver(placeButton).observe(intro, { attributes: true, attributeFilter: ["hidden", "class", "style"] });
  }

  // the first visit: the offer (once per page; "Don't show again" for every page)
  function offer() {
    if (store.get("never") === "1" || store.get("seen:" + pageKey()) === "1" || !steps().length) return;
    const box = el("div", "lg-tour-offer"); box.setAttribute("role", "dialog"); box.setAttribute("aria-labelledby", "lgTourOfferT");
    const t = el("b", null, "New here?"); t.id = "lgTourOfferT";
    const x = el("p", null, "Take a short tour of this page: what its sections, buttons and charts show. The Tutorial button in the header shows it again any time.");
    const a = el("div", "lg-tour-acts"), yes = el("button", "lg-tour-next", "Take the tour"), no = el("button", "lg-tour-skip", "Skip"), never = el("button", "lg-tour-never", "Don't show again");
    for (const b of [yes, no, never]) b.type = "button";
    a.append(never, no, yes); box.append(t, x, a); document.body.append(box);
    yes.addEventListener("click", () => { box.remove(); start(); });
    no.addEventListener("click", () => { box.remove(); store.set("seen:" + pageKey(), "1"); });
    never.addEventListener("click", () => { box.remove(); store.set("never", "1"); });
    yes.focus({ preventScroll: true });
  }

  window.LGTour = { start, end, steps, offer, STEPS, pageKey };
  // the offer after the page's own loading (its logo gone: LGLoader), so it never covers a page still being drawn
  const settled = () => !document.querySelector("#lgTransition.on, .st-loading:not([hidden])");
  const go = async () => {
    addButton();
    try {
      const r = await fetch("/api/tour", { credentials: "same-origin", cache: "no-store" });
      if (r.ok) { const d = await r.json(); server.pages = d.pages || []; server.never = !!d.never; }
    } catch { /* no server memory: this browser's */ }
    let waited = 0;
    const tick = () => { if (settled() || waited > 15000) offer(); else { waited += 500; setTimeout(tick, 500); } };
    setTimeout(tick, 1200);
  };
  if (document.readyState === "complete") go(); else addEventListener("load", go, { once: true });
})();
