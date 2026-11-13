# Running Looking Glass day to day

Commands are run in the platform folder as the user the service runs as. Scripts marked ▶ start themselves with the
project's Python (`.venv`); run the others with `.venv/bin/python <script>`.

## Folders

| Folder | What is in it |
|---|---|
| `deploy/` | installing and running the service: `install.sh`, the service template, HTTPS certificate, reload, read-only database account |
| `manage/` | looking after a running installation: accounts, backups, network names, infection knowledge base, region maps |
| `security_testing/` | the security documentation, the penetration test report and the security retest |
| `tests/` | automated checks of both platforms against the database |
| `tools/` | diagnostics for the database and the reports |
| `docs/` | these guides |

## The service

| Task | Command |
|---|---|
| Restart after a change (no sudo) | `deploy/reload.sh` |
| Status, start, stop | `systemctl status looking-glass`, `sudo systemctl start|stop|restart looking-glass` |
| Logs (live) | `journalctl -u looking-glass -f` |
| Health | `curl -s localhost:5000/healthz` (or `curl -sk https://localhost:5000/healthz` with HTTPS) |
| HTTPS certificate for other screens | `deploy/make_tls_cert.sh [extra names or addresses]` ▶ (no sudo; renews by running it again) |

The replay needs nothing from you: it waits for each day's reports, then replays the day. The intro page and the
top bar show "Waiting for the reports of …" while it waits.

## Accounts

Normally done on the **Admin** page ([USER_GUIDE.md](USER_GUIDE.md)). On the command line, for recovery:

```bash
manage/manage_users.py list                 # accounts, roles, MFA, recovery codes left
manage/manage_users.py add NAME --admin     # new administrator (asks for the password, shows the QR key)
manage/manage_users.py help                 # every command: passwd, mfa, role, remove
```

## Backups

```bash
manage/backup.sh [folder]        # default ~/backups; archive mode 600 with a .sha256 file
manage/verify_backup.sh [archive]
```
The archive holds the code, `.env` and all of `data/` (accounts, sessions, audit log, settings, certificates), not
`.venv`. It contains secrets: copy it to safe storage off the computer. **Restore:** unpack it in the parent folder
(`tar -xzf <archive>`), run `deploy/install.sh` (recreates `.venv`, keeps `.env`) and restart the service.

MongoDB itself is backed up with the pipeline ([../../database/README.md](../database/README.md)).

## Reference data

### Network names (`data/asns.json`)
Turns AS numbers into company names ("AS64500" → the operator's name), and gives each network a type and a stable
demo alias. Built from your own data:
```bash
.venv/bin/python manage/asn_registry.py 7      # add the AS numbers seen in the last 7 days
```
New numbers are looked up in RIPEstat and added with `"reviewed": false`. To correct a name, edit `name` and set
`"reviewed": true`; the service picks the change up by itself.

### Infection knowledge base (`data/infections.json`)
What each infection is and the recommended action, shown in the details and analyses.
```bash
.venv/bin/python manage/infections_missing.py 7   # infections seen in 7 days with no entry yet
```
It writes stubs to `data/infections_missing.json`. Research and write the entries (title, type, description,
action, confidence), then add them to `data/infections.json`; open pages pick them up within 10 minutes.

Simpler: give a person the **researcher** role. The **Definitions** page lists the names Malpedia does not know (new
report names appear by themselves) and saves definitions with references to `data/definitions.json`. That file takes
precedence over `data/infections.json`, is never part of a release (so upgrades keep it) and is in the backups.

Updates replace `data/infections.json` and `data/issues.json` (the shipped definitions, signed *Looking Glass*) and
never touch what a site wrote: `data/definitions.json` (site definitions), `data/notes.json` (researchers' notes),
`data/combo_codes.json` (combination codes), `data/findings.json` (findings and their history) and
`data/seen_names.json` (where and when each name was last seen) are run-time files, all in the backups. A site
definition still overrides a shipped one of the same name after an update; to take the shipped one instead, delete the
site's entry from `data/definitions.json`.

### Researchers' notes (`data/notes.json`) and last seen (`data/seen_names.json`)
Notes are written on the Definitions page and shown on every card and in the PDF reports; the author or an
administrator removes them there. The last-seen record fills itself: once from the last 14 days (in the background
after the first start; `data/seen_names.json.done` marks it done, delete both files to rebuild it) and then from every
replay day. It keeps 30 days.

### Combination codes (`data/combo_codes.json`) and findings (`data/findings.json`)
Every code a researcher is shown is written to `data/combo_codes.json`, so an analyst can still resolve it after the days
that produced it have left memory (a code not found there is looked for in memory again). It keeps the twenty thousand most
recently shown. A history search reads at most 31 days, one day at a time, only the reports of that name, in a background
thread (two searches cannot run at once for one analyst); a finished search is held for an hour, in memory and in
`data/combo_exports/` (owner-only files, so a service restart before the download loses nothing), then deleted.
Findings are never deleted by the platform; a closed finding stays under *All*.

### Report definitions (`data/service_reports.json`)
Plain-language definitions of every Shadowserver report, with Shadowserver's severity and a link to its page. When
Shadowserver adds a report type, add an entry with the collection name as key.

### Region maps (`static/data/adm1/`)
First-level regions of all 54 African countries (geoBoundaries, CC BY 4.0), with the names geolocation uses.
`manage/fetch_africa_boundaries.py` downloads them again, and `manage/region_aliases.py` re-links the region names
found in reports to the map regions (needs Ubuntu's `iso-codes` package).

### Offline name sources (`data/names_misp_galaxy.json`, `data/names_attack.json`)
MISP Galaxy (Malpedia, Botnet and Tool clusters) and MITRE ATT&CK (malware and tools) explain names that neither the
researchers nor Malpedia explain, and appear under "Also described by" on every card (see the User Guide, Definitions).
`manage/fetch_offline_names.py` downloads them (at most once a week; `--force` now, `--status` to see what is installed).
The installer schedules it weekly (`--schedule`: Mondays 04:17 in the user's crontab, tagged `# looking-glass-name-sources`;
`--unschedule` removes it). A download that is invalid, too small, or under 70% of the copy in use is refused and the old
copy kept; the reason is in `data/names_refresh.log` and `data/names_refresh.json`, and every refresh (with counts and the
ATT&CK version) is in the audit log. Administrators can also refresh from the Definitions page (**Refresh sources**,
at most once an hour). Look-ups only read these files. The same script downloads MITRE CTID's KEV → ATT&CK mappings
(`data/attack_kev.json`, `--only kev`), and when a new ATT&CK version arrives it compares it with the old one: the report
mappings it touches go back to "please check" (`data/attack_mappings.json`; the rule table that suggests them is the
shipped `data/attack_rules.json`), one notice appears on the Definitions page and one entry in the audit log.

## Checks

| Command | What it checks | Time |
|---|---|---|
| `security_testing/security_retest.py` ▶ | about 120 checks of every security protection against the running service; must end with ALL PASSED | 2 min |
| `tests/run_all_checks.sh` | replay schedule, new reports on both platforms, consistency of every figure, totals against MongoDB, every statistic and filter of both platforms and the Executive portal against MongoDB (`tests/verify_stats.py`, `verify_svc_stats.py`, `verify_management.py`), report downloads, CSV formula safety, masking (fails on any leak), privacy and roles unit tests, Intel gathered, researchers' notes, cross-report filters | 4 min |
| `tests/check_baseline_concurrency.py` | 24 new Executive selections at the same moment: every 7-day baseline completes and none fails; runs in a temporary copy | 3 min |
| `tests/check_past_days.py` | the Executive 7-day baseline from compact past days equals the full days (complete answers, 7 days, both platforms); runs in a temporary copy | 5 min |
| `tests/e2e_test.py all` ▶ | end to end: runs a copy on port 5055 with a throwaway database, simulates Shadowserver deliveries and checks what both platforms show | 5 min |

The checks only read the real database and service; tests that create reports use throwaway databases and drop them.
They reach the API with the local automation key (`data/automation.key`), accepted from this computer only.

## Diagnostics (`tools/`)

| Script | Shows |
|---|---|
| `tools/envcheck.sh` | Python, venv, and whether MongoDB is reachable |
| `tools/quickcheck.py` | connection, indexes, collection size, a timed sample query |
| `tools/diagnose_reports.py [collection...]` | which reports are used, and what the others lack |
| `tools/discover.py`, `tools/show_srcdst.py` | a survey of every collection (written to `tools/discovery.json`) |
| `tools/analyze_services.py` | the fields of the services reports |
| `tools/daysize.py YYYY-MM-DD` | the size of one day |
| `tools/report_arrivals.py [day]` | when each report of a day arrived in MongoDB |
| `tools/check_reports.py [day]` | MongoDB against what the running service has loaded |
| `tools/list_infections.py [day]` | every infection of a day with counts |
| `tools/malpedia_check.py` | which infections Malpedia knows |

### A report is listed as "not processed yet"
Usually it has no `filename` index. Create one (with an administrator account) in `mongosh`:
```js
use shadowserver
db.<collection>.createIndex({ filename: 1 })
```
The pipeline creates these indexes for every report it loads.
