# Architecture and threat model

This page describes how Looking Glass is built and where its trust boundaries are. It names what an attacker would
want, who that attacker might be, and what stops each attack. It also
lists the risks that remain. It describes the code as it is now; when the code changes, this page should change with it.

The details of each control are in [Security](SECURITY.md), and the logic of the audit log is in
[How the audit log proves itself](AUDIT_LOG_PROOF.md).

---

## 1. The parts

Looking Glass is two programs that share one database. Everything except the browsers runs on one server:

```
 Shadowserver
   │  e-mail to the mailbox, or the report API (HTTPS)
   ▼
 database/   the pipeline: its own Linux user and database account
   fetch → check the sender (DKIM) → unzip within limits
         → sort → load
   │  read and write, its own database only
   ▼
 MongoDB     127.0.0.1 only, login required
   │  read only
   ▼
 platform/   the web app: a sandboxed systemd service
   data/: accounts, sessions, audit log, findings, advisories
   │  HTTPS; sign-in with password + TOTP
   ▼
 staff browsers, one role each:
   analyst · researcher · management · advisor
   auditor · admin · external
```

| Part | What it does | Runs as | Can write |
|---|---|---|---|
| **Pipeline** (`database/`) | On its schedule (every 30 minutes recommended): fetches the reports (mailbox read-only, or Shadowserver's report API), checks who sent each e-mail, unzips within limits, sorts and loads each CSV row into MongoDB | its own user, cron | its folders, and its own database through `lookingglass_pipeline` |
| **MongoDB** | Holds the reports: one document per row, per report type | `mongod`, bound to 127.0.0.1 | n/a |
| **Platform** (`platform/`) | The web app: the map, services, Intel gathered, findings, the Executive portal, advisories and the Audit portal | a systemd service with `NoNewPrivileges`, `ProtectSystem=strict` and `ProtectHome=read-only`; writable only in `data/` | only `data/`; the database through the read-only account `lookingglass_ro` |
| **Browser** | Shows the pages; all report data is inserted as text, under a strict Content-Security-Policy | the user's computer | nothing on the server, except through the signed-in API |

There is one way back from the web app to the pipeline: Settings → Workers. The web app can't write the pipeline's
folder. A setting change is a request file in the web app's own `data/pipeline_requests/`, which the pipeline checks
again at its next run. A request that would make the pipeline **less strict** waits until someone confirms it on the
server, on the pipeline's own account ([Security, section 2](SECURITY.md#pipeline-settings-from-the-web-app-settings--workers)).

## 2. From a report to an advisory

1. **Arrives.** A Shadowserver e-mail, or a file from the report API. In both cases only the pipeline touches it.
2. **Checked.** The sender's DKIM signature is checked on the message exactly as it was downloaded. Zips are unpacked
   within limits counted on the real bytes, and file names inside a zip can't leave its folder. One-off special
   reports are loaded apart.
3. **Stored.** One document per CSV row. Duplicates are refused by a unique index.
4. **Seen.** Each role sees only its part:
   - Analysts see addresses.
   - Researchers see the threat data with every constituent address masked. Patterns carried by fewer than 5 hosts
     get no lasting code.
   - Management sees numbers and the C2 / sinkhole domains by name; a C2 host that is an IP address reads
     "IP address 1, 2…", never the address.
   - External viewers see everything masked.
   - The auditor sees only the audit log and its evidence.
5. **Followed up.** A finding is a channel. Every hand-over names a person, and only the people in it (and admins)
   can open it.
6. **Advised.** The advisor drafts one advisory per organisation and generates the PDF, then marks it as sent. Every
   step goes into the audit log.
7. **Audited.** Every sign-in, change, export and view of host-level data goes into a hash-chained audit log. The
   auditor takes a proof package and verifies it offline on their own computer.

## 3. Trust boundaries

| # | Boundary | What crosses it | What is checked there |
|---|---|---|---|
| B1 | Internet → pipeline | e-mails and report files | DKIM signature by the expected signer; zip limits; safe file names; HTTPS to Shadowserver, with each API request signed with the secret (`HMAC2`) |
| B2 | Pipeline → database | report rows | the pipeline's own account: its database only, no account management |
| B3 | Database → platform | report rows | a read-only account; every value is treated as untrusted text (it came from scanned hosts) |
| B4 | Network → platform | HTTP requests | `ACCESS_MODE` and the allow list; the host-name check (against DNS rebinding); HTTPS for remote sign-in; a 64 KB request limit |
| B5 | Signed-in user → data | API calls | role permissions enforced on the server; masking done on the server; CSRF token and same-origin checks on changes |
| B6 | Platform → pipeline | setting requests | re-checked by the pipeline; loosening needs a confirmation on the server, bound to the request's SHA-256 |
| B7 | Platform → outside services | look-ups | only what each service needs: AS numbers (PeeringDB, RIPEstat), CVE IDs (NVD, FIRST, CISA), malware hashes and families (Malpedia), place names (Mapbox geocoding). No constituent IP address is sent to any of them |
| B8 | Server → auditor | the proof package | the auditor's own verifier, standard library only, run off the server; the head is kept off the server |

## 4. What an attacker would want

| Asset | Where | Why it matters |
|---|---|---|
| **Constituent identities**: IP addresses, host names and network names of the organisations in the reports | MongoDB; shown to analysts | A list of vulnerable or infected hosts in the country is a target list |
| **Credentials**: mailbox and database passwords, the Shadowserver API key, `REF_SECRET`, TLS key, session store | `.env`, `data/` (mode 600), `/etc/looking-glass/mongo-admin.env` (root only) | They open everything else. `REF_SECRET` is what makes masked host labels unguessable |
| **The audit log** | `data/audit.log`, its archives, `audit.head`, `audit.seal` | It is the evidence an auditor and the CSIRT rely on |
| **The integrity of the reports** | the pipeline's intake, MongoDB | Forged reports would send analysts and advisories after the wrong hosts |
| **Pipeline settings** | the pipeline's `.env` | Turning the sender check or the unzip limits off would open the intake |
| **Findings and advisories** | `data/findings.json`, `data/advisories/` | They say who is affected and what to do; they are not for every role |
| **Accounts and roles** | `data/users.json`, roles | A role change is a way into everything above |

## 5. Who might attack, and what stops them

Each row below names a threat and the control that stops it.

### A1. Someone on the network, with no account

| Threat | Control |
|---|---|
| Reach pages or the API without signing in | Every page and API needs a sign-in: password (scrypt) plus TOTP |
| Replay an authenticator code, or reuse a recovery code | Each code works once, checked again when it is recorded; recovery codes are removed when used |
| Guess passwords | 5 failures per account and address, then a 15-minute lock; 20 per address per hour; same answer and timing for wrong names |
| Steal or plant a session | Server-side sessions (only a hash is stored); a new ID at sign-in; HttpOnly, SameSite=Strict, Secure, `__Host-`; bound to address and browser |
| Make a signed-in user's browser change things (CSRF, DNS rebinding) | CSRF token, JSON only, `Origin` and `Sec-Fetch-Site` checks, host-name allow list |
| Become the first administrator | A one-time setup code readable only on the server; over HTTPS only from another computer; a wrongly set up reverse proxy can't make everyone look local |
| Inject script through report values (banners come from scanned hosts) | Everything inserted as text; CSP with a per-request nonce, no eval, no inline handlers; CSV cells that look like formulas are neutralised |

### A2. Someone who can send e-mail to the mailbox

| Threat | Control |
|---|---|
| Send a forged "Shadowserver" report | DKIM checked on the message as downloaded, with the From header bound to the signer's domain; a message the parser would read differently from the check is `permerror`; `MAIL_AUTH=enforce` holds back anything that does not pass |
| Add a header above a genuine signed report (a Content-Type of their own, read first by the parser) | More From, Content-Type, Content-Transfer-Encoding or MIME-Version headers than the signature covers: not a pass |
| A zip bomb, or names that climb out of the folder | Limits counted on the real bytes (unpacked size, ratio, files, free disk); a bomb is quarantined with its reason |
| Links to somewhere other than Shadowserver, or huge downloads | Only `https://dl.shadowserver.org/` links are followed (`LINK_RE` in `shadowserver_pipeline.py`); a download is capped at the unzip size limit |
| A report type made to skew the day's figures | One-off special reports are loaded apart, never replayed or counted in the totals and trends |

### A3. A signed-in user stepping outside their role

| Threat | Control |
|---|---|
| A researcher or external viewer reads constituent addresses | Masking on the server, with HMAC labels under `REF_SECRET`; network filters accept only aliases; report fields only from an allowlist; the one address finder every masker shares |
| Follow one rare host over time | Patterns carried by fewer than 5 hosts get no lasting code |
| Open a finding or advisory they are not part of | Findings are channels: only participants and admins |
| Change Settings, roles or accounts | Permissions checked on the server; exclusive and fixed roles; the last administrator kept; on a 5-day session, changes need a fresh sign-in after 12 hours |
| Look at or download host data quietly | Every export, and every view of host-level data with every filter of it, is an audit entry, with hosts by reference |
| Tie up the server's CPU with one request (a long run of colons for the address finder) | The finder reads candidates of at most 45 characters; logged values are cut before it reads them |
| Send an organisation a report that no longer says what the advisory's record says (edited text or TLP) | The report keeps a fingerprint of its text; drafted and sent are refused until it is generated again |
| Register a look-alike name ("Grace" beside "grace") | Names and e-mail addresses that differ only in letter case are one |

### A4. A takeover of the web app (a bug, or its Linux account)

| Threat | Control |
|---|---|
| Switch off the sender check or the unzip limits, or swap the API key | Requests that loosen the pipeline wait for a confirmation on the pipeline's account, bound to the request's SHA-256. The request folder is untrusted (no symlinks, plain small files, fixed result fields), and control characters are removed before display |
| Write to the database | The platform's account is read-only; `deploy/create_readonly_db_user.py` checks that it can't write |
| Read the database administrator's password | It is kept in `/etc/looking-glass/mongo-admin.env`, which only root can read |
| Write outside `data/` | systemd sandbox (rated by `systemd-analyze security`) |

### A5. Someone who edits the audit log

| Threat | Control |
|---|---|
| Change, insert or remove an entry | Each entry carries the SHA-256 of the one before it; `audit.head` catches entries cut from the end; archives removed by retention leave their last link |
| Delete an archive and plant notes to hide it | The chain must be whole from the seal to the head, in the portal and in the standalone verifier alike; notes are matched to their archive's rotation entry by last link and name, and every kept rotation entry must have its archive or a matching note |
| Rewrite the whole chain, with full control of the server | Not preventable on the server itself. The auditor keeps an earlier head off the server, and at the next audit it must still be at its entry number ([How the audit log proves itself](AUDIT_LOG_PROOF.md)) |

## 6. What remains

These risks are known and accepted, or left to the operator. They are listed here so nobody has to discover them.

- **Root on the server can do anything.** It can read every secret and every report, and it can rewrite the audit log.
  The audit log's protection against that lies off the server: an earlier head kept by the auditor. A user with
  passwordless sudo counts as root.
- **Data at rest is not encrypted by Looking Glass.** MongoDB, `data/` and the backups rely on file permissions
  (mode 600 and 700). Use disk encryption on the server, and keep backups somewhere equally protected. The CIS map
  says the same (LG-10 → 3.11: not backed).
- **The sender check only records by default** (`MAIL_AUTH=log`). Until an installation switches to `enforce`, a
  forged e-mail would be loaded and only flagged in the run log and the Audit portal. Using the report API avoids the
  mailbox altogether.
- **Advisories carry no digital signature.** The PDF names the CSIRT, but an organisation can't check cryptographically
  that it came from the CSIRT. It has to trust the channel the advisory arrives by.
- **`REF_SECRET` is the key to masking.** The address space of a constituency is small, so anyone who holds the secret
  can compute the label of every address and unmask the views. Treat it like a password: keep it in `.env` only, and
  change it if it leaks (the labels then change too).
- **Legitimate access is logged, not prevented.** An analyst may see addresses, and does. View logging records this,
  and it can be turned off (`DATA_ACCESS_LOG=0`), which the audit portal then shows.
- **The browser contacts outside hosts.** The map tiles come from Mapbox, the fonts from Google Fonts, and some
  libraries from cdnjs and unpkg (pinned, with integrity hashes). Those hosts see the viewer's IP address and when the
  page was opened, but no report data.
- **"Devices" are IP addresses.** One address behind NAT can be many devices, and one device on DHCP can be several
  addresses over a week. The Executive portal and its PDF say so beside the figures.
- **One server.** There is no failover. Availability depends on the server, and recovery on the backups
  (`manage/backup.sh`) being taken and kept elsewhere.
- **Dependencies come from PyPI and the CDNs** with version ranges (Python) or pinned versions with hashes (browser).
  A compromised upstream package is not something Looking Glass would catch.
- **The audit portal shows evidence, not verdicts.** Its 15 control checks give the facts, and the auditor decides.

## 7. Keeping this page true

- A new feature that crosses a boundary in section 3, or touches an asset in section 4, adds its row to section 5,
  with its control, in the same release.
- A risk that is fixed moves from section 6 to section 5. A new one is added to section 6 before the release, not
  after.
- The installation check (`platform/security_testing/security_retest.py` and `platform/tests/run_all_checks.sh`)
  must pass before a release.
