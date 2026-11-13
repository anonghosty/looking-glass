# How the audit log proves itself

This guide is for auditors and for the people who answer to them. It explains how Looking Glass makes its audit log
tamper evident, how an auditor checks that without trusting Looking Glass, and what the proof does and does not
cover. The Audit portal itself is described in the [user guide](USER_GUIDE.md#the-audit-portal-audit); the protections
behind it in [SECURITY.md](SECURITY.md).

In short: every entry carries the fingerprint of the entry before it, so the fingerprint of the newest entry (the
**head**) stands for the whole log up to that point. The auditor keeps the head outside the server. At the next audit,
if that head is still at the same entry number, nothing before it was changed.

## 1. Each entry carries the hash of the one before it

The audit log (`data/audit.log`) holds one entry per line, written as JSON. When Looking Glass writes an entry, it adds
a field `prev`: the SHA-256 of the previous line, exactly as that line was written (its UTF-8 bytes, without the
newline).

```text
entry 1  {"t": …, "event": "login", "user": "grace", …, "prev": "000…000"}
entry 2  {"t": …, "event": "login_failed", …,        "prev": SHA-256(line 1)}
entry 3  {"t": …, "event": "user_role", …,           "prev": SHA-256(line 2)}
```

SHA-256 changes completely when a single character of its input changes, and no one can find two different inputs with
the same SHA-256. So:

- line 3 contains the hash of line 2;
- line 2 contains the hash of line 1;
- therefore **the hash of line 3 depends on lines 1, 2 and 3 together**. Change anything in any of them and it changes.

The first chained entry's `prev` is 64 zeros (or, after the retention has removed the oldest archives, the last hash of
the newest removed archive; see section 7).

## 2. The head

The **head** is the SHA-256 of the newest line, together with its entry number, written `hash@entry`, for example
`9f2c…a41e@1200`. Because of the chaining, that one value stands for **every entry from 1 to 1,200, exactly as
written**. Looking Glass also keeps it in `data/audit.head`, with the number of entries.

The head is shown in the Audit portal (Integrity and evidence → Verify the audit log), after every proof-package
download, and in the evidence report (PDF).

## 3. Checking the chain

Checking means reading every line and, for each one:

1. comparing its `prev` with the SHA-256 of the line before it;
2. computing its own SHA-256 for the next line to be compared with.

| What was done to the log | What the check finds |
|---|---|
| An entry was changed | its hash changes, so the next entry's `prev` no longer matches: broken right after it |
| An entry was inserted or removed | the `prev` links no longer line up: broken at that point |
| Entries were cut from the end | the last line and the number of entries no longer match `audit.head` |
| Entries cut from the end and `audit.head` deleted | a break: `audit.head` is written with every chained entry, so its absence is not excused |
| `audit.seal` deleted or rewritten, then an entry from before the chain changed | a break: the seal's count and SHA-256 are taken from its own entry in the chain (`audit_sealed`) |
| An archive deleted, with hand-written retention notes | a break unless each note is backed by the chain: its removal entry, or (for a note whose entry went with a later removal) no rotation entry of its archive left either. Archives are known by name and last link together; a note for an empty archive, or a line that is not a note, is a break |
| An archive deleted, with a note under a made-up name that carries the real last link and old dates | a break: a note is matched to its archive's rotation entry by its last link as well as by its name, so the archive's real name and dates are judged, not the note's |
| An archive deleted, with no note at all, or with a note that does not match | a break: every rotation entry still in the log must point to an archive that is there (same name, same last link) or to a retention note for exactly that archive |

The portal's **Verify the audit log** runs exactly the same code as the verifier in the proof package
(`audit_verifier.py`): one implementation, so the two can never disagree. That is still Looking Glass checking itself,
which is why the next step exists.

## 4. Checking it without Looking Glass: the proof package

**Proof package (ZIP)** (Audit portal → Integrity and evidence → Proof to take away) holds:

| File | What it is |
|---|---|
| `log/` | the log's files exactly as stored: `audit.log`, the archives (`audit_archive/*.log.gz`), the retention notes (`removed.jsonl`), `audit.head` and `audit.seal`. They are copied at one moment, under the same lock every writer of the log takes, so no entry is half written |
| `audit_log.csv` | every entry in `log/` (archives first, then `audit.log`) as a spreadsheet: one row per entry, numbered as in the chain (the last row is the head), with readable names and the detail as logged, every cell formula-safe. It is made from the same copy as `log/` and listed in `MANIFEST.json`, so the verifier reports a changed CSV. The proof is `log/`; the CSV is its readable copy for working papers |
| `MANIFEST.json` | the SHA-256 of every file in the package when it was made, and the head it holds |
| `verify_audit_log.py` | the verifier: Python 3.8 or newer, standard library only, short enough to read before relying on it |
| `README.txt` | what to keep, and how to check at the next audit |

On the auditor's own computer, with no network and no Looking Glass:

```bash
python verify_audit_log.py
```

It recomputes every link, the seal and the head, checks every file against `MANIFEST.json`, and ends with
`RESULT: verified` or `RESULT: NOT verified`, saying where the chain breaks if it does.

After the download the page shows two values to keep in the working papers: the SHA-256 of the ZIP file and its head
(`hash@entry`). Looking Glass also writes both into the audit log, so every later package carries the receipt of this
one.

### Check the verifier itself

The verifier comes in the package, from the server it checks. A tampered server could hand out a tampered verifier
that always says "verified". So do not take it on trust:

- **Compare its SHA-256** (`sha256sum verify_audit_log.py`, or `Get-FileHash verify_audit_log.py` in Windows
  PowerShell) with the one published here, outside the server:

  ```text
  6e169444581c5e056d2cf47512c34cf63f0595d00dd3aadceda3d26551aa16b3
  ```

  This is the verifier of the current release on GitHub. An installation of an older release ships the verifier of
  that release: compare with this guide in the repository's history at that release.
- **Or use the copy from GitHub** instead of the one in the package: `platform/audit_verifier.py` in
  [the repository](https://github.com/anonghosty/looking-glass), saved as `verify_audit_log.py` next to `log/`.
- **Or read it:** it is short, uses the Python standard library only, and this guide describes everything it checks.

The evidence report and the package's `README.txt` print the SHA-256 of the verifier the server handed out, to compare
with the one above.

## 5. What a whole chain cannot prove on its own

Someone with full control of the server could change entry 500, then recompute every `prev` from entry 501 to the end,
write a new `audit.head`, and rebuild a package with a new manifest. The chain would check out perfectly, because it
was rebuilt to. The test suite performs exactly this attack (`tests/check_auditor_portal.py`), and on its own the
verifier finds the rewritten log whole.

A chain proves that nothing was changed *after* it was written. It cannot, by itself, tell an original log from one
rebuilt from scratch.

## 6. The earlier head: what defeats a rewrite

At the end of an audit, the auditor writes down the head, for example `9f2c…a41e@1200`, and keeps it **outside the
server**: in the working papers, with the evidence report and the package's SHA-256.

At the next audit, they take a new proof package and run

```bash
python verify_audit_log.py --earlier 9f2c…a41e@1200
```

or enter the same value in the portal's **Compare with an earlier audit**. The check recomputes the hash of every line
of today's log and looks at entry 1,200:

| Result | What it means |
|---|---|
| **Found at entry 1,200** | that hash depends on entries 1 to 1,200, so every one of them is exactly what it was at the earlier audit. Faking this would mean finding different content with the same SHA-256, which is not feasible |
| **Not found** | the log was rewritten since, even if the chain is whole today (this is how the attack in section 5 is caught), or the head was noted wrongly |
| **Found, but at another entry number** | entries before it were added or removed |
| **Found, but the chain is broken** | the entries up to the earlier head are as they were; something after it was changed (the check says where) |

The entry number matters as much as the hash: the hash proves what the entries say, the number proves that none were
added before it or dropped.

The proof rests on the earlier head being kept where the server's operator cannot change it. A head kept only on the
server could be replaced along with the log.

## 7. Retention and the entries before the chain

**Retention.** When `data/audit.log` reaches `AUDIT_ROTATE_MB` it is compressed into `data/audit_archive/` and the
chain goes on in a new file. Archives older than `AUDIT_RETENTION_DAYS` (default 400) are deleted; the last hash and
the number of entries of each deleted archive are noted in `removed.jsonl` first, so the chain still checks out from
there, and entry numbers still count from the start of the log. Each removal is also **recorded as an entry in the
chain itself** ("Old audit archive removed by the retention": the archive, its number of entries, its newest time and
its last link), so a removal cannot be hidden or its note changed afterwards: the check reports any note without its
chain entry. A removal made between two writes is recorded with the next entry.

A removal must also have been **allowed**: an archive may only go once its newest entry is older than the retention.
The note is written by whoever removed the archive, so the two values that decide are **not taken from the note**:
the removal time is the time of the chain entry Looking Glass wrote for it, and the retention is the **setting in
force then, recorded in the chain** ("Audit log retention setting recorded": at start-up, whenever it changes, and
again right before a removal is recorded, in case its earlier record went with the removed archive). A note claiming
a later removal time or a shorter retention than the chain shows is a forged note. A removal that was not allowed
makes the check report the log as not whole, and Looking Glass records it as an **alert** ("Audit archive deleted
BEFORE its retention ended", with the reason), never as a normal one. Every change of the setting is visible too,
also a lowering that would let the retention remove recent entries; the evidence report lists the setting's history.
Logs from before the setting was recorded can only be judged by their notes: the check marks those removals "setting
not recorded". The archive's own dates are not taken from the note either: **each rotation is recorded in the chain**
("Audit log archived": the archive's name, its number of entries, its oldest and newest times and its last link),
as the first entry of the new file. That entry stays in the kept log after the archive is deleted, so a note that
disagrees with it (for example one claiming a seconds-old archive held 500-day-old entries) makes the check report
the log as not whole, and the age is judged by the recorded dates. Removals go oldest first, so the newest removed
archive's rotation entry is always among the entries kept. For archives made before rotations were recorded, the check
looks at time itself: a removed archive followed by more than `AUDIT_GAP_DAYS` (30) days without any entry is reported
for the auditor to ask about (`--gap-days` in the verifier).
The evidence report lists every removed archive with its dates and this finding. Archives are never overwritten:
two in the same second get numbered names. An earlier head that falls in a removed archive can no
longer be compared entry by entry; the check says so. Set the retention to cover the time between audits
([CONFIGURATION.md](CONFIGURATION.md#audit-portal-and-the-audit-log)).

**Entries before the chain.** Versions of Looking Glass before the chain wrote entries without `prev`. They are kept,
counted as "written before the chain started", and **sealed** once: their number, time span and the SHA-256 of all of
them go to `data/audit.seal`, and the seal itself is recorded as an entry in the chain. From then on any change to them
is detected. Nothing can prove they were unchanged before the seal, and the evidence says so.

## 8. What the proof does not cover

- **A careful rewrite of the oldest entries by someone who controls the server**, if the dates are faked well enough
  to leave no gap. The age and gap checks make a hidden deletion visible in the common cases; the auditor's earlier
  head (section 6) is what proves the entries up to it are unchanged.

- **Completeness when written.** Entries are made by the application. An action it never logged cannot be shown by any
  hash. The control checks (LG-08, LG-15) and the auditor's own testing address what is logged.
- **The time before the auditor's first head.** A rewrite made before then cannot be told apart. From the first head
  kept outside the server on, it can.
- **What lies outside the application:** the server's operating system, its clock (LG-12 reports the NTP status),
  backups and network.

## 9. An auditor's routine

1. **This audit.** Verify the log, then download the **evidence report (PDF)** and the **proof package (ZIP)**. Run
   `python verify_audit_log.py` on your own computer. Keep the ZIP's SHA-256 and the head (`hash@entry`) with your
   working papers.
2. **Next audit.** Download a new proof package and run `python verify_audit_log.py --earlier HASH@ENTRY` with the head
   you kept (or use **Compare with an earlier audit**). Keep the new head for the audit after.
3. **Every comparison and download is itself in the audit log**, with who did it and when.
