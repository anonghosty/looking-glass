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

The portal's **Verify the audit log** does this on the server. That is Looking Glass checking itself, which is why the
next step exists.

## 4. Checking it without Looking Glass: the proof package

**Proof package (ZIP)** (Audit portal → Integrity and evidence → Proof to take away) holds:

| File | What it is |
|---|---|
| `log/` | the log's files exactly as stored: `audit.log`, the archives (`audit_archive/*.log.gz`), the retention notes (`removed.jsonl`), `audit.head` and `audit.seal`. They are copied at one moment, under the same lock every writer of the log takes, so no entry is half written |
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
there, and entry numbers still count from the start of the log. An earlier head that falls in a removed archive can no
longer be compared entry by entry; the check says so. Set the retention to cover the time between audits
([CONFIGURATION.md](CONFIGURATION.md#audit-portal-and-the-audit-log)).

**Entries before the chain.** Versions of Looking Glass before the chain wrote entries without `prev`. They are kept,
counted as "written before the chain started", and **sealed** once: their number, time span and the SHA-256 of all of
them go to `data/audit.seal`, and the seal itself is recorded as an entry in the chain. From then on any change to them
is detected. Nothing can prove they were unchanged before the seal, and the evidence says so.

## 8. What the proof does not cover

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
