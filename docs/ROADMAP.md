# Roadmap

What the project intends to work on over the next year (from November 2026). These are intentions, not promises:
priorities change with what CSIRTs ask for and with Shadowserver's reports. Each item ships with its documentation, its
tests and a note in the [CHANGELOG](https://github.com/anonghosty/looking-glass/blob/main/CHANGELOG.md).

## Reports and decoding

- **More decoded beacon formats.** Encoded check-ins that Looking Glass cannot decode yet are sent in privately through
  the [HTTP Requests Decoding](https://github.com/anonghosty/http-requests-decoding) repository; each format worked
  out there becomes a decoder in a release, written and tested with made-up values only.
- **New and changed Shadowserver reports** recognised as Shadowserver publishes them.

## The mailbox and the sender check

- **Moving to enforce safely.** Settings shows when every report e-mail of the last 7 days passed the sender check,
  and only then suggests switching from recording to enforcing.
- Help for mail gateways that rewrite messages, and for reports kept in a dedicated mailbox folder.
- A daily limit for the report API, so a misconfigured schedule can't use up an account's allowance.

## Quality and security

- **Test coverage measured** on GitHub, aiming at 80% of statements.
- **Python style checked** automatically on GitHub, alongside Bandit and ShellCheck.
- **Signed advisories:** a way for an organisation to check that an advisory PDF came from its CSIRT.
- A yearly review of the [architecture and threat model](ARCHITECTURE.md).

## The project

- **A second maintainer** with administrator access to the repository and the docs site
  ([Governance, Continuity](GOVERNANCE.md#continuity)).
- The OpenSSF Best Practices silver level.

Suggestions are welcome as [issues](https://github.com/anonghosty/looking-glass/issues).
