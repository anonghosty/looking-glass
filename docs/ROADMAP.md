# Roadmap

What the project intends to work on over the next year (from November 2026). These are intentions, not promises:
priorities change with what CSIRTs ask for and with Shadowserver's reports. Each item ships with its documentation, its
tests and a note in the [CHANGELOG](https://github.com/anonghosty/looking-glass/blob/main/CHANGELOG.md).

## Reports and decoding

- **More decoded beacon formats.** Encoded check-ins that Looking Glass cannot decode yet are sent in privately through
  the [HTTP Requests Decoding](https://github.com/anonghosty/http-requests-decoding) repository; each format worked
  out there becomes a decoder in a release, written and tested with made-up values only.
- **New and changed Shadowserver reports** recognised as Shadowserver publishes them.

## Quality and security

- **Test coverage measured** on GitHub, aiming at 80% of statements.
- **Python style checked** automatically on GitHub, alongside Bandit and ShellCheck.
- **Signed advisories:** a way for an organisation to check that an advisory PDF came from its CSIRT.
- A yearly review of the [architecture and threat model](ARCHITECTURE.md).

## The project

- **Collaboration** with CSIRTs and people who want to work on Looking Glass
  ([Governance, Community](GOVERNANCE.md#community)).
- The OpenSSF Best Practices silver level.

Suggestions are welcome as [issues](https://github.com/anonghosty/looking-glass/issues).
