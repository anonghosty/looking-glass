# Contributing to Looking Glass

Thank you for helping. Looking Glass handles data about vulnerable and compromised devices in a country, so every
contribution is held to a security-first standard. Please read this page before opening an issue or a pull request.

Everyone taking part follows the [Code of Conduct](CODE_OF_CONDUCT.md).

## Before you start

- **Security problems are never public issues.** Report them privately through the repository's Security tab
  (**Report a vulnerability**), as described in the [security policy](docs/SECURITY.md).
- **Never post real data.** No real IP addresses, host names, e-mail addresses, network names of constituents, or
  extracts of Shadowserver reports, in issues, pull requests, screenshots, tests or examples. Use the documentation
  ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32) and `example.org`.
- **Accessibility counts.** Changes to pages follow the [accessibility statement](ACCESSIBILITY.md).
- For a larger change, open an issue first so we can agree on the approach.

## Opening a good issue

Use the forms offered when you click **New issue**: a bug report, a feature request, or an accessibility barrier.

- One problem or idea per issue.
- For a bug: the version (commit) you run, what you did, what you expected, what happened, and the relevant log lines
  with any constituent data removed.
- For a feature: the problem it solves for an analyst, researcher, manager, advisor or administrator, before the
  solution.

How decisions are made and who does what: [Governance](docs/GOVERNANCE.md). What is planned next:
[Roadmap](docs/ROADMAP.md).

## Setting up

Follow [docs/INSTALLATION.md](docs/INSTALLATION.md) on a test machine, never on an installation that holds real
reports. The demo data (`lg_demo`) is enough for nearly every change.

## Making a change

- **One change per pull request**, with a clear title and the reason for it.
- **New features go in their own module**, called from `app.py` / `app.js`; large existing files get small fixes only.
- **Every feature carries its security checks**: permission and channel checks on the server, the CSRF token on every
  change, masking for masked roles (researchers never see host identities), and audit-log entries for sensitive
  actions.
- **Every feature carries its own test** in `platform/tests/`, added to `tests/run_all_checks.sh` and to the CI list
  in `.github/workflows/checks.yml`. Tests use made-up data only.
- **Text shows in full.** No cut-off text on pages or in PDFs; lists wrap.
- **Readable names, not internal identifiers**, wherever people read them.
- **Documentation** is updated in the same pull request when behaviour or a setting changes.
- **Code standard:** Python passes [Bandit](https://bandit.readthedocs.io/) with no medium or high finding and shell
  scripts pass [ShellCheck](https://www.shellcheck.net/) with no warning (both run in CI). A finding kept on purpose is
  marked where it is, with the reason: `# nosec B310  # why` or `# shellcheck disable=SC2024  # why`. Follow the style
  of the file you change (PEP 8 for new Python modules).

## Checks to run

```bash
cd platform && tests/run_all_checks.sh
```

```bash
cd database && .venv/bin/python -m unittest discover -s tests
```

Pull requests run the same checks in CI; they must pass.

## Commits

- **Signed commits** (SSH or GPG) are required; unsigned commits are not merged.
- Write the message in plain words: what changed and why.

## How your contribution is reviewed

Every pull request is inspected before it is merged:

1. **A maintainer reads the whole change**: what it does, what it touches, and whether it follows this guide.
2. **An automated security review** runs on the change, and each of its findings is checked by hand.
3. **The checks above** must pass, and pages that changed are looked at on a test installation.

A change may be asked to be split, reworked or declined; the reason is always given. By contributing you agree that
your contribution is licensed under the project's licence ([LICENSE](LICENSE)).
