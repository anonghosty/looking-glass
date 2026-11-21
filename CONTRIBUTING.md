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
- **Code standard:** Python passes [Ruff](https://docs.astral.sh/ruff/) with the rules in [ruff.toml](ruff.toml)
  (undefined and unused names, bare `except:`, mutable or computed default arguments, late-bound loop variables and
  the like) and [Bandit](https://bandit.readthedocs.io/) with no medium or high finding; shell scripts pass
  [ShellCheck](https://www.shellcheck.net/) with no warning. All three run in CI and a change that breaks them fails.
  A finding kept on purpose is marked where it is, with the reason: `# noqa: F401  # why`, `# nosec B310  # why` or
  `# shellcheck disable=SC2024  # why`. Layout follows the file you change (PEP 8 for new Python modules).

## Checks to run

```bash
cd platform && tests/run_all_checks.sh
```

With the outside-connection guard, as GitHub's checks run: only this computer and the database may be reached, every
other connection or name look-up is refused and listed, and the run fails on any place Looking Glass has no reason to
reach (`platform/tests/no_outside/`). A made-up map key switches the map look-ups on, so a check that should send
nothing is seen if it tries. Nothing a check does can leave the computer.

```bash
cd platform && LG_NO_OUTSIDE=1 tests/run_all_checks.sh
```

```bash
cd database && .venv/bin/python -m unittest discover -s tests
```

The coding rules, from the top of the repository (`pip install ruff==0.17.6`, the version CI uses):

```bash
ruff check platform database
```

Pull requests run the same checks in CI; they must pass.

## Changing the libraries

Installations take their Python libraries only from the lock files (`platform/requirements.lock`,
`database/requirements.lock`, `docs/requirements.lock`), every file checked against its sha256 value. If your change
adds, removes or re-ranges a library in a `requirements.txt`, make the locks again in the same pull request:

```bash
cd platform && tools/lock_requirements.sh      # needs the internet; versions already locked stay as they are
```

Commit the changed `requirements.lock` files with your `requirements.txt` change. Never edit a lock by hand, and do not
add `--upgrade` unless updating every library is the point of the change. `tests/check_installer_supply.py` fails
when a lock no longer fits its `requirements.txt` (a library missing, a version outside its range, a line without its
sha256 values), and GitHub's checks install from the locks with `--require-hashes` and run pip-audit on them.
OPERATIONS.md, "Updating the libraries on purpose", has the whole procedure.

## Commits

- **Signed commits** (SSH or GPG) are required; unsigned commits are not merged.
- **Signed off, under the Developer Certificate of Origin.** Every commit carries a `Signed-off-by:` line with your
  name and e-mail, the same as the commit's author (`git commit -s` adds it). With it you certify the
  [Developer Certificate of Origin 1.1](https://developercertificate.org/): that you wrote the change, or otherwise have
  the right to submit it under the project's licence (AGPL-3.0). A pull request with a commit that is not signed off by
  its author fails the "Commits signed off" check; `git commit --amend -s` (or `git rebase --signoff`) fixes it. The
  maintainer's own commits are signed off the same way.
- Write the message in plain words: what changed and why.

## How your contribution is reviewed

Every pull request is inspected before it is merged:

1. **A maintainer reads the whole change**: what it does, what it touches, and whether it follows this guide.
2. **An automated security review** runs on the change, and each of its findings is checked by hand.
3. **The checks above** must pass, and pages that changed are looked at on a test installation.

A change may be asked to be split, reworked or declined; the reason is always given. By contributing you agree that
your contribution is licensed under the project's licence ([LICENSE](LICENSE)).
