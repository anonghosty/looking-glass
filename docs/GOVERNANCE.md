# Governance

How decisions about Looking Glass are made, who does what, and what happens if the maintainer is not available.

## How decisions are made

Looking Glass has one maintainer today, who makes the final decision on every change, release and security fix. The
maintainer decides in the open where the subject allows it: in issues and pull requests on
[GitHub](https://github.com/anonghosty/looking-glass), with the reason written down. Security matters are discussed
privately until a fix is released ([Security, section 6](SECURITY.md#6-reporting-a-vulnerability)).

A proposal is judged on:

- whether it helps a CSIRT act on Shadowserver reports;
- whether it keeps constituent data safe: masking for roles that must not see host identities, audit-log entries for
  sensitive actions, no real report data outside an installation;
- whether it follows the [contribution guide](https://github.com/anonghosty/looking-glass/blob/main/CONTRIBUTING.md):
  its own test, its security checks, documentation in the same change.

A declined proposal always gets its reason.

## Roles

| Role | Who | What they do |
|---|---|---|
| **Maintainer** | the owner of the GitHub repository | Reviews and merges changes, makes releases (signed commits and tags), answers security reports, keeps the documentation and the docs site current, and owns the project's settings on GitHub, Read the Docs and the OpenSSF Best Practices entry |
| **Contributor** | anyone | Opens issues and pull requests following the contribution guide, under the [code of conduct](https://github.com/anonghosty/looking-glass/blob/main/CODE_OF_CONDUCT.md) |
| **Security reporter** | anyone | Reports a vulnerability privately; is credited when it is fixed, unless they ask not to be |
| **CSIRT operator** | each installation's team | Runs their own installation and its data; reports a problem in an installation to that team, never here |

Every change, including the maintainer's own, passes the automated checks on GitHub and an automated security review
before it is released.

## Continuity

The project depends on one person today. To keep it usable if the maintainer is not available:

- Everything needed to carry on is public: the code, the full history, the documentation sources and the release notes
  are in the repository, under the AGPL-3.0 licence, so anyone can fork it and continue.
- Releases need no secret held only by the maintainer to be used: an installation updates from the public repository
  ([Installation, Updating](INSTALLATION.md#updating)).
- The project is looking for a second maintainer, from another organisation, with administrator access to the
  repository and the docs site. Until then this risk remains, and it is said here so nobody has to discover it.

## Changing this page

Changes to how the project is governed are made by pull request to this page and noted in the
[CHANGELOG](https://github.com/anonghosty/looking-glass/blob/main/CHANGELOG.md).
