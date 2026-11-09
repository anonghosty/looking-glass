<p align="center"><img src="static/img/logo.svg" alt="Looking Glass" width="96"></p>

# Looking Glass: platform

The web platform of Looking Glass. It reads the Shadowserver reports that the database pipeline (`../database`)
loads into MongoDB, and replays the previous day, at the same time of day, as two live platforms:

- **Reported network communications:** a 3D map of infected and attacking hosts in your country and the servers
  they reach (botnet command and control, sinkholes, honeypots), with filters, analysis and an event stream.
- **Publicly accessible / vulnerable services:** exposed and vulnerable services, devices, compromised and
  blocklisted hosts, by service, region, network and issue, with the hosts to follow up first.

Built for African national and sector CSIRTs: any of the 54 countries, with its own regions map, your
constituency's networks only if you wish, masked views for partners and public screens, and sign-in with MFA.

## Quick start

```bash
cd platform
deploy/install.sh            # Python environment, .env, data folder, service file
nano .env                    # MongoDB account, MAPBOX_TOKEN, COUNTRY
sudo cp deploy/looking-glass.service /etc/systemd/system/ && sudo systemctl daemon-reload && sudo systemctl enable --now looking-glass
```
Open http://localhost:5000 and choose **Let's get started** to create the first administrator. Full instructions,
including Windows (WSL) and Linux servers, HTTPS and firewalls: [docs/INSTALLATION.md](docs/INSTALLATION.md).

## Documentation

| Guide | For |
|---|---|
| [docs/INSTALLATION.md](docs/INSTALLATION.md) | installing on Windows with WSL 2 or on a Linux server, HTTPS, firewall, updating, troubleshooting |
| [docs/CONFIGURATION.md](docs/CONFIGURATION.md) | every setting in `.env` and on the Settings page |
| [docs/USER_GUIDE.md](docs/USER_GUIDE.md) | signing in, roles, both platforms, analysis, demo mode, Settings, administration |
| [docs/OPERATIONS.md](docs/OPERATIONS.md) | day-to-day running: service, accounts, backups, reference data, checks, diagnostics |
| [docs/TECHNICAL_REFERENCE.md](docs/TECHNICAL_REFERENCE.md) | how it works inside: data sources, replay schedule, masking, API, every script |
| [security_testing/SECURITY.md](security_testing/SECURITY.md) | how it is secured: accounts, MFA, sessions, roles, hardening, operator checklist |
| [security_testing/SECURITY_REPORT.md](security_testing/SECURITY_REPORT.md) | the penetration test and how every finding was fixed |

## Folder layout

```
platform/
├── app.py, auth.py, security.py, ...   the application (Flask)
├── gunicorn.conf.py, requirements.txt
├── .env.example                        configuration template (copy to .env)
├── templates/, static/                 pages, styles, scripts, logo, region maps of all 54 African countries
├── data/                               reference data shipped (infections.json, service_reports.json);
│                                       accounts, sessions, settings and caches are created here at run time
├── deploy/                             install.sh, service template, HTTPS certificate, reload, read-only DB account
├── manage/                             accounts, backups, network names, knowledge base, region maps
├── security_testing/                   SECURITY.md, penetration test report, security_retest.py
├── tests/                              automated checks (run_all_checks.sh, end-to-end test)
├── tools/                              database and report diagnostics
└── docs/                               the guides above
```

## Requirements

Ubuntu 24.04 or later, Desktop or Server, with systemd (on the computer itself, in a virtual machine or as Ubuntu on WSL 2; on Ubuntu Server, create the first administrator through an SSH tunnel: `ssh -L 5000:127.0.0.1:5000 user@server`, then open http://localhost:5000), Python 3.12+, MongoDB 6+ filled by the
pipeline, a free Mapbox token, and optionally a Malpedia token. The browser needs WebGL 2 (any browser from about
2021 on).

## Third-party data and services

- Shadowserver reports: https://www.shadowserver.org (your CSIRT's own free reports).
- Region boundaries: geoBoundaries gbOpen ADM1, CC BY 4.0, https://www.geoboundaries.org.
- Map tiles and place look-ups: Mapbox. 3D arcs: deck.gl. Network names: RIPEstat. Malware look-ups: Malpedia.
