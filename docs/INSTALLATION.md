# Installing Looking Glass

## The easy way: the guided installer

On Windows, do [A1](#a1-wsl-with-systemd-and-mirrored-networking) first (systemd and mirrored networking), then
run these steps in the Ubuntu window. On Ubuntu, run them in a terminal, as the ordinary user who will run Looking Glass
(not as root).

1. **Install git**, if the computer does not have it yet:
   ```bash
   sudo apt update && sudo apt install -y git
   ```
2. **Get the code:** clone the repository and go into it.
   ```bash
   git clone https://github.com/anonghosty/looking-glass.git
   cd looking-glass
   ```
3. **Run the installer:**
   ```bash
   ./install.sh
   ```
   It asks its questions in windows (`./install.sh --text` for plain prompts), checks every answer (mailbox login,
   tokens, MongoDB, ports), installs both parts and runs the checks.
4. **Open the address it shows** and create the first administrator (see [A6](#a6-the-first-administrator-security)).

Later updates are a `git pull` in the same folder (see [Updating](#updating)).

The rest of this guide is the same installation by hand, and the background the installer's questions refer to
(access modes, HTTPS, firewall).

**MongoDB already on the computer?** The installer finds it and shows its version, port, whether it is running and
whether it requires a login. It then uses that MongoDB as it is: its configuration is never rewritten (other programs
may rely on it), a stopped MongoDB is started if you agree, and you give one of its administrator accounts. A MongoDB
that requires no login is accepted with a warning (turn on `authorization` when you can). A MongoDB in Docker, which
shows up only as a busy port, can be used the same way. If the reports database already holds data, new reports are
added and rows already there are skipped. Running the installer again on an installation it made keeps MongoDB's port,
data and administrator account: leave the MongoDB password empty and it is taken from the existing `database/.env`
(the installer stops with a clear message if it cannot find one, and never writes an empty password).

Looking Glass has two parts, installed in this order:

1. **The Shadowserver database pipeline** (`../database`): fetches your Shadowserver report e-mails every day and
   loads them into MongoDB. Install it first: [../../database/README.md](../database/README.md).
2. **The Looking Glass platform** (this folder): reads that database and replays it on the two platforms.

Two setups are supported, with the same code:

- **A. Windows with WSL 2:** Ubuntu running inside Windows on an analyst's PC or laptop.
- **B. Ubuntu Desktop or Server:** Ubuntu 24.04 or later, on its own computer or in a virtual machine. Recommended for a permanent, shared installation. On Ubuntu Server, create the first administrator through an SSH tunnel (`ssh -L 5000:127.0.0.1:5000 user@server`, then open http://localhost:5000).

Security is described in [../docs/SECURITY.md](SECURITY.md). Steps marked
**(security)** are part of the hardening and must be done on every installation.

---

## What you need

| | |
|---|---|
| Countries | the 54 African countries today (regions maps, settings, constituency); global coverage is in the pipeline |
| Operating system | Ubuntu 24.04 or later, Desktop or Server, with systemd (on the computer itself, in a virtual machine, or Ubuntu on WSL 2 on Windows 10/11) |
| Python | 3.12 or newer, with `venv` (tested on 3.14) |
| MongoDB | 6 or newer, with authentication on, filled by the database pipeline |
| Shadowserver | your CSIRT's free Shadowserver reports (https://www.shadowserver.org/what-we-do/network-reporting/) delivered to a mailbox, or fetched with your Shadowserver API key |
| Mapbox | a free account and a public access token (`pk.…`) for the map: https://account.mapbox.com |
| Malpedia (optional) | an API token, for the "Look up on Malpedia" buttons |
| Memory / disk | about 2 GB RAM for the platform. Disk: the download (`git clone`) is about 100 MB: the code itself is about 9 MB, the rest is screenshots, film posters and the history. The two Python environments the installer makes add about 120 MB. MongoDB needs space for your reports |

## Who can reach Looking Glass: `ACCESS_MODE`

| `ACCESS_MODE` | Who can open the sign-in page | Use for |
|---|---|---|
| `local` (default) | this computer only | a single analyst workstation |
| `private` | this computer + the addresses / ranges in `VIEWER_NETWORKS` | an internal deployment behind an allow list |
| `public` | any address (`VIEWER_NETWORKS=any` means the same) | an internet-facing deployment, with HTTPS in front (B5) |

In every mode, everything behind the sign-in page needs an account with MFA, and other computers can only sign in
over HTTPS. The service must also listen on the network (`deploy/install.sh --network`, or a reverse proxy) and the
firewall must let the traffic through (A6, A7, B6).

---

## A. Windows with WSL 2

### A1. WSL with systemd and mirrored networking
1. In an **administrator** PowerShell, install WSL with Ubuntu:
   ```powershell
   wsl --install -d Ubuntu-24.04
   ```
2. In Ubuntu, make sure systemd is on (the default on new installs). `/etc/wsl.conf` must contain:
   ```ini
   [boot]
   systemd=true
   ```
3. Give WSL the same network address as Windows. In `%UserProfile%\.wslconfig` on Windows:
   ```ini
   [wsl2]
   networkingMode=Mirrored
   ```
   Then restart WSL from PowerShell with `wsl --shutdown`, and open Ubuntu again.

With mirrored networking your Windows browser opens Looking Glass at `http://localhost:5000`.

### A2. Get the code, then the database
Clone the repository into your home folder; both parts are installed from it:
```bash
sudo apt update && sudo apt install -y git
cd ~ && git clone https://github.com/anonghosty/looking-glass.git looking-glass
```
Then install MongoDB and the Shadowserver pipeline from its `database` folder as described in
[../../database/README.md](../database/README.md), and let it load your reports once (`shadowserver run`).
Looking Glass needs at least one day of reports to show.

### A3. Install the platform
```bash
sudo apt install -y python3-venv python3-pip curl openssl
cd ~/looking-glass/platform
deploy/install.sh
```
`deploy/install.sh` checks Python, creates the virtual environment (`.venv`), installs the packages, creates `.env`
from `.env.example` (mode 600) and the private `data/` folder, and writes the service file `deploy/looking-glass.service`
for your user and folder. It never uses sudo; it prints the commands that need it.

Then fill in `.env` (all settings: [CONFIGURATION.md](CONFIGURATION.md)):
```bash
nano .env
```
At least: `MONGO_USER` / `MONGO_PASSWORD` (the account the pipeline created, replaced by a read-only one in A5),
`MAPBOX_TOKEN`, and `COUNTRY` (your country's two-letter code, for example `KE`, `NG`, `SN`, `ZA`).

### A4. The service **(security)**
The service listens on 127.0.0.1 only and runs sandboxed (it can write only to `data/`). Install it:
```bash
sudo cp deploy/looking-glass.service /etc/systemd/system/looking-glass.service
```
```bash
sudo systemd-analyze verify /etc/systemd/system/looking-glass.service
```
```bash
sudo systemctl daemon-reload && sudo systemctl enable --now looking-glass
```
Check that it runs, and on 127.0.0.1:5000 only:
```bash
systemctl status looking-glass --no-pager | head -5; ss -ltn | grep 5000; curl -s localhost:5000/healthz
```
After changing the code or `.env`, restart it without sudo with `deploy/reload.sh`.

**Keeping WSL running:** WSL stops when nothing from Windows uses it. For an always-on screen, start it at Windows
logon with a Task Scheduler task: trigger *At log on*, action `wsl.exe`, arguments
`-d Ubuntu-24.04 --exec sleep infinity`, and tick "Run whether user is logged on or not".

### A5. Read-only database account **(security)**
Looking Glass only reads the database. Give it an account that cannot write:
```bash
.venv/bin/python deploy/create_readonly_db_user.py && deploy/reload.sh
```
The script uses the administrator account in `.env` once, creates `lookingglass_ro` with read access only, checks
that it cannot write, and puts it in `.env`. The old file, `.env.before-readonly`, holds the administrator password:
when the database pipeline is next to the platform, the script moves that account to
`/etc/looking-glass/mongo-admin.env` (readable only by root; it asks for your sudo password) and removes the copy.
Otherwise, move the copy off the computer.

The pipeline gets its own account too, with read and write on its database only (in the database folder):
```bash
./create_pipeline_db_user.py
```
It keeps the administrator account in `/etc/looking-glass/mongo-admin.env` too, never in the project folders, where
the programs' own Linux user could read it (`sudo cat` it when you need it). The installer does all of this. When
MongoDB runs on another server, run by someone else, add `--print` to either script:
it shows the commands for that server's administrator to run, and they give you the password for `.env`. Their own
account is never needed or changed.

### A6. The first administrator **(security)**
On the computer itself (your Windows browser counts), open http://localhost:5000:
1. Click **Let's get started**. It asks for the one-time **setup code**: in a terminal, in the platform folder, run
   `cat data/setup_code` (the installer printed this command). It proves you can reach the server itself, works
   once, and is deleted when the administrator exists.
2. Enter your full name, organisation, email, country, a user name and a strong password.
3. Scan the QR code with an authenticator app (Google Authenticator, Microsoft Authenticator, Aegis, 2FAS...) and type the code it shows.
4. Keep the 8 recovery codes offline. Never paste them, or the key, into chat or email.

This first account is the administrator. Colleagues then use **Create an account** on the sign-in page, and you
approve them in **Admin → Users** with a role (external, analyst or admin; [USER_GUIDE.md](USER_GUIDE.md)).

If every administrator is ever locked out, use the command line on the computer:
```bash
manage/manage_users.py add YOURNAME --admin
```

### A7. Windows firewall **(security)**
With mirrored networking two firewall layers decide whether other computers reach port 5000: the Windows Defender
Firewall and the Hyper-V firewall for WSL. If only this computer uses Looking Glass, make sure no rule opens port
5000. In an **administrator** PowerShell, list them:
```powershell
Get-NetFirewallRule -Enabled True -Direction Inbound | Where-Object { ($_ | Get-NetFirewallPortFilter).LocalPort -contains '5000' } | Select DisplayName, Profile
```
```powershell
Get-NetFirewallHyperVRule | Where-Object { $_.LocalPorts -contains '5000' } | Select Name, DisplayName, RemoteAddresses
```
Disable any you find with `Disable-NetFirewallRule -DisplayName "<name>"` and
`Get-NetFirewallHyperVRule | Where-Object DisplayName -eq "<name>" | Remove-NetFirewallHyperVRule`.
Keep untrusted networks (hotel, mobile hotspot) on the **Public** profile.

### A8. Other screens (optional)
To show Looking Glass on a TV, a wall screen or colleagues' computers:
1. **HTTPS:** `deploy/make_tls_cert.sh` creates a certificate for this computer's names and addresses and switches
   the service to HTTPS. A self-signed certificate warns once on each screen (or install `data/tls/cert.pem` as
   trusted there); a certificate from your organisation's CA can replace the two files in `data/tls/`.
2. **Listen on the network:** run `deploy/install.sh --network`, then copy the service file again and restart (A4 commands, then `sudo systemctl restart looking-glass`).
3. **`.env`:** `ACCESS_MODE=private` with `VIEWER_NETWORKS=<screen address or range>` (for example `192.168.10.0/24`),
   or `ACCESS_MODE=public`. Other host names than the computer's own go in `ALLOWED_HOSTS`. Then `deploy/reload.sh`.
4. **Firewall:** open port 5000 to those screens only, on the **Private** profile, in both layers (administrator PowerShell):
   ```powershell
   New-NetFirewallRule -DisplayName "Looking Glass (screens)" -Direction Inbound -Protocol TCP -LocalPort 5000 -RemoteAddress <screen-address> -Profile Private -Action Allow
   ```
   ```powershell
   New-NetFirewallHyperVRule -Name LookingGlassScreens -DisplayName "Looking Glass (screens)" -Direction Inbound -VMCreatorId '{40E0AC32-46A5-438A-A0B2-2B479E8F2E90}' -Protocol TCP -LocalPorts 5000 -RemoteAddresses <screen-address> -Action Allow
   ```
5. **On the screen:** open `https://<computer-name>:5000` and sign in. For a public screen, use an **external**
   account (always masked) or set `PUBLIC_DEMO=1`, and tick **Stay signed in for 5 days**.

---

## B. Linux server (Ubuntu / Debian)

### B1. System and database
```bash
sudo apt update && sudo apt install -y python3-venv python3-pip git curl openssl ufw
sudo adduser --system --group --home /opt/looking-glass lookingglass     # a dedicated service account
sudo -u lookingglass -H git clone https://github.com/anonghosty/looking-glass.git /opt/looking-glass/src   # the code
```
Install MongoDB and the pipeline from `/opt/looking-glass/src/database` ([../../database/README.md](../database/README.md)). Keep
`net.bindIp: 127.0.0.1` and `security.authorization: enabled` in `/etc/mongod.conf`. If MongoDB runs on another
server, allow only this server to reach it, and use TLS for MongoDB.

### B2. Platform
```bash
sudo -u lookingglass -H bash -c 'cd /opt/looking-glass/src/platform && deploy/install.sh'   # the code is from B1
sudoedit /opt/looking-glass/src/platform/.env          # MongoDB, MAPBOX_TOKEN, COUNTRY (CONFIGURATION.md)
```

### B3. Service **(security)**
`install.sh` wrote `deploy/looking-glass.service` for the `lookingglass` user and the folder above, listening on
127.0.0.1 only: the reverse proxy (B5) is the only thing that talks to it.
```bash
cd /opt/looking-glass/src/platform
sudo cp deploy/looking-glass.service /etc/systemd/system/
sudo systemd-analyze verify /etc/systemd/system/looking-glass.service
sudo systemctl daemon-reload && sudo systemctl enable --now looking-glass
systemd-analyze security looking-glass --no-pager | tail -1
```

### B4. Accounts and database **(security)**
```bash
sudo -u lookingglass .venv/bin/python deploy/create_readonly_db_user.py && sudo systemctl restart looking-glass
```
Create the first administrator: read the setup code on the server (`sudo -u lookingglass cat data/setup_code` in the
platform folder), then open http://localhost:5000 in a browser on the server, or tunnel to it over SSH
(`ssh -L 5000:127.0.0.1:5000 you@server`, then open http://localhost:5000 on your computer), or, once the reverse
proxy below is set up, its HTTPS address; choose **Let's get started** and type the code. Or on the command line:
```bash
sudo -u lookingglass manage/manage_users.py add YOURNAME --admin
```

### B5. HTTPS with a reverse proxy **(security)**
**Caddy** (simplest: it gets and renews certificates by itself when the name is reachable from the internet; on an
internal network use your CA or `tls internal`). In `/etc/caddy/Caddyfile`:
```
lookingglass.example.org {
    reverse_proxy 127.0.0.1:5000
    encode gzip
}
```
**nginx** alternative:
```nginx
server {
    listen 443 ssl http2;
    server_name lookingglass.example.org;
    ssl_certificate     /etc/ssl/lookingglass/fullchain.pem;
    ssl_certificate_key /etc/ssl/lookingglass/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    add_header Strict-Transport-Security "max-age=31536000" always;
    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host $host;
        client_max_body_size 64k;
    }
}
server { listen 80; server_name lookingglass.example.org; return 301 https://$host$request_uri; }
```
In `.env`:
- `TRUST_PROXY=1`: the real client address and `https` come from the proxy's headers, so session binding, address checks and Secure cookies work. The proxy **must** send `X-Forwarded-For` (Caddy does by itself; for nginx keep the `proxy_set_header` lines above): a request without it is refused, because it would look like it came from the server itself. The headers are believed only from a proxy on this computer. With `TRUST_PROXY=1`, an SSH tunnel to port 5000 is refused too (it carries no such header): use the proxy's address;
- `ALLOWED_HOSTS=lookingglass.example.org`;
- `ACCESS_MODE=private` with `VIEWER_NETWORKS=` your CSIRT's address ranges, or `ACCESS_MODE=public` for an internet-facing site.

Then `sudo systemctl restart looking-glass`.

### B6. Firewall
```bash
sudo ufw default deny incoming && sudo ufw allow OpenSSH
sudo ufw allow from 10.20.0.0/24 to any port 443 proto tcp     # your CSIRT network only (or: sudo ufw allow 443/tcp)
sudo ufw enable
```
Port 5000 and MongoDB's 27017 stay closed to the network.

---

## After installing (both setups)

1. Check the security protections (about 2 minutes); it must end with **ALL PASSED**:
   ```bash
   security_testing/security_retest.py
   ```
2. Check both platforms against the database:
   ```bash
   tests/run_all_checks.sh
   ```
3. Open Looking Glass, sign in, and open **Settings** to choose your country and constituency ([USER_GUIDE.md](USER_GUIDE.md)).
4. Build the network-name registry for your country (company names instead of AS numbers):
   ```bash
   .venv/bin/python manage/asn_registry.py 7
   ```
5. In your Mapbox account, restrict the token to your site's address.
6. Back up (`manage/backup.sh`) and copy the archive off the computer. Day-to-day running: [OPERATIONS.md](OPERATIONS.md).

## Updating

```bash
manage/backup.sh
git pull
.venv/bin/pip install -r requirements.txt
.venv/bin/python tests/check_libraries.py   # the libraries: inside the tested versions, and working
deploy/reload.sh                     # or: sudo systemctl restart looking-glass
security_testing/security_retest.py && tests/run_all_checks.sh
```
`requirements.txt` lets each library update within its major version only, so an update brings fixes but no big
changes. If `check_libraries.py` fails, its line names the library.
If `deploy/looking-glass.service.template` changed, run `deploy/install.sh` again and copy the service file again (A4 / B3).

## Uninstalling

Run `./uninstall.sh` from the top of the Looking Glass folder (the one with `install.sh`), as the user who installed
it. It shows what it will remove and what it keeps, and asks before it starts.

| Command | Removes | Keeps |
|---|---|---|
| `./uninstall.sh` | the platform service, the pipeline's schedule, the global `shadowserver` command (man page, completion) | the reports database, MongoDB, this folder (settings, accounts, findings, audit log) |
| `./uninstall.sh --remove-database` | also the reports database and the accounts `lookingglass_pipeline` and `lookingglass_ro`, and `/etc/looking-glass` | other databases and accounts in the same MongoDB |
| `./uninstall.sh --remove-mongodb` | also MongoDB itself and **all** its data, only if Looking Glass installed it | a MongoDB that was there before Looking Glass (never touched) |
| `./uninstall.sh --remove-files` | also this folder | — |
| `./uninstall.sh --all` | everything above | system packages (python3, cron, curl…) |

- `./uninstall.sh --dry-run` (with any of the options) shows what would be done and changes nothing.
- Deleting data needs a typed confirmation: the database name, `remove-mongodb`, or the folder name. Unattended:
  `--yes --i-understand-data-loss`.
- It removes only what belongs to **this** folder. Another installation's service, schedule or command, other cron
  jobs, and a MongoDB that Looking Glass did not install are left alone.
- **Back up first** if you may want the data again: `platform/manage/backup.sh` for the platform, and `mongodump`
  for the reports.
- Firewall rules you added for the platform's port (A7 / B6) are not removed: remove them yourself.
- After `./uninstall.sh` without options, `./install.sh` in the same folder installs again with the kept settings
  and data.

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `install.sh`: Python too old | Ubuntu 24.04 or later (Desktop or Server), or install a newer `python3` |
| Service does not start | `journalctl -u looking-glass -n 50`; usually `.env` (MongoDB address or account) or a path in the service file |
| Pages load but show no data | The database has no reports for the replay day yet: check the pipeline (`shadowserver status`), and `tools/diagnose_reports.py` |
| "Unknown host name" (400) | The name in the address bar is not allowed: add it to `ALLOWED_HOSTS` (or `*` for any name) |
| "Looking Glass is not available from your network" (403) | `ACCESS_MODE` is `local`, or the address is not in `VIEWER_NETWORKS` |
| Sign-in page says the connection is not encrypted | Other computers must use HTTPS (A8 / B5) |
| Authenticator: "illegal character" | Type the key without spaces |
| Code always "wrong" | The phone's clock is off: turn on automatic time |
| "Too many failed attempts" | Wait 15 minutes, or restart the service |
| Signed out unexpectedly | Idle or maximum time reached, password changed, or the session was used from another address or browser |
| Map blank | Check `MAPBOX_TOKEN` and the browser console; the map needs WebGL 2 (a browser from about 2021 on) |
| Something is blocked by the browser | Set `CSP_REPORT_ONLY=1`, restart, look at the browser console, and set it back to 0 |
