#!/usr/bin/env bash
# Install Looking Glass in this folder: Python environment, .env, data folder and the systemd unit file.
# Run it as the user the service will run as (not root). It never uses sudo itself: the last step prints the
# sudo commands that install the service, for you to run.
#
#   deploy/install.sh                 this computer only (127.0.0.1:5000)
#   deploy/install.sh --network       other screens too (0.0.0.0:5000; also set ACCESS_MODE in .env and use HTTPS)
#   deploy/install.sh --port N        listen on port N instead of 5000
#   deploy/install.sh --name NAME     service name (default: looking-glass)
set -euo pipefail
cd "$(dirname "$0")/.."
project="$(pwd)"
name="looking-glass"; host="127.0.0.1"; port=5000
while [ $# -gt 0 ]; do
  case "$1" in
    --network) host="0.0.0.0"; shift ;;
    --port) port="${2:?--port needs a number}"; shift 2 ;;
    --name) name="${2:?--name needs a value}"; shift 2 ;;
    -h|--help) sed -n '2,9p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option $1 (deploy/install.sh --help)"; exit 1 ;;
  esac
done
case "$port" in ''|*[!0-9]*) echo "--port needs a number"; exit 1 ;; esac
bind="$host:$port"
step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
[ "$(id -u)" != 0 ] || { echo "Run this as the user the service will run as, not as root."; exit 1; }

step "1. Python"
command -v python3 >/dev/null || { echo "python3 is missing: sudo apt install python3 python3-venv"; exit 1; }
python3 - <<'EOF'
import sys
v = sys.version_info
print(f"python3 {v.major}.{v.minor}.{v.micro}")
if v < (3, 12):
    sys.exit("Looking Glass needs Python 3.12 or newer (Ubuntu 24.04 or later ships it).")
EOF
python3 -m venv --help >/dev/null 2>&1 || { echo "python3-venv is missing: sudo apt install python3-venv"; exit 1; }

step "2. Virtual environment and packages (.venv)"
[ -x .venv/bin/python ] || python3 -m venv .venv
.venv/bin/pip install --quiet --upgrade pip
.venv/bin/pip install --quiet -r requirements.txt
.venv/bin/python -c "import flask, pymongo, dotenv, gunicorn; print('packages ok')"

step "3. Configuration (.env) and data folder"
if [ ! -f .env ]; then
  cp .env.example .env
  echo "created .env from .env.example: fill in MongoDB and MAPBOX_TOKEN (docs/CONFIGURATION.md)"
else
  echo ".env exists (kept)"
fi
chmod 600 .env
if grep -qE '^LG_PORT=' .env; then sed -i "s/^LG_PORT=.*/LG_PORT=$port/" .env; else printf '\n# Port the service listens on (set by deploy/install.sh)\nLG_PORT=%s\n' "$port" >> .env; fi
mkdir -p data && chmod 700 data
find deploy manage security_testing tests tools -maxdepth 1 \( -name '*.sh' -o -name '*.py' \) -exec chmod +x {} +

step "4. Service unit (deploy/$name.service)"
sed -e "s|@USER@|$(id -un)|g" -e "s|@PROJECT@|$project|g" -e "s|@BIND@|$bind|g" \
  deploy/looking-glass.service.template > "deploy/$name.service"
echo "written for user $(id -un), folder $project, listening on $bind"
if ! pidof systemd >/dev/null 2>&1 && [ ! -d /run/systemd/system ]; then
  echo "systemd is not running here. On WSL, enable it first (docs/INSTALLATION.md, part A1)."
fi

step "Next steps"
cat <<EOF
1. Edit .env (MongoDB address and account, MAPBOX_TOKEN):   nano $project/.env
2. Install and start the service (needs sudo):
     sudo cp $project/deploy/$name.service /etc/systemd/system/$name.service
     sudo systemctl daemon-reload
     sudo systemctl enable --now $name
3. Check it:  curl -s localhost:$port/healthz      logs: journalctl -u $name -f
4. Open http://localhost:$port in a browser and choose "Let's get started" to create the first administrator.
   It asks for the one-time setup code: cat $(pwd)/data/setup_code
5. Other screens: deploy/make_tls_cert.sh (HTTPS), ACCESS_MODE in .env, firewall (docs/INSTALLATION.md).
EOF
