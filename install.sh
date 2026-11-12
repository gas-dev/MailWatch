#!/usr/bin/env bash
set -euo pipefail
if [[ "$(id -u)" -ne 0 ]]; then echo "Esegui con sudo bash install.sh"; exit 1; fi
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y git python3-venv python3-pip
id mailwatch >/dev/null 2>&1 || useradd --system --home /var/lib/mailwatch --shell /usr/sbin/nologin mailwatch
install -d -o root -g root -m 0755 /opt/mailwatch
install -d -o mailwatch -g mailwatch -m 0700 /var/lib/mailwatch
install -d -o root -g root -m 0700 /etc/mailwatch
cp mailwatch.py google_mail.py requirements.txt /opt/mailwatch/
/usr/bin/python3 -m venv /opt/mailwatch/.venv
/opt/mailwatch/.venv/bin/python -m pip install -r /opt/mailwatch/requirements.txt
if [[ ! -f /etc/mailwatch/service.env ]]; then
  read -r -s -p "Scegli password amministratore MailWatch (minimo 16 caratteri): " PASS
  echo
  if [[ $(printf %s "$PASS" | wc -c) -lt 16 ]]; then echo "Password troppo breve"; exit 1; fi
  export MW_PASSWORD="$PASS"
  /opt/mailwatch/.venv/bin/python - <<'PY'
import os,secrets
from werkzeug.security import generate_password_hash
p="/etc/mailwatch/service.env"
with open(p,"w") as f:
    f.write("MAILWATCH_DATA=/var/lib/mailwatch\n")
    f.write("MAILWATCH_SESSION_KEY="+secrets.token_hex(32)+"\n")
    f.write("MAILWATCH_ADMIN_HASH="+generate_password_hash(os.environ["MW_PASSWORD"])+"\n")
os.chmod(p,0o600)
PY
  unset PASS MW_PASSWORD
fi
cat > /etc/systemd/system/mailwatch.service <<'UNIT'
[Unit]
Description=MailWatch by Techitapp
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
User=mailwatch
Group=mailwatch
WorkingDirectory=/opt/mailwatch
EnvironmentFile=/etc/mailwatch/service.env
ExecStart=/opt/mailwatch/.venv/bin/python /opt/mailwatch/mailwatch.py
Restart=always
RestartSec=10
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/mailwatch
UMask=0077
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable --now mailwatch
echo
echo "MailWatch installato. Stato:"
systemctl --no-pager --full status mailwatch | head -15
echo
echo "Interfaccia disponibile solo sul Raspberry: http://127.0.0.1:8092"
echo "Per aprirla dal tuo PC: ssh -L 8092:127.0.0.1:8092 USER@YOUR-SERVER"
