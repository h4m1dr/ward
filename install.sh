#!/usr/bin/env bash
set -e

REPO_URL="https://github.com/h4m1dr/ward"
INSTALL_DIR="/opt/ward"

echo "=========================================="
echo "    Installing WARD System Watchdog       "
echo "=========================================="

if [ "$EUID" -ne 0 ]; then
  echo "[-] Please run as root."
  exit 1
fi

apt-get update -qq && apt-get install -y -qq git python3 curl

if [ -d "$INSTALL_DIR/.git" ]; then
    echo "[+] Updating WARD installation..."
    cd "$INSTALL_DIR"
    git reset --hard HEAD
    git pull
else
    echo "[+] Cloning repository to $INSTALL_DIR..."
    git clone "$REPO_URL.git" "$INSTALL_DIR"
    cd "$INSTALL_DIR"
fi

if [ ! -f "$INSTALL_DIR/config.json" ]; then
    echo "[+] Creating initial config.json..."
    cp "$INSTALL_DIR/config.json.example" "$INSTALL_DIR/config.json"
fi

cat << 'SERVICE_EOF' > /etc/systemd/system/ward.service
[Unit]
Description=WARD - Watchdog for Applications, Resources & Directories
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/ward
ExecStart=/usr/bin/python3 /opt/ward/server.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
SERVICE_EOF

systemctl daemon-reload
systemctl enable --now ward
systemctl restart ward

echo "=========================================="
echo " [✓] WARD installed successfully!"
echo " Listening locally on: http://127.0.0.1:8765"
echo "=========================================="
