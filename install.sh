#!/usr/bin/env bash
set -e

REPO_URL="https://github.com/h4m1dr/ward.git"
INSTALL_DIR="/opt/ward"

echo "=========================================="
echo "    WARD System Watchdog - Interactive Setup"
echo "=========================================="

if [ "$EUID" -ne 0 ]; then
  echo "[-] Please run as root."
  exit 1
fi

apt-get update -qq && apt-get install -y -qq git python3 curl

if [ -d "$INSTALL_DIR/.git" ]; then
  echo "[+] Updating local repository..."
  cd "$INSTALL_DIR"
  git reset --hard HEAD
  git pull origin main
else
  echo "[+] Cloning repository to $INSTALL_DIR..."
  git clone "$REPO_URL" "$INSTALL_DIR"
  cd "$INSTALL_DIR"
fi

# from client
echo ""
read -p "Enter Panel Title [Default: WARD Monitor]: " CUSTOM_NAME
CUSTOM_NAME=${CUSTOM_NAME:-"WARD Monitor"}

read -p "Enter Internal Service Port [Default: 54321]: " CUSTOM_PORT
CUSTOM_PORT=${CUSTOM_PORT:-54321}

read -s -p "Set Web Admin Password [Default: admin1234]: " ADMIN_PASS
echo ""
ADMIN_PASS=${ADMIN_PASS:-"admin1234"}

# hash
PASS_HASH=$(echo -n "$ADMIN_PASS" | sha256sum | awk '{print $1}')

# custom config
cat << CONFIG_EOF > "$INSTALL_DIR/config.json"
{
  "panel_name": "$CUSTOM_NAME",
  "panel_port": $CUSTOM_PORT,
  "auth_enabled": true,
  "admin_password_hash": "$PASS_HASH",
  "telegram": {
    "bot_token": "",
    "chat_id": ""
  },
  "monitored_services": ["nginx", "ssh"],
  "monitored_ports": [80, 443, 22],
  "blocked_ports_trigger": [21, 23, 3306, 5432, 6379],
  "monitored_directories": {
    "system_cache": "/var/cache",
    "tmp": "/tmp"
  },
  "monitored_apps": [
    "dockerd",
    "xray"
  ],
  "scheduled_tasks": [
    {
      "id": "t1",
      "name": "Purge Temp",
      "cron_hour": 4,
      "command": "rm -rf /tmp/*",
      "enabled": true
    }
  ]
}
CONFIG_EOF

# راه‌اندازی سرویس systemd
cp "$INSTALL_DIR/ward.service" /etc/systemd/system/ward.service
systemctl daemon-reload
systemctl enable --now ward
systemctl restart ward

echo ""
echo "=========================================="
echo "[✓] Installation Finished Successfully!"
echo "    Panel Title: $CUSTOM_NAME"
echo "    Listening on: http://127.0.0.1:$CUSTOM_PORT"
echo "    Auth Security: Active (Password Protected)"
echo ""
echo "[!] IMPORTANT NGINX NOTICE:"
echo "    In your Nginx domain config, set:"
echo "    proxy_pass http://127.0.0.1:$CUSTOM_PORT;"
echo "=========================================="
