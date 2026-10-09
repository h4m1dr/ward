#!/usr/bin/env bash
set -e

INSTALL_DIR="/opt/ward"
SERVICE_NAME="ward"
CONFIG_BACKUP="/tmp/ward_config_backup.json"

echo "[*] Checking for updates..."
cd "$INSTALL_DIR"

# Fetch the latest changes from the remote repository
git fetch origin main

LOCAL_HASH=$(git rev-parse HEAD)
REMOTE_HASH=$(git rev-parse origin/main)

if [ "$LOCAL_HASH" = "$REMOTE_HASH" ]; then
    echo "[✓] WARD is already up to date!"
    exit 0
fi

echo "[+] New version found. Updating..."

# Safety net: Backup local configuration before applying changes
if [ -f "$INSTALL_DIR/config.json" ]; then
    cp "$INSTALL_DIR/config.json" "$CONFIG_BACKUP"
fi

# Apply the latest code from GitHub
git reset --hard origin/main

# Restore configuration if it was accidentally removed (extra safety layer)
if [ ! -f "$INSTALL_DIR/config.json" ] && [ -f "$CONFIG_BACKUP" ]; then
    mv "$CONFIG_BACKUP" "$INSTALL_DIR/config.json"
    echo "[+] Configuration restored safely."
else
    rm -f "$CONFIG_BACKUP"
fi

# Ensure executable permissions for core scripts
chmod +x "$INSTALL_DIR/update.sh" 2>/dev/null || true
chmod +x "$INSTALL_DIR/server.py" 2>/dev/null || true

echo "[+] Restarting service..."
systemctl daemon-reload
systemctl restart "$SERVICE_NAME"

echo "[✓] WARD updated successfully to the latest commit!"
