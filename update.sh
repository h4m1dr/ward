#!/usr/bin/env bash
set -e

INSTALL_DIR="/opt/ward"
SERVICE_NAME="ward"

echo "[*] Checking for updates..."
cd "$INSTALL_DIR"

# بررسی ریموت گیت
git fetch origin main

LOCAL_HASH=$(git rev-parse HEAD)
REMOTE_HASH=$(git rev-parse origin/main)

if [ "$LOCAL_HASH" = "$REMOTE_HASH" ]; then
    echo "[✓] WARD is already up to date!"
    exit 0
fi

echo "[+] New version found. Updating..."
# حفظ فایل‌های کانفیگ محلی و اعمال آخرین کدهای گیت‌هاب
git reset --hard origin/main
chmod +x "$INSTALL_DIR/update.sh" 2>/dev/null || true

echo "[+] Restarting service..."
systemctl daemon-reload
systemctl restart "$SERVICE_NAME"

echo "[✓] WARD updated successfully to the latest commit!"
