# WARD (v1.0.0)

> **Watchdog for Applications, Resources & Directories**  
> An ultra-lightweight, zero-database Linux server monitoring daemon, interactive drag-and-drop web dashboard, and Telegram Mini App.

---

## ⚡ Highlights

- **Zero Heavy Dependencies:** Written entirely in pure Python 3 using direct Linux `/proc` kernel interfaces—no external libraries (`psutil`, `flask`, etc.).
- **Interactive Multi-Row UI:** Drag-and-drop dashboard layout with persistent card positions (CPU, Memory, Swap, Disk storage, Dual-stream network speed, and socket connections).
- **Password-Protected Access:** Built-in session token authentication and SHA-256 hash validation to secure the dashboard.
- **High-Precision Telemetry:** Real-time native canvas graphs with background reference grids and vertical percentage scales tracking exact metrics, averages, and peak spikes.
- **Pinned Process Watchlist:** Persistent monitoring for bookmarked services and applications without noise from kernel threads.
- **Live Scanners & Task Manager:** On-demand inspection popups for all running OS processes, active systemd daemons, and listening network sockets with single-click watchlist pinning.
- **Directory Tree Explorer:** Built-in storage subfolder inspector to audit directory sizes and track targets with a single click.
- **Service Logs Inspector:** Real-time `journalctl` log viewer for systemd services.
- **Security Watchdog:** Proactive socket tracking with instant Telegram alert triggers if specified blocked/closed ports are opened.
- **Dedicated Quick Updater:** Lightweight background updating engine via panel button or instant CLI command (`ward-update`).
- **Interactive Management CLI:** All-in-one terminal menu for clean setup, configuration tuning, service control, and log debugging.

---

## 🚀 Quick Installation & Setup

Run the interactive management script on your server (Ubuntu / Debian):

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/h4m1dr/ward/main/install.sh)

```

### Setup Options

When prompted, you can configure:

1. **Target Directory:** Default is `/opt/ward`.
2. **Panel Title:** Custom name displayed on the dashboard.
3. **Internal Port:** Custom port for local daemon binding (e.g., `54321`).
4. **Admin Password:** Access password for web authorization.

### CLI Management Menu

Rerunning the same script anytime gives you access to:

* **Install WARD:** Clean automated setup flow.
* **Edit Configuration:** Modify port, title, installation path, or admin password on the fly.
* **Service Health & Logs:** Restart the daemon, check systemd status, or view live `journalctl` output.
* **Uninstall:** Clean removal of all files and systemd units.

---

## 🔄 Updating WARD

Updates do not require reinstalling or re-entering your configuration.

* **Via Web Dashboard:** When a new release is detected on GitHub, an **Update** badge appears in the header. Clicking it opens a modal to apply the update immediately in the background.
* **Via Terminal (One Word):** Run the globally registered updater command anytime:

```bash
ward-update

```

*(Or manually via: `bash /opt/ward/update.sh`)*

---

## 🌐 Nginx Reverse Proxy Setup

To serve WARD securely over HTTPS with your custom domain or subdomain, add the following block to your Nginx configuration:

```nginx
server {
    server_name your-subdomain.domain.com;

    listen 443 ssl http2;
    # ssl_certificate /path/to/fullchain.pem;
    # ssl_certificate_key /path/to/privkey.pem;

    location / {
        # Replace 54321 with your configured internal port
        proxy_pass [http://127.0.0.1:54321](http://127.0.0.1:54321);
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}

```

Reload Nginx after saving:

```bash
nginx -t && systemctl reload nginx

```

---

## 📱 Telegram Mini App (TMA) Integration

1. Open Telegram and start a chat with [@BotFather](https://t.me/BotFather).
2. Send the `/newapp` command and select your bot.
3. Choose a title (e.g., `WARD Monitor`) and short description.
4. Upload an application icon.
5. Set the Web App URL to your HTTPS domain:

```text
https://your-subdomain.domain.com

```

6. Define a short name for the URL.
7. Launch the Mini App button inside your chat to monitor server metrics directly in Telegram.

---

## 📄 License

Distributed under the [MIT License](https://www.google.com/search?q=LICENSE).


---
