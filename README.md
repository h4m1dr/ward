# WARD (v1.0.0)

> **Watchdog for Applications, Resources & Directories**  
> An ultra-lightweight, zero-database Linux server monitoring daemon, interactive drag-and-drop web dashboard, and Telegram Mini App.

---

## ⚡ Highlights

- **Zero Heavy Dependencies:** Written entirely in pure Python 3 using direct Linux `/proc` kernel interfaces—no external libraries (`psutil`, `flask`, etc.).
- **Interactive Multi-Row UI:** Drag-and-drop dashboard layout with persistent card positions (CPU, Memory, Swap, Disk storage, Dual-stream network speed, and socket connections).
- **Password-Protected Access:** Built-in session token authentication and SHA-256 hash validation to secure the dashboard.
- **High-Precision Telemetry:** Real-time native canvas graphs tracking load averages, exact metrics, and peak spikes.
- **Pinned Process Watchlist:** Persistent monitoring for bookmarked services and applications without noise from kernel threads.
- **Live Task Manager Snapshot:** On-demand full system process inspection with single-click pinning to the permanent watchlist.
- **Service Logs Inspector:** Real-time `journalctl` log viewer for systemd services.
- **Security Watchdog:** Proactive socket tracking with instant Telegram alert triggers if specified blocked/closed ports are opened.
- **Interactive Management CLI:** All-in-one terminal menu for installation, configuration tuning, service control, and log debugging.
- **In-Panel Self-Updater:** Checks GitHub for new releases and updates the daemon in the background with a single click.

---

## 🚀 Quick Installation & Management

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

Rerunning the same command anytime gives you access to:

* **Install / Update:** Automated setup flow.
* **Edit Configuration:** Modify port, title, installation path, or admin password on the fly.
* **Service Health & Logs:** Restart the daemon, check systemd status, or view live `journalctl` output.
* **Uninstall:** Clean removal of all files and systemd units.

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
5. Set the Web App URL to your domain:
```text
https://your-subdomain.domain.com

```


6. Define a short name for the URL.
7. Launch the Mini App button inside your chat to monitor server metrics directly in Telegram.

---

## 🔄 Updating WARD

* **Via Web Dashboard:** If an update is detected on GitHub, an **Update** badge appears in the header. Clicking it will pull changes and restart the daemon.
* **Via CLI:** Run the install command and select option `1` to pull the latest version:
```bash
bash <(curl -fsSL https://raw.githubusercontent.com/h4m1dr/ward/main/install.sh)

```



---

## 📄 License

Distributed under the [MIT License](https://www.google.com/search?q=LICENSE).


---
