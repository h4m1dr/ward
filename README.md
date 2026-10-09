# WARD (v1.0.0)

> **Watchdog for Applications, Resources & Directories**  
> An ultra-lightweight, zero-database server monitoring daemon, interactive drag-and-drop web dashboard, and Telegram Mini App.

---

## ⚡ Key Highlights

- **Zero External Dependencies:** Pure Python 3 daemon using direct `/proc` kernel interfaces—no heavy third-party packages.
- **Draggable Multi-Row UI:** Persistent drag-and-drop metric cards (CPU, RAM, SWAP, Storage, Dual-stream network speed, and active sockets).
- **Password Protected (Auth):** Secure session token authentication to block unauthorized access.
- **High-Precision Telemetry:** Real-time canvas graphs with moving averages and peak load calculations.
- **Pinned Process Watchlist:** Persistent watchlist for bookmarked processes—no rotating or cluttered system processes.
- **On-Demand Live Task Manager:** Scan active system processes on the fly without cluttering your persistent watchlist.
- **Service Logs Inspector:** Instant journalctl log inspector for systemd daemons.
- **Proactive Port Security:** Continuous socket listener tracking with emergency Telegram alerts if trapped ports are opened.
- **In-Panel Self-Updater:** Checks GitHub for new releases and updates itself with a single click.

---

## 🚀 One-Line Installation

Run the interactive installer on your server (Ubuntu / Debian):

```bash
curl -fsSL [https://raw.githubusercontent.com/h4m1dr/ward/main/install.sh](https://raw.githubusercontent.com/h4m1dr/ward/main/install.sh) | bash

```

During installation, you will be prompted to set:

1. **Panel Title:** Custom name displayed in the header.
2. **Internal Port:** Custom port (Default: `54321`) for local binding.
3. **Admin Password:** Access password for the web dashboard.

---

## 🌐 Nginx Reverse Proxy Setup

To expose the dashboard behind SSL and your custom domain, configure an Nginx server block:

```nginx
server {
    server_name your-subdomain.domain.com;

    listen 443 ssl http2;
    # ssl_certificate /path/to/fullchain.pem;
    # ssl_certificate_key /path/to/privkey.pem;

    location / {
        # Replace 54321 with your chosen port from the installer
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

Reload Nginx:

```bash
nginx -t && systemctl reload nginx

```

---

## 📱 Telegram Mini App (TMA) Setup

1. Open Telegram and start a chat with [@BotFather](https://t.me/BotFather).
2. Send the `/newapp` command.
3. Select your notification bot.
4. Set the title and description for your app.
5. Upload a square icon/image.
6. When prompted for the Web App URL, enter your HTTPS domain:
```text
[https://your-subdomain.domain.com](https://your-subdomain.domain.com)

```


7. Define a short name for the URL.
8. Open the web app button directly inside your Telegram chat to view the live dashboard.

---

## 🔄 Self-Updating

* **From Web Panel:** When a new release is pushed to GitHub, an update banner appears in the header. Click the button to trigger a background pull and daemon restart.
* **From CLI:**
```bash
cd /opt/ward && git pull origin main && systemctl restart ward

```

---

## 📄 License

Distributed under the [MIT License](https://www.google.com/search?q=LICENSE).


---
