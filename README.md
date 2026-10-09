# WARD (v1.0.0)

> **Watchdog for Applications, Resources & Directories**  
> An ultra-lightweight, zero-database server monitoring daemon, interactive drag-and-drop web dashboard, and Telegram Mini App.

---

## ⚡ Key Highlights

- **Zero External Dependencies:** Pure Python 3 daemon using direct `/proc` kernel interfaces—no `psutil`, no `flask`.
- **Draggable Multi-Row UI:** Persistent drag-and-drop metric cards (CPU, RAM, SWAP, Storage, Dual-stream network speed, and socket connections).
- **High-Precision Telemetry:** Real-time canvas graphs with moving averages, real peak load tracking, and exact scale markers.
- **Pinned Process Watchlist:** Persistent watchlist for bookmarked processes—no rotating or cluttered system processes.
- **On-Demand Live Task Manager:** Scan all running system PIDs with a single click and pin workloads instantly.
- **Service Logs Inspector:** Instant journalctl log inspector for systemd daemons.
- **Proactive Port Security:** Continuous socket listener tracking with emergency Telegram alerts if trapped/blocked ports are opened.
- **In-Panel Self-Updater:** Checks GitHub for new releases and updates itself with a single click.

---

## 🚀 One-Line Installation

Run the following command on your server (Ubuntu / Debian):

```bash
curl -fsSL [https://raw.githubusercontent.com/h4m1dr/ward/main/install.sh](https://raw.githubusercontent.com/h4m1dr/ward/main/install.sh) | bash

```

The daemon will be installed at `/opt/ward` and will run locally as a systemd service on `127.0.0.1:8765`.

---

## 🌐 Nginx Reverse Proxy Setup

If you use Nginx to manage SSL and subdomains, add this block to your site configuration:

```nginx
server {
    server_name 9z.ykno.ir;

    listen 443 ssl http2;
    # Add your SSL certificate paths:
    # ssl_certificate /path/to/fullchain.pem;
    # ssl_certificate_key /path/to/privkey.pem;

    location / {
        proxy_pass [http://127.0.0.1:8765](http://127.0.0.1:8765);
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

## 📱 Telegram Mini App (TMA) Setup

1. Open Telegram and start a chat with [@BotFather](https://t.me/BotFather).
2. Send the `/newapp` command.
3. Select your bot.
4. Set the title to `WARD Monitor` and provide a short description.
5. Upload a square icon/image for the application.
6. When prompted for the Web App URL, enter your HTTPS domain:
```text
[https://9z.ykno.ir](https://9z.ykno.ir)

```


7. Define a short name for the URL.
8. Open the web app button directly inside your Telegram chat to view the live dashboard.

---

## 🔄 Self-Updating

* **From Web Panel:** When a new version is pushed to GitHub, an update banner appears in the header. Click the button to trigger a background pull and restart.
* **From CLI:**
```bash
cd /opt/ward && git pull origin main && systemctl restart ward

```



---

## 📄 License

Distributed under the [MIT License](https://www.google.com/search?q=LICENSE).


---
