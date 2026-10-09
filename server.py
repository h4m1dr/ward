import os
import sys
import json
import time
import socket
import subprocess
import threading
import urllib.request
import urllib.parse
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime

PORT = 8765
CONFIG_PATH = "/opt/ward/config.json"
VERSION_PATH = "/opt/ward/version.json"

_prev_idle = 0
_prev_total = 0
_prev_net_rx = 0
_prev_net_tx = 0
_prev_net_time = 0
_known_listening_ports = set()
_proc_cpu_prev = {}

def load_config():
    default_config = {
        "telegram": {"bot_token": "", "chat_id": ""},
        "monitored_services": ["nginx", "ssh"],
        "monitored_ports": [80, 443, 22],
        "blocked_ports_trigger": [21, 23, 3306, 5432, 6379],
        "monitored_directories": {"system_cache": "/var/cache", "tmp": "/tmp"},
        "monitored_apps": ["dockerd", "xray"],
        "scheduled_tasks": [
            {"id": "t1", "name": "Purge Temp", "cron_hour": 4, "command": "rm -rf /tmp/*", "enabled": True}
        ]
    }
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, 'r') as f:
                return json.load(f)
        except Exception:
            return default_config
    return default_config

def save_config(cfg):
    try:
        with open(CONFIG_PATH, 'w') as f:
            json.dump(cfg, f, indent=2)
        return True
    except Exception:
        return False

def send_telegram_alert(text):
    cfg = load_config()
    token = cfg.get("telegram", {}).get("bot_token")
    chat_id = cfg.get("telegram", {}).get("chat_id")
    if not token or not chat_id:
        return
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = urllib.parse.urlencode({"chat_id": chat_id, "text": f"[WARD Alert]\n{text}"}).encode("utf-8")
    try:
        req = urllib.request.Request(url, data=payload, method="POST")
        urllib.request.urlopen(req, timeout=5)
    except Exception:
        pass

def get_cpu_info():
    global _prev_idle, _prev_total
    model = "Linux Processor"
    cores = 0
    try:
        with open("/proc/cpuinfo", "r") as f:
            for line in f:
                if "model name" in line and model == "Linux Processor":
                    model = line.split(":", 1)[1].strip()
                elif "processor" in line:
                    cores += 1
    except Exception:
        pass

    cpu_percent = 0.0
    try:
        with open("/proc/stat", "r") as f:
            fields = [float(x) for x in f.readline().strip().split()[1:]]
            idle = fields[3] + fields[4]
            total = sum(fields)
            diff_idle = idle - _prev_idle
            diff_total = total - _prev_total
            if diff_total > 0:
                cpu_percent = round((1.0 - (diff_idle / diff_total)) * 100, 1)
            _prev_idle = idle
            _prev_total = total
    except Exception:
        pass
    return {"model": model, "cores": max(cores, 1), "usage_pct": max(0.0, min(100.0, cpu_percent))}

def get_network_stats():
    global _prev_net_rx, _prev_net_tx, _prev_net_time
    total_rx = 0
    total_tx = 0
    try:
        with open("/proc/net/dev", "r") as f:
            lines = f.readlines()[2:]
            for line in lines:
                parts = line.split()
                iface = parts[0].strip(":")
                if iface != "lo":
                    total_rx += int(parts[1])
                    total_tx += int(parts[9])
    except Exception:
        pass

    now = time.time()
    diff_t = max(now - _prev_net_time, 0.001) if _prev_net_time > 0 else 1.0
    speed_rx = round(max((total_rx - _prev_net_rx), 0) / (diff_t * 1024 * 1024), 2) if _prev_net_time > 0 else 0.0
    speed_tx = round(max((total_tx - _prev_net_tx), 0) / (diff_t * 1024 * 1024), 2) if _prev_net_time > 0 else 0.0
    _prev_net_rx = total_rx
    _prev_net_tx = total_tx
    _prev_net_time = now

    return {
        "total_rx_gib": round(total_rx / (1024**3), 2),
        "total_tx_gib": round(total_tx / (1024**3), 2),
        "speed_rx_mb": speed_rx,
        "speed_tx_mb": speed_tx
    }

def get_active_listening_ports():
    global _known_listening_ports
    ports = set()
    try:
        res = subprocess.run(["ss", "-tuln"], capture_output=True, text=True)
        for line in res.stdout.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 5:
                addr = parts[4]
                port_str = addr.rsplit(":", 1)[-1]
                if port_str.isdigit():
                    ports.add(int(port_str))
    except Exception:
        pass

    cfg = load_config()
    for bp in cfg.get("blocked_ports_trigger", []):
        if int(bp) in ports and int(bp) not in _known_listening_ports:
            send_telegram_alert(f"⚠️ Critical Port Opened: Monitored port {bp} is now listening!")
    _known_listening_ports = ports
    return sorted(list(ports))

def get_dir_size_mb(path):
    if not os.path.exists(path):
        return 0.0
    total = 0
    for root, dirs, files in os.walk(path):
        for f in files:
            fp = os.path.join(root, f)
            if not os.path.islink(fp):
                try:
                    total += os.path.getsize(fp)
                except OSError:
                    pass
    return round(total / (1024 * 1024), 2)

def scan_all_processes():
    global _proc_cpu_prev
    procs = []
    total_mem = 1
    with open('/proc/meminfo', 'r') as f:
        for line in f:
            if "MemTotal" in line:
                total_mem = int(line.split()[1]) * 1024
                break
    now = time.time()
    for pid in [p for p in os.listdir('/proc') if p.isdigit()]:
        try:
            with open(f"/proc/{pid}/comm", "r") as f:
                comm = f.readline().strip()
            with open(f"/proc/{pid}/stat", "r") as f:
                sp = f.readline().split()
                total_time = int(sp[13]) + int(sp[14])
            with open(f"/proc/{pid}/status", "r") as f:
                vm_rss = 0
                threads = 1
                for s in f:
                    if s.startswith("VmRSS:"):
                        vm_rss = int(s.split()[1]) * 1024
                    elif s.startswith("Threads:"):
                        threads = int(s.split()[1])
            if vm_rss == 0:
                continue
            cpu = 0.0
            if pid in _proc_cpu_prev:
                old_time, old_t = _proc_cpu_prev[pid]
                dt = now - old_t
                if dt > 0:
                    cpu = round(((total_time - old_time) / (dt * 100)), 1)
            _proc_cpu_prev[pid] = (total_time, now)
            procs.append({
                "pid": pid,
                "name": comm,
                "cpu_pct": max(0.0, min(100.0, cpu)),
                "memory_mb": round(vm_rss / (1024 * 1024), 2),
                "memory_pct": round((vm_rss / total_mem) * 100, 1),
                "threads": threads
            })
        except Exception:
            continue
    procs.sort(key=lambda x: x["memory_mb"], reverse=True)
    return procs

def get_pinned_apps(pinned_names):
    all_procs = scan_all_processes()
    proc_dict = {}
    for p in all_procs:
        if p["name"] not in proc_dict:
            proc_dict[p["name"]] = p
        else:
            proc_dict[p["name"]]["memory_mb"] += p["memory_mb"]
            proc_dict[p["name"]]["memory_pct"] = round(proc_dict[p["name"]]["memory_pct"] + p["memory_pct"], 1)
            proc_dict[p["name"]]["cpu_pct"] = round(proc_dict[p["name"]]["cpu_pct"] + p["cpu_pct"], 1)
            proc_dict[p["name"]]["threads"] += p["threads"]

    result = []
    for name in pinned_names:
        if name in proc_dict:
            item = proc_dict[name].copy()
            item["status"] = "Active"
            result.append(item)
        else:
            result.append({
                "pid": "-", "name": name, "cpu_pct": 0.0, "memory_mb": 0.0,
                "memory_pct": 0.0, "threads": 0, "status": "Stopped"
            })
    return result

def collect_metrics():
    cfg = load_config()
    cpu_data = get_cpu_info()
    net_data = get_network_stats()
    active_ports = get_active_listening_ports()

    mem = {}
    with open('/proc/meminfo', 'r') as f:
        for line in f:
            parts = line.split(':')
            mem[parts[0].strip()] = int(parts[1].split()[0]) // 1024
    avail_ram = mem.get('MemAvailable', 0)
    total_ram = mem.get('MemTotal', 1)
    used_ram = total_ram - avail_ram
    total_swap = mem.get('SwapTotal', 1)
    free_swap = mem.get('SwapFree', 0)
    used_swap = total_swap - free_swap

    st = os.statvfs('/')
    total_disk = round((st.f_blocks * st.f_frsize) / (1024**3), 2)
    free_disk = round((st.f_bavail * st.f_frsize) / (1024**3), 2)
    used_disk = round(total_disk - free_disk, 2)
    used_disk_pct = round((used_disk / total_disk) * 100, 1)

    services_state = {}
    for s in cfg.get("monitored_services", []):
        res = subprocess.run(["systemctl", "is-active", "--quiet", s])
        services_state[s] = "Running" if res.returncode == 0 else "Down"

    watched_ports = {}
    for p in cfg.get("monitored_ports", []):
        watched_ports[str(p)] = "Listening" if int(p) in active_ports else "Closed"

    dir_sizes = {}
    for name, path in cfg.get("monitored_directories", {}).items():
        dir_sizes[name] = {"path": path, "size_mb": get_dir_size_mb(path)}

    pinned_apps = get_pinned_apps(cfg.get("monitored_apps", []))

    tcp_count = len([1 for l in open("/proc/net/tcp").readlines() if not l.strip().startswith("sl")])
    udp_count = len([1 for l in open("/proc/net/udp").readlines() if not l.strip().startswith("sl")])

    with open("/proc/uptime") as f:
        s = float(f.readline().split()[0])
        uptime = f"{int(s//86400)}d {int((s%86400)//3600)}h {int((s%3600)//60)}m"
    with open("/proc/loadavg") as f:
        p = f.readline().split()
        load_avg = f"{p[0]} / {p[1]} / {p[2]}"

    return {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "uptime": uptime,
        "load_avg": load_avg,
        "cpu": cpu_data,
        "ram": {"used_mb": used_ram, "total_mb": total_ram, "pct": round((used_ram/total_ram)*100, 1)},
        "swap": {"used_mb": used_swap, "total_mb": total_swap, "pct": round((used_swap/max(total_swap, 1))*100, 1)},
        "disk": {"used_gb": used_disk, "free_gb": free_disk, "total_gb": total_disk, "pct": used_disk_pct},
        "network": net_data,
        "connections": {"tcp": tcp_count, "udp": udp_count},
        "services": services_state,
        "ports": watched_ports,
        "all_open_ports": active_ports,
        "blocked_ports": cfg.get("blocked_ports_trigger", []),
        "caches": dir_sizes,
        "apps": pinned_apps,
        "tasks": cfg.get("scheduled_tasks", [])
    }

class RequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/api/status":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps(collect_metrics()).encode("utf-8"))
        elif self.path == "/api/taskmanager/snapshot":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps({"processes": scan_all_processes()}).encode("utf-8"))
        elif self.path.startswith("/api/service/logs?"):
            qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            srv = qs.get("name", [""])[0]
            logs = "No logs available"
            if srv:
                res = subprocess.run(["journalctl", "-u", srv, "-n", "35", "--no-pager"], capture_output=True, text=True)
                logs = res.stdout or res.stderr
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(logs.encode("utf-8"))
        elif self.path == "/api/system/check-update":
            curr_v = "1.0.0"
            if os.path.exists(VERSION_PATH):
                try:
                    with open(VERSION_PATH) as f:
                        curr_v = json.load(f).get("version", "1.0.0")
                except Exception:
                    pass
            remote_v = curr_v
            try:
                url = "https://raw.githubusercontent.com/h4m1dr/ward/main/version.json"
                req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
                with urllib.request.urlopen(req, timeout=4) as response:
                    data = json.loads(response.read().decode())
                    remote_v = data.get("version", curr_v)
            except Exception:
                pass
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps({"current": curr_v, "latest": remote_v, "has_update": remote_v != curr_v}).encode("utf-8"))
        elif self.path in ["/", "/index.html"]:
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            with open("/opt/ward/index.html", "rb") as f:
                self.wfile.write(f.read())
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        length = int(self.headers.get('content-length', 0))
        payload = json.loads(self.rfile.read(length).decode('utf-8'))
        cfg = load_config()

        if self.path == "/api/config/add":
            t, v = payload.get("type"), payload.get("value")
            if t == "app" and v not in cfg.get("monitored_apps", []):
                cfg.setdefault("monitored_apps", []).append(v)
            elif t == "service" and v not in cfg.get("monitored_services", []):
                cfg.setdefault("monitored_services", []).append(v)
            elif t == "port" and int(v) not in cfg.get("monitored_ports", []):
                cfg.setdefault("monitored_ports", []).append(int(v))
            elif t == "blocked_port" and int(v) not in cfg.get("blocked_ports_trigger", []):
                cfg.setdefault("blocked_ports_trigger", []).append(int(v))
            elif t == "directory":
                cfg["monitored_directories"][payload.get("name")] = v
        elif self.path == "/api/config/remove":
            t, v = payload.get("type"), payload.get("value")
            if t == "app":
                cfg["monitored_apps"] = [x for x in cfg.get("monitored_apps", []) if x != v]
            elif t == "service":
                cfg["monitored_services"] = [x for x in cfg.get("monitored_services", []) if x != v]
            elif t == "port":
                cfg["monitored_ports"] = [x for x in cfg.get("monitored_ports", []) if str(x) != str(v)]
            elif t == "blocked_port":
                cfg["blocked_ports_trigger"] = [x for x in cfg.get("blocked_ports_trigger", []) if str(x) != str(v)]
            elif t == "directory":
                cfg["monitored_directories"].pop(v, None)
        elif self.path == "/api/system/apply-update":
            def do_up():
                time.sleep(1)
                subprocess.run("cd /opt/ward && git fetch && git reset --hard origin/main && systemctl restart ward", shell=True)
            threading.Thread(target=do_up, daemon=True).start()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status":"updating"}')
            return

        save_config(cfg)
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(b'{"status":"ok"}')

if __name__ == "__main__":
    server = HTTPServer(("127.0.0.1", PORT), RequestHandler)
    server.serve_forever()
