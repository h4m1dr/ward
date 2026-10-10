import os
import sys
import json
import time
import socket
import secrets
import hashlib
import subprocess
import threading
import urllib.request
import urllib.parse
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime

# Dynamic base path resolution
INSTALL_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(INSTALL_DIR, "config.json")
VERSION_PATH = os.path.join(INSTALL_DIR, "version.json")

_active_sessions = set()
_prev_idle = 0
_prev_total = 0
_prev_net_rx = 0
_prev_net_tx = 0
_prev_net_time = 0
_known_listening_ports = set()
_proc_cpu_prev = {}

def hash_pw(pw):
    return hashlib.sha256(pw.encode('utf-8')).hexdigest()

def load_config():
    default_config = {
        "panel_name": "WARD Monitor",
        "panel_port": 54321,
        "auth_enabled": True,
        "admin_password_hash": hash_pw("admin1234"),
        "telegram": {"bot_token": "", "chat_id": ""},
        "monitored_services": ["nginx", "ssh"],
        "monitored_ports": [80, 443, 22],
        "blocked_ports_trigger": [21, 23, 3306, 5432, 6379],
        "monitored_directories": {"system_cache": "/var/cache", "tmp": "/tmp"},
        "monitored_apps": ["dockerd", "xray"],
        "scheduled_tasks": [],
        # NEW: Theme Customizer Default Values
        "theme": {
            "primary": "#4a9eff",
            "success": "#00d68f",
            "danger": "#ff4757",
            "bg": "#0f1419",
            "card": "#1a2332",
            "text": "#e4e8f1"
        }
    }
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, 'r') as f:
                data = json.load(f)
                # Merge safely to ensure new keys (like theme) are added to old configs
                for key, value in default_config.items():
                    if key not in data:
                        data[key] = value
                return data
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

# ... [get_cpu_info, get_network_stats, get_active_listening_ports, get_dir_size_mb remain EXACTLY the same as before] ...
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
    return sorted(list(ports))

def get_dir_size_mb(path):
    if not os.path.exists(path):
        return 0.0
    try:
        res = subprocess.run(["du", "-sm", path], capture_output=True, text=True)
        if res.returncode == 0:
            return float(res.stdout.split()[0])
    except Exception:
        pass
    return 0.0

# --- FIXED: Robust Folder Explorer ---
def explore_directory_tree(path):
    if not os.path.exists(path) or not os.path.isdir(path):
        return []
    items = []
    try:
        # Use 2>/dev/null to suppress "Permission denied" errors and ensure clean output
        cmd = f"du -sm --max-depth=1 '{path}' 2>/dev/null"
        res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if res.returncode == 0:
            for line in res.stdout.strip().split("\n"):
                parts = line.split("\t")
                if len(parts) == 2:
                    try:
                        sz_mb = float(parts[0])
                        sub_path = parts[1].strip()
                        if sub_path != path and os.path.basename(sub_path):
                            items.append({
                                "name": os.path.basename(sub_path),
                                "path": sub_path,
                                "size_mb": sz_mb
                            })
                    except ValueError:
                        continue # Skip malformed lines
        # Sort by size descending
        items.sort(key=lambda x: x["size_mb"], reverse=True)
    except Exception:
        pass
    return items

def scan_all_processes():
    global _proc_cpu_prev
    procs = []
    total_mem = 1
    try:
        with open('/proc/meminfo', 'r') as f:
            for line in f:
                if "MemTotal" in line:
                    total_mem = int(line.split()[1]) * 1024
                    break
    except Exception:
        pass

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
                "pid": int(pid),
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

def scan_systemd_services():
    services = []
    try:
        res = subprocess.run(["systemctl", "list-units", "--type=service", "--all", "--no-pager", "--no-legend"], capture_output=True, text=True)
        for line in res.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 4 and parts[0].endswith(".service"):
                s_name = parts[0][:-8]
                s_state = parts[3]
                services.append({"name": s_name, "state": s_state, "sub": parts[2]})
    except Exception:
        pass
    services.sort(key=lambda x: x["name"])
    return services

def get_pinned_apps(pinned_names):
    all_procs = scan_all_processes()
    proc_dict = {}
    for p in all_procs:
        if p["name"] not in proc_dict:
            proc_dict[p["name"]] = p.copy()
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
    try:
        with open('/proc/meminfo', 'r') as f:
            for line in f:
                parts = line.split(':')
                mem[parts[0].strip()] = int(parts[1].split()[0]) // 1024
    except Exception:
        pass
        
    avail_ram = mem.get('MemAvailable', 0)
    total_ram = mem.get('MemTotal', 1)
    used_ram = total_ram - avail_ram

    total_swap = mem.get('SwapTotal', 1)
    free_swap = mem.get('SwapFree', 0)
    used_swap = total_swap - free_swap

    try:
        st = os.statvfs('/')
        total_disk = round((st.f_blocks * st.f_frsize) / (1024**3), 2)
        free_disk = round((st.f_bavail * st.f_frsize) / (1024**3), 2)
        used_disk = round(total_disk - free_disk, 2)
        used_disk_pct = round((used_disk / total_disk) * 100, 1)
    except Exception:
        total_disk = free_disk = used_disk = used_disk_pct = 0.0

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

    tcp_count = 0
    udp_count = 0
    try:
        tcp_count = len([1 for l in open("/proc/net/tcp").readlines() if not l.strip().startswith("sl")])
        udp_count = len([1 for l in open("/proc/net/udp").readlines() if not l.strip().startswith("sl")])
    except Exception:
        pass

    uptime = "0d 0h 0m"
    load_avg = "0.0 / 0.0 / 0.0"
    try:
        with open("/proc/uptime") as f:
            s = float(f.readline().split()[0])
            uptime = f"{int(s//86400)}d {int((s%86400)//3600)}h {int((s%3600)//60)}m"
        with open("/proc/loadavg") as f:
            p = f.readline().split()
            load_avg = f"{p[0]} / {p[1]} / {p[2]}"
    except Exception:
        pass

    return {
        "panel_name": cfg.get("panel_name", "WARD"),
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "uptime": uptime,
        "load_avg": load_avg,
        "cpu": cpu_data,
        "ram": {"used_mb": used_ram, "total_mb": total_ram, "pct": round((used_ram/total_ram)*100, 1) if total_ram > 0 else 0.0},
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
        "tasks": cfg.get("scheduled_tasks", []),
        "theme": cfg.get("theme", default_config["theme"]) # Return theme to frontend
    }

class RequestHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def is_authenticated(self):
        cfg = load_config()
        if not cfg.get("auth_enabled", True):
            return True
        token = self.headers.get("X-Session-Token", "")
        if not token:
            cookies = self.headers.get("Cookie", "")
            for c in cookies.split(";"):
                if "ward_token=" in c:
                    token = c.split("ward_token=")[1].strip()
        return token in _active_sessions

    def do_GET(self):
        if self.path == "/api/auth/status":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            cfg = load_config()
            self.wfile.write(json.dumps({
                "authenticated": self.is_authenticated(),
                "panel_name": cfg.get("panel_name", "WARD"),
                "theme": cfg.get("theme", {})
            }).encode("utf-8"))
            return

        if not self.is_authenticated() and self.path not in ["/", "/index.html"]:
            self.send_response(401)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"error": "Unauthorized"}')
            return

        if self.path == "/api/status":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(collect_metrics()).encode("utf-8"))
            
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
            self.wfile.write(json.dumps({
                "current": curr_v,
                "latest": remote_v,
                "has_update": (remote_v != curr_v)
            }).encode("utf-8"))
            
        elif self.path == "/api/taskmanager/snapshot":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"processes": scan_all_processes()}).encode("utf-8"))
            
        elif self.path == "/api/services/snapshot":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"services": scan_systemd_services()}).encode("utf-8"))
            
        elif self.path == "/api/ports/snapshot":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"ports": get_active_listening_ports()}).encode("utf-8"))
            
        elif self.path.startswith("/api/storage/explore?"):
            qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            target = qs.get("path", ["/"])[0]
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"path": target, "items": explore_directory_tree(target)}).encode("utf-8"))
            
        elif self.path.startswith("/api/service/logs?"):
            qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            srv = qs.get("name", [""])[0]
            logs = "No logs available"
            if srv:
                res = subprocess.run(["journalctl", "-u", "ward", "-n", "35", "--no-pager"], capture_output=True, text=True)
                logs = res.stdout or res.stderr
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(logs.encode("utf-8"))

        elif self.path == "/api/tasks/list":
            cfg = load_config()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"tasks": cfg.get("scheduled_tasks", [])}).encode("utf-8"))

        elif self.path == "/api/settings/config":
            cfg = load_config()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"config": cfg}).encode("utf-8"))
            
        elif self.path in ["/", "/index.html"]:
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            index_path = os.path.join(INSTALL_DIR, "index.html")
            if os.path.exists(index_path):
                with open(index_path, "rb") as f:
                    self.wfile.write(f.read())
            else:
                self.send_response(404)
                self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        length = int(self.headers.get('content-length', 0))
        payload = json.loads(self.rfile.read(length).decode('utf-8')) if length > 0 else {}
        
        if self.path == "/api/auth/login":
            pw = payload.get("password", "")
            cfg = load_config()
            if hash_pw(pw) == cfg.get("admin_password_hash"):
                token = secrets.token_hex(24)
                _active_sessions.add(token)
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Set-Cookie", f"ward_token={token}; Path=/; HttpOnly; SameSite=Lax")
                self.end_headers()
                self.wfile.write(json.dumps({"status": "ok", "token": token}).encode("utf-8"))
            else:
                self.send_response(401)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"status": "error", "message": "Invalid Password"}')
            return

        if not self.is_authenticated():
            self.send_response(401)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"error": "Unauthorized"}')
            return

        cfg = load_config()

        if self.path == "/api/system/apply-update":
            update_script = os.path.join(INSTALL_DIR, "update.sh")
            if not os.path.exists(update_script):
                self.send_response(500)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"error": "update.sh script not found"}')
                return

            def do_up():
                time.sleep(1.5)
                try:
                    os.chmod(update_script, 0o755)
                    subprocess.run(["bash", update_script], capture_output=True, text=True)
                except Exception:
                    pass

            threading.Thread(target=do_up, daemon=True).start()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status": "updating"}')
            return

        if self.path == "/api/auth/logout":
            token = self.headers.get("X-Session-Token", "")
            _active_sessions.discard(token)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Set-Cookie", "ward_token=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT")
            self.end_headers()
            self.wfile.write(b'{"status": "ok"}')
            return

        # --- NEW: Theme Update Endpoint ---
        if self.path == "/api/settings/update-theme":
            new_theme = payload.get("theme", {})
            if "theme" not in cfg:
                cfg["theme"] = {}
            cfg["theme"].update(new_theme)
            save_config(cfg)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status": "ok"}')
            return

        if self.path == "/api/settings/change-password":
            old_pw = payload.get("old_password", "")
            new_pw = payload.get("new_password", "")
            if hash_pw(old_pw) == cfg.get("admin_password_hash"):
                cfg["admin_password_hash"] = hash_pw(new_pw)
                save_config(cfg)
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"status": "ok"}')
            else:
                self.send_response(401)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"status": "error", "message": "Current password is incorrect"}')
            return

        elif self.path == "/api/settings/restore-config":
            new_cfg = payload.get("config", {})
            if "admin_password_hash" in new_cfg and "panel_port" in new_cfg:
                save_config(new_cfg)
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"status": "ok"}')
            else:
                self.send_response(400)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"status": "error", "message": "Invalid config format"}')
            return

        elif self.path == "/api/tasks/add":
            tasks = cfg.setdefault("scheduled_tasks", [])
            tasks.append({
                "name": payload.get("name"),
                "command": payload.get("command"),
                "schedule_type": payload.get("schedule_type"),
                "schedule_value": payload.get("schedule_value"),
                "enabled": payload.get("enabled", True)
            })
            save_config(cfg)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status": "ok"}')
            return

        elif self.path == "/api/tasks/toggle":
            idx = payload.get("index")
            tasks = cfg.get("scheduled_tasks", [])
            if isinstance(idx, int) and 0 <= idx < len(tasks):
                tasks[idx]["enabled"] = payload.get("enabled", True)
                save_config(cfg)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status": "ok"}')
            return

        elif self.path == "/api/tasks/delete":
            idx = payload.get("index")
            tasks = cfg.get("scheduled_tasks", [])
            if isinstance(idx, int) and 0 <= idx < len(tasks):
                tasks.pop(idx)
                save_config(cfg)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status": "ok"}')
            return

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

        save_config(cfg)
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"status": "ok"}')

if __name__ == "__main__":
    cfg = load_config()
    port = int(cfg.get("panel_port", 54321))
    server = HTTPServer(("127.0.0.1", port), RequestHandler)
    print(f"WARD Server running on port {port}")
    server.serve_forever()
