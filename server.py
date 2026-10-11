import os
import sys
import json
import time
import socket
import secrets
import hashlib
import subprocess
import signal
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime
from collections import deque

INSTALL_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(INSTALL_DIR, "config.json")
VERSION_PATH = os.path.join(INSTALL_DIR, "version.json")

_active_sessions = set()
_event_log = deque(maxlen=100)
_prev_net = {}
_prev_net_time = 0.0
_prev_cpu = {}
_prev_disk = {}
_proc_cpu_prev = {}

# LAW #1 & LAW #2: Protected PIDs (Never kill/terminate)
SELF_PID = os.getpid()
PROTECTED_PIDS = {1, SELF_PID}

def hash_pw(pw):
    return hashlib.sha256(pw.encode('utf-8')).hexdigest()

def log_event(severity, title, message, source="system"):
    _event_log.append({
        "id": secrets.token_hex(8),
        "timestamp": int(time.time()),
        "severity": severity,
        "title": title,
        "message": message,
        "source": source
    })

def load_config():
    default_config = {
        "panel_name": "WARD Monitor",
        "panel_port": 7654,
        "auth_enabled": True,
        "admin_password_hash": hash_pw("admin1234"),
        "monitored_services": ["nginx", "ssh"],
        "monitored_ports": [80, 443, 22],
        "monitored_directories": {"system_cache": "/var/cache", "tmp": "/tmp"},
        "watched_processes": [
            {"name": "nginx", "alias": "Nginx Server", "row_id": 1},
            {"name": "xray", "alias": "Xray Core", "row_id": 2},
            {"name": "dockerd", "alias": "Docker Daemon", "row_id": 3}
        ]
    }
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, 'r') as f:
                data = json.load(f)
                for k, v in default_config.items():
                    if k not in data:
                        data[k] = v
                return data
        except Exception:
            return default_config
    return default_config

def save_config(cfg):
    tmp_path = CONFIG_PATH + ".tmp"
    try:
        with open(tmp_path, 'w') as f:
            json.dump(cfg, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, CONFIG_PATH)
        return True
    except Exception:
        if os.path.exists(tmp_path):
            try: os.remove(tmp_path)
            except: pass
        return False

def is_protected_pid(pid):
    if pid in PROTECTED_PIDS or pid < 100:
        return True
    try:
        with open(f"/proc/{pid}/comm", "r") as f:
            comm = f.readline().strip()
            if comm in ["systemd", "kthreadd", "sshd", "init", "ward"]:
                return True
    except Exception:
        pass
    return False

def get_cpu_telemetry():
    global _prev_cpu
    model = "Linux Processor"
    cores = os.cpu_count() or 1
    user_pct = sys_pct = io_pct = total_pct = 0.0

    try:
        with open("/proc/stat", "r") as f:
            fields = [int(x) for x in f.readline().split()[1:]]
        user, nice, system, idle, iowait = fields[0], fields[1], fields[2], fields[3], fields[4]
        total = sum(fields[:7])

        if _prev_cpu:
            du = user - _prev_cpu.get('user', user)
            ds = system - _prev_cpu.get('system', system)
            di = iowait - _prev_cpu.get('iowait', iowait)
            dt = total - _prev_cpu.get('total', total)
            if dt > 0:
                user_pct = round(max(0.0, (du / dt) * 100), 1)
                sys_pct = round(max(0.0, (ds / dt) * 100), 1)
                io_pct = round(max(0.0, (di / dt) * 100), 1)
                total_pct = min(100.0, round(user_pct + sys_pct + io_pct, 1))

        _prev_cpu = {'user': user, 'system': system, 'iowait': iowait, 'total': total}
    except Exception:
        pass

    return {
        "model": model, "cores": cores, "total_percent": total_pct,
        "user_percent": user_pct, "system_percent": sys_pct, "iowait_percent": io_pct
    }

def get_memory_telemetry():
    mem = {}
    try:
        with open('/proc/meminfo', 'r') as f:
            for line in f:
                p = line.split(':')
                mem[p[0].strip()] = int(p[1].split()[0]) * 1024
    except Exception:
        pass
    total = mem.get('MemTotal', 1)
    avail = mem.get('MemAvailable', 0)
    cached = mem.get('Cached', 0)
    swap_total = mem.get('SwapTotal', 0)
    swap_free = mem.get('SwapFree', 0)

    return {
        "total_bytes": total, "used_bytes": max(0, total - avail),
        "available_bytes": avail, "cached_bytes": cached,
        "swap_total_bytes": swap_total, "swap_used_bytes": max(0, swap_total - swap_free)
    }

def get_disk_telemetry():
    global _prev_disk
    mount = "/"
    device = "sda"
    r_speed = w_speed = 0

    try:
        st = os.statvfs(mount)
        d_total = st.f_blocks * st.f_frsize
        d_free = st.f_bavail * st.f_frsize
        d_used = d_total - d_free
    except Exception:
        d_total = d_free = d_used = 0

    now = time.time()
    try:
        with open("/proc/diskstats", "r") as f:
            for line in f:
                p = line.split()
                if len(p) >= 14 and (p[2].startswith("sd") or p[2].startswith("vd") or p[2].startswith("nvme")):
                    device = p[2]
                    rd_sec = int(p[5]) * 512
                    wr_sec = int(p[9]) * 512
                    if device in _prev_disk:
                        dt = max(0.001, now - _prev_disk[device]['time'])
                        r_speed = round(max(0, rd_sec - _prev_disk[device]['rd']) / dt)
                        w_speed = round(max(0, wr_sec - _prev_disk[device]['wr']) / dt)
                    _prev_disk[device] = {'rd': rd_sec, 'wr': wr_sec, 'time': now}
                    break
    except Exception:
        pass

    return {
        "mount_point": mount, "device": device, "total_bytes": d_total,
        "used_bytes": d_used, "free_bytes": d_free,
        "read_bytes_sec": r_speed, "write_bytes_sec": w_speed
    }

def get_net_telemetry():
    global _prev_net, _prev_net_time
    now = time.time()
    dt = max(0.001, now - _prev_net_time) if _prev_net_time > 0 else 1.0
    interfaces = {}
    tot_rx = tot_tx = 0

    try:
        with open("/proc/net/dev", "r") as f:
            for line in f.readlines()[2:]:
                p = line.split()
                name = p[0].rstrip(':')
                if name == "lo": continue
                rx = int(p[1]); tx = int(p[9])
                tot_rx += rx; tot_tx += tx
                rx_speed = round(max(0, rx - _prev_net.get(name, {}).get('rx', rx)) / dt)
                tx_speed = round(max(0, tx - _prev_net.get(name, {}).get('tx', tx)) / dt)
                interfaces[name] = {
                    "rx_bytes_sec": rx_speed, "tx_bytes_sec": tx_speed,
                    "errors": int(p[3]) + int(p[11]), "drops": int(p[4]) + int(p[12])
                }
                _prev_net[name] = {'rx': rx, 'tx': tx}
    except Exception:
        pass

    _prev_net_time = now
    return {"interfaces": interfaces, "total_rx_bytes": tot_rx, "total_tx_bytes": tot_tx}

def get_socket_telemetry():
    tcp_est = tcp_tw = udp_act = 0
    try:
        with open("/proc/net/tcp", "r") as f:
            for l in f.readlines()[1:]:
                st = l.split()[3]
                if st == "01": tcp_est += 1
                elif st == "06": tcp_tw += 1
    except Exception: pass
    try:
        with open("/proc/net/udp", "r") as f:
            udp_act = len(f.readlines()) - 1
    except Exception: pass

    return {
        "tcp_established": tcp_est, "tcp_time_wait": tcp_tw,
        "udp_active": max(0, udp_act), "total_sockets": tcp_est + tcp_tw + max(0, udp_act)
    }

def scan_all_processes(limit=None, sort_by="mem_mb"):
    global _proc_cpu_prev
    procs = []
    total_mem = 1
    try:
        with open('/proc/meminfo') as f:
            for line in f:
                if "MemTotal" in line: total_mem = int(line.split()[1]) * 1024; break
    except Exception: pass

    now = time.time()
    for pid_str in os.listdir('/proc'):
        if not pid_str.isdigit(): continue
        pid = int(pid_str)
        try:
            with open(f"/proc/{pid}/comm", "r") as f: comm = f.readline().strip()
            with open(f"/proc/{pid}/stat", "r") as f:
                sp = f.readline().split()
                tt = int(sp[13]) + int(sp[14])

            vm_rss = threads = uid = 0
            with open(f"/proc/{pid}/status", "r") as f:
                for s in f:
                    if s.startswith("VmRSS:"): vm_rss = int(s.split()[1]) * 1024
                    elif s.startswith("Threads:"): threads = int(s.split()[1])
                    elif s.startswith("Uid:"): uid = int(s.split()[1])

            try:
                import pwd
                user = pwd.getpwuid(uid).pw_name
            except Exception:
                user = str(uid)

            try:
                with open(f"/proc/{pid}/cmdline", "rb") as f:
                    raw = f.read().replace(b'\x00', b' ').decode('utf-8', errors='ignore').strip()
                    cmdline = raw if raw else comm
            except Exception:
                cmdline = comm

            cpu = 0.0
            if pid in _proc_cpu_prev:
                dt = now - _proc_cpu_prev[pid][1]
                if dt > 0: cpu = round(((tt - _proc_cpu_prev[pid][0]) / (dt * 100)), 1)
            _proc_cpu_prev[pid] = (tt, now)

            procs.append({
                "pid": pid, "name": comm, "user": user, "cmdline": cmdline,
                "cpu_percent": max(0.0, min(100.0, cpu)),
                "mem_mb": round(vm_rss / (1024 * 1024), 2),
                "threads": threads, "status": "running",
                "is_protected": is_protected_pid(pid)
            })
        except Exception:
            continue

    if sort_by == "cpu_percent":
        procs.sort(key=lambda x: x["cpu_percent"], reverse=True)
    else:
        procs.sort(key=lambda x: x["mem_mb"], reverse=True)

    if limit and len(procs) > limit:
        procs = procs[:limit]
    return procs

def get_watched_processes():
    cfg = load_config()
    watched_items = cfg.get("watched_processes", [])
    all_procs = scan_all_processes()
    proc_map = {}
    for p in all_procs:
        proc_map.setdefault(p["name"], []).append(p)

    result = []
    for idx, item in enumerate(watched_items):
        name = item.get("name", "") if isinstance(item, dict) else item
        alias = item.get("alias", name) if isinstance(item, dict) else name
        row_id = item.get("row_id", idx + 1) if isinstance(item, dict) else idx + 1

        if name in proc_map and len(proc_map[name]) > 0:
            p = proc_map[name][0].copy()
            p["alias"] = alias
            p["row_id"] = row_id
            result.append(p)
        else:
            result.append({
                "pid": 0, "name": name, "alias": alias, "user": "-", "cmdline": "-",
                "cpu_percent": 0.0, "mem_mb": 0.0, "threads": 0,
                "status": "stopped", "row_id": row_id, "is_protected": False
            })
    return result

def get_active_listening_ports():
    ports = set()
    try:
        res = subprocess.run(["ss", "-tuln"], capture_output=True, text=True, timeout=2)
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

def scan_systemd_services():
    services = []
    try:
        res = subprocess.run(["systemctl", "list-units", "--type=service", "--all", "--no-pager", "--no-legend"], capture_output=True, text=True, timeout=3)
        for line in res.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 4 and parts[0].endswith(".service"):
                services.append({"name": parts[0][:-8], "state": parts[3], "sub": parts[2]})
    except Exception:
        pass
    services.sort(key=lambda x: x["name"])
    return services

def collect_telemetry():
    uptime = "0d 0h 0m"
    load = "0.0 / 0.0 / 0.0"
    try:
        with open("/proc/uptime") as f:
            s = float(f.readline().split()[0])
            uptime = f"{int(s//86400)}d {int((s%86400)//3600)}h {int((s%3600)//60)}m"
        with open("/proc/loadavg") as f:
            p = f.readline().split()
            load = f"{p[0]} / {p[1]} / {p[2]}"
    except Exception: pass

    cfg = load_config()
    active_ports = get_active_listening_ports()
    services_state = {}
    for s in cfg.get("monitored_services", []):
        try:
            res = subprocess.run(["systemctl", "is-active", "--quiet", s], timeout=1)
            services_state[s] = "Running" if res.returncode == 0 else "Down"
        except Exception:
            services_state[s] = "Unknown"

    ports_state = {}
    for p in cfg.get("monitored_ports", []):
        ports_state[str(p)] = "Listening" if int(p) in active_ports else "Closed"

    dir_sizes = {}
    for name, path in cfg.get("monitored_directories", {}).items():
        size = 0.0
        try:
            if os.path.exists(path):
                res = subprocess.run(["du", "-sm", path], capture_output=True, text=True, timeout=2)
                if res.returncode == 0: size = float(res.stdout.split()[0])
        except Exception: pass
        dir_sizes[name] = {"path": path, "size_mb": size}

    return {
        "timestamp": int(time.time()),
        "uptime": uptime,
        "load_avg": load,
        "cpu": get_cpu_telemetry(),
        "memory": get_memory_telemetry(),
        "disk": get_disk_telemetry(),
        "network": get_net_telemetry(),
        "connections": get_socket_telemetry(),
        "apps": get_watched_processes(),
        "services": services_state,
        "ports": ports_state,
        "caches": dir_sizes
    }

class RequestHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args): pass

    def is_authenticated(self):
        cfg = load_config()
        if not cfg.get("auth_enabled", True): return True
        token = self.headers.get("X-Session-Token", "")
        if not token:
            for c in self.headers.get("Cookie", "").split(";"):
                if "ward_token=" in c:
                    token = c.split("ward_token=")[1].strip()
        return token in _active_sessions

    def do_GET(self):
        if self.path in ["/api/telemetry/overview", "/api/status"]:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(collect_telemetry()).encode("utf-8"))
            return

        if self.path == "/api/events/recent":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(list(_event_log)).encode("utf-8"))
            return

        if self.path == "/api/auth/status":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            cfg = load_config()
            self.wfile.write(json.dumps({
                "authenticated": self.is_authenticated(),
                "panel_name": cfg.get("panel_name", "WARD")
            }).encode("utf-8"))
            return

        if self.path == "/api/processes/watched":
            if not self.is_authenticated():
                self.send_response(401); self.end_headers(); return
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "processes": get_watched_processes(),
                "total_system_cpu": get_cpu_telemetry()["total_percent"]
            }).encode("utf-8"))
            return

        if self.path.startswith("/api/processes/all"):
            if not self.is_authenticated():
                self.send_response(401); self.end_headers(); return
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "processes": scan_all_processes(limit=80)
            }).encode("utf-8"))
            return

        if self.path in ["/", "/index.html"]:
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            idx_file = os.path.join(INSTALL_DIR, "index.html")
            if os.path.exists(idx_file):
                with open(idx_file, "rb") as f: self.wfile.write(f.read())
            else:
                self.wfile.write(b"<h1>WARD index.html not found</h1>")
            return

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
                log_event("info", "Login", f"Auth success from {self.client_address[0]}")
            else:
                self.send_response(401)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"status": "error", "message": "Invalid Password"}')
            return

        if not self.is_authenticated():
            self.send_response(401); self.end_headers(); return

        cfg = load_config()

        if self.path == "/api/processes/action":
            pid = payload.get("pid")
            action = payload.get("action")
            proc_name = payload.get("name", "")

            if action == "unwatch":
                watched = [w for w in cfg.get("watched_processes", []) if (w.get("name") if isinstance(w, dict) else w) != proc_name]
                cfg["watched_processes"] = watched
                save_config(cfg)
                self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
                self.wfile.write(json.dumps({"success": True, "message": f"Unwatched {proc_name}"}).encode("utf-8"))
                log_event("info", "Process Unwatched", f"Removed {proc_name} from watchlist", "processes")
                return

            if not pid or is_protected_pid(int(pid)):
                self.send_response(403); self.send_header("Content-Type", "application/json"); self.end_headers()
                self.wfile.write(json.dumps({"success": False, "error": "Operation not permitted on protected PID"}).encode("utf-8"))
                log_event("crit", "Action Blocked", f"Blocked attempt to {action} PID {pid}", "security")
                return

            try:
                sig = signal.SIGTERM if action == "sigterm" else signal.SIGKILL
                os.kill(int(pid), sig)
                self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
                self.wfile.write(json.dumps({"success": True, "message": f"Signal sent to PID {pid}"}).encode("utf-8"))
                log_event("warn", "Process Action", f"{action.upper()} sent to PID {pid}", "processes")
            except Exception as e:
                self.send_response(500); self.send_header("Content-Type", "application/json"); self.end_headers()
                self.wfile.write(json.dumps({"success": False, "error": str(e)}).encode("utf-8"))
            return

        if self.path == "/api/processes/watch":
            name = payload.get("value", "").strip()
            alias = payload.get("alias", name).strip()
            if not name:
                self.send_response(400); self.end_headers(); return

            watched = cfg.get("watched_processes", [])
            for w in watched:
                if (w.get("name") if isinstance(w, dict) else w) == name:
                    self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
                    self.wfile.write(json.dumps({"success": True, "message": "Already watched"}).encode("utf-8"))
                    return

            new_entry = {"name": name, "alias": alias, "row_id": len(watched) + 1}
            watched.append(new_entry)
            cfg["watched_processes"] = watched
            save_config(cfg)
            self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
            self.wfile.write(json.dumps({"success": True, "row_id": new_entry["row_id"]}).encode("utf-8"))
            log_event("info", "Process Watched", f"Added {name} to watchlist", "processes")
            return

        if self.path == "/api/processes/reorder":
            order_ids = payload.get("order", [])
            watched = cfg.get("watched_processes", [])
            name_map = { (w.get("name") if isinstance(w, dict) else w): w for w in watched }
            reordered = []
            for idx, name in enumerate(order_ids):
                if name in name_map:
                    item = name_map[name]
                    if isinstance(item, dict):
                        item["row_id"] = idx + 1
                    else:
                        item = {"name": item, "alias": item, "row_id": idx + 1}
                    reordered.append(item)
            cfg["watched_processes"] = reordered
            save_config(cfg)
            self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
            self.wfile.write(json.dumps({"success": True}).encode("utf-8"))
            return

        # Handlers for legacy config add/remove
        if self.path == "/api/config/add":
            t, v = payload.get("type"), payload.get("value")
            if t == "service" and v not in cfg.get("monitored_services", []):
                cfg.setdefault("monitored_services", []).append(v)
            elif t == "port" and int(v) not in cfg.get("monitored_ports", []):
                cfg.setdefault("monitored_ports", []).append(int(v))
            elif t == "directory":
                cfg.setdefault("monitored_directories", {})[payload.get("name")] = v
            save_config(cfg)
            self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
            self.wfile.write(b'{"status":"ok"}'); return

        if self.path == "/api/config/remove":
            t, v = payload.get("type"), payload.get("value")
            if t == "service":
                cfg["monitored_services"] = [x for x in cfg.get("monitored_services", []) if x != v]
            elif t == "port":
                cfg["monitored_ports"] = [x for x in cfg.get("monitored_ports", []) if str(x) != str(v)]
            elif t == "directory":
                cfg.get("monitored_directories", {}).pop(v, None)
            save_config(cfg)
            self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
            self.wfile.write(b'{"status":"ok"}'); return

        self.send_response(404)
        self.end_headers()

if __name__ == "__main__":
    cfg = load_config()
    port = int(cfg.get("panel_port", 7654))
    server = HTTPServer(("127.0.0.1", port), RequestHandler)
    print(f"WARD running on 127.0.0.1:{port}")
    server.serve_forever()
