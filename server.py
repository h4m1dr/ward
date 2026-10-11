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

# === CONFIGURATION & GLOBALS ===
INSTALL_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(INSTALL_DIR, "config.json")
_active_sessions = set()
_event_log = deque(maxlen=100)

# Performance Caching for Delta Calculations
_prev_cpu = {}
_prev_net = {}
_prev_net_time = 0.0
_prev_disk = {}
_proc_cpu_prev = {}

# LAW #1 & #2: Protected Entities
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
        "admin_password_hash": hash_pw("admin1234"), # Default Password
        "monitored_services": ["nginx", "ssh"],
        "monitored_ports": [80, 443, 22],
        "monitored_directories": {"system_cache": "/var/cache", "tmp": "/tmp"},
        "watched_processes": [] # Section 3 Key
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
            pass
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

# === SECTION 2: TELEMETRY HELPERS ===

def get_cpu_telemetry():
    global _prev_cpu
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
    return {"cores": cores, "total_percent": total_pct, "user_percent": user_pct, 
            "system_percent": sys_pct, "iowait_percent": io_pct}

def get_memory_telemetry():
    mem = {}
    try:
        with open('/proc/meminfo', 'r') as f:
            for line in f:
                parts = line.split(':')
                mem[parts[0].strip()] = int(parts[1].split()[0]) * 1024
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
    device = "unknown"
    r_speed = w_speed = 0
    d_total = d_used = 0
    
    try:
        st = os.statvfs('/')
        d_total = st.f_blocks * st.f_frsize
        d_free = st.f_bavail * st.f_frsize
        d_used = d_total - d_free
        
        # Find root device
        res = subprocess.run(["findmnt", "-n", "-o", "SOURCE", "/"], capture_output=True, text=True, timeout=1)
        if res.returncode == 0:
            dev_path = res.stdout.strip()
            device = os.path.basename(dev_path)
            
        now = time.time()
        with open("/proc/diskstats", "r") as f:
            for line in f:
                p = line.split()
                if len(p) >= 14 and p[2] == device:
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
        
    return {"mount_point": "/", "device": device, "total_bytes": d_total, 
            "used_bytes": d_used, "free_bytes": d_total - d_used,
            "read_bytes_sec": r_speed, "write_bytes_sec": w_speed}

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
                
                prev = _prev_net.get(name, {'rx': rx, 'tx': tx})
                rx_speed = round(max(0, rx - prev['rx']) / dt)
                tx_speed = round(max(0, tx - prev['tx']) / dt)
                
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
        with open("/proc/net/udp", "r") as f:
            udp_act = len(f.readlines()) - 1
    except Exception:
        pass
    return {"tcp_established": tcp_est, "tcp_time_wait": tcp_tw, 
            "udp_active": max(0, udp_act), "total_sockets": tcp_est + tcp_tw + max(0, udp_act)}

def collect_telemetry_overview():
    uptime = "0d 0h 0m"
    load = "0.0 / 0.0 / 0.0"
    try:
        with open("/proc/uptime") as f:
            s = float(f.readline().split()[0])
            uptime = f"{int(s//86400)}d {int((s%86400)//3600)}h {int((s%3600)//60)}m"
        with open("/proc/loadavg") as f:
            p = f.readline().split()
            load = f"{p[0]} / {p[1]} / {p[2]}"
    except Exception:
        pass
        
    cfg = load_config()
    return {
        "timestamp": int(time.time()),
        "uptime": uptime,
        "load_avg": load,
        "cpu": get_cpu_telemetry(),
        "memory": get_memory_telemetry(),
        "disk": get_disk_telemetry(),
        "network": get_net_telemetry(),
        "connections": get_socket_telemetry(),
        # Legacy keys for other tabs to avoid breaking them yet
        "services": {s: "Running" for s in cfg.get("monitored_services", [])},
        "ports": {str(p): "Listening" for p in cfg.get("monitored_ports", [])},
        "caches": {}
    }

# === SECTION 3: PROCESS INSPECTOR LOGIC ===

def is_protected_pid(pid):
    if pid in PROTECTED_PIDS or pid < 100:
        return True
    try:
        with open(f"/proc/{pid}/comm", "r") as f:
            comm = f.readline().strip()
            # Critical system daemons protection
            if comm in ["systemd", "kthreadd", "sshd", "init", "ward", "kernel"]:
                return True
    except Exception:
        pass
    return False

def scan_all_processes(limit=None, sort_by="mem_mb"):
    global _proc_cpu_prev
    procs = []
    total_mem = 1
    try:
        with open('/proc/meminfo') as f:
            for line in f:
                if "MemTotal" in line: 
                    total_mem = int(line.split()[1]) * 1024
                    break
    except Exception:
        pass

    now = time.time()
    for pid_str in os.listdir('/proc'):
        if not pid_str.isdigit(): continue
        pid = int(pid_str)
        try:
            with open(f"/proc/{pid}/comm", "r") as f: comm = f.readline().strip()
            with open(f"/proc/{pid}/stat", "r") as f:
                sp = f.readline().split()
                tt = int(sp[13]) + int(sp[14]) # utime + stime
            
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
                if dt > 0: 
                    # ticks per second assumption ~100Hz -> divide by 100
                    cpu = round(((tt - _proc_cpu_prev[pid][0]) / (dt * 100)), 1)
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
    
    # Map process names to their latest data
    proc_map = {}
    for p in all_procs:
        # If multiple processes have same name, take the first one (usually main thread/master)
        if p["name"] not in proc_map:
            proc_map[p["name"]] = p

    result = []
    for idx, item in enumerate(watched_items):
        name = item.get("name", "") if isinstance(item, dict) else item
        alias = item.get("alias", name) if isinstance(item, dict) else name
        row_id = item.get("row_id", idx + 1) if isinstance(item, dict) else idx + 1

        if name in proc_map:
            p_data = proc_map[name].copy()
            p_data["alias"] = alias
            p_data["row_id"] = row_id
            p_data["status"] = "running"
            result.append(p_data)
        else:
            # Stopped process placeholder
            result.append({
                "pid": 0, "name": name, "alias": alias, "user": "-", "cmdline": "-",
                "cpu_percent": 0.0, "mem_mb": 0.0, "threads": 0,
                "status": "stopped", "row_id": row_id, "is_protected": False
            })
    return result

# === REQUEST HANDLER ===

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
        # Public Endpoints
        if self.path in ["/", "/index.html"]:
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            idx_file = os.path.join(INSTALL_DIR, "index.html")
            if os.path.exists(idx_file):
                with open(idx_file, "rb") as f: self.wfile.write(f.read())
            else:
                self.wfile.write(b"<h1>WARD index.html missing</h1>")
            return

        if self.path == "/favicon.svg":
             self.send_response(200); self.send_header("Content-Type", "image/svg+xml"); self.end_headers()
             svg = '''<svg viewBox="0 0 128 128" xmlns="http://www.w3.org/2000/svg"><rect width="128" height="128" rx="26" fill="#141824"/><path d="M58 122L56 86Q54 64 45 48Q37 34 45 20Q53 8 64 8Q75 8 83 20Q91 34 83 48Q74 64 72 86L70 122Z" fill="#4d3727" stroke="#110c07" stroke-width="2"/><circle cx="64" cy="36" r="19" fill="#ffea00" stroke="#92400e" stroke-width="1.2"/><circle cx="64" cy="36" r="8" fill="#000"/></svg>'''
             self.wfile.write(svg.encode()); return

        # Auth Check for APIs
        if not self.is_authenticated():
            self.send_response(401)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"error":"Unauthorized"}')
            return

        # API: Telemetry Overview
        if self.path in ["/api/telemetry/overview", "/api/status"]:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(collect_telemetry_overview()).encode("utf-8"))
            return

        # API: Events
        if self.path == "/api/events/recent":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(list(_event_log)).encode("utf-8"))
            return

        # API: Auth Status
        if self.path == "/api/auth/status":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            cfg = load_config()
            self.wfile.write(json.dumps({"authenticated": True, "panel_name": cfg.get("panel_name","WARD")}).encode("utf-8"))
            return

        # API: Processes Watched (Section 3)
        if self.path == "/api/processes/watched":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            procs = get_watched_processes()
            self.wfile.write(json.dumps({"processes": procs}).encode("utf-8"))
            return

        # API: All Processes (Section 3 Helper)
        if self.path.startswith("/api/processes/all"):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            procs = scan_all_processes(limit=100)
            self.wfile.write(json.dumps({"processes": procs}).encode("utf-8"))
            return

        self.send_response(404)
        self.end_headers()

    def do_POST(self):
        length = int(self.headers.get('content-length', 0))
        payload = json.loads(self.rfile.read(length).decode('utf-8')) if length > 0 else {}

        # Login
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
                log_event("info", "Login", f"Success from {self.client_address[0]}")
            else:
                self.send_response(401)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"status":"error","message":"Invalid Password"}')
            return

        # Logout
        if self.path == "/api/auth/logout":
            _active_sessions.discard(self.headers.get("X-Session-Token",""))
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status":"ok"}')
            return

        # Auth Check for remaining POSTs
        if not self.is_authenticated():
            self.send_response(401)
            self.end_headers()
            return

        cfg = load_config()

        # ACTION: Process Operations (Kill/Term/Unwatch)
        if self.path == "/api/processes/action":
            pid = payload.get("pid")
            action = payload.get("action")
            proc_name = payload.get("name", "")

            # Handle Unwatch separately (doesn't need PID validation against running procs)
            if action == "unwatch":
                watched = cfg.get("watched_processes", [])
                new_watched = [w for w in watched if (w.get("name") if isinstance(w, dict) else w) != proc_name]
                cfg["watched_processes"] = new_watched
                save_config(cfg)
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"success": True, "message": f"Unwatched {proc_name}"}).encode("utf-8"))
                log_event("info", "Process Unwatched", f"Removed {proc_name}", "processes")
                return

            # Validate PID for Kill/Term
            if not pid:
                self.send_response(400)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"error":"Missing PID"}')
                return

            if is_protected_pid(int(pid)):
                self.send_response(403)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"success": False, "error": "Cannot kill protected process"}).encode("utf-8"))
                log_event("crit", "Security Block", f"Attempt to {action} protected PID {pid}", "security")
                return

            try:
                sig = signal.SIGTERM if action == "sigterm" else signal.SIGKILL
                os.kill(int(pid), sig)
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"success": True, "message": f"Sent {action} to PID {pid}"}).encode("utf-8"))
                log_event("warn", "Process Action", f"{action.upper()} sent to PID {pid}", "processes")
            except Exception as e:
                self.send_response(500)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"success": False, "error": str(e)}).encode("utf-8"))
            return

        # WATCH: Add Process
        if self.path == "/api/processes/watch":
            name = payload.get("value", "").strip()
            alias = payload.get("alias", name).strip()
            if not name:
                self.send_response(400)
                self.end_headers()
                return

            watched = cfg.get("watched_processes", [])
            # Check duplicate
            exists = any((w.get("name") if isinstance(w, dict) else w) == name for w in watched)
            if exists:
                 self.send_response(200)
                 self.send_header("Content-Type", "application/json")
                 self.end_headers()
                 self.wfile.write(json.dumps({"success": True, "message": "Already watched"}).encode("utf-8"))
                 return

            new_entry = {"name": name, "alias": alias, "row_id": len(watched) + 1}
            watched.append(new_entry)
            cfg["watched_processes"] = watched
            save_config(cfg)
            
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"success": True, "row_id": new_entry["row_id"]}).encode("utf-8"))
            log_event("info", "Process Watched", f"Added {name}", "processes")
            return

        # REORDER: Save Drag & Drop Order
        if self.path == "/api/processes/reorder":
            order_names = payload.get("order", []) # List of names
            watched = cfg.get("watched_processes", [])
            name_to_obj = { (w.get("name") if isinstance(w, dict) else w): w for w in watched }
            
            reordered_list = []
            for idx, n in enumerate(order_names):
                if n in name_to_obj:
                    obj = name_to_obj[n]
                    if isinstance(obj, dict):
                        obj["row_id"] = idx + 1
                        reordered_list.append(obj)
                    else:
                        reordered_list.append({"name": obj, "alias": obj, "row_id": idx + 1})
            
            cfg["watched_processes"] = reordered_list
            save_config(cfg)
            
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"success":true}')
            return

        self.send_response(404)
        self.end_headers()

if __name__ == "__main__":
    cfg = load_config()
    port = int(cfg.get("panel_port", 7654))
    server = HTTPServer(("127.0.0.1", port), RequestHandler)
    print(f"WARD Server running on 127.0.0.1:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down WARD...")
        server.shutdown()
