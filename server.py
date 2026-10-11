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
from collections import deque

# === GLOBAL STATE & SAFETY CONSTANTS ===
_event_log = deque(maxlen=100) 
INSTALL_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(INSTALL_DIR, "config.json")
VERSION_PATH = os.path.join(INSTALL_DIR, "version.json")

_active_sessions = set()
_prev_cpu = {}
_prev_net_time = 0.0
_prev_disk_stats = {} 
_proc_cpu_prev = {}

# LAW #1: Self-Exclusion & Protected Entities
SELF_PID = os.getpid()
PROTECTED_PIDS = {1, SELF_PID}  # PID 1 (init/systemd) and WARD itself are always protected

def hash_pw(pw):
    return hashlib.sha256(pw.encode('utf-8')).hexdigest()

def log_event(severity, title, message, source="system"):
    _event_log.append({
        "id": secrets.token_hex(8), "timestamp": int(time.time()),
        "severity": severity, "title": title, "message": message, "source": source
    })

def load_config():
    default_config = {
        "panel_name": "WARD Monitor", "panel_port": 7654, "auth_enabled": True,
        "admin_password_hash": hash_pw("admin1234"), "telegram": {"bot_token": "", "chat_id": ""},
        "monitored_services": ["nginx", "ssh"], "monitored_ports": [80, 443, 22],
        "blocked_ports_trigger": [21, 23, 3306, 5432, 6379],
        "monitored_directories": {"system_cache": "/var/cache", "tmp": "/tmp"},
        "watched_processes": [], # New key for Section 3
        "scheduled_tasks": [],
        "theme": {"primary": "#00ab44", "success": "#00d68f", "danger": "#ff3366",
                  "bg": "#1a1d29", "card": "#252836", "text": "#e8e8e8"}
    }
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, 'r') as f: data = json.load(f)
            for k, v in default_config.items():
                if k not in data: data[k] = v
            return data
        except: return default_config
    return default_config

def save_config(cfg):
    tmp_path = CONFIG_PATH + ".tmp"
    try:
        with open(tmp_path, 'w') as f: json.dump(cfg, f, indent=2); f.flush(); os.fsync(f.fileno())
        os.replace(tmp_path, CONFIG_PATH); return True
    except:
        if os.path.exists(tmp_path): os.remove(tmp_path)
        return False

# === TELEMETRY FUNCTIONS (SECTION 2.8 PRESERVED) ===
def get_cpu_info():
    global _prev_cpu; model = "Linux Processor"; cores = os.cpu_count() or 1
    user_pct = sys_pct = io_pct = total_pct = 0.0
    try:
        with open("/proc/stat", "r") as f: fields = [int(x) for x in f.readline().split()[1:]]
        cu, cn, cs, ci, cw = fields[0], fields[1], fields[2], fields[3], fields[4]
        ct = sum(fields[:7])
        if _prev_cpu:
            dt = max(1, ct - _prev_cpu.get('total', ct))
            user_pct = round(max(0, (cu - _prev_cpu.get('user', cu)) / dt * 100), 1)
            sys_pct = round(max(0, (cs - _prev_cpu.get('sys', cs)) / dt * 100), 1)
            io_pct = round(max(0, (cw - _prev_cpu.get('iowait', cw)) / dt * 100), 1)
            total_pct = min(100.0, round(user_pct + sys_pct + io_pct, 1))
        _prev_cpu = {'user': cu, 'sys': cs, 'iowait': cw, 'total': ct}
    except: pass
    return {"model": model, "cores": cores, "total_percent": total_pct, 
            "user_percent": user_pct, "system_percent": sys_pct, "iowait_percent": io_pct}

def get_network_stats():
    global _prev_net_time; now = time.time()
    dt = max(0.001, now - _prev_net_time) if _prev_net_time > 0 else 1.0
    interfaces = {}; tot_rx = tot_tx = 0
    prev_ifaces = getattr(get_network_stats, '_prev_iface', {})
    try:
        with open("/proc/net/dev", "r") as f:
            for line in f.readlines()[2:]:
                p = line.split(); name = p[0].rstrip(':')
                if name == "lo": continue
                rx, tx = int(p[1]), int(p[9]); tot_rx += rx; tot_tx += tx
                prev = prev_ifaces.get(name, {"rx": rx, "tx": tx})
                rxd = max(0, rx - prev["rx"]) / dt; txd = max(0, tx - prev["tx"]) / dt
                interfaces[name] = {"rx_bytes_sec": round(rxd), "tx_bytes_sec": round(txd), 
                                    "errors": int(p[3])+int(p[11]), "drops": int(p[4])+int(p[12])}
    except: pass
    get_network_stats._prev_iface = {n: {"rx": int(v["rx_bytes_sec"]*dt + prev_ifaces.get(n,{}).get("rx",0)), 
                                         "tx": int(v["tx_bytes_sec"]*dt + prev_ifaces.get(n,{}).get("tx",0))} 
                                     for n, v in interfaces.items()}
    _prev_net_time = now
    return {"interfaces": interfaces, "total_rx_bytes": tot_rx, "total_tx_bytes": tot_tx}

def get_disk_io():
    global _prev_disk_stats; r_speed = w_speed = 0; device = "unknown"
    try:
        res = subprocess.run(["findmnt", "-n", "-o", "SOURCE", "/"], capture_output=True, text=True, timeout=2)
        if res.returncode == 0: device = os.path.basename(res.stdout.strip())
        with open("/proc/diskstats", "r") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 14 and parts[2] == device:
                    rd, wr = int(parts[5])*512, int(parts[9])*512
                    prev = _prev_disk_stats.get(device, (rd, wr, time.time()))
                    dt = max(0.001, time.time() - prev[2])
                    r_speed = round(max(0, rd - prev[0]) / dt); w_speed = round(max(0, wr - prev[1]) / dt)
                    _prev_disk_stats[device] = (rd, wr, time.time()); break
    except: pass
    try:
        st = os.statvfs('/'); d_total = st.f_blocks * st.f_frsize; d_used = (st.f_blocks - st.f_bavail) * st.f_frsize
    except: d_total = d_used = 0
    return {"mount_point": "/", "device": device, "total_bytes": d_total, "used_bytes": d_used, 
            "free_bytes": d_total - d_used, "read_bytes_sec": r_speed, "write_bytes_sec": w_speed}

def get_connection_states():
    tcp_est = tcp_tw = udp_act = 0
    try:
        with open("/proc/net/tcp") as f:
            for l in f.readlines()[1:]:
                s = l.split()[3]
                if s == "01": tcp_est += 1
                elif s == "06": tcp_tw += 1
        with open("/proc/net/udp") as f: udp_act = len(f.readlines()) - 1
    except: pass
    return {"tcp_established": tcp_est, "tcp_time_wait": tcp_tw, "udp_active": max(0, udp_act), 
            "total_sockets": tcp_est + tcp_tw + max(0, udp_act)}

def collect_telemetry_overview():
    mem = {}
    try:
        with open('/proc/meminfo') as f:
            for line in f: p = line.split(':'); mem[p[0].strip()] = int(p[1].split()[0]) * 1024
    except: pass
    uptime = load = "N/A"
    try:
        with open("/proc/uptime") as f: 
            s = float(f.readline().split()[0]); uptime = f"{int(s//86400)}d {int((s%86400)//3600)}h {int((s%3600)//60)}m"
        with open("/proc/loadavg") as f: p = f.readline().split(); load = f"{p[0]} / {p[1]} / {p[2]}"
    except: pass
    return {
        "timestamp": int(time.time()), "uptime": uptime, "load_avg": load, "cpu": get_cpu_info(),
        "memory": {"total_bytes": mem.get('MemTotal', 1), "used_bytes": max(0, mem.get('MemTotal',1) - mem.get('MemAvailable',0)),
                   "available_bytes": mem.get('MemAvailable', 0), "cached_bytes": mem.get('Cached', 0),
                   "swap_total_bytes": mem.get('SwapTotal', 0), "swap_used_bytes": max(0, mem.get('SwapTotal',0) - mem.get('SwapFree',0))},
        "disk": get_disk_io(), "network": get_network_stats(), "connections": get_connection_states()
    }

# === SECTION 3: PROCESS INSPECTOR LOGIC ===

def is_protected_pid(pid):
    """LAW #1 & #2: Check if PID is critical system process"""
    if pid in PROTECTED_PIDS: return True
    # Protect kernel threads (PID < 100 usually, but check comm to be safe)
    try:
        with open(f"/proc/{pid}/comm") as f: comm = f.readline().strip()
        if comm in ["kthreadd", "ksoftirqd", "migration", "rcu_sched", "watchdog"]: return True
    except: pass
    return False

def scan_all_processes(limit=None, sort_by="memory_mb"):
    """Returns list of all running processes with detailed telemetry"""
    global _proc_cpu_prev; procs = []; total_mem = 1
    try:
        with open('/proc/meminfo') as f:
            for line in f:
                if "MemTotal" in line: total_mem = int(line.split()[1]) * 1024; break
    except: pass
    
    now = time.time()
    for pid_str in os.listdir('/proc'):
        if not pid_str.isdigit(): continue
        pid = int(pid_str)
        try:
            # Read basic info
            with open(f"/proc/{pid}/comm") as f: comm = f.readline().strip()
            with open(f"/proc/{pid}/stat") as f: sp = f.readline().split(); tt = int(sp[13]) + int(sp[14])
            
            vm_rss = threads = uid = 0; cmdline = ""
            with open(f"/proc/{pid}/status") as f:
                for s in f:
                    if s.startswith("VmRSS:"): vm_rss = int(s.split()[1]) * 1024
                    elif s.startswith("Threads:"): threads = int(s.split()[1])
                    elif s.startswith("Uid:"): uid = int(s.split()[1])
            
            # Get username
            try: import pwd; user = pwd.getpwuid(uid).pw_name
            except: user = str(uid)
            
            # Get full command line
            try:
                with open(f"/proc/{pid}/cmdline", "rb") as f: 
                    raw = f.read().replace(b'\x00', b' ').decode('utf-8', errors='ignore').strip()
                    cmdline = raw if raw else comm
            except: cmdline = comm
            
            # Calculate CPU Delta
            cpu = 0.0
            if pid in _proc_cpu_prev:
                dt = now - _proc_cpu_prev[pid][1]
                if dt > 0: cpu = round(((tt - _proc_cpu_prev[pid][0]) / (dt * 100)), 1)
            _proc_cpu_prev[pid] = (tt, now)
            
            # Calculate uptime
            try:
                stat = os.stat(f"/proc/{pid}")
                uptime_sec = max(0, now - stat.st_birthtime) if hasattr(stat, 'st_birthtime') else now - stat.st_mtime
            except: uptime_sec = 0
            
            procs.append({
                "pid": pid, "name": comm, "user": user, "cmdline": cmdline,
                "cpu_percent": max(0.0, min(100.0, cpu)),
                "mem_mb": round(vm_rss/(1024*1024), 2), 
                "mem_percent": round((vm_rss/total_mem)*100, 1) if total_mem > 0 else 0.0,
                "threads": threads, "uptime_seconds": round(uptime_sec),
                "is_protected": is_protected_pid(pid)
            })
        except (FileNotFoundError, PermissionError, ProcessLookupError): 
            continue # Process died while scanning, skip safely
        except: continue
    
    # Sort and limit
    if sort_by == "cpu_percent": procs.sort(key=lambda x: x["cpu_percent"], reverse=True)
    else: procs.sort(key=lambda x: x["mem_mb"], reverse=True)
    
    if limit and len(procs) > limit: procs = procs[:limit]
    return procs

def get_watched_processes():
    """Returns watched processes + stopped ones for layout stability"""
    cfg = load_config(); watched_names = cfg.get("watched_processes", [])
    all_procs = scan_all_processes()
    proc_map = {p["name"]: p for p in all_procs}
    
    result = []
    assigned_pids = set()
    
    # Add active watched processes
    for wp in watched_names:
        name = wp.get("name", "") if isinstance(wp, dict) else wp
        alias = wp.get("alias", name) if isinstance(wp, dict) else name
        row_id = wp.get("row_id", len(result)+1) if isinstance(wp, dict) else len(result)+1
        
        if name in proc_map:
            p = proc_map[name].copy()
            p["alias"] = alias; p["row_id"] = row_id; p["status"] = "running"
            result.append(p); assigned_pids.add(p["pid"])
        else:
            # Stopped process placeholder
            result.append({"pid": 0, "name": name, "alias": alias, "user": "-", "cmdline": "-",
                           "cpu_percent": 0.0, "mem_mb": 0.0, "mem_percent": 0.0, "threads": 0,
                           "uptime_seconds": 0, "status": "stopped", "row_id": row_id, "is_protected": False})
    
    # Optionally add top non-watched processes if list is short
    if len(result) < 5:
        for p in all_procs:
            if p["pid"] not in assigned_pids and len(result) < 10:
                p["alias"] = p["name"]; p["row_id"] = len(result)+1; p["status"] = "running"
                result.append(p); assigned_pids.add(p["pid"])
                
    return result

# === REQUEST HANDLER WITH SECTION 3 ENDPOINTS ===
class RequestHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args): pass
    
    def is_authenticated(self):
        cfg = load_config()
        if not cfg.get("auth_enabled", True): return True
        token = self.headers.get("X-Session-Token", "")
        if not token:
            for c in self.headers.get("Cookie", "").split(";"):
                if "ward_token=" in c: token = c.split("ward_token=")[1].strip()
        return token in _active_sessions

    def do_GET(self):
        # Telemetry Overview
        if self.path in ["/api/telemetry/overview", "/api/status"]:
            self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
            data = collect_telemetry_overview() if self.path=="/api/telemetry/overview" else collect_metrics()
            self.wfile.write(json.dumps(data).encode("utf-8")); return
            
        # Events
        if self.path == "/api/events/recent":
            self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
            self.wfile.write(json.dumps(list(_event_log)).encode("utf-8")); return
            
        # Auth Status
        if self.path == "/api/auth/status":
            self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
            cfg = load_config()
            self.wfile.write(json.dumps({"authenticated": self.is_authenticated(), 
                                         "panel_name": cfg.get("panel_name","WARD")}).encode("utf-8")); return
            
        # System Info
        if self.path == "/api/system/info":
            self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
            v = "1.2.0"
            if os.path.exists(VERSION_PATH):
                try: v = json.load(open(VERSION_PATH)).get("version", "1.2.0")
                except: pass
            self.wfile.write(json.dumps({"version": v, "hostname": socket.gethostname(), 
                                         "os": sys.platform}).encode("utf-8")); return

        # === SECTION 3: PROCESS ENDPOINTS ===
        
        # GET /api/processes/watched
        if self.path == "/api/processes/watched":
            if not self.is_authenticated(): 
                self.send_response(401); self.send_header("Content-Type", "application/json"); self.end_headers()
                self.wfile.write(b'{"error":"Unauthorized"}'); return
            self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
            procs = get_watched_processes()
            cpu_info = get_cpu_info()
            self.wfile.write(json.dumps({
                "processes": procs, 
                "total_system_cpu": cpu_info["total_percent"],
                "total_system_mem": round((sum(p["mem_mb"] for p in procs) / (os.sysconf('SC_PAGE_SIZE') * os.sysconf('SC_PHYS_PAGES') / (1024*1024))) * 100, 1)
            }).encode("utf-8")); return

        # GET /api/processes/all?limit=100&sort=cpu
        if self.path.startswith("/api/processes/all"):
            if not self.is_authenticated(): 
                self.send_response(401); self.send_header("Content-Type", "application/json"); self.end_headers()
                self.wfile.write(b'{"error":"Unauthorized"}'); return
            qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            limit = int(qs.get("limit", ["100"])[0])
            sort_by = qs.get("sort", ["memory_mb"])[0]
            self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
            self.wfile.write(json.dumps({"processes": scan_all_processes(limit=limit, sort_by=sort_by)}).encode("utf-8")); return

        # Legacy endpoints preserved
        if not self.is_authenticated() and self.path not in ["/", "/index.html", "/favicon.svg", "/favicon.ico"]:
            self.send_response(401); self.send_header("Content-Type", "application/json"); self.end_headers()
            self.wfile.write(b'{"error":"Unauthorized"}'); return

        if self.path in ["/", "/index.html"]:
            self.send_response(200); self.send_header("Content-Type", "text/html; charset=utf-8"); self.end_headers()
            idx = os.path.join(INSTALL_DIR, "index.html")
            self.wfile.write(open(idx,"rb").read() if os.path.exists(idx) else b"<h1>Not Found</h1>"); return
            
        self.send_response(404); self.end_headers()

    def do_POST(self):
        length = int(self.headers.get('content-length', 0))
        payload = json.loads(self.rfile.read(length).decode('utf-8')) if length > 0 else {}
        
        # Auth Login
        if self.path == "/api/auth/login":
            cfg = load_config()
            if hash_pw(payload.get("password","")) == cfg.get("admin_password_hash"):
                token = secrets.token_hex(24); _active_sessions.add(token)
                self.send_response(200); self.send_header("Content-Type", "application/json")
                self.send_header("Set-Cookie", f"ward_token={token}; Path=/; HttpOnly; SameSite=Lax"); self.end_headers()
                self.wfile.write(json.dumps({"status": "ok", "token": token}).encode("utf-8"))
                log_event("info", "Login", f"Success from {self.client_address[0]}")
            else:
                self.send_response(401); self.send_header("Content-Type", "application/json"); self.end_headers()
                self.wfile.write(b'{"status":"error","message":"Invalid Password"}')
            return

        # Auth Logout
        if self.path == "/api/auth/logout":
            _active_sessions.discard(self.headers.get("X-Session-Token",""))
            self.send_response(200); self.send_header("Content-Type", "application/json")
            self.send_header("Set-Cookie", "ward_token=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT"); self.end_headers()
            self.wfile.write(b'{"status":"ok"}'); return

        # === SECTION 3: PROCESS ACTIONS ===
        
        # POST /api/processes/action
        if self.path == "/api/processes/action":
            if not self.is_authenticated(): 
                self.send_response(401); self.send_header("Content-Type", "application/json"); self.end_headers()
                self.wfile.write(b'{"error":"Unauthorized"}'); return
                
            pid = payload.get("pid"); action = payload.get("action")
            if not pid or not action:
                self.send_response(400); self.send_header("Content-Type", "application/json"); self.end_headers()
                self.wfile.write(b'{"error":"Missing pid or action"}'); return
            
            # LAW #2: Safety Check
            if is_protected_pid(int(pid)):
                self.send_response(403); self.send_header("Content-Type", "application/json"); self.end_headers()
                self.wfile.write(json.dumps({"success": False, "error": "Cannot kill protected system process"}).encode("utf-8"))
                log_event("crit", "Blocked Action", f"Attempt to {action} protected PID {pid}", "security")
                return
            
            try:
                sig = signal.SIGTERM if action == "sigterm" else signal.SIGKILL
                os.kill(int(pid), sig)
                self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
                self.wfile.write(json.dumps({"success": True, "message": f"Signal {action} sent to PID {pid}"}).encode("utf-8"))
                log_event("warn", "Process Action", f"{action.upper()} sent to PID {pid}", "processes")
            except Exception as e:
                self.send_response(500); self.send_header("Content-Type", "application/json"); self.end_headers()
                self.wfile.write(json.dumps({"success": False, "error": str(e)}).encode("utf-8"))
            return

        # POST /api/processes/watch
        if self.path == "/api/processes/watch":
            if not self.is_authenticated(): 
                self.send_response(401); self.send_header("Content-Type", "application/json"); self.end_headers()
                self.wfile.write(b'{"error":"Unauthorized"}'); return
                
            cfg = load_config(); watched = cfg.get("watched_processes", [])
            new_entry = {
                "name": payload.get("value", ""), 
                "match_type": payload.get("match_type", "exact"),
                "alias": payload.get("alias", payload.get("value", "")),
                "row_id": len(watched) + 1
            }
            watched.append(new_entry); cfg["watched_processes"] = watched; save_config(cfg)
            
            self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
            self.wfile.write(json.dumps({"success": True, "row_id": new_entry["row_id"]}).encode("utf-8"))
            log_event("info", "Watch Added", f"Added {new_entry['name']} to watchlist", "processes")
            return

        self.send_response(404); self.end_headers()

if __name__ == "__main__":
    cfg = load_config(); port = int(cfg.get("panel_port", 7654)) 
    server = HTTPServer(("127.0.0.1", port), RequestHandler)
    print(f"WARD Server running on 127.0.0.1:{port}")
    server.serve_forever()
