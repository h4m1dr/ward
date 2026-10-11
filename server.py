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

# Global Event Buffer for Notification System (LAW #5 compliant memory bound)
_event_log = deque(maxlen=100) 

INSTALL_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(INSTALL_DIR, "config.json")
VERSION_PATH = os.path.join(INSTALL_DIR, "version.json")

_active_sessions = set()
_prev_cpu = {}
_prev_net_time = 0.0
_prev_disk_stats = {} 
_proc_cpu_prev = {}

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
    # FIXED: Default port changed to 7654 to match your Nginx upstream
    default_config = {
        "panel_name": "WARD Monitor",
        "panel_port": 7654, 
        "auth_enabled": True,
        "admin_password_hash": hash_pw("admin1234"),
        "telegram": {"bot_token": "", "chat_id": ""},
        "monitored_services": ["nginx", "ssh"],
        "monitored_ports": [80, 443, 22],
        "blocked_ports_trigger": [21, 23, 3306, 5432, 6379],
        "monitored_directories": {"system_cache": "/var/cache", "tmp": "/tmp"},
        "monitored_apps": ["dockerd", "xray"],
        "scheduled_tasks": [],
        "theme": {
            "primary": "#00ab44", "success": "#00d68f", "danger": "#ff3366",
            "bg": "#1a1d29", "card": "#252836", "text": "#e8e8e8"
        }
    }
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, 'r') as f:
                data = json.load(f)
                for key, value in default_config.items():
                    if key not in data:
                        data[key] = value
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
        if os.path.exists(tmp_path): os.remove(tmp_path)
        return False

# === SECTION 2.8: CLEAN TELEMETRY FUNCTIONS ===

def get_cpu_info():
    global _prev_cpu
    model = "Linux Processor"; cores = os.cpu_count() or 1
    user_pct = sys_pct = io_pct = total_pct = 0.0
    try:
        with open("/proc/stat", "r") as f:
            fields = [int(x) for x in f.readline().split()[1:]]
        curr_user, curr_nice, curr_sys, curr_idle, curr_iowait = fields[0], fields[1], fields[2], fields[3], fields[4]
        curr_total = sum(fields[:7])
        
        if _prev_cpu:
            dt = max(1, curr_total - _prev_cpu.get('total', curr_total))
            user_pct = round(max(0, (curr_user - _prev_cpu.get('user', curr_user)) / dt * 100), 1)
            sys_pct = round(max(0, (curr_sys - _prev_cpu.get('sys', curr_sys)) / dt * 100), 1)
            io_pct = round(max(0, (curr_iowait - _prev_cpu.get('iowait', curr_iowait)) / dt * 100), 1)
            total_pct = min(100.0, round(user_pct + sys_pct + io_pct, 1))
            
        _prev_cpu = {'user': curr_user, 'sys': curr_sys, 'iowait': curr_iowait, 'total': curr_total}
    except: pass
    
    return {"model": model, "cores": cores, "total_percent": total_pct, 
            "user_percent": user_pct, "system_percent": sys_pct, "iowait_percent": io_pct}

def get_network_stats():
    global _prev_net_time
    now = time.time(); dt = max(0.001, now - _prev_net_time) if _prev_net_time > 0 else 1.0
    interfaces = {}; tot_rx = tot_tx = 0
    prev_ifaces = getattr(get_network_stats, '_prev_iface', {})
    
    try:
        with open("/proc/net/dev", "r") as f:
            for line in f.readlines()[2:]:
                p = line.split(); name = p[0].rstrip(':')
                if name == "lo": continue
                rx, tx = int(p[1]), int(p[9]); tot_rx += rx; tot_tx += tx
                prev = prev_ifaces.get(name, {"rx": rx, "tx": tx})
                rxd = max(0, rx - prev["rx"]) / dt
                txd = max(0, tx - prev["tx"]) / dt
                interfaces[name] = {"rx_bytes_sec": round(rxd), "tx_bytes_sec": round(txd), 
                                    "errors": int(p[3])+int(p[11]), "drops": int(p[4])+int(p[12])}
    except: pass
    
    get_network_stats._prev_iface = {n: {"rx": int(v["rx_bytes_sec"]*dt + prev_ifaces.get(n,{}).get("rx",0)), 
                                         "tx": int(v["tx_bytes_sec"]*dt + prev_ifaces.get(n,{}).get("tx",0))} 
                                     for n, v in interfaces.items()}
    _prev_net_time = now
    return {"interfaces": interfaces, "total_rx_bytes": tot_rx, "total_tx_bytes": tot_tx}

def get_disk_io():
    global _prev_disk_stats
    r_speed = w_speed = 0; device = "unknown"
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
                    r_speed = round(max(0, rd - prev[0]) / dt)
                    w_speed = round(max(0, wr - prev[1]) / dt)
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
            for line in f:
                p = line.split(':'); mem[p[0].strip()] = int(p[1].split()[0]) * 1024
    except: pass
    
    uptime = load = "N/A"
    try:
        with open("/proc/uptime") as f: 
            s = float(f.readline().split()[0]); uptime = f"{int(s//86400)}d {int((s%86400)//3600)}h {int((s%3600)//60)}m"
        with open("/proc/loadavg") as f: p = f.readline().split(); load = f"{p[0]} / {p[1]} / {p[2]}"
    except: pass

    return {
        "timestamp": int(time.time()), "uptime": uptime, "load_avg": load,
        "cpu": get_cpu_info(),
        "memory": {
            "total_bytes": mem.get('MemTotal', 1), "used_bytes": max(0, mem.get('MemTotal',1) - mem.get('MemAvailable',0)),
            "available_bytes": mem.get('MemAvailable', 0), "cached_bytes": mem.get('Cached', 0),
            "swap_total_bytes": mem.get('SwapTotal', 0), "swap_used_bytes": max(0, mem.get('SwapTotal',0) - mem.get('SwapFree',0))
        },
        "disk": get_disk_io(), "network": get_network_stats(), "connections": get_connection_states()
    }

# === LEGACY FUNCTIONS FOR OTHER TABS ===
def get_active_listening_ports():
    ports = set()
    try:
        res = subprocess.run(["ss", "-tuln"], capture_output=True, text=True)
        for line in res.stdout.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 5 and parts[4].rsplit(":",1)[-1].isdigit():
                ports.add(int(parts[4].rsplit(":",1)[-1]))
    except: pass
    return sorted(list(ports))

def scan_all_processes():
    global _proc_cpu_prev; procs = []; total_mem = 1
    try:
        with open('/proc/meminfo') as f:
            for line in f:
                if "MemTotal" in line: total_mem = int(line.split()[1]) * 1024; break
    except: pass
    now = time.time()
    for pid in [p for p in os.listdir('/proc') if p.isdigit()]:
        try:
            with open(f"/proc/{pid}/comm") as f: comm = f.readline().strip()
            with open(f"/proc/{pid}/stat") as f: sp = f.readline().split(); tt = int(sp[13]) + int(sp[14])
            vm_rss = threads = 0
            with open(f"/proc/{pid}/status") as f:
                for s in f:
                    if s.startswith("VmRSS:"): vm_rss = int(s.split()[1]) * 1024
                    elif s.startswith("Threads:"): threads = int(s.split()[1])
            if vm_rss == 0: continue
            cpu = 0.0
            if pid in _proc_cpu_prev:
                dt = now - _proc_cpu_prev[pid][1]
                if dt > 0: cpu = round(((tt - _proc_cpu_prev[pid][0]) / (dt * 100)), 1)
            _proc_cpu_prev[pid] = (tt, now)
            procs.append({"pid": int(pid), "name": comm, "cpu_pct": max(0.0, min(100.0, cpu)),
                          "memory_mb": round(vm_rss/(1024*1024), 2), "memory_pct": round((vm_rss/total_mem)*100, 1), "threads": threads})
        except: continue
    procs.sort(key=lambda x: x["memory_mb"], reverse=True); return procs

def collect_metrics():
    cfg = load_config(); cpu = get_cpu_info(); net = get_network_stats(); ports = get_active_listening_ports()
    mem = {}; 
    try:
        with open('/proc/meminfo') as f:
            for line in f: p = line.split(':'); mem[p[0].strip()] = int(p[1].split()[0]) // 1024
    except: pass
    tr = mem.get('MemTotal',1); ar = mem.get('MemAvailable',0); ur = tr - ar
    ts = mem.get('SwapTotal',1); fs = mem.get('SwapFree',0); us = ts - fs
    try:
        st = os.statvfs('/'); td = round((st.f_blocks*st.f_frsize)/(1024**3),2); fd = round((st.f_bavail*st.f_frsize)/(1024**3),2)
        ud = round(td-fd, 2); up = round((ud/td)*100, 1)
    except: td=fd=ud=up=0.0
    
    svcs = {}; 
    for s in cfg.get("monitored_services", []):
        svcs[s] = "Running" if subprocess.run(["systemctl","is-active","--quiet",s]).returncode==0 else "Down"
    wports = {str(p): "Listening" if int(p) in ports else "Closed" for p in cfg.get("monitored_ports", [])}
    
    tcp=udp=0
    try:
        tcp = len([1 for l in open("/proc/net/tcp").readlines() if not l.strip().startswith("sl")])
        udp = len([1 for l in open("/proc/net/udp").readlines() if not l.strip().startswith("sl")])
    except: pass
    
    uptime=load="N/A"
    try:
        with open("/proc/uptime") as f: s=float(f.readline().split()[0]); uptime=f"{int(s//86400)}d {int((s%86400)//3600)}h {int((s%3600)//60)}m"
        with open("/proc/loadavg") as f: p=f.readline().split(); load=f"{p[0]} / {p[1]} / {p[2]}"
    except: pass
    
    return {
        "panel_name": cfg.get("panel_name","WARD"), "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "uptime": uptime, "load_avg": load, "cpu": cpu,
        "ram": {"used_mb": ur, "total_mb": tr, "pct": round((ur/tr)*100,1) if tr>0 else 0.0},
        "swap": {"used_mb": us, "total_mb": ts, "pct": round((us/max(ts,1))*100,1)},
        "disk": {"used_gb": ud, "free_gb": fd, "total_gb": td, "pct": up},
        "network": net, "connections": {"tcp": tcp, "udp": udp},
        "services": svcs, "ports": wports, "all_open_ports": ports,
        "blocked_ports": cfg.get("blocked_ports_trigger",[]), "caches": {},
        "apps": [], "tasks": cfg.get("scheduled_tasks",[]), "theme": cfg.get("theme",{})
    }

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
        if self.path in ["/api/telemetry/overview", "/api/status"]:
            self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
            self.wfile.write(json.dumps(collect_telemetry_overview() if self.path=="/api/telemetry/overview" else collect_metrics()).encode("utf-8")); return
            
        if self.path == "/api/events/recent":
            self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
            self.wfile.write(json.dumps(list(_event_log)).encode("utf-8")); return
            
        if self.path == "/api/auth/status":
            self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
            cfg = load_config()
            self.wfile.write(json.dumps({"authenticated": self.is_authenticated(), "panel_name": cfg.get("panel_name","WARD")}).encode("utf-8")); return
            
        if self.path == "/api/system/info":
            self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
            v = "1.2.0"
            if os.path.exists(VERSION_PATH):
                try: v = json.load(open(VERSION_PATH)).get("version", "1.2.0")
                except: pass
            self.wfile.write(json.dumps({"version": v, "hostname": socket.gethostname(), "os": sys.platform}).encode("utf-8")); return

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

        if self.path == "/api/auth/logout":
            _active_sessions.discard(self.headers.get("X-Session-Token",""))
            self.send_response(200); self.send_header("Content-Type", "application/json")
            self.send_header("Set-Cookie", "ward_token=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT"); self.end_headers()
            self.wfile.write(b'{"status":"ok"}'); return

        self.send_response(404); self.end_headers()

# FIXED: Removed duplicate file content and syntax error
if __name__ == "__main__":
    cfg = load_config()
    # FIXED: Default port is now 7654 to match your Nginx configuration
    port = int(cfg.get("panel_port", 7654)) 
    server = HTTPServer(("127.0.0.1", port), RequestHandler)
    print(f"WARD Server running on 127.0.0.1:{port}")
    server.serve_forever()
