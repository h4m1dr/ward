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
_prev_cpu_idle = 0
_prev_cpu_total = 0
_prev_net_time = 0
_prev_disk_stats = {} # {device: (sectors_read, sectors_written)}
_known_listening_ports = set()
_proc_cpu_prev = {}

def hash_pw(pw):
    return hashlib.sha256(pw.encode('utf-8')).hexdigest()

def log_event(severity, title, message, source="system"):
    """Thread-safe event logging for notification drawer"""
    event = {
        "id": secrets.token_hex(8),
        "timestamp": int(time.time()),
        "severity": severity,
        "title": title,
        "message": message,
        "source": source
    }
    _event_log.append(event)

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
        "theme": {
            "primary": "#00ab44",
            "success": "#00d68f",
            "danger": "#ff3366",
            "bg": "#1a1d29",
            "card": "#252836",
            "text": "#e8e8e8"
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
    """LAW #4: Atomic Write Pattern to prevent config corruption"""
    tmp_path = CONFIG_PATH + ".tmp"
    try:
        with open(tmp_path, 'w') as f:
            json.dump(cfg, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, CONFIG_PATH)
        return True
    except Exception:
        try: 
            if os.path.exists(tmp_path): os.remove(tmp_path)
        except: pass
        return False

# === SECTION 2.8: ADVANCED TELEMETRY FUNCTIONS ===

def get_cpu_info():
    """Returns CPU stats including User, System and IO Wait percentages"""
    global _prev_cpu_idle, _prev_cpu_total
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
    
    cpu_data = {"user": 0.0, "nice": 0.0, "system": 0.0, "idle": 0.0, "iowait": 0.0}
    try:
        with open("/proc/stat", "r") as f:
            fields = [float(x) for x in f.readline().strip().split()[1:]]
        
        user, nice, system, idle, iowait = fields[0], fields[1], fields[2], fields[3], fields[4]
        total = sum(fields[:8]) if len(fields) >= 8 else sum(fields[:5])
        
        diff_user = user - _prev_cpu_idle # Note: using prev as baseline for delta
        # Correct delta calculation requires storing all previous fields
        # Simplified approach for this refactor: store full tuple next time
        # For now, let's use a proper delta implementation
        
    except Exception:
        pass
        
    # Re-implementing with proper state tracking for deltas
    try:
        with open("/proc/stat", "r") as f:
            current_fields = [int(x) for x in f.readline().strip().split()[1:]]
            
        curr_user, curr_nice, curr_sys, curr_idle, curr_iowait = current_fields[0], current_fields[1], current_fields[2], current_fields[3], current_fields[4]
        curr_total = sum(current_fields[:8]) if len(current_fields) >= 8 else sum(current_fields[:5])
        
        if _prev_cpu_total > 0:
            diff_total = curr_total - _prev_cpu_total
            if diff_total > 0:
                cpu_data["user"] = round(((curr_user - _prev_cpu_idle + curr_nice - (_prev_cpu_total - _prev_cpu_idle - _prev_cpu_total)) / diff_total) * 100, 1) # Simplified logic below
                
                # Proper Delta Calculation
                d_user = curr_user - getattr(get_cpu_info, '_prev_user', curr_user)
                d_nice = curr_nice - getattr(get_cpu_info, '_prev_nice', curr_nice)
                d_sys = curr_sys - getattr(get_cpu_info, '_prev_sys', curr_sys)
                d_idle = curr_idle - getattr(get_cpu_info, '_prev_idle', curr_idle)
                d_iowait = curr_iowait - getattr(get_cpu_info, '_prev_iowait', curr_iowait)
                
                d_total = d_user + d_nice + d_sys + d_idle + d_iowait
                if d_total > 0:
                    cpu_data["user"] = round((d_user / d_total) * 100, 1)
                    cpu_data["system"] = round((d_sys / d_total) * 100, 1)
                    cpu_data["iowait"] = round((d_iowait / d_total) * 100, 1)
                    
                # Save state for next iteration
                get_cpu_info._prev_user = curr_user
                get_cpu_info._prev_nice = curr_nice
                get_cpu_info._prev_sys = curr_sys
                get_cpu_info._prev_idle = curr_idle
                get_cpu_info._prev_iowait = curr_iowait
                
        _prev_cpu_total = curr_total
        _prev_cpu_idle = curr_idle # Legacy var update
        
    except Exception:
        pass
        
    total_pct = min(100.0, max(0.0, cpu_data["user"] + cpu_data["system"] + cpu_data["iowait"]))
    
    return {
        "model": model, 
        "cores": max(cores, 1), 
        "total_percent": round(total_pct, 1),
        "user_percent": cpu_data["user"],
        "system_percent": cpu_data["system"],
        "iowait_percent": cpu_data["iowait"]
    }

def get_network_stats():
    """Returns per-interface network stats and totals"""
    global _prev_net_time
    interfaces = {}
    total_rx = total_tx = 0
    
    try:
        with open("/proc/net/dev", "r") as f:
            lines = f.readlines()[2:]
            for line in lines:
                parts = line.split()
                iface = parts[0].strip(":")
                if iface == "lo": continue
                
                rx_bytes = int(parts[1])
                tx_bytes = int(parts[9])
                rx_errs = int(parts[3])
                tx_errs = int(parts[11])
                rx_drops = int(parts[4])
                tx_drops = int(parts[12])
                
                total_rx += rx_bytes
                total_tx += tx_bytes
                
                interfaces[iface] = {
                    "rx_bytes_sec": 0, "tx_bytes_sec": 0,
                    "errors": rx_errs + tx_errs, "drops": rx_drops + tx_drops
                }
    except Exception:
        pass
        
    now = time.time()
    if _prev_net_time > 0:
        diff_t = max(now - _prev_net_time, 0.001)
        for iface in interfaces:
            # In a real persistent app, we'd store prev values per interface
            # Here we rely on the fact that /proc/net/dev is cumulative
            # For this refactor, we'll assume frontend handles smoothing or 
            # we implement a simple cache here. 
            # Implementing simple cache for accuracy:
            pass 
            
    # Since we need deltas, let's use a module-level dict for prev interface stats
    if not hasattr(get_network_stats, '_prev_iface'):
        get_network_stats._prev_iface = {}
        
    now = time.time()
    diff_t = max(now - _prev_net_time, 0.001) if _prev_net_time > 0 else 1.0
    
    for iface, stats in interfaces.items():
        prev = get_network_stats._prev_iface.get(iface, {"rx": 0, "tx": 0})
        rx_delta = max(stats["rx_bytes_sec_placeholder"] - prev["rx"], 0) if "rx_bytes_sec_placeholder" in stats else 0 
        # Wait, I need actual cumulative bytes from /proc/net/dev, not rates yet.
        # Let's re-parse properly inside the delta block.
        pass

    # CORRECTED NETWORK FUNCTION WITH DELTAS
    net_ifaces = {}
    tot_rx = tot_tx = 0
    try:
        with open("/proc/net/dev", "r") as f:
            for line in f.readlines()[2:]:
                p = line.split()
                name = p[0].rstrip(':')
                if name == 'lo': continue
                rx = int(p[1]); tx = int(p[9])
                errs = int(p[3]) + int(p[11])
                drops = int(p[4]) + int(p[12])
                tot_rx += rx; tot_tx += tx
                net_ifaces[name] = {"rx": rx, "tx": tx, "errs": errs, "drops": drops}
    except: pass

    now = time.time()
    dt = max(now - _prev_net_time, 0.001) if _prev_net_time > 0 else 1.0
    prev_ifaces = getattr(get_network_stats, '_prev_iface', {})
    
    result_ifaces = {}
    for name, cur in net_ifaces.items():
        prev = prev_ifaces.get(name, {"rx": cur["rx"], "tx": cur["tx"]})
        rxd = max(cur["rx"] - prev["rx"], 0) / (dt * 1024 * 1024)
        txd = max(cur["tx"] - prev["tx"], 0) / (dt * 1024 * 1024)
        result_ifaces[name] = {
            "rx_bytes_sec": round(rxd * 1024 * 1024), # Keep raw bytes for frontend conversion if needed, or MB/s
            "tx_bytes_sec": round(txd * 1024 * 1024),
            "errors": cur["errs"], "drops": cur["drops"]
        }
        # Actually spec says MB/s in some places but bytes in contract. Contract wins.
        result_ifaces[name]["rx_bytes_sec"] = round(rxd * 1024 * 1024)
        result_ifaces[name]["tx_bytes_sec"] = round(txd * 1024 * 1024)

    get_network_stats._prev_iface = net_ifaces
    _prev_net_time = now
    
    # Calculate totals based on deltas too if possible, or just sum current rates
    # Spec contract uses total_rx_bytes (cumulative). Let's provide both.
    return {
        "interfaces": result_ifaces,
        "total_rx_bytes": tot_rx,
        "total_tx_bytes": tot_tx
    }

def get_disk_io():
    """Calculates Read/Write speeds in Bytes/sec from /proc/diskstats"""
    global _prev_disk_stats
    read_bytes_sec = write_bytes_sec = 0
    mount_point = "/"
    device = "unknown"
    
    try:
        # Find root device
        res = subprocess.run(["findmnt", "-n", "-o", "SOURCE", "/"], capture_output=True, text=True, timeout=2)
        if res.returncode == 0:
            dev_path = res.stdout.strip()
            device = os.path.basename(dev_path)
            
        # Parse diskstats
        with open("/proc/diskstats", "r") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 14 and parts[2] == device:
                    # Fields 6 (sectors read) and 10 (sectors written) are in 512-byte sectors
                    curr_read_sectors = int(parts[5])
                    curr_write_sectors = int(parts[9])
                    
                    prev = _prev_disk_stats.get(device, (curr_read_sectors, curr_write_sectors, time.time()))
                    now = time.time()
                    dt = max(now - prev[2], 0.001)
                    
                    d_read = max(curr_read_sectors - prev[0], 0) * 512
                    d_write = max(curr_write_sectors - prev[1], 0) * 512
                    
                    read_bytes_sec = d_read / dt
                    write_bytes_sec = d_write / dt
                    
                    _prev_disk_stats[device] = (curr_read_sectors, curr_write_sectors, now)
                    break
    except Exception:
        pass
        
    return {
        "mount_point": mount_point,
        "device": device,
        "read_bytes_sec": round(read_bytes_sec),
        "write_bytes_sec": round(write_bytes_sec)
    }

def get_connection_states():
    """Counts TCP/UDP states from /proc/net/tcp and /proc/net/udp"""
    tcp_est = tcp_tw = udp_active = 0
    try:
        with open("/proc/net/tcp", "r") as f:
            for line in f.readlines()[1:]:
                state = line.strip().split()[3]
                if state == "01": tcp_est += 1      # ESTABLISHED
                elif state == "06": tcp_tw += 1     # TIME_WAIT
    except: pass
    
    try:
        with open("/proc/net/udp", "r") as f:
            udp_active = len(f.readlines()[1:])
    except: pass
    
    return {
        "tcp_established": tcp_est,
        "tcp_time_wait": tcp_tw,
        "udp_active": udp_active,
        "total_sockets": tcp_est + tcp_tw + udp_active
    }

def collect_telemetry_overview():
    """Main aggregator for Section 2.8 Data Contract"""
    cfg = load_config()
    
    # Memory
    mem = {}
    try:
        with open('/proc/meminfo', 'r') as f:
            for line in f:
                parts = line.split(':')
                mem[parts[0].strip()] = int(parts[1].split()[0]) * 1024 # Convert KB to Bytes
    except: pass
    
    avail = mem.get('MemAvailable', 0)
    total = mem.get('MemTotal', 1)
    cached = mem.get('Cached', 0)
    swap_total = mem.get('SwapTotal', 0)
    swap_free = mem.get('SwapFree', 0)
    
    # Disk Space
    try:
        st = os.statvfs('/')
        d_total = st.f_blocks * st.f_frsize
        d_free = st.f_bavail * st.f_frsize
        d_used = d_total - d_free
    except:
        d_total = d_free = d_used = 0
        
    # Uptime & Load
    uptime_str = "0d 0h 0m"; load_str = "0.0 / 0.0 / 0.0"
    try:
        with open("/proc/uptime") as f:
            s = float(f.readline().split()[0])
            uptime_str = f"{int(s//86400)}d {int((s%86400)//3600)}h {int((s%3600)//60)}m"
        with open("/proc/loadavg") as f:
            p = f.readline().split()
            load_str = f"{p[0]} / {p[1]} / {p[2]}"
    except: pass

    return {
        "timestamp": int(time.time()),
        "cpu": get_cpu_info(),
        "memory": {
            "total_bytes": total,
            "used_bytes": total - avail,
            "available_bytes": avail,
            "cached_bytes": cached,
            "swap_total_bytes": swap_total,
            "swap_used_bytes": swap_total - swap_free
        },
        "disk": {
            **get_disk_io(),
            "total_bytes": d_total,
            "used_bytes": d_used,
            "free_bytes": d_free
        },
        "network": get_network_stats(),
        "connections": get_connection_states(),
        "uptime": uptime_str,
        "load_avg": load_str
    }


# === LEGACY FUNCTIONS PRESERVED FOR OTHER TABS ===
def get_active_listening_ports():
    ports = set()
    try:
        res = subprocess.run(["ss", "-tuln"], capture_output=True, text=True)
        for line in res.stdout.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 5:
                addr = parts[4]
                port_str = addr.rsplit(":", 1)[-1]
                if port_str.isdigit(): ports.add(int(port_str))
    except: pass
    return sorted(list(ports))

def get_dir_size_mb(path):
    if not os.path.exists(path): return 0.0
    try:
        res = subprocess.run(["du", "-sm", path], capture_output=True, text=True)
        if res.returncode == 0: return float(res.stdout.split()[0])
    except: pass
    return 0.0

def explore_directory_tree(path):
    if not os.path.exists(path) or not os.path.isdir(path):
        return {"items": [], "error": "Path does not exist"}
    virtual_fs = {'proc', 'sys', 'dev', 'run', 'snap'}
    items = []
    try:
        entries = os.listdir(path)
        for entry in entries:
            full_path = os.path.join(path, entry)
            if not os.path.isdir(full_path): continue
            if entry in virtual_fs: continue
            try:
                cmd = f"du -sm '{full_path}' 2>/dev/null"
                res = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
                size_mb = float(res.stdout.strip().split()[0]) if res.returncode == 0 and res.stdout.strip() else 0
                items.append({"name": entry, "path": full_path, "size_mb": size_mb})
            except: items.append({"name": entry, "path": full_path, "size_mb": 0})
        items.sort(key=lambda x: x["size_mb"], reverse=True)
        return {"items": items}
    except PermissionError: return {"items": [], "error": "Permission denied"}
    except Exception as e: return {"items": [], "error": str(e)}

def scan_all_processes():
    global _proc_cpu_prev
    procs = []; total_mem = 1
    try:
        with open('/proc/meminfo', 'r') as f:
            for line in f:
                if "MemTotal" in line: total_mem = int(line.split()[1]) * 1024; break
    except: pass
    now = time.time()
    for pid in [p for p in os.listdir('/proc') if p.isdigit()]:
        try:
            with open(f"/proc/{pid}/comm", "r") as f: comm = f.readline().strip()
            with open(f"/proc/{pid}/stat", "r") as f:
                sp = f.readline().split(); total_time = int(sp[13]) + int(sp[14])
            with open(f"/proc/{pid}/status", "r") as f:
                vm_rss = 0; threads = 1
                for s in f:
                    if s.startswith("VmRSS:"): vm_rss = int(s.split()[1]) * 1024
                    elif s.startswith("Threads:"): threads = int(s.split()[1])
            if vm_rss == 0: continue
            cpu = 0.0
            if pid in _proc_cpu_prev:
                old_time, old_t = _proc_cpu_prev[pid]; dt = now - old_t
                if dt > 0: cpu = round(((total_time - old_time) / (dt * 100)), 1)
            _proc_cpu_prev[pid] = (total_time, now)
            procs.append({"pid": int(pid), "name": comm, "cpu_pct": max(0.0, min(100.0, cpu)),
                          "memory_mb": round(vm_rss / (1024 * 1024), 2),
                          "memory_pct": round((vm_rss / total_mem) * 100, 1), "threads": threads})
        except: continue
    procs.sort(key=lambda x: x["memory_mb"], reverse=True)
    return procs

def scan_systemd_services():
    services = []
    try:
        res = subprocess.run(["systemctl", "list-units", "--type=service", "--all", "--no-pager", "--no-legend"], capture_output=True, text=True)
        for line in res.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 4 and parts[0].endswith(".service"):
                services.append({"name": parts[0][:-8], "state": parts[3], "sub": parts[2]})
    except: pass
    services.sort(key=lambda x: x["name"])
    return services

def get_pinned_apps(pinned_names):
    all_procs = scan_all_processes(); proc_dict = {}
    for p in all_procs:
        if p["name"] not in proc_dict: proc_dict[p["name"]] = p.copy()
        else:
            proc_dict[p["name"]]["memory_mb"] += p["memory_mb"]
            proc_dict[p["name"]]["memory_pct"] = round(proc_dict[p["name"]]["memory_pct"] + p["memory_pct"], 1)
            proc_dict[p["name"]]["cpu_pct"] = round(proc_dict[p["name"]]["cpu_pct"] + p["cpu_pct"], 1)
            proc_dict[p["name"]]["threads"] += p["threads"]
    result = []
    for name in pinned_names:
        if name in proc_dict:
            item = proc_dict[name].copy(); item["status"] = "Active"; result.append(item)
        else:
            result.append({"pid": "-", "name": name, "cpu_pct": 0.0, "memory_mb": 0.0, "memory_pct": 0.0, "threads": 0, "status": "Stopped"})
    return result

def collect_metrics():
    """Legacy metrics collector preserved for backward compatibility with older tabs"""
    cfg = load_config()
    cpu_data = get_cpu_info(); net_data = get_network_stats(); active_ports = get_active_listening_ports()
    mem = {}
    try:
        with open('/proc/meminfo', 'r') as f:
            for line in f:
                parts = line.split(':'); mem[parts[0].strip()] = int(parts[1].split()[0]) // 1024
    except: pass
    avail_ram = mem.get('MemAvailable', 0); total_ram = mem.get('MemTotal', 1); used_ram = total_ram - avail_ram
    total_swap = mem.get('SwapTotal', 1); free_swap = mem.get('SwapFree', 0); used_swap = total_swap - free_swap
    try:
        st = os.statvfs('/')
        total_disk = round((st.f_blocks * st.f_frsize) / (1024**3), 2)
        free_disk = round((st.f_bavail * st.f_frsize) / (1024**3), 2)
        used_disk = round(total_disk - free_disk, 2)
        used_disk_pct = round((used_disk / total_disk) * 100, 1)
    except: total_disk = free_disk = used_disk = used_disk_pct = 0.0
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
    tcp_count = udp_count = 0
    try:
        tcp_count = len([1 for l in open("/proc/net/tcp").readlines() if not l.strip().startswith("sl")])
        udp_count = len([1 for l in open("/proc/net/udp").readlines() if not l.strip().startswith("sl")])
    except: pass
    uptime = "0d 0h 0m"; load_avg = "0.0 / 0.0 / 0.0"
    try:
        with open("/proc/uptime") as f:
            s = float(f.readline().split()[0]); uptime = f"{int(s//86400)}d {int((s%86400)//3600)}h {int((s%3600)//60)}m"
        with open("/proc/loadavg") as f:
            p = f.readline().split(); load_avg = f"{p[0]} / {p[1]} / {p[2]}"
    except: pass
    default_theme = {"primary": "#00ab44", "success": "#00d68f", "danger": "#ff3366", "bg": "#1a1d29", "card": "#252836", "text": "#e8e8e8"}
    return {
        "panel_name": cfg.get("panel_name", "WARD"), "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "uptime": uptime, "load_avg": load_avg, "cpu": cpu_data,
        "ram": {"used_mb": used_ram, "total_mb": total_ram, "pct": round((used_ram/total_ram)*100, 1) if total_ram > 0 else 0.0},
        "swap": {"used_mb": used_swap, "total_mb": total_swap, "pct": round((used_swap/max(total_swap, 1))*100, 1)},
        "disk": {"used_gb": used_disk, "free_gb": free_disk, "total_gb": total_disk, "pct": used_disk_pct},
        "network": net_data, "connections": {"tcp": tcp_count, "udp": udp_count},
        "services": services_state, "ports": watched_ports, "all_open_ports": active_ports,
        "blocked_ports": cfg.get("blocked_ports_trigger", []), "caches": dir_sizes,
        "apps": pinned_apps, "tasks": cfg.get("scheduled_tasks", []), "theme": cfg.get("theme", default_theme)
    }

class RequestHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args): pass

    def is_authenticated(self):
        cfg = load_config()
        if not cfg.get("auth_enabled", True): return True
        token = self.headers.get("X-Session-Token", "")
        if not token:
            cookies = self.headers.get("Cookie", "")
            for c in cookies.split(";"):
                if "ward_token=" in c: token = c.split("ward_token=")[1].strip()
        return token in _active_sessions

    def do_GET(self):
        # NEW ENDPOINT: Telemetry Overview (Section 2.8)
        if self.path == "/api/telemetry/overview":
            self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
            self.wfile.write(json.dumps(collect_telemetry_overview()).encode("utf-8"))
            return

        if self.path == "/api/system/info":
            self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
            hostname = socket.gethostname(); os_info = sys.platform; version = "1.2.0"
            if os.path.exists(VERSION_PATH):
                try:
                    with open(VERSION_PATH) as f: version = json.load(f).get("version", "1.2.0")
                except: pass
            self.wfile.write(json.dumps({"version": version, "hostname": hostname, "os": os_info}).encode("utf-8"))
            return

        if self.path == "/api/events/recent":
            self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
            self.wfile.write(json.dumps(list(_event_log)).encode("utf-8"))
            return

        if self.path == "/api/auth/status":
            self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
            cfg = load_config()
            self.wfile.write(json.dumps({"authenticated": self.is_authenticated(), "panel_name": cfg.get("panel_name", "WARD"), "theme": cfg.get("theme", {})}).encode("utf-8"))
            return

        if not self.is_authenticated() and self.path not in ["/", "/index.html", "/favicon.svg", "/favicon.ico"]:
            self.send_response(401); self.send_header("Content-Type", "application/json"); self.end_headers()
            self.wfile.write(b'{"error": "Unauthorized"}'); return

        if self.path == "/api/status":
            self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
            self.wfile.write(json.dumps(collect_metrics()).encode("utf-8"))
            
        elif self.path == "/api/system/check-update":
            curr_v = "1.2.0"
            if os.path.exists(VERSION_PATH):
                try:
                    with open(VERSION_PATH) as f: curr_v = json.load(f).get("version", "1.2.0")
                except: pass
            remote_v = curr_v
            try:
                url = "https://raw.githubusercontent.com/h4m1dr/ward/main/version.json"
                req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
                with urllib.request.urlopen(req, timeout=4) as response:
                    data = json.loads(response.read().decode()); remote_v = data.get("version", curr_v)
            except: pass
            self.send_response(200); self.send_header("Content-Type", "application/json"); self.send_header("Access-Control-Allow-Origin", "*"); self.end_headers()
            self.wfile.write(json.dumps({"current": curr_v, "latest": remote_v, "has_update": (remote_v != curr_v)}).encode("utf-8"))
            
        elif self.path == "/api/taskmanager/snapshot":
            self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
            self.wfile.write(json.dumps({"processes": scan_all_processes()}).encode("utf-8"))
            
        elif self.path == "/api/services/snapshot":
            self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
            self.wfile.write(json.dumps({"services": scan_systemd_services()}).encode("utf-8"))
            
        elif self.path == "/api/ports/snapshot":
            self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
            self.wfile.write(json.dumps({"ports": get_active_listening_ports()}).encode("utf-8"))
            
        elif self.path.startswith("/api/storage/explore?"):
            qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            target = qs.get("path", ["/"])[0]
            self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
            result = explore_directory_tree(target)
            self.wfile.write(json.dumps(result).encode("utf-8"))
            
        elif self.path.startswith("/api/service/logs?"):
            qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            srv = qs.get("name", [""])[0]; logs = "No logs available"
            if srv:
                res = subprocess.run(["journalctl", "-u", "ward", "-n", "35", "--no-pager"], capture_output=True, text=True)
                logs = res.stdout or res.stderr
            self.send_response(200); self.send_header("Content-Type", "text/plain; charset=utf-8"); self.end_headers()
            self.wfile.write(logs.encode("utf-8"))

        elif self.path == "/api/tasks/list":
            cfg = load_config(); self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
            self.wfile.write(json.dumps({"tasks": cfg.get("scheduled_tasks", [])}).encode("utf-8"))

        elif self.path == "/api/settings/config":
            cfg = load_config(); self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
            self.wfile.write(json.dumps({"config": cfg}).encode("utf-8"))

        elif self.path in ["/favicon.svg", "/favicon.ico"]:
            self.send_response(200); self.send_header("Content-Type", "image/svg+xml"); self.send_header("Access-Control-Allow-Origin", "*"); self.send_header("Cache-Control", "public, max-age=86400"); self.end_headers()
            favicon_path = os.path.join(INSTALL_DIR, "favicon.svg")
            if os.path.exists(favicon_path):
                with open(favicon_path, "rb") as f: self.wfile.write(f.read())
            else: self.send_response(404); self.end_headers()
            
        elif self.path in ["/", "/index.html"]:
            self.send_response(200); self.send_header("Content-Type", "text/html; charset=utf-8"); self.end_headers()
            index_path = os.path.join(INSTALL_DIR, "index.html")
            if os.path.exists(index_path):
                with open(index_path, "rb") as f: self.wfile.write(f.read())
            else: self.send_response(404); self.end_headers()
        else: self.send_response(404); self.end_headers()

    def do_POST(self):
        length = int(self.headers.get('content-length', 0))
        payload = json.loads(self.rfile.read(length).decode('utf-8')) if length > 0 else {}
        
        if self.path == "/api/auth/login":
            pw = payload.get("password", ""); cfg = load_config()
            if hash_pw(pw) == cfg.get("admin_password_hash"):
                token = secrets.token_hex(24); _active_sessions.add(token)
                self.send_response(200); self.send_header("Content-Type", "application/json")
                self.send_header("Set-Cookie", f"ward_token={token}; Path=/; HttpOnly; SameSite=Lax"); self.end_headers()
                self.wfile.write(json.dumps({"status": "ok", "token": token}).encode("utf-8"))
                log_event('info', 'Login Success', f'New session started from {self.client_address[0]}', 'auth')
            else:
                self.send_response(401); self.send_header("Content-Type", "application/json"); self.end_headers()
                self.wfile.write(b'{"status": "error", "message": "Invalid Password"}')
                log_event('warn', 'Login Failed', f'Failed attempt from {self.client_address[0]}', 'auth')
            return

        if not self.is_authenticated():
            self.send_response(401); self.send_header("Content-Type", "application/json"); self.end_headers()
            self.wfile.write(b'{"error": "Unauthorized"}'); return

        cfg = load_config()

        if self.path == "/api/system/apply-update":
            update_script = os.path.join(INSTALL_DIR, "update.sh")
            if not os.path.exists(update_script):
                self.send_response(500); self.send_header("Content-Type", "application/json"); self.end_headers()
                self.wfile.write(b'{"error": "update.sh script not found"}'); return
            def do_up():
                time.sleep(1.5)
                try:
                    os.chmod(update_script, 0o755); subprocess.run(["bash", update_script], capture_output=True, text=True)
                except: pass
            threading.Thread(target=do_up, daemon=True).start()
            self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
            self.wfile.write(b'{"status": "updating"}')
            log_event('info', 'Update Started', 'System update initiated via UI', 'updater')
            return

        if self.path == "/api/auth/logout":
            token = self.headers.get("X-Session-Token", ""); _active_sessions.discard(token)
            self.send_response(200); self.send_header("Content-Type", "application/json")
            self.send_header("Set-Cookie", "ward_token=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT"); self.end_headers()
            self.wfile.write(b'{"status": "ok"}')
            log_event('info', 'Logout', 'Session terminated', 'auth')
            return

        if self.path == "/api/settings/change-password":
            old_pw = payload.get("old_password", ""); new_pw = payload.get("new_password", "")
            if hash_pw(old_pw) == cfg.get("admin_password_hash"):
                cfg["admin_password_hash"] = hash_pw(new_pw); save_config(cfg)
                self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
                self.wfile.write(b'{"status": "ok"}')
                log_event('crit', 'Password Changed', 'Admin password was updated', 'security')
            else:
                self.send_response(401); self.send_header("Content-Type", "application/json"); self.end_headers()
                self.wfile.write(b'{"status": "error", "message": "Current password is incorrect"}')
            return

        elif self.path == "/api/settings/restore-config":
            new_cfg = payload.get("config", {})
            if "admin_password_hash" in new_cfg and "panel_port" in new_cfg:
                save_config(new_cfg); self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
                self.wfile.write(b'{"status": "ok"}')
                log_event('warn', 'Config Restored', 'Configuration restored from backup', 'settings')
            else:
                self.send_response(400); self.send_header("Content-Type", "application/json"); self.end_headers()
                self.wfile.write(b'{"status": "error", "message": "Invalid config format"}')
            return

        elif self.path == "/api/settings/update-theme":
            new_theme = payload.get("theme", {})
            if "theme" not in cfg: cfg["theme"] = {}
            cfg["theme"].update(new_theme); save_config(cfg)
            self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
            self.wfile.write(b'{"status": "ok"}')
            return

        elif self.path == "/api/tasks/add":
            tasks = cfg.setdefault("scheduled_tasks", [])
            tasks.append({"name": payload.get("name"), "command": payload.get("command"), "schedule_type": payload.get("schedule_type"), "schedule_value": payload.get("schedule_value"), "enabled": payload.get("enabled", True)})
            save_config(cfg); self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
            self.wfile.write(b'{"status": "ok"}')
            return

        elif self.path == "/api/tasks/toggle":
            idx = payload.get("index"); tasks = cfg.get("scheduled_tasks", [])
            if isinstance(idx, int) and 0 <= idx < len(tasks):
                tasks[idx]["enabled"] = payload.get("enabled", True); save_config(cfg)
            self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
            self.wfile.write(b'{"status": "ok"}')
            return

        elif self.path == "/api/tasks/delete":
            idx = payload.get("index"); tasks = cfg.get("scheduled_tasks", [])
            if isinstance(idx, int) and 0 <= idx < len(tasks):
                tasks.pop(idx); save_config(cfg)
            self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
            self.wfile.write(b'{"status": "ok"}')
            return

        if self.path == "/api/config/add":
            t, v = payload.get("type"), payload.get("value")
            if t == "app" and v not in cfg.get("monitored_apps", []): cfg.setdefault("monitored_apps", []).append(v)
            elif t == "service" and v not in cfg.get("monitored_services", []): cfg.setdefault("monitored_services", []).append(v)
            elif t == "port" and int(v) not in cfg.get("monitored_ports", []): cfg.setdefault("monitored_ports", []).append(int(v))
            elif t == "blocked_port" and int(v) not in cfg.get("blocked_ports_trigger", []): cfg.setdefault("blocked_ports_trigger", []).append(int(v))
            elif t == "directory": cfg["monitored_directories"][payload.get("name")] = v

        elif self.path == "/api/config/remove":
            t, v = payload.get("type"), payload.get("value")
            if t == "app": cfg["monitored_apps"] = [x for x in cfg.get("monitored_apps", []) if x != v]
            elif t == "service": cfg["monitored_services"] = [x for x in cfg.get("monitored_services", []) if x != v]
            elif t == "port": cfg["monitored_ports"] = [x for x in cfg.get("monitored_ports", []) if str(x) != str(v)]
            elif t == "blocked_port": cfg["blocked_ports_trigger"] = [x for x in cfg.get("blocked_ports_trigger", []) if str(x) != str(v)]
            elif t == "directory": cfg["monitored_directories"].pop(v, None)

        save_config(cfg)
        self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
        self.wfile.write(b'{"status": "ok"}')

if __name__ == "__main__":
    cfg = load_config(); port = int(cfg.get("panel_port", 54321))
    server = HTTPServer(("127.0.0.1", port), RequestHandler)
    print(f"WARD Server running on port {port}")
    server.serve_forever()import os
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
_prev_cpu_idle = 0
_prev_cpu_total = 0
_prev_net_time = 0
_prev_disk_stats = {} # {device: (sectors_read, sectors_written)}
_known_listening_ports = set()
_proc_cpu_prev = {}

def hash_pw(pw):
    return hashlib.sha256(pw.encode('utf-8')).hexdigest()

def log_event(severity, title, message, source="system"):
    """Thread-safe event logging for notification drawer"""
    event = {
        "id": secrets.token_hex(8),
        "timestamp": int(time.time()),
        "severity": severity,
        "title": title,
        "message": message,
        "source": source
    }
    _event_log.append(event)

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
        "theme": {
            "primary": "#00ab44",
            "success": "#00d68f",
            "danger": "#ff3366",
            "bg": "#1a1d29",
            "card": "#252836",
            "text": "#e8e8e8"
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
    """LAW #4: Atomic Write Pattern to prevent config corruption"""
    tmp_path = CONFIG_PATH + ".tmp"
    try:
        with open(tmp_path, 'w') as f:
            json.dump(cfg, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, CONFIG_PATH)
        return True
    except Exception:
        try: 
            if os.path.exists(tmp_path): os.remove(tmp_path)
        except: pass
        return False

# === SECTION 2.8: ADVANCED TELEMETRY FUNCTIONS ===

def get_cpu_info():
    """Returns CPU stats including User, System and IO Wait percentages"""
    global _prev_cpu_idle, _prev_cpu_total
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
    
    cpu_data = {"user": 0.0, "nice": 0.0, "system": 0.0, "idle": 0.0, "iowait": 0.0}
    try:
        with open("/proc/stat", "r") as f:
            fields = [float(x) for x in f.readline().strip().split()[1:]]
        
        user, nice, system, idle, iowait = fields[0], fields[1], fields[2], fields[3], fields[4]
        total = sum(fields[:8]) if len(fields) >= 8 else sum(fields[:5])
        
        diff_user = user - _prev_cpu_idle # Note: using prev as baseline for delta
        # Correct delta calculation requires storing all previous fields
        # Simplified approach for this refactor: store full tuple next time
        # For now, let's use a proper delta implementation
        
    except Exception:
        pass
        
    # Re-implementing with proper state tracking for deltas
    try:
        with open("/proc/stat", "r") as f:
            current_fields = [int(x) for x in f.readline().strip().split()[1:]]
            
        curr_user, curr_nice, curr_sys, curr_idle, curr_iowait = current_fields[0], current_fields[1], current_fields[2], current_fields[3], current_fields[4]
        curr_total = sum(current_fields[:8]) if len(current_fields) >= 8 else sum(current_fields[:5])
        
        if _prev_cpu_total > 0:
            diff_total = curr_total - _prev_cpu_total
            if diff_total > 0:
                cpu_data["user"] = round(((curr_user - _prev_cpu_idle + curr_nice - (_prev_cpu_total - _prev_cpu_idle - _prev_cpu_total)) / diff_total) * 100, 1) # Simplified logic below
                
                # Proper Delta Calculation
                d_user = curr_user - getattr(get_cpu_info, '_prev_user', curr_user)
                d_nice = curr_nice - getattr(get_cpu_info, '_prev_nice', curr_nice)
                d_sys = curr_sys - getattr(get_cpu_info, '_prev_sys', curr_sys)
                d_idle = curr_idle - getattr(get_cpu_info, '_prev_idle', curr_idle)
                d_iowait = curr_iowait - getattr(get_cpu_info, '_prev_iowait', curr_iowait)
                
                d_total = d_user + d_nice + d_sys + d_idle + d_iowait
                if d_total > 0:
                    cpu_data["user"] = round((d_user / d_total) * 100, 1)
                    cpu_data["system"] = round((d_sys / d_total) * 100, 1)
                    cpu_data["iowait"] = round((d_iowait / d_total) * 100, 1)
                    
                # Save state for next iteration
                get_cpu_info._prev_user = curr_user
                get_cpu_info._prev_nice = curr_nice
                get_cpu_info._prev_sys = curr_sys
                get_cpu_info._prev_idle = curr_idle
                get_cpu_info._prev_iowait = curr_iowait
                
        _prev_cpu_total = curr_total
        _prev_cpu_idle = curr_idle # Legacy var update
        
    except Exception:
        pass
        
    total_pct = min(100.0, max(0.0, cpu_data["user"] + cpu_data["system"] + cpu_data["iowait"]))
    
    return {
        "model": model, 
        "cores": max(cores, 1), 
        "total_percent": round(total_pct, 1),
        "user_percent": cpu_data["user"],
        "system_percent": cpu_data["system"],
        "iowait_percent": cpu_data["iowait"]
    }

def get_network_stats():
    """Returns per-interface network stats and totals"""
    global _prev_net_time
    interfaces = {}
    total_rx = total_tx = 0
    
    try:
        with open("/proc/net/dev", "r") as f:
            lines = f.readlines()[2:]
            for line in lines:
                parts = line.split()
                iface = parts[0].strip(":")
                if iface == "lo": continue
                
                rx_bytes = int(parts[1])
                tx_bytes = int(parts[9])
                rx_errs = int(parts[3])
                tx_errs = int(parts[11])
                rx_drops = int(parts[4])
                tx_drops = int(parts[12])
                
                total_rx += rx_bytes
                total_tx += tx_bytes
                
                interfaces[iface] = {
                    "rx_bytes_sec": 0, "tx_bytes_sec": 0,
                    "errors": rx_errs + tx_errs, "drops": rx_drops + tx_drops
                }
    except Exception:
        pass
        
    now = time.time()
    if _prev_net_time > 0:
        diff_t = max(now - _prev_net_time, 0.001)
        for iface in interfaces:
            # In a real persistent app, we'd store prev values per interface
            # Here we rely on the fact that /proc/net/dev is cumulative
            # For this refactor, we'll assume frontend handles smoothing or 
            # we implement a simple cache here. 
            # Implementing simple cache for accuracy:
            pass 
            
    # Since we need deltas, let's use a module-level dict for prev interface stats
    if not hasattr(get_network_stats, '_prev_iface'):
        get_network_stats._prev_iface = {}
        
    now = time.time()
    diff_t = max(now - _prev_net_time, 0.001) if _prev_net_time > 0 else 1.0
    
    for iface, stats in interfaces.items():
        prev = get_network_stats._prev_iface.get(iface, {"rx": 0, "tx": 0})
        rx_delta = max(stats["rx_bytes_sec_placeholder"] - prev["rx"], 0) if "rx_bytes_sec_placeholder" in stats else 0 
        # Wait, I need actual cumulative bytes from /proc/net/dev, not rates yet.
        # Let's re-parse properly inside the delta block.
        pass

    # CORRECTED NETWORK FUNCTION WITH DELTAS
    net_ifaces = {}
    tot_rx = tot_tx = 0
    try:
        with open("/proc/net/dev", "r") as f:
            for line in f.readlines()[2:]:
                p = line.split()
                name = p[0].rstrip(':')
                if name == 'lo': continue
                rx = int(p[1]); tx = int(p[9])
                errs = int(p[3]) + int(p[11])
                drops = int(p[4]) + int(p[12])
                tot_rx += rx; tot_tx += tx
                net_ifaces[name] = {"rx": rx, "tx": tx, "errs": errs, "drops": drops}
    except: pass

    now = time.time()
    dt = max(now - _prev_net_time, 0.001) if _prev_net_time > 0 else 1.0
    prev_ifaces = getattr(get_network_stats, '_prev_iface', {})
    
    result_ifaces = {}
    for name, cur in net_ifaces.items():
        prev = prev_ifaces.get(name, {"rx": cur["rx"], "tx": cur["tx"]})
        rxd = max(cur["rx"] - prev["rx"], 0) / (dt * 1024 * 1024)
        txd = max(cur["tx"] - prev["tx"], 0) / (dt * 1024 * 1024)
        result_ifaces[name] = {
            "rx_bytes_sec": round(rxd * 1024 * 1024), # Keep raw bytes for frontend conversion if needed, or MB/s
            "tx_bytes_sec": round(txd * 1024 * 1024),
            "errors": cur["errs"], "drops": cur["drops"]
        }
        # Actually spec says MB/s in some places but bytes in contract. Contract wins.
        result_ifaces[name]["rx_bytes_sec"] = round(rxd * 1024 * 1024)
        result_ifaces[name]["tx_bytes_sec"] = round(txd * 1024 * 1024)

    get_network_stats._prev_iface = net_ifaces
    _prev_net_time = now
    
    # Calculate totals based on deltas too if possible, or just sum current rates
    # Spec contract uses total_rx_bytes (cumulative). Let's provide both.
    return {
        "interfaces": result_ifaces,
        "total_rx_bytes": tot_rx,
        "total_tx_bytes": tot_tx
    }

def get_disk_io():
    """Calculates Read/Write speeds in Bytes/sec from /proc/diskstats"""
    global _prev_disk_stats
    read_bytes_sec = write_bytes_sec = 0
    mount_point = "/"
    device = "unknown"
    
    try:
        # Find root device
        res = subprocess.run(["findmnt", "-n", "-o", "SOURCE", "/"], capture_output=True, text=True, timeout=2)
        if res.returncode == 0:
            dev_path = res.stdout.strip()
            device = os.path.basename(dev_path)
            
        # Parse diskstats
        with open("/proc/diskstats", "r") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 14 and parts[2] == device:
                    # Fields 6 (sectors read) and 10 (sectors written) are in 512-byte sectors
                    curr_read_sectors = int(parts[5])
                    curr_write_sectors = int(parts[9])
                    
                    prev = _prev_disk_stats.get(device, (curr_read_sectors, curr_write_sectors, time.time()))
                    now = time.time()
                    dt = max(now - prev[2], 0.001)
                    
                    d_read = max(curr_read_sectors - prev[0], 0) * 512
                    d_write = max(curr_write_sectors - prev[1], 0) * 512
                    
                    read_bytes_sec = d_read / dt
                    write_bytes_sec = d_write / dt
                    
                    _prev_disk_stats[device] = (curr_read_sectors, curr_write_sectors, now)
                    break
    except Exception:
        pass
        
    return {
        "mount_point": mount_point,
        "device": device,
        "read_bytes_sec": round(read_bytes_sec),
        "write_bytes_sec": round(write_bytes_sec)
    }

def get_connection_states():
    """Counts TCP/UDP states from /proc/net/tcp and /proc/net/udp"""
    tcp_est = tcp_tw = udp_active = 0
    try:
        with open("/proc/net/tcp", "r") as f:
            for line in f.readlines()[1:]:
                state = line.strip().split()[3]
                if state == "01": tcp_est += 1      # ESTABLISHED
                elif state == "06": tcp_tw += 1     # TIME_WAIT
    except: pass
    
    try:
        with open("/proc/net/udp", "r") as f:
            udp_active = len(f.readlines()[1:])
    except: pass
    
    return {
        "tcp_established": tcp_est,
        "tcp_time_wait": tcp_tw,
        "udp_active": udp_active,
        "total_sockets": tcp_est + tcp_tw + udp_active
    }

def collect_telemetry_overview():
    """Main aggregator for Section 2.8 Data Contract"""
    cfg = load_config()
    
    # Memory
    mem = {}
    try:
        with open('/proc/meminfo', 'r') as f:
            for line in f:
                parts = line.split(':')
                mem[parts[0].strip()] = int(parts[1].split()[0]) * 1024 # Convert KB to Bytes
    except: pass
    
    avail = mem.get('MemAvailable', 0)
    total = mem.get('MemTotal', 1)
    cached = mem.get('Cached', 0)
    swap_total = mem.get('SwapTotal', 0)
    swap_free = mem.get('SwapFree', 0)
    
    # Disk Space
    try:
        st = os.statvfs('/')
        d_total = st.f_blocks * st.f_frsize
        d_free = st.f_bavail * st.f_frsize
        d_used = d_total - d_free
    except:
        d_total = d_free = d_used = 0
        
    # Uptime & Load
    uptime_str = "0d 0h 0m"; load_str = "0.0 / 0.0 / 0.0"
    try:
        with open("/proc/uptime") as f:
            s = float(f.readline().split()[0])
            uptime_str = f"{int(s//86400)}d {int((s%86400)//3600)}h {int((s%3600)//60)}m"
        with open("/proc/loadavg") as f:
            p = f.readline().split()
            load_str = f"{p[0]} / {p[1]} / {p[2]}"
    except: pass

    return {
        "timestamp": int(time.time()),
        "cpu": get_cpu_info(),
        "memory": {
            "total_bytes": total,
            "used_bytes": total - avail,
            "available_bytes": avail,
            "cached_bytes": cached,
            "swap_total_bytes": swap_total,
            "swap_used_bytes": swap_total - swap_free
        },
        "disk": {
            **get_disk_io(),
            "total_bytes": d_total,
            "used_bytes": d_used,
            "free_bytes": d_free
        },
        "network": get_network_stats(),
        "connections": get_connection_states(),
        "uptime": uptime_str,
        "load_avg": load_str
    }


# === LEGACY FUNCTIONS PRESERVED FOR OTHER TABS ===
def get_active_listening_ports():
    ports = set()
    try:
        res = subprocess.run(["ss", "-tuln"], capture_output=True, text=True)
        for line in res.stdout.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 5:
                addr = parts[4]
                port_str = addr.rsplit(":", 1)[-1]
                if port_str.isdigit(): ports.add(int(port_str))
    except: pass
    return sorted(list(ports))

def get_dir_size_mb(path):
    if not os.path.exists(path): return 0.0
    try:
        res = subprocess.run(["du", "-sm", path], capture_output=True, text=True)
        if res.returncode == 0: return float(res.stdout.split()[0])
    except: pass
    return 0.0

def explore_directory_tree(path):
    if not os.path.exists(path) or not os.path.isdir(path):
        return {"items": [], "error": "Path does not exist"}
    virtual_fs = {'proc', 'sys', 'dev', 'run', 'snap'}
    items = []
    try:
        entries = os.listdir(path)
        for entry in entries:
            full_path = os.path.join(path, entry)
            if not os.path.isdir(full_path): continue
            if entry in virtual_fs: continue
            try:
                cmd = f"du -sm '{full_path}' 2>/dev/null"
                res = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
                size_mb = float(res.stdout.strip().split()[0]) if res.returncode == 0 and res.stdout.strip() else 0
                items.append({"name": entry, "path": full_path, "size_mb": size_mb})
            except: items.append({"name": entry, "path": full_path, "size_mb": 0})
        items.sort(key=lambda x: x["size_mb"], reverse=True)
        return {"items": items}
    except PermissionError: return {"items": [], "error": "Permission denied"}
    except Exception as e: return {"items": [], "error": str(e)}

def scan_all_processes():
    global _proc_cpu_prev
    procs = []; total_mem = 1
    try:
        with open('/proc/meminfo', 'r') as f:
            for line in f:
                if "MemTotal" in line: total_mem = int(line.split()[1]) * 1024; break
    except: pass
    now = time.time()
    for pid in [p for p in os.listdir('/proc') if p.isdigit()]:
        try:
            with open(f"/proc/{pid}/comm", "r") as f: comm = f.readline().strip()
            with open(f"/proc/{pid}/stat", "r") as f:
                sp = f.readline().split(); total_time = int(sp[13]) + int(sp[14])
            with open(f"/proc/{pid}/status", "r") as f:
                vm_rss = 0; threads = 1
                for s in f:
                    if s.startswith("VmRSS:"): vm_rss = int(s.split()[1]) * 1024
                    elif s.startswith("Threads:"): threads = int(s.split()[1])
            if vm_rss == 0: continue
            cpu = 0.0
            if pid in _proc_cpu_prev:
                old_time, old_t = _proc_cpu_prev[pid]; dt = now - old_t
                if dt > 0: cpu = round(((total_time - old_time) / (dt * 100)), 1)
            _proc_cpu_prev[pid] = (total_time, now)
            procs.append({"pid": int(pid), "name": comm, "cpu_pct": max(0.0, min(100.0, cpu)),
                          "memory_mb": round(vm_rss / (1024 * 1024), 2),
                          "memory_pct": round((vm_rss / total_mem) * 100, 1), "threads": threads})
        except: continue
    procs.sort(key=lambda x: x["memory_mb"], reverse=True)
    return procs

def scan_systemd_services():
    services = []
    try:
        res = subprocess.run(["systemctl", "list-units", "--type=service", "--all", "--no-pager", "--no-legend"], capture_output=True, text=True)
        for line in res.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 4 and parts[0].endswith(".service"):
                services.append({"name": parts[0][:-8], "state": parts[3], "sub": parts[2]})
    except: pass
    services.sort(key=lambda x: x["name"])
    return services

def get_pinned_apps(pinned_names):
    all_procs = scan_all_processes(); proc_dict = {}
    for p in all_procs:
        if p["name"] not in proc_dict: proc_dict[p["name"]] = p.copy()
        else:
            proc_dict[p["name"]]["memory_mb"] += p["memory_mb"]
            proc_dict[p["name"]]["memory_pct"] = round(proc_dict[p["name"]]["memory_pct"] + p["memory_pct"], 1)
            proc_dict[p["name"]]["cpu_pct"] = round(proc_dict[p["name"]]["cpu_pct"] + p["cpu_pct"], 1)
            proc_dict[p["name"]]["threads"] += p["threads"]
    result = []
    for name in pinned_names:
        if name in proc_dict:
            item = proc_dict[name].copy(); item["status"] = "Active"; result.append(item)
        else:
            result.append({"pid": "-", "name": name, "cpu_pct": 0.0, "memory_mb": 0.0, "memory_pct": 0.0, "threads": 0, "status": "Stopped"})
    return result

def collect_metrics():
    """Legacy metrics collector preserved for backward compatibility with older tabs"""
    cfg = load_config()
    cpu_data = get_cpu_info(); net_data = get_network_stats(); active_ports = get_active_listening_ports()
    mem = {}
    try:
        with open('/proc/meminfo', 'r') as f:
            for line in f:
                parts = line.split(':'); mem[parts[0].strip()] = int(parts[1].split()[0]) // 1024
    except: pass
    avail_ram = mem.get('MemAvailable', 0); total_ram = mem.get('MemTotal', 1); used_ram = total_ram - avail_ram
    total_swap = mem.get('SwapTotal', 1); free_swap = mem.get('SwapFree', 0); used_swap = total_swap - free_swap
    try:
        st = os.statvfs('/')
        total_disk = round((st.f_blocks * st.f_frsize) / (1024**3), 2)
        free_disk = round((st.f_bavail * st.f_frsize) / (1024**3), 2)
        used_disk = round(total_disk - free_disk, 2)
        used_disk_pct = round((used_disk / total_disk) * 100, 1)
    except: total_disk = free_disk = used_disk = used_disk_pct = 0.0
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
    tcp_count = udp_count = 0
    try:
        tcp_count = len([1 for l in open("/proc/net/tcp").readlines() if not l.strip().startswith("sl")])
        udp_count = len([1 for l in open("/proc/net/udp").readlines() if not l.strip().startswith("sl")])
    except: pass
    uptime = "0d 0h 0m"; load_avg = "0.0 / 0.0 / 0.0"
    try:
        with open("/proc/uptime") as f:
            s = float(f.readline().split()[0]); uptime = f"{int(s//86400)}d {int((s%86400)//3600)}h {int((s%3600)//60)}m"
        with open("/proc/loadavg") as f:
            p = f.readline().split(); load_avg = f"{p[0]} / {p[1]} / {p[2]}"
    except: pass
    default_theme = {"primary": "#00ab44", "success": "#00d68f", "danger": "#ff3366", "bg": "#1a1d29", "card": "#252836", "text": "#e8e8e8"}
    return {
        "panel_name": cfg.get("panel_name", "WARD"), "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "uptime": uptime, "load_avg": load_avg, "cpu": cpu_data,
        "ram": {"used_mb": used_ram, "total_mb": total_ram, "pct": round((used_ram/total_ram)*100, 1) if total_ram > 0 else 0.0},
        "swap": {"used_mb": used_swap, "total_mb": total_swap, "pct": round((used_swap/max(total_swap, 1))*100, 1)},
        "disk": {"used_gb": used_disk, "free_gb": free_disk, "total_gb": total_disk, "pct": used_disk_pct},
        "network": net_data, "connections": {"tcp": tcp_count, "udp": udp_count},
        "services": services_state, "ports": watched_ports, "all_open_ports": active_ports,
        "blocked_ports": cfg.get("blocked_ports_trigger", []), "caches": dir_sizes,
        "apps": pinned_apps, "tasks": cfg.get("scheduled_tasks", []), "theme": cfg.get("theme", default_theme)
    }

class RequestHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args): pass

    def is_authenticated(self):
        cfg = load_config()
        if not cfg.get("auth_enabled", True): return True
        token = self.headers.get("X-Session-Token", "")
        if not token:
            cookies = self.headers.get("Cookie", "")
            for c in cookies.split(";"):
                if "ward_token=" in c: token = c.split("ward_token=")[1].strip()
        return token in _active_sessions

    def do_GET(self):
        # NEW ENDPOINT: Telemetry Overview (Section 2.8)
        if self.path == "/api/telemetry/overview":
            self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
            self.wfile.write(json.dumps(collect_telemetry_overview()).encode("utf-8"))
            return

        if self.path == "/api/system/info":
            self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
            hostname = socket.gethostname(); os_info = sys.platform; version = "1.2.0"
            if os.path.exists(VERSION_PATH):
                try:
                    with open(VERSION_PATH) as f: version = json.load(f).get("version", "1.2.0")
                except: pass
            self.wfile.write(json.dumps({"version": version, "hostname": hostname, "os": os_info}).encode("utf-8"))
            return

        if self.path == "/api/events/recent":
            self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
            self.wfile.write(json.dumps(list(_event_log)).encode("utf-8"))
            return

        if self.path == "/api/auth/status":
            self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
            cfg = load_config()
            self.wfile.write(json.dumps({"authenticated": self.is_authenticated(), "panel_name": cfg.get("panel_name", "WARD"), "theme": cfg.get("theme", {})}).encode("utf-8"))
            return

        if not self.is_authenticated() and self.path not in ["/", "/index.html", "/favicon.svg", "/favicon.ico"]:
            self.send_response(401); self.send_header("Content-Type", "application/json"); self.end_headers()
            self.wfile.write(b'{"error": "Unauthorized"}'); return

        if self.path == "/api/status":
            self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
            self.wfile.write(json.dumps(collect_metrics()).encode("utf-8"))
            
        elif self.path == "/api/system/check-update":
            curr_v = "1.2.0"
            if os.path.exists(VERSION_PATH):
                try:
                    with open(VERSION_PATH) as f: curr_v = json.load(f).get("version", "1.2.0")
                except: pass
            remote_v = curr_v
            try:
                url = "https://raw.githubusercontent.com/h4m1dr/ward/main/version.json"
                req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
                with urllib.request.urlopen(req, timeout=4) as response:
                    data = json.loads(response.read().decode()); remote_v = data.get("version", curr_v)
            except: pass
            self.send_response(200); self.send_header("Content-Type", "application/json"); self.send_header("Access-Control-Allow-Origin", "*"); self.end_headers()
            self.wfile.write(json.dumps({"current": curr_v, "latest": remote_v, "has_update": (remote_v != curr_v)}).encode("utf-8"))
            
        elif self.path == "/api/taskmanager/snapshot":
            self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
            self.wfile.write(json.dumps({"processes": scan_all_processes()}).encode("utf-8"))
            
        elif self.path == "/api/services/snapshot":
            self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
            self.wfile.write(json.dumps({"services": scan_systemd_services()}).encode("utf-8"))
            
        elif self.path == "/api/ports/snapshot":
            self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
            self.wfile.write(json.dumps({"ports": get_active_listening_ports()}).encode("utf-8"))
            
        elif self.path.startswith("/api/storage/explore?"):
            qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            target = qs.get("path", ["/"])[0]
            self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
            result = explore_directory_tree(target)
            self.wfile.write(json.dumps(result).encode("utf-8"))
            
        elif self.path.startswith("/api/service/logs?"):
            qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            srv = qs.get("name", [""])[0]; logs = "No logs available"
            if srv:
                res = subprocess.run(["journalctl", "-u", "ward", "-n", "35", "--no-pager"], capture_output=True, text=True)
                logs = res.stdout or res.stderr
            self.send_response(200); self.send_header("Content-Type", "text/plain; charset=utf-8"); self.end_headers()
            self.wfile.write(logs.encode("utf-8"))

        elif self.path == "/api/tasks/list":
            cfg = load_config(); self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
            self.wfile.write(json.dumps({"tasks": cfg.get("scheduled_tasks", [])}).encode("utf-8"))

        elif self.path == "/api/settings/config":
            cfg = load_config(); self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
            self.wfile.write(json.dumps({"config": cfg}).encode("utf-8"))

        elif self.path in ["/favicon.svg", "/favicon.ico"]:
            self.send_response(200); self.send_header("Content-Type", "image/svg+xml"); self.send_header("Access-Control-Allow-Origin", "*"); self.send_header("Cache-Control", "public, max-age=86400"); self.end_headers()
            favicon_path = os.path.join(INSTALL_DIR, "favicon.svg")
            if os.path.exists(favicon_path):
                with open(favicon_path, "rb") as f: self.wfile.write(f.read())
            else: self.send_response(404); self.end_headers()
            
        elif self.path in ["/", "/index.html"]:
            self.send_response(200); self.send_header("Content-Type", "text/html; charset=utf-8"); self.end_headers()
            index_path = os.path.join(INSTALL_DIR, "index.html")
            if os.path.exists(index_path):
                with open(index_path, "rb") as f: self.wfile.write(f.read())
            else: self.send_response(404); self.end_headers()
        else: self.send_response(404); self.end_headers()

    def do_POST(self):
        length = int(self.headers.get('content-length', 0))
        payload = json.loads(self.rfile.read(length).decode('utf-8')) if length > 0 else {}
        
        if self.path == "/api/auth/login":
            pw = payload.get("password", ""); cfg = load_config()
            if hash_pw(pw) == cfg.get("admin_password_hash"):
                token = secrets.token_hex(24); _active_sessions.add(token)
                self.send_response(200); self.send_header("Content-Type", "application/json")
                self.send_header("Set-Cookie", f"ward_token={token}; Path=/; HttpOnly; SameSite=Lax"); self.end_headers()
                self.wfile.write(json.dumps({"status": "ok", "token": token}).encode("utf-8"))
                log_event('info', 'Login Success', f'New session started from {self.client_address[0]}', 'auth')
            else:
                self.send_response(401); self.send_header("Content-Type", "application/json"); self.end_headers()
                self.wfile.write(b'{"status": "error", "message": "Invalid Password"}')
                log_event('warn', 'Login Failed', f'Failed attempt from {self.client_address[0]}', 'auth')
            return

        if not self.is_authenticated():
            self.send_response(401); self.send_header("Content-Type", "application/json"); self.end_headers()
            self.wfile.write(b'{"error": "Unauthorized"}'); return

        cfg = load_config()

        if self.path == "/api/system/apply-update":
            update_script = os.path.join(INSTALL_DIR, "update.sh")
            if not os.path.exists(update_script):
                self.send_response(500); self.send_header("Content-Type", "application/json"); self.end_headers()
                self.wfile.write(b'{"error": "update.sh script not found"}'); return
            def do_up():
                time.sleep(1.5)
                try:
                    os.chmod(update_script, 0o755); subprocess.run(["bash", update_script], capture_output=True, text=True)
                except: pass
            threading.Thread(target=do_up, daemon=True).start()
            self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
            self.wfile.write(b'{"status": "updating"}')
            log_event('info', 'Update Started', 'System update initiated via UI', 'updater')
            return

        if self.path == "/api/auth/logout":
            token = self.headers.get("X-Session-Token", ""); _active_sessions.discard(token)
            self.send_response(200); self.send_header("Content-Type", "application/json")
            self.send_header("Set-Cookie", "ward_token=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT"); self.end_headers()
            self.wfile.write(b'{"status": "ok"}')
            log_event('info', 'Logout', 'Session terminated', 'auth')
            return

        if self.path == "/api/settings/change-password":
            old_pw = payload.get("old_password", ""); new_pw = payload.get("new_password", "")
            if hash_pw(old_pw) == cfg.get("admin_password_hash"):
                cfg["admin_password_hash"] = hash_pw(new_pw); save_config(cfg)
                self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
                self.wfile.write(b'{"status": "ok"}')
                log_event('crit', 'Password Changed', 'Admin password was updated', 'security')
            else:
                self.send_response(401); self.send_header("Content-Type", "application/json"); self.end_headers()
                self.wfile.write(b'{"status": "error", "message": "Current password is incorrect"}')
            return

        elif self.path == "/api/settings/restore-config":
            new_cfg = payload.get("config", {})
            if "admin_password_hash" in new_cfg and "panel_port" in new_cfg:
                save_config(new_cfg); self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
                self.wfile.write(b'{"status": "ok"}')
                log_event('warn', 'Config Restored', 'Configuration restored from backup', 'settings')
            else:
                self.send_response(400); self.send_header("Content-Type", "application/json"); self.end_headers()
                self.wfile.write(b'{"status": "error", "message": "Invalid config format"}')
            return

        elif self.path == "/api/settings/update-theme":
            new_theme = payload.get("theme", {})
            if "theme" not in cfg: cfg["theme"] = {}
            cfg["theme"].update(new_theme); save_config(cfg)
            self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
            self.wfile.write(b'{"status": "ok"}')
            return

        elif self.path == "/api/tasks/add":
            tasks = cfg.setdefault("scheduled_tasks", [])
            tasks.append({"name": payload.get("name"), "command": payload.get("command"), "schedule_type": payload.get("schedule_type"), "schedule_value": payload.get("schedule_value"), "enabled": payload.get("enabled", True)})
            save_config(cfg); self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
            self.wfile.write(b'{"status": "ok"}')
            return

        elif self.path == "/api/tasks/toggle":
            idx = payload.get("index"); tasks = cfg.get("scheduled_tasks", [])
            if isinstance(idx, int) and 0 <= idx < len(tasks):
                tasks[idx]["enabled"] = payload.get("enabled", True); save_config(cfg)
            self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
            self.wfile.write(b'{"status": "ok"}')
            return

        elif self.path == "/api/tasks/delete":
            idx = payload.get("index"); tasks = cfg.get("scheduled_tasks", [])
            if isinstance(idx, int) and 0 <= idx < len(tasks):
                tasks.pop(idx); save_config(cfg)
            self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
            self.wfile.write(b'{"status": "ok"}')
            return

        if self.path == "/api/config/add":
            t, v = payload.get("type"), payload.get("value")
            if t == "app" and v not in cfg.get("monitored_apps", []): cfg.setdefault("monitored_apps", []).append(v)
            elif t == "service" and v not in cfg.get("monitored_services", []): cfg.setdefault("monitored_services", []).append(v)
            elif t == "port" and int(v) not in cfg.get("monitored_ports", []): cfg.setdefault("monitored_ports", []).append(int(v))
            elif t == "blocked_port" and int(v) not in cfg.get("blocked_ports_trigger", []): cfg.setdefault("blocked_ports_trigger", []).append(int(v))
            elif t == "directory": cfg["monitored_directories"][payload.get("name")] = v

        elif self.path == "/api/config/remove":
            t, v = payload.get("type"), payload.get("value")
            if t == "app": cfg["monitored_apps"] = [x for x in cfg.get("monitored_apps", []) if x != v]
            elif t == "service": cfg["monitored_services"] = [x for x in cfg.get("monitored_services", []) if x != v]
            elif t == "port": cfg["monitored_ports"] = [x for x in cfg.get("monitored_ports", []) if str(x) != str(v)]
            elif t == "blocked_port": cfg["blocked_ports_trigger"] = [x for x in cfg.get("blocked_ports_trigger", []) if str(x) != str(v)]
            elif t == "directory": cfg["monitored_directories"].pop(v, None)

        save_config(cfg)
        self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
        self.wfile.write(b'{"status": "ok"}')

if __name__ == "__main__":
    cfg = load_config(); port = int(cfg.get("panel_port", 54321))
    server = HTTPServer(("127.0.0.1", port), RequestHandler)
    print(f"WARD Server running on port {port}")
    server.serve_forever()
