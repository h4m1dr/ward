import os
import sys
import json
import time
import socket
import secrets
import hashlib
import subprocess
import signal
import threading
import urllib.request
import urllib.parse
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime
from collections import deque
from concurrent.futures import ThreadPoolExecutor

# === CONFIGURATION & DIRECTORIES ===
INSTALL_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(INSTALL_DIR, "config.json")
VERSION_PATH = os.path.join(INSTALL_DIR, "version.json")

# === RUNTIME STATE ===
_active_sessions = set()
_event_log = deque(maxlen=100)
_prev_net = {}
_prev_net_time = 0.0
_prev_cpu = {}
_prev_disk = {}
_proc_cpu_prev = {}

# Caching for Port & Flow (LAW #4: Min 5s throttle)
_last_port_scan_time = 0.0
_cached_port_list = []
_port_owner_cache = {}
_last_owner_cache_time = 0.0

# LAW #1 & #2: Self-Exclusion & Protected Entities
SELF_PID = os.getpid()
PROTECTED_PIDS = {1, SELF_PID}
PROTECTED_UNITS = {
    "ward.service", "ward",
    "systemd-journald.service", "systemd-journald",
    "sshd.service", "sshd",
    "docker.service", "docker"
}

_thread_pool = ThreadPoolExecutor(max_workers=5)

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
        "auto_recovery_services": ["nginx.service"],
        "monitored_ports": [80, 443, 22, 7654],
        "monitored_domains": ["https://9z.ykno.ir", "https://hari2.ykno.ir"],
        "idle_threshold_minutes": 15,
        "monitored_directories": {"system_cache": "/var/cache", "tmp": "/tmp"},
        "watched_processes": [
            {"name": "nginx", "alias": "Nginx Web Server", "row_id": 1},
            {"name": "xray", "alias": "Xray Proxy Core", "row_id": 2},
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

def is_protected_unit(unit_name):
    clean = unit_name.strip()
    return clean in PROTECTED_UNITS or (clean + ".service") in PROTECTED_UNITS

# === SECTION 2: TELEMETRY ENGINE ===
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

    return {
        "model": "Linux Processor", "cores": cores, "total_percent": total_pct,
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
    d_total = d_used = d_free = 0

    try:
        st = os.statvfs(mount)
        d_total = st.f_blocks * st.f_frsize
        d_free = st.f_bavail * st.f_frsize
        d_used = d_total - d_free
    except Exception:
        pass

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
        "services": {s: "Running" for s in cfg.get("monitored_services", [])},
        "ports": {str(p): "Listening" for p in cfg.get("monitored_ports", [])},
        "caches": {}
    }

# === SECTION 3: PROCESS INSPECTOR LOGIC ===
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

# === SECTION 4: SERVICE MANAGER & GUARDIAN ===
def scan_all_services():
    cfg = load_config()
    watched = set(cfg.get("monitored_services", []))
    auto_recover = set(cfg.get("auto_recovery_services", []))

    units = []
    try:
        res = subprocess.run(
            ["systemctl", "list-units", "--type=service", "--all", "--no-pager", "--no-legend"],
            capture_output=True, text=True, timeout=4
        )
        for line in res.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 4 and parts[0].endswith(".service"):
                u_name = parts[0]
                base_name = u_name[:-8]
                sub_st = parts[2]
                active_st = parts[3]
                desc = " ".join(parts[4:]) if len(parts) > 4 else ""

                is_w = (base_name in watched or u_name in watched)
                is_ar = (base_name in auto_recover or u_name in auto_recover)
                is_p = is_protected_unit(u_name)

                units.append({
                    "name": u_name,
                    "description": desc,
                    "active_state": active_st,
                    "sub_state": sub_st,
                    "is_watched": is_w,
                    "auto_recovery": is_ar,
                    "is_protected": is_p
                })
    except Exception:
        pass

    # Sort watched first, then alphabetical
    units.sort(key=lambda x: (not x["is_watched"], x["name"]))
    return units

class ServiceGuardian(threading.Thread):
    def __init__(self, check_interval=10):
        super().__init__(daemon=True)
        self.check_interval = check_interval
        self.failure_counts = {}

    def run(self):
        while True:
            try:
                cfg = load_config()
                ar_units = cfg.get("auto_recovery_services", [])
                for u in ar_units:
                    if is_protected_unit(u):
                        continue
                    unit = u if u.endswith(".service") else (u + ".service")
                    res = subprocess.run(
                        ["systemctl", "show", unit, "--property=ActiveState,SubState", "--no-pager"],
                        capture_output=True, text=True, timeout=2
                    )
                    props = dict(l.split("=", 1) for l in res.stdout.strip().split("\n") if "=" in l)
                    active_st = props.get("ActiveState", "unknown")
                    sub_st = props.get("SubState", "unknown")

                    if active_st in ["failed", "inactive"] or sub_st in ["dead", "failed"]:
                        fc = self.failure_counts.get(unit, 0) + 1
                        self.failure_counts[unit] = fc
                        if fc <= 3:
                            log_event("warn", "Guardian Triggered", f"Service {unit} down. Attempting auto-restart ({fc}/3)", "guardian")
                            subprocess.run(["systemctl", "restart", unit], timeout=5)
                            log_event("info", "Auto-Recovered", f"Restarted {unit}", "guardian")
                        else:
                            log_event("crit", "Recovery Aborted", f"Service {unit} failed {fc} times. Intervention required.", "guardian")
                    else:
                        self.failure_counts[unit] = 0
            except Exception:
                pass
            time.sleep(self.check_interval)

_guardian = ServiceGuardian()
_guardian.start()

# === SECTION 5: PORTS & FLOW + WEB DOMAIN HEALTH ENGINE ===
def resolve_port_owner(port, proto="tcp"):
    global _port_owner_cache, _last_owner_cache_time
    now = time.time()
    # Cache port bindings for 60s
    if now - _last_owner_cache_time < 60 and port in _port_owner_cache:
        return _port_owner_cache[port]

    owner_name = "unknown"
    owner_pid = None
    try:
        flag = "-tlnp" if proto == "tcp" else "-ulnp"
        res = subprocess.run(["ss", flag, f"sport = :{port}"], capture_output=True, text=True, timeout=2)
        for line in res.stdout.splitlines():
            if "users:" in line:
                import re
                m = re.search(r'\("([^"]+)",pid=(\d+)', line)
                if m:
                    owner_name = m.group(1)
                    owner_pid = int(m.group(2))
                    break
    except Exception:
        pass

    _port_owner_cache[port] = (owner_name, owner_pid)
    _last_owner_cache_time = now
    return owner_name, owner_pid

def get_ports_intelligence():
    global _last_port_scan_time, _cached_port_list
    now = time.time()
    # LAW #4: 5s Cache for expensive network inspection
    if now - _last_port_scan_time < 5.0 and _cached_port_list:
        return _cached_port_list

    cfg = load_config()
    monitored = set(cfg.get("monitored_ports", []))
    idle_threshold = cfg.get("idle_threshold_minutes", 15)

    listening = set()
    try:
        res = subprocess.run(["ss", "-tuln"], capture_output=True, text=True, timeout=2)
        for line in res.stdout.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 5:
                proto = parts[0].lower()
                p_str = parts[4].rsplit(":", 1)[-1]
                if p_str.isdigit():
                    listening.add((int(p_str), proto))
    except Exception:
        pass

    # Count established TCP connections per port
    established_map = {}
    try:
        with open("/proc/net/tcp", "r") as f:
            for line in f.readlines()[1:]:
                parts = line.split()
                if len(parts) >= 4 and parts[3] == "01": # ESTABLISHED
                    local_hex = parts[1].split(":")[1]
                    p_num = int(local_hex, 16)
                    established_map[p_num] = established_map.get(p_num, 0) + 1
    except Exception:
        pass

    results = []
    # Build list for monitored ports + active listening ports
    all_ports_to_check = set(monitored)
    for p, _ in listening:
        all_ports_to_check.add(p)

    for p in sorted(all_ports_to_check):
        is_tcp = (p, "tcp") in listening
        is_udp = (p, "udp") in listening
        proto = "tcp" if is_tcp else ("udp" if is_udp else "tcp")
        is_listen = is_tcp or is_udp

        owner_name, owner_pid = resolve_port_owner(p, proto)
        estab_cnt = established_map.get(p, 0)

        # Idle logic
        if not is_listen:
            status = "down"
        elif estab_cnt == 0:
            status = "idle"
        else:
            status = "active"

        results.append({
            "port": p,
            "protocol": proto.upper(),
            "owner_name": owner_name,
            "owner_pid": owner_pid,
            "state": "LISTEN" if is_listen else "CLOSED",
            "established_count": estab_cnt,
            "status": status,
            "is_watched": (p in monitored)
        })

    _cached_port_list = results
    _last_port_scan_time = now
    return results

def check_domain_target(url):
    """Probes single URL with 3s timeout for Section 5.10 LAW #3"""
    try:
        req = urllib.request.Request(
            url, headers={"User-Agent": "Mozilla/5.0 (WARD Web Monitor)"}, method="HEAD"
        )
        t0 = time.time()
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            lat = round((time.time() - t0) * 1000, 1)
            code = resp.getcode()
            return {
                "url": url,
                "status_code": code,
                "latency_ms": lat,
                "state": "healthy" if code < 400 else "warn"
            }
    except urllib.error.HTTPError as e:
        return {"url": url, "status_code": e.code, "latency_ms": None, "state": "warn" if e.code < 500 else "crit"}
    except Exception:
        return {"url": url, "status_code": 0, "latency_ms": None, "state": "down"}

def check_all_web_domains():
    cfg = load_config()
    domains = cfg.get("monitored_domains", [])
    if not domains:
        return []
    futures = [_thread_pool.submit(check_domain_target, d) for d in domains]
    return [f.result() for f in futures]

# === HTTP REQUEST HANDLER ===
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
        # 1. Static & Public Endpoints
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

        if self.path == "/favicon.svg":
            self.send_response(200); self.send_header("Content-Type", "image/svg+xml"); self.end_headers()
            self.wfile.write(b'''<svg viewBox="0 0 128 128" xmlns="http://www.w3.org/2000/svg"><rect width="128" height="128" rx="26" fill="#141824"/><path d="M58 122L56 86Q54 64 45 48Q37 34 45 20Q53 8 64 8Q75 8 83 20Q91 34 83 48Q74 64 72 86L70 122Z" fill="#4d3727" stroke="#110c07" stroke-width="2"/><circle cx="64" cy="36" r="19" fill="#ffea00" stroke="#92400e" stroke-width="1.2"/><circle cx="64" cy="36" r="8" fill="#000"/></svg>''')
            return

        # 2. Auth Status
        if self.path == "/api/auth/status":
            self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
            cfg = load_config()
            self.wfile.write(json.dumps({
                "authenticated": self.is_authenticated(),
                "panel_name": cfg.get("panel_name", "WARD")
            }).encode("utf-8"))
            return

        # Protected APIs Require Authentication
        if not self.is_authenticated():
            self.send_response(401); self.end_headers(); return

        # 3. Telemetry & Events (Section 1 & 2)
        if self.path in ["/api/telemetry/overview", "/api/status"]:
            self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
            self.wfile.write(json.dumps(collect_telemetry()).encode("utf-8"))
            return

        if self.path == "/api/events/recent":
            self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
            self.wfile.write(json.dumps(list(_event_log)).encode("utf-8"))
            return

        # 4. Processes (Section 3)
        if self.path == "/api/processes/watched":
            self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
            self.wfile.write(json.dumps({
                "processes": get_watched_processes(),
                "total_system_cpu": get_cpu_telemetry()["total_percent"]
            }).encode("utf-8"))
            return

        if self.path.startswith("/api/processes/all"):
            self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
            self.wfile.write(json.dumps({"processes": scan_all_processes(limit=80)}).encode("utf-8"))
            return

        # 5. Services (Section 4)
        if self.path == "/api/services/list":
            units = scan_all_services()
            self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
            self.wfile.write(json.dumps({
                "units": units,
                "summary": {
                    "total": len(units),
                    "active": len([u for u in units if u["active_state"] == "active"]),
                    "failed": len([u for u in units if u["active_state"] == "failed"])
                }
            }).encode("utf-8"))
            return

        if self.path.startswith("/api/services/logs/"):
            unit = urllib.parse.unquote(self.path.split("/api/services/logs/")[1].split("?")[0])
            try:
                res = subprocess.run(["journalctl", "-u", unit, "-n", "40", "--no-pager"], capture_output=True, text=True, timeout=2)
                logs = res.stdout or res.stderr or "No logs found."
            except Exception as e:
                logs = str(e)
            self.send_response(200); self.send_header("Content-Type", "text/plain; charset=utf-8"); self.end_headers()
            self.wfile.write(logs.encode("utf-8"))
            return

        # 6. Ports & Flow (Section 5)
        if self.path == "/api/ports/list":
            ports = get_ports_intelligence()
            self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
            self.wfile.write(json.dumps({"ports": ports}).encode("utf-8"))
            return

        if self.path == "/api/web/health":
            domains_health = check_all_web_domains()
            self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
            self.wfile.write(json.dumps({"domains": domains_health}).encode("utf-8"))
            return

        self.send_response(404)
        self.end_headers()

    def do_POST(self):
        length = int(self.headers.get('content-length', 0))
        payload = json.loads(self.rfile.read(length).decode('utf-8')) if length > 0 else {}

        # Public Login
        if self.path == "/api/auth/login":
            pw = payload.get("password", "")
            cfg = load_config()
            if hash_pw(pw) == cfg.get("admin_password_hash"):
                token = secrets.token_hex(24)
                _active_sessions.add(token)
                self.send_response(200); self.send_header("Content-Type", "application/json")
                self.send_header("Set-Cookie", f"ward_token={token}; Path=/; HttpOnly; SameSite=Lax")
                self.end_headers()
                self.wfile.write(json.dumps({"status": "ok", "token": token}).encode("utf-8"))
                log_event("info", "Login", f"Auth success from {self.client_address[0]}")
            else:
                self.send_response(401); self.send_header("Content-Type", "application/json"); self.end_headers()
                self.wfile.write(b'{"status": "error", "message": "Invalid Password"}')
            return

        if not self.is_authenticated():
            self.send_response(401); self.end_headers(); return

        cfg = load_config()

        # SECTION 3 ACTIONS
        if self.path == "/api/processes/action":
            pid = payload.get("pid")
            action = payload.get("action")
            proc_name = payload.get("name", "")

            if action == "unwatch":
                watched = [w for w in cfg.get("watched_processes", []) if (w.get("name") if isinstance(w, dict) else w) != proc_name]
                cfg["watched_processes"] = watched
                save_config(cfg)
                self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
                self.wfile.write(json.dumps({"success": True}).encode("utf-8"))
                log_event("info", "Process Unwatched", f"Removed {proc_name}", "processes")
                return

            if not pid or is_protected_pid(int(pid)):
                self.send_response(403); self.send_header("Content-Type", "application/json"); self.end_headers()
                self.wfile.write(json.dumps({"success": False, "error": "Cannot signal protected PID"}).encode("utf-8"))
                log_event("crit", "Action Blocked", f"Blocked attempt to {action} PID {pid}", "security")
                return

            try:
                sig = signal.SIGTERM if action == "sigterm" else signal.SIGKILL
                os.kill(int(pid), sig)
                self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
                self.wfile.write(json.dumps({"success": True, "message": f"Sent {action} to PID {pid}"}).encode("utf-8"))
                log_event("warn", "Process Action", f"{action.upper()} to PID {pid}", "processes")
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
            watched.append({"name": name, "alias": alias, "row_id": len(watched) + 1})
            cfg["watched_processes"] = watched
            save_config(cfg)
            self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
            self.wfile.write(json.dumps({"success": True}).encode("utf-8"))
            log_event("info", "Process Watched", f"Added {name}", "processes")
            return

        if self.path == "/api/processes/reorder":
            order_names = payload.get("order", [])
            watched = cfg.get("watched_processes", [])
            name_map = { (w.get("name") if isinstance(w, dict) else w): w for w in watched }
            reordered = []
            for idx, n in enumerate(order_names):
                if n in name_map:
                    it = name_map[n]
                    if isinstance(it, dict): it["row_id"] = idx + 1
                    else: it = {"name": it, "alias": it, "row_id": idx + 1}
                    reordered.append(it)
            cfg["watched_processes"] = reordered
            save_config(cfg)
            self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
            self.wfile.write(b'{"success":true}'); return

        # SECTION 4 ACTIONS: SERVICES
        if self.path == "/api/services/action":
            unit = payload.get("unit", "").strip()
            action = payload.get("action", "").strip()

            if action == "daemon-reload":
                subprocess.run(["systemctl", "daemon-reload"], timeout=5)
                self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
                self.wfile.write(json.dumps({"success": True, "message": "daemon-reload executed"}).encode("utf-8"))
                log_event("info", "Systemd Reload", "systemctl daemon-reload executed", "services")
                return

            if not unit or is_protected_unit(unit):
                self.send_response(403); self.send_header("Content-Type", "application/json"); self.end_headers()
                self.wfile.write(json.dumps({"success": False, "error": "Operation not permitted on protected service"}).encode("utf-8"))
                log_event("crit", "Service Block", f"Attempted {action} on protected {unit}", "security")
                return

            if action in ["start", "stop", "restart", "enable", "disable"]:
                try:
                    subprocess.run(["systemctl", action, unit], timeout=6)
                    self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
                    self.wfile.write(json.dumps({"success": True, "message": f"{action} sent to {unit}"}).encode("utf-8"))
                    log_event("warn", "Service Control", f"{action.upper()} -> {unit}", "services")
                except Exception as e:
                    self.send_response(500); self.send_header("Content-Type", "application/json"); self.end_headers()
                    self.wfile.write(json.dumps({"success": False, "error": str(e)}).encode("utf-8"))
                return

        if self.path == "/api/services/configure":
            unit = payload.get("unit", "").strip()
            auto_rec = payload.get("auto_recovery")
            watch = payload.get("watch")

            ar_list = set(cfg.get("auto_recovery_services", []))
            ms_list = set(cfg.get("monitored_services", []))

            if auto_rec is not None:
                if auto_rec and not is_protected_unit(unit): ar_list.add(unit)
                else: ar_list.discard(unit); ar_list.discard(unit[:-8] if unit.endswith('.service') else unit)

            if watch is not None:
                base = unit[:-8] if unit.endswith('.service') else unit
                if watch: ms_list.add(base)
                else: ms_list.discard(base); ms_list.discard(unit)

            cfg["auto_recovery_services"] = list(ar_list)
            cfg["monitored_services"] = list(ms_list)
            save_config(cfg)
            self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
            self.wfile.write(json.dumps({"success": True}).encode("utf-8"))
            return

        # SECTION 5 ACTIONS: PORTS
        if self.path == "/api/ports/test":
            port = payload.get("port")
            proto = payload.get("protocol", "tcp").lower()
            if not port:
                self.send_response(400); self.end_headers(); return

            t0 = time.time()
            ok = False
            http_code = None
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2.0)
                res = s.connect_ex(("127.0.0.1", int(port)))
                if res == 0:
                    ok = True
                    # Optional probe for HTTP
                    try:
                        s.sendall(b"HEAD / HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n")
                        resp_data = s.recv(256).decode("utf-8", errors="ignore")
                        if "HTTP/" in resp_data:
                            http_code = int(resp_data.split()[1])
                    except Exception:
                        pass
                s.close()
            except Exception:
                pass
            lat = round((time.time() - t0) * 1000, 2)
            self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
            self.wfile.write(json.dumps({"tcp_ok": ok, "latency_ms": lat, "http_status": http_code}).encode("utf-8"))
            return

        if self.path == "/api/ports/configure":
            port = int(payload.get("port", 0))
            watch = payload.get("watch", True)
            ports_set = set(cfg.get("monitored_ports", []))
            if watch and port > 0: ports_set.add(port)
            elif not watch and port > 0: ports_set.discard(port)
            cfg["monitored_ports"] = sorted(list(ports_set))
            save_config(cfg)
            self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
            self.wfile.write(json.dumps({"success": True}).encode("utf-8"))
            return

        # Legacy config management
        if self.path == "/api/config/add":
            t, v = payload.get("type"), payload.get("value")
            if t == "directory":
                cfg.setdefault("monitored_directories", {})[payload.get("name")] = v
            save_config(cfg)
            self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
            self.wfile.write(b'{"status":"ok"}'); return

        if self.path == "/api/config/remove":
            t, v = payload.get("type"), payload.get("value")
            if t == "directory":
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
    print(f"WARD Server running on 127.0.0.1:{port}")
    server.serve_forever()
