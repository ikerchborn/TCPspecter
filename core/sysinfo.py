import os
import psutil
import socket
import time

# ─────────────────────────────────────────────────────────────────────────────
# CPU percent two-pass cache: psutil always returns 0.0 on the FIRST call
# for any process. We keep a persistent process iterator state between ticks.
# ─────────────────────────────────────────────────────────────────────────────
_cpu_warmed_up = False

def get_system_stats():
    """
    Returns general CPU/RAM stats.
    CPU usage, RAM usage, and virtual_memory status.
    """
    try:
        cpu_percent = psutil.cpu_percent(interval=None)
        mem = psutil.virtual_memory()
        ram_percent = mem.percent
        return {
            "cpu": cpu_percent,
            "ram": ram_percent,
            "total_ram": mem.total,
            "used_ram": mem.used,
            "free_ram": mem.available
        }
    except Exception:
        return {"cpu": 0.0, "ram": 0.0, "total_ram": 0, "used_ram": 0, "free_ram": 0}

def get_network_io():
    """
    Returns bytes sent/received since boot.
    """
    try:
        net_io = psutil.net_io_counters()
        return {
            "bytes_sent": net_io.bytes_sent,
            "bytes_recv": net_io.bytes_recv
        }
    except Exception:
        return {"bytes_sent": 0, "bytes_recv": 0}

def check_privileges():
    """
    Checks if the user has administrator privileges (UID == 0).
    """
    return os.geteuid() == 0

def get_process_list():
    """
    Fetches all active processes in the system.
    Returns a list of dicts with PID, Name, User, CPU%, RAM%.

    BUG #2 FIX: psutil.cpu_percent() always returns 0.0 on the FIRST call for
    any process because it needs two time samples to compute a delta. We call
    process_iter() once as a warm-up (seeding internal counters) and rely on
    Textual's 1.5-second refresh interval to produce meaningful values on the
    next tick. The global _cpu_warmed_up flag skips the duplicate warm-up pass
    after the very first invocation.
    """
    global _cpu_warmed_up

    processes = []
    try:
        proc_list = list(psutil.process_iter(
            ['pid', 'name', 'username', 'cpu_percent', 'memory_percent', 'status']
        ))

        # On first boot, seed cpu_percent counters for all processes and return
        # a list with 0.0 CPU (acceptable for first render frame).
        if not _cpu_warmed_up:
            _cpu_warmed_up = True
            # First pass just seeds the cpu_percent counters
            for proc in proc_list:
                try:
                    info = proc.info
                    pid = info['pid']
                    name = info['name'] or "?"
                    user = info['username'] or "?"
                    ram = info['memory_percent'] or 0.0
                    processes.append({
                        "pid": pid,
                        "name": name,
                        "user": user,
                        "cpu": 0.0,   # always 0 on first call
                        "ram": round(ram, 1),
                        "status": info.get('status', '?')
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                except Exception:
                    continue
            return processes

        # Subsequent passes: cpu_percent is now properly measured
        for proc in proc_list:
            try:
                info = proc.info
                pid = info['pid']
                name = info['name'] or "?"
                user = info['username'] or "?"
                cpu = info['cpu_percent'] or 0.0
                ram = info['memory_percent'] or 0.0
                processes.append({
                    "pid": pid,
                    "name": name,
                    "user": user,
                    "cpu": round(cpu, 1),
                    "ram": round(ram, 1),
                    "status": info.get('status', '?')
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            except Exception:
                continue

    except Exception:
        pass

    return processes

def get_process_connections(pid, protocol_filter="ALL"):
    """
    Fetches net connections for a specific process PID.
    Filters: TCP, UDP, LISTEN, ALL.
    """
    conns = []
    try:
        proc = psutil.Process(pid)
        connections = proc.connections(kind='inet')

        for conn in connections:
            is_tcp = (conn.type == socket.SOCK_STREAM)
            is_udp = (conn.type == socket.SOCK_DGRAM)

            proto = "TCP" if is_tcp else ("UDP" if is_udp else "UNKNOWN")
            # UDP connections have empty status — normalize to "UDP" label
            raw_status = conn.status if conn.status else ""
            status = raw_status if raw_status else ("-" if is_udp else "-")

            if protocol_filter == "TCP" and not is_tcp:
                continue
            if protocol_filter == "UDP" and not is_udp:
                continue
            if protocol_filter == "LISTEN" and status != "LISTEN":
                continue

            laddr_ip = conn.laddr.ip if conn.laddr else "-"
            laddr_port = conn.laddr.port if conn.laddr else "-"
            raddr_ip = conn.raddr.ip if conn.raddr else "-"
            raddr_port = conn.raddr.port if conn.raddr else "-"

            conns.append({
                "pid": pid,
                "name": proc.name(),
                "proto": proto,
                "laddr_ip": laddr_ip,
                "laddr_port": laddr_port,
                "raddr_ip": raddr_ip,
                "raddr_port": raddr_port,
                "status": status,
                "fd": conn.fd
            })
    except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
        raise e
    except Exception as e:
        raise e
    return conns

def get_system_protocol_distribution():
    """
    Scans system-wide network connections to count TCP, UDP, and LISTEN sockets.
    Requires administrator privileges for a complete scan.

    BUG #8 FIX: Distinguishes between AccessDenied and other errors, and returns
    a special marker tuple when privileges are missing.
    """
    tcp_count = 0
    udp_count = 0
    listen_count = 0

    try:
        connections = psutil.net_connections(kind='inet')
        for conn in connections:
            if conn.status == "LISTEN":
                listen_count += 1
            elif conn.type == socket.SOCK_STREAM:
                tcp_count += 1
            elif conn.type == socket.SOCK_DGRAM:
                udp_count += 1
    except psutil.AccessDenied:
        # Signal caller that we couldn't read (no root)
        return [("TCP", 0), ("UDP", 0), ("LISTEN", 0), ("NO_ROOT", 1)]
    except Exception:
        return [("TCP", 0), ("UDP", 0), ("LISTEN", 0)]

    return [
        ("TCP", tcp_count),
        ("UDP", udp_count),
        ("LISTEN", listen_count)
    ]

def get_top_processes_by_resource(processes, resource="cpu", limit=3):
    """
    Sorts a process list and returns the top N processes for CPU or RAM.
    """
    if not processes:
        return []
    filtered = [p for p in processes if p["pid"] != 0 and p["name"] != "?"]
    filtered.sort(key=lambda x: x[resource], reverse=True)

    top = filtered[:limit]
    others_val = sum(p[resource] for p in filtered[limit:])

    res = [(p["name"], p[resource]) for p in top]
    if others_val > 0:
        res.append(("OTROS", round(others_val, 1)))
    return res


def get_all_connections(protocol_filter="ALL"):
    """
    Fetches all active network connections system-wide.
    Resolves the process name and PID for each connection.
    Returns a list of connection dicts.
    """
    conns = []
    pid_to_name = {}
    
    # Pre-build a PID-to-name lookup cache for fast name resolution
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            pid_to_name[proc.info['pid']] = proc.info['name'] or "?"
        except Exception:
            continue

    try:
        connections = psutil.net_connections(kind='inet')
        for conn in connections:
            is_tcp = (conn.type == socket.SOCK_STREAM)
            is_udp = (conn.type == socket.SOCK_DGRAM)

            proto = "TCP" if is_tcp else ("UDP" if is_udp else "UNKNOWN")
            raw_status = conn.status if conn.status else ""
            status = raw_status if raw_status else "-"

            if protocol_filter == "TCP" and not is_tcp:
                continue
            if protocol_filter == "UDP" and not is_udp:
                continue
            if protocol_filter == "LISTEN" and status != "LISTEN":
                continue

            laddr_ip = conn.laddr.ip if conn.laddr else "-"
            laddr_port = conn.laddr.port if conn.laddr else "-"
            raddr_ip = conn.raddr.ip if conn.raddr else "-"
            raddr_port = conn.raddr.port if conn.raddr else "-"

            pid = conn.pid if conn.pid else "-"
            name = pid_to_name.get(conn.pid, "?") if conn.pid else "-"

            conns.append({
                "pid": pid,
                "name": name,
                "proto": proto,
                "laddr_ip": laddr_ip,
                "laddr_port": laddr_port,
                "raddr_ip": raddr_ip,
                "raddr_port": raddr_port,
                "status": status,
                "fd": conn.fd if conn.fd else "-"
            })
    except psutil.AccessDenied:
        # Fallback for standard user mode: scan accessible processes individually
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                pid = proc.info['pid']
                name = proc.info['name'] or "?"
                p_conns = proc.connections(kind='inet')
                for conn in p_conns:
                    is_tcp = (conn.type == socket.SOCK_STREAM)
                    is_udp = (conn.type == socket.SOCK_DGRAM)

                    proto = "TCP" if is_tcp else ("UDP" if is_udp else "UNKNOWN")
                    raw_status = conn.status if conn.status else ""
                    status = raw_status if raw_status else "-"

                    if protocol_filter == "TCP" and not is_tcp:
                        continue
                    if protocol_filter == "UDP" and not is_udp:
                        continue
                    if protocol_filter == "LISTEN" and status != "LISTEN":
                        continue

                    laddr_ip = conn.laddr.ip if conn.laddr else "-"
                    laddr_port = conn.laddr.port if conn.laddr else "-"
                    raddr_ip = conn.raddr.ip if conn.raddr else "-"
                    raddr_port = conn.raddr.port if conn.raddr else "-"

                    conns.append({
                        "pid": pid,
                        "name": name,
                        "proto": proto,
                        "laddr_ip": laddr_ip,
                        "laddr_port": laddr_port,
                        "raddr_ip": raddr_ip,
                        "raddr_port": raddr_port,
                        "status": status,
                        "fd": conn.fd if conn.fd else "-"
                    })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    except Exception:
        pass

    return conns

