import asyncio
import re

# Memory cache for traceroute paths
# Key: destination IP string, Value: list of hop IPs
traceroute_cache = {}

async def get_hops(ip_str):
    """
    Asynchronously runs a traceroute to the destination IP.
    Returns a list of IP addresses representing the hops.
    The list always ends with the destination IP.
    Caches the results to prevent spamming.
    """
    if not ip_str or ip_str == "-" or ip_str == "0.0.0.0" or ip_str == "127.0.0.1":
        return []

    global traceroute_cache
    if len(traceroute_cache) > 1000:
        traceroute_cache.clear()

    if ip_str in traceroute_cache:
        return traceroute_cache[ip_str]

    # Command: traceroute -n (numeric) -m 12 (max 12 hops) -w 1 (timeout 1s) -q 1 (1 probe per hop)
    cmd = f"traceroute -n -m 12 -w 1 -q 1 {ip_str}"
    
    hops = []
    try:
        proc = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        stdout, stderr = await proc.communicate()
        if stdout:
            lines = stdout.decode('utf-8', errors='ignore').split('\n')
            for line in lines[1:]: # Skip header
                line = line.strip()
                if not line:
                    continue
                
                # Parse traceroute line. Example: " 1  192.168.1.1  1.234 ms"
                # Match the first IP-like string in the line
                match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line)
                if match:
                    hop_ip = match.group(0)
                    if hop_ip not in hops:
                        hops.append(hop_ip)
                        
    except Exception:
        pass

    # Ensure destination is the last hop
    if not hops or hops[-1] != ip_str:
        hops.append(ip_str)

    traceroute_cache[ip_str] = hops
    return hops
