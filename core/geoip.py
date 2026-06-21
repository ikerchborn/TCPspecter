import ipaddress
import httpx

# Memory cache for looked up IPs
# Key: IP string, Value: dict of lat, lon, country, city, org
geoip_cache = {}

def is_private_ip(ip_str):
    """
    Checks if an IP address is private/loopback/local.
    """
    if not ip_str or ip_str in ("-", "*", "::"):
        return True
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast
    except ValueError:
        return True

async def lookup_self_geoip():
    """
    Asynchronously queries the host's own public IP geolocation.
    Returns: {country, city, org, lat, lon, ip} or None
    """
    url = "http://ip-api.com/json/"
    try:
        async with httpx.AsyncClient(timeout=4.0) as client:
            response = await client.get(url)
            if response.status_code == 200:
                data = response.json()
                if data.get("status") == "success":
                    return {
                        "ip": data.get("query", "127.0.0.1"),
                        "country": data.get("country", "Desconocido"),
                        "city": data.get("city", "Desconocido"),
                        "org": data.get("org", "Desconocido"),
                        "lat": float(data.get("lat", 0.0)),
                        "lon": float(data.get("lon", 0.0)),
                        "is_local": False
                    }
    except Exception:
        pass
    return None

async def lookup_ip_geoip(ip_str):
    """
    Asynchronously queries IP geolocation.
    Returns: {country, city, org, lat, lon, is_local} or None
    """
    if not ip_str or ip_str == "-":
        return None
        
    global geoip_cache
    if len(geoip_cache) > 2000:
        geoip_cache.clear()
        
    if ip_str in geoip_cache:
        return geoip_cache[ip_str]
        
    # Check private
    if is_private_ip(ip_str):
        res = {
            "country": "Local Network",
            "city": "Internal / Loopback",
            "org": "Localhost / Intranet",
            "lat": 0.0,
            "lon": 0.0,
            "is_local": True
        }
        geoip_cache[ip_str] = res
        return res
        
    # Public IP: fetch from ip-api.com (free, no API key, up to 45 req/min)
    url = f"http://ip-api.com/json/{ip_str}"
    try:
        async with httpx.AsyncClient(timeout=4.0) as client:
            response = await client.get(url)
            if response.status_code == 200:
                data = response.json()
                if data.get("status") == "success":
                    res = {
                        "country": data.get("country", "Desconocido"),
                        "city": data.get("city", "Desconocido"),
                        "org": data.get("org", "Desconocido"),
                        "lat": float(data.get("lat", 0.0)),
                        "lon": float(data.get("lon", 0.0)),
                        "is_local": False
                    }
                    geoip_cache[ip_str] = res
                    return res
    except Exception:
        # Fallback to ipapi.co if ip-api fails or times out
        url_fallback = f"https://ipapi.co/{ip_str}/json/"
        try:
            async with httpx.AsyncClient(timeout=4.0) as client:
                response = await client.get(url_fallback)
                if response.status_code == 200:
                    data = response.json()
                    if not data.get("error"):
                        res = {
                            "country": data.get("country_name", "Desconocido"),
                            "city": data.get("city", "Desconocido"),
                            "org": data.get("org", "Desconocido"),
                            "lat": float(data.get("latitude", 0.0)),
                            "lon": float(data.get("longitude", 0.0)),
                            "is_local": False
                        }
                        geoip_cache[ip_str] = res
                        return res
        except Exception:
            pass
            
    # If both queries fail, use deterministic pseudo-random location
    import hashlib
    h = int(hashlib.md5(ip_str.encode()).hexdigest(), 16)
    lat = (h % 14000) / 100.0 - 70.0  # -70 to +70
    lon = ((h // 14000) % 36000) / 100.0 - 180.0 # -180 to 180
    
    return {
        "country": "Offline / Estimado",
        "city": "Fallback",
        "org": "Desconocido",
        "lat": lat,
        "lon": lon,
        "is_local": False
    }
