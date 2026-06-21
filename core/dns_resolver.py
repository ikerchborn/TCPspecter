import socket
import asyncio
from concurrent.futures import ThreadPoolExecutor

class DNSResolver:
    """
    Asynchronous DNS Resolver with memory caching.
    Uses a thread pool executor for reverse DNS lookups (socket.gethostbyaddr).
    """
    def __init__(self):
        self.cache = {}
        self.executor = ThreadPoolExecutor(max_workers=5)

    def _resolve_sync(self, ip):
        if not ip or ip in ("-", "*", "0.0.0.0", "::"):
            return ip
        try:
            # Returns (hostname, aliaslist, ipaddrlist)
            name, _, _ = socket.gethostbyaddr(ip)
            return name
        except Exception:
            return ip

    async def resolve(self, ip):
        if not ip or ip in ("-", "*", "0.0.0.0", "::"):
            return ip
        
        if len(self.cache) > 5000:
            self.cache.clear()

        # Check cache
        if ip in self.cache:
            return self.cache[ip]
            
        loop = asyncio.get_running_loop()
        try:
            # Resolve asynchronously using thread pool
            hostname = await loop.run_in_executor(self.executor, self._resolve_sync, ip)
            self.cache[ip] = hostname
            return hostname
        except Exception:
            self.cache[ip] = ip
            return ip
            
    def clear_cache(self):
        self.cache.clear()
        
# Global singleton instance
dns_resolver_instance = DNSResolver()
