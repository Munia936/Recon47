"""
Recon47 — Shared Utilities
Author: Munia936
"""
import re
import time
import threading
import socket
from urllib.parse import urlparse

class RateLimiter:
    """Token-bucket rate limiter for stealth scanning."""
    def __init__(self, rate=10):
        self._rate = rate
        self._lock = threading.Lock()
        self._last = time.time()
        self._tokens = rate

    def acquire(self):
        with self._lock:
            now = time.time()
            elapsed = now - self._last
            self._tokens = min(self._rate, self._tokens + elapsed * self._rate)
            self._last = now
            if self._tokens >= 1:
                self._tokens -= 1
                return
            time.sleep((1 - self._tokens) / self._rate)

class Deduplicator:
    """Thread-safe result deduplicator."""
    def __init__(self):
        self._seen = set()
        self._lock = threading.Lock()

    def is_new(self, item):
        with self._lock:
            if item in self._seen:
                return False
            self._seen.add(item)
            return True

    def add(self, item):
        with self._lock:
            self._seen.add(item)

def parse_target(target):
    """Parse target into domain, scheme, base_url components."""
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    parsed = urlparse(target)
    return {
        "raw":    target,
        "scheme": parsed.scheme,
        "domain": parsed.netloc.split(":")[0],
        "port":   parsed.port,
        "path":   parsed.path or "/",
        "base":   f"{parsed.scheme}://{parsed.netloc}",
    }

def resolve_ip(domain):
    """Resolve domain to IP, return None on failure."""
    try:
        return socket.gethostbyname(domain)
    except Exception:
        return None

def severity_color(sev):
    """Return ANSI color for severity level."""
    from .console import R, Y, C, G, RS
    return {
        "critical": f"\033[91m{sev}\033[0m",
        "high":     f"\033[91m{sev}\033[0m",
        "medium":   f"\033[93m{sev}\033[0m",
        "low":      f"\033[96m{sev}\033[0m",
        "info":     f"\033[97m{sev}\033[0m",
    }.get(sev.lower(), sev)

def clean_url(url):
    """Normalize URL — lowercase scheme+host, strip fragments."""
    try:
        p = urlparse(url)
        return p._replace(fragment="", scheme=p.scheme.lower()).geturl()
    except Exception:
        return url
