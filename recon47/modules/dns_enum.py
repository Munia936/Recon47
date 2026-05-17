"""
Recon47 — DNS Enumeration Module
Author: Munia936
"""
import socket
from ..utils.console import kv, warn, err, ok, info

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "PTR", "SRV"]

def dns_enum(target_info):
    domain = target_info["domain"]
    data = {"domain": domain, "records": {}, "ip": None}

    # Resolve IP
    ip = _resolve(domain)
    if ip:
        data["ip"] = ip
        kv("Resolved IP", ip)

    try:
        import dns.resolver
        for rtype in RECORD_TYPES:
            try:
                answers = dns.resolver.resolve(domain, rtype, lifetime=4)
                vals = [str(r) for r in answers]
                data["records"][rtype] = vals
                kv(rtype, ", ".join(vals[:4])[:80])
            except Exception:
                pass
        ok("DNS enumeration complete")
    except ImportError:
        warn("dnspython not installed — socket A-record only")
        if ip:
            data["records"]["A"] = [ip]
    except Exception as e:
        err(f"DNS error: {e}")

    # Zone transfer attempt (informational)
    ns_list = data["records"].get("NS", [])
    if ns_list:
        _axfr(domain, ns_list[0].rstrip("."), data)

    return data

def _resolve(domain):
    try:
        return socket.gethostbyname(domain)
    except Exception:
        return None

def _axfr(domain, ns, data):
    """Attempt DNS zone transfer — flag if misconfigured."""
    try:
        import dns.zone, dns.query
        zone = dns.zone.from_xfr(dns.query.xfr(ns, domain, timeout=3))
        names = [str(n) for n in zone.nodes.keys()]
        if names:
            warn(f"ZONE TRANSFER allowed on {ns}! ({len(names)} records)")
            data["zone_transfer"] = {"ns": ns, "records": names[:20]}
    except Exception:
        pass
