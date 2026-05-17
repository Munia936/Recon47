"""
Recon47 — WHOIS Lookup Module
Author: Munia936
"""
import socket
from ..utils.console import kv, warn, err, ok

def whois_lookup(target_info):
    domain = target_info["domain"]
    data = {"domain": domain, "fields": {}, "error": None}
    try:
        import whois
        w = whois.whois(domain)
        fields = {
            "Registrar":     getattr(w, "registrar", None),
            "Creation Date": str(getattr(w, "creation_date", "N/A")),
            "Expiry Date":   str(getattr(w, "expiration_date", "N/A")),
            "Name Servers":  _fmt_list(getattr(w, "name_servers", [])),
            "Country":       getattr(w, "country", None),
            "Organization":  getattr(w, "org", None),
            "Registrant":    getattr(w, "name", None),
            "Emails":        _fmt_list(getattr(w, "emails", [])),
        }
        for k, v in fields.items():
            if v and v not in ("None", "[]"):
                kv(k, str(v)[:80])
                data["fields"][k] = str(v)
        ok("WHOIS lookup complete")
    except ImportError:
        warn("python-whois not installed — raw socket fallback")
        raw = _raw_whois(domain)
        data["fields"]["raw"] = raw[:800]
        kv("Raw WHOIS", raw[:120] + "...")
    except Exception as e:
        err(f"WHOIS error: {e}")
        data["error"] = str(e)
    return data

def _fmt_list(val):
    if isinstance(val, (list, set)):
        return ", ".join(str(x) for x in val)[:120]
    return str(val) if val else None

def _raw_whois(domain):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect(("whois.iana.org", 43))
        s.send((domain + "\r\n").encode())
        resp = b""
        while True:
            chunk = s.recv(4096)
            if not chunk: break
            resp += chunk
        s.close()
        return resp.decode(errors="ignore")
    except Exception as e:
        return f"Error: {e}"
