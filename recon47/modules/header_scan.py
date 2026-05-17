"""
Recon47 — HTTP Header Scanner & Technology Fingerprinting
Author: Munia936
"""
import urllib.request
import urllib.error
import ssl
import re
from ..utils.console import kv, warn, ok, err, found, info

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "X-XSS-Protection",
]

# Technology fingerprints: header_name -> {value_pattern -> tech_name}
TECH_HEADERS = {
    "Server": {
        r"nginx":    "Nginx", r"apache": "Apache", r"iis": "Microsoft IIS",
        r"cloudflare": "Cloudflare", r"litespeed": "LiteSpeed",
        r"openresty": "OpenResty/Nginx", r"caddy": "Caddy",
    },
    "X-Powered-By": {
        r"php": "PHP", r"asp\.net": "ASP.NET", r"express": "Node.js/Express",
        r"django": "Django", r"ruby": "Ruby on Rails",
    },
    "X-Generator":     {r".+": None},
    "X-Drupal-Cache":  {r".+": "Drupal"},
    "X-Wp-Total":      {r".+": "WordPress"},
    "X-Joomla":        {r".+": "Joomla"},
}

def header_scan(target_info):
    domain = target_info["domain"]
    data = {
        "url": None, "status": None,
        "headers": {}, "missing_security": [],
        "technologies": [], "cookies": [],
        "redirects": [], "server_info": {}
    }

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    for scheme in ["https", "http"]:
        url = f"{scheme}://{domain}"
        try:
            req = urllib.request.Request(url, headers={
                "User-Agent": "Mozilla/5.0 (Recon47/2.0; Security Scanner)"
            })
            with urllib.request.urlopen(req, timeout=8, context=ctx if scheme=="https" else None) as resp:
                hdrs = {k.lower(): v for k, v in resp.headers.items()}
                data["url"]     = url
                data["status"]  = resp.status
                data["headers"] = hdrs

                kv("URL",    url)
                kv("Status", str(resp.status))

                # Server info
                for h in ["server", "x-powered-by", "x-generator"]:
                    if h in hdrs:
                        kv(h.title(), hdrs[h])
                        data["server_info"][h] = hdrs[h]

                # Technology fingerprinting
                techs = set()
                for hdr, patterns in TECH_HEADERS.items():
                    val = hdrs.get(hdr.lower(), "")
                    if val:
                        for pattern, name in patterns.items():
                            if re.search(pattern, val, re.I):
                                techs.add(name or val[:40])
                if techs:
                    found(f"Technologies: {', '.join(techs)}")
                data["technologies"] = list(techs)

                # Security headers check
                for sh in SECURITY_HEADERS:
                    if sh.lower() in hdrs:
                        kv(f"[✔] {sh}", hdrs[sh.lower()][:60])
                    else:
                        warn(f"MISSING: {sh}")
                        data["missing_security"].append(sh)

                # Cookie analysis
                raw_cookies = resp.headers.get_all("Set-Cookie") or []
                for c in raw_cookies:
                    flags = []
                    if "httponly" not in c.lower(): flags.append("NO HttpOnly")
                    if "secure"   not in c.lower(): flags.append("NO Secure")
                    if "samesite" not in c.lower(): flags.append("NO SameSite")
                    if flags:
                        warn(f"Cookie issue: {c[:50]} — {', '.join(flags)}")
                    data["cookies"].append({"raw": c[:100], "flags": flags})

                ok("Header scan complete")
                break
        except Exception as e:
            err(f"{scheme.upper()} error: {e}")

    return data
