"""
Recon47 — Port Scanner Module
Author: Munia936
"""
import socket
import concurrent.futures
from ..utils.console import kv, info, ok, warn, progress

SERVICES = {
    21:"FTP", 22:"SSH", 23:"Telnet", 25:"SMTP", 53:"DNS",
    80:"HTTP", 110:"POP3", 143:"IMAP", 443:"HTTPS", 445:"SMB",
    465:"SMTPS", 587:"SMTP-TLS", 993:"IMAPS", 995:"POP3S",
    1433:"MSSQL", 3306:"MySQL", 3389:"RDP", 5432:"PostgreSQL",
    5900:"VNC", 6379:"Redis", 8080:"HTTP-Alt", 8443:"HTTPS-Alt",
    8888:"Jupyter", 9200:"Elasticsearch", 27017:"MongoDB",
    2375:"Docker", 2376:"Docker-TLS", 6443:"Kubernetes",
}

RISKY = {23:"Telnet (unencrypted)", 21:"FTP (unencrypted)",
         3389:"RDP exposed", 6379:"Redis (no auth?)", 9200:"Elasticsearch open",
         2375:"Docker daemon exposed", 27017:"MongoDB exposed"}

def port_scan(target_info, ports=None, threads=50, timeout=1.0):
    domain = target_info["domain"]
    if ports is None:
        ports = list(SERVICES.keys())

    try:
        ip = socket.gethostbyname(domain)
        info(f"Resolved {domain} → {ip}")
    except Exception:
        ip = domain
        warn("Could not resolve hostname; scanning raw target")

    data = {"ip": ip, "open_ports": {}, "risky": []}
    total = len(ports)

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(_check, ip, p, timeout): p for p in ports}
        done = 0
        for f in concurrent.futures.as_completed(futures):
            done += 1
            progress("Ports", done, total)
            port, is_open, banner_txt = f.result()
            if is_open:
                svc = SERVICES.get(port, "unknown")
                data["open_ports"][port] = {"service": svc, "banner": banner_txt}
                kv(f"Port {port}", f"OPEN  [{svc}]  {banner_txt or ''}")
                if port in RISKY:
                    warn(f"RISK: {RISKY[port]}")
                    data["risky"].append({"port": port, "reason": RISKY[port]})

    if not data["open_ports"]:
        kv("Result", "No open ports found in scanned range")
    else:
        ok(f"Found {len(data['open_ports'])} open port(s)")
    return data

def _check(host, port, timeout):
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            banner_txt = ""
            try:
                s.settimeout(0.5)
                banner_txt = s.recv(256).decode(errors="ignore").strip()[:60]
            except Exception:
                pass
            return port, True, banner_txt
    except Exception:
        return port, False, ""
