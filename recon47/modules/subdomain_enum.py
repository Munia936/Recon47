"""
Recon47 — Subdomain Enumeration Module
Author: Munia936
"""
import socket
import concurrent.futures
from ..utils.console import kv, info, ok, found, progress
from ..utils.helpers import Deduplicator

WORDLIST = [
    "www","mail","ftp","remote","blog","webmail","server","ns","ns1","ns2",
    "smtp","secure","vpn","m","shop","portal","api","dev","staging","test",
    "admin","dashboard","app","static","cdn","support","help","login","git",
    "gitlab","jenkins","jira","confluence","docs","wiki","status","monitor",
    "assets","media","upload","download","beta","alpha","new","old","backup",
    "mx","mx1","pop","imap","autodiscover","cpanel","whm","forum","news",
    "img","images","video","mobile","demo","sandbox","v1","v2","internal",
    "api2","stage","preprod","prod","auth","oauth","sso","account","accounts",
    "payment","pay","billing","store","search","proxy","gateway","ws","socket",
    "metrics","graphql","grpc","rpc","data","db","sql","redis","cache","node",
]

def subdomain_enum(target_info, threads=30):
    domain = target_info["domain"]
    data = {"domain": domain, "found": {}}
    dedup = Deduplicator()
    total = len(WORDLIST)

    info(f"Brute-forcing {total} subdomains with {threads} threads...")

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(_resolve, sub, domain): sub for sub in WORDLIST}
        done = 0
        for f in concurrent.futures.as_completed(futures):
            done += 1
            progress("Subdomains", done, total)
            fqdn, ip = f.result()
            if fqdn and ip and dedup.is_new(fqdn):
                found(f"{fqdn}  →  {ip}")
                data["found"][fqdn] = ip

    count = len(data["found"])
    ok(f"Discovered {count} subdomain(s)")
    return data

def _resolve(sub, domain):
    fqdn = f"{sub}.{domain}"
    try:
        ip = socket.gethostbyname(fqdn)
        return fqdn, ip
    except Exception:
        return None, None
