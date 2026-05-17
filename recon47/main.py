#!/usr/bin/env python3
"""
Recon47 v2.0 — Automated Reconnaissance & Vulnerability Scanner
Author: Munia936
CLI entry point / orchestrator
"""
import argparse
import sys
import time
import os
from datetime import datetime

from .utils.console import banner, section, ok, warn, info, err
from .utils.helpers import parse_target, resolve_ip
from .modules.whois_lookup  import whois_lookup
from .modules.dns_enum       import dns_enum
from .modules.subdomain_enum import subdomain_enum
from .modules.port_scan      import port_scan
from .modules.header_scan    import header_scan
from .modules.crawler        import crawl
from .modules.vuln_scanner   import VulnScanner
from .report.html_report     import generate_html_report
from .report.pdf_report      import generate_pdf_report


def run(args):
    banner()
    start   = time.time()
    target  = args.target.strip()
    t_info  = parse_target(target)
    ts      = datetime.now().isoformat()

    info(f"Target  : {t_info['base']}")
    info(f"Domain  : {t_info['domain']}")
    info(f"Started : {ts}\n")

    results = {
        "target":      t_info["domain"],
        "timestamp":   ts,
        "modules_run": [],
    }

    # ── Recon Modules ─────────────────────────────────────────
    if args.all or args.whois:
        section("WHOIS LOOKUP")
        results["whois"]  = whois_lookup(t_info)
        results["modules_run"].append("WHOIS")

    if args.all or args.dns:
        section("DNS ENUMERATION")
        results["dns"] = dns_enum(t_info)
        results["modules_run"].append("DNS")

    if args.all or args.subdomains:
        section("SUBDOMAIN ENUMERATION")
        results["subdomains"] = subdomain_enum(t_info, threads=args.threads)
        results["modules_run"].append("Subdomains")

    if args.all or args.ports:
        section("PORT SCANNER")
        ports = [int(p) for p in args.ports_list.split(",")] if args.ports_list else None
        results["ports"] = port_scan(t_info, ports=ports, threads=args.threads)
        results["modules_run"].append("Ports")

    if args.all or args.headers:
        section("HTTP HEADERS & TECH FINGERPRINT")
        results["headers"] = header_scan(t_info)
        results["modules_run"].append("Headers")

    if args.all or args.crawl:
        section("WEB CRAWLER")
        results["crawl"] = crawl(t_info, max_depth=args.depth, max_pages=args.max_pages)
        results["modules_run"].append("Crawler")

    # ── Vulnerability Scan ────────────────────────────────────
    if args.all or args.vuln:
        section("VULNERABILITY SCANNER")
        scanner = VulnScanner(t_info, crawl_data=results.get("crawl"))
        results["vulnerabilities"] = scanner.run_all(
            header_data=results.get("headers"),
            port_data=results.get("ports"),
            use_nikto=not args.no_nikto,
            use_nuclei=not args.no_nuclei,
        )
        results["modules_run"].append("VulnScan")
    else:
        results["vulnerabilities"] = []

    # ── AI Summary ────────────────────────────────────────────
    if args.ai:
        section("AI ANALYSIS")
        from .ai.summarizer import ai_summarize
        results["ai_summary"] = ai_summarize(results, api_key=args.api_key)
        results["modules_run"].append("AI")

    # ── Reports ───────────────────────────────────────────────
    section("GENERATING REPORTS")
    base    = args.output or f"recon47_{t_info['domain'].replace('.','_')}_{int(start)}"
    html_p  = generate_html_report(results, base + ".html")
    pdf_p   = generate_pdf_report(results, base + ".pdf")
    ok(f"HTML Report : {html_p}")
    ok(f"PDF Report  : {pdf_p}")

    elapsed = round(time.time() - start, 1)
    vulns   = results.get("vulnerabilities", [])
    sev     = {s:0 for s in ["critical","high","medium","low","info"]}
    for v in vulns:
        s = v.get("severity","info").lower()
        if s in sev: sev[s]+=1

    section("SCAN COMPLETE")
    info(f"Duration     : {elapsed}s")
    info(f"Findings     : {len(vulns)} total  |  " +
         "  ".join(f"{k.upper()}:{v}" for k,v in sev.items() if v))
    ok("Recon47 finished. Stay legal, hack ethically.\n")


def main():
    p = argparse.ArgumentParser(
        description="Recon47 v2.0 — Automated Recon & Vuln Scanner by Munia936",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  recon47 -t example.com --all
  recon47 -t https://target.com --recon --vuln -o report_out
  recon47 -t 192.168.1.1 --ports --headers --vuln --no-nikto
  recon47 -t target.com --all --ai --api-key sk-ant-...
"""
    )
    p.add_argument("-t", "--target",     required=True, help="Domain, subdomain, URL, or IP")
    p.add_argument("-o", "--output",     help="Output base filename (no extension)")
    p.add_argument("--threads",          type=int, default=30, help="Thread count (default: 30)")
    p.add_argument("--depth",            type=int, default=2,  help="Crawl depth (default: 2)")
    p.add_argument("--max-pages",        type=int, default=80, help="Max crawl pages (default: 80)")

    # Module flags
    g = p.add_argument_group("Modules")
    g.add_argument("--all",       action="store_true", help="Run all modules")
    g.add_argument("--recon",     action="store_true", help="Run all recon (whois+dns+subs+ports+headers)")
    g.add_argument("--whois",     action="store_true")
    g.add_argument("--dns",       action="store_true")
    g.add_argument("--subdomains",action="store_true")
    g.add_argument("--ports",     action="store_true")
    g.add_argument("--headers",   action="store_true")
    g.add_argument("--crawl",     action="store_true")
    g.add_argument("--vuln",      action="store_true", help="Run vulnerability scan")
    g.add_argument("--ports-list",default=None, help="CSV port list e.g. 80,443,22")
    g.add_argument("--no-nikto",  action="store_true", help="Skip Nikto")
    g.add_argument("--no-nuclei", action="store_true", help="Skip Nuclei")

    # Bonus
    b = p.add_argument_group("Bonus")
    b.add_argument("--ai",        action="store_true", help="AI executive summary (needs API key)")
    b.add_argument("--api-key",   default=None, help="Anthropic API key (or set ANTHROPIC_API_KEY)")

    args = p.parse_args()

    # --recon expands to individual recon modules
    if args.recon:
        args.whois = args.dns = args.subdomains = args.ports = args.headers = True

    has_module = any([args.all, args.recon, args.whois, args.dns, args.subdomains,
                      args.ports, args.headers, args.crawl, args.vuln])
    if not has_module:
        warn("No module selected. Use --all, --recon, or specify modules. (-h for help)")
        sys.exit(1)

    try:
        run(args)
    except KeyboardInterrupt:
        err("\nInterrupted by user.")
        sys.exit(0)
    except Exception as e:
        err(f"Fatal: {e}")
        import traceback; traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
