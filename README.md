# Recon47 v2.0

> **Automated Reconnaissance & Vulnerability Scanner**  
> Author: **Munia936** | Python 3.8+ | CLI-based | Modular Architecture

---

## Overview

Recon47 is a modular, automated security assessment tool that performs full-cycle reconnaissance and vulnerability scanning on web targets. It accepts domains, subdomains, URLs, or IPs, and produces both a hacker-themed **HTML report** and a professional **PDF report**.

---

## Features

| Category | Feature |
|---|---|
| **Recon** | WHOIS, DNS (A/AAAA/MX/NS/TXT/CNAME/SOA + zone transfer check) |
| **Discovery** | Subdomain brute-force (70+ wordlist, multi-threaded) |
| **Scanning** | Concurrent TCP port scanner with banner grabbing |
| **Fingerprinting** | HTTP headers, technology detection, server info |
| **Crawling** | Recursive web crawler — URLs, JS files, params, forms, interesting endpoints |
| **Vuln Scanning** | Custom checks: SQLi, XSS, CORS, open redirect, sensitive files, SSL/TLS, methods, dir listing |
| **External Tools** | Nikto + Nuclei integration (auto-detected) |
| **AI** | Claude-powered executive summary + remediation advice |
| **Reporting** | Hacker-theme HTML report + cyber-theme PDF |
| **Docker** | Full containerized support |

---

## Project Structure

```
recon47/
├── recon47/
│   ├── main.py                  # CLI entry point & orchestrator
│   ├── modules/
│   │   ├── whois_lookup.py      # WHOIS lookup
│   │   ├── dns_enum.py          # DNS enumeration + zone transfer
│   │   ├── subdomain_enum.py    # Subdomain brute-force
│   │   ├── port_scan.py         # Multi-threaded TCP port scanner
│   │   ├── header_scan.py       # HTTP headers + tech fingerprinting
│   │   ├── crawler.py           # Recursive web crawler
│   │   └── vuln_scanner.py      # Custom vuln checks + Nikto/Nuclei
│   ├── report/
│   │   ├── html_report.py       # Hacker-theme HTML report
│   │   └── pdf_report.py        # Cyber-theme PDF report
│   ├── ai/
│   │   └── summarizer.py        # AI executive summary (Claude API)
│   └── utils/
│       ├── console.py           # Terminal output utilities
│       └── helpers.py           # Rate limiter, deduplicator, URL parser
├── setup.py
├── requirements.txt
├── Dockerfile
└── docker-compose.yml
```

---

## Installation

### Option 1 — pip (recommended)
```bash
git clone https://github.com/Munia936/recon47
cd recon47
pip install -r requirements.txt
pip install -e .
```

### Option 2 — Docker
```bash
docker build -t recon47:2.0 .
docker run recon47:2.0 -t example.com --all
# Save reports to host:
docker run -v $(pwd)/reports:/reports recon47:2.0 -t example.com --all -o /reports/scan
```

### External Tools (optional but recommended)
```bash
# Nikto
sudo apt install nikto

# Nuclei
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

---

## Usage

```bash
# Run everything
recon47 -t example.com --all

# Recon only (no vuln scan)
recon47 -t example.com --recon

# Specific modules
recon47 -t target.com --whois --dns --ports --headers

# Full scan with crawler + vuln scan + custom output
recon47 -t https://target.com --all --vuln -o output/report

# Skip Nikto/Nuclei (faster)
recon47 -t target.com --all --no-nikto --no-nuclei

# With AI summary
recon47 -t target.com --all --ai --api-key sk-ant-xxxxx
# Or via env var:
export ANTHROPIC_API_KEY=sk-ant-xxxxx
recon47 -t target.com --all --ai

# Custom threading + depth
recon47 -t target.com --all --threads 50 --depth 3 --max-pages 150

# Custom port list
recon47 -t target.com --ports --ports-list 80,443,22,3306,8080
```

---

## CLI Reference

```
positional arguments:
  -t, --target       Domain, URL, subdomain, or IP address

Module Flags:
  --all              Run all modules
  --recon            Run all recon modules (whois+dns+subs+ports+headers)
  --whois            WHOIS lookup
  --dns              DNS enumeration
  --subdomains       Subdomain brute-force
  --ports            Port scanner
  --headers          HTTP headers + tech fingerprint
  --crawl            Recursive web crawler
  --vuln             Vulnerability scanner

Scanner Options:
  --ports-list       CSV port list (default: 27 common ports)
  --no-nikto         Skip Nikto
  --no-nuclei        Skip Nuclei
  --threads N        Thread count (default: 30)
  --depth N          Crawl depth (default: 2)
  --max-pages N      Max pages to crawl (default: 80)

Bonus:
  --ai               Generate AI executive summary
  --api-key KEY      Anthropic API key

Output:
  -o, --output BASE  Output filename base (no extension)
```

---

## Output

Every scan produces two files:

| File | Description |
|---|---|
| `<name>.html` | Interactive hacker-theme report with animated scan-line |
| `<name>.pdf` | Professional cyber-theme PDF, black background, color-coded severities |

---

## Vulnerability Checks

Custom checks (no external tools needed):

| Check | Severity |
|---|---|
| Missing security headers | Medium/Low |
| Insecure cookie flags | Medium |
| Exposed sensitive files (.env, .git, backup.zip, etc.) | Critical–Info |
| SSL/TLS issues | Medium |
| CORS misconfiguration | High |
| Dangerous HTTP methods | Medium |
| Directory listing | Medium |
| Reflected XSS probe | High |
| SQL injection probe | Critical |
| Open redirect | Medium |
| Risky open ports | Medium |

External tools (if installed):
- **Nikto** — web server misconfiguration scanner
- **Nuclei** — template-based vulnerability scanner (CVEs, misconfigs, exposures)

---

## Bonus Features Implemented

- [x] Recursive crawling with depth control
- [x] Multi-threading / async processing (ports, subdomains, crawler)
- [x] Smart deduplication of URLs and results
- [x] HTML report generation (hacker theme)
- [x] Docker support
- [x] AI-assisted summarization (Claude claude-sonnet-4-20250514)
- [x] Advanced attack surface discovery (JS files, params, forms, endpoints)
- [x] Stealth rate-limiting (token bucket)
- [x] Nikto + Nuclei integration
- [x] Zone transfer detection
- [x] Banner grabbing on open ports
- [x] Cookie security analysis
- [x] Technology fingerprinting

---

## Ethics & Legal

> **IMPORTANT**: Recon47 must only be used against targets you own or have **explicit written authorization** to test.  
> Unauthorized scanning is illegal in most jurisdictions.  
> The author assumes no liability for misuse.

---

## Sample Output

```
 ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗    ██╗  ██╗███████╗
 ...
 ─────────────────────────────────────────────────────────────────
  Automated Reconnaissance & Vulnerability Scanner  |  Munia936

  [*] Target  : https://example.com
  [*] Started : 2025-01-01T12:00:00

 ┌─[ WHOIS LOOKUP ]──────────────────────────────────────────┐
  │  Registrar              ICANN
  │  Creation Date          1995-08-14
  ...

 ┌─[ PORT SCANNER ]──────────────────────────────────────────┐
  [████████████████████████░░░░░░] Ports 80/100
  │  Port 80               OPEN  [HTTP]
  │  Port 443              OPEN  [HTTPS]
  ...

 ┌─[ VULNERABILITY SCANNER ]─────────────────────────────────┐
  [VULN] [MEDIUM] Missing Content-Security-Policy
  [VULN] [HIGH]   Exposed: /.env  HTTP 200
  ...

  [✔] HTML Report : recon47_example_com_1234567890.html
  [✔] PDF Report  : recon47_example_com_1234567890.pdf
  [✔] Recon47 finished. Stay legal, hack ethically.
```

---

*Built with Python 3.8+ · dnspython · python-whois · reportlab · Nikto · Nuclei · Claude AI*
