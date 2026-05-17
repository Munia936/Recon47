"""
Recon47 — Vulnerability Scanner
Author: Munia936
Custom checks + Nikto & Nuclei integration
"""
import subprocess
import urllib.request
import urllib.error
import ssl
import re
import os
import json
import tempfile
from ..utils.console import vuln, warn, ok, info, err, kv

CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE

SEVERITY = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

def _req(url, method="GET", timeout=6, follow=True):
    """HTTP request helper."""
    try:
        req = urllib.request.Request(url, method=method, headers={
            "User-Agent": "Mozilla/5.0 (Recon47/2.0)"
        })
        with urllib.request.urlopen(req, timeout=timeout, context=CTX) as r:
            return r.status, dict(r.headers), r.read(65536).decode(errors="ignore")
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), ""
    except Exception:
        return None, {}, ""

class VulnScanner:
    def __init__(self, target_info, crawl_data=None):
        self.t          = target_info
        self.base       = target_info["base"]
        self.domain     = target_info["domain"]
        self.crawl      = crawl_data or {}
        self.findings   = []

    def _add(self, title, sev, desc, evidence="", url=""):
        finding = {
            "title":    title,
            "severity": sev,
            "desc":     desc,
            "evidence": evidence[:200],
            "url":      url or self.base,
        }
        self.findings.append(finding)
        vuln(f"[{sev.upper()}] {title}")
        if evidence:
            kv("  Evidence", evidence[:80])

    # ── Custom Checks ────────────────────────────────────────────

    def check_headers(self, header_data):
        """Missing security headers."""
        for h in header_data.get("missing_security", []):
            sev = "medium" if h in ("Strict-Transport-Security","Content-Security-Policy") else "low"
            self._add(f"Missing {h}", sev,
                      f"The {h} header is absent, leaving users exposed.",
                      evidence=f"Header not present in response")

        for c in header_data.get("cookies", []):
            if c["flags"]:
                self._add("Insecure Cookie Flags", "medium",
                          "Cookie lacks security flags.",
                          evidence=", ".join(c["flags"]))

    def check_open_ports(self, port_data):
        """Risky open ports."""
        for entry in port_data.get("risky", []):
            self._add(f"Risky Port {entry['port']} Open", "medium",
                      entry["reason"], evidence=str(entry))

    def check_sensitive_files(self):
        """Check for exposed sensitive paths."""
        paths = [
            ("/.env",             "high",   "Environment file exposed"),
            ("/.git/HEAD",        "high",   "Git repository exposed"),
            ("/wp-config.php.bak","high",   "WordPress config backup"),
            ("/phpinfo.php",      "medium", "PHP info page exposed"),
            ("/server-status",    "medium", "Apache server-status exposed"),
            ("/admin/",           "medium", "Admin panel accessible"),
            ("/backup.zip",       "high",   "Backup archive exposed"),
            ("/robots.txt",       "info",   "robots.txt (check disallow entries)"),
            ("/sitemap.xml",      "info",   "Sitemap found"),
            ("/.htaccess",        "medium", "htaccess file exposed"),
            ("/config.json",      "high",   "Config JSON exposed"),
            ("/api/v1/",          "info",   "API endpoint discovered"),
            ("/graphql",          "info",   "GraphQL endpoint found"),
            ("/.DS_Store",        "low",    "Mac DS_Store file exposed"),
            ("/crossdomain.xml",  "low",    "Crossdomain policy found"),
            ("/web.config",       "high",   "IIS web.config exposed"),
        ]
        info("Checking sensitive paths...")
        for path, sev, desc in paths:
            url = self.base.rstrip("/") + path
            code, hdrs, body = _req(url)
            if code and code not in (404, 400, 403):
                self._add(f"Exposed: {path}", sev, desc,
                          evidence=f"HTTP {code}", url=url)

    def check_xss(self):
        """Basic reflected XSS probe on crawled params."""
        payload  = "<script>alert(1)</script>"
        forms    = self.crawl.get("forms", [])[:5]
        for form in forms:
            for param in form.get("params", [])[:3]:
                url = f"{form['url']}?{param}={payload}"
                code, _, body = _req(url)
                if payload in body:
                    self._add("Reflected XSS", "high",
                              "User input reflected without encoding.",
                              evidence=f"Param: {param}", url=url)

    def check_sqli(self):
        """Basic SQLi error probe."""
        payload  = "'"
        errors   = ["sql syntax", "mysql_fetch", "unclosed quotation",
                    "ORA-", "pg_query", "sqlite_", "syntax error"]
        forms    = self.crawl.get("forms", [])[:5]
        for form in forms:
            for param in form.get("params", [])[:3]:
                url = f"{form['url']}?{param}={payload}"
                code, _, body = _req(url)
                body_l = body.lower()
                for e in errors:
                    if e.lower() in body_l:
                        self._add("Possible SQL Injection", "critical",
                                  "SQL error triggered by quote injection.",
                                  evidence=f"Error: {e} | Param: {param}", url=url)
                        break

    def check_open_redirect(self):
        """Open redirect probe."""
        payload = "https://evil.com"
        params  = ["redirect", "url", "next", "return", "goto", "redir", "dest"]
        for param in params:
            url = f"{self.base}?{param}={payload}"
            try:
                req = urllib.request.Request(url, headers={"User-Agent":"Recon47/2.0"})
                resp = urllib.request.urlopen(req, timeout=4, context=CTX)
                if "evil.com" in resp.url:
                    self._add("Open Redirect", "medium",
                              "Application redirects to attacker-supplied URL.",
                              evidence=f"Param: {param}", url=url)
            except Exception:
                pass

    def check_cors(self):
        """Misconfigured CORS check."""
        try:
            req = urllib.request.Request(self.base, headers={
                "Origin": "https://evil.com",
                "User-Agent": "Recon47/2.0"
            })
            with urllib.request.urlopen(req, timeout=5, context=CTX) as r:
                acao = r.headers.get("Access-Control-Allow-Origin", "")
                acac = r.headers.get("Access-Control-Allow-Credentials", "")
                if acao == "*" and "true" in acac.lower():
                    self._add("CORS Misconfiguration", "high",
                              "Wildcard ACAO + Allow-Credentials = credential theft risk.",
                              evidence=f"ACAO: {acao} | ACAC: {acac}")
                elif "evil.com" in acao:
                    self._add("CORS Origin Reflection", "high",
                              "Origin reflected — arbitrary cross-origin requests possible.",
                              evidence=f"Reflected: {acao}")
        except Exception:
            pass

    def check_http_methods(self):
        """Check for dangerous HTTP methods."""
        dangerous = ["TRACE", "PUT", "DELETE", "CONNECT"]
        for method in dangerous:
            code, _, _ = _req(self.base, method=method)
            if code and code not in (405, 501, 404, None):
                self._add(f"HTTP Method {method} Allowed", "medium",
                          f"{method} method accepted by server.",
                          evidence=f"HTTP {code}")

    def check_directory_listing(self):
        """Check for directory listing."""
        paths = ["/images/", "/uploads/", "/files/", "/static/", "/assets/"]
        for path in paths:
            url = self.base + path
            code, _, body = _req(url)
            if code == 200 and ("index of" in body.lower() or "parent directory" in body.lower()):
                self._add("Directory Listing Enabled", "medium",
                          "Server exposes directory contents.",
                          evidence=f"Path: {path}", url=url)

    def check_ssl(self):
        """Basic SSL/TLS checks."""
        import ssl as ssl_mod
        if "https" not in self.base:
            self._add("No HTTPS", "high",
                      "Site does not use HTTPS — traffic is unencrypted.")
            return
        try:
            ctx = ssl_mod.create_default_context()
            conn = ctx.wrap_socket(
                __import__("socket").create_connection((self.domain, 443), timeout=5),
                server_hostname=self.domain
            )
            cert = conn.getpeercert()
            conn.close()
            ver = conn.version()
            if ver in ("TLSv1", "TLSv1.1"):
                self._add("Weak TLS Version", "medium",
                          f"{ver} is deprecated and insecure.",
                          evidence=ver)
        except ssl_mod.SSLCertVerificationError as e:
            self._add("SSL Certificate Error", "medium",
                      "Certificate validation failed.",
                      evidence=str(e)[:100])
        except Exception:
            pass

    # ── External Tool Integration ────────────────────────────────

    def run_nikto(self):
        """Run Nikto if available."""
        if not _tool_available("nikto"):
            warn("Nikto not found — install with: apt install nikto")
            return []
        info("Running Nikto (may take a few minutes)...")
        try:
            out = subprocess.check_output(
                ["nikto", "-h", self.base, "-Format", "csv", "-nointeractive"],
                stderr=subprocess.DEVNULL, timeout=120
            ).decode(errors="ignore")
            findings = _parse_nikto(out, self.base)
            for f in findings:
                self._add(f["title"], f["severity"], f["desc"],
                          evidence=f.get("evidence",""), url=f.get("url",""))
            ok(f"Nikto: {len(findings)} finding(s)")
            return findings
        except subprocess.TimeoutExpired:
            warn("Nikto timed out")
        except Exception as e:
            err(f"Nikto error: {e}")
        return []

    def run_nuclei(self):
        """Run Nuclei if available."""
        if not _tool_available("nuclei"):
            warn("Nuclei not found — install: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")
            return []
        info("Running Nuclei (may take a few minutes)...")
        tmpfile = tempfile.mktemp(suffix=".json")
        try:
            subprocess.run(
                ["nuclei", "-u", self.base, "-json-export", tmpfile,
                 "-severity", "critical,high,medium,low",
                 "-no-color", "-silent"],
                timeout=180, capture_output=True
            )
            findings = _parse_nuclei(tmpfile)
            for f in findings:
                self._add(f["title"], f["severity"], f["desc"],
                          evidence=f.get("evidence",""), url=f.get("url",""))
            ok(f"Nuclei: {len(findings)} finding(s)")
            return findings
        except subprocess.TimeoutExpired:
            warn("Nuclei timed out")
        except Exception as e:
            err(f"Nuclei error: {e}")
        finally:
            if os.path.exists(tmpfile):
                os.remove(tmpfile)
        return []

    # ── Run All ──────────────────────────────────────────────────

    def run_all(self, header_data=None, port_data=None, use_nikto=True, use_nuclei=True):
        checks = [
            ("Sensitive Files",      self.check_sensitive_files),
            ("SSL/TLS",              self.check_ssl),
            ("CORS",                 self.check_cors),
            ("HTTP Methods",         self.check_http_methods),
            ("Directory Listing",    self.check_directory_listing),
            ("XSS Probes",           self.check_xss),
            ("SQLi Probes",          self.check_sqli),
            ("Open Redirect",        self.check_open_redirect),
        ]
        if header_data:
            self.check_headers(header_data)
        if port_data:
            self.check_open_ports(port_data)
        for name, fn in checks:
            try:
                info(f"→ {name}")
                fn()
            except Exception as e:
                err(f"{name} error: {e}")

        if use_nikto:   self.run_nikto()
        if use_nuclei:  self.run_nuclei()

        # Sort by severity
        self.findings.sort(key=lambda x: SEVERITY.get(x["severity"].lower(), 9))
        ok(f"Vulnerability scan complete: {len(self.findings)} finding(s)")
        return self.findings


# ── Parsers ──────────────────────────────────────────────────────

def _tool_available(name):
    try:
        subprocess.run([name, "--version"], capture_output=True, timeout=3)
        return True
    except Exception:
        return False

def _parse_nikto(output, base):
    results = []
    for line in output.splitlines():
        parts = line.split(",")
        if len(parts) >= 6:
            desc = parts[6] if len(parts) > 6 else parts[-1]
            results.append({
                "title": "Nikto: " + desc[:60],
                "severity": "medium",
                "desc": desc.strip(),
                "evidence": line[:120],
                "url": base,
            })
    return results

def _parse_nuclei(filepath):
    results = []
    if not os.path.exists(filepath):
        return results
    try:
        with open(filepath) as f:
            for line in f:
                try:
                    d = json.loads(line)
                    results.append({
                        "title":    d.get("info",{}).get("name","Nuclei Finding"),
                        "severity": d.get("info",{}).get("severity","info"),
                        "desc":     d.get("info",{}).get("description",""),
                        "evidence": d.get("matched-at",""),
                        "url":      d.get("host",""),
                    })
                except Exception:
                    pass
    except Exception:
        pass
    return results
