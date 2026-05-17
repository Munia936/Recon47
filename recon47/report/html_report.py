"""
Recon47 — HTML Report Generator (Hacker Cyber Theme)
Author: Munia936
"""
from datetime import datetime

SEV_COLOR = {
    "critical": "#ff1744", "high": "#ff5252",
    "medium": "#ffcc00",   "low": "#00d4ff", "info": "#aaaaaa"
}

def generate_html_report(results, filepath):
    target    = results.get("target", "unknown")
    ts        = results.get("timestamp", datetime.now().isoformat())
    modules   = results.get("modules_run", [])
    whois_d   = results.get("whois", {})
    dns_d     = results.get("dns", {})
    subs_d    = results.get("subdomains", {}).get("found", {})
    ports_d   = results.get("ports", {})
    headers_d = results.get("headers", {})
    crawl_d   = results.get("crawl", {})
    vulns     = results.get("vulnerabilities", [])
    ai_sum    = results.get("ai_summary")

    # Stats
    sev_counts = {"critical":0,"high":0,"medium":0,"low":0,"info":0}
    for v in vulns:
        s = v.get("severity","info").lower()
        if s in sev_counts: sev_counts[s] += 1

    open_ports  = ports_d.get("open_ports", {})
    techs       = headers_d.get("technologies", [])

    # Build sections
    body = ""

    # AI Summary
    if ai_sum:
        body += f"""
<div class="card ai-card">
  <div class="card-hdr ai-hdr">◈  AI EXECUTIVE SUMMARY</div>
  <div class="card-body ai-body"><pre>{_esc(ai_sum)}</pre></div>
</div>"""

    # Severity summary bar
    body += f"""
<div class="card">
  <div class="card-hdr">◈  VULNERABILITY SUMMARY</div>
  <div class="card-body">
    <div class="sev-bar">
      {"".join(f'<div class="sev-badge" style="background:{SEV_COLOR[s]};color:#000"><span>{c}</span><em>{s.upper()}</em></div>' for s,c in sev_counts.items())}
    </div>
  </div>
</div>"""

    # Target overview
    body += _card("◈  TARGET OVERVIEW", _table([
        ("Target",       target),
        ("IP Address",   ports_d.get("ip", dns_d.get("ip","N/A"))),
        ("Scan Time",    ts),
        ("Technologies", ", ".join(techs) if techs else "Unknown"),
        ("HTTP Status",  str(headers_d.get("status","N/A"))),
        ("Modules Run",  ", ".join(modules)),
    ]))

    # WHOIS
    if whois_d.get("fields"):
        rows = [(k,str(v)) for k,v in whois_d["fields"].items()]
        body += _card("◈  WHOIS", _table(rows))

    # DNS
    if dns_d.get("records"):
        rows = [(k, ", ".join(v) if isinstance(v,list) else str(v))
                for k,v in dns_d["records"].items()]
        if dns_d.get("zone_transfer"):
            rows.append(("⚠ Zone Transfer", "ALLOWED on " + dns_d["zone_transfer"]["ns"]))
        body += _card("◈  DNS RECORDS", _table(rows))

    # Subdomains
    if subs_d:
        rows = [(k, v) for k,v in subs_d.items()]
        body += _card(f"◈  SUBDOMAINS ({len(subs_d)} found)", _table(rows))

    # Open Ports
    if open_ports:
        rows = [(f"Port {p}", f"{d['service']}  {d.get('banner','')[:40]}")
                for p,d in open_ports.items()]
        body += _card(f"◈  OPEN PORTS ({len(open_ports)} open)", _table(rows))

    # HTTP Headers
    body += _card("◈  HTTP SECURITY HEADERS", _table([
        ("Server",           headers_d.get("server_info",{}).get("server","N/A")),
        ("Technologies",     ", ".join(techs) or "N/A"),
        ("Missing Headers",  ", ".join(headers_d.get("missing_security",[])) or "None ✔"),
        ("Cookie Issues",    str(len([c for c in headers_d.get("cookies",[]) if c.get("flags")]))),
    ]))

    # Crawl results
    if crawl_d:
        urls_sample  = crawl_d.get("urls",[])[:15]
        js_files     = crawl_d.get("js_files",[])[:10]
        params       = crawl_d.get("parameters",[])[:20]
        interesting  = crawl_d.get("interesting",[])

        crawl_html = f"""
<div class="crawl-grid">
  <div>
    <div class="sub-hdr">URLs ({len(crawl_d.get('urls',[]))} total)</div>
    {"".join(f'<div class="endpoint">{_esc(u)}</div>' for u in urls_sample)}
    {"<div class='dim'>...and more</div>" if len(crawl_d.get('urls',[])) > 15 else ""}
  </div>
  <div>
    <div class="sub-hdr">JavaScript Files ({len(js_files)})</div>
    {"".join(f'<div class="endpoint js">{_esc(j)}</div>' for j in js_files)}
  </div>
  <div>
    <div class="sub-hdr">Parameters ({len(params)})</div>
    {"".join(f'<span class="param-badge">{_esc(p)}</span>' for p in params)}
  </div>
  <div>
    <div class="sub-hdr">Interesting Endpoints ({len(interesting)})</div>
    {"".join(f'<div class="endpoint int">{_esc(u)}</div>' for u in interesting)}
  </div>
</div>"""
        body += _card("◈  CRAWL RESULTS", crawl_html)

    # Vulnerabilities
    if vulns:
        vuln_html = ""
        for v in vulns:
            s   = v.get("severity","info").lower()
            col = SEV_COLOR.get(s, "#aaa")
            vuln_html += f"""
<div class="vuln-item" style="border-left:3px solid {col}">
  <div class="vuln-title">
    <span class="sev-tag" style="background:{col};color:#000">{s.upper()}</span>
    {_esc(v.get('title',''))}
  </div>
  <div class="vuln-desc">{_esc(v.get('desc',''))}</div>
  {f'<div class="vuln-ev">Evidence: {_esc(v.get("evidence",""))}</div>' if v.get("evidence") else ""}
  {f'<div class="vuln-ev">URL: {_esc(v.get("url",""))}</div>' if v.get("url") else ""}
</div>"""
        body += _card(f"◈  VULNERABILITIES ({len(vulns)} found)", vuln_html)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Recon47 Report — {_esc(target)}</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@300;400;600;700&display=swap');
:root {{
  --bg:#050a0e; --bg2:#080f18; --bg3:#0a1520; --bg4:#0d1f2d;
  --green:#00ff9d; --cyan:#00d4ff; --red:#ff1744; --yellow:#ffcc00;
  --magenta:#ff00ff; --dim:#3a5a6a; --text:#9abccc; --border:#0f2535;
}}
*{{box-sizing:border-box;margin:0;padding:0}}
html{{scroll-behavior:smooth}}
body{{background:var(--bg);color:var(--text);font-family:'Rajdhani',sans-serif;
      font-size:15px;line-height:1.5;min-height:100vh}}
/* scanline overlay */
body::after{{content:'';position:fixed;inset:0;pointer-events:none;z-index:9998;
  background:repeating-linear-gradient(0deg,transparent,transparent 3px,
  rgba(0,255,157,.012) 3px,rgba(0,255,157,.012) 4px)}}
/* noise grain */
body::before{{content:'';position:fixed;inset:0;pointer-events:none;z-index:9997;
  opacity:.04;background-image:url("data:image/svg+xml,%3Csvg viewBox='0 0 200 200' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='.9' numOctaves='4'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)'/%3E%3C/svg%3E");
  background-size:200px}}
/* top pulse bar */
.pulse-bar{{position:fixed;top:0;left:0;right:0;height:2px;z-index:9999;
  background:linear-gradient(90deg,transparent 0%,var(--green) 50%,transparent 100%);
  animation:pulse 3s ease-in-out infinite}}
@keyframes pulse{{0%,100%{{opacity:.3}}50%{{opacity:1}}}}
header{{background:linear-gradient(180deg,#030810,var(--bg2));
  border-bottom:1px solid var(--border);padding:32px 40px 24px;position:relative;overflow:hidden}}
header::before{{content:'';position:absolute;inset:0;
  background:radial-gradient(ellipse 60% 80% at 50% -20%,rgba(0,255,157,.07),transparent)}}
.logo{{font-family:'Share Tech Mono',monospace;font-size:3rem;
  color:var(--green);letter-spacing:10px;
  text-shadow:0 0 30px rgba(0,255,157,.6),0 0 60px rgba(0,255,157,.2);
  position:relative}}
.logo span{{color:var(--cyan)}}
.tagline{{font-family:'Share Tech Mono',monospace;font-size:.7rem;
  letter-spacing:4px;color:var(--dim);margin-top:6px}}
.meta-row{{display:flex;flex-wrap:wrap;gap:12px;margin-top:20px;position:relative}}
.meta-chip{{background:var(--bg4);border:1px solid var(--border);
  border-left:3px solid var(--cyan);padding:8px 16px;border-radius:1px;
  min-width:140px}}
.meta-chip label{{display:block;font-size:.6rem;letter-spacing:3px;
  color:var(--dim);text-transform:uppercase;margin-bottom:2px}}
.meta-chip span{{font-family:'Share Tech Mono',monospace;color:var(--cyan);font-size:.85rem}}
main{{max-width:1140px;margin:0 auto;padding:28px 36px 60px}}
.card{{background:var(--bg2);border:1px solid var(--border);
  border-top:2px solid var(--cyan);margin-bottom:20px;
  border-radius:1px;overflow:hidden;
  box-shadow:0 4px 24px rgba(0,0,0,.4)}}
.card-hdr{{background:var(--bg4);padding:11px 20px;
  font-family:'Share Tech Mono',monospace;font-size:.75rem;
  letter-spacing:3px;color:var(--cyan);
  display:flex;align-items:center;gap:8px;
  border-bottom:1px solid var(--border)}}
.card-body{{padding:18px 20px}}
.ai-card{{border-top-color:var(--magenta)}}
.ai-hdr{{color:var(--magenta)!important}}
.ai-body pre{{font-family:'Share Tech Mono',monospace;font-size:.75rem;
  color:#d4aaf0;white-space:pre-wrap;line-height:1.7}}
table{{width:100%;border-collapse:collapse}}
td{{padding:7px 12px;border-bottom:1px solid var(--border);font-size:.88rem}}
td:first-child{{color:var(--dim);font-family:'Share Tech Mono',monospace;
  font-size:.7rem;letter-spacing:1px;width:200px;white-space:nowrap}}
tr:last-child td{{border-bottom:none}}
tr:hover td{{background:rgba(0,212,255,.03)}}
.sev-bar{{display:flex;flex-wrap:wrap;gap:10px;padding:4px 0}}
.sev-badge{{padding:10px 18px;border-radius:2px;min-width:80px;text-align:center;
  font-family:'Share Tech Mono',monospace}}
.sev-badge span{{display:block;font-size:1.8rem;font-weight:700;line-height:1}}
.sev-badge em{{font-style:normal;font-size:.6rem;letter-spacing:2px}}
.crawl-grid{{display:grid;grid-template-columns:1fr 1fr;gap:16px}}
.sub-hdr{{font-family:'Share Tech Mono',monospace;font-size:.65rem;
  letter-spacing:3px;color:var(--cyan);margin-bottom:8px;
  border-bottom:1px solid var(--border);padding-bottom:4px}}
.endpoint{{font-family:'Share Tech Mono',monospace;font-size:.7rem;
  color:var(--text);padding:2px 0;word-break:break-all;
  border-bottom:1px dashed var(--border)}}
.endpoint.js{{color:#ffd54f}}
.endpoint.int{{color:var(--red)}}
.param-badge{{display:inline-block;background:rgba(0,212,255,.07);
  border:1px solid rgba(0,212,255,.2);color:var(--cyan);
  font-family:'Share Tech Mono',monospace;font-size:.65rem;
  padding:2px 8px;margin:2px;border-radius:1px}}
.vuln-item{{background:var(--bg3);padding:14px;margin-bottom:10px;
  border-radius:1px}}
.vuln-title{{font-size:1rem;font-weight:600;color:#e0e0e0;margin-bottom:6px;
  display:flex;align-items:center;gap:10px}}
.sev-tag{{padding:2px 8px;border-radius:1px;font-family:'Share Tech Mono',monospace;
  font-size:.65rem;letter-spacing:1px;font-weight:700}}
.vuln-desc{{font-size:.85rem;color:var(--text);margin-bottom:4px}}
.vuln-ev{{font-family:'Share Tech Mono',monospace;font-size:.7rem;
  color:var(--dim);margin-top:4px}}
.dim{{color:var(--dim);font-size:.8rem;margin-top:4px}}
footer{{text-align:center;padding:20px;color:var(--dim);
  font-family:'Share Tech Mono',monospace;font-size:.65rem;
  letter-spacing:2px;border-top:1px solid var(--border);margin-top:20px}}
@media(max-width:700px){{
  header{{padding:20px}}.logo{{font-size:2rem}}
  main{{padding:16px}}.crawl-grid{{grid-template-columns:1fr}}
}}
</style>
</head>
<body>
<div class="pulse-bar"></div>
<header>
  <div class="logo">RECON<span>47</span></div>
  <div class="tagline">AUTOMATED RECONNAISSANCE &amp; VULNERABILITY SCANNER  |  AUTHOR: MUNIA936</div>
  <div class="meta-row">
    <div class="meta-chip"><label>Target</label><span>{_esc(target)}</span></div>
    <div class="meta-chip"><label>Scan Time</label><span>{ts[:19]}</span></div>
    <div class="meta-chip"><label>Vulnerabilities</label><span style="color:var(--red)">{len(vulns)}</span></div>
    <div class="meta-chip"><label>Subdomains</label><span>{len(subs_d)}</span></div>
    <div class="meta-chip"><label>Open Ports</label><span>{len(open_ports)}</span></div>
    <div class="meta-chip"><label>Status</label><span style="color:var(--green)">COMPLETE</span></div>
  </div>
</header>
<main>{body}</main>
<footer>
  RECON47 v2.0  &nbsp;·&nbsp;  AUTHOR: MUNIA936  &nbsp;·&nbsp;
  FOR AUTHORIZED PENETRATION TESTING ONLY  &nbsp;·&nbsp;  {ts[:10]}
</footer>
</body>
</html>"""

    with open(filepath, "w", encoding="utf-8") as f:
        f.write(html)
    return filepath


def _card(title, inner):
    return (f'<div class="card">'
            f'<div class="card-hdr">{title}</div>'
            f'<div class="card-body">{inner}</div>'
            f'</div>\n')

def _table(rows):
    trs = "".join(f"<tr><td>{_esc(str(k))}</td><td>{_esc(str(v))}</td></tr>"
                  for k, v in rows if v not in (None,"","N/A") or True)
    return f"<table>{trs}</table>"

def _esc(s):
    return str(s).replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")
