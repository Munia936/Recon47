"""
Recon47 — AI-Assisted Findings Summarizer (Bonus Feature)
Author: Munia936
Uses Claude claude-sonnet-4-20250514 to generate executive summary + remediation advice
"""
import json
import urllib.request
import urllib.error
from ..utils.console import info, ok, err, warn

ANTHROPIC_API = "https://api.anthropic.com/v1/messages"

def ai_summarize(results, api_key=None):
    """
    Generate AI-powered executive summary of scan findings.
    api_key: Anthropic API key, or set ANTHROPIC_API_KEY env var.
    """
    import os
    key = api_key or os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        warn("No ANTHROPIC_API_KEY set — skipping AI summary")
        return None

    info("Generating AI executive summary...")

    # Build concise scan digest for the prompt
    findings = results.get("vulnerabilities", [])
    sev_counts = {}
    for f in findings:
        s = f.get("severity","info").lower()
        sev_counts[s] = sev_counts.get(s, 0) + 1

    techs     = results.get("headers", {}).get("technologies", [])
    subdomains = list(results.get("subdomains", {}).get("found", {}).keys())[:10]
    open_ports = results.get("ports", {}).get("open_ports", {})
    top_vulns  = [f"{f['severity'].upper()}: {f['title']}" for f in findings[:10]]

    prompt = f"""You are a senior penetration tester. Analyze this automated recon scan and provide:
1. Executive Summary (3-4 sentences, business-level risk)
2. Top 3 Critical Remediation Actions (numbered)
3. Overall Risk Rating: Critical/High/Medium/Low

Scan Data:
- Target: {results.get('target','')}
- Technologies: {', '.join(techs) or 'Unknown'}
- Open Ports: {', '.join(str(p) for p in open_ports.keys()) or 'None found'}
- Subdomains Found: {len(subdomains)}
- Severity Counts: {json.dumps(sev_counts)}
- Top Findings: {chr(10).join(top_vulns) or 'None'}

Be concise and actionable. Format as plain text."""

    try:
        payload = json.dumps({
            "model": "claude-sonnet-4-20250514",
            "max_tokens": 600,
            "messages": [{"role": "user", "content": prompt}]
        }).encode()

        req = urllib.request.Request(ANTHROPIC_API, data=payload, method="POST", headers={
            "Content-Type":      "application/json",
            "x-api-key":         key,
            "anthropic-version": "2023-06-01",
        })
        with urllib.request.urlopen(req, timeout=30) as r:
            data = json.loads(r.read())
            summary = data["content"][0]["text"]
            ok("AI summary generated")
            return summary
    except Exception as e:
        err(f"AI summary failed: {e}")
        return None
