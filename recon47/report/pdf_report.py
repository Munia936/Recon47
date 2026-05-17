"""
Recon47 — PDF Report Generator
Author: Munia936
"""
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import mm
from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table,
                                  TableStyle, HRFlowable, KeepTogether)
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT

BG    = colors.HexColor("#050a0e")
BG2   = colors.HexColor("#0a1520")
BG3   = colors.HexColor("#0d1f2d")
GREEN = colors.HexColor("#00ff9d")
CYAN  = colors.HexColor("#00d4ff")
RED   = colors.HexColor("#ff1744")
YELL  = colors.HexColor("#ffcc00")
DIM   = colors.HexColor("#3a5a6a")
TEXT  = colors.HexColor("#9abccc")
BORD  = colors.HexColor("#0f2535")
MAG   = colors.HexColor("#cc44ff")
WHITE = colors.HexColor("#e0e8f0")

SEV_COLORS = {
    "critical": colors.HexColor("#ff1744"),
    "high":     colors.HexColor("#ff5252"),
    "medium":   colors.HexColor("#ffcc00"),
    "low":      colors.HexColor("#00d4ff"),
    "info":     colors.HexColor("#888888"),
}

def _s(name, **kw):
    defaults = dict(fontName="Courier", fontSize=8, textColor=TEXT,
                    spaceAfter=3, leading=12, leftIndent=0)
    defaults.update(kw)
    return ParagraphStyle(name, **defaults)

STYLES = {
    "logo":    _s("logo", fontName="Courier-Bold", fontSize=20, textColor=GREEN,
                   spaceAfter=2, leading=24),
    "tagline": _s("tagline", fontSize=6, textColor=DIM, spaceAfter=8, leading=8),
    "h2":      _s("h2", fontName="Courier-Bold", fontSize=9, textColor=CYAN,
                   spaceBefore=12, spaceAfter=5, leading=12),
    "body":    _s("body"),
    "dim":     _s("dim", textColor=DIM, fontSize=7),
    "warn":    _s("warn", fontName="Courier-Bold", textColor=YELL),
    "crit":    _s("crit", fontName="Courier-Bold", textColor=RED),
    "footer":  _s("footer", fontSize=6, textColor=DIM, alignment=TA_CENTER, leading=8),
    "ai":      _s("ai", fontName="Courier", fontSize=7, textColor=MAG, leading=11),
    "vtitle":  _s("vtitle", fontName="Courier-Bold", fontSize=8, textColor=WHITE, leading=11),
    "vdesc":   _s("vdesc", fontSize=7, textColor=TEXT, leading=10),
    "vev":     _s("vev", fontSize=6, textColor=DIM, leading=9),
}

def _tbl(data, col_w=None):
    if not data: return Spacer(1,2)
    cw = col_w or [55*mm, 100*mm]
    t = Table(data, colWidths=cw, repeatRows=0)
    t.setStyle(TableStyle([
        ("FONTNAME",      (0,0),(-1,-1), "Courier"),
        ("FONTSIZE",      (0,0),(-1,-1), 7),
        ("TEXTCOLOR",     (0,0),(0,-1),  DIM),
        ("TEXTCOLOR",     (1,0),(1,-1),  TEXT),
        ("ROWBACKGROUNDS",(0,0),(-1,-1), [BG, BG2]),
        ("GRID",          (0,0),(-1,-1), 0.3, BORD),
        ("TOPPADDING",    (0,0),(-1,-1), 4),
        ("BOTTOMPADDING", (0,0),(-1,-1), 4),
        ("LEFTPADDING",   (0,0),(-1,-1), 6),
        ("VALIGN",        (0,0),(-1,-1), "TOP"),
    ]))
    return t

def _bg_rect(canvas, x, y, w, h, color):
    canvas.saveState()
    canvas.setFillColor(color)
    canvas.rect(x, y, w, h, fill=1, stroke=0)
    canvas.restoreState()

def _on_page(canvas, doc):
    W, H = A4
    canvas.saveState()
    # full page dark bg
    canvas.setFillColor(BG)
    canvas.rect(0, 0, W, H, fill=1, stroke=0)
    # top green stripe
    canvas.setFillColor(GREEN)
    canvas.rect(0, H-5, W, 5, fill=1, stroke=0)
    # footer bar
    canvas.setFillColor(BG2)
    canvas.rect(0, 0, W, 16, fill=1, stroke=0)
    canvas.setFillColor(DIM)
    canvas.setFont("Courier", 5.5)
    canvas.drawString(15, 5.5, "RECON47 v2.0  |  AUTHOR: MUNIA936  |  AUTHORIZED SECURITY TESTING ONLY")
    canvas.drawRightString(W-15, 5.5, f"PAGE {doc.page}")
    canvas.restoreState()

def generate_pdf_report(results, filepath):
    target  = results.get("target","unknown")
    ts      = results.get("timestamp", datetime.now().isoformat())[:19]
    whois_d = results.get("whois",{}).get("fields",{})
    dns_d   = results.get("dns",{}).get("records",{})
    subs_d  = results.get("subdomains",{}).get("found",{})
    ports_d = results.get("ports",{})
    hdr_d   = results.get("headers",{})
    crawl_d = results.get("crawl",{})
    vulns   = results.get("vulnerabilities",[])
    ai_sum  = results.get("ai_summary")

    doc = SimpleDocTemplate(filepath, pagesize=A4,
                            leftMargin=18*mm, rightMargin=18*mm,
                            topMargin=18*mm, bottomMargin=22*mm)
    S   = STYLES
    story = []

    # Header
    story.append(Paragraph("RECON47", S["logo"]))
    story.append(Paragraph("AUTOMATED RECONNAISSANCE & VULNERABILITY SCANNER  |  AUTHOR: MUNIA936", S["tagline"]))
    story.append(HRFlowable(width="100%", thickness=1, color=CYAN))
    story.append(Spacer(1, 4*mm))

    # Meta overview
    open_ports = ports_d.get("open_ports",{})
    techs      = hdr_d.get("technologies",[])
    story.append(_tbl([
        ["TARGET",          target],
        ["IP ADDRESS",      ports_d.get("ip", dns_d.get("A",["N/A"])[0] if dns_d.get("A") else "N/A")],
        ["SCAN TIME",       ts],
        ["TECHNOLOGIES",    ", ".join(techs) or "Unknown"],
        ["OPEN PORTS",      str(len(open_ports))],
        ["SUBDOMAINS",      str(len(subs_d))],
        ["VULNERABILITIES", str(len(vulns))],
        ["STATUS",          "COMPLETE"],
    ]))
    story.append(Spacer(1,5*mm))

    # Sev summary
    sev_counts = {"critical":0,"high":0,"medium":0,"low":0,"info":0}
    for v in vulns:
        s = v.get("severity","info").lower()
        if s in sev_counts: sev_counts[s]+=1
    sev_row = [[f"{s.upper()}\n{c}" for s,c in sev_counts.items()]]
    st = Table(sev_row, colWidths=[35*mm]*5)
    st.setStyle(TableStyle([
        ("FONTNAME",   (0,0),(-1,-1),"Courier-Bold"),
        ("FONTSIZE",   (0,0),(-1,-1),8),
        ("ALIGN",      (0,0),(-1,-1),"CENTER"),
        ("VALIGN",     (0,0),(-1,-1),"MIDDLE"),
        ("TOPPADDING", (0,0),(-1,-1),6),
        ("BOTTOMPADDING",(0,0),(-1,-1),6),
        ("BACKGROUND", (0,0),(0,0), SEV_COLORS["critical"]),
        ("BACKGROUND", (1,0),(1,0), SEV_COLORS["high"]),
        ("BACKGROUND", (2,0),(2,0), SEV_COLORS["medium"]),
        ("BACKGROUND", (3,0),(3,0), SEV_COLORS["low"]),
        ("BACKGROUND", (4,0),(4,0), SEV_COLORS["info"]),
        ("TEXTCOLOR",  (0,0),(3,0), colors.black),
        ("TEXTCOLOR",  (4,0),(4,0), colors.white),
    ]))
    story.append(st)
    story.append(Spacer(1,5*mm))

    # AI Summary
    if ai_sum:
        story.append(Paragraph("▶  AI EXECUTIVE SUMMARY", S["h2"]))
        for line in ai_sum.strip().splitlines():
            story.append(Paragraph(line or " ", S["ai"]))
        story.append(Spacer(1,3*mm))

    # WHOIS
    if whois_d:
        story.append(Paragraph("▶  WHOIS", S["h2"]))
        story.append(_tbl([[k,str(v)[:80]] for k,v in whois_d.items()]))

    # DNS
    if dns_d:
        story.append(Paragraph("▶  DNS RECORDS", S["h2"]))
        rows = [[k, ", ".join(v)[:80] if isinstance(v,list) else str(v)]
                for k,v in dns_d.items()]
        story.append(_tbl(rows))

    # Subdomains
    if subs_d:
        story.append(Paragraph(f"▶  SUBDOMAINS ({len(subs_d)} found)", S["h2"]))
        story.append(_tbl([[k,v] for k,v in list(subs_d.items())[:30]]))

    # Ports
    if open_ports:
        story.append(Paragraph(f"▶  OPEN PORTS ({len(open_ports)} open)", S["h2"]))
        rows = [[f"Port {p}", f"{d['service']}  {d.get('banner','')[:40]}"]
                for p,d in open_ports.items()]
        story.append(_tbl(rows))

    # Headers
    story.append(Paragraph("▶  HTTP HEADERS & TECHNOLOGY", S["h2"]))
    story.append(_tbl([
        ["Server",          hdr_d.get("server_info",{}).get("server","N/A")],
        ["Technologies",    ", ".join(techs) or "Unknown"],
        ["Missing Headers", ", ".join(hdr_d.get("missing_security",[])) or "None"],
        ["Cookie Issues",   str(len([c for c in hdr_d.get("cookies",[]) if c.get("flags")]))],
    ]))

    # Crawl
    if crawl_d:
        story.append(Paragraph("▶  CRAWL RESULTS", S["h2"]))
        story.append(_tbl([
            ["URLs Found",         str(len(crawl_d.get("urls",[])))],
            ["JS Files",           str(len(crawl_d.get("js_files",[])))],
            ["Parameters",         str(len(crawl_d.get("parameters",[])))],
            ["Interesting Paths",  str(len(crawl_d.get("interesting",[])))],
            ["Forms Found",        str(len(crawl_d.get("forms",[])))],
        ]))
        # Top interesting
        for ep in crawl_d.get("interesting",[])[:8]:
            story.append(Paragraph(f"  ⚑  {ep[:90]}", S["warn"]))

    # Vulnerabilities
    if vulns:
        story.append(Paragraph(f"▶  VULNERABILITIES ({len(vulns)} total)", S["h2"]))
        for v in vulns:
            sev = v.get("severity","info").lower()
            col = SEV_COLORS.get(sev, DIM)
            block = [
                Paragraph(f"[{sev.upper()}]  {v.get('title','')[:80]}", S["vtitle"]),
                Paragraph(v.get("desc","")[:150], S["vdesc"]),
            ]
            if v.get("evidence"):
                block.append(Paragraph(f"Evidence: {v['evidence'][:100]}", S["vev"]))
            if v.get("url"):
                block.append(Paragraph(f"URL: {v['url'][:100]}", S["vev"]))
            block.append(Spacer(1,2*mm))
            story.append(KeepTogether(block))

    story.append(Spacer(1,6*mm))
    story.append(HRFlowable(width="100%", thickness=0.4, color=DIM))
    story.append(Spacer(1,2*mm))
    story.append(Paragraph("Generated by Recon47 v2.0  |  Author: Munia936  |  For authorized security testing only", S["footer"]))

    doc.build(story, onFirstPage=_on_page, onLaterPages=_on_page)
    return filepath
