"""
PDF Report Generator for CyberRecon Pro
Generates professional security reports to deliver to clients
"""

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, KeepTogether
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
import datetime
import os

# Color palette
DARK_BLUE = colors.HexColor("#0d1b3e")
ACCENT_BLUE = colors.HexColor("#1565c0")
LIGHT_BLUE = colors.HexColor("#4fc3f7")
RED = colors.HexColor("#c62828")
ORANGE = colors.HexColor("#e65100")
GREEN = colors.HexColor("#2e7d32")
LIGHT_GRAY = colors.HexColor("#f5f7fa")
MID_GRAY = colors.HexColor("#90a4ae")
WHITE = colors.white
BLACK = colors.HexColor("#1a1a1a")


def get_risk_color(level):
    mapping = {
        "LOW RISK": GREEN,
        "MEDIUM RISK": ORANGE,
        "HIGH RISK": RED,
        "CRITICAL RISK": colors.HexColor("#7b0000"),
    }
    return mapping.get(level, ORANGE)


def generate_pdf_report(data):
    domain = data.get("domain", "unknown")
    filename = f"CyberRecon_{domain}_{datetime.datetime.now().strftime('%Y%m%d_%H%M')}.pdf"

    doc = SimpleDocTemplate(
        filename,
        pagesize=A4,
        rightMargin=2*cm,
        leftMargin=2*cm,
        topMargin=2*cm,
        bottomMargin=2*cm
    )

    styles = getSampleStyleSheet()
    story = []

    # ─── HEADER ───────────────────────────────────────────────
    title_style = ParagraphStyle(
        "Title", fontSize=26, textColor=WHITE,
        alignment=TA_CENTER, fontName="Helvetica-Bold",
        spaceAfter=4
    )
    sub_style = ParagraphStyle(
        "Sub", fontSize=11, textColor=LIGHT_BLUE,
        alignment=TA_CENTER, fontName="Helvetica"
    )

    header_table = Table([[
        Paragraph("🛡️ CyberRecon Pro", title_style),
    ]], colWidths=[17*cm])
    header_table.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), DARK_BLUE),
        ("TOPPADDING", (0,0), (-1,-1), 20),
        ("BOTTOMPADDING", (0,0), (-1,-1), 20),
        ("ROUNDEDCORNERS", [8]),
    ]))
    story.append(header_table)
    story.append(Spacer(1, 0.3*cm))

    sub = Paragraph("Domain Security Reconnaissance Report", sub_style)
    story.append(Table([[sub]], colWidths=[17*cm], style=[
        ("BACKGROUND", (0,0), (-1,-1), ACCENT_BLUE),
        ("TOPPADDING", (0,0), (-1,-1), 8),
        ("BOTTOMPADDING", (0,0), (-1,-1), 8),
    ]))
    story.append(Spacer(1, 0.5*cm))

    # ─── META INFO ────────────────────────────────────────────
    meta_data = [
        ["Target Domain", data.get("domain", "N/A")],
        ["IP Address", data.get("ip_info", {}).get("ip", "N/A")],
        ["Scan Date", data.get("scan_time", "N/A")],
        ["Analyst", data.get("analyst", "N/A")],
    ]
    meta_table = Table(meta_data, colWidths=[5*cm, 12*cm])
    meta_table.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (0,-1), LIGHT_GRAY),
        ("TEXTCOLOR", (0,0), (0,-1), DARK_BLUE),
        ("FONTNAME", (0,0), (0,-1), "Helvetica-Bold"),
        ("FONTSIZE", (0,0), (-1,-1), 10),
        ("ROWBACKGROUNDS", (1,0), (1,-1), [WHITE, LIGHT_GRAY]),
        ("GRID", (0,0), (-1,-1), 0.5, MID_GRAY),
        ("TOPPADDING", (0,0), (-1,-1), 8),
        ("BOTTOMPADDING", (0,0), (-1,-1), 8),
        ("LEFTPADDING", (0,0), (-1,-1), 10),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 0.6*cm))

    # ─── RISK SCORE ───────────────────────────────────────────
    score = data.get("risk_score", 0)
    level = data.get("risk_level", "UNKNOWN")
    risk_color = get_risk_color(level)

    score_style = ParagraphStyle("Score", fontSize=48, textColor=WHITE,
                                  fontName="Helvetica-Bold", alignment=TA_CENTER)
    level_style = ParagraphStyle("Level", fontSize=14, textColor=WHITE,
                                  fontName="Helvetica-Bold", alignment=TA_CENTER)
    note_style = ParagraphStyle("Note", fontSize=9, textColor=LIGHT_GRAY,
                                 fontName="Helvetica", alignment=TA_CENTER)

    score_block = Table([[
        Paragraph(f"{score}/100", score_style),
        Paragraph(f"{level}", level_style),
    ]], colWidths=[8.5*cm, 8.5*cm])
    score_block.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (0,0), ACCENT_BLUE),
        ("BACKGROUND", (1,0), (1,0), risk_color),
        ("TOPPADDING", (0,0), (-1,-1), 20),
        ("BOTTOMPADDING", (0,0), (-1,-1), 20),
        ("ROUNDEDCORNERS", [8]),
    ]))
    story.append(score_block)
    story.append(Spacer(1, 0.6*cm))

    # ─── SECTION HELPER ───────────────────────────────────────
    def section_title(text):
        s = ParagraphStyle("SH", fontSize=12, textColor=WHITE, fontName="Helvetica-Bold",
                            leftIndent=8)
        t = Table([[Paragraph(text, s)]], colWidths=[17*cm])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,-1), ACCENT_BLUE),
            ("TOPPADDING", (0,0), (-1,-1), 8),
            ("BOTTOMPADDING", (0,0), (-1,-1), 8),
        ]))
        return t

    def info_row(label, value, value_color=None):
        ls = ParagraphStyle("L", fontSize=9, fontName="Helvetica-Bold", textColor=DARK_BLUE)
        vs = ParagraphStyle("V", fontSize=9, fontName="Helvetica",
                             textColor=value_color or BLACK)
        return [Paragraph(label, ls), Paragraph(str(value), vs)]

    body_style = ParagraphStyle("Body", fontSize=9, fontName="Helvetica",
                                 textColor=BLACK, leading=14)

    # ─── SSL ──────────────────────────────────────────────────
    ssl = data.get("ssl", {})
    story.append(section_title("🔒 SSL Certificate"))
    story.append(Spacer(1, 0.2*cm))

    ssl_valid = ssl.get("valid", False)
    ssl_rows = [
        info_row("Status", "✅ Valid" if ssl_valid else "❌ Invalid / Not Found",
                 GREEN if ssl_valid else RED),
        info_row("Issuer", ssl.get("issuer", "N/A")),
        info_row("Expiry Date", ssl.get("expires", "N/A")),
        info_row("Days Remaining", ssl.get("days_remaining", "N/A"),
                 RED if (ssl.get("days_remaining") or 999) < 30 else GREEN),
    ]
    if not ssl_valid:
        ssl_rows.append(info_row("Error", ssl.get("error", "Unknown error"), RED))

    ssl_table = Table(ssl_rows, colWidths=[5*cm, 12*cm])
    ssl_table.setStyle(TableStyle([
        ("GRID", (0,0), (-1,-1), 0.3, MID_GRAY),
        ("ROWBACKGROUNDS", (0,0), (-1,-1), [LIGHT_GRAY, WHITE]),
        ("TOPPADDING", (0,0), (-1,-1), 7),
        ("BOTTOMPADDING", (0,0), (-1,-1), 7),
        ("LEFTPADDING", (0,0), (-1,-1), 10),
    ]))
    story.append(ssl_table)
    story.append(Spacer(1, 0.5*cm))

    # ─── PORT SCAN ────────────────────────────────────────────
    story.append(section_title("🔌 Port Scan Results"))
    story.append(Spacer(1, 0.2*cm))

    ports = data.get("ports", {})
    port_risks = data.get("port_risks", [])

    if ports:
        port_header = [
            Paragraph("Port", ParagraphStyle("PH", fontSize=9, fontName="Helvetica-Bold", textColor=WHITE)),
            Paragraph("Service", ParagraphStyle("PH", fontSize=9, fontName="Helvetica-Bold", textColor=WHITE)),
            Paragraph("Status", ParagraphStyle("PH", fontSize=9, fontName="Helvetica-Bold", textColor=WHITE)),
            Paragraph("Risk", ParagraphStyle("PH", fontSize=9, fontName="Helvetica-Bold", textColor=WHITE)),
        ]
        port_rows = [port_header]

        risky_ports = [21, 23, 3306, 3389]
        for port, info in sorted(ports.items()):
            is_open = info.get("open", False)
            is_risky = is_open and port in risky_ports
            status_color = RED if is_risky else (GREEN if is_open else MID_GRAY)
            status_text = "🔴 OPEN" if is_open else "🟢 CLOSED"
            risk_text = "⚠️ HIGH RISK" if is_risky else ("Normal" if is_open else "Safe")

            s = ParagraphStyle("PC", fontSize=8, fontName="Helvetica")
            port_rows.append([
                Paragraph(str(port), s),
                Paragraph(info.get("service", ""), s),
                Paragraph(status_text, ParagraphStyle("PS", fontSize=8, fontName="Helvetica-Bold",
                                                        textColor=status_color)),
                Paragraph(risk_text, ParagraphStyle("PR", fontSize=8, fontName="Helvetica",
                                                     textColor=RED if is_risky else BLACK)),
            ])

        port_table = Table(port_rows, colWidths=[2.5*cm, 4*cm, 4*cm, 6.5*cm])
        port_table.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,0), DARK_BLUE),
            ("GRID", (0,0), (-1,-1), 0.3, MID_GRAY),
            ("ROWBACKGROUNDS", (0,1), (-1,-1), [LIGHT_GRAY, WHITE]),
            ("TOPPADDING", (0,0), (-1,-1), 6),
            ("BOTTOMPADDING", (0,0), (-1,-1), 6),
            ("LEFTPADDING", (0,0), (-1,-1), 8),
        ]))
        story.append(port_table)
    else:
        story.append(Paragraph("Port scan data not available.", body_style))

    story.append(Spacer(1, 0.5*cm))

    # ─── HTTP HEADERS ─────────────────────────────────────────
    story.append(section_title("🌐 Security Headers"))
    story.append(Spacer(1, 0.2*cm))

    headers = data.get("headers", {})
    found = headers.get("found", {})
    missing = headers.get("missing", [])
    header_score = headers.get("score", 0)
    header_max = headers.get("max_score", 6)

    hdr_summary_style = ParagraphStyle("HS", fontSize=10, fontName="Helvetica-Bold",
                                        textColor=GREEN if header_score >= 4 else RED)
    story.append(Paragraph(
        f"Security Header Score: {header_score}/{header_max}",
        hdr_summary_style
    ))
    story.append(Spacer(1, 0.2*cm))

    if found:
        story.append(Paragraph("✅ Present Headers:", ParagraphStyle("FH", fontSize=9,
                                fontName="Helvetica-Bold", textColor=GREEN)))
        for name, val in found.items():
            story.append(Paragraph(f"  • {name}: {val[:60]}...", body_style))

    if missing:
        story.append(Spacer(1, 0.2*cm))
        story.append(Paragraph("❌ Missing Headers (Vulnerabilities):", ParagraphStyle("MH", fontSize=9,
                                fontName="Helvetica-Bold", textColor=RED)))
        for m in missing:
            story.append(Paragraph(f"  • {m}", body_style))

    story.append(Spacer(1, 0.5*cm))

    # ─── RECOMMENDATIONS ──────────────────────────────────────
    story.append(section_title("💡 Security Recommendations"))
    story.append(Spacer(1, 0.2*cm))

    recs = []
    if not ssl.get("valid"):
        recs.append("🔴 CRITICAL: Install a valid SSL certificate immediately (use Let's Encrypt — free).")
    elif ssl.get("warning"):
        recs.append("🟡 WARNING: SSL certificate expires in less than 30 days. Renew immediately.")
    else:
        recs.append("✅ SSL certificate is valid. Continue monitoring for renewal.")

    for risk in data.get("port_risks", []):
        recs.append(f"🔴 HIGH RISK: {risk}. Close this port or restrict access via firewall immediately.")

    for m in missing[:4]:
        recs.append(f"🟡 MEDIUM: Add HTTP security header '{m}' to your web server configuration.")

    if not recs:
        recs.append("✅ No critical issues detected. Continue regular security monitoring.")

    for rec in recs:
        story.append(Paragraph(f"  {rec}", body_style))
        story.append(Spacer(1, 0.15*cm))

    story.append(Spacer(1, 0.5*cm))

    # ─── FOOTER ───────────────────────────────────────────────
    story.append(HRFlowable(width="100%", thickness=1, color=ACCENT_BLUE))
    story.append(Spacer(1, 0.2*cm))

    footer_style = ParagraphStyle("Footer", fontSize=8, textColor=MID_GRAY,
                                   alignment=TA_CENTER, fontName="Helvetica-Oblique")
    story.append(Paragraph(
        f"Generated by CyberRecon Pro · Analyst: Olojede Emmanuel Kolade · "
        f"Date: {data.get('scan_time', '')} · Confidential Security Report",
        footer_style
    ))

    doc.build(story)
    return filename
