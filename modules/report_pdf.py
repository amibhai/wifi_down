"""
PDF Report Engine — generates professional pentest PDF reports.

Structure:
  Page 1  — Cover: wifi_down logo, engagement name, target count, date, "Confidential"
  Page 2  — Executive Summary: risk heat map + top 3 findings + overall risk rating
  Page 3+ — Technical Findings: one section per target AP
  Final   — Remediation Checklist: NIST 800-153 control references

Uses reportlab as primary engine.
Falls back to weasyprint HTML→PDF if reportlab is absent.
Falls back to noting missing PDF engine in output and skipping PDF.
"""
from __future__ import annotations

import hashlib
import json
import logging
import textwrap
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

REPORTS_DIR = Path("results")

_TEAL_HEX = "#00D4AA"


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _sha256_file(path: Path) -> str:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return "unavailable"


def _load_session(session_id: str) -> dict:
    sessions_dir = Path.home() / ".wifi-auditor" / "sessions"
    path = sessions_dir / f"{session_id}.json"
    if path.exists():
        return json.loads(path.read_text())
    for p in Path("results").glob(f"*{session_id}*.jsonl"):
        events: list[dict] = []
        for line in p.read_text().splitlines():
            try:
                events.append(json.loads(line))
            except Exception:
                pass
        return {"events": events, "session_id": session_id}
    raise FileNotFoundError(f"Session {session_id!r} not found")


def _risk_rating(findings: list[dict]) -> str:
    severities = {f.get("severity", "LOW") for f in findings}
    if "CRITICAL" in severities:
        return "Critical"
    if "HIGH" in severities:
        return "High"
    if "MEDIUM" in severities:
        return "Medium"
    return "Low"


# ─── reportlab engine ─────────────────────────────────────────────────────────

def _generate_with_reportlab(
    session_id: str,
    data: dict,
    findings: list[dict],
    out_path: Path,
) -> None:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm, mm
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table as RLTable,
        TableStyle, HRFlowable, PageBreak,
    )
    from reportlab.lib.enums import TA_CENTER, TA_LEFT

    TEAL  = colors.HexColor(_TEAL_HEX)
    DARK  = colors.HexColor("#1a1a1a")
    LIGHT = colors.HexColor("#f5f5f5")

    doc = SimpleDocTemplate(
        str(out_path),
        pagesize=A4,
        leftMargin=2*cm, rightMargin=2*cm,
        topMargin=2*cm, bottomMargin=2*cm,
    )

    styles = getSampleStyleSheet()
    h1 = ParagraphStyle("h1", parent=styles["Heading1"],
                         textColor=TEAL, fontSize=24, spaceAfter=12)
    h2 = ParagraphStyle("h2", parent=styles["Heading2"],
                         textColor=TEAL, fontSize=16, spaceAfter=8)
    h3 = ParagraphStyle("h3", parent=styles["Heading3"],
                         textColor=DARK, fontSize=12, spaceAfter=6)
    body = ParagraphStyle("body", parent=styles["Normal"],
                           fontSize=10, leading=14, spaceAfter=6)
    dim  = ParagraphStyle("dim", parent=styles["Normal"],
                           fontSize=9, textColor=colors.grey, spaceAfter=4)
    conf = ParagraphStyle("conf", parent=styles["Normal"],
                           textColor=colors.red, fontSize=12,
                           alignment=TA_CENTER, spaceAfter=6)

    bssid        = data.get("target_bssid", "Unknown")
    ssid         = data.get("target_ssid",  "Unknown")
    stage        = data.get("stage",        "unknown")
    key_found    = data.get("result")
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    risk_rating  = _risk_rating(findings)

    story: list = []

    # ── Page 1: Cover ────────────────────────────────────────────────────────
    story.append(Spacer(1, 4*cm))
    story.append(Paragraph("wifi_down", h1))
    story.append(Paragraph("WiFi Security Audit Report", h2))
    story.append(HRFlowable(width="100%", color=TEAL, thickness=2, spaceAfter=12))
    story.append(Spacer(1, 1*cm))

    cover_data = [
        ["Engagement:",    ssid],
        ["Target BSSID:",  bssid],
        ["Session ID:",    session_id],
        ["Date:",          generated_at],
        ["Risk Rating:",   risk_rating],
        ["Targets:",       "1"],
    ]
    cover_table = RLTable(cover_data, colWidths=[5*cm, 11*cm])
    cover_table.setStyle(TableStyle([
        ("FONTNAME",   (0,0), (-1,-1), "Helvetica"),
        ("FONTSIZE",   (0,0), (-1,-1), 11),
        ("FONTNAME",   (0,0), (0,-1), "Helvetica-Bold"),
        ("TEXTCOLOR",  (0,0), (0,-1), TEAL),
        ("ROWBACKGROUNDS", (0,0), (-1,-1), [LIGHT, colors.white]),
        ("TOPPADDING", (0,0), (-1,-1), 6),
        ("BOTTOMPADDING", (0,0), (-1,-1), 6),
    ]))
    story.append(cover_table)
    story.append(Spacer(1, 2*cm))
    story.append(Paragraph("CONFIDENTIAL", conf))
    story.append(Paragraph(
        "This report contains sensitive security findings and is intended solely "
        "for the authorized recipient. Distribution or reproduction without permission "
        "is prohibited.",
        dim,
    ))
    story.append(PageBreak())

    # ── Page 2: Executive Summary ────────────────────────────────────────────
    story.append(Paragraph("Executive Summary", h1))
    story.append(HRFlowable(width="100%", color=TEAL, thickness=1, spaceAfter=8))

    risk_colors = {"Critical": "red", "High": "orange", "Medium": "#cc8800", "Low": "green"}
    rc = risk_colors.get(risk_rating, "grey")
    story.append(Paragraph(
        f'Overall Risk Rating: <font color="{rc}"><b>{risk_rating}</b></font>',
        body,
    ))
    story.append(Spacer(1, 0.5*cm))

    if key_found:
        story.append(Paragraph(
            f"The WPA2 pre-shared key for network <b>{ssid}</b> (BSSID: {bssid}) "
            f"was successfully recovered during this assessment. "
            f"The recovered key demonstrates the network's susceptibility to "
            "dictionary-based attacks.",
            body,
        ))
    else:
        story.append(Paragraph(
            f"A WiFi security assessment was performed against <b>{ssid}</b> "
            f"(BSSID: {bssid}). The pre-shared key was not recovered within the "
            "scope of this test, suggesting the use of a non-dictionary password.",
            body,
        ))

    story.append(Spacer(1, 0.5*cm))

    # Top findings table
    if findings:
        story.append(Paragraph("Key Findings", h3))
        top3 = findings[:3]
        rows = [["#", "Type", "Severity", "Detail"]]
        for i, f in enumerate(top3, 1):
            sev = f.get("severity", "LOW")
            rows.append([str(i), f.get("protocol", f.get("type", "–")).upper(),
                         sev, str(f.get("detail", ""))[:60]])
        ft = RLTable(rows, colWidths=[1*cm, 4*cm, 3*cm, 9*cm])
        ft.setStyle(TableStyle([
            ("BACKGROUND",  (0,0), (-1,0), TEAL),
            ("TEXTCOLOR",   (0,0), (-1,0), colors.white),
            ("FONTNAME",    (0,0), (-1,0), "Helvetica-Bold"),
            ("FONTSIZE",    (0,0), (-1,-1), 9),
            ("ROWBACKGROUNDS", (0,1), (-1,-1), [LIGHT, colors.white]),
            ("GRID",        (0,0), (-1,-1), 0.5, colors.lightgrey),
        ]))
        story.append(ft)
    story.append(PageBreak())

    # ── Page 3+: Technical Findings ─────────────────────────────────────────
    story.append(Paragraph("Technical Findings", h1))
    story.append(HRFlowable(width="100%", color=TEAL, thickness=1, spaceAfter=8))

    tech_data = [
        ["SSID",        ssid],
        ["BSSID",       bssid],
        ["Security",    data.get("privacy", "Unknown")],
        ["Channel",     str(data.get("channel", "–"))],
        ["Vendor",      data.get("vendor", "Unknown")],
        ["Stage",       stage],
        ["Outcome",     "KEY FOUND" if key_found else "NOT CRACKED"],
    ]
    tech_table = RLTable(tech_data, colWidths=[5*cm, 11*cm])
    tech_table.setStyle(TableStyle([
        ("FONTNAME",   (0,0), (0,-1), "Helvetica-Bold"),
        ("TEXTCOLOR",  (0,0), (0,-1), TEAL),
        ("ROWBACKGROUNDS", (0,0), (-1,-1), [LIGHT, colors.white]),
        ("TOPPADDING", (0,0), (-1,-1), 5),
        ("BOTTOMPADDING", (0,0), (-1,-1), 5),
        ("FONTSIZE",   (0,0), (-1,-1), 10),
    ]))
    story.append(tech_table)
    story.append(Spacer(1, 0.5*cm))

    # Evidence
    capture_file  = data.get("capture_file")
    wordlist_file = data.get("wordlist_file")
    cap_hash      = _sha256_file(Path(capture_file)) if capture_file else "N/A"
    story.append(Paragraph("Evidence", h3))
    ev_data = [
        ["Capture file",     str(capture_file or "N/A")],
        ["Capture SHA-256",  cap_hash[:32] + "…" if len(cap_hash) > 32 else cap_hash],
        ["Wordlist used",    str(wordlist_file or "N/A")],
    ]
    ev_table = RLTable(ev_data, colWidths=[5*cm, 11*cm])
    ev_table.setStyle(TableStyle([
        ("FONTNAME", (0,0), (0,-1), "Helvetica-Bold"),
        ("FONTSIZE", (0,0), (-1,-1), 9),
        ("ROWBACKGROUNDS", (0,0), (-1,-1), [LIGHT, colors.white]),
    ]))
    story.append(ev_table)
    story.append(PageBreak())

    # ── Final page: Remediation Checklist ────────────────────────────────────
    story.append(Paragraph("Remediation Checklist", h1))
    story.append(HRFlowable(width="100%", color=TEAL, thickness=1, spaceAfter=8))
    story.append(Paragraph(
        "The following remediation actions are recommended, mapped to "
        "NIST SP 800-153 (Guidelines for Securing Wireless Local Area Networks).",
        body,
    ))
    story.append(Spacer(1, 0.3*cm))

    remediation_items = [
        ("☐", "Change default SSID to a non-identifying name",
         "NIST 800-153 §4.1", "Remove information leakage via SSID"),
        ("☐", "Set a strong, random WPA2/WPA3 passphrase (≥ 20 chars)",
         "NIST 800-153 §4.2", "Prevent dictionary attacks"),
        ("☐", "Disable WPS if not needed",
         "NIST 800-153 §4.3", "Eliminate PIN-based attack surface"),
        ("☐", "Enable WPA3-SAE if hardware supports it",
         "NIST 800-153 §4.2", "Prevent offline dictionary attacks"),
        ("☐", "Update router firmware to latest version",
         "NIST 800-153 §4.4", "Patch known CVEs"),
        ("☐", "Disable UPnP and remote management",
         "NIST 800-153 §4.5", "Reduce attack surface"),
        ("☐", "Enable MAC address filtering (defense-in-depth only)",
         "NIST 800-153 §4.1", "Adds friction for opportunistic attacks"),
        ("☐", "Use separate guest network for untrusted devices",
         "NIST 800-153 §4.6", "Network segmentation"),
    ]

    rem_rows = [["", "Action", "NIST Control", "Rationale"]]
    for chk, action, ctrl, rationale in remediation_items:
        rem_rows.append([chk, action, ctrl, rationale])

    rem_table = RLTable(
        rem_rows,
        colWidths=[0.5*cm, 6*cm, 4*cm, 6*cm],
    )
    rem_table.setStyle(TableStyle([
        ("BACKGROUND",   (0,0), (-1,0), TEAL),
        ("TEXTCOLOR",    (0,0), (-1,0), colors.white),
        ("FONTNAME",     (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE",     (0,0), (-1,-1), 9),
        ("ROWBACKGROUNDS", (0,1), (-1,-1), [LIGHT, colors.white]),
        ("GRID",         (0,0), (-1,-1), 0.5, colors.lightgrey),
        ("TOPPADDING",   (0,0), (-1,-1), 4),
        ("BOTTOMPADDING",(0,0), (-1,-1), 4),
    ]))
    story.append(rem_table)

    story.append(Spacer(1, 1*cm))
    story.append(Paragraph(
        f"Report generated by wifi_down | {generated_at}",
        dim,
    ))

    doc.build(story)
    logger.info("PDF report (reportlab): %s", out_path)


# ─── weasyprint fallback ──────────────────────────────────────────────────────

def _generate_with_weasyprint(
    session_id: str,
    data: dict,
    findings: list[dict],
    out_path: Path,
) -> None:
    from weasyprint import HTML

    bssid        = data.get("target_bssid", "Unknown")
    ssid         = data.get("target_ssid",  "Unknown")
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    risk_rating  = _risk_rating(findings)

    rows_html = ""
    for f in findings[:10]:
        sev = f.get("severity", "LOW")
        sc  = {"CRITICAL":"#c00","HIGH":"#e65c00","MEDIUM":"#cc8800","LOW":"#666"}.get(sev, "#666")
        rows_html += (
            f"<tr><td>{f.get('protocol','–').upper()}</td>"
            f"<td style='color:{sc};font-weight:bold'>{sev}</td>"
            f"<td>{str(f.get('detail',''))[:80]}</td></tr>"
        )

    html_content = textwrap.dedent(f"""\
    <!DOCTYPE html><html><head><meta charset="UTF-8">
    <style>
      body{{font-family:Arial,sans-serif;color:#1a1a1a;margin:40px;}}
      h1{{color:#00D4AA;}} h2{{color:#00D4AA;border-bottom:2px solid #00D4AA;padding-bottom:4px;}}
      .cover{{text-align:center;padding:60px 0;}}
      .conf{{color:red;font-weight:bold;font-size:1.2em;}}
      table{{width:100%;border-collapse:collapse;margin:16px 0;}}
      th{{background:#00D4AA;color:#fff;padding:8px;text-align:left;}}
      td{{padding:6px 8px;border-bottom:1px solid #eee;}}
      tr:nth-child(even){{background:#f5f5f5;}}
      @page{{size:A4;margin:2cm;}}
    </style></head><body>
    <div class="cover">
      <h1>wifi_down</h1>
      <h2>WiFi Security Audit Report</h2>
      <p><b>Network:</b> {ssid}</p>
      <p><b>BSSID:</b> {bssid}</p>
      <p><b>Date:</b> {generated_at}</p>
      <p><b>Risk Rating:</b> {risk_rating}</p>
      <p class="conf">CONFIDENTIAL</p>
    </div>
    <h2>Technical Findings</h2>
    <table><tr><th>Type</th><th>Severity</th><th>Detail</th></tr>
    {rows_html or '<tr><td colspan="3">No intercept findings</td></tr>'}
    </table>
    <p style="color:#999;font-size:.85em">Generated by wifi_down | {generated_at}</p>
    </body></html>
    """)

    HTML(string=html_content).write_pdf(str(out_path))
    logger.info("PDF report (weasyprint): %s", out_path)


# ─── Public API ───────────────────────────────────────────────────────────────

def generate_pdf_report(
    session_id: str,
    out_dir: Path = REPORTS_DIR,
    ghost_report: Optional[object] = None,
    intercept_findings: Optional[list[dict]] = None,
) -> Optional[Path]:
    """
    Generate a PDF pentest report for *session_id*.
    Returns the PDF path on success, None if no PDF engine is available.
    """
    out_dir.mkdir(parents=True, exist_ok=True)

    try:
        data = _load_session(session_id)
    except FileNotFoundError as exc:
        logger.error("PDF report: %s", exc)
        return None

    findings: list[dict] = intercept_findings or []

    # Enrich with CVE findings from ghost report
    if ghost_report:
        for cve in getattr(ghost_report, "cves", []):
            findings.append({
                "type":     "cve",
                "severity": cve.severity,
                "detail":   f"{cve.cve_id}: {cve.description[:100]}",
                "protocol": "CVE",
            })

    # Key found = finding
    if data.get("result"):
        findings.insert(0, {
            "type":     "wpa_crack",
            "severity": "CRITICAL",
            "detail":   "WPA2 pre-shared key recovered",
            "protocol": "WPA2",
        })

    pdf_path = out_dir / f"report_{session_id}.pdf"

    # Try reportlab first
    try:
        import reportlab  # noqa: F401
        _generate_with_reportlab(session_id, data, findings, pdf_path)
        return pdf_path
    except ImportError:
        logger.debug("reportlab not available, trying weasyprint")
    except Exception as exc:
        logger.warning("reportlab PDF generation failed: %s", exc)

    # Try weasyprint fallback
    try:
        import weasyprint  # noqa: F401
        _generate_with_weasyprint(session_id, data, findings, pdf_path)
        return pdf_path
    except ImportError:
        logger.debug("weasyprint not available")
    except Exception as exc:
        logger.warning("weasyprint PDF generation failed: %s", exc)

    # Neither available
    logger.warning("No PDF engine available (install reportlab or weasyprint)")
    return None
