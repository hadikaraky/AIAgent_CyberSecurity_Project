"""
Tool: generate_report
Purpose: Generate a HackTheBox OSCP-style PDF incident report.
Input: {
  "incident_id": str,
  "title": str,
  "severity": str,
  "description": str,
  "mitre_technique": str,
  "mitre_tactic": str,
  "tactic_id": str,
  "affected_asset": str,
  "source_ip": str or None,
  "risk_score": int,
  "containment_steps": list[str],
  "estimated_impact": str,
  "analyst_name": str
}
Output: {
  "report_id": str,
  "pdf_path": str,
  "generated_at": str,
  "report_text": str  — chat summary (for agent display)
}
"""

import os
from datetime import datetime, timezone

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm, mm
from reportlab.pdfgen import canvas
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    NextPageTemplate,
    PageBreak,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)
from reportlab.platypus.flowables import Flowable

HTB_GREEN = colors.HexColor("#9FEF00")
HTB_NAVY = colors.HexColor("#141D2B")
BODY_TEXT = colors.HexColor("#2D2D2D")
FOOTER_GRAY = colors.HexColor("#888888")
WHITE = colors.HexColor("#FFFFFF")

SEVERITY_COLORS = {
    "Critical": colors.HexColor("#FF4D4D"),
    "High": colors.HexColor("#FF8C00"),
    "Medium": colors.HexColor("#FFD700"),
    "Low": colors.HexColor("#9FEF00"),
}

REPORTS_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "logs", "reports")

SECTION_NAMES = [
    "Executive Summary",
    "Threat Intelligence",
    "Impact Assessment",
    "Incident Description",
    "Containment Checklist",
    "Disclaimer",
]


class SectionMarker(Flowable):
    """Invisible flowable that records the page number for a section."""

    def __init__(self, section_name: str, page_tracker: dict):
        Flowable.__init__(self)
        self.section_name = section_name
        self.page_tracker = page_tracker

    def wrap(self, availWidth, availHeight):
        return 0, 0

    def draw(self):
        self.page_tracker[self.section_name] = self.canv.getPageNumber()


class SeverityBadge(Flowable):
    """Colored rounded rectangle severity badge."""

    def __init__(self, severity: str, width: float = 120, height: float = 28):
        Flowable.__init__(self)
        self.severity = severity
        self.width = width
        self.height = height
        self.color = SEVERITY_COLORS.get(severity, HTB_GREEN)

    def wrap(self, availWidth, availHeight):
        return self.width, self.height

    def draw(self):
        self.canv.setFillColor(self.color)
        self.canv.roundRect(0, 0, self.width, self.height, 6, fill=1, stroke=0)
        self.canv.setFillColor(WHITE if self.severity != "Low" else HTB_NAVY)
        self.canv.setFont("Helvetica-Bold", 11)
        self.canv.drawCentredString(self.width / 2, 9, self.severity.upper())


class GreenRule(Flowable):
    """HTB green horizontal divider."""

    def __init__(self, width: float = 16 * cm, thickness: float = 2):
        Flowable.__init__(self)
        self.width = width
        self.height = thickness + 4

    def wrap(self, availWidth, availHeight):
        return min(self.width, availWidth), self.height

    def draw(self):
        self.canv.setStrokeColor(HTB_GREEN)
        self.canv.setLineWidth(2)
        self.canv.line(0, 2, self.width, 2)


def _make_styles():
    base = getSampleStyleSheet()
    return {
        "section_title": ParagraphStyle(
            "SectionTitle",
            parent=base["Heading2"],
            fontSize=14,
            textColor=HTB_NAVY,
            spaceBefore=14,
            spaceAfter=4,
            fontName="Helvetica-Bold",
        ),
        "body": ParagraphStyle(
            "Body",
            parent=base["Normal"],
            fontSize=10,
            textColor=BODY_TEXT,
            leading=14,
            spaceAfter=8,
        ),
        "toc_title": ParagraphStyle(
            "TOCTitle",
            parent=base["Heading1"],
            fontSize=18,
            textColor=WHITE,
            spaceBefore=0,
            spaceAfter=8,
            fontName="Helvetica-Bold",
        ),
        "toc_entry": ParagraphStyle(
            "TOCEntry",
            parent=base["Normal"],
            fontSize=11,
            textColor=WHITE,
            leading=20,
            fontName="Helvetica",
        ),
        "disclaimer": ParagraphStyle(
            "Disclaimer",
            parent=base["Normal"],
            fontSize=9,
            textColor=FOOTER_GRAY,
            fontName="Helvetica-Oblique",
            leading=13,
        ),
        "cover_title": ParagraphStyle(
            "CoverTitle",
            parent=base["Title"],
            fontSize=28,
            textColor=WHITE,
            alignment=TA_CENTER,
            fontName="Helvetica-Bold",
            spaceAfter=12,
        ),
        "cover_subtitle": ParagraphStyle(
            "CoverSubtitle",
            parent=base["Normal"],
            fontSize=18,
            textColor=HTB_GREEN,
            alignment=TA_CENTER,
            fontName="Helvetica-Bold",
        ),
    }


def _draw_cover_page(canv: canvas.Canvas, doc, meta: dict):
    width, height = A4
    canv.saveState()
    canv.setFillColor(HTB_NAVY)
    canv.rect(0, 0, width, height, fill=1, stroke=0)

    canv.setFillColor(HTB_GREEN)
    canv.rect(2 * cm, height - 4 * cm, 2.5 * cm, 1.2 * cm, fill=1, stroke=0)
    canv.setFillColor(WHITE)
    canv.setFont("Helvetica-Bold", 16)
    canv.drawCentredString(2 * cm + 1.25 * cm, height - 3.55 * cm, "HTB")

    styles = _make_styles()
    from reportlab.platypus import Paragraph as P

    title_para = P("Incident Report", styles["cover_title"])
    subtitle_para = P(meta["incident_id"], styles["cover_subtitle"])

    title_para.wrapOn(canv, width - 4 * cm, 4 * cm)
    title_para.drawOn(canv, 2 * cm, height / 2 + 2 * cm)

    subtitle_para.wrapOn(canv, width - 4 * cm, 2 * cm)
    subtitle_para.drawOn(canv, 2 * cm, height / 2 + 0.5 * cm)

    line_y = height / 2 - 0.5 * cm
    canv.setStrokeColor(HTB_GREEN)
    canv.setLineWidth(2)
    canv.line(4 * cm, line_y, width - 4 * cm, line_y)

    table_data = [
        ["Analyst", meta["analyst_name"]],
        ["Date", meta["generated_at"]],
        ["Severity", meta["severity"]],
        ["Status", "Open — Awaiting Containment"],
    ]
    tbl = Table(table_data, colWidths=[4 * cm, 8 * cm])
    tbl.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), HTB_NAVY),
                ("TEXTCOLOR", (0, 0), (-1, -1), WHITE),
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("FONTNAME", (1, 0), (1, -1), "Helvetica"),
                ("FONTSIZE", (0, 0), (-1, -1), 11),
                ("LINEBELOW", (0, 0), (-1, -2), 0.5, HTB_GREEN),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                ("LEFTPADDING", (0, 0), (-1, -1), 12),
            ]
        )
    )
    tw, th = tbl.wrap(width - 8 * cm, 6 * cm)
    tbl.drawOn(canv, 4 * cm, line_y - th - 1.5 * cm)

    canv.restoreState()


def _draw_content_page(canv: canvas.Canvas, doc, meta: dict):
    width, height = A4
    canv.saveState()

    canv.setFillColor(WHITE)
    canv.rect(0, 0, width, height, fill=1, stroke=0)

    canv.setFillColor(HTB_NAVY)
    canv.rect(0, height - 1.2 * cm, width, 1.2 * cm, fill=1, stroke=0)
    canv.setFillColor(WHITE)
    canv.setFont("Helvetica-Bold", 9)
    canv.drawString(1.5 * cm, height - 0.85 * cm, "CyberTriage Agent")
    canv.drawRightString(width - 1.5 * cm, height - 0.85 * cm, meta["incident_id"])

    canv.setFillColor(FOOTER_GRAY)
    canv.setFont("Helvetica", 8)
    canv.drawCentredString(width / 2, 1 * cm, f"Page {canv.getPageNumber()}")
    canv.drawCentredString(
        width / 2,
        0.55 * cm,
        "AI Decision Support Only — Not Authoritative",
    )

    canv.restoreState()


def _section_block(title: str, content_flowables: list, styles: dict) -> list:
    return [
        Paragraph(title, styles["section_title"]),
        GreenRule(),
        Spacer(1, 6),
        *content_flowables,
        Spacer(1, 10),
    ]


def _toc_table(section_pages: dict, styles: dict) -> Table:
    from reportlab.pdfbase.pdfmetrics import stringWidth

    rows = []
    usable_width = 15 * cm
    for section in SECTION_NAMES:
        page_num = str(section_pages.get(section, "—"))
        title_w = stringWidth(section, "Helvetica", 11)
        page_w = stringWidth(page_num, "Helvetica", 11)
        dot_w = stringWidth(".", "Helvetica", 11)
        num_dots = max(3, int((usable_width - title_w - page_w - 24) / dot_w))
        line = f"{section}{'.' * num_dots}{page_num}"
        rows.append([Paragraph(line, styles["toc_entry"])])

    table = Table(rows, colWidths=[usable_width])
    table.setStyle(
        TableStyle(
            [
                ("TEXTCOLOR", (0, 0), (-1, -1), WHITE),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("LEFTPADDING", (0, 0), (-1, -1), 0),
                ("RIGHTPADDING", (0, 0), (-1, -1), 0),
            ]
        )
    )
    return table


def _toc_section(page_tracker: dict, styles: dict) -> Table:
    """Navy Table of Contents panel with white text — does not affect content pages."""
    panel = Table(
        [
            [Paragraph("Table of Contents", styles["toc_title"])],
            [GreenRule()],
            [Spacer(1, 12)],
            [_toc_table(page_tracker, styles)],
        ],
        colWidths=[16 * cm],
    )
    panel.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), HTB_NAVY),
                ("TOPPADDING", (0, 0), (-1, -1), 22),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 22),
                ("LEFTPADDING", (0, 0), (-1, -1), 18),
                ("RIGHTPADDING", (0, 0), (-1, -1), 18),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]
        )
    )
    return panel


def _build_story(
    meta: dict,
    styles: dict,
    page_tracker: dict,
    include_toc: bool = False,
) -> list:
    story = []

    if include_toc and page_tracker:
        story.append(_toc_section(page_tracker, styles))
        story.append(Spacer(1, 14))
        story.append(PageBreak())

    exec_summary = (
        f"This incident report documents a <b>{meta['severity']}</b> severity security event "
        f"(Risk Score: {meta['risk_score']}/100) identified as <b>{meta['title']}</b>. "
        f"The incident was reported by analyst <b>{meta['analyst_name']}</b> and is currently "
        f"in <b>Open — Awaiting Containment</b> status. Based on available data from the "
        f"MITRE ATT&CK knowledge base, immediate containment actions are recommended."
    )

    story.append(SectionMarker("Executive Summary", page_tracker))
    story.extend(
        _section_block(
            "Executive Summary",
            [
                Paragraph(exec_summary, styles["body"]),
                Spacer(1, 6),
                SeverityBadge(meta["severity"]),
            ],
            styles,
        )
    )

    source_display = meta["source_ip"] if meta["source_ip"] else "Unknown"
    threat_data = [
        ["Field", "Value"],
        ["MITRE Tactic", f"{meta['tactic_id']} — {meta['mitre_tactic']}"],
        ["MITRE Technique", meta["mitre_technique"]],
        ["Affected Asset", meta["affected_asset"]],
        ["Source IP", source_display],
        ["CVE", meta.get("cve_id", "N/A")],
        ["Intelligence Source", "MITRE ATT&CK Framework"],
    ]
    threat_table = Table(threat_data, colWidths=[5 * cm, 10 * cm])
    threat_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), HTB_NAVY),
                ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("BACKGROUND", (0, 1), (0, -1), colors.HexColor("#F5F5F5")),
                ("FONTNAME", (0, 1), (0, -1), "Helvetica-Bold"),
                ("TEXTCOLOR", (0, 1), (-1, -1), BODY_TEXT),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#DDDDDD")),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ]
        )
    )

    story.append(SectionMarker("Threat Intelligence", page_tracker))
    story.extend(
        _section_block("Threat Intelligence", [threat_table], styles)
    )

    story.append(SectionMarker("Impact Assessment", page_tracker))
    story.extend(
        _section_block(
            "Impact Assessment",
            [Paragraph(meta["estimated_impact"], styles["body"])],
            styles,
        )
    )

    story.append(SectionMarker("Incident Description", page_tracker))
    story.extend(
        _section_block(
            "Incident Description",
            [Paragraph(meta["description"], styles["body"])],
            styles,
        )
    )

    checklist_items = meta["containment_steps"] or [
        "Follow general incident response playbook"
    ]
    checklist_flowables = [
        Paragraph(f"□ {i + 1}. {step}", styles["body"])
        for i, step in enumerate(checklist_items)
    ]

    story.append(SectionMarker("Containment Checklist", page_tracker))
    story.extend(
        _section_block("Containment Checklist", checklist_flowables, styles)
    )

    disclaimer_text = (
        "This report was generated by an AI triage assistant and serves as decision-support "
        "only. All recommended actions must be verified by a qualified security engineer "
        "before execution."
    )
    disclaimer_para = Paragraph(disclaimer_text, styles["disclaimer"])
    disclaimer_table = Table([[disclaimer_para]], colWidths=[15 * cm])
    disclaimer_table.setStyle(
        TableStyle(
            [
                ("BOX", (0, 0), (-1, -1), 1, FOOTER_GRAY),
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#FAFAFA")),
                ("TOPPADDING", (0, 0), (-1, -1), 12),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
                ("LEFTPADDING", (0, 0), (-1, -1), 12),
                ("RIGHTPADDING", (0, 0), (-1, -1), 12),
            ]
        )
    )

    story.append(SectionMarker("Disclaimer", page_tracker))
    story.extend(_section_block("Disclaimer", [disclaimer_table], styles))

    return story


def _make_doc(output_path: str) -> BaseDocTemplate:
    doc = BaseDocTemplate(
        output_path,
        pagesize=A4,
        leftMargin=2 * cm,
        rightMargin=2 * cm,
        topMargin=2 * cm,
        bottomMargin=2.2 * cm,
    )
    cover_frame = Frame(
        doc.leftMargin,
        doc.bottomMargin,
        doc.width,
        doc.height,
        id="cover",
    )
    content_frame = Frame(
        doc.leftMargin,
        doc.bottomMargin,
        doc.width,
        doc.height - 0.8 * cm,
        id="content",
        topPadding=1.4 * cm,
    )
    return doc, cover_frame, content_frame


def _render_pdf(meta: dict, output_path: str) -> None:
    page_tracker: dict = {}
    styles = _make_styles()

    doc, cover_frame, content_frame = _make_doc(output_path)
    doc.addPageTemplates(
        [
            PageTemplate(
                id="Cover",
                frames=[cover_frame],
                onPage=lambda c, d: _draw_cover_page(c, d, meta),
            ),
            PageTemplate(
                id="Content",
                frames=[content_frame],
                onPage=lambda c, d: _draw_content_page(c, d, meta),
            ),
        ]
    )

    pass1_story = [
        Spacer(1, 1),
        PageBreak(),
        NextPageTemplate("Content"),
        *_build_story(meta, styles, page_tracker, include_toc=False),
    ]
    doc.build(pass1_story, canvasmaker=canvas.Canvas)

    adjusted_tracker = {
        name: page_tracker[name] + 1
        for name in SECTION_NAMES
        if name in page_tracker
    }

    doc2, cover_frame2, content_frame2 = _make_doc(output_path)
    doc2.addPageTemplates(
        [
            PageTemplate(
                id="Cover",
                frames=[cover_frame2],
                onPage=lambda c, d: _draw_cover_page(c, d, meta),
            ),
            PageTemplate(
                id="Content",
                frames=[content_frame2],
                onPage=lambda c, d: _draw_content_page(c, d, meta),
            ),
        ]
    )

    pass2_story = [
        Spacer(1, 1),
        PageBreak(),
        NextPageTemplate("Content"),
        *_build_story(meta, styles, adjusted_tracker, include_toc=True),
    ]
    doc2.build(pass2_story, canvasmaker=canvas.Canvas)


def generate_report(
    incident_id: str,
    title: str,
    severity: str,
    description: str,
    mitre_technique: str,
    mitre_tactic: str,
    tactic_id: str,
    affected_asset: str,
    source_ip: str | None,
    risk_score: int,
    containment_steps: list[str],
    estimated_impact: str,
    analyst_name: str,
) -> dict:
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    report_id = f"RPT-{incident_id.replace('INC-', '')}"
    timestamp_slug = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    os.makedirs(REPORTS_DIR, exist_ok=True)
    pdf_filename = f"{incident_id}_{timestamp_slug}.pdf"
    pdf_path = os.path.join(REPORTS_DIR, pdf_filename)

    meta = {
        "incident_id": incident_id,
        "title": title,
        "severity": severity,
        "description": description,
        "mitre_technique": mitre_technique,
        "mitre_tactic": mitre_tactic,
        "tactic_id": tactic_id,
        "affected_asset": affected_asset,
        "source_ip": source_ip,
        "risk_score": risk_score,
        "containment_steps": containment_steps,
        "estimated_impact": estimated_impact,
        "analyst_name": analyst_name,
        "generated_at": generated_at,
        "cve_id": "N/A",
    }

    _render_pdf(meta, pdf_path)

    report_text = (
        f"Incident **{incident_id}** created successfully.\n\n"
        f"**Severity:** {severity} (Risk Score: {risk_score}/100)\n"
        f"**MITRE:** {mitre_technique} — {mitre_tactic}\n"
        f"**PDF Report:** {pdf_path}\n\n"
        f"Use **Export Last Report** to download the full HTB-style PDF."
    )

    return {
        "report_id": report_id,
        "pdf_path": pdf_path,
        "generated_at": generated_at,
        "report_text": report_text,
    }
