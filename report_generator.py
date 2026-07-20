"""
report_generator.py
---------------------
Generates downloadable security reports in CSV, Excel, and PDF formats.
"""

import io
import pandas as pd
from datetime import datetime


def generate_csv_report(df: pd.DataFrame) -> bytes:
    return df.to_csv(index=False).encode("utf-8")


def generate_excel_report(sheets: dict) -> bytes:
    """sheets: dict of {sheet_name: dataframe}"""
    buffer = io.BytesIO()
    with pd.ExcelWriter(buffer, engine="openpyxl") as writer:
        for name, sheet_df in sheets.items():
            safe_name = name[:31]
            sheet_df.to_excel(writer, sheet_name=safe_name, index=False)
    buffer.seek(0)
    return buffer.getvalue()


def generate_pdf_report(title, summary_lines, table_df=None, recommendations=None):
    """Generate a simple, clean PDF report using reportlab."""
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import mm
    from reportlab.lib import colors
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    )
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4,
                             topMargin=20 * mm, bottomMargin=20 * mm)
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "TitleStyle", parent=styles["Title"], textColor=colors.HexColor("#0a2540")
    )
    heading_style = ParagraphStyle(
        "Heading", parent=styles["Heading2"], textColor=colors.HexColor("#0a2540")
    )

    elements = [
        Paragraph(title, title_style),
        Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}", styles["Normal"]),
        Spacer(1, 10),
        Paragraph("Summary", heading_style),
    ]
    for line in summary_lines:
        elements.append(Paragraph(line, styles["Normal"]))
    elements.append(Spacer(1, 10))

    if table_df is not None and not table_df.empty:
        elements.append(Paragraph("Data Table", heading_style))
        data = [list(table_df.columns)] + table_df.astype(str).values.tolist()
        t = Table(data, repeatRows=1)
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0a2540")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTSIZE", (0, 0), (-1, -1), 7),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f0f4f8")]),
        ]))
        elements.append(t)
        elements.append(Spacer(1, 10))

    if recommendations:
        elements.append(Paragraph("AI Recommendations", heading_style))
        for rec in recommendations:
            elements.append(Paragraph(f"• {rec}", styles["Normal"]))

    doc.build(elements)
    buffer.seek(0)
    return buffer.getvalue()
