"""
Raporlama Modülü
=================

Üretilen formatlar:
    - HTML  : Web arayüzünde gösterilen interaktif rapor
    - JSON  : Diğer sistemlere aktarılmak için (SIEM uyumlu)
    - PDF   : reportlab ile native olarak üretilir; HTML raporunun
              görünümüyle birebir uyumlu (aynı renkler, aynı düzen).

Rapor şablonu içeriği:
    A. Yönetici Özeti — tarama tarihi, hedef, toplam zafiyet, risk dağılımı
    B. Zafiyet Detayları — her açık için tanım, risk, hedef, kanıt, çözüm
"""

import os
import json
from datetime import datetime, timezone, timedelta
from typing import Optional

from ..core.models import ScanResult, Severity


# ──────────────────────────────────────────────────────────────────────────
# HTML ŞABLONU (web arayüzünde gösterilen interaktif rapor)
# ──────────────────────────────────────────────────────────────────────────

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="UTF-8">
<title>Sızma Testi Otomasyon Aracı — Tarama Raporu #{scan_id}</title>
<style>
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
  background: #f1f5f9;
  color: #0f172a;
  line-height: 1.6;
  padding: 24px;
}}
.container {{ max-width: 1100px; margin: 0 auto; }}
header {{
  background: linear-gradient(135deg, #1e293b 0%, #334155 100%);
  color: white;
  padding: 32px 40px;
  border-radius: 12px 12px 0 0;
}}
header h1 {{ font-size: 28px; margin-bottom: 8px; }}
header .subtitle {{ opacity: 0.85; font-size: 14px; }}
.meta {{
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
  gap: 16px;
  margin-top: 24px;
  background: rgba(255,255,255,0.1);
  padding: 16px;
  border-radius: 8px;
}}
.meta-item {{ }}
.meta-item .label {{ font-size: 12px; opacity: 0.75; text-transform: none; letter-spacing: 0.5px; }}
.meta-item .value {{ font-size: 16px; margin-top: 4px; word-break: break-all; }}

.summary-grid {{
  background: white;
  padding: 32px 40px;
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
  gap: 20px;
  border-bottom: 1px solid #e2e8f0;
}}
.stat-card {{ text-align: center; padding: 16px; border-radius: 8px; }}
.stat-card .count {{ font-size: 32px; font-weight: 700; }}
.stat-card .label {{ font-size: 13px; color: #64748b; margin-top: 4px; }}
.stat-critical {{ background: #fee2e2; color: #991b1b; }}
.stat-high {{ background: #ffedd5; color: #9a3412; }}
.stat-medium {{ background: #fef3c7; color: #854d0e; }}
.stat-low {{ background: #dbeafe; color: #1e40af; }}
.stat-info {{ background: #f3f4f6; color: #374151; }}
.stat-total {{ background: #1e293b; color: white; }}

.summary-text {{
  background: white;
  padding: 24px 40px;
  border-bottom: 1px solid #e2e8f0;
  white-space: pre-wrap;
  font-size: 14px;
}}

.section {{
  background: white;
  padding: 32px 40px;
}}
.section h2 {{
  font-size: 20px;
  margin-bottom: 20px;
  color: #1e293b;
  border-bottom: 2px solid #e2e8f0;
  padding-bottom: 12px;
}}

.vuln {{
  border-left: 4px solid #cbd5e1;
  padding: 16px 20px;
  margin-bottom: 16px;
  background: #f8fafc;
  border-radius: 0 8px 8px 0;
}}
.vuln-Critical {{ border-color: #dc2626; }}
.vuln-High {{ border-color: #ea580c; }}
.vuln-Medium {{ border-color: #ca8a04; }}
.vuln-Low {{ border-color: #2563eb; }}
.vuln-Informational {{ border-color: #6b7280; }}

.vuln-header {{
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 12px;
  flex-wrap: wrap;
  gap: 8px;
}}
.vuln-title {{ font-size: 16px; font-weight: 600; }}
.severity-badge {{
  display: inline-block;
  padding: 4px 12px;
  border-radius: 12px;
  font-size: 12px;
  font-weight: 600;
  color: white;
}}
.vuln-body {{ font-size: 14px; }}
.vuln-row {{ margin: 8px 0; }}
.vuln-row strong {{ color: #475569; display: inline-block; min-width: 100px; }}
.vuln-row code {{
  background: #1e293b;
  color: #94e2d5;
  padding: 2px 8px;
  border-radius: 4px;
  font-size: 13px;
  word-break: break-all;
}}

.no-vulns {{
  text-align: center;
  padding: 60px 40px;
  background: #f0fdf4;
  border-radius: 8px;
  color: #166534;
  font-size: 18px;
}}

footer {{
  background: #1e293b;
  color: #cbd5e1;
  text-align: center;
  padding: 24px;
  border-radius: 0 0 12px 12px;
  font-size: 13px;
}}
footer a {{ color: #94e2d5; }}
</style>
</head>
<body>
<div class="container">

<header>
  <h1>🛡️ Sızma Testi Otomasyon Aracı — Tarama Raporu</h1>
  <div class="subtitle">Otomatik Zafiyet Analizi ve OWASP Top 10 Tarama Sonuçları</div>
  <div class="meta">
    <div class="meta-item">
      <div class="label">Tarama ID</div>
      <div class="value">#{scan_id}</div>
    </div>
    <div class="meta-item">
      <div class="label">Hedef</div>
      <div class="value">{target_url}</div>
    </div>
    <div class="meta-item">
      <div class="label">Başlangıç</div>
      <div class="value">{started_at}</div>
    </div>
    <div class="meta-item">
      <div class="label">Süre</div>
      <div class="value">{duration}</div>
    </div>
    <div class="meta-item">
      <div class="label">Modüller</div>
      <div class="value">{modules}</div>
    </div>
  </div>
</header>

<div class="summary-grid">
  <div class="stat-card stat-total">
    <div class="count">{total}</div>
    <div class="label" style="color:rgba(255,255,255,0.7)">Toplam Zafiyet</div>
  </div>
  <div class="stat-card stat-critical">
    <div class="count">{critical}</div>
    <div class="label">Kritik</div>
  </div>
  <div class="stat-card stat-high">
    <div class="count">{high}</div>
    <div class="label">Yüksek</div>
  </div>
  <div class="stat-card stat-medium">
    <div class="count">{medium}</div>
    <div class="label">Orta</div>
  </div>
  <div class="stat-card stat-low">
    <div class="count">{low}</div>
    <div class="label">Düşük</div>
  </div>
  <div class="stat-card stat-info">
    <div class="count">{info}</div>
    <div class="label">Bilgi</div>
  </div>
</div>

<div class="summary-text"><strong>Yönetici Özeti</strong>
{summary}
</div>

<div class="section">
  <h2>🔍 Tespit Edilen Zafiyetler</h2>
  {vulnerabilities_html}
</div>

<footer>
  Sızma Testi Otomasyon Aracı v1.0 — Siber Savaşçılar Ekibi<br>
  Fırat Üniversitesi Yazılım Mühendisliği Temelleri Dersi<br>
  Rapor oluşturma zamanı: {generated_at}
</footer>

</div>
</body>
</html>"""


VULN_TEMPLATE = """<div class="vuln vuln-{severity}">
  <div class="vuln-header">
    <div class="vuln-title">{idx}. {vuln_type}</div>
    <span class="severity-badge" style="background:{color}">{severity}</span>
  </div>
  <div class="vuln-body">
    <div class="vuln-row"><strong>Hedef:</strong> <code>{target}</code></div>
    <div class="vuln-row"><strong>Açıklama:</strong> {description}</div>
    {parameter_row}
    {payload_row}
    {evidence_row}
    {cwe_row}
    <div class="vuln-row"><strong>Çözüm:</strong> {remediation}</div>
  </div>
</div>"""


class ReportGenerator:
    """HTML, JSON ve PDF rapor üreten sınıf."""

    def __init__(self, output_dir: str = None):
        if output_dir is None:
            project_root = os.path.dirname(os.path.dirname(
                os.path.dirname(os.path.abspath(__file__))))
            output_dir = os.path.join(project_root, "reports")
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)

    # ──────────────────────────────────────────────────────────────────
    # HTML
    # ──────────────────────────────────────────────────────────────────
    def generate_html(self, scan_result: ScanResult) -> str:
        """HTML rapor üretir ve dosya yolunu döndürür."""
        if not scan_result.vulnerabilities:
            vulns_html = '<div class="no-vulns">✅ Bu hedefte zafiyet tespit edilmedi.</div>'
        else:
            sorted_vulns = sorted(
                scan_result.vulnerabilities,
                key=lambda v: -Severity._order.get(v.severity, -1)
            )
            vulns_html = "\n".join(
                self._render_vuln(v, i + 1) for i, v in enumerate(sorted_vulns)
            )

        brk = scan_result.severity_breakdown
        duration = (f"{scan_result.duration_seconds:.1f} saniye"
                    if scan_result.duration_seconds else "-")

        html = HTML_TEMPLATE.format(
            scan_id=scan_result.scan_id or "?",
            target_url=self._escape(scan_result.target_url),
            started_at=(scan_result.started_at.strftime("%d.%m.%Y %H:%M:%S")
                        if scan_result.started_at else "-"),
            duration=duration,
            modules=", ".join(scan_result.modules_run),
            total=scan_result.vulnerability_count,
            critical=brk["Critical"],
            high=brk["High"],
            medium=brk["Medium"],
            low=brk["Low"],
            info=brk["Informational"],
            summary=self._escape(scan_result.summary or scan_result.generate_summary()),
            vulnerabilities_html=vulns_html,
            generated_at=datetime.now(timezone(timedelta(hours=3))).replace(tzinfo=None).strftime("%d.%m.%Y %H:%M:%S"),
        )

        filename = f"rapor_{scan_result.scan_id}_{datetime.now(timezone(timedelta(hours=3))).replace(tzinfo=None).strftime('%Y%m%d_%H%M%S')}.html"
        filepath = os.path.join(self.output_dir, filename)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html)
        return filepath

    # ──────────────────────────────────────────────────────────────────
    # JSON
    # ──────────────────────────────────────────────────────────────────
    def generate_json(self, scan_result: ScanResult) -> str:
        filename = f"rapor_{scan_result.scan_id}_{datetime.now(timezone(timedelta(hours=3))).replace(tzinfo=None).strftime('%Y%m%d_%H%M%S')}.json"
        filepath = os.path.join(self.output_dir, filename)
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(scan_result.to_dict(), f, indent=2, ensure_ascii=False, default=str)
        return filepath

    # ──────────────────────────────────────────────────────────────────
    # PDF  (reportlab ile native — HTML görünümüyle birebir uyumlu)
    # ──────────────────────────────────────────────────────────────────
    def generate_pdf(self, scan_result: ScanResult) -> Optional[str]:
        """PDF rapor üretir. reportlab gerekli; yoksa None döner.

        PDF'in görsel düzeni HTML raporun aynısıdır:
          - Koyu üst başlık (Tarama ID, Hedef, Başlangıç, Süre, Modüller)
          - 6 istatistik kartı (Toplam, Kritik, Yüksek, Orta, Düşük, Bilgi)
          - Yönetici Özeti
          - Tespit Edilen Zafiyetler (varsa kartlar, yoksa yeşil "temiz" kutusu)
        """
        try:
            from reportlab.lib import colors
            from reportlab.lib.pagesizes import A4
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import mm
            from reportlab.lib.enums import TA_CENTER, TA_LEFT
            from reportlab.platypus import (
                SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
                KeepTogether
            )
            from reportlab.pdfbase import pdfmetrics
            from reportlab.pdfbase.ttfonts import TTFont
        except ImportError:
            return None

        # ── Türkçe destekli font kaydı (DejaVu Sans paketle birlikte gelir) ──
        font_normal, font_bold = self._register_fonts(pdfmetrics, TTFont)

        # ── Renkler (HTML şablonu ile birebir aynı) ──
        def hexc(h):
            h = h.lstrip("#")
            return colors.Color(int(h[0:2], 16)/255,
                                int(h[2:4], 16)/255,
                                int(h[4:6], 16)/255)

        C_DARK   = hexc("#1e293b")
        C_TEXT   = hexc("#0f172a")
        C_MUTED  = hexc("#64748b")
        C_BORDER = hexc("#e2e8f0")
        C_META   = hexc("#3b4a63")
        C_PANEL  = hexc("#f8fafc")
        C_LABEL  = hexc("#475569")

        sev_palette = {
            "Critical":      (hexc("#fee2e2"), hexc("#991b1b"), hexc("#dc2626")),
            "High":          (hexc("#ffedd5"), hexc("#9a3412"), hexc("#ea580c")),
            "Medium":        (hexc("#fef3c7"), hexc("#854d0e"), hexc("#ca8a04")),
            "Low":           (hexc("#dbeafe"), hexc("#1e40af"), hexc("#2563eb")),
            "Informational": (hexc("#f3f4f6"), hexc("#374151"), hexc("#6b7280")),
        }

        C_GREEN_BG = hexc("#f0fdf4")
        C_GREEN_FG = hexc("#166534")
        C_CODE_BG  = hexc("#1e293b")
        C_CODE_FG  = hexc("#94e2d5")

        # ── Paragraf stilleri ──
        styles = getSampleStyleSheet()
        st_h1 = ParagraphStyle(
            "h1", parent=styles["Normal"], fontName=font_bold,
            fontSize=17, textColor=colors.white, leading=21,
        )
        st_subtitle = ParagraphStyle(
            "subtitle", parent=styles["Normal"], fontName=font_normal,
            fontSize=10, textColor=colors.Color(1, 1, 1, 0.85), leading=13,
        )
        st_meta_label = ParagraphStyle(
            "meta_label", parent=styles["Normal"], fontName=font_normal,
            fontSize=8, textColor=colors.Color(1, 1, 1, 0.7), leading=10,
        )
        st_meta_value = ParagraphStyle(
            "meta_value", parent=styles["Normal"], fontName=font_bold,
            fontSize=11, textColor=colors.white, leading=14,
        )
        st_stat_label = ParagraphStyle(
            "stat_label", parent=styles["Normal"], fontName=font_normal,
            fontSize=9, alignment=TA_CENTER, leading=11,
        )
        st_section_h = ParagraphStyle(
            "section_h", parent=styles["Normal"], fontName=font_bold,
            fontSize=13, textColor=C_DARK, leading=16, spaceAfter=8,
            borderPadding=0,
        )
        st_body = ParagraphStyle(
            "body", parent=styles["Normal"], fontName=font_normal,
            fontSize=10, textColor=C_TEXT, leading=14,
        )
        st_body_bold = ParagraphStyle(
            "body_bold", parent=styles["Normal"], fontName=font_bold,
            fontSize=10, textColor=C_TEXT, leading=14,
        )
        st_no_vulns = ParagraphStyle(
            "no_vulns", parent=styles["Normal"], fontName=font_bold,
            fontSize=12, alignment=TA_CENTER, textColor=C_GREEN_FG, leading=18,
        )
        st_vuln_title = ParagraphStyle(
            "vuln_title", parent=styles["Normal"], fontName=font_bold,
            fontSize=11, textColor=C_TEXT, leading=14,
        )
        st_badge = ParagraphStyle(
            "badge", parent=styles["Normal"], fontName=font_bold,
            fontSize=9, alignment=TA_CENTER, textColor=colors.white, leading=11,
        )
        st_vuln_label = ParagraphStyle(
            "vuln_label", parent=styles["Normal"], fontName=font_bold,
            fontSize=10, textColor=C_LABEL, leading=14,
        )
        st_footer = ParagraphStyle(
            "footer", parent=styles["Normal"], fontName=font_normal,
            fontSize=9, alignment=TA_CENTER, textColor=hexc("#cbd5e1"), leading=12,
        )

        # ── Sayfa genişliği hesabı ──
        page_width = A4[0]
        left_margin = right_margin = 15 * mm
        content_width = page_width - left_margin - right_margin   # ≈ 180mm

        # ── HEADER (koyu kart) ──
        def build_header():
            duration = (f"{scan_result.duration_seconds:.1f} saniye"
                        if scan_result.duration_seconds else "-")
            started = (scan_result.started_at.strftime("%d.%m.%Y %H:%M:%S")
                       if scan_result.started_at else "-")
            modules = ", ".join(scan_result.modules_run) or "-"

            meta_items = [
                ("Tarama ID",   f"#{scan_result.scan_id or '?'}"),
                ("Hedef",       scan_result.target_url),
                ("Başlangıç",   started),
                ("Süre",        duration),
                ("Modüller",    modules),
            ]

            def cell(label, value):
                return [
                    Paragraph(self._escape(label), st_meta_label),
                    Spacer(1, 3),
                    Paragraph(self._escape(value), st_meta_value),
                ]

            col_w = (content_width - 32) / 4  # 4 sütun, 16pt kenar boşluğu ×2
            # Satır 1: 4 hücre  ·  Satır 2: 1 hücre (4 sütuna yaslı)
            meta_rows = [
                [cell(*meta_items[0]), cell(*meta_items[1]),
                 cell(*meta_items[2]), cell(*meta_items[3])],
                [cell(*meta_items[4]), "", "", ""],
            ]
            meta_table = Table(meta_rows, colWidths=[col_w] * 4)
            meta_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), C_META),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 10),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
                ("SPAN", (0, 1), (3, 1)),
            ]))

            header_inner = [
                [Paragraph("Sızma Testi Otomasyon Aracı — Tarama Raporu", st_h1)],
                [Paragraph("Otomatik Zafiyet Analizi ve OWASP Top 10 Tarama Sonuçları", st_subtitle)],
                [Spacer(1, 12)],
                [meta_table],
            ]
            header = Table(header_inner, colWidths=[content_width])
            header.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), C_DARK),
                ("LEFTPADDING", (0, 0), (-1, -1), 16),
                ("RIGHTPADDING", (0, 0), (-1, -1), 16),
                ("TOPPADDING", (0, 0), (0, 0), 18),
                ("TOPPADDING", (0, 1), (0, 3), 0),
                ("BOTTOMPADDING", (0, 0), (0, 2), 0),
                ("BOTTOMPADDING", (0, 3), (0, 3), 18),
            ]))
            return header

        # ── STAT CARDS (6 kart) ──
        def build_stats():
            brk = scan_result.severity_breakdown
            cards = [
                ("Toplam Zafiyet", scan_result.vulnerability_count,
                 C_DARK, colors.white, colors.Color(1, 1, 1, 0.7)),
                ("Kritik", brk["Critical"],
                 sev_palette["Critical"][0], sev_palette["Critical"][1], sev_palette["Critical"][1]),
                ("Yüksek", brk["High"],
                 sev_palette["High"][0], sev_palette["High"][1], sev_palette["High"][1]),
                ("Orta", brk["Medium"],
                 sev_palette["Medium"][0], sev_palette["Medium"][1], sev_palette["Medium"][1]),
                ("Düşük", brk["Low"],
                 sev_palette["Low"][0], sev_palette["Low"][1], sev_palette["Low"][1]),
                ("Bilgi", brk["Informational"],
                 sev_palette["Informational"][0], sev_palette["Informational"][1], sev_palette["Informational"][1]),
            ]

            sub_tables = []
            for label, num, bg, num_fg, label_fg in cards:
                num_style = ParagraphStyle(
                    "n", parent=styles["Normal"], fontName=font_bold,
                    fontSize=22, alignment=TA_CENTER, textColor=num_fg, leading=24,
                )
                lab_style = ParagraphStyle(
                    "l", parent=styles["Normal"], fontName=font_normal,
                    fontSize=9, alignment=TA_CENTER, textColor=label_fg, leading=11,
                )
                t = Table(
                    [[Paragraph(str(num), num_style)],
                     [Paragraph(self._escape(label), lab_style)]],
                    colWidths=[content_width / 6 - 4],
                )
                t.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (-1, -1), bg),
                    ("LEFTPADDING", (0, 0), (-1, -1), 4),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                    ("TOPPADDING", (0, 0), (0, 0), 12),
                    ("BOTTOMPADDING", (0, 0), (0, 0), 2),
                    ("TOPPADDING", (0, 1), (0, 1), 2),
                    ("BOTTOMPADDING", (0, 1), (0, 1), 12),
                ]))
                sub_tables.append(t)

            grid = Table([sub_tables], colWidths=[content_width / 6] * 6)
            grid.setStyle(TableStyle([
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("LEFTPADDING", (0, 0), (-1, -1), 2),
                ("RIGHTPADDING", (0, 0), (-1, -1), 2),
                ("TOPPADDING", (0, 0), (-1, -1), 0),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
            ]))
            return grid

        # ── ÖZET ──
        def build_summary():
            text = scan_result.summary or scan_result.generate_summary()
            return [
                Paragraph("Yönetici Özeti", st_section_h),
                Paragraph(self._escape(text).replace("\n", "<br/>"), st_body),
            ]

        # ── ZAFİYETLER ──
        def build_vulns():
            elems = [Paragraph("Tespit Edilen Zafiyetler", st_section_h)]
            # Altına ince çizgi
            line = Table([[""]], colWidths=[content_width])
            line.setStyle(TableStyle([
                ("LINEBELOW", (0, 0), (-1, -1), 1, C_BORDER),
                ("TOPPADDING", (0, 0), (-1, -1), 0),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
            ]))
            elems.append(line)
            elems.append(Spacer(1, 10))

            if not scan_result.vulnerabilities:
                box = Table(
                    [[Paragraph("✓ Bu hedefte zafiyet tespit edilmedi.", st_no_vulns)]],
                    colWidths=[content_width],
                )
                box.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (-1, -1), C_GREEN_BG),
                    ("TOPPADDING", (0, 0), (-1, -1), 28),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 28),
                    ("LEFTPADDING", (0, 0), (-1, -1), 16),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 16),
                ]))
                elems.append(box)
                return elems

            sorted_vulns = sorted(
                scan_result.vulnerabilities,
                key=lambda v: -Severity._order.get(v.severity, -1),
            )
            for i, v in enumerate(sorted_vulns, start=1):
                elems.append(self._build_vuln_card(
                    v, i, content_width, font_bold, font_normal,
                    Paragraph, Table, TableStyle, Spacer, ParagraphStyle, styles,
                    colors, sev_palette, C_PANEL, C_LABEL, C_TEXT, C_CODE_BG, C_CODE_FG,
                    st_vuln_title, st_badge, st_vuln_label, st_body,
                ))
                elems.append(Spacer(1, 8))
            return elems

        # ── FOOTER ──
        def build_footer():
            generated = datetime.now(timezone(timedelta(hours=3))).replace(tzinfo=None).strftime("%d.%m.%Y %H:%M:%S")
            text = (
                "Sızma Testi Otomasyon Aracı v1.0 — Siber Savaşçılar Ekibi<br/>"
                "Fırat Üniversitesi Yazılım Mühendisliği Temelleri Dersi<br/>"
                f"Rapor oluşturma zamanı: {generated}"
            )
            inner = Paragraph(text, st_footer)
            t = Table([[inner]], colWidths=[content_width])
            t.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), C_DARK),
                ("TOPPADDING", (0, 0), (-1, -1), 18),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 18),
                ("LEFTPADDING", (0, 0), (-1, -1), 16),
                ("RIGHTPADDING", (0, 0), (-1, -1), 16),
            ]))
            return t

        # ── PDF dökümanını birleştir ──
        filename = f"rapor_{scan_result.scan_id}_{datetime.now(timezone(timedelta(hours=3))).replace(tzinfo=None).strftime('%Y%m%d_%H%M%S')}.pdf"
        filepath = os.path.join(self.output_dir, filename)

        doc = SimpleDocTemplate(
            filepath, pagesize=A4,
            leftMargin=left_margin, rightMargin=right_margin,
            topMargin=15 * mm, bottomMargin=15 * mm,
            title=f"Tarama Raporu #{scan_result.scan_id}",
            author="Siber Savaşçılar Ekibi",
        )

        story = []
        story.append(build_header())
        story.append(Spacer(1, 12))
        story.append(build_stats())
        story.append(Spacer(1, 18))
        story.extend(build_summary())
        story.append(Spacer(1, 18))
        story.extend(build_vulns())
        story.append(Spacer(1, 18))
        story.append(build_footer())

        try:
            doc.build(story)
        except Exception:
            return None

        return filepath

    # ──────────────────────────────────────────────────────────────────
    # PDF yardımcıları
    # ──────────────────────────────────────────────────────────────────
    def _register_fonts(self, pdfmetrics, TTFont):
        """Türkçe destekli DejaVu Sans fontunu kaydeder.

        Önce paket içindeki fonts/ klasöründe arar (her platformda taşınır).
        Yoksa yaygın sistem yollarına bakar. Hiçbiri yoksa Helvetica döner
        (Türkçe karakterler kutucuk olabilir).
        """
        font_normal = "Helvetica"
        font_bold = "Helvetica-Bold"

        candidates = []
        pkg_fonts_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fonts")
        candidates.append((
            os.path.join(pkg_fonts_dir, "DejaVuSans.ttf"),
            os.path.join(pkg_fonts_dir, "DejaVuSans-Bold.ttf"),
        ))
        # Yaygın Linux yolları
        candidates.append((
            "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
            "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
        ))
        # macOS / Windows benzeri yollar (best-effort)
        candidates.append((
            "C:\\Windows\\Fonts\\DejaVuSans.ttf",
            "C:\\Windows\\Fonts\\DejaVuSans-Bold.ttf",
        ))

        for normal_path, bold_path in candidates:
            if os.path.exists(normal_path) and os.path.exists(bold_path):
                try:
                    if "DejaVuSans" not in pdfmetrics.getRegisteredFontNames():
                        pdfmetrics.registerFont(TTFont("DejaVuSans", normal_path))
                    if "DejaVuSans-Bold" not in pdfmetrics.getRegisteredFontNames():
                        pdfmetrics.registerFont(TTFont("DejaVuSans-Bold", bold_path))
                    font_normal = "DejaVuSans"
                    font_bold = "DejaVuSans-Bold"
                    break
                except Exception:
                    continue

        return font_normal, font_bold

    def _build_vuln_card(self, v, idx, content_width,
                         font_bold, font_normal,
                         Paragraph, Table, TableStyle, Spacer, ParagraphStyle, styles,
                         colors, sev_palette, C_PANEL, C_LABEL, C_TEXT, C_CODE_BG, C_CODE_FG,
                         st_vuln_title, st_badge, st_vuln_label, st_body):
        """Tek bir zafiyet kartı (HTML'deki .vuln bloğunun PDF karşılığı)."""
        from reportlab.lib.units import mm
        """Tek bir zafiyet kartı (HTML'deki .vuln bloğunun PDF karşılığı)."""
        sev_bg, sev_fg, sev_main = sev_palette.get(v.severity, sev_palette["Informational"])

        # Üst satır: başlık + severity rozeti
        badge = Table(
            [[Paragraph(self._escape(v.severity), st_badge)]],
            colWidths=[26 * mm],
        )
        badge.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), sev_main),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ]))

        title_para = Paragraph(
            f"{idx}. {self._escape(v.vuln_type)}", st_vuln_title
        )
        header_row = Table(
            [[title_para, badge]],
            colWidths=[content_width - 26 * mm - 36, 26 * mm + 8],
        )
        header_row.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("ALIGN", (1, 0), (1, 0), "RIGHT"),
            ("LEFTPADDING", (0, 0), (-1, -1), 0),
            ("RIGHTPADDING", (0, 0), (-1, -1), 0),
            ("TOPPADDING", (0, 0), (-1, -1), 0),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
        ]))

        # Detay satırları (label : value)
        def row(label, value, code=False):
            if code:
                code_style = ParagraphStyle(
                    "code", parent=styles["Normal"], fontName=font_normal,
                    fontSize=9, textColor=C_CODE_FG, backColor=C_CODE_BG,
                    leading=12, borderPadding=2,
                )
                val_para = Paragraph(self._escape(value), code_style)
            else:
                val_para = Paragraph(self._escape(value), st_body)
            return [Paragraph(self._escape(label) + ":", st_vuln_label), val_para]

        detail_rows = []
        detail_rows.append(row("Hedef", v.target or "-", code=True))
        if v.description:
            detail_rows.append(row("Açıklama", v.description))
        if v.parameter:
            detail_rows.append(row("Parametre", v.parameter, code=True))
        if v.payload:
            detail_rows.append(row("Payload", v.payload, code=True))
        if v.evidence:
            detail_rows.append(row("Kanıt", v.evidence))
        if v.cwe:
            detail_rows.append(row("CWE", v.cwe))
        if v.remediation:
            detail_rows.append(row("Çözüm", v.remediation))

        details = Table(detail_rows, colWidths=[28 * mm, content_width - 28 * mm - 28])
        details.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 0),
            ("RIGHTPADDING", (0, 0), (-1, -1), 0),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]))

        # Kart: panel arka planı + sol kenarda renkli şerit (severity rengi)
        card_inner = Table(
            [[header_row], [Spacer(1, 6)], [details]],
            colWidths=[content_width - 28],
        )
        card_inner.setStyle(TableStyle([
            ("LEFTPADDING", (0, 0), (-1, -1), 0),
            ("RIGHTPADDING", (0, 0), (-1, -1), 0),
            ("TOPPADDING", (0, 0), (-1, -1), 0),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
        ]))

        card = Table([[card_inner]], colWidths=[content_width])
        card.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), C_PANEL),
            ("LINEBEFORE", (0, 0), (0, -1), 4, sev_main),
            ("LEFTPADDING", (0, 0), (-1, -1), 14),
            ("RIGHTPADDING", (0, 0), (-1, -1), 14),
            ("TOPPADDING", (0, 0), (-1, -1), 12),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
        ]))
        return card

    # ──────────────────────────────────────────────────────────────────
    # HTML yardımcıları
    # ──────────────────────────────────────────────────────────────────
    def _render_vuln(self, v, idx: int) -> str:
        def row(label, value):
            return f'<div class="vuln-row"><strong>{label}:</strong> {value}</div>'

        parameter_row = (row("Parametre", f"<code>{self._escape(v.parameter)}</code>")
                         if v.parameter else "")
        payload_row = (row("Payload", f"<code>{self._escape(v.payload)}</code>")
                       if v.payload else "")
        evidence_row = row("Kanıt", self._escape(v.evidence)) if v.evidence else ""
        cwe_row = row("CWE", v.cwe) if v.cwe else ""

        return VULN_TEMPLATE.format(
            idx=idx,
            vuln_type=self._escape(v.vuln_type),
            severity=v.severity,
            color=Severity.color(v.severity),
            target=self._escape(v.target),
            description=self._escape(v.description),
            parameter_row=parameter_row,
            payload_row=payload_row,
            evidence_row=evidence_row,
            cwe_row=cwe_row,
            remediation=self._escape(v.remediation),
        )

    @staticmethod
    def _escape(s) -> str:
        if s is None:
            return ""
        return (str(s)
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;"))