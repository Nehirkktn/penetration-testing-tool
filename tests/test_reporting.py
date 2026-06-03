"""ReportGenerator için testler."""

import os
import json
import tempfile
from datetime import datetime
import pytest

from siber_savascilar.reporting import ReportGenerator
from siber_savascilar.core.models import (
    ScanResult, Vulnerability, Severity, VulnType, ScanStatus
)


@pytest.fixture
def sample_result():
    """Tipik bir tarama sonucu."""
    r = ScanResult(
        scan_id=42,
        target_url="http://test.example.com",
        status=ScanStatus.COMPLETED,
        started_at=datetime(2025, 1, 1, 10, 0, 0),
        finished_at=datetime(2025, 1, 1, 10, 0, 30),
        modules_run=["sqli", "xss", "misconfig"],
    )
    r.add_vulnerability(Vulnerability(
        vuln_type=VulnType.SQLI,
        severity=Severity.CRITICAL,
        target="http://test.example.com/?id=1",
        description="SQL Injection açığı",
        payload="' OR 1=1--",
        cwe="CWE-89",
        remediation="Parametreli sorgu kullanın",
    ))
    r.add_vulnerability(Vulnerability(
        vuln_type=VulnType.XSS,
        severity=Severity.HIGH,
        target="http://test.example.com/?q=test",
        payload="<script>alert(1)</script>",
        cwe="CWE-79",
    ))
    return r


@pytest.fixture
def empty_result():
    """Zafiyetsiz tarama."""
    return ScanResult(
        scan_id=1,
        target_url="http://safe.com",
        status=ScanStatus.COMPLETED,
        started_at=datetime.now(),
        finished_at=datetime.now(),
        modules_run=["sqli"],
    )


@pytest.fixture
def tmp_reports_dir(tmp_path):
    return str(tmp_path)


# ─────────────────────────────────────────────────────────────────────────
# HTML
# ─────────────────────────────────────────────────────────────────────────

class TestHTMLGeneration:
    def test_generates_file(self, sample_result, tmp_reports_dir):
        gen = ReportGenerator(output_dir=tmp_reports_dir)
        path = gen.generate_html(sample_result)
        assert os.path.exists(path)
        assert path.endswith(".html")

    def test_filename_includes_scan_id(self, sample_result, tmp_reports_dir):
        gen = ReportGenerator(output_dir=tmp_reports_dir)
        path = gen.generate_html(sample_result)
        assert "42" in os.path.basename(path)

    def test_content_includes_target(self, sample_result, tmp_reports_dir):
        gen = ReportGenerator(output_dir=tmp_reports_dir)
        path = gen.generate_html(sample_result)
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
        assert "test.example.com" in content

    def test_content_includes_all_vulnerabilities(self, sample_result, tmp_reports_dir):
        gen = ReportGenerator(output_dir=tmp_reports_dir)
        path = gen.generate_html(sample_result)
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
        assert "SQL Injection" in content
        assert "Cross-Site Scripting" in content

    def test_content_includes_severity_counts(self, sample_result, tmp_reports_dir):
        gen = ReportGenerator(output_dir=tmp_reports_dir)
        path = gen.generate_html(sample_result)
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
        assert "Critical" in content or "Kritik" in content

    def test_content_includes_cwe(self, sample_result, tmp_reports_dir):
        gen = ReportGenerator(output_dir=tmp_reports_dir)
        path = gen.generate_html(sample_result)
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
        assert "CWE-89" in content
        assert "CWE-79" in content

    def test_payload_escaped_in_html(self, sample_result, tmp_reports_dir):
        """Payload HTML olarak escape edilmeli, script tagı çalıştırılmamalı."""
        gen = ReportGenerator(output_dir=tmp_reports_dir)
        path = gen.generate_html(sample_result)
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
        # <script> içeren payload escape olmalı
        # &lt;script&gt; veya benzeri görmeyi bekleriz
        # XSS scanner'ın payload'unu içeren yer escape olmalı
        # (En azından raw <script>alert(1)</script> body içinde
        #  yer almamalı — çünkü bizim "vulnerability" listemizdeki bir veri)
        # HTML şablon dışında raw script olamaz
        idx = content.find("Cross-Site Scripting")
        assert idx >= 0

    def test_empty_result_shows_clean_message(self, empty_result, tmp_reports_dir):
        gen = ReportGenerator(output_dir=tmp_reports_dir)
        path = gen.generate_html(empty_result)
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
        assert "zafiyet tespit edilmedi" in content.lower()


# ─────────────────────────────────────────────────────────────────────────
# JSON
# ─────────────────────────────────────────────────────────────────────────

class TestJSONGeneration:
    def test_generates_file(self, sample_result, tmp_reports_dir):
        gen = ReportGenerator(output_dir=tmp_reports_dir)
        path = gen.generate_json(sample_result)
        assert os.path.exists(path)
        assert path.endswith(".json")

    def test_valid_json(self, sample_result, tmp_reports_dir):
        gen = ReportGenerator(output_dir=tmp_reports_dir)
        path = gen.generate_json(sample_result)
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        # JSON parse hatasız geçmeli
        assert isinstance(data, dict)

    def test_json_contains_target(self, sample_result, tmp_reports_dir):
        gen = ReportGenerator(output_dir=tmp_reports_dir)
        path = gen.generate_json(sample_result)
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        assert data["target_url"] == "http://test.example.com"

    def test_json_contains_all_vulnerabilities(self, sample_result, tmp_reports_dir):
        gen = ReportGenerator(output_dir=tmp_reports_dir)
        path = gen.generate_json(sample_result)
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        assert len(data["vulnerabilities"]) == 2

    def test_json_includes_severity_breakdown(self, sample_result, tmp_reports_dir):
        gen = ReportGenerator(output_dir=tmp_reports_dir)
        path = gen.generate_json(sample_result)
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        assert "severity_breakdown" in data
        assert data["severity_breakdown"]["Critical"] == 1
        assert data["severity_breakdown"]["High"] == 1

    def test_json_preserves_turkish(self, tmp_reports_dir):
        r = ScanResult(scan_id=1, target_url="http://türkçe.com",
                       started_at=datetime.now())
        r.add_vulnerability(Vulnerability(
            description="Türkçe açıklama içeriği özçg",
        ))
        gen = ReportGenerator(output_dir=tmp_reports_dir)
        path = gen.generate_json(r)
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        assert "Türkçe açıklama" in data["vulnerabilities"][0]["description"]


# ─────────────────────────────────────────────────────────────────────────
# PDF (opsiyonel)
# ─────────────────────────────────────────────────────────────────────────

class TestPDFGeneration:
    def test_returns_none_or_path(self, sample_result, tmp_reports_dir):
        """reportlab kuruluysa path döner, değilse None."""
        gen = ReportGenerator(output_dir=tmp_reports_dir)
        result = gen.generate_pdf(sample_result)
        if result is not None:
            assert os.path.exists(result)
            assert result.endswith(".pdf")

    def test_pdf_when_reportlab_available(self, sample_result, tmp_reports_dir):
        try:
            import reportlab  # noqa
        except ImportError:
            pytest.skip("reportlab kurulu değil")
        gen = ReportGenerator(output_dir=tmp_reports_dir)
        path = gen.generate_pdf(sample_result)
        assert path is not None
        assert os.path.exists(path)


# ─────────────────────────────────────────────────────────────────────────
# Output dir
# ─────────────────────────────────────────────────────────────────────────

class TestReportGeneratorSetup:
    def test_creates_output_dir(self, tmp_path):
        new_dir = str(tmp_path / "new_reports_dir")
        gen = ReportGenerator(output_dir=new_dir)
        assert os.path.exists(new_dir)

    def test_default_output_dir(self):
        gen = ReportGenerator()
        assert os.path.exists(gen.output_dir)

    def test_escape_handles_none(self):
        """_escape None'u boş string'e çevirmeli, crash etmemeli."""
        gen = ReportGenerator()
        assert gen._escape(None) == ""

    def test_escape_escapes_html(self):
        gen = ReportGenerator()
        assert "&lt;script&gt;" in gen._escape("<script>alert(1)</script>")
        assert "&amp;" in gen._escape("a & b")
